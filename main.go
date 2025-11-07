package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/binary"
	"errors"
	"fmt"
	"golang.org/x/sys/unix"
	"io"
	"log"
	"runtime"
	"runtime/debug"
	"sync"
	"time"
)

type SecureStore struct {
	mu          sync.RWMutex
	masterKey   [32]byte            // мастер-ключ в памяти
	dataStore   map[string][]byte   // зашифрованные данные
	keyCache    map[string][32]byte // ключи для каждого элемента
	cleanupFunc func()              // функция очистки при завершении
}

func NewSecureStore() (*SecureStore, error) {
	store := &SecureStore{
		dataStore: make(map[string][]byte),
		keyCache:  make(map[string][32]byte),
	}

	// Генерируем мастер-ключ
	if _, err := rand.Read(store.masterKey[:]); err != nil {
		return nil, err
	}

	// Регистрируем очистку при завершении
	store.registerCleanup()

	return store, nil
}

// deriveKey создает ключ для конкретного элемента на основе мастер-ключа и идентификатора
func (s *SecureStore) deriveKey(id string) [32]byte {
	var key [32]byte

	// Используем HKDF-like подход для деривации ключа
	h, _ := aes.NewCipher(s.masterKey[:])

	// Создаем уникальный ключ для каждого id
	idBytes := stringToBytes(id)
	for i := 0; i < len(key); i += aes.BlockSize {
		block := make([]byte, aes.BlockSize)
		copy(block, idBytes)
		binary.LittleEndian.PutUint64(block[8:], uint64(i))

		encrypted := make([]byte, aes.BlockSize)
		h.Encrypt(encrypted, block)

		copy(key[i:], encrypted)
	}

	return key
}

////////

func (s *SecureStore) Set(key string, data []byte) error {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Деривируем ключ для этого элемента
	itemKey := s.deriveKey(key)

	// Шифруем данные
	encrypted, err := s.encryptData(data, itemKey)
	if err != nil {
		return err
	}

	// Сохраняем зашифрованные данные и ключ
	s.dataStore[key] = encrypted
	s.keyCache[key] = itemKey

	// Немедленно очищаем оригинальные данные
	s.wipeBytes(data)

	return nil
}

func (s *SecureStore) Get(key string) ([]byte, bool) {
	s.mu.RLock()
	defer s.mu.RUnlock()

	encrypted, exists := s.dataStore[key]
	if !exists {
		return nil, false
	}

	itemKey, keyExists := s.keyCache[key]
	if !keyExists {
		return nil, false
	}

	// Дешифруем данные
	decrypted, err := s.decryptData(encrypted, itemKey)
	if err != nil {
		return nil, false
	}

	return decrypted, true
}

func (s *SecureStore) GetAndUse(key string, fn func([]byte) error) error {
	data, exists := s.Get(key)
	if !exists {
		return errors.New("key not found")
	}
	defer s.wipeBytes(data) // Очищаем после использования

	return fn(data)
}

////////

func (s *SecureStore) encryptData(data []byte, key [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	encrypted := gcm.Seal(nonce, nonce, data, nil)
	return encrypted, nil
}

func (s *SecureStore) decryptData(encrypted []byte, key [32]byte) ([]byte, error) {
	block, err := aes.NewCipher(key[:])
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encrypted) < nonceSize {
		return nil, errors.New("invalid ciphertext")
	}

	nonce, ciphertext := encrypted[:nonceSize], encrypted[nonceSize:]
	decrypted, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return decrypted, nil
}

///////

func (s *SecureStore) Delete(key string) {
	s.mu.Lock()
	defer s.mu.Unlock()

	if encrypted, exists := s.dataStore[key]; exists {
		s.wipeBytes(encrypted)
		delete(s.dataStore, key)
	}

	if itemKey, exists := s.keyCache[key]; exists {
		s.wipeKey(&itemKey)
		delete(s.keyCache, key)
	}

	runtime.GC()
}

func (s *SecureStore) Wipe() {
	s.mu.Lock()
	defer s.mu.Unlock()

	// Очищаем все данные
	for key, encrypted := range s.dataStore {
		s.wipeBytes(encrypted)
		delete(s.dataStore, key)
	}

	// Очищаем все ключи
	for key, itemKey := range s.keyCache {
		s.wipeKey(&itemKey)
		delete(s.keyCache, key)
	}

	// Очищаем мастер-ключ
	s.wipeKey(&s.masterKey)

	runtime.GC()
}

func (s *SecureStore) wipeBytes(data []byte) {
	for i := range data {
		data[i] = 0
	}
}

func (s *SecureStore) wipeKey(key *[32]byte) {
	for i := range key {
		key[i] = 0
	}
}

//////////

func (s *SecureStore) registerCleanup() {
	// Отключаем сборщик мусора для критических данных
	debug.SetGCPercent(-1)

	// Блокируем память от свапа (Linux/Unix)
	//s.lockMemory()

	// Регистрируем очистку при завершении
	s.cleanupFunc = func() {
		s.Wipe()
		debug.SetGCPercent(100) // Восстанавливаем GC
	}
}

func (s *SecureStore) lockMemory() {
	// Блокируем текущие и будущие страницы памяти
	err := unix.Mlockall(unix.MCL_CURRENT | unix.MCL_FUTURE)
	if err != nil {
		log.Printf("Не удалось заблокировать память: %v", err)
	}
}

// Finalizer для гарантированной очистки
func (s *SecureStore) setFinalizer() {
	runtime.SetFinalizer(s, func(ss *SecureStore) {
		ss.Wipe()
	})
}

////////

// Безопасное преобразование строки в байты
func stringToBytes(s string) []byte {
	b := make([]byte, len(s))
	copy(b, s)
	return b
}

// Безопасная работа со строками
type SecureString struct {
	data []byte
}

func NewSecureString(s string) *SecureString {
	bytes := stringToBytes(s)
	return &SecureString{data: bytes}
}

func (ss *SecureString) Get() string {
	return string(ss.data)
}

func (ss *SecureString) Wipe() {
	for i := range ss.data {
		ss.data[i] = 0
	}
	ss.data = nil
}

/////////

func main() {
	// Создаем безопасное хранилище
	store, err := NewSecureStore()
	if err != nil {
		log.Fatal(err)
	}
	defer store.Wipe() // Очистка при завершении

	// Сохраняем чувствительные данные
	secret := []byte("my_super_secret_password")
	err = store.Set("password", secret)
	if err != nil {
		log.Fatal(err)
	}

	// Используем данные безопасно
	err = store.GetAndUse("password", func(data []byte) error {
		// data доступен только внутри этой функции
		fmt.Printf("Длина пароля: %d\n", len(data))
		// Используем данные...
		return nil
	})
	if err != nil {
		log.Fatal(err)
	}

	// Программа продолжает работать, данные защищены в памяти
	time.Sleep(10 * time.Second)
}
