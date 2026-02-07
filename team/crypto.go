package main

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"io"

	"golang.org/x/crypto/argon2"
)

const (
	saltSize	= 32
	keySize	= 32
	nonceSize	= 12
	iterations	= 3
	memory	= 64 * 1024
	threads	= 4
)

type DerivedKeys struct {
	EncryptionKey	[]byte
	AuthKey	[]byte
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, saltSize)
	_, err := rand.Read(salt)
	return salt, err
}

func GenerateRandomKey() ([]byte, error) {
	key := make([]byte, keySize)
	_, err := rand.Read(key)
	return key, err
}

func DeriveKeys(password string, salt []byte, costMultiplier int) DerivedKeys {
	mem := uint32(memory * costMultiplier)
	iter := uint32(iterations * costMultiplier)

	derivedKey := argon2.IDKey([]byte(password), salt, iter, mem, uint8(threads), 64)

	return DerivedKeys{
		EncryptionKey:	derivedKey[:32],
		AuthKey:	derivedKey[32:64],
	}
}

func WrapKey(key, wrapperKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(wrapperKey)
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

	ciphertext := gcm.Seal(nonce, nonce, key, nil)
	return ciphertext, nil
}

func UnwrapKey(wrappedKey, wrapperKey []byte) ([]byte, error) {
	block, err := aes.NewCipher(wrapperKey)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(wrappedKey) < nonceSize {
		return nil, errors.New("invalid wrapped key")
	}

	nonce, ciphertext := wrappedKey[:nonceSize], wrappedKey[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func EncryptData(data, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
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

	ciphertext := gcm.Seal(nonce, nonce, data, nil)
	return ciphertext, nil
}

func DecryptData(encryptedData, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonceSize := gcm.NonceSize()
	if len(encryptedData) < nonceSize {
		return nil, errors.New("invalid encrypted data")
	}

	nonce, ciphertext := encryptedData[:nonceSize], encryptedData[nonceSize:]
	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func hashData(data []byte) string {
	hash := sha256.Sum256(data)
	return hex.EncodeToString(hash[:])
}
