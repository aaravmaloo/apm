package apm

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/base64"
	"fmt"
	"io"
	"math/big"
	"strings"

	"golang.org/x/crypto/argon2"
	"golang.org/x/crypto/chacha20poly1305"
)

func DeriveKeys(password string, salt []byte) ([]byte, []byte) {
	fullKey := argon2.IDKey([]byte(password), salt, 1, 256*1024, 4, 64)
	return fullKey[:32], fullKey[32:]
}

func EncryptMultiLayer(plaintext []byte, k1, k2 []byte) ([]byte, error) {

	block, err := aes.NewCipher(k1)
	if err != nil {
		return nil, err
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce1 := make([]byte, aesGcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce1); err != nil {
		return nil, err
	}
	ciphertext1 := aesGcm.Seal(nonce1, nonce1, plaintext, nil)

	aead, err := chacha20poly1305.New(k2)
	if err != nil {
		return nil, err
	}
	nonce2 := make([]byte, aead.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce2); err != nil {
		return nil, err
	}
	ciphertext2 := aead.Seal(nonce2, nonce2, ciphertext1, nil)

	return ciphertext2, nil
}

func DecryptMultiLayer(ciphertext []byte, k1, k2 []byte) ([]byte, error) {

	aead, err := chacha20poly1305.New(k2)
	if err != nil {
		return nil, err
	}
	nonceSize2 := aead.NonceSize()
	if len(ciphertext) < nonceSize2 {
		return nil, fmt.Errorf("ciphertext too short (chacha20)")
	}
	nonce2, ciphertext1Enc := ciphertext[:nonceSize2], ciphertext[nonceSize2:]
	ciphertext1, err := aead.Open(nil, nonce2, ciphertext1Enc, nil)
	if err != nil {
		return nil, err
	}

	block, err := aes.NewCipher(k1)
	if err != nil {
		return nil, err
	}
	aesGcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize1 := aesGcm.NonceSize()
	if len(ciphertext1) < nonceSize1 {
		return nil, fmt.Errorf("ciphertext too short (aes)")
	}
	nonce1, plaintextEnc := ciphertext1[:nonceSize1], ciphertext1[nonceSize1:]
	plaintext, err := aesGcm.Open(nil, nonce1, plaintextEnc, nil)
	if err != nil {
		return nil, err
	}

	return plaintext, nil
}

func DeriveKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 256*1024, 4, 32)
}

func GenerateSalt() ([]byte, error) {
	salt := make([]byte, 16)
	_, err := rand.Read(salt)
	return salt, err
}

func GeneratePassword(length int) (string, error) {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+"
	result := make([]byte, length)
	for i := range result {
		num, err := rand.Int(rand.Reader, big.NewInt(int64(len(charset))))
		if err != nil {
			return "", err
		}
		result[i] = charset[num.Int64()]
	}
	return string(result), nil
}

func EncodeBase64(b []byte) string {
	return base64.StdEncoding.EncodeToString(b)
}

func DecodeBase64(s string) ([]byte, error) {
	return base64.StdEncoding.DecodeString(s)
}

func ValidateMasterPassword(password string) error {
	if len(password) < 8 {
		return fmt.Errorf("password must be at least 8 characters long")
	}

	var hasUpper, hasLower, hasDigit, hasSymbol bool
	for _, char := range password {
		switch {
		case 'A' <= char && char <= 'Z':
			hasUpper = true
		case 'a' <= char && char <= 'z':
			hasLower = true
		case '0' <= char && char <= '9':
			hasDigit = true
		case strings.ContainsRune("!@#$%^&*()-_=+", char):
			hasSymbol = true
		}
	}

	if !hasUpper {
		return fmt.Errorf("password must contain at least one uppercase letter")
	}
	if !hasLower {
		return fmt.Errorf("password must contain at least one lowercase letter")
	}
	if !hasDigit {
		return fmt.Errorf("password must contain at least one digit")
	}
	if !hasSymbol {
		return fmt.Errorf("password must contain at least one symbol (!@#$%%^&*()-_=+)")
	}

	return nil
}
