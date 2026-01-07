package apm

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	// Crypto Constants
	ArgonTime        = 3
	ArgonMemory      = 128 * 1024 // 128 MB
	ArgonParallelism = 4
	SaltSize         = 16
	KeySize          = 32
	NonceSize        = 12
	ValidatorSize    = 32
)

// Keys holds the derived keys for various operations
type Keys struct {
	EncryptionKey []byte
	AuthKey       []byte // For HMAC
	Validator     []byte // To verify password without decrypting
}

// DeriveKeys generates all necessary keys from the master password and salt
// We generate 96 bytes: 32 enc + 32 auth + 32 validator
func DeriveKeys(password string, salt []byte) *Keys {
	keyMaterial := argon2.IDKey([]byte(password), salt, ArgonTime, ArgonMemory, ArgonParallelism, 96)
	
	keys := &Keys{
		EncryptionKey: keyMaterial[0:32],
		AuthKey:       keyMaterial[32:64],
		Validator:     keyMaterial[64:96],
	}
	
	// Zero out the keyMaterial buffer immediately after copying (best effort)
	Wipe(keyMaterial)
	
	return keys
}

// GenerateSalt creates a new random salt
func GenerateSalt() ([]byte, error) {
	salt := make([]byte, SaltSize)
	_, err := rand.Read(salt)
	return salt, err
}

// CalculateHMAC computes the HMAC-SHA256 of the data using the AuthKey
func CalculateHMAC(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

// VerifyHMAC checks if the data matches the provided signature
func VerifyHMAC(data, signature, key []byte) bool {
	expectedMAC := CalculateHMAC(data, key)
	return subtle.ConstantTimeCompare(signature, expectedMAC) == 1
}

// VerifyPasswordValidator checks if the derived validator matches the stored one
func VerifyPasswordValidator(derived, stored []byte) bool {
	return subtle.ConstantTimeCompare(derived, stored) == 1
}

// Wipe attempts to zero out a byte slice
func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
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
