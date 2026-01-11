package apm

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"crypto/subtle"
	"encoding/base64"
	"fmt"
	"math/big"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	"golang.org/x/crypto/argon2"
)

const (
	ArgonTime        = 3
	ArgonMemory      = 128 * 1024
	ArgonParallelism = 4
	KeyLength        = 32
)

type Keys struct {
	EncryptionKey []byte
	AuthKey       []byte
	Validator     []byte
}

func DeriveKeys(password string, salt []byte, costMultiplier int) *Keys {
	timeParam := uint32(ArgonTime)
	memoryParam := uint32(ArgonMemory)

	if costMultiplier > 1 {
		timeParam *= uint32(costMultiplier)
		memoryParam *= uint32(costMultiplier)
	}

	keyMaterial := argon2.IDKey([]byte(password), salt, timeParam, memoryParam, ArgonParallelism, 96)

	keys := &Keys{
		EncryptionKey: make([]byte, 32),
		AuthKey:       make([]byte, 32),
		Validator:     make([]byte, 32),
	}

	copy(keys.EncryptionKey, keyMaterial[0:32])
	copy(keys.AuthKey, keyMaterial[32:64])
	copy(keys.Validator, keyMaterial[64:96])

	Wipe(keyMaterial)

	return keys
}

func DeriveLegacyKey(password string, salt []byte) []byte {
	return argon2.IDKey([]byte(password), salt, 1, 256*1024, 4, 32)
}

func Wipe(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func CalculateHMAC(data, key []byte) []byte {
	h := hmac.New(sha256.New, key)
	h.Write(data)
	return h.Sum(nil)
}

func VerifyHMAC(data, signature, key []byte) bool {
	expectedMAC := CalculateHMAC(data, key)
	return subtle.ConstantTimeCompare(signature, expectedMAC) == 1
}

func VerifyPasswordValidator(derived, stored []byte) bool {
	return subtle.ConstantTimeCompare(derived, stored) == 1
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

func GetFailureCount() int {
	exe, _ := os.Executable()
	path := filepath.Join(filepath.Dir(exe), ".apm_lock")
	data, err := os.ReadFile(path)
	if err != nil {
		return 0
	}
	count, _ := strconv.Atoi(strings.TrimSpace(string(data)))
	return count
}

func TrackFailure() {
	exe, _ := os.Executable()
	path := filepath.Join(filepath.Dir(exe), ".apm_lock")
	count := GetFailureCount()
	os.WriteFile(path, []byte(strconv.Itoa(count+1)), 0600)
}

func ClearFailures() {
	exe, _ := os.Executable()
	path := filepath.Join(filepath.Dir(exe), ".apm_lock")
	os.Remove(path)
}
