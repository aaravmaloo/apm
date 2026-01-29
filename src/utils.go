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
	KeyLength = 32
)

type CryptoProfile struct {
	Name        string
	KDF         string
	Time        uint32
	Memory      uint32
	Parallelism uint8
	SaltLen     int
	NonceLen    int
}

var (
	ProfileStandard = CryptoProfile{
		Name:        "standard",
		KDF:         "argon2id",
		Time:        3,
		Memory:      64 * 1024,
		Parallelism: 2,
		SaltLen:     16,
		NonceLen:    12,
	}
	ProfileHardened = CryptoProfile{
		Name:        "hardened",
		KDF:         "argon2id",
		Time:        5,
		Memory:      256 * 1024,
		Parallelism: 4,
		SaltLen:     32,
		NonceLen:    12,
	}
	ProfileParanoid = CryptoProfile{
		Name:        "paranoid",
		KDF:         "argon2id",
		Time:        6,
		Memory:      512 * 1024,
		Parallelism: 4,
		SaltLen:     32,
		NonceLen:    24,
	}
	ProfileLegacy = CryptoProfile{
		Name:        "legacy",
		KDF:         "pbkdf2",
		Time:        600000,
		Memory:      0,
		Parallelism: 1,
		SaltLen:     16,
		NonceLen:    12,
	}
)

var Profiles = map[string]CryptoProfile{
	"standard": ProfileStandard,
	"hardened": ProfileHardened,
	"paranoid": ProfileParanoid,
	"legacy":   ProfileLegacy,
}

func GetProfile(name string) CryptoProfile {
	if p, ok := Profiles[name]; ok {
		return p
	}
	return ProfileStandard
}

type Keys struct {
	EncryptionKey []byte
	AuthKey       []byte
	Validator     []byte
}

func DeriveKeys(password string, salt []byte, time, memory uint32, parallelism uint8) *Keys {
	keyMaterial := argon2.IDKey([]byte(password), salt, time, memory, parallelism, 96)

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

func GenerateSalt(length int) ([]byte, error) {
	salt := make([]byte, length)
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
	_ = os.WriteFile(path, []byte(strconv.Itoa(count+1)), 0600)
}

func ClearFailures() {
	exe, _ := os.Executable()
	path := filepath.Join(filepath.Dir(exe), ".apm_lock")
	os.Remove(path)
}

func GenerateRandomWords() (string, error) {
	adjectives := []string{
		"Swift", "Silent", "Rapid", "Blue", "Red", "Green", "Brave", "Calm", "Eager", "Fair", "Grand", "Happy",
		"Jolly", "Kind", "Lively", "Mighty", "Noble", "Proud", "Quick", "Royal", "Sharp", "Tough", "Vivid", "Wise",
		"Amber", "Bold", "Crisp", "Daring", "Elite", "Fancy", "Giant", "Hero", "Iron", "Jade", "Keen", "Lucky",
		"Magic", "Neon", "Ocean", "Prime", "Quiet", "Rare", "Solar", "Titan", "Ultra", "Vital", "Wild", "Zeal",
	}
	nouns := []string{
		"Fox", "Hawk", "Eagle", "Bear", "Wolf", "Tiger", "Lion", "Falcon", "Owl", "Shark", "Whale", "Dolphin",
		"Raven", "Crow", "Stag", "Hares", "Panda", "Koala", "Leopard", "Cobra", "Viper", "Python", "Badger", "Otter",
		"Beacon", "Comet", "Delta", "Echo", "Flame", "Globe", "Halo", "Icon", "Jet", "Kite", "Luna", "Mars",
		"Nova", "Orbit", "Pulse", "Quest", "Rider", "Star", "Token", "Unity", "Vertex", "Wave", "Xenon", "Zone",
	}

	adjIdx, err := rand.Int(rand.Reader, big.NewInt(int64(len(adjectives))))
	if err != nil {
		return "", err
	}
	nounIdx, err := rand.Int(rand.Reader, big.NewInt(int64(len(nouns))))
	if err != nil {
		return "", err
	}

	return fmt.Sprintf("%s%s", adjectives[adjIdx.Int64()], nouns[nounIdx.Int64()]), nil
}
func GenerateRandomHex(n int) (string, error) {
	bytes := make([]byte, n/2)
	if _, err := rand.Read(bytes); err != nil {
		return "", err
	}
	return fmt.Sprintf("%x", bytes), nil
}
