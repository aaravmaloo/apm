package apm

import (
	"encoding/hex"
	"strings"
	"testing"
)

func TestDeriveKeys(t *testing.T) {
	password := "testpassword"
	salt := []byte("somesalt12345678")
	time := uint32(1)
	memory := uint32(64 * 1024)
	parallelism := uint8(1)

	keys := DeriveKeys(password, salt, time, memory, parallelism)

	if len(keys.EncryptionKey) != 32 {
		t.Errorf("Expected EncryptionKey length 32, got %d", len(keys.EncryptionKey))
	}
	if len(keys.AuthKey) != 32 {
		t.Errorf("Expected AuthKey length 32, got %d", len(keys.AuthKey))
	}
	if len(keys.Validator) != 32 {
		t.Errorf("Expected Validator length 32, got %d", len(keys.Validator))
	}

	// Ensure keys are derived deterministically
	keys2 := DeriveKeys(password, salt, time, memory, parallelism)
	if string(keys.EncryptionKey) != string(keys2.EncryptionKey) {
		t.Error("EncryptionKey should be deterministic")
	}
}

func TestGeneratePassword(t *testing.T) {
	length := 16
	password, err := GeneratePassword(length)
	if err != nil {
		t.Fatalf("GeneratePassword failed: %v", err)
	}
	if len(password) != length {
		t.Errorf("Expected password length %d, got %d", length, len(password))
	}
}

func TestValidateMasterPassword(t *testing.T) {
	tests := []struct {
		password string
		valid    bool
	}{
		{"Short1!", false},       // Too short
		{"nouppercase1!", false}, // No uppercase
		{"NOLOWERCASE1!", false}, // No lowercase
		{"NoDigit!", false},      // No digit
		{"NoSymbol123", false},   // No symbol
		{"ValidPass1!", true},    // Valid
		{"AnotherValid1#", true}, // Valid
	}

	for _, test := range tests {
		err := ValidateMasterPassword(test.password)
		if (err == nil) != test.valid {
			t.Errorf("ValidateMasterPassword(%q) = %v; want valid=%v", test.password, err, test.valid)
		}
	}
}

func TestGenerateRandomWords(t *testing.T) {
	word, err := GenerateRandomWords()
	if err != nil {
		t.Fatalf("GenerateRandomWords failed: %v", err)
	}
	if len(word) == 0 {
		t.Error("Generated word is empty")
	}
	// Check case (CamelCase expected effectively)
	if strings.ToLower(word) == word {
		t.Error("Generated word should contain uppercase letters (CamelCase format expected)")
	}
}

func TestGenerateRandomHex(t *testing.T) {
	length := 10
	hexStr, err := GenerateRandomHex(length)
	if err != nil {
		t.Fatalf("GenerateRandomHex failed: %v", err)
	}
	if len(hexStr) != length {
		t.Errorf("Expected hex string length %d, got %d", length, len(hexStr))
	}
	_, err = hex.DecodeString(hexStr)
	if err != nil {
		t.Errorf("Generated string is not valid hex: %v", err)
	}
}

func TestMaskEmail(t *testing.T) {
	tests := []struct {
		email    string
		expected string
	}{
		{"test@example.com", "t****@example.com"},
		{"a@b.c", "a****@b.c"},
		{"short", "****"},
		{"", "****"},
	}

	for _, test := range tests {
		result := maskEmail(test.email)
		if result != test.expected {
			t.Errorf("maskEmail(%q) = %q; want %q", test.email, result, test.expected)
		}
	}
}

func TestHMAC(t *testing.T) {
	data := []byte("hello world")
	key := []byte("secret-key")

	sig := CalculateHMAC(data, key)
	if len(sig) == 0 {
		t.Fatal("HMAC signature is empty")
	}

	if !VerifyHMAC(data, sig, key) {
		t.Error("HMAC verification failed for correct key")
	}

	if VerifyHMAC(data, sig, []byte("wrong-key")) {
		t.Error("HMAC verification should fail for wrong key")
	}
}

func TestWipe(t *testing.T) {
	b := []byte{1, 2, 3, 4, 5}
	Wipe(b)
	for i, v := range b {
		if v != 0 {
			t.Errorf("Byte at index %d not wiped: %d", i, v)
		}
	}
}

func TestBase64Utils(t *testing.T) {
	data := []byte("hello base64")
	encoded := EncodeBase64(data)
	decoded, err := DecodeBase64(encoded)
	if err != nil {
		t.Fatalf("DecodeBase64 failed: %v", err)
	}
	if string(decoded) != string(data) {
		t.Errorf("DecodeBase64 result mismatch: got %s", string(decoded))
	}
}
