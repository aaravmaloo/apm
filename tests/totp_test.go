package apm_test

import (
	"testing"

	apm "password-manager/src"
)

func TestGenerateTOTP(t *testing.T) {
	secret := "JBSWY3DPEHPK3PXP" // Standard test secret (base32)
	code, err := apm.GenerateTOTP(secret)
	if err != nil {
		t.Fatalf("Failed to generate TOTP: %v", err)
	}
	if len(code) != 6 {
		t.Errorf("Expected 6-digit code, got %d digits: %s", len(code), code)
	}
}

func TestTimeRemaining(t *testing.T) {
	remaining := apm.TimeRemaining()
	if remaining < 0 || remaining > 30 {
		t.Errorf("Invalid time remaining: %d", remaining)
	}
}
