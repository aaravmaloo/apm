package apm_test

import (
	"testing"

	src "password-manager/src"
)

func TestNewSecretTypes(t *testing.T) {
	vault := &src.Vault{}

	// Test Secure Notes
	vault.AddSecureNote("Test Note", "Test Content")
	note, ok := vault.GetSecureNote("Test Note")
	if !ok || note.Content != "Test Content" {
		t.Errorf("Secure Note failed: expected Test Content, got %s", note.Content)
	}

	// Test API Keys
	vault.AddAPIKey("Test API", "Test Service", "Test Key")
	apiKey, ok := vault.GetAPIKey("Test API")
	if !ok || apiKey.Key != "Test Key" {
		t.Errorf("API Key failed: expected Test Key, got %s", apiKey.Key)
	}

	// Test SSH Keys
	vault.AddSSHKey("Test SSH", "Test Private Key")
	sshKey, ok := vault.GetSSHKey("Test SSH")
	if !ok || sshKey.PrivateKey != "Test Private Key" {
		t.Errorf("SSH Key failed: expected Test Private Key, got %s", sshKey.PrivateKey)
	}

	// Test Wi-Fi
	vault.AddWiFi("Test SSID", "Test Pass", "WPA2")
	wifi, ok := vault.GetWiFi("Test SSID")
	if !ok || wifi.Password != "Test Pass" {
		t.Errorf("Wi-Fi failed: expected Test Pass, got %s", wifi.Password)
	}

	// Test Recovery Codes
	codes := []string{"code1", "code2"}
	vault.AddRecoveryCode("Test Service", codes)
	rec, ok := vault.GetRecoveryCode("Test Service")
	if !ok || len(rec.Codes) != 2 || rec.Codes[0] != "code1" {
		t.Errorf("Recovery Code failed")
	}
}
