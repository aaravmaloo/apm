package apm_test

import (
	"testing"

	src "password-manager/src"
)

func TestNewSecretTypes(t *testing.T) {
	vault := &src.Vault{}

	// Test Generic Tokens (Notes/API Keys)
	vault.AddToken("Test Note", "Test Content", "SecureNote")
	tok, ok := vault.GetToken("Test Note")
	if !ok || tok.Token != "Test Content" {
		t.Errorf("Token (Note) failed: expected Test Content, got %s", tok.Token)
	}

	vault.AddToken("Test API", "Test Key", "APIKey")
	tok2, ok := vault.GetToken("Test API")
	if !ok || tok2.Token != "Test Key" {
		t.Errorf("Token (API) failed: expected Test Key, got %s", tok2.Token)
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
