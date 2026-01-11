package apm_test

import (
	"testing"
	"time"

	src "password-manager/src"
)

func TestNewSecretTypes(t *testing.T) {
	vault := &src.Vault{}

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

	vault.AddSSHKey("Test SSH", "Test Private Key")
	sshKey, ok := vault.GetSSHKey("Test SSH")
	if !ok || sshKey.PrivateKey != "Test Private Key" {
		t.Errorf("SSH Key failed: expected Test Private Key, got %s", sshKey.PrivateKey)
	}

	vault.AddWiFi("Test SSID", "Test Pass", "WPA2")
	wifi, ok := vault.GetWiFi("Test SSID")
	if !ok || wifi.Password != "Test Pass" {
		t.Errorf("Wi-Fi failed: expected Test Pass, got %s", wifi.Password)
	}

	codes := []string{"code1", "code2"}
	vault.AddRecoveryCode("Test Service", codes)
	rec, ok := vault.GetRecoveryCode("Test Service")
	if !ok || len(rec.Codes) != 2 || rec.Codes[0] != "code1" {
		t.Errorf("Recovery Code failed")
	}


	expiry := time.Now().Add(24 * time.Hour)
	vault.AddCertificate("Test Cert", "CERT DATA", "KEY DATA", "Test Issuer", expiry)
	cert, ok := vault.GetCertificate("Test Cert")
	if !ok || cert.Issuer != "Test Issuer" {
		t.Errorf("Certificate failed")
	}


	vault.AddBankingItem("Test Card", "Card", "1234567812345678", "123", "12/25")
	bank, ok := vault.GetBankingItem("Test Card")
	if !ok || bank.Details != "1234567812345678" {
		t.Errorf("Banking item failed")
	}


	vault.AddDocument("Test Doc", "test.pdf", []byte("pdf content"), "docpass")
	doc, ok := vault.GetDocument("Test Doc")
	if !ok || string(doc.Content) != "pdf content" {
		t.Errorf("Document failed")
	}
}