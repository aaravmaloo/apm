package apm_test

import (
	"os"
	"testing"

	apm "password-manager/src"
)

func TestPortabilityParsers(t *testing.T) {
	vault := &apm.Vault{}

	csvData := "ENTRY,google,user@gmail.com,secretpass\nTOTP,github,GITHUBSECRET"
	os.WriteFile("test.csv", []byte(csvData), 0600)
	defer os.Remove("test.csv")

	if err := apm.ImportFromCSV(vault, "test.csv"); err != nil {
		t.Fatalf("CSV Import function error: %v", err)
	}

	if len(vault.Entries) != 1 {
		t.Errorf("Expected 1 PV entry, got %d", len(vault.Entries))
	} else if vault.Entries[0].Account != "google" {
		t.Errorf("Expected PV account 'google', got '%s'", vault.Entries[0].Account)
	}

	if len(vault.TOTPEntries) != 1 {
		t.Errorf("Expected 1 TOTP entry, got %d", len(vault.TOTPEntries))
	} else if vault.TOTPEntries[0].Account != "github" {
		t.Errorf("Expected TOTP account 'github', got '%s'", vault.TOTPEntries[0].Account)
	}

	os.Remove("test.txt")
	if err := apm.ExportToTXT(vault, "test.txt", false); err != nil {
		t.Fatalf("TXT Export function error: %v", err)
	}
	defer os.Remove("test.txt")

	newVault := &apm.Vault{}
	if err := apm.ImportFromTXT(newVault, "test.txt"); err != nil {
		t.Fatalf("TXT Import function error: %v", err)
	}
	if len(newVault.Entries) != 1 {
		t.Errorf("Expected 1 PV entry in newVault, got %d", len(newVault.Entries))
	} else if newVault.Entries[0].Password != "secretpass" {
		t.Errorf("Expected password 'secretpass', got '%s'", newVault.Entries[0].Password)
	}
}
