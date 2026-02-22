package apm

import (
	"bytes"
	"path/filepath"
	"testing"
)

func TestVaultEncryptDecryptRoundTrip(t *testing.T) {
	t.Parallel()

	masterPassword := "ValidPass123!"
	v := &Vault{
		Profile: "standard",
		Spaces:  []string{"default"},
	}

	if err := v.AddEntry("github", "alice", "s3cret"); err != nil {
		t.Fatalf("AddEntry failed: %v", err)
	}
	if err := v.AddSecureNote("note-1", "hello world"); err != nil {
		t.Fatalf("AddSecureNote failed: %v", err)
	}

	data, err := EncryptVault(v, masterPassword)
	if err != nil {
		t.Fatalf("EncryptVault failed: %v", err)
	}

	profile, version, err := GetVaultParams(data)
	if err != nil {
		t.Fatalf("GetVaultParams failed: %v", err)
	}
	if version != int(CurrentVersion) {
		t.Fatalf("expected version %d, got %d", CurrentVersion, version)
	}
	if profile.Name == "" {
		t.Fatal("expected profile name in vault header")
	}

	roundTrip, err := DecryptVault(data, masterPassword, 1)
	if err != nil {
		t.Fatalf("DecryptVault failed: %v", err)
	}

	entry, ok := roundTrip.GetEntry("github")
	if !ok {
		t.Fatal("expected entry to exist after decryption")
	}
	if entry.Username != "alice" || entry.Password != "s3cret" {
		t.Fatalf("unexpected entry after decryption: %+v", entry)
	}

	results := roundTrip.SearchAll("git")
	if len(results) == 0 {
		t.Fatal("expected search results after decryption")
	}
}

func TestVaultDecryptWrongPasswordFails(t *testing.T) {
	t.Parallel()

	v := &Vault{Profile: "standard"}
	data, err := EncryptVault(v, "ValidPass123!")
	if err != nil {
		t.Fatalf("EncryptVault failed: %v", err)
	}

	if _, err := DecryptVault(data, "WrongPass123!", 1); err == nil {
		t.Fatal("expected decryption failure with wrong password")
	}
}

func TestStorageSaveLoadExists(t *testing.T) {
	t.Parallel()

	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "vault.dat")
	payload := []byte("vault-bytes")

	if VaultExists(vaultPath) {
		t.Fatal("vault should not exist before save")
	}
	if err := SaveVault(vaultPath, payload); err != nil {
		t.Fatalf("SaveVault failed: %v", err)
	}
	if !VaultExists(vaultPath) {
		t.Fatal("vault should exist after save")
	}

	loaded, err := LoadVault(vaultPath)
	if err != nil {
		t.Fatalf("LoadVault failed: %v", err)
	}
	if !bytes.Equal(loaded, payload) {
		t.Fatalf("loaded payload mismatch: got=%q want=%q", loaded, payload)
	}
}

func TestVaultSpaceIsolation(t *testing.T) {
	t.Parallel()

	v := &Vault{
		Profile: "standard",
		Spaces:  []string{"default", "work"},
	}

	if err := v.AddEntry("account", "default-user", "default-pass"); err != nil {
		t.Fatalf("AddEntry(default) failed: %v", err)
	}

	v.CurrentSpace = "work"
	if err := v.AddEntry("account", "work-user", "work-pass"); err != nil {
		t.Fatalf("AddEntry(work) failed: %v", err)
	}

	v.CurrentSpace = ""
	eDefault, ok := v.GetEntry("account")
	if !ok || eDefault.Username != "default-user" {
		t.Fatalf("expected default-space entry, got %+v, ok=%v", eDefault, ok)
	}

	v.CurrentSpace = "work"
	eWork, ok := v.GetEntry("account")
	if !ok || eWork.Username != "work-user" {
		t.Fatalf("expected work-space entry, got %+v, ok=%v", eWork, ok)
	}

	if got := len(v.SearchAll("account")); got != 1 {
		t.Fatalf("expected exactly 1 result in active space, got %d", got)
	}
}
