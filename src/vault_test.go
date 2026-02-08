package apm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestVaultOperations(t *testing.T) {
	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "test_vault.dat")
	password := "securepassword"

	t.Run("Create and Save Vault", func(t *testing.T) {
		v := &Vault{
			Entries: []Entry{
				{
					Title:    "Test Entry",
					Username: "user",
					Password: "password",
					URL:      "http://example.com",
					Notes:    "Some notes",
				},
			},
		}

		err := saveVault(v, password, vaultPath)
		if err != nil {
			t.Fatalf("Failed to save vault: %v", err)
		}

		if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
			t.Errorf("Vault file was not created at %s", vaultPath)
		}
	})

	t.Run("Load and Decrypt Vault", func(t *testing.T) {
		v, err := loadVault(vaultPath, password)
		if err != nil {
			t.Fatalf("Failed to load vault: %v", err)
		}

		if len(v.Entries) != 1 {
			t.Errorf("Expected 1 entry, got %d", len(v.Entries))
		}

		entry := v.Entries[0]
		if entry.Title != "Test Entry" {
			t.Errorf("Expected title 'Test Entry', got '%s'", entry.Title)
		}
		if entry.Password != "password" {
			t.Errorf("Expected password 'password', got '%s'", entry.Password)
		}
	})

	t.Run("Load with Wrong Password", func(t *testing.T) {
		_, err := loadVault(vaultPath, "wrongpassword")
		if err == nil {
			t.Error("Expected error when loading with wrong password, got nil")
		}
	})

	t.Run("Add Entry", func(t *testing.T) {
		v, err := loadVault(vaultPath, password)
		if err != nil {
			t.Fatalf("Failed to load vault: %v", err)
		}

		err = v.AddEntry("New Entry", "newuser", "newpass")
		if err != nil {
			t.Fatalf("Failed to add entry: %v", err)
		}

		// Verify in memory
		entry, found := v.GetEntry("New Entry")
		if !found {
			t.Error("New entry not found in memory")
		}
		if entry.Username != "newuser" {
			t.Errorf("Expected username 'newuser', got '%s'", entry.Username)
		}

		// Save and reload to verify persistence
		err = saveVault(v, password, vaultPath)
		if err != nil {
			t.Fatalf("Failed to save vault: %v", err)
		}

		v2, err := loadVault(vaultPath, password)
		if err != nil {
			t.Fatalf("Failed to reload vault: %v", err)
		}
		entry2, found := v2.GetEntry("New Entry")
		if !found {
			t.Error("New entry not found after reload")
		}
		if entry2.Username != "newuser" {
			t.Errorf("Expected username 'newuser' after reload, got '%s'", entry2.Username)
		}
	})

	t.Run("Delete Entry", func(t *testing.T) {
		v, err := loadVault(vaultPath, password)
		if err != nil {
			t.Fatalf("Failed to load vault: %v", err)
		}

		deleted := v.DeleteEntry("Test Entry")
		if !deleted {
			t.Error("Failed to delete existing entry")
		}

		_, found := v.GetEntry("Test Entry")
		if found {
			t.Error("Entry should not be found after deletion")
		}

		deleted = v.DeleteEntry("Non Existent")
		if deleted {
			t.Error("DeleteEntry should return false for non-existent entry")
		}
	})
}

func FuzzDecryptVault(f *testing.F) {
	f.Add([]byte(VaultHeader+"\x00"), "password123")
	f.Add([]byte(VaultHeader), "password123")
	f.Add([]byte("notavaultatall"), "password123")

	f.Fuzz(func(t *testing.T, data []byte, password string) {
		_, _ = DecryptVault(data, password, 1)
	})
}