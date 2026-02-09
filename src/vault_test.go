package apm

import (
	"os"
	"path/filepath"
	"testing"
)

// Helper to save vault for testing
func saveTestVault(v *Vault, password, path string) error {
	data, err := v.Serialize(password)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
}

// Helper to load vault for testing
func loadTestVault(path, password string) (*Vault, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	return DecryptVault(data, password, 1)
}

func TestVaultOperations(t *testing.T) {
	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "test_vault.dat")
	password := "securepassword"

	t.Run("Create and Save Vault", func(t *testing.T) {
		v := &Vault{
			Entries: []Entry{
				{
					Account:  "Test Entry",
					Username: "user",
					Password: "password",
				},
			},
		}

		err := saveTestVault(v, password, vaultPath)
		if err != nil {
			t.Fatalf("Failed to save vault: %v", err)
		}

		if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
			t.Errorf("Vault file was not created at %s", vaultPath)
		}
	})

	t.Run("Load and Decrypt Vault", func(t *testing.T) {
		v, err := loadTestVault(vaultPath, password)
		if err != nil {
			t.Fatalf("Failed to load vault: %v", err)
		}

		if len(v.Entries) != 1 {
			t.Errorf("Expected 1 entry, got %d", len(v.Entries))
		}

		entry := v.Entries[0]
		if entry.Account != "Test Entry" {
			t.Errorf("Expected Account 'Test Entry', got '%s'", entry.Account)
		}
		if entry.Password != "password" {
			t.Errorf("Expected password 'password', got '%s'", entry.Password)
		}
	})

	t.Run("Load with Wrong Password", func(t *testing.T) {
		_, err := loadTestVault(vaultPath, "wrongpassword")
		if err == nil {
			t.Error("Expected error when loading with wrong password, got nil")
		}
	})

	t.Run("Add Entry", func(t *testing.T) {
		v, err := loadTestVault(vaultPath, password)
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
		err = saveTestVault(v, password, vaultPath)
		if err != nil {
			t.Fatalf("Failed to save vault: %v", err)
		}

		v2, err := loadTestVault(vaultPath, password)
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
		v, err := loadTestVault(vaultPath, password)
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

	// Detailed tests for other types
	t.Run("TOTP Operations", func(t *testing.T) {
		v, _ := loadTestVault(vaultPath, password)
		err := v.AddTOTPEntry("Google", "SECRET123")
		if err != nil {
			t.Fatalf("Failed to add TOTP: %v", err)
		}

		totp, found := v.GetTOTPEntry("Google")
		if !found || totp.Secret != "SECRET123" {
			t.Error("TOTP retrieval failed")
		}

		if !v.DeleteTOTPEntry("Google") {
			t.Error("TOTP deletion failed")
		}
	})

	t.Run("Secure Note Operations", func(t *testing.T) {
		v, _ := loadTestVault(vaultPath, password)
		err := v.AddSecureNote("MyNote", "Secret Content")
		if err != nil {
			t.Fatalf("Failed to add note: %v", err)
		}

		note, found := v.GetSecureNote("MyNote")
		if !found || note.Content != "Secret Content" {
			t.Error("Note retrieval failed")
		}

		if !v.DeleteSecureNote("MyNote") {
			t.Error("Note deletion failed")
		}
	})
}

func FuzzDecryptVault(f *testing.F) {
	// Seed corpus with valid vault header
	f.Add([]byte(VaultHeader+"\x00"), "password123")
	f.Add([]byte(VaultHeader), "password123")
	f.Add([]byte("notavaultatall"), "password123")

	// Prepare a small valid wrapped vault for fuzzing structure
	v := &Vault{Entries: []Entry{{Account: "A", Password: "B"}}}
	validData, _ := v.Serialize("pass")
	if len(validData) > 0 {
		f.Add(validData, "pass")
	}

	f.Fuzz(func(t *testing.T, data []byte, password string) {
		// Just ensure it doesn't panic
		_, _ = DecryptVault(data, password, 1)

		// Also try verifying validator independently if possible,
		// but DecryptVault covers the whole flow.
	})
}

// Add checks for Encryption/Decryption round trip with heavy fuzzing data?
// Fuzzing mainly checks for crashes on bad input.
// We can add property-based testing here too if desired.
func TestVaultRoundTripProperty(t *testing.T) {
	v := &Vault{
		Entries: []Entry{
			{Account: "Acc1", Username: "User1", Password: "Pass1"},
		},
		SecureNotes: []SecureNoteEntry{
			{Name: "Note1", Content: "Content1"},
		},
	}
	pass := "Testing123!"

	data, err := v.Serialize(pass)
	if err != nil {
		t.Fatalf("Serialize failed: %v", err)
	}

	v2, err := DecryptVault(data, pass, 1)
	if err != nil {
		t.Fatalf("Decrypt failed: %v", err)
	}

	// verify contents
	// Note: DeepEqual might fail used directly due to unexported fields or pointer differences,
	// but JSON comparison is a decent proxy for data integrity here,
	// excluding transient fields like CurrentProfileParams or derived fields.
	// Actually v2 will have derived fields populated.
	// Let's check specific data points.

	if len(v.Entries) != len(v2.Entries) {
		t.Errorf("Entries count mismatch")
	}
	if v.Entries[0].Account != v2.Entries[0].Account {
		t.Errorf("Entry mismatch")
	}
}
