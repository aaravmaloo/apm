package apm

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"strings"
	"path/filepath"
	"testing"
	"time"
)

// ---------------------------------------------------------------------------
// AuthKey-based history HMAC signing tests (Bug #5 fix)
// ---------------------------------------------------------------------------

// TestAuthKeyHistorySigning verifies that history entries are signed using the
// derived AuthKey (not the public salt) and that VerifyHistoryEntrySignature
// correctly validates with AuthKey and falls back to salt for legacy entries.
func TestAuthKeyHistorySigning(t *testing.T) {
	authKey := []byte("this-is-a-32-byte-auth-key-for-te")
	salt := []byte("0123456789abcdef")

	v := &Vault{
		Profile: "standard",
		Spaces:  []string{"default"},
		AuthKey: authKey,
		Salt:    salt,
	}

	if err := v.AddEntry("test-account", "user", "pass"); err != nil {
		t.Fatalf("AddEntry failed: %v", err)
	}

	if len(v.History) != 1 {
		t.Fatalf("expected 1 history entry, got %d", len(v.History))
	}

	entry := v.History[0]

	t.Run("validates-with-correct-authKey", func(t *testing.T) {
		if !VerifyHistoryEntrySignature(authKey, salt, entry) {
			t.Fatal("expected signature to verify with correct AuthKey")
		}
	})

	t.Run("fails-with-wrong-authKey", func(t *testing.T) {
		wrongKey := []byte("this-is-a-different-key-for-test")
		if VerifyHistoryEntrySignature(wrongKey, nil, entry) {
			t.Fatal("expected signature to fail with wrong AuthKey")
		}
	})

	t.Run("fails-with-wrong-authKey-no-salt", func(t *testing.T) {
		wrongKey := []byte("this-is-a-different-key-for-test")
		if VerifyHistoryEntrySignature(wrongKey, []byte("different-salt"), entry) {
			t.Fatal("expected signature to fail with both wrong keys")
		}
	})

	t.Run("authkey-signed-fails-with-salt-only", func(t *testing.T) {
		// Entry was signed with AuthKey, so salt alone should NOT verify it.
		if VerifyHistoryEntrySignature(nil, salt, entry) {
			t.Fatal("expected AuthKey-signed entry to NOT verify with salt only")
		}
	})

	t.Run("fails-with-no-keys", func(t *testing.T) {
		if VerifyHistoryEntrySignature(nil, nil, entry) {
			t.Fatal("expected signature to fail with no keys")
		}
	})
}

// TestHistoryChainVerification tests that the full history chain validates
// correctly and tampered entries are detected.
func TestHistoryChainVerification(t *testing.T) {
	authKey := []byte("this-is-a-32-byte-auth-key-for-te2")
	salt := []byte("fedcba9876543210")

	v := &Vault{
		Profile: "standard",
		Spaces:  []string{"default"},
		AuthKey: authKey,
		Salt:    salt,
	}

	// Build a history chain of 3 operations
	if err := v.AddEntry("account-1", "user1", "pass1"); err != nil {
		t.Fatalf("AddEntry 1 failed: %v", err)
	}
	if err := v.AddEntry("account-2", "user2", "pass2"); err != nil {
		t.Fatalf("AddEntry 2 failed: %v", err)
	}
	if err := v.AddSecureNote("note-1", "content"); err != nil {
		t.Fatalf("AddSecureNote failed: %v", err)
	}

	if len(v.History) != 3 {
		t.Fatalf("expected 3 history entries, got %d", len(v.History))
	}

	t.Run("all-entries-valid-in-chain", func(t *testing.T) {
		results := VerifyHistoryChain(v)
		for i, ok := range results {
			if !ok {
				t.Fatalf("expected history entry %d to be valid", i)
			}
		}
	})

	t.Run("tampered-hash-detected", func(t *testing.T) {
		v.History[1].Hash = "tampered"
		results := VerifyHistoryChain(v)
		if results[1] {
			t.Fatal("expected tampered entry to be invalid")
		}
		if results[2] {
			t.Fatal("expected entry after tampered to be invalid (chain broken)")
		}
	})
}

// TestHistoryChainEmptyVault tests that an empty vault has no history issues.
func TestHistoryChainEmptyVault(t *testing.T) {
	v := &Vault{
		Profile: "standard",
		AuthKey: []byte("this-is-a-32-byte-auth-key-for-te3"),
		Salt:    []byte("abcdef0123456789"),
	}

	results := VerifyHistoryChain(v)
	if len(results) != 0 {
		t.Fatalf("expected empty results for empty vault, got %d", len(results))
	}
}

// TestHistoryBackwardCompatSaltOnly verifies that history entries signed with
// the old salt-based HMAC still verify after the AuthKey upgrade.
func TestHistoryBackwardCompatSaltOnly(t *testing.T) {
	authKey := []byte("new-auth-key-for-testing-purpose")
	salt := []byte("legacy-salt-value-1234567")

	// Manually create a history entry signed with the old salt-based HMAC
	entry := HistoryEntry{
		Timestamp:  time.Now(),
		Action:     "ADD",
		Category:   "PASSWORD",
		Identifier: "legacy-account",
		PrevHash:   "",
	}

	data := fmt.Sprintf("%d:%s:%s:%s:%s", entry.Timestamp.UnixNano(), entry.Action, entry.Category, entry.Identifier, entry.PrevHash)
	hash := sha256.Sum256([]byte(data))
	entry.Hash = hex.EncodeToString(hash[:])

	// Sign with salt (old method)
	mac := hmac.New(sha256.New, salt)
	mac.Write([]byte(entry.Hash))
	entry.Signature = hex.EncodeToString(mac.Sum(nil))

	t.Run("verifies-with-salt-fallback", func(t *testing.T) {
		if !VerifyHistoryEntrySignature(authKey, salt, entry) {
			t.Fatal("expected legacy salt-signed entry to verify with salt fallback")
		}
	})

	t.Run("verifies-with-salt-only", func(t *testing.T) {
		if !VerifyHistoryEntrySignature(nil, salt, entry) {
			t.Fatal("expected legacy salt-signed entry to verify with salt only")
		}
	})

	t.Run("fails-with-authkey-only", func(t *testing.T) {
		if VerifyHistoryEntrySignature(authKey, nil, entry) {
			t.Fatal("expected legacy salt-signed entry to NOT verify with AuthKey only")
		}
	})
}

// TestDecryptVaultSetsAuthKeyOnVault verifies that after a full encrypt-then-
// decrypt round trip, the decrypted vault has a non-empty AuthKey that can
// successfully validate new history signatures.
func TestDecryptVaultSetsAuthKeyOnVault(t *testing.T) {
	masterPassword := "ValidPass123!"

	// Encrypt a fresh vault
	v := &Vault{Profile: "standard", Spaces: []string{"default"}}
	if err := v.AddEntry("test", "user", "pass"); err != nil {
		t.Fatalf("AddEntry failed: %v", err)
	}

	data, err := EncryptVault(v, masterPassword)
	if err != nil {
		t.Fatalf("EncryptVault failed: %v", err)
	}

	// Decrypt it
	decrypted, err := DecryptVault(data, masterPassword, 1)
	if err != nil {
		t.Fatalf("DecryptVault failed: %v", err)
	}

	// AuthKey should be non-nil and non-empty
	if len(decrypted.AuthKey) == 0 {
		t.Fatal("expected AuthKey to be set after decryption")
	}

	// Adding a new entry should create an AuthKey-validated history entry
	decrypted.AddEntry("new-entry", "new-user", "new-pass")
	entry := decrypted.History[len(decrypted.History)-1]

	if !VerifyHistoryEntrySignature(decrypted.AuthKey, decrypted.Salt, entry) {
		t.Fatal("expected new history entry to verify with AuthKey from decrypted vault")
	}
}

// ---------------------------------------------------------------------------
// ImportFromJSON wrong-password error tests (Bug #9 fix)
// ---------------------------------------------------------------------------

// TestImportFromJSONWrongPassword verifies that ImportFromJSON returns the
// decryption error when an incorrect password is provided for encrypted data.
func TestImportFromJSONWrongPassword(t *testing.T) {
	tempDir := t.TempDir()

	exportData := ExportData{
		Entries: []Entry{
			{Account: "test", Username: "user", Password: "secret"},
		},
		TOTPEntries: []TOTPEntry{
			{Account: "totp-test", Secret: "JBSWY3DPEHPK3PXP"},
		},
	}

	jsonBytes, err := json.Marshal(exportData)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	correctPass := "CorrectPass123!"
	wrongPass := "WrongPass123!"

	// Encrypt the data
	encrypted, err := EncryptData(jsonBytes, correctPass)
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	encPath := filepath.Join(tempDir, "encrypted.json")
	if err := os.WriteFile(encPath, encrypted, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	t.Run("wrong-password-returns-error", func(t *testing.T) {
		v := &Vault{Profile: "standard", Spaces: []string{"default"}}
		err = ImportFromJSON(v, encPath, wrongPass)
		if err == nil {
			t.Fatal("expected error when importing with wrong password")
		}
		// Should mention decryption failure
		if !strings.Contains(err.Error(), "decryption failed") {
			t.Fatalf("expected decryption failure error, got: %v", err)
		}
	})

	t.Run("correct-password-imports-successfully", func(t *testing.T) {
		v2 := &Vault{Profile: "standard", Spaces: []string{"default"}}
		err = ImportFromJSON(v2, encPath, correctPass)
		if err != nil {
			t.Fatalf("unexpected error with correct password: %v", err)
		}
		if len(v2.Entries) != 1 || v2.Entries[0].Account != "test" {
			t.Fatal("expected imported entry to exist")
		}
		if len(v2.TOTPEntries) != 1 || v2.TOTPEntries[0].Account != "totp-test" {
			t.Fatal("expected imported TOTP entry to exist")
		}
	})
}

// TestImportFromJSONPlaintextWithPassword verifies that importing a plaintext
// (unencrypted) file with a password provided still works (backward compat).
func TestImportFromJSONPlaintextWithPassword(t *testing.T) {
	tempDir := t.TempDir()

	exportData := ExportData{
		Entries: []Entry{
			{Account: "plain", Username: "user", Password: "secret"},
		},
	}

	jsonBytes, err := json.Marshal(exportData)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	jsonPath := filepath.Join(tempDir, "plain.json")
	if err := os.WriteFile(jsonPath, jsonBytes, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// Providing a password for a plaintext file should still work
	v := &Vault{Profile: "standard", Spaces: []string{"default"}}
	err = ImportFromJSON(v, jsonPath, "SomePassword")
	if err != nil {
		t.Fatalf("unexpected error when importing plaintext with password: %v", err)
	}
	if len(v.Entries) != 1 || v.Entries[0].Account != "plain" {
		t.Fatal("expected imported entry to exist")
	}
}

// TestImportFromJSONNoPassword verifies importing an encrypted file without
// a password fails since the binary data is not valid JSON.
func TestImportFromJSONEncryptedNoPassword(t *testing.T) {
	tempDir := t.TempDir()

	exportData := ExportData{
		Entries: []Entry{
			{Account: "test", Username: "user", Password: "secret"},
		},
	}

	jsonBytes, err := json.Marshal(exportData)
	if err != nil {
		t.Fatalf("json.Marshal failed: %v", err)
	}

	encrypted, err := EncryptData(jsonBytes, "CorrectPass123!")
	if err != nil {
		t.Fatalf("EncryptData failed: %v", err)
	}

	encPath := filepath.Join(tempDir, "encrypted.json")
	if err := os.WriteFile(encPath, encrypted, 0600); err != nil {
		t.Fatalf("WriteFile failed: %v", err)
	}

	// No password provided — encrypted binary won't parse as JSON
	v := &Vault{Profile: "standard", Spaces: []string{"default"}}
	err = ImportFromJSON(v, encPath, "")
	if err == nil {
		t.Fatal("expected error when importing encrypted file without password")
	}
}


