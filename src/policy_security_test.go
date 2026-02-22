package apm

import (
	"path/filepath"
	"testing"
)

func TestPasswordPolicyValidate(t *testing.T) {
	policy := PasswordPolicy{
		MinLength:      10,
		RequireUpper:   true,
		RequireNumbers: true,
		RequireSymbols: true,
	}

	if err := policy.Validate("short"); err == nil {
		t.Fatal("expected short password validation error")
	}
	if err := policy.Validate("longpassword1!"); err == nil {
		t.Fatal("expected uppercase validation error")
	}
	if err := policy.Validate("Longpassword!!"); err == nil {
		t.Fatal("expected number validation error")
	}
	if err := policy.Validate("Longpassword1"); err == nil {
		t.Fatal("expected symbol validation error")
	}
	if err := policy.Validate("LongPass1!!"); err != nil {
		t.Fatalf("expected valid password, got error: %v", err)
	}
}

func TestLoadPolicies(t *testing.T) {
	tempDir := t.TempDir()

	validPath := filepath.Join(tempDir, "valid.yml")
	validPolicy := `
name: "strict"
password_policy:
  min_length: 14
  require_uppercase: true
  require_numbers: true
  require_symbols: true
`
	if err := SaveVault(validPath, []byte(validPolicy)); err != nil {
		t.Fatalf("failed to write valid policy: %v", err)
	}

	invalidPath := filepath.Join(tempDir, "invalid.yml")
	if err := SaveVault(invalidPath, []byte("name: [")); err != nil {
		t.Fatalf("failed to write invalid policy: %v", err)
	}

	policies, err := LoadPolicies(tempDir)
	if err != nil {
		t.Fatalf("LoadPolicies failed: %v", err)
	}
	if len(policies) != 1 {
		t.Fatalf("expected 1 valid policy, got %d", len(policies))
	}
	if policies[0].Name != "strict" {
		t.Fatalf("unexpected policy name: %q", policies[0].Name)
	}

	missingDir := filepath.Join(tempDir, "does-not-exist")
	policies, err = LoadPolicies(missingDir)
	if err != nil {
		t.Fatalf("expected nil error for missing policy dir, got %v", err)
	}
	if len(policies) != 0 {
		t.Fatalf("expected no policies for missing dir, got %d", len(policies))
	}
}

func TestChangeProfileAndConfigureAlerts(t *testing.T) {
	profileName := "fast_test_profile"
	AddCustomProfile(CryptoProfile{
		Name:        profileName,
		KDF:         "argon2id",
		Time:        1,
		Memory:      8 * 1024,
		Parallelism: 1,
		SaltLen:     16,
		NonceLen:    12,
	})
	defer delete(Profiles, profileName)

	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "vault.dat")
	masterPassword := "ValidPass123!"

	v := &Vault{
		Profile: "standard",
		Spaces:  []string{"default"},
	}

	enc, err := EncryptVault(v, masterPassword)
	if err != nil {
		t.Fatalf("EncryptVault failed: %v", err)
	}
	if err := SaveVault(vaultPath, enc); err != nil {
		t.Fatalf("SaveVault failed: %v", err)
	}

	if err := ChangeProfile(v, profileName, masterPassword, vaultPath); err != nil {
		t.Fatalf("ChangeProfile failed: %v", err)
	}

	raw, err := LoadVault(vaultPath)
	if err != nil {
		t.Fatalf("LoadVault failed: %v", err)
	}
	updated, err := DecryptVault(raw, masterPassword, 1)
	if err != nil {
		t.Fatalf("DecryptVault failed after ChangeProfile: %v", err)
	}
	if updated.Profile != profileName {
		t.Fatalf("expected profile %q, got %q", profileName, updated.Profile)
	}

	if err := ConfigureAlerts(updated, true, "alice@example.com", masterPassword, vaultPath); err != nil {
		t.Fatalf("ConfigureAlerts failed: %v", err)
	}

	raw, err = LoadVault(vaultPath)
	if err != nil {
		t.Fatalf("LoadVault failed after ConfigureAlerts: %v", err)
	}
	withAlerts, err := DecryptVault(raw, masterPassword, 1)
	if err != nil {
		t.Fatalf("DecryptVault failed after ConfigureAlerts: %v", err)
	}
	if !withAlerts.AlertsEnabled {
		t.Fatal("expected alerts to be enabled")
	}
	if withAlerts.AlertEmail != "alice@example.com" {
		t.Fatalf("expected alert email to persist, got %q", withAlerts.AlertEmail)
	}
}

func TestMaskEmail(t *testing.T) {
	if got := maskEmail("alice@example.com"); got != "a****@example.com" {
		t.Fatalf("unexpected masked email: %q", got)
	}
	if got := maskEmail("bad"); got != "****" {
		t.Fatalf("unexpected mask for short email: %q", got)
	}
	if got := maskEmail("invalid-email"); got != "****" {
		t.Fatalf("unexpected mask for malformed email: %q", got)
	}
}
