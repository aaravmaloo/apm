package apm

import (
	"os"
	"path/filepath"
	"testing"
)

func TestChangeProfile(t *testing.T) {
	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "test_security_vault.dat")
	masterPassword := "SecurityTestPass1!"

	// Create a dummy vault
	v := &Vault{
		Entries: []Entry{},
		Profile: "standard",
	}
	data, err := EncryptVault(v, masterPassword)
	if err != nil {
		t.Fatalf("Failed to encrypt initial vault: %v", err)
	}
	if err := os.WriteFile(vaultPath, data, 0600); err != nil {
		t.Fatalf("Failed to write initial vault: %v", err)
	}

	// Test Valid Change
	err = ChangeProfile(v, "paranoid", masterPassword, vaultPath)
	if err != nil {
		t.Errorf("ChangeProfile failed: %v", err)
	}
	if v.Profile != "paranoid" {
		t.Errorf("Profile not updated in memory object")
	}

	// Verify persistence
	v2, err := loadTestVault(vaultPath, masterPassword)
	if err != nil {
		t.Fatalf("Failed to reload vault: %v", err)
	}
	if v2.Profile != "paranoid" {
		t.Errorf("Profile not updated in file")
	}

	// Test Invalid Profile
	err = ChangeProfile(v, "nonexistent", masterPassword, vaultPath)
	if err == nil {
		t.Error("Expected error for non-existent profile, got nil")
	}
}

func TestConfigureAlerts(t *testing.T) {
	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "test_alerts_vault.dat")
	masterPassword := "AlertsTestPass1!"

	v := &Vault{Entries: []Entry{}}

	// Enable Alerts
	email := "alerts@example.com"
	err := ConfigureAlerts(v, true, email, masterPassword, vaultPath)
	if err != nil {
		t.Errorf("ConfigureAlerts(true) failed: %v", err)
	}
	if !v.AlertsEnabled {
		t.Error("AlertsEnabled should be true")
	}
	if v.AlertEmail != email {
		t.Errorf("AlertEmail mismatch: got %s, want %s", v.AlertEmail, email)
	}

	// Verify persistence
	v2, err := loadTestVault(vaultPath, masterPassword)
	if err != nil {
		t.Fatalf("Failed to reload vault: %v", err)
	}
	if !v2.AlertsEnabled {
		t.Error("AlertsEnabled not persisted")
	}

	// Disable Alerts
	err = ConfigureAlerts(v, false, "", masterPassword, vaultPath)
	if err != nil {
		t.Errorf("ConfigureAlerts(false) failed: %v", err)
	}
	if v.AlertsEnabled {
		t.Error("AlertsEnabled should be false")
	}
}
