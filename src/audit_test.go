package apm

import (
	"os"
	"testing"
)

func TestAuditLog(t *testing.T) {
	tempHome := t.TempDir()
	if os.Getenv("OS") == "Windows_NT" {
		oldAppdata := os.Getenv("APPDATA")
		os.Setenv("APPDATA", tempHome)
		defer os.Setenv("APPDATA", oldAppdata)
	} else {
		oldXdg := os.Getenv("XDG_CONFIG_HOME")
		os.Setenv("XDG_CONFIG_HOME", tempHome)
		defer os.Setenv("XDG_CONFIG_HOME", oldXdg)
	}

	LogAction("AUTH_LOGIN", "User logged in")
	LogAction("VAULT_UNLOCK", "Vault was unlocked")

	logs, err := GetAuditLogs(0)
	if err != nil {
		t.Fatalf("Failed to get audit logs: %v", err)
	}

	if len(logs) != 2 {
		t.Errorf("Expected 2 logs, got %d", len(logs))
	}

	if logs[0].Action != "AUTH_LOGIN" {
		t.Errorf("Expected first log action AUTH_LOGIN, got %s", logs[0].Action)
	}

	if logs[1].Action != "VAULT_UNLOCK" {
		t.Errorf("Expected second log action VAULT_UNLOCK, got %s", logs[1].Action)
	}

	// Test limit
	logsLimited, err := GetAuditLogs(1)
	if err != nil {
		t.Fatalf("Failed to get limited logs: %v", err)
	}
	if len(logsLimited) != 1 {
		t.Errorf("Expected 1 log with limit, got %d", len(logsLimited))
	}
	if logsLimited[0].Action != "VAULT_UNLOCK" {
		t.Errorf("Expected limited log to be the latest action VAULT_UNLOCK, got %s", logsLimited[0].Action)
	}
}

func TestGetAuditLogsNoFile(t *testing.T) {
	tempHome := t.TempDir()
	if os.Getenv("OS") == "Windows_NT" {
		oldAppdata := os.Getenv("APPDATA")
		os.Setenv("APPDATA", tempHome)
		defer os.Setenv("APPDATA", oldAppdata)
	} else {
		oldXdg := os.Getenv("XDG_CONFIG_HOME")
		os.Setenv("XDG_CONFIG_HOME", tempHome)
		defer os.Setenv("XDG_CONFIG_HOME", oldXdg)
	}

	// File shouldn't exist in fresh temp dir
	logs, err := GetAuditLogs(0)
	if err != nil {
		t.Fatalf("GetAuditLogs failed on non-existent file: %v", err)
	}
	if len(logs) != 0 {
		t.Errorf("Expected 0 logs, got %d", len(logs))
	}
}
