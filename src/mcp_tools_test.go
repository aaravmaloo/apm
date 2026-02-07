package apm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMCPToolsBasic(t *testing.T) {
	vaultPath := "test_mcp_tools_vault.dat"
	os.Remove(vaultPath)
	defer os.Remove(vaultPath)

	v := &Vault{Entries: []Entry{}}
	if err := saveVault(v, "masterpass", vaultPath); err != nil {
		t.Fatalf("Failed to create test vault: %v", err)
	}

	os.Setenv("APM_SESSION_ID", "mcptoolstest")
	sessionFile := filepath.Join(os.TempDir(), "pm_session_mcptoolstest.json")
	sessionParams := Session{
		MasterPassword:	"masterpass",
		Expiry:	time.Now().Add(1 * time.Hour),
		LastUsed:	time.Now(),
		InactivityTimeout:	1 * time.Hour,
	}
	sessData, _ := json.Marshal(sessionParams)
	os.WriteFile(sessionFile, sessData, 0600)
	defer os.Remove(sessionFile)
	defer os.Unsetenv("APM_SESSION_ID")

	t.Run("UnlockVault", func(t *testing.T) {
		vault, pwd, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			t.Fatalf("Failed to unlock vault: %v", err)
		}
		if vault == nil {
			t.Fatal("Vault is nil")
		}
		if pwd != "masterpass" {
			t.Errorf("Expected master password 'masterpass', got '%s'", pwd)
		}
	})

	t.Run("AddAndListEntry", func(t *testing.T) {
		vault, pwd, _ := unlockVaultForMCP(vaultPath)

		err := vault.AddEntry("TestAccount", "testuser", "testpass123")
		if err != nil {
			t.Fatalf("Failed to add entry: %v", err)
		}

		if err := saveVault(vault, pwd, vaultPath); err != nil {
			t.Fatalf("Failed to save vault: %v", err)
		}

		vault2, _, _ := unlockVaultForMCP(vaultPath)
		entry, found := vault2.GetEntry("TestAccount")
		if !found {
			t.Fatal("Entry not found after save/reload")
		}
		if entry.Username != "testuser" {
			t.Errorf("Expected username 'testuser', got '%s'", entry.Username)
		}
	})

	t.Run("DeleteEntry", func(t *testing.T) {
		vault, pwd, _ := unlockVaultForMCP(vaultPath)

		deleted := vault.DeleteEntry("TestAccount")
		if !deleted {
			t.Fatal("Failed to delete entry")
		}

		if err := saveVault(vault, pwd, vaultPath); err != nil {
			t.Fatalf("Failed to save vault: %v", err)
		}

		vault2, _, _ := unlockVaultForMCP(vaultPath)
		_, found := vault2.GetEntry("TestAccount")
		if found {
			t.Fatal("Entry should not exist after deletion")
		}
	})
}

func TestMCPAuditLogs(t *testing.T) {
	auditFile := getAuditFile()
	os.Remove(auditFile)
	defer os.Remove(auditFile)

	LogAction("TEST_ACTION_1", "Test details 1")
	LogAction("TEST_ACTION_2", "Test details 2")
	LogAction("TEST_ACTION_3", "Test details 3")

	logs, err := GetAuditLogs(0)
	if err != nil {
		t.Fatalf("Failed to get audit logs: %v", err)
	}
	if len(logs) != 3 {
		t.Errorf("Expected 3 logs, got %d", len(logs))
	}

	logsLimited, err := GetAuditLogs(2)
	if err != nil {
		t.Fatalf("Failed to get limited audit logs: %v", err)
	}
	if len(logsLimited) != 2 {
		t.Errorf("Expected 2 logs with limit, got %d", len(logsLimited))
	}

	if logsLimited[0].Action != "TEST_ACTION_2" {
		t.Errorf("Expected first limited log to be TEST_ACTION_2, got %s", logsLimited[0].Action)
	}
}

func TestMCPTokenManagement(t *testing.T) {
	configDir, _ := os.UserConfigDir()
	apmDir := filepath.Join(configDir, "apm")
	os.MkdirAll(apmDir, 0700)
	authFile := filepath.Join(apmDir, "mcp_auth.json")
	os.Remove(authFile)
	defer os.Remove(authFile)

	token, err := GenerateMCPToken("TestToken", []string{"vault.read", "vault.write"}, 0)
	if err != nil {
		t.Fatalf("Failed to generate token: %v", err)
	}
	if token == "" {
		t.Fatal("Generated token is empty")
	}

	config, err := LoadMCPConfig()
	if err != nil {
		t.Fatalf("Failed to load config: %v", err)
	}

	mcpToken, exists := config.Tokens[token]
	if !exists {
		t.Fatal("Token not found in config")
	}
	if len(mcpToken.Permissions) != 2 {
		t.Errorf("Expected 2 permissions, got %d", len(mcpToken.Permissions))
	}

	tokens, err := ListMCPTokens()
	if err != nil {
		t.Fatalf("Failed to list tokens: %v", err)
	}
	if len(tokens) == 0 {
		t.Fatal("No tokens listed")
	}
	found := false
	for _, tok := range tokens {
		if strings.Contains(tok.Token, token[:8]) {
			found = true
			break
		}
	}
	if !found {
		t.Error("Token not found in list")
	}

	revoked, err := RevokeMCPToken(token)
	if err != nil {
		t.Fatalf("Failed to revoke token: %v", err)
	}
	if !revoked {
		t.Fatal("Token was not revoked")
	}

	config2, _ := LoadMCPConfig()
	if _, exists := config2.Tokens[token]; exists {
		t.Error("Token should be revoked")
	}
}
