package apm

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func TestMCPVaultIntegration(t *testing.T) {
	tempDir := t.TempDir()
	vaultPath := filepath.Join(tempDir, "test_mcp_integration_vault.dat")
	authFile := filepath.Join(tempDir, "apm", "mcp_auth.json")
	os.MkdirAll(filepath.Dir(authFile), 0700)

	// Setup Config Dir Mocking
	if os.Getenv("OS") == "Windows_NT" {
		t.Setenv("APPDATA", tempDir)
	} else {
		t.Setenv("XDG_CONFIG_HOME", tempDir)
	}
	t.Setenv("HOME", tempDir)

	masterPass := "masterpass"

	// Create Vault
	v := &Vault{Entries: []Entry{}}
	if err := saveVault(v, masterPass, vaultPath); err != nil {
		t.Fatalf("Failed to create test vault: %v", err)
	}

	validToken := "valid-integration-token"
	config := MCPAuthConfig{
		Tokens: map[string]MCPToken{
			validToken: {
				Name:        "TestToken",
				Token:       validToken,
				Permissions: []string{"all"},
				CreatedAt:   time.Now(),
				ExpiresAt:   time.Now().Add(24 * time.Hour),
			},
		},
	}
	data, _ := json.Marshal(config)
	if err := os.WriteFile(authFile, data, 0600); err != nil {
		t.Fatalf("Failed to write auth file: %v", err)
	}

	// Mock Stdin/Stdout
	rIn, wIn, _ := os.Pipe()
	rOut, wOut, _ := os.Pipe()

	origStdin := os.Stdin
	origStdout := os.Stdout
	os.Stdin = rIn
	os.Stdout = wOut

	defer func() {
		os.Stdin = origStdin
		os.Stdout = origStdout
		rIn.Close()
		wIn.Close()
		rOut.Close()
		wOut.Close()
	}()

	// Mock Session
	t.Setenv("APM_SESSION_ID", "integrationtest")
	// The session file path is likely constructed using os.TempDir() inside session.go
	// We should try to intercept that if possible, but assuming it uses os.TempDir():
	sessionFile := filepath.Join(os.TempDir(), "pm_session_integrationtest.json")
	sessionParams := Session{
		MasterPassword:    masterPass,
		Expiry:            time.Now().Add(1 * time.Hour),
		LastUsed:          time.Now(),
		InactivityTimeout: 1 * time.Hour,
	}
	sessData, _ := json.Marshal(sessionParams)
	os.WriteFile(sessionFile, sessData, 0600)
	defer os.Remove(sessionFile)

	serverErrCh := make(chan error, 1)
	go func() {
		// StartMCPServer(token, vaultPath, input, output)
		// We pass nil for streams to let it use os.Stdin/Stdout which we mocked
		err := StartMCPServer(validToken, vaultPath, nil, nil)
		if err != nil {
			serverErrCh <- err
		}
		close(serverErrCh)
	}()

	// Helper to send request and get response
	idCounter := 0
	callTool := func(tool string, args map[string]interface{}) map[string]interface{} {
		idCounter++
		reqID := idCounter
		req := map[string]interface{}{
			"jsonrpc": "2.0",
			"id":      reqID,
			"method":  "tools/call",
			"params": map[string]interface{}{
				"name":      tool,
				"arguments": args,
			},
		}

		reqBytes, _ := json.Marshal(req)
		wIn.Write(reqBytes)
		wIn.Write([]byte("\n"))

		dec := json.NewDecoder(rOut)
		for {
			var resp map[string]interface{}
			if err := dec.Decode(&resp); err != nil {
				t.Fatalf("Failed to decode response from server: %v", err)
			}

			if respID, ok := resp["id"]; ok {
				if int(respID.(float64)) == reqID {
					return resp
				}
			}
		}
	}

	// Initialize
	idCounter++
	initReq := map[string]interface{}{
		"jsonrpc": "2.0",
		"id":      idCounter,
		"method":  "initialize",
		"params": map[string]interface{}{
			"protocolVersion": "2024-11-05",
			"capabilities":    map[string]interface{}{},
			"clientInfo":      map[string]interface{}{"name": "test-client", "version": "1.0"},
		},
	}

	initBytes, _ := json.Marshal(initReq)
	wIn.Write(initBytes)
	wIn.Write([]byte("\n"))

	var initResp map[string]interface{}
	json.NewDecoder(rOut).Decode(&initResp)

	// Send initialized notification
	wIn.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"))

	// Test: generate_password
	resp := callTool("generate_password", map[string]interface{}{"length": 15})
	res := getResultStr(resp)
	if len(res) != 15 {
		t.Errorf("Expected password length 15, got %d: %s", len(res), res)
	}

	// Test: add_entry
	resp = callTool("add_entry", map[string]interface{}{
		"type":     "password",
		"name":     "IntegrationTestEntry",
		"username": "user1",
		"password": res,
	})
	if isError(resp) {
		t.Errorf("add_entry failed: %v", resp)
	}

	// Test: list_vault
	resp = callTool("list_vault", map[string]interface{}{})
	listContent := getResultStr(resp)
	if !strings.Contains(listContent, "IntegrationTestEntry") {
		t.Errorf("Vault listing missing entry: %s", listContent)
	}

	// Test: delete_entry
	resp = callTool("delete_entry", map[string]interface{}{"name": "IntegrationTestEntry"})
	if isError(resp) {
		t.Errorf("delete_entry failed: %v", resp)
	}

	// Verify Deletion
	resp = callTool("list_vault", map[string]interface{}{})
	listContent = getResultStr(resp)
	if strings.Contains(listContent, "IntegrationTestEntry") {
		t.Errorf("Vault listing should NOT contain entry: %s", listContent)
	}
}

func getResultStr(resp map[string]interface{}) string {
	if resp == nil {
		return ""
	}
	res, ok := resp["result"].(map[string]interface{})
	if !ok {
		return ""
	}
	content, ok := res["content"].([]interface{})
	if !ok || len(content) == 0 {
		return ""
	}
	textObj, ok := content[0].(map[string]interface{})
	if !ok {
		return ""
	}
	text, ok := textObj["text"].(string)
	if !ok {
		return ""
	}
	return text
}

func isError(resp map[string]interface{}) bool {
	if resp == nil {
		return true
	}
	if _, ok := resp["error"]; ok {
		return true
	}
	res, ok := resp["result"].(map[string]interface{})
	if ok {
		if val, ok := res["isError"]; ok {
			if b, ok := val.(bool); ok && b {
				return true
			}
		}
	}
	return false
}
