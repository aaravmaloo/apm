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

	vaultPath := "test_mcp_integration_vault.dat"
	os.Remove(vaultPath)
	defer os.Remove(vaultPath)

	v := &Vault{Entries: []Entry{}}
	if err := saveVault(v, "masterpass", vaultPath); err != nil {
		t.Fatalf("Failed to create test vault: %v", err)
	}

	configDir, _ := os.UserConfigDir()
	apmDir := filepath.Join(configDir, "apm")
	os.MkdirAll(apmDir, 0700)
	authFile := filepath.Join(apmDir, "mcp_auth.json")

	validToken := "valid-integration-token"
	config := MCPAuthConfig{
		Tokens: map[string]MCPToken{
			validToken: {
				Name:	"TestToken",
				Token:	validToken,
				Permissions:	[]string{"all"},
				CreatedAt:	time.Now(),
				ExpiresAt:	time.Now().Add(24 * time.Hour),
			},
		},
	}
	data, _ := json.Marshal(config)
	os.WriteFile(authFile, data, 0600)
	defer os.Remove(authFile)

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

	os.Setenv("APM_SESSION_ID", "integrationtest")
	sessionFile := filepath.Join(os.TempDir(), "pm_session_integrationtest.json")
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

	serverErrCh := make(chan error, 1)
	go func() {

		err := StartMCPServer(validToken, vaultPath, nil, nil)
		if err != nil {
			serverErrCh <- err
		}
		close(serverErrCh)
	}()

	idCounter := 0
	callTool := func(tool string, args map[string]interface{}) map[string]interface{} {
		idCounter++
		req := map[string]interface{}{
			"jsonrpc":	"2.0",
			"id":	idCounter,
			"method":	"tools/call",
			"params": map[string]interface{}{
				"name":	tool,
				"arguments":	args,
			},
		}

		reqBytes, _ := json.Marshal(req)
		wIn.Write(reqBytes)
		wIn.Write([]byte("\n"))

		dec := json.NewDecoder(rOut)
		var resp map[string]interface{}
		if err := dec.Decode(&resp); err != nil {
			t.Fatalf("Failed to decode response from server: %v", err)
		}

		select {
		case err := <-serverErrCh:
			if err != nil {
				t.Fatalf("Server crashed: %v", err)
			}
		default:
		}

		return resp
	}

	idCounter++
	initReq := map[string]interface{}{
		"jsonrpc":	"2.0",
		"id":	idCounter,
		"method":	"initialize",
		"params": map[string]interface{}{
			"protocolVersion":	"2024-11-05",
			"capabilities":	map[string]interface{}{},
			"clientInfo":	map[string]interface{}{"name": "test-client", "version": "1.0"},
		},
	}

	initBytes, _ := json.Marshal(initReq)
	wIn.Write(initBytes)
	wIn.Write([]byte("\n"))

	// Read init result
	var initResp map[string]interface{}

	json.NewDecoder(rOut).Decode(&initResp)

	wIn.Write([]byte(`{"jsonrpc":"2.0","method":"notifications/initialized"}` + "\n"))

	resp := callTool("generate_password", map[string]interface{}{"length": 15})
	res := getResultStr(resp)
	if len(res) != 15 {
		t.Errorf("Expected password length 15, got %d: %s", len(res), res)
	}

	resp = callTool("add_entry", map[string]interface{}{
		"type":	"password",
		"name":	"IntegrationTestEntry",
		"username":	"user1",
		"password":	res,
	})
	if isError(resp) {
		t.Errorf("add_entry failed: %v", resp)
		if errData, ok := resp["error"]; ok {
			t.Logf("Error details: %v", errData)
		}
	}

	resp = callTool("list_vault", map[string]interface{}{})
	listContent := getResultStr(resp)
	if !strings.Contains(listContent, "IntegrationTestEntry") {
		t.Errorf("Vault listing missing entry: %s", listContent)
	}

	resp = callTool("delete_entry", map[string]interface{}{"name": "IntegrationTestEntry"})
	if isError(resp) {
		t.Errorf("delete_entry failed: %v", resp)
	}

	resp = callTool("list_vault", map[string]interface{}{})
	listContent = getResultStr(resp)
	if strings.Contains(listContent, "IntegrationTestEntry") {
		t.Errorf("Vault listing should NOT contain entry: %s", listContent)
	}
}

func getResultStr(resp map[string]interface{}) string {
	res, _ := resp["result"].(map[string]interface{})
	content, _ := res["content"].([]interface{})
	if len(content) > 0 {
		textObj, _ := content[0].(map[string]interface{})
		return textObj["text"].(string)
	}
	return ""
}

func isError(resp map[string]interface{}) bool {
	if _, ok := resp["error"]; ok {
		return true
	}
	res, _ := resp["result"].(map[string]interface{})
	if val, ok := res["isError"]; ok {
		if b, ok := val.(bool); ok && b {
			return true
		}
	}
	return false
}
