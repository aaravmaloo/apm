package apm

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
	"github.com/modelcontextprotocol/go-sdk/server"
	"github.com/modelcontextprotocol/go-sdk/server/stdio"
)

type MCPAuthConfig struct {
	Tokens map[string]MCPToken `json:"tokens"`
}

type MCPToken struct {
	Token       string    `json:"token"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
}

func getMCPConfigFile() string {
	configDir, _ := os.UserConfigDir()
	apmDir := filepath.Join(configDir, "apm")
	_ = os.MkdirAll(apmDir, 0700)
	return filepath.Join(apmDir, "mcp_auth.json")
}

func LoadMCPConfig() (*MCPAuthConfig, error) {
	file := getMCPConfigFile()
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return &MCPAuthConfig{Tokens: make(map[string]MCPToken)}, nil
	}
	data, err := os.ReadFile(file)
	if err != nil {
		return nil, err
	}
	var config MCPAuthConfig
	if err := json.Unmarshal(data, &config); err != nil {
		return nil, err
	}
	if config.Tokens == nil {
		config.Tokens = make(map[string]MCPToken)
	}
	return &config, nil
}

func SaveMCPConfig(config *MCPAuthConfig) error {
	data, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(getMCPConfigFile(), data, 0600)
}

func GenerateMCPToken(permissions []string) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := "apm_mcp_" + hex.EncodeToString(b)

	config, err := LoadMCPConfig()
	if err != nil {
		return "", err
	}

	config.Tokens[token] = MCPToken{
		Token:       token,
		Permissions: permissions,
		CreatedAt:   time.Now(),
	}

	if err := SaveMCPConfig(config); err != nil {
		return "", err
	}
	return token, nil
}

func StartMCPServer(token string, vaultPath string) error {
	config, err := LoadMCPConfig()
	if err != nil {
		return err
	}

	mcpToken, ok := config.Tokens[token]
	if !ok {
		return errors.New("invalid or revoked MCP token")
	}

	s := server.NewServer(
		mcp.NewImplementation("APM-Server", "1.1.0"),
		server.WithLogging(),
	)

	s.AddTool(mcp.NewTool("list_entries",
		mcp.WithDescription("List all account/service names stored in the vault across all categories"),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "read") {
			return mcp.NewCallToolResult(mcp.NewTextContent("Permission denied: read scope required")), nil
		}

		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return mcp.NewCallToolResult(mcp.NewTextContent(fmt.Sprintf("Vault Error: %v", err))), nil
		}

		var names []string
		for _, e := range vault.Entries {
			names = append(names, "[Password] "+e.Account)
		}
		for _, e := range vault.TOTPEntries {
			names = append(names, "[TOTP] "+e.Account)
		}
		for _, e := range vault.SecureNotes {
			names = append(names, "[Note] "+e.Name)
		}
		for _, e := range vault.SSHKeys {
			names = append(names, "[SSH] "+e.Name)
		}

		if len(names) == 0 {
			return mcp.NewCallToolResult(mcp.NewTextContent("The vault is empty.")), nil
		}
		return mcp.NewCallToolResult(mcp.NewTextContent(fmt.Sprintf("Found %d entries:\n%s", len(names), strings.Join(names, "\n")))), nil
	})

	s.AddTool(mcp.NewTool("get_password",
		mcp.WithDescription("Retrieve username and password for a specific account"),
		mcp.WithSchema(map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"account": map[string]interface{}{
					"type":        "string",
					"description": "Exactly as shown in list_entries",
				},
			},
			"required": []string{"account"},
		}),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "secrets") {
			return mcp.NewCallToolResult(mcp.NewTextContent("Permission denied: secrets scope required")), nil
		}

		account := req.Arguments["account"].(string)
		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return mcp.NewCallToolResult(mcp.NewTextContent(fmt.Sprintf("Vault Error: %v", err))), nil
		}

		for _, e := range vault.Entries {
			if e.Account == account {
				return mcp.NewCallToolResult(mcp.NewTextContent(fmt.Sprintf("Account: %s\nUsername: %s\nPassword: %s", e.Account, e.Username, e.Password))), nil
			}
		}
		return mcp.NewCallToolResult(mcp.NewTextContent("Entry not found.")), nil
	})

	s.AddTool(mcp.NewTool("search",
		mcp.WithDescription("Search for entries matching a query string"),
		mcp.WithSchema(map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"query": map[string]interface{}{
					"type": "string",
				},
			},
			"required": []string{"query"},
		}),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "read") {
			return mcp.NewCallToolResult(mcp.NewTextContent("Permission denied")), nil
		}

		query := strings.ToLower(req.Arguments["query"].(string))
		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return mcp.NewCallToolResult(mcp.NewTextContent(fmt.Sprintf("Vault Error: %v", err))), nil
		}

		var matches []string
		for _, e := range vault.Entries {
			if strings.Contains(strings.ToLower(e.Account), query) || strings.Contains(strings.ToLower(e.Username), query) {
				matches = append(matches, fmt.Sprintf("[Password] %s (%s)", e.Account, e.Username))
			}
		}
		// ... more categories ...

		if len(matches) == 0 {
			return mcp.NewCallToolResult(mcp.NewTextContent("No matches found.")), nil
		}
		return mcp.NewCallToolResult(mcp.NewTextContent(fmt.Sprintf("Search results:\n%s", strings.Join(matches, "\n")))), nil
	})

	s.AddTool(mcp.NewTool("add_password",
		mcp.WithDescription("Add a new password entry to the vault"),
		mcp.WithSchema(map[string]interface{}{
			"type": "object",
			"properties": map[string]interface{}{
				"account":  map[string]interface{}{"type": "string"},
				"username": map[string]interface{}{"type": "string"},
				"password": map[string]interface{}{"type": "string"},
			},
			"required": []string{"account", "username", "password"},
		}),
	), func(ctx context.Context, req mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "write") {
			return mcp.NewCallToolResult(mcp.NewTextContent("Permission denied")), nil
		}

		acc := req.Arguments["account"].(string)
		user := req.Arguments["username"].(string)
		pass := req.Arguments["password"].(string)

		vault, masterKey, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return mcp.NewCallToolResult(mcp.NewTextContent(fmt.Sprintf("Vault Error: %v", err))), nil
		}

		vault.Entries = append(vault.Entries, Entry{Account: acc, Username: user, Password: pass})

		data, _ := EncryptVault(vault, masterKey)
		if err := SaveVault(vaultPath, data); err != nil {
			return mcp.NewCallToolResult(mcp.NewTextContent(fmt.Sprintf("Save Error: %v", err))), nil
		}

		return mcp.NewCallToolResult(mcp.NewTextContent(fmt.Sprintf("Successfully added entry for %s", acc))), nil
	})

	t := stdio.NewTransport()
	return s.Serve(t)
}

func unlockVaultForMCP(vaultPath string) (*Vault, string, error) {
	session, err := GetSession()
	if err != nil {
		return nil, "", errors.New("vault is locked. please run 'pm unlock' first to start an MCP session")
	}

	data, err := LoadVault(vaultPath)
	if err != nil {
		return nil, "", err
	}

	vault, err := DecryptVault(data, session.MasterPassword)
	if err != nil {
		return nil, "", err
	}

	return vault, session.MasterPassword, nil
}
