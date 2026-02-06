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

	s := mcp.NewServer(&mcp.Implementation{
		Name:    "APM-Server",
		Version: "1.2.0",
	}, nil)

	// Add list_entries tool
	s.AddTool(&mcp.Tool{
		Name:        "list_entries",
		Description: "List all account/service names stored in the vault",
		InputSchema: map[string]any{"type": "object"},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "read") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Vault Error: %v", err)}}}, nil
		}
		var res []string
		for _, e := range vault.Entries {
			res = append(res, e.Account)
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(res, "\n")}}}, nil
	})

	// Add get_details tool
	s.AddTool(&mcp.Tool{
		Name:        "get_details",
		Description: "Get username and password for a specific account",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"account": map[string]any{"type": "string"},
			},
			"required": []string{"account"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "secrets") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}

		var args struct {
			Account string `json:"account"`
		}
		if len(req.Params.Arguments) > 0 {
			if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Invalid arguments"}}}, nil
			}
		}

		if args.Account == "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Missing account argument"}}}, nil
		}

		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Vault Error: %v", err)}}}, nil
		}
		for _, e := range vault.Entries {
			if e.Account == args.Account {
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("User: %s\nPass: %s", e.Username, e.Password)}}}, nil
			}
		}
		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Not found"}}}, nil
	})

	// Add search tool
	s.AddTool(&mcp.Tool{
		Name:        "search",
		Description: "Search for entries matching a query",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"query": map[string]any{"type": "string"},
			},
			"required": []string{"query"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "read") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}

		var args struct {
			Query string `json:"query"`
		}
		if len(req.Params.Arguments) > 0 {
			if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Invalid arguments"}}}, nil
			}
		}

		if args.Query == "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Missing query argument"}}}, nil
		}

		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Vault Error: %v", err)}}}, nil
		}
		query := strings.ToLower(args.Query)
		var res []string
		for _, e := range vault.Entries {
			if strings.Contains(strings.ToLower(e.Account), query) {
				res = append(res, e.Account)
			}
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(res, "\n")}}}, nil
	})

	return s.Run(context.Background(), &mcp.StdioTransport{})
}

func hasPermission(scopes []string, required string) bool {
	for _, s := range scopes {
		if s == required || s == "all" {
			return true
		}
	}
	return false
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

	vault, err := DecryptVault(data, session.MasterPassword, 1)
	if err != nil {
		return nil, "", err
	}

	return vault, session.MasterPassword, nil
}
