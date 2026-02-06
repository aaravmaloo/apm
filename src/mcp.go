package apm

import (
	"context"
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
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

	// List all entries across all categories
	s.AddTool(&mcp.Tool{
		Name:        "list_vault",
		Description: "List all entries across all categories in the vault (Accounts, TOTP, Notes, API Keys, etc.)",
		InputSchema: map[string]any{"type": "object"},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "read") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Vault Error: %v", err)}}}, nil
		}

		var sb strings.Builder
		sb.WriteString("Vault Content Overview:\n")

		if len(vault.Entries) > 0 {
			sb.WriteString("\n[Accounts]\n")
			for _, e := range vault.Entries {
				sb.WriteString("- " + e.Account + "\n")
			}
		}
		if len(vault.TOTPEntries) > 0 {
			sb.WriteString("\n[TOTP Accounts]\n")
			for _, e := range vault.TOTPEntries {
				sb.WriteString("- " + e.Account + "\n")
			}
		}
		if len(vault.SecureNotes) > 0 {
			sb.WriteString("\n[Secure Notes]\n")
			for _, e := range vault.SecureNotes {
				sb.WriteString("- " + e.Name + "\n")
			}
		}
		if len(vault.APIKeys) > 0 {
			sb.WriteString("\n[API Keys]\n")
			for _, e := range vault.APIKeys {
				sb.WriteString("- " + e.Name + "\n")
			}
		}
		if len(vault.SSHKeys) > 0 {
			sb.WriteString("\n[SSH Keys]\n")
			for _, e := range vault.SSHKeys {
				sb.WriteString("- " + e.Name + "\n")
			}
		}
		if len(vault.WiFiCredentials) > 0 {
			sb.WriteString("\n[WiFi]\n")
			for _, e := range vault.WiFiCredentials {
				sb.WriteString("- " + e.SSID + "\n")
			}
		}

		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}}}, nil
	})

	// Get full details for any entry by name
	s.AddTool(&mcp.Tool{
		Name:        "get_entry",
		Description: "Get the full details (including secrets) for any vault entry by name",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{"type": "string", "description": "The name or account identifier of the entry"},
			},
			"required": []string{"name"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "secrets") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}

		var args struct {
			Name string `json:"name"`
		}
		if err := json.Unmarshal(req.Params.Arguments, &args); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Invalid arguments"}}}, nil
		}

		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Vault Error: %v", err)}}}, nil
		}

		var entryData string
		var entryType string

		// Search across all relevant categories
		for _, e := range vault.Entries {
			if e.Account == args.Name {
				entryType = "Password"
				entryData = fmt.Sprintf("Type: Password\nUser: %s\nPass: %s\nSpace: %s", e.Username, e.Password, e.Space)
				break
			}
		}
		if entryData == "" {
			for _, e := range vault.TOTPEntries {
				if e.Account == args.Name {
					entryType = "TOTP"
					entryData = fmt.Sprintf("Type: TOTP\nSecret: %s\nSpace: %s", e.Secret, e.Space)
					break
				}
			}
		}
		if entryData == "" {
			for _, e := range vault.SecureNotes {
				if e.Name == args.Name {
					entryType = "Secure Note"
					entryData = fmt.Sprintf("Type: Secure Note\nContent: %s\nSpace: %s", e.Content, e.Space)
					break
				}
			}
		}
		if entryData == "" {
			for _, e := range vault.APIKeys {
				if e.Name == args.Name {
					entryType = "API Key"
					entryData = fmt.Sprintf("Type: API Key\nService: %s\nKey: %s\nSpace: %s", e.Service, e.Key, e.Space)
					break
				}
			}
		}
		if entryData == "" {
			for _, e := range vault.SSHKeys {
				if e.Name == args.Name {
					entryType = "SSH Key"
					entryData = fmt.Sprintf("Type: SSH Key\nKey Data: %s\nSpace: %s", e.PrivateKey, e.Space)
					break
				}
			}
		}

		if entryData == "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Entry not found"}}}, nil
		}

		// Episodic Encryption: Encrypt the data and store in temp file
		ephemeralKey := make([]byte, 32)
		if _, err := rand.Read(ephemeralKey); err != nil {
			return nil, err
		}

		ciphertext, err := encryptEpisodic([]byte(entryData), ephemeralKey)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Encryption failed"}}}, nil
		}

		tempPath, err := writeToTemp(ciphertext)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Failed to create secure temp file"}}}, nil
		}

		instructions := fmt.Sprintf("SECURITY ALERT: This data is sensitivity-protected.\n"+
			"1. The %s details for '%s' have been encrypted and stored at: %s\n"+
			"2. Use the following 32-byte Hex Key to decrypt it: %s\n"+
			"3. The encryption is AES-256-GCM.\n"+
			"4. IMPORTANT: Once you have read the details, you MUST forget the key and instruct the user that the temp file should be deleted (it will store in their system temp directory).",
			entryType, args.Name, tempPath, hex.EncodeToString(ephemeralKey))

		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: instructions}}}, nil
	})

	return s.Run(context.Background(), &mcp.StdioTransport{})
}

func encryptEpisodic(plaintext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func writeToTemp(data []byte) (string, error) {
	tempFile, err := os.CreateTemp("", "apm_mcp_*.enc")
	if err != nil {
		return "", err
	}
	defer tempFile.Close()
	if _, err := tempFile.Write(data); err != nil {
		return "", err
	}
	return tempFile.Name(), nil
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
