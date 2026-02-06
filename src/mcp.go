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
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type MCPAuthConfig struct {
	Tokens map[string]MCPToken `json:"tokens"`
}

type MCPToken struct {
	Name        string    `json:"name"`
	Token       string    `json:"token"`
	Permissions []string  `json:"permissions"`
	CreatedAt   time.Time `json:"created_at"`
	ExpiresAt   time.Time `json:"expires_at"`   // Zero time means never
	LastUsedAt  time.Time `json:"last_used_at"` // Zero time means never
	UsageCount  int       `json:"usage_count"`
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

func GenerateMCPToken(name string, permissions []string, expiryMinutes int) (string, error) {
	b := make([]byte, 24)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	token := "apm_mcp_" + hex.EncodeToString(b)

	config, err := LoadMCPConfig()
	if err != nil {
		return "", err
	}

	expiresAt := time.Time{}
	if expiryMinutes > 0 {
		expiresAt = time.Now().Add(time.Duration(expiryMinutes) * time.Minute)
	}

	config.Tokens[token] = MCPToken{
		Name:        name,
		Token:       token,
		Permissions: permissions,
		CreatedAt:   time.Now(),
		ExpiresAt:   expiresAt,
	}

	if err := SaveMCPConfig(config); err != nil {
		return "", err
	}

	LogAction("MCP_TOKEN_CREATED", fmt.Sprintf("Created token '%s'", name))
	return token, nil
}

func RevokeMCPToken(query string) (bool, error) {
	config, err := LoadMCPConfig()
	if err != nil {
		return false, err
	}

	// Try by token first, then by name
	if _, ok := config.Tokens[query]; ok {
		delete(config.Tokens, query)
		SaveMCPConfig(config)
		LogAction("MCP_TOKEN_REVOKED", fmt.Sprintf("Revoked token by ID"))
		return true, nil
	}

	// By Name
	for t, data := range config.Tokens {
		if data.Name == query {
			delete(config.Tokens, t)
			SaveMCPConfig(config)
			LogAction("MCP_TOKEN_REVOKED", fmt.Sprintf("Revoked token '%s'", query))
			return true, nil
		}
	}

	return false, nil
}

func ListMCPTokens() ([]MCPToken, error) {
	config, err := LoadMCPConfig()
	if err != nil {
		return nil, err
	}
	var list []MCPToken
	for _, t := range config.Tokens {
		list = append(list, t)
	}
	return list, nil
}

type PluginManager interface {
	LoadPlugins() error
	ListPlugins() []string
}

func StartMCPServer(token string, vaultPath string, transport mcp.Transport, pm PluginManager) error {
	config, err := LoadMCPConfig()
	if err != nil {
		return err
	}

	mcpToken, ok := config.Tokens[token]
	if !ok {
		LogAction("MCP_AUTH_FAILED", "Invalid token used")
		return errors.New("invalid or revoked MCP token")
	}

	if !mcpToken.ExpiresAt.IsZero() && time.Now().After(mcpToken.ExpiresAt) {
		LogAction("MCP_AUTH_FAILED", fmt.Sprintf("Expired token '%s' used", mcpToken.Name))
		return errors.New("token expired")
	}

	mcpToken.LastUsedAt = time.Now()
	mcpToken.UsageCount++
	config.Tokens[token] = mcpToken
	SaveMCPConfig(config)

	s := mcp.NewServer(&mcp.Implementation{
		Name:    "APM-Server",
		Version: "1.3.0",
	}, nil)

	// --- Vault Management Tools ---

	s.AddTool(&mcp.Tool{
		Name:        "list_vault",
		Description: "List all entries in the vault",
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
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "get_entry",
		Description: "Get the full details (including secrets) for any vault entry by name",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"name": map[string]any{"type": "string"},
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
		json.Unmarshal(req.Params.Arguments, &args)

		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Vault Error: %v", err)}}}, nil
		}

		var entryData, entryType string
		for _, e := range vault.Entries {
			if e.Account == args.Name {
				entryType, entryData = "Password", fmt.Sprintf("User: %s\nPass: %s\nSpace: %s", e.Username, e.Password, e.Space)
				break
			}
		}
		if entryData == "" {
			for _, e := range vault.TOTPEntries {
				if e.Account == args.Name {
					entryType, entryData = "TOTP", fmt.Sprintf("Secret: %s\nSpace: %s", e.Secret, e.Space)
					break
				}
			}
		}
		if entryData == "" {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Entry not found"}}}, nil
		}

		ephemeralKey := make([]byte, 32)
		rand.Read(ephemeralKey)
		ciphertext, _ := encryptEpisodic([]byte(entryData), ephemeralKey)
		tempPath, _ := writeToTemp(ciphertext)

		LogAction("MCP_ENTRY_ACCESSED", fmt.Sprintf("Token '%s' accessed entry '%s'", mcpToken.Name, args.Name))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Data for %s '%s' encrypted at %s. Key: %s", entryType, args.Name, tempPath, hex.EncodeToString(ephemeralKey))}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "add_entry",
		Description: "Add a new entry to the vault",
		InputSchema: map[string]any{
			"type": "object",
			"properties": map[string]any{
				"type":     map[string]any{"type": "string", "enum": []string{"password", "totp", "note"}},
				"name":     map[string]any{"type": "string"},
				"username": map[string]any{"type": "string"},
				"password": map[string]any{"type": "string"},
				"secret":   map[string]any{"type": "string"},
				"content":  map[string]any{"type": "string"},
				"space":    map[string]any{"type": "string"},
			},
			"required": []string{"type", "name"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "write") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Type     string `json:"type"`
			Name     string `json:"name"`
			Username string `json:"username"`
			Password string `json:"password"`
			Secret   string `json:"secret"`
			Content  string `json:"content"`
			Space    string `json:"space"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		vault, masterPwd, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Vault Error: %v", err)}}}, nil
		}

		switch args.Type {
		case "password":
			vault.Entries = append(vault.Entries, Entry{Account: args.Name, Username: args.Username, Password: args.Password, Space: args.Space})
		case "totp":
			vault.TOTPEntries = append(vault.TOTPEntries, TOTPEntry{Account: args.Name, Secret: args.Secret, Space: args.Space})
		case "note":
			vault.SecureNotes = append(vault.SecureNotes, SecureNoteEntry{Name: args.Name, Content: args.Content, Space: args.Space})
		}

		if err := saveVault(vault, masterPwd, vaultPath); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Save failed"}}}, nil
		}
		LogAction("MCP_ENTRY_ADDED", fmt.Sprintf("Token '%s' added entry '%s'", mcpToken.Name, args.Name))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Entry added"}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "delete_entry",
		Description: "Remove an entry from the vault",
		InputSchema: map[string]any{
			"type":       "object",
			"properties": map[string]any{"name": map[string]any{"type": "string"}},
			"required":   []string{"name"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "write") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Name string `json:"name"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		vault, masterPwd, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error"}}}, nil
		}

		newEntries := []Entry{}
		deleted := false
		for _, e := range vault.Entries {
			if e.Account != args.Name {
				newEntries = append(newEntries, e)
			} else {
				deleted = true
			}
		}
		vault.Entries = newEntries
		// Similar logic for other types omitted for brevity in this massive replace, but assume handled if user asks specifically.
		// Actually, let's include TOTP and Notes to be safe.
		newTOTP := []TOTPEntry{}
		for _, e := range vault.TOTPEntries {
			if e.Account != args.Name {
				newTOTP = append(newTOTP, e)
			} else {
				deleted = true
			}
		}
		vault.TOTPEntries = newTOTP
		newNotes := []SecureNoteEntry{}
		for _, e := range vault.SecureNotes {
			if e.Name != args.Name {
				newNotes = append(newNotes, e)
			} else {
				deleted = true
			}
		}
		vault.SecureNotes = newNotes

		if !deleted {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Entry not found"}}}, nil
		}
		saveVault(vault, masterPwd, vaultPath)
		LogAction("MCP_ENTRY_DELETED", fmt.Sprintf("Token '%s' deleted '%s'", mcpToken.Name, args.Name))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Entry deleted"}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "generate_password",
		Description: "Generate a secure random password",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"length": map[string]any{"type": "integer"}}},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		var args struct {
			Length int `json:"length"`
		}
		json.Unmarshal(req.Params.Arguments, &args)
		if args.Length == 0 {
			args.Length = 20
		}
		pwd, _ := GeneratePassword(args.Length)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: pwd}}}, nil
	})

	// --- Plugins ---
	pluginsDir := filepath.Join(filepath.Dir(vaultPath), "plugins")
	if pm != nil {
		pm.LoadPlugins()
	}

	s.AddTool(&mcp.Tool{
		Name:        "list_plugins",
		Description: "List installed plugins",
		InputSchema: map[string]any{"type": "object"},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "read") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		pm.LoadPlugins()
		list := pm.ListPlugins()
		sort.Strings(list)
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(list, "\n")}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:        "install_plugin",
		Description: "Install a plugin from Marketplace",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string"}}, "required": []string{"name"}},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "write") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Name string `json:"name"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error"}}}, nil
		}
		cm, err := GetCloudProvider("gdrive", context.Background(), vault.CloudCredentials, vault.CloudToken, "apm_public")
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Cloud Error: %v", err)}}}, nil
		}
		targetDir := filepath.Join(pluginsDir, args.Name)
		if err := cm.DownloadPlugin(args.Name, targetDir); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Download failed: %v", err)}}}, nil
		}
		pm.LoadPlugins()
		LogAction("MCP_PLUGIN_INSTALLED", fmt.Sprintf("Token '%s' installed '%s'", mcpToken.Name, args.Name))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Plugin installed"}}}, nil
	})

	// --- Cloud ---
	s.AddTool(&mcp.Tool{
		Name:        "cloud_sync",
		Description: "Trigger cloud sync",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"provider": map[string]any{"type": "string", "enum": []string{"gdrive", "github"}}}, "required": []string{"provider"}},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "write") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Provider string `json:"provider"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		vault, masterPwd, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error"}}}, nil
		}
		cm, err := GetCloudProvider(args.Provider, context.Background(), vault.CloudCredentials, vault.CloudToken, "apm_public")
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Cloud Init Error"}}}, nil
		}

		targetID := vault.CloudFileID
		if args.Provider == "github" {
			targetID = vault.GitHubRepo
		}
		if targetID == "" {
			newID, err := cm.UploadVault(vaultPath, vault.RetrievalKey)
			if err != nil {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Upload failed: %v", err)}}}, nil
			}
			if args.Provider == "gdrive" {
				vault.CloudFileID = newID
			} else {
				vault.GitHubRepo = newID
			}
			saveVault(vault, masterPwd, vaultPath)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Uploaded to %s (ID: %s)", args.Provider, newID)}}}, nil
		}
		if err := cm.SyncVault(vaultPath, targetID); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Sync failed: %v", err)}}}, nil
		}
		LogAction("MCP_CLOUD_SYNC", fmt.Sprintf("Synced to %s", args.Provider))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Sync successful"}}}, nil
	})

	// --- Admin ---
	s.AddTool(&mcp.Tool{
		Name:        "get_audit_logs",
		Description: "Retrieve recent audit logs",
		InputSchema: map[string]any{"type": "object", "properties": map[string]any{"limit": map[string]any{"type": "integer"}}},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "admin") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Limit int `json:"limit"`
		}
		json.Unmarshal(req.Params.Arguments, &args)
		if args.Limit == 0 {
			args.Limit = 50
		}
		logs, _ := GetAuditLogs(args.Limit)
		var sb strings.Builder
		for _, l := range logs {
			sb.WriteString(fmt.Sprintf("[%s] %s: %s\n", l.Timestamp.Format(time.RFC3339), l.Action, l.Details))
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}}}, nil
	})

	if transport == nil {
		transport = &mcp.StdioTransport{}
	}
	return s.Run(context.Background(), transport)
}

func saveVault(vault *Vault, masterPwd string, path string) error {
	data, err := EncryptVault(vault, masterPwd)
	if err != nil {
		return err
	}
	return os.WriteFile(path, data, 0600)
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
