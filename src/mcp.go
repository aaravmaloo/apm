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
	"os/exec"
	"path/filepath"
	"reflect"
	"sort"
	"strings"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

type MCPAuthConfig struct {
	Tokens map[string]MCPToken `json:"tokens"`
}

type MCPToken struct {
	Name	string		`json:"name"`
	Token	string		`json:"token"`
	Permissions	[]string		`json:"permissions"`
	CreatedAt	time.Time		`json:"created_at"`
	ExpiresAt	time.Time		`json:"expires_at,omitempty"`
	LastUsedAt	time.Time		`json:"last_used_at,omitempty"`
	UsageCount	int		`json:"usage_count"`
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
		Name:	name,
		Token:	token,
		Permissions:	permissions,
		CreatedAt:	time.Now(),
		ExpiresAt:	expiresAt,
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

	if _, ok := config.Tokens[query]; ok {
		delete(config.Tokens, query)
		SaveMCPConfig(config)
		LogAction("MCP_TOKEN_REVOKED", "Revoked token by ID")
		return true, nil
	}

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
	ExecuteHooks(hookType, hookName string, vault *Vault, vaultPath string) error
}

func StartMCPServer(token string, vaultPath string, transport mcp.Transport, pm PluginManager) error {
	config, err := LoadMCPConfig()
	if err != nil {
		return err
	}

	mcpToken, ok := config.Tokens[token]
	if !ok {
		fmt.Printf("DEBUG: Token mismatch. Wanted: %s, have tokens: %v\n", token, config.Tokens)
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
		Name:	"APM-Server",
		Version:	"1.3.0",
	}, nil)

	s.AddTool(&mcp.Tool{
		Name:	"check_installation",
		Description:	"Check if apm is installed and initialized on the system",
		InputSchema:	map[string]any{"type": "object", "properties": map[string]any{}},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		_, err := exec.LookPath("apm")
		installed := err == nil
		vaultExists := VaultExists(vaultPath)

		status := "APM is fully installed and initialized."
		if !installed && !vaultExists {
			status = "APM is NOT installed. Please run 'install_apm' to set it up."
		} else if !installed {
			status = "APM binary not found in PATH, but vault exists."
		} else if !vaultExists {
			status = "APM binary found, but vault is not initialized. Run 'pm init'."
		}

		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: status}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:	"install_apm",
		Description:	"Install and initialize APM (requires LLM help/interaction)",
		InputSchema: map[string]any{
			"type":	"object",
			"properties": map[string]any{
				"master_password": map[string]any{"type": "string"},
			},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if VaultExists(vaultPath) {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Vault already exists. No installation needed."}}}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "To install APM: 1. Ensure go is installed. 2. Clone repo. 3. Run 'go build -o apm.exe'. 4. Run 'pm init'. I can guide you through each step if you'd like."}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:	"list_vault",
		Description:	"List all entries in the vault by category",
		InputSchema:	map[string]any{"type": "object"},
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

		addSection := func(title string, items interface{}, nameField string) {
			val := reflect.ValueOf(items)
			if val.Kind() == reflect.Slice && val.Len() > 0 {
				sb.WriteString(fmt.Sprintf("\n[%s]\n", title))
				for i := 0; i < val.Len(); i++ {
					item := val.Index(i)
					if item.Kind() == reflect.Struct {
						f := item.FieldByName(nameField)
						if f.IsValid() {
							sb.WriteString("- " + f.String() + "\n")
						}
					}
				}
			}
		}

		addSection("Passwords", vault.Entries, "Account")
		addSection("TOTP", vault.TOTPEntries, "Account")
		addSection("Secure Notes", vault.SecureNotes, "Name")
		addSection("API Keys", vault.APIKeys, "Name")
		addSection("SSH Keys", vault.SSHKeys, "Name")
		addSection("WiFi Credentials", vault.WiFiCredentials, "SSID")
		addSection("Recovery Codes", vault.RecoveryCodeItems, "Service")
		addSection("Certificates", vault.Certificates, "Label")
		addSection("Banking Items", vault.BankingItems, "Label")
		addSection("Documents", vault.Documents, "Name")
		addSection("Medical Records", vault.MedicalRecords, "Label")
		addSection("Travel Documents", vault.TravelDocs, "Label")
		addSection("Gov IDs", vault.GovIDs, "Name")
		addSection("Contacts", vault.Contacts, "Name")
		addSection("Cloud Credentials", vault.CloudCredentialsItems, "Label")
		addSection("K8s Secrets", vault.K8sSecrets, "Name")
		addSection("Docker Registries", vault.DockerRegistries, "Name")
		addSection("SSH Configs", vault.SSHConfigs, "Name")
		addSection("CI/CD Secrets", vault.CICDSecrets, "Name")
		addSection("Licenses", vault.SoftwareLicenses, "Name")
		addSection("Contracts", vault.LegalContracts, "Name")

		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:	"get_entry",
		Description:	"Get the full details (including secrets) for any vault entry by name. You can optionally specify a category to narrow down the search.",
		InputSchema: map[string]any{
			"type":	"object",
			"properties": map[string]any{
				"name":	map[string]any{"type": "string"},
				"category":	map[string]any{"type": "string", "description": "Optional category hint (e.g., 'password', 'totp', 'banking', 'recovery_code', etc.)"},
			},
			"required":	[]string{"name"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "secrets") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Name	string		`json:"name"`
			Category	string		`json:"category"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Vault Error: %v", err)}}}, nil
		}

		var foundItem interface{}
		var itemType string

		searchIn := func(items interface{}, typeName string, nameField string) bool {
			if args.Category != "" && !strings.Contains(strings.ToLower(typeName), strings.ToLower(args.Category)) && !strings.Contains(strings.ToLower(args.Category), strings.ToLower(typeName)) {
				return false
			}
			val := reflect.ValueOf(items)
			for i := 0; i < val.Len(); i++ {
				item := val.Index(i)
				f := item.FieldByName(nameField)
				if f.IsValid() && f.String() == args.Name {
					foundItem = item.Interface()
					itemType = typeName
					return true
				}
			}
			return false
		}

		found := searchIn(vault.Entries, "Password", "Account") ||
			searchIn(vault.TOTPEntries, "TOTP", "Account") ||
			searchIn(vault.SecureNotes, "Secure Note", "Name") ||
			searchIn(vault.APIKeys, "API Key", "Name") ||
			searchIn(vault.SSHKeys, "SSH Key", "Name") ||
			searchIn(vault.WiFiCredentials, "WiFi", "SSID") ||
			searchIn(vault.RecoveryCodeItems, "Recovery Code", "Service") ||
			searchIn(vault.Certificates, "Certificate", "Label") ||
			searchIn(vault.BankingItems, "Banking", "Label") ||
			searchIn(vault.Documents, "Document", "Name") ||
			searchIn(vault.MedicalRecords, "Medical Record", "Label") ||
			searchIn(vault.TravelDocs, "Travel", "Label") ||
			searchIn(vault.GovIDs, "Gov ID", "Name") ||
			searchIn(vault.Contacts, "Contact", "Name") ||
			searchIn(vault.CloudCredentialsItems, "Cloud", "Label") ||
			searchIn(vault.K8sSecrets, "K8s Secret", "Name") ||
			searchIn(vault.DockerRegistries, "Docker", "Name") ||
			searchIn(vault.SSHConfigs, "SSH Config", "Name") ||
			searchIn(vault.CICDSecrets, "CI/CD", "Name") ||
			searchIn(vault.SoftwareLicenses, "License", "Name") ||
			searchIn(vault.LegalContracts, "Contract", "Name")

		if !found {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Entry not found"}}}, nil
		}

		jsonData, _ := json.MarshalIndent(foundItem, "", "  ")

		ephemeralKey := make([]byte, 32)
		rand.Read(ephemeralKey)
		ciphertext, _ := encryptEpisodic(jsonData, ephemeralKey)
		tempPath, _ := writeToTemp(ciphertext)

		LogAction("MCP_ENTRY_ACCESSED", fmt.Sprintf("Token '%s' accessed entry '%s' (%s)", mcpToken.Name, args.Name, itemType))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Data for %s '%s' encrypted at %s. Reference: %s. Use decrypt_entry to view.", itemType, args.Name, tempPath, hex.EncodeToString(ephemeralKey))}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:	"search_vault",
		Description:	"Search for a keyword across all vault entries and categories",
		InputSchema: map[string]any{
			"type":	"object",
			"properties": map[string]any{
				"query": map[string]any{"type": "string"},
			},
			"required":	[]string{"query"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "read") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Query string `json:"query"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error"}}}, nil
		}

		var results []string
		searchTerm := strings.ToLower(args.Query)

		searchSlice := func(items interface{}, typeName string) {
			val := reflect.ValueOf(items)
			for i := 0; i < val.Len(); i++ {
				item := val.Index(i)
				data, _ := json.Marshal(item.Interface())
				if strings.Contains(strings.ToLower(string(data)), searchTerm) {
					results = append(results, fmt.Sprintf("[%s] %v", typeName, item.Interface()))
				}
			}
		}

		searchSlice(vault.Entries, "Password")
		searchSlice(vault.TOTPEntries, "TOTP")
		searchSlice(vault.SecureNotes, "Note")
		searchSlice(vault.APIKeys, "APIKey")
		searchSlice(vault.SSHKeys, "SSHKey")
		searchSlice(vault.WiFiCredentials, "WiFi")
		searchSlice(vault.RecoveryCodeItems, "RecoveryCode")
		searchSlice(vault.BankingItems, "Banking")
		searchSlice(vault.GovIDs, "GovID")
		searchSlice(vault.MedicalRecords, "Medical")
		searchSlice(vault.TravelDocs, "Travel")
		searchSlice(vault.Documents, "Document")
		searchSlice(vault.Contacts, "Contact")

		if len(results) == 0 {
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "No matches found"}}}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: strings.Join(results, "\n")}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:	"decrypt_entry",
		Description:	"Decrypt an entry using a provided reference key (from get_entry)",
		InputSchema: map[string]any{
			"type":	"object",
			"properties": map[string]any{
				"path":	map[string]any{"type": "string"},
				"reference":	map[string]any{"type": "string"},
			},
			"required":	[]string{"path", "reference"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "secrets") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Path	string		`json:"path"`
			Reference	string		`json:"reference"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		ciphertext, err := os.ReadFile(args.Path)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Failed to read encrypted file"}}}, nil
		}

		key, err := hex.DecodeString(args.Reference)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Invalid reference key"}}}, nil
		}

		plaintext, err := decryptEpisodic(ciphertext, key)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Decryption failed"}}}, nil
		}

		os.Remove(args.Path)

		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: string(plaintext)}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:	"get_totp",
		Description:	"Get the current TOTP code for a vault entry",
		InputSchema: map[string]any{
			"type":	"object",
			"properties": map[string]any{
				"name": map[string]any{"type": "string"},
			},
			"required":	[]string{"name"},
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
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error"}}}, nil
		}

		for _, e := range vault.TOTPEntries {
			if e.Account == args.Name {
				code, _ := GenerateTOTP(e.Secret)
				return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("TOTP Code for %s: %s", args.Name, code)}}}, nil
			}
		}

		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "TOTP Account not found"}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:	"add_entry",
		Description:	"Add a new entry to the vault",
		InputSchema: map[string]any{
			"type":	"object",
			"properties": map[string]any{
				"type":	map[string]any{"type": "string", "enum": []string{"password", "totp", "note"}},
				"name":	map[string]any{"type": "string"},
				"username":	map[string]any{"type": "string"},
				"password":	map[string]any{"type": "string"},
				"secret":	map[string]any{"type": "string"},
				"content":	map[string]any{"type": "string"},
				"space":	map[string]any{"type": "string"},
			},
			"required":	[]string{"type", "name"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "write") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Type	string		`json:"type"`
			Name	string		`json:"name"`
			Username	string		`json:"username"`
			Password	string		`json:"password"`
			Secret	string		`json:"secret"`
			Content	string		`json:"content"`
			Space	string		`json:"space"`
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
		Name:	"delete_entry",
		Description:	"Remove an entry from the vault",
		InputSchema: map[string]any{
			"type":	"object",
			"properties":	map[string]any{"name": map[string]any{"type": "string"}},
			"required":	[]string{"name"},
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

		if !vault.DeleteEntry(args.Name) && !vault.DeleteTOTPEntry(args.Name) && !vault.DeleteSecureNote(args.Name) {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Entry not found"}}}, nil
		}
		saveVault(vault, masterPwd, vaultPath)
		LogAction("MCP_ENTRY_DELETED", fmt.Sprintf("Token '%s' deleted '%s'", mcpToken.Name, args.Name))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Entry deleted"}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:	"edit_entry",
		Description:	"Edit an existing entry in the vault",
		InputSchema: map[string]any{
			"type":	"object",
			"properties": map[string]any{
				"type":	map[string]any{"type": "string", "enum": []string{"password", "totp", "note"}},
				"name":	map[string]any{"type": "string"},
				"username":	map[string]any{"type": "string"},
				"password":	map[string]any{"type": "string"},
				"secret":	map[string]any{"type": "string"},
				"content":	map[string]any{"type": "string"},
				"space":	map[string]any{"type": "string"},
			},
			"required":	[]string{"type", "name"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "write") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Type	string		`json:"type"`
			Name	string		`json:"name"`
			Username	string		`json:"username"`
			Password	string		`json:"password"`
			Secret	string		`json:"secret"`
			Content	string		`json:"content"`
			Space	string		`json:"space"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		vault, masterPwd, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error"}}}, nil
		}

		updated := false
		switch args.Type {
		case "password":
			for i, e := range vault.Entries {
				if e.Account == args.Name {
					if args.Username != "" {
						vault.Entries[i].Username = args.Username
					}
					if args.Password != "" {
						vault.Entries[i].Password = args.Password
					}
					if args.Space != "" {
						vault.Entries[i].Space = args.Space
					}
					updated = true
					break
				}
			}
		case "totp":
			for i, e := range vault.TOTPEntries {
				if e.Account == args.Name {
					if args.Secret != "" {
						vault.TOTPEntries[i].Secret = args.Secret
					}
					if args.Space != "" {
						vault.TOTPEntries[i].Space = args.Space
					}
					updated = true
					break
				}
			}
		case "note":
			for i, e := range vault.SecureNotes {
				if e.Name == args.Name {
					if args.Content != "" {
						vault.SecureNotes[i].Content = args.Content
					}
					if args.Space != "" {
						vault.SecureNotes[i].Space = args.Space
					}
					updated = true
					break
				}
			}
		}

		if !updated {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Entry not found"}}}, nil
		}

		saveVault(vault, masterPwd, vaultPath)
		LogAction("MCP_ENTRY_EDITED", fmt.Sprintf("Token '%s' edited entry '%s'", mcpToken.Name, args.Name))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Entry updated"}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:	"manage_profiles",
		Description:	"List or configure encryption profiles",
		InputSchema: map[string]any{
			"type":	"object",
			"properties": map[string]any{
				"action":	map[string]any{"type": "string", "enum": []string{"list", "set"}},
				"profile":	map[string]any{"type": "string"},
			},
			"required":	[]string{"action"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "admin") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Action	string		`json:"action"`
			Profile	string		`json:"profile"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		vault, masterPwd, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error"}}}, nil
		}

		if args.Action == "list" {
			profiles := []string{}
			for name := range Profiles {
				profiles = append(profiles, name)
			}
			sort.Strings(profiles)
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Current Profile: %s\nAvailable: %s", vault.Profile, strings.Join(profiles, ", "))}}}, nil
		}

		if args.Action == "set" {
			p := GetProfile(args.Profile)
			if p.Name == "" {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Invalid profile name"}}}, nil
			}
			vault.Profile = args.Profile
			vault.CurrentProfileParams = &p
			saveVault(vault, masterPwd, vaultPath)
			LogAction("MCP_PROFILE_CHANGED", fmt.Sprintf("Changed profile to %s", args.Profile))
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Profile updated"}}}, nil
		}

		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Unknown action"}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:	"manage_spaces",
		Description:	"List, create or switch spaces",
		InputSchema: map[string]any{
			"type":	"object",
			"properties": map[string]any{
				"action":	map[string]any{"type": "string", "enum": []string{"list", "add", "switch"}},
				"name":	map[string]any{"type": "string"},
			},
			"required":	[]string{"action"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "write") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Action	string		`json:"action"`
			Name	string		`json:"name"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		vault, masterPwd, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error"}}}, nil
		}

		switch args.Action {
		case "list":
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Current Space: %s\nAll Spaces: %s", vault.CurrentSpace, strings.Join(vault.Spaces, ", "))}}}, nil
		case "add":
			for _, s := range vault.Spaces {
				if s == args.Name {
					return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Space already exists"}}}, nil
				}
			}
			vault.Spaces = append(vault.Spaces, args.Name)
			saveVault(vault, masterPwd, vaultPath)
			LogAction("MCP_SPACE_ADDED", fmt.Sprintf("Added space %s", args.Name))
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Space added"}}}, nil
		case "switch":
			found := false
			for _, s := range vault.Spaces {
				if s == args.Name {
					found = true
					break
				}
			}
			if !found && args.Name != "" {
				return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Space not found"}}}, nil
			}
			vault.CurrentSpace = args.Name
			saveVault(vault, masterPwd, vaultPath)
			LogAction("MCP_SPACE_SWITCHED", fmt.Sprintf("Switched to space %s", args.Name))
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Switched to %s", args.Name)}}}, nil
		}

		return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Unknown action"}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:	"cloud_config",
		Description:	"Configure cloud sync credentials",
		InputSchema: map[string]any{
			"type":	"object",
			"properties": map[string]any{
				"provider":	map[string]any{"type": "string", "enum": []string{"gdrive", "github"}},
				"token":	map[string]any{"type": "string"},
				"repo":	map[string]any{"type": "string"},
			},
			"required":	[]string{"provider", "token"},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "admin") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Provider	string		`json:"provider"`
			Token	string		`json:"token"`
			Repo	string		`json:"repo"`
		}
		json.Unmarshal(req.Params.Arguments, &args)

		vault, masterPwd, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error"}}}, nil
		}

		if args.Provider == "gdrive" {
			vault.CloudToken = []byte(args.Token)
		} else {
			vault.GitHubToken = args.Token
			vault.GitHubRepo = args.Repo
		}

		if err := saveVault(vault, masterPwd, vaultPath); err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Save Error: %v", err)}}}, nil
		}
		LogAction("MCP_CLOUD_CONFIG", fmt.Sprintf("Updated %s config", args.Provider))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Cloud configuration updated"}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:	"get_history",
		Description:	"View vault item history (audit logs for specific items)",
		InputSchema: map[string]any{
			"type":	"object",
			"properties": map[string]any{
				"limit": map[string]any{"type": "integer"},
			},
		},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "admin") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		var args struct {
			Limit int `json:"limit"`
		}
		json.Unmarshal(req.Params.Arguments, &args)
		if args.Limit == 0 {
			args.Limit = 20
		}

		vault, _, err := unlockVaultForMCP(vaultPath)
		if err != nil {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Vault Error"}}}, nil
		}

		history := vault.History
		if len(history) > args.Limit {
			history = history[len(history)-args.Limit:]
		}

		var sb strings.Builder
		sb.WriteString("Vault History:\n")
		for i := len(history) - 1; i >= 0; i-- {
			h := history[i]
			sb.WriteString(fmt.Sprintf("[%s] %s %s: %s\n", h.Timestamp.Format(time.RFC3339), h.Action, h.Category, h.Identifier))
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: sb.String()}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:	"generate_password",
		Description:	"Generate a secure random password",
		InputSchema:	map[string]any{"type": "object", "properties": map[string]any{"length": map[string]any{"type": "integer"}}},
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

	pluginsDir := filepath.Join(filepath.Dir(vaultPath), "plugins")
	if pm != nil {
		if pm != nil {
			pm.LoadPlugins()
		}
	}

	s.AddTool(&mcp.Tool{
		Name:	"list_plugins",
		Description:	"List installed plugins",
		InputSchema:	map[string]any{"type": "object"},
	}, func(ctx context.Context, req *mcp.CallToolRequest) (*mcp.CallToolResult, error) {
		if !hasPermission(mcpToken.Permissions, "read") {
			return &mcp.CallToolResult{IsError: true, Content: []mcp.Content{&mcp.TextContent{Text: "Denied"}}}, nil
		}
		if pm != nil {
			pm.LoadPlugins()
			list := pm.ListPlugins()
			return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: fmt.Sprintf("Installed plugins: %s", strings.Join(list, ", "))}}}, nil
		}
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Plugin manager not available"}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:	"install_plugin",
		Description:	"Install a plugin from Marketplace",
		InputSchema:	map[string]any{"type": "object", "properties": map[string]any{"name": map[string]any{"type": "string"}}, "required": []string{"name"}},
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
		if pm != nil {
			pm.LoadPlugins()
		}
		LogAction("MCP_PLUGIN_INSTALLED", fmt.Sprintf("Token '%s' installed '%s'", mcpToken.Name, args.Name))
		return &mcp.CallToolResult{Content: []mcp.Content{&mcp.TextContent{Text: "Plugin installed"}}}, nil
	})

	s.AddTool(&mcp.Tool{
		Name:	"cloud_sync",
		Description:	"Trigger cloud sync",
		InputSchema:	map[string]any{"type": "object", "properties": map[string]any{"provider": map[string]any{"type": "string", "enum": []string{"gdrive", "github"}}}, "required": []string{"provider"}},
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

	s.AddTool(&mcp.Tool{
		Name:	"get_audit_logs",
		Description:	"Retrieve recent audit logs",
		InputSchema:	map[string]any{"type": "object", "properties": map[string]any{"limit": map[string]any{"type": "integer"}}},
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
	nonceSize := gcm.NonceSize()
	if len(plaintext) < nonceSize {
		return nil, fmt.Errorf("plaintext too short")
	}
	nonce := make([]byte, nonceSize)
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}
	return gcm.Seal(nonce, nonce, plaintext, nil), nil
}

func decryptEpisodic(ciphertext []byte, key []byte) ([]byte, error) {
	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}
	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}
	nonceSize := gcm.NonceSize()
	if len(ciphertext) < nonceSize {
		return nil, fmt.Errorf("ciphertext too short")
	}
	nonce, ciphertext := ciphertext[:nonceSize], ciphertext[nonceSize:]
	return gcm.Open(nil, nonce, ciphertext, nil)
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
		fmt.Printf("DEBUG: LoadVault error: %v\n", err)
		return nil, "", err
	}

	if session.ReadOnly {
		return GetDecoyVault(), session.MasterPassword, nil
	}

	vault, err := DecryptVault(data, session.MasterPassword, 1)
	if err != nil {
		fmt.Printf("DEBUG: DecryptVault error: %v\n", err)
		return nil, "", err
	}

	return vault, session.MasterPassword, nil
}
