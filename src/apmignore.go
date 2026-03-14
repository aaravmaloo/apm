package apm

import (
	"bufio"
	"fmt"
	"os"
	"path"
	"path/filepath"
	"strings"
)

const APMIgnoreFileName = ".apmignore"

type IgnoreEntryRule struct {
	SpacePattern string
	TypePattern  string
	NamePattern  string
}

type IgnoreCloudRule struct {
	ProviderPattern string
	SpacePattern    string
	TypePattern     string
	NamePattern     string
}

type IgnoreConfig struct {
	Spaces        []string
	Entries       []IgnoreEntryRule
	Vocab         []string
	CloudSpecific []IgnoreCloudRule
	Misc          map[string]string
}

func (cfg IgnoreConfig) IsEmpty() bool {
	return len(cfg.Spaces) == 0 && len(cfg.Entries) == 0 && len(cfg.Vocab) == 0 && len(cfg.CloudSpecific) == 0 && len(cfg.Misc) == 0
}

func LoadIgnoreConfigForVault(vaultPath string) (IgnoreConfig, string, error) {
	candidates := make([]string, 0, 2)
	if wd, err := os.Getwd(); err == nil && wd != "" {
		candidates = append(candidates, filepath.Join(wd, APMIgnoreFileName))
	}
	if strings.TrimSpace(vaultPath) != "" {
		candidates = append(candidates, filepath.Join(filepath.Dir(vaultPath), APMIgnoreFileName))
	}

	seen := make(map[string]struct{})
	for _, c := range candidates {
		c = filepath.Clean(c)
		if _, ok := seen[c]; ok {
			continue
		}
		seen[c] = struct{}{}

		info, err := os.Stat(c)
		if err != nil || info.IsDir() {
			continue
		}
		cfg, parseErr := LoadIgnoreConfig(c)
		return cfg, c, parseErr
	}
	return IgnoreConfig{}, "", nil
}

func LoadIgnoreConfig(filePath string) (IgnoreConfig, error) {
	data, err := os.ReadFile(filePath)
	if err != nil {
		return IgnoreConfig{}, err
	}
	return ParseIgnoreConfig(string(data))
}

func ParseIgnoreConfig(content string) (IgnoreConfig, error) {
	cfg := IgnoreConfig{
		Misc: make(map[string]string),
	}

	section := ""
	scanner := bufio.NewScanner(strings.NewReader(content))
	lineNo := 0
	for scanner.Scan() {
		lineNo++
		line := strings.TrimSpace(stripIgnoreInlineComment(scanner.Text()))
		if line == "" {
			continue
		}

		if strings.HasPrefix(line, "[") && strings.HasSuffix(line, "]") {
			section = strings.ToLower(strings.TrimSpace(line[1 : len(line)-1]))
			continue
		}

		switch section {
		case "spaces":
			cfg.Spaces = append(cfg.Spaces, normalizeIgnoreToken(line, false))
		case "entries":
			rule, err := parseIgnoreEntryRule(line)
			if err != nil {
				return IgnoreConfig{}, fmt.Errorf(".apmignore line %d: %w", lineNo, err)
			}
			cfg.Entries = append(cfg.Entries, rule)
		case "vocab":
			cfg.Vocab = append(cfg.Vocab, normalizeIgnoreToken(line, true))
		case "cloud-specific-ignore":
			rule, err := parseIgnoreCloudRule(line)
			if err != nil {
				return IgnoreConfig{}, fmt.Errorf(".apmignore line %d: %w", lineNo, err)
			}
			cfg.CloudSpecific = append(cfg.CloudSpecific, rule)
		case "misc":
			key, value := parseIgnoreKeyValue(line)
			if key == "" {
				continue
			}
			cfg.Misc[strings.ToLower(key)] = value
		default:

		}
	}
	if err := scanner.Err(); err != nil {
		return IgnoreConfig{}, err
	}
	return cfg, nil
}

func (cfg IgnoreConfig) ShouldIgnoreSpace(space string) bool {
	space = normalizeIgnoreSpace(space)
	for _, pattern := range cfg.Spaces {
		if ignorePatternMatch(pattern, space, false) {
			return true
		}
	}
	return false
}

func (cfg IgnoreConfig) ShouldIgnoreEntry(space, entryType, name, provider string) bool {
	space = normalizeIgnoreSpace(space)
	entryType = normalizeIgnoreType(entryType)
	name = strings.TrimSpace(name)
	provider = strings.ToLower(strings.TrimSpace(provider))

	if cfg.ShouldIgnoreSpace(space) {
		return true
	}

	for _, rule := range cfg.Entries {
		if ignorePatternMatch(rule.SpacePattern, space, false) &&
			ignorePatternMatch(rule.TypePattern, entryType, false) &&
			ignorePatternMatch(rule.NamePattern, name, false) {
			return true
		}
	}

	for _, rule := range cfg.CloudSpecific {
		if ignorePatternMatch(rule.ProviderPattern, provider, false) &&
			ignorePatternMatch(rule.SpacePattern, space, false) &&
			ignorePatternMatch(rule.TypePattern, entryType, false) &&
			ignorePatternMatch(rule.NamePattern, name, false) {
			return true
		}
	}
	return false
}

func (cfg IgnoreConfig) ShouldIgnoreVocabWord(word string) bool {
	word = strings.TrimSpace(word)
	for _, pattern := range cfg.Vocab {
		if ignorePatternMatch(pattern, word, true) {
			return true
		}
	}
	return false
}

func (cfg IgnoreConfig) MiscIgnoreEnabled(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	if name == "" {
		return false
	}
	for key, value := range cfg.Misc {
		v := strings.ToLower(strings.TrimSpace(value))
		if key == "ignore" && (v == name || v == "*") {
			return true
		}
		if key == name && (v == "" || v == "true" || v == "1" || v == "yes" || v == "on") {
			return true
		}
	}
	return false
}

func (cfg IgnoreConfig) FilterVaultForProvider(vault *Vault, provider string) *Vault {
	if vault == nil {
		return nil
	}
	clone := *vault
	provider = strings.ToLower(strings.TrimSpace(provider))

	clone.Entries = filterSlice(clone.Entries, func(e Entry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "password", e.Account, provider)
	})
	clone.TOTPEntries = filterSlice(clone.TOTPEntries, func(e TOTPEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "totp", e.Account, provider)
	})
	clone.Tokens = filterSlice(clone.Tokens, func(e TokenEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "token", e.Name, provider)
	})
	clone.SecureNotes = filterSlice(clone.SecureNotes, func(e SecureNoteEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "note", e.Name, provider)
	})
	clone.APIKeys = filterSlice(clone.APIKeys, func(e APIKeyEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "api-key", e.Name, provider)
	})
	clone.SSHKeys = filterSlice(clone.SSHKeys, func(e SSHKeyEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "ssh-key", e.Name, provider)
	})
	clone.WiFiCredentials = filterSlice(clone.WiFiCredentials, func(e WiFiEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "wifi", e.SSID, provider)
	})
	clone.RecoveryCodeItems = filterSlice(clone.RecoveryCodeItems, func(e RecoveryCodeEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "recovery-codes", e.Service, provider)
	})
	clone.Certificates = filterSlice(clone.Certificates, func(e CertificateEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "certificate", e.Label, provider)
	})
	clone.BankingItems = filterSlice(clone.BankingItems, func(e BankingEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "banking", e.Label, provider)
	})
	clone.Documents = filterSlice(clone.Documents, func(e DocumentEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "document", e.Name, provider)
	})
	clone.AudioFiles = filterSlice(clone.AudioFiles, func(e AudioEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "audio", e.Name, provider)
	})
	clone.VideoFiles = filterSlice(clone.VideoFiles, func(e VideoEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "video", e.Name, provider)
	})
	clone.PhotoFiles = filterSlice(clone.PhotoFiles, func(e PhotoEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "photo", e.Name, provider)
	})
	clone.GovIDs = filterSlice(clone.GovIDs, func(e GovIDEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "gov-id", e.IDNumber, provider)
	})
	clone.MedicalRecords = filterSlice(clone.MedicalRecords, func(e MedicalRecordEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "medical", e.Label, provider)
	})
	clone.TravelDocs = filterSlice(clone.TravelDocs, func(e TravelEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "travel", e.Label, provider)
	})
	clone.Contacts = filterSlice(clone.Contacts, func(e ContactEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "contact", e.Name, provider)
	})
	clone.CloudCredentialsItems = filterSlice(clone.CloudCredentialsItems, func(e CloudCredentialEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "cloud-credentials", e.Label, provider)
	})
	clone.K8sSecrets = filterSlice(clone.K8sSecrets, func(e K8sSecretEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "k8s-secret", e.Name, provider)
	})
	clone.DockerRegistries = filterSlice(clone.DockerRegistries, func(e DockerRegistryEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "docker-registry", e.Name, provider)
	})
	clone.SSHConfigs = filterSlice(clone.SSHConfigs, func(e SSHConfigEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "ssh-config", e.Alias, provider)
	})
	clone.CICDSecrets = filterSlice(clone.CICDSecrets, func(e CICDSecretEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "cicd-secret", e.Name, provider)
	})
	clone.SoftwareLicenses = filterSlice(clone.SoftwareLicenses, func(e SoftwareLicenseEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "software-license", e.ProductName, provider)
	})
	clone.LegalContracts = filterSlice(clone.LegalContracts, func(e LegalContractEntry) bool {
		return !cfg.ShouldIgnoreEntry(e.Space, "legal-contract", e.Name, provider)
	})

	if len(clone.Spaces) > 0 {
		clone.Spaces = filterSlice(clone.Spaces, func(space string) bool {
			return !cfg.ShouldIgnoreSpace(space)
		})
		if len(clone.Spaces) == 0 {
			clone.Spaces = []string{"default"}
		}
	}
	if cfg.ShouldIgnoreSpace(clone.CurrentSpace) {
		clone.CurrentSpace = ""
	}

	if clone.SecretTelemetry != nil {
		filtered := make(map[string]SecretTelemetry, len(clone.SecretTelemetry))
		for key, telemetry := range clone.SecretTelemetry {
			category, identifier, space := parseSecretTelemetryKey(key)
			if cfg.ShouldIgnoreEntry(space, historyCategoryToIgnoreType(category), identifier, provider) {
				continue
			}
			filtered[key] = telemetry
		}
		clone.SecretTelemetry = filtered
	}

	if len(clone.History) > 0 {
		clone.History = filterSlice(clone.History, func(h HistoryEntry) bool {
			entryType := historyCategoryToIgnoreType(h.Category)
			if entryType == "" {
				return true
			}
			return !cfg.ShouldIgnoreEntry("", entryType, h.Identifier, provider)
		})
	}

	if cfg.MiscIgnoreEnabled("vocab") {
		clone.VocabCompressed = nil
	} else if len(cfg.Vocab) > 0 && len(clone.VocabCompressed) > 0 {
		vocab, err := clone.LoadNoteVocabulary()
		if err == nil {
			for word := range vocab.Words {
				if cfg.ShouldIgnoreVocabWord(word) {
					delete(vocab.Words, word)
				}
			}
			_ = clone.SaveNoteVocabulary(vocab)
		}
	}

	return &clone
}

func stripIgnoreInlineComment(line string) string {
	inSingle := false
	inDouble := false
	for i, r := range line {
		switch r {
		case '\'':
			if !inDouble {
				inSingle = !inSingle
			}
		case '"':
			if !inSingle {
				inDouble = !inDouble
			}
		case '#':
			if !inSingle && !inDouble {
				return line[:i]
			}
		}
	}
	return line
}

func parseIgnoreEntryRule(line string) (IgnoreEntryRule, error) {
	parts := strings.SplitN(line, ":", 3)
	if len(parts) != 3 {
		return IgnoreEntryRule{}, fmt.Errorf("entry rule must be 'space:type:name'")
	}
	return IgnoreEntryRule{
		SpacePattern: normalizeIgnoreToken(parts[0], false),
		TypePattern:  normalizeIgnoreType(parts[1]),
		NamePattern:  normalizeIgnoreToken(parts[2], false),
	}, nil
}

func parseIgnoreCloudRule(line string) (IgnoreCloudRule, error) {
	parts := strings.SplitN(line, ":", 4)
	if len(parts) != 4 {
		return IgnoreCloudRule{}, fmt.Errorf("cloud-specific rule must be 'provider:space:type:name'")
	}
	return IgnoreCloudRule{
		ProviderPattern: normalizeIgnoreToken(parts[0], false),
		SpacePattern:    normalizeIgnoreSpace(parts[1]),
		TypePattern:     normalizeIgnoreType(parts[2]),
		NamePattern:     normalizeIgnoreToken(parts[3], false),
	}, nil
}

func parseIgnoreKeyValue(line string) (string, string) {
	parts := strings.SplitN(line, ":", 2)
	if len(parts) == 1 {
		return normalizeIgnoreToken(parts[0], false), ""
	}
	return normalizeIgnoreToken(parts[0], false), normalizeIgnoreToken(parts[1], false)
}

func normalizeIgnoreToken(v string, caseSensitive bool) string {
	v = strings.TrimSpace(v)
	if len(v) >= 2 {
		if (v[0] == '\'' && v[len(v)-1] == '\'') || (v[0] == '"' && v[len(v)-1] == '"') {
			v = v[1 : len(v)-1]
		}
	}
	v = strings.TrimSpace(v)
	if !caseSensitive {
		v = strings.ToLower(v)
	}
	return v
}

func normalizeIgnoreSpace(v string) string {
	v = normalizeIgnoreToken(v, false)
	if v == "" {
		return "default"
	}
	return v
}

func normalizeIgnoreType(v string) string {
	t := normalizeIgnoreToken(v, false)
	if strings.ContainsAny(t, "*?[]") {
		return t
	}
	switch t {
	case "", "secret":
		return "*"
	case "password", "pass":
		return "password"
	case "totp", "otp":
		return "totp"
	case "token", "tokens":
		return "token"
	case "note", "notes", "secure-note", "secure-notes":
		return "note"
	case "api", "api-key", "apikey", "api-keys":
		return "api-key"
	case "ssh", "ssh-key", "ssh-keys":
		return "ssh-key"
	case "wifi", "wi-fi":
		return "wifi"
	case "recovery", "recovery-code", "recovery-codes":
		return "recovery-codes"
	case "certificate", "cert", "certs":
		return "certificate"
	case "banking", "bank":
		return "banking"
	case "document", "docs":
		return "document"
	case "audio":
		return "audio"
	case "video":
		return "video"
	case "photo", "image":
		return "photo"
	case "gov-id", "government-id", "id":
		return "gov-id"
	case "medical", "medical-record":
		return "medical"
	case "travel":
		return "travel"
	case "contact":
		return "contact"
	case "cloud", "cloud-credentials":
		return "cloud-credentials"
	case "k8s", "k8s-secret", "kubernetes", "kubernetes-secret":
		return "k8s-secret"
	case "docker", "docker-registry":
		return "docker-registry"
	case "ssh-config":
		return "ssh-config"
	case "cicd", "ci/cd", "ci-cd", "cicd-secret":
		return "cicd-secret"
	case "software-license", "license":
		return "software-license"
	case "legal", "legal-contract", "contract":
		return "legal-contract"
	default:
		return t
	}
}

func ignorePatternMatch(pattern, value string, caseSensitive bool) bool {
	pattern = normalizeIgnoreToken(pattern, caseSensitive)
	value = strings.TrimSpace(value)
	if !caseSensitive {
		value = strings.ToLower(value)
	}
	if pattern == "" {
		return false
	}
	if pattern == "*" {
		return true
	}
	if strings.ContainsAny(pattern, "*?[]") {
		matched, err := path.Match(pattern, value)
		if err == nil {
			return matched
		}
	}
	return pattern == value
}

func historyCategoryToIgnoreType(category string) string {
	switch strings.ToUpper(strings.TrimSpace(category)) {
	case "PASSWORD":
		return "password"
	case "TOTP":
		return "totp"
	case "TOKEN":
		return "token"
	case "NOTE":
		return "note"
	case "APIKEY":
		return "api-key"
	case "SSHKEY":
		return "ssh-key"
	case "WIFI":
		return "wifi"
	case "RECOVERY":
		return "recovery-codes"
	case "CERTIFICATE":
		return "certificate"
	case "BANKING":
		return "banking"
	case "DOCUMENT":
		return "document"
	case "AUDIO":
		return "audio"
	case "VIDEO":
		return "video"
	case "PHOTO":
		return "photo"
	case "GOVID":
		return "gov-id"
	case "MEDICAL":
		return "medical"
	case "TRAVEL":
		return "travel"
	case "CONTACT":
		return "contact"
	case "CLOUDCRED":
		return "cloud-credentials"
	case "K8S":
		return "k8s-secret"
	case "DOCKER":
		return "docker-registry"
	case "SSHCONFIG":
		return "ssh-config"
	case "CICD":
		return "cicd-secret"
	case "LICENSE":
		return "software-license"
	case "CONTRACT":
		return "legal-contract"
	default:
		return strings.ToLower(strings.TrimSpace(category))
	}
}

func filterSlice[T any](items []T, keep func(T) bool) []T {
	if len(items) == 0 {
		return items
	}
	out := make([]T, 0, len(items))
	for _, item := range items {
		if keep(item) {
			out = append(out, item)
		}
	}
	return out
}
