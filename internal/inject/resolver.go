package inject

import (
	"errors"
	"fmt"
	"strings"
	"unicode"

	apm "github.com/aaravmaloo/apm/src"
)

type ResolvedEntry struct {
	EntryName  string
	EnvVarName string
	Value      []byte
	Type       string
}

func ResolveEntries(vault *apm.Vault, names []string) ([]ResolvedEntry, error) {
	if vault == nil {
		return nil, errors.New("vault is nil")
	}

	missing := make([]string, 0)
	results := make([]ResolvedEntry, 0, len(names))

	for _, raw := range names {
		name := strings.TrimSpace(raw)
		if name == "" {
			continue
		}

		resolved, ok := resolveByName(vault, name)
		if !ok {
			missing = append(missing, name)
			continue
		}
		results = append(results, resolved)
	}

	if len(missing) > 0 {
		return nil, fmt.Errorf("entries not found: %s", strings.Join(missing, ", "))
	}

	return results, nil
}

func ToEnvVarName(entryName string) string {
	name := strings.TrimSpace(entryName)
	if name == "" {
		return ""
	}

	var b strings.Builder
	lastUnderscore := false

	for _, r := range name {
		if unicode.IsLetter(r) || unicode.IsNumber(r) {
			b.WriteRune(unicode.ToUpper(r))
			lastUnderscore = false
			continue
		}
		if !lastUnderscore {
			b.WriteByte('_')
			lastUnderscore = true
		}
	}

	result := strings.Trim(b.String(), "_")
	if result == "" {
		return ""
	}
	if result[0] >= '0' && result[0] <= '9' {
		result = "_" + result
	}
	return result
}

func resolveByName(vault *apm.Vault, name string) (ResolvedEntry, bool) {
	if e, ok := vault.GetEntry(name); ok {
		return newResolved(name, "Password", e.Password), true
	}
	if e, ok := vault.GetTOTPEntry(name); ok {
		return newResolved(name, "TOTP", e.Secret), true
	}
	if e, ok := vault.GetToken(name); ok {
		return newResolved(name, "Token", e.Token), true
	}
	if e, ok := vault.GetSecureNote(name); ok {
		return newResolved(name, "SecureNote", e.Content), true
	}
	if e, ok := vault.GetAPIKey(name); ok {
		return newResolved(name, "APIKey", e.Key), true
	}
	if e, ok := vault.GetSSHKey(name); ok {
		return newResolved(name, "SSHKey", e.PrivateKey), true
	}
	if e, ok := vault.GetWiFi(name); ok {
		return newResolved(name, "WiFi", e.Password), true
	}
	if e, ok := vault.GetRecoveryCode(name); ok {
		return newResolved(name, "RecoveryCodes", strings.Join(e.Codes, "\n")), true
	}
	if e, ok := vault.GetCertificate(name); ok {
		return newResolved(name, "Certificate", e.PrivateKey), true
	}

	if e, ok := resolveCloudCredential(vault, name); ok {
		return e, true
	}
	if e, ok := resolveDockerRegistry(vault, name); ok {
		return e, true
	}
	if e, ok := resolveSSHConfig(vault, name); ok {
		return e, true
	}

	return ResolvedEntry{}, false
}

func newResolved(name, typ, value string) ResolvedEntry {
	return ResolvedEntry{
		EntryName:  name,
		EnvVarName: ToEnvVarName(name),
		Value:      []byte(value),
		Type:       typ,
	}
}

func matchSpace(vault *apm.Vault, entrySpace string) bool {
	current := vault.CurrentSpace
	if current == "" {
		current = "default"
	}
	target := entrySpace
	if target == "" {
		target = "default"
	}
	return current == target
}

func resolveCloudCredential(vault *apm.Vault, name string) (ResolvedEntry, bool) {
	for _, e := range vault.CloudCredentialsItems {
		if e.Label == name && matchSpace(vault, e.Space) {
			return newResolved(name, "CloudCredential", e.SecretKey), true
		}
	}
	return ResolvedEntry{}, false
}

func resolveDockerRegistry(vault *apm.Vault, name string) (ResolvedEntry, bool) {
	for _, e := range vault.DockerRegistries {
		if e.Name == name && matchSpace(vault, e.Space) {
			return newResolved(name, "DockerRegistry", e.Token), true
		}
	}
	return ResolvedEntry{}, false
}

func resolveSSHConfig(vault *apm.Vault, name string) (ResolvedEntry, bool) {
	for _, e := range vault.SSHConfigs {
		if e.Alias == name && matchSpace(vault, e.Space) {
			return newResolved(name, "SSHConfig", e.PrivateKey), true
		}
	}
	return ResolvedEntry{}, false
}
