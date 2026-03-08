package autofill

import (
	"encoding/json"
	"net/url"
	"os"
	"sort"
	"strings"

	src "github.com/aaravmaloo/apm/src"
)

func loadConfiguredProfiles() ([]Profile, error) {
	path, err := profileFilePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return []Profile{}, nil
		}
		return nil, err
	}

	var profiles []Profile
	if err := json.Unmarshal(data, &profiles); err != nil {
		return nil, err
	}

	for i := range profiles {
		profiles[i] = normalizeProfile(profiles[i])
	}
	return profiles, nil
}

func buildProfiles(vault *src.Vault) ([]Profile, error) {
	configured, err := loadConfiguredProfiles()
	if err != nil {
		return nil, err
	}

	seen := map[string]struct{}{}
	for _, p := range configured {
		seen[entryKey(p.EntryAccount, p.EntryUsername)] = struct{}{}
	}

	out := make([]Profile, 0, len(configured)+len(vault.Entries))
	out = append(out, configured...)

	for _, entry := range vault.Entries {
		key := entryKey(entry.Account, entry.Username)
		if _, ok := seen[key]; ok {
			continue
		}

		p := Profile{
			ID:            profileID(entry.Account, entry.Username),
			Service:       entry.Account,
			Domain:        inferDomain(entry.Account),
			EntryAccount:  entry.Account,
			EntryUsername: entry.Username,
			TOTPAccount:   entry.Account,
			Sequence:      DefaultSequenceTemplate,
		}
		p = normalizeProfile(p)
		out = append(out, p)
	}

	sort.SliceStable(out, func(i, j int) bool {
		left := strings.ToLower(out[i].Service + "|" + out[i].EntryUsername + "|" + out[i].ID)
		right := strings.ToLower(out[j].Service + "|" + out[j].EntryUsername + "|" + out[j].ID)
		return left < right
	})

	return out, nil
}

func normalizeProfile(p Profile) Profile {
	if p.ID == "" {
		p.ID = profileID(p.EntryAccount, p.EntryUsername)
	}
	if p.Service == "" {
		p.Service = p.EntryAccount
	}
	p.Domain = normalizeDomain(p.Domain)
	for i := range p.Domains {
		p.Domains[i] = normalizeDomain(p.Domains[i])
	}
	if p.TOTPAccount == "" {
		p.TOTPAccount = p.EntryAccount
	}
	if p.Sequence == "" {
		p.Sequence = DefaultSequenceTemplate
	}
	for i := range p.ProcessNames {
		p.ProcessNames[i] = strings.ToLower(strings.TrimSpace(p.ProcessNames[i]))
	}
	for i := range p.WindowContains {
		p.WindowContains[i] = strings.ToLower(strings.TrimSpace(p.WindowContains[i]))
	}
	return p
}

func inferDomain(account string) string {
	account = strings.TrimSpace(account)
	if account == "" {
		return ""
	}

	if strings.Contains(account, "://") {
		u, err := url.Parse(account)
		if err == nil {
			return normalizeDomain(u.Hostname())
		}
	}

	account = strings.TrimPrefix(account, "www.")
	if strings.Contains(account, "/") {
		u, err := url.Parse("https://" + account)
		if err == nil {
			return normalizeDomain(u.Hostname())
		}
	}

	if strings.Count(account, ".") >= 1 && !strings.Contains(account, " ") {
		return normalizeDomain(account)
	}
	return ""
}

func normalizeDomain(domain string) string {
	domain = strings.ToLower(strings.TrimSpace(domain))
	domain = strings.TrimPrefix(domain, "http://")
	domain = strings.TrimPrefix(domain, "https://")
	domain = strings.TrimPrefix(domain, "www.")
	domain = strings.TrimSuffix(domain, "/")
	return domain
}

func profileID(account, username string) string {
	base := sanitizeID(account)
	user := sanitizeID(username)
	if user == "" {
		return "entry-" + base
	}
	return "entry-" + base + "-" + user
}

func sanitizeID(v string) string {
	v = strings.ToLower(strings.TrimSpace(v))
	if v == "" {
		return "unknown"
	}
	var b strings.Builder
	for _, r := range v {
		switch {
		case r >= 'a' && r <= 'z':
			b.WriteRune(r)
		case r >= '0' && r <= '9':
			b.WriteRune(r)
		default:
			b.WriteRune('-')
		}
	}
	out := strings.Trim(b.String(), "-")
	if out == "" {
		return "unknown"
	}
	return out
}

func entryKey(account, username string) string {
	return strings.ToLower(strings.TrimSpace(account)) + "|" + strings.ToLower(strings.TrimSpace(username))
}
