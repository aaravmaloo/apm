package apm

import (
	"fmt"
	"strings"
)

// CleanupIssue represents a single issue found during vault cleanup.
type CleanupIssue struct {
	Severity  string // "info", "warning", "error"
	Section   string // e.g. "entries", "totp", "documents"
	Message   string
	AutoFix   bool          // true if APM can safely remove this
	RemoveFn  func(v *Vault) // nil if no auto-fix available
}

// RunCleanup scans the vault and returns all discovered issues.
func RunCleanup(v *Vault) []CleanupIssue {
	var issues []CleanupIssue

	issues = append(issues, checkEmptyEntries(v)...)
	issues = append(issues, checkOrphanedSpaces(v)...)
	issues = append(issues, checkDeprecatedFields(v)...)
	issues = append(issues, checkCorruptedEntries(v)...)
	issues = append(issues, checkTOTPIssues(v)...)

	return issues
}

// checkEmptyEntries finds entries with empty identifiers.
func checkEmptyEntries(v *Vault) []CleanupIssue {
	var issues []CleanupIssue

	for i, e := range v.Entries {
		if strings.TrimSpace(e.Account) == "" {
			idx := i
			issues = append(issues, CleanupIssue{
				Severity: "warning",
				Section:  "entries",
				Message:  fmt.Sprintf("Password entry #%d has an empty account name", i+1),
				AutoFix:  true,
				RemoveFn: func(v *Vault) {
					if idx < len(v.Entries) {
						v.Entries = append(v.Entries[:idx], v.Entries[idx+1:]...)
					}
				},
			})
		}
	}

	for i, t := range v.TOTPEntries {
		if strings.TrimSpace(t.Account) == "" {
			idx := i
			issues = append(issues, CleanupIssue{
				Severity: "warning",
				Section:  "totp_entries",
				Message:  fmt.Sprintf("TOTP entry #%d has an empty account name", i+1),
				AutoFix:  true,
				RemoveFn: func(v *Vault) {
					if idx < len(v.TOTPEntries) {
						v.TOTPEntries = append(v.TOTPEntries[:idx], v.TOTPEntries[idx+1:]...)
					}
				},
			})
		} else if strings.TrimSpace(t.Secret) == "" {
			idx := i
			issues = append(issues, CleanupIssue{
				Severity: "error",
				Section:  "totp_entries",
				Message:  fmt.Sprintf("TOTP entry '%s' has an empty secret", t.Account),
				AutoFix:  true,
				RemoveFn: func(v *Vault) {
					if idx < len(v.TOTPEntries) {
						v.TOTPEntries = append(v.TOTPEntries[:idx], v.TOTPEntries[idx+1:]...)
					}
				},
			})
		}
	}

	for i, n := range v.SecureNotes {
		if strings.TrimSpace(n.Name) == "" {
			idx := i
			issues = append(issues, CleanupIssue{
				Severity: "warning",
				Section:  "secure_notes",
				Message:  fmt.Sprintf("Secure note #%d has an empty name", i+1),
				AutoFix:  true,
				RemoveFn: func(v *Vault) {
					if idx < len(v.SecureNotes) {
						v.SecureNotes = append(v.SecureNotes[:idx], v.SecureNotes[idx+1:]...)
					}
				},
			})
		}
	}

	for i, t := range v.Tokens {
		if strings.TrimSpace(t.Name) == "" {
			idx := i
			issues = append(issues, CleanupIssue{
				Severity: "warning",
				Section:  "tokens",
				Message:  fmt.Sprintf("Token #%d has an empty name", i+1),
				AutoFix:  true,
				RemoveFn: func(v *Vault) {
					if idx < len(v.Tokens) {
						v.Tokens = append(v.Tokens[:idx], v.Tokens[idx+1:]...)
					}
				},
			})
		}
	}

	for i, k := range v.APIKeys {
		if strings.TrimSpace(k.Name) == "" {
			idx := i
			issues = append(issues, CleanupIssue{
				Severity: "warning",
				Section:  "api_keys",
				Message:  fmt.Sprintf("API key #%d has an empty name", i+1),
				AutoFix:  true,
				RemoveFn: func(v *Vault) {
					if idx < len(v.APIKeys) {
						v.APIKeys = append(v.APIKeys[:idx], v.APIKeys[idx+1:]...)
					}
				},
			})
		}
	}

	return issues
}

// checkOrphanedSpaces finds entries referencing spaces that no longer exist.
func checkOrphanedSpaces(v *Vault) []CleanupIssue {
	var issues []CleanupIssue

	spaceSet := make(map[string]bool)
	for _, s := range v.Spaces {
		spaceSet[strings.ToLower(strings.TrimSpace(s))] = true
	}
	spaceSet["default"] = true
	spaceSet[""] = true

	// Check password entries
	for i, e := range v.Entries {
		space := strings.ToLower(strings.TrimSpace(e.Space))
		if space != "" && !spaceSet[space] {
			idx := i
			account := e.Account
			if account == "" {
				account = fmt.Sprintf("#%d", i+1)
			}
			issues = append(issues, CleanupIssue{
				Severity: "warning",
				Section:  "entries",
				Message:  fmt.Sprintf("Entry '%s' references unknown space '%s'", account, e.Space),
				AutoFix:  true,
				RemoveFn: func(v *Vault) {
					if idx < len(v.Entries) {
						v.Entries[idx].Space = ""
					}
				},
			})
		}
	}

	// Check TOTP entries
	for i, t := range v.TOTPEntries {
		space := strings.ToLower(strings.TrimSpace(t.Space))
		if space != "" && !spaceSet[space] {
			idx := i
			account := t.Account
			if account == "" {
				account = fmt.Sprintf("#%d", i+1)
			}
			issues = append(issues, CleanupIssue{
				Severity: "warning",
				Section:  "totp_entries",
				Message:  fmt.Sprintf("TOTP entry '%s' references unknown space '%s'", account, t.Space),
				AutoFix:  true,
				RemoveFn: func(v *Vault) {
					if idx < len(v.TOTPEntries) {
						v.TOTPEntries[idx].Space = ""
					}
				},
			})
		}
	}

	return issues
}

// checkDeprecatedFields checks for deprecated or empty configuration fields.
func checkDeprecatedFields(v *Vault) []CleanupIssue {
	var issues []CleanupIssue

	// Check for empty cloud configs that take up space
	if v.CloudFileID == "" && v.CloudToken == nil && v.GitHubToken == "" && v.DropboxToken == nil {
		// Clean, no cloud config
	} else if v.CloudFileID == "" && v.GitHubToken == "" && v.DropboxToken == nil {
		// Cloud token exists but no provider configured - orphaned
		issues = append(issues, CleanupIssue{
			Severity: "info",
			Section:  "cloud",
			Message:  "Orphaned cloud token with no active provider configured",
			AutoFix:  true,
			RemoveFn: func(v *Vault) {
				v.CloudToken = nil
				v.CloudCredentials = nil
			},
		})
	}

	// Check for deprecated AutocompleteWindowDisabled (now always disabled in new versions)
	if !v.AutocompleteWindowDisabled {
		issues = append(issues, CleanupIssue{
			Severity: "info",
			Section:  "config",
			Message:  "Autocomplete window protection is not enabled (recommended)",
			AutoFix:  false,
		})
	}

	// Check for empty vault spaces list
	if len(v.Spaces) == 1 && v.Spaces[0] == "" {
		issues = append(issues, CleanupIssue{
			Severity: "info",
			Section:  "spaces",
			Message:  "Spaces list contains only an empty entry",
			AutoFix:  true,
			RemoveFn: func(v *Vault) {
				v.Spaces = nil
			},
		})
	}

	// Check for failed attempts tracking that's stale
	if v.FailedAttempts > 0 && !v.EmergencyMode {
		issues = append(issues, CleanupIssue{
			Severity: "info",
			Section:  "security",
			Message:  fmt.Sprintf("Stale failed attempts counter (%d) — can be reset", v.FailedAttempts),
			AutoFix:  true,
			RemoveFn: func(v *Vault) {
				v.FailedAttempts = 0
			},
		})
	}

	return issues
}

// checkCorruptedEntries finds entries with corrupted or impossible data.
func checkCorruptedEntries(v *Vault) []CleanupIssue {
	var issues []CleanupIssue

	for _, e := range v.Entries {
		if strings.TrimSpace(e.Account) != "" &&
			strings.TrimSpace(e.Username) == "" &&
			strings.TrimSpace(e.Password) == "" {
			issues = append(issues, CleanupIssue{
				Severity: "warning",
				Section:  "entries",
				Message:  fmt.Sprintf("Entry '%s' has no username or password", e.Account),
				AutoFix:  false, // User should decide
			})
		}
	}

	return issues
}

// checkTOTPIssues finds TOTP entries with configuration problems.
func checkTOTPIssues(v *Vault) []CleanupIssue {
	var issues []CleanupIssue

	for _, t := range v.TOTPEntries {
		if strings.TrimSpace(t.Secret) != "" && len(t.Secret) < 16 {
			issues = append(issues, CleanupIssue{
				Severity: "warning",
				Section:  "totp_entries",
				Message:  fmt.Sprintf("TOTP entry '%s' has an unusually short secret (%d chars)", t.Account, len(t.Secret)),
				AutoFix:  false,
			})
		}
	}

	// Check for duplicate TOTP entries (same account name + same space)
	seen := make(map[string]int)
	for _, t := range v.TOTPEntries {
		key := strings.ToLower(strings.TrimSpace(t.Account) + "|" + strings.TrimSpace(t.Space))
		seen[key]++
	}
	for key, count := range seen {
		if count > 1 {
			parts := strings.SplitN(key, "|", 2)
			account := parts[0]
			space := ""
			if len(parts) > 1 {
				space = parts[1]
			}
			msg := fmt.Sprintf("Duplicate TOTP entry '%s'", account)
			if space != "" {
				msg += fmt.Sprintf(" in space '%s'", space)
			}
			msg += fmt.Sprintf(" (%d copies)", count)
			issues = append(issues, CleanupIssue{
				Severity: "info",
				Section:  "totp_entries",
				Message:  msg,
				AutoFix:  false,
			})
		}
	}

	return issues
}
