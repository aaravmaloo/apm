package apm

import (
	"strings"
	"testing"
)

func TestRunCleanupNoIssues(t *testing.T) {
	v := &Vault{
		Spaces:  []string{"default"},
		Entries: []Entry{{Account: "test", Username: "user", Password: "pass"}},
		AutocompleteWindowDisabled: true,
	}

	issues := RunCleanup(v)
	// A vault with AutocompleteWindowDisabled=true and no other problems should have 0 issues
	for _, iss := range issues {
		t.Errorf("unexpected issue: [%s] %s", iss.Section, iss.Message)
	}
}

func TestRunCleanupEmptyEntry(t *testing.T) {
	v := &Vault{
		Entries: []Entry{
			{Account: "valid", Username: "u", Password: "p"},
			{Account: "", Username: "", Password: ""},
		},
	}

	issues := RunCleanup(v)
	found := false
	for _, iss := range issues {
		if iss.Section == "entries" && iss.Severity == "warning" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected warning about empty entry")
	}
}

func TestRunCleanupEmptyTOTP(t *testing.T) {
	v := &Vault{
		Spaces: []string{"default"},
		TOTPEntries: []TOTPEntry{
			{Account: "", Secret: ""},
		},
	}

	issues := RunCleanup(v)
	found := false
	for _, iss := range issues {
		if iss.Section == "totp_entries" && iss.Severity == "warning" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected warning about empty TOTP entry")
	}
}

func TestRunCleanupEmptySecret(t *testing.T) {
	v := &Vault{
		Spaces: []string{"default"},
		TOTPEntries: []TOTPEntry{
			{Account: "test", Secret: ""},
		},
	}

	issues := RunCleanup(v)
	found := false
	for _, iss := range issues {
		if iss.Section == "totp_entries" && iss.Severity == "error" {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected error about empty TOTP secret")
	}
}

func TestRunCleanupOrphanedSpace(t *testing.T) {
	v := &Vault{
		Spaces:  []string{"default"},
		Entries: []Entry{{Account: "test", Space: "nonexistent"}},
	}

	issues := RunCleanup(v)
	found := false
	for _, iss := range issues {
		if iss.Section == "entries" && iss.Severity == "warning" && strings.Contains(iss.Message, "nonexistent") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected warning about orphaned space")
	}
}

func TestRunCleanupStaleFailedAttempts(t *testing.T) {
	v := &Vault{
		Spaces:         []string{"default"},
		FailedAttempts: 3,
		EmergencyMode:  false,
	}

	issues := RunCleanup(v)
	found := false
	for _, iss := range issues {
		if iss.Section == "security" && iss.AutoFix {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected auto-fixable stale failed attempts issue")
	}
}

func TestRunCleanupCorruptedEntry(t *testing.T) {
	v := &Vault{
		Spaces:  []string{"default"},
		Entries: []Entry{{Account: "empty", Username: "", Password: ""}},
	}

	issues := RunCleanup(v)
	found := false
	for _, iss := range issues {
		if iss.Section == "entries" && iss.Severity == "warning" && strings.Contains(iss.Message, "no username") {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected warning about entry with no username or password")
	}
}

func TestRunCleanupEmptySpacesList(t *testing.T) {
	v := &Vault{
		Spaces: []string{""},
	}

	issues := RunCleanup(v)
	found := false
	for _, iss := range issues {
		if iss.Section == "spaces" && iss.AutoFix {
			found = true
			break
		}
	}
	if !found {
		t.Fatal("expected auto-fixable empty spaces list issue")
	}
}

func TestRunCleanupAutoFix(t *testing.T) {
	v := &Vault{
		Spaces:         []string{"default"},
		Entries: []Entry{
			{Account: "keep", Username: "u", Password: "p"},
			{Account: "", Username: "", Password: ""},
			{Account: "also-keep", Username: "u2", Password: "p2"},
		},
	}

	issues := RunCleanup(v)
	for _, iss := range issues {
		if iss.AutoFix && iss.RemoveFn != nil {
			iss.RemoveFn(v)
		}
	}

	if len(v.Entries) != 2 {
		t.Fatalf("expected 2 entries after fix, got %d", len(v.Entries))
	}
	if v.Entries[0].Account != "keep" || v.Entries[1].Account != "also-keep" {
		t.Fatal("entries not in expected order after fix")
	}
}


