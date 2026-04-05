package apm

import "testing"

func TestDiffVaultEntriesReportsAddModifyRemove(t *testing.T) {
	local := &Vault{
		Entries: []Entry{
			{Account: "github", Username: "alice", Password: "old", Space: "default"},
			{Account: "legacy", Username: "bob", Password: "keep", Space: "default"},
		},
		SecureNotes: []SecureNoteEntry{
			{Name: "local-only", Content: "old note", Space: "work"},
		},
	}

	remote := &Vault{
		Entries: []Entry{
			{Account: "github", Username: "alice2", Password: "new", Space: "default"},
			{Account: "notion", Username: "carol", Password: "fresh", Space: "default"},
		},
	}

	changes := DiffVaultEntries(local, remote)
	if len(changes) != 4 {
		t.Fatalf("expected 4 changes, got %d", len(changes))
	}

	var sawAdded, sawModified, sawRemovedPassword, sawRemovedNote bool
	for _, change := range changes {
		switch {
		case change.Kind == VaultDiffAdded && change.ItemType == "Password" && change.Identifier == "notion":
			sawAdded = true
		case change.Kind == VaultDiffModified && change.ItemType == "Password" && change.Identifier == "github":
			sawModified = true
			if !containsAll(change.ChangedFields, "password", "username") {
				t.Fatalf("expected modified password fields to include username and password, got %v", change.ChangedFields)
			}
		case change.Kind == VaultDiffRemoved && change.ItemType == "Password" && change.Identifier == "legacy":
			sawRemovedPassword = true
		case change.Kind == VaultDiffRemoved && change.ItemType == "Secure Note" && change.Identifier == "local-only":
			sawRemovedNote = true
		}
	}

	if !sawAdded || !sawModified || !sawRemovedPassword || !sawRemovedNote {
		t.Fatalf("unexpected diff result set: %+v", changes)
	}
}

func TestApplyVaultDiffSelectionMergesRemoteChanges(t *testing.T) {
	local := &Vault{
		Entries: []Entry{
			{Account: "github", Username: "alice", Password: "old", Space: "default"},
			{Account: "legacy", Username: "bob", Password: "keep", Space: "default"},
		},
	}

	remote := &Vault{
		Entries: []Entry{
			{Account: "github", Username: "alice2", Password: "new", Space: "default"},
			{Account: "notion", Username: "carol", Password: "fresh", Space: "default"},
		},
	}

	changes := DiffVaultEntries(local, remote)
	if err := ApplyVaultDiffSelection(local, changes, []int{0, 1, 2}); err != nil {
		t.Fatalf("apply diff failed: %v", err)
	}

	if len(local.Entries) != 2 {
		t.Fatalf("expected 2 entries after merge, got %d", len(local.Entries))
	}

	entryByAccount := make(map[string]Entry, len(local.Entries))
	for _, entry := range local.Entries {
		entryByAccount[entry.Account] = entry
	}

	if _, exists := entryByAccount["legacy"]; exists {
		t.Fatalf("expected legacy entry to be removed")
	}
	if entryByAccount["github"].Username != "alice2" || entryByAccount["github"].Password != "new" {
		t.Fatalf("expected github entry to be updated, got %+v", entryByAccount["github"])
	}
	if entryByAccount["notion"].Username != "carol" {
		t.Fatalf("expected notion entry to be added, got %+v", entryByAccount["notion"])
	}
}

func containsAll(values []string, expected ...string) bool {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		seen[value] = struct{}{}
	}
	for _, want := range expected {
		if _, ok := seen[want]; !ok {
			return false
		}
	}
	return true
}
