package apm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type EphemeralSession struct {
	ID             string    `json:"id"`
	Label          string    `json:"label,omitempty"`
	Scope          string    `json:"scope"`
	BoundHostHash  string    `json:"bound_host_hash,omitempty"`
	BoundPID       int       `json:"bound_pid,omitempty"`
	BoundAgent     string    `json:"bound_agent,omitempty"`
	MasterPassword string    `json:"master_password"`
	CreatedAt      time.Time `json:"created_at"`
	ExpiresAt      time.Time `json:"expires_at"`
	Revoked        bool      `json:"revoked"`
	RevokedAt      time.Time `json:"revoked_at,omitempty"`
}

type EphemeralSessionStore struct {
	Sessions map[string]EphemeralSession `json:"sessions"`
}

// Ephemeral sessions live in the user config directory so short-lived unlock
// material stays outside the vault blob and can be revoked independently.
func getEphemeralSessionFile() string {
	configDir, _ := os.UserConfigDir()
	apmDir := filepath.Join(configDir, "apm")
	_ = os.MkdirAll(apmDir, 0700)
	return filepath.Join(apmDir, "ephemeral_sessions.json")
}

func currentHostHash() string {
	host, _ := os.Hostname()
	user := os.Getenv("USERNAME")
	if user == "" {
		user = os.Getenv("USER")
	}
	h := sha256.Sum256([]byte(strings.ToLower(strings.TrimSpace(host + "|" + user))))
	return hex.EncodeToString(h[:])
}

// loadEphemeralSessionStore also opportunistically prunes expired entries so
// callers do not have to maintain a separate cleanup step.
func loadEphemeralSessionStore() (*EphemeralSessionStore, error) {
	path := getEphemeralSessionFile()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &EphemeralSessionStore{Sessions: map[string]EphemeralSession{}}, nil
	}
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	store := &EphemeralSessionStore{}
	if err := json.Unmarshal(data, store); err != nil {
		return nil, err
	}
	if store.Sessions == nil {
		store.Sessions = map[string]EphemeralSession{}
	}

	now := time.Now()
	changed := false
	for id, s := range store.Sessions {
		if now.After(s.ExpiresAt) {
			delete(store.Sessions, id)
			changed = true
		}
	}
	if changed {
		_ = saveEphemeralSessionStore(store)
	}
	return store, nil
}

func saveEphemeralSessionStore(store *EphemeralSessionStore) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(getEphemeralSessionFile(), data, 0600)
}

// IssueEphemeralSession records a scoped unlock token that can optionally bind
// to host, pid, and agent identity to reduce reuse outside the intended caller.
func IssueEphemeralSession(masterPassword, label, scope, agent string, ttl time.Duration, bindHost bool, bindPID int) (EphemeralSession, error) {
	if ttl <= 0 {
		return EphemeralSession{}, fmt.Errorf("ttl must be greater than zero")
	}
	if scope == "" {
		scope = "read"
	}
	if scope != "read" && scope != "write" {
		return EphemeralSession{}, fmt.Errorf("invalid scope '%s': use read or write", scope)
	}

	randID, err := GenerateRandomHex(24)
	if err != nil {
		return EphemeralSession{}, err
	}
	s := EphemeralSession{
		ID:             "eps_" + randID,
		Label:          strings.TrimSpace(label),
		Scope:          scope,
		BoundPID:       bindPID,
		BoundAgent:     strings.TrimSpace(agent),
		MasterPassword: masterPassword,
		CreatedAt:      time.Now(),
		ExpiresAt:      time.Now().Add(ttl),
	}
	if bindHost {
		s.BoundHostHash = currentHostHash()
	}

	store, err := loadEphemeralSessionStore()
	if err != nil {
		return EphemeralSession{}, err
	}
	store.Sessions[s.ID] = s
	if err := saveEphemeralSessionStore(store); err != nil {
		return EphemeralSession{}, err
	}
	LogAction("EPHEMERAL_SESSION_ISSUED", fmt.Sprintf("Issued ephemeral session '%s' scope=%s", s.ID, s.Scope))
	return s, nil
}

// ValidateEphemeralSession enforces expiry and all requested bindings before
// handing the stored master password back to the unlock path.
func ValidateEphemeralSession(id string, currentPID int, currentAgent string) (*EphemeralSession, error) {
	store, err := loadEphemeralSessionStore()
	if err != nil {
		return nil, err
	}
	s, ok := store.Sessions[strings.TrimSpace(id)]
	if !ok {
		return nil, fmt.Errorf("ephemeral session not found")
	}
	if s.Revoked {
		return nil, fmt.Errorf("ephemeral session revoked")
	}
	if time.Now().After(s.ExpiresAt) {
		delete(store.Sessions, s.ID)
		_ = saveEphemeralSessionStore(store)
		return nil, fmt.Errorf("ephemeral session expired")
	}
	if s.BoundHostHash != "" && s.BoundHostHash != currentHostHash() {
		return nil, fmt.Errorf("ephemeral session host binding mismatch")
	}
	if s.BoundPID > 0 && s.BoundPID != currentPID {
		return nil, fmt.Errorf("ephemeral session pid binding mismatch")
	}
	if strings.TrimSpace(s.BoundAgent) != "" && strings.TrimSpace(currentAgent) != strings.TrimSpace(s.BoundAgent) {
		return nil, fmt.Errorf("ephemeral session agent binding mismatch")
	}
	return &s, nil
}

func RevokeEphemeralSession(id string) (bool, error) {
	store, err := loadEphemeralSessionStore()
	if err != nil {
		return false, err
	}
	s, ok := store.Sessions[strings.TrimSpace(id)]
	if !ok {
		return false, nil
	}
	s.Revoked = true
	s.RevokedAt = time.Now()
	store.Sessions[s.ID] = s
	if err := saveEphemeralSessionStore(store); err != nil {
		return false, err
	}
	LogAction("EPHEMERAL_SESSION_REVOKED", fmt.Sprintf("Revoked ephemeral session '%s'", s.ID))
	return true, nil
}

func ListEphemeralSessions() ([]EphemeralSession, error) {
	store, err := loadEphemeralSessionStore()
	if err != nil {
		return nil, err
	}
	out := make([]EphemeralSession, 0, len(store.Sessions))
	for _, s := range store.Sessions {
		if !time.Now().After(s.ExpiresAt) {
			out = append(out, s)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].ExpiresAt.Before(out[j].ExpiresAt)
	})
	return out, nil
}
