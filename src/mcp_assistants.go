package apm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

// An assistant grant is what the user allowed when an MCP client first ran
// pm mcp serve without a token. It is matched by the harness pm was started
// for (--client) and the name the client reports in MCP initialize.
type MCPAssistant struct {
	ID         string    `json:"id"`
	Name       string    `json:"name"`
	ClientID   string    `json:"client_id"`
	Harness    string    `json:"harness,omitempty"`
	Perms      []string  `json:"perms"`
	CreatedAt  time.Time `json:"created"`
	LastUsedAt time.Time `json:"last_used,omitempty"`
	Uses       int       `json:"uses"`
	// Bypass is "ask" (every change is approved in the prompt) or "always"
	// (changes are approved automatically). BypassUntil approves them
	// automatically until then.
	Bypass      string    `json:"bypass,omitempty"`
	BypassUntil time.Time `json:"bypass_until,omitzero"`
}

const (
	MCPBypassAsk    = "ask"
	MCPBypassAlways = "always"
	MCPBypassHour   = "hour"
)

// BypassActive reports whether the assistant's changes are approved without
// asking at now.
func (a MCPAssistant) BypassActive(now time.Time) bool {
	return a.Bypass == MCPBypassAlways || (!a.BypassUntil.IsZero() && now.Before(a.BypassUntil))
}

// BypassMode is "always", "hour" while a timed bypass runs, or "ask".
func (a MCPAssistant) BypassMode(now time.Time) string {
	switch {
	case a.Bypass == MCPBypassAlways:
		return MCPBypassAlways
	case !a.BypassUntil.IsZero() && now.Before(a.BypassUntil):
		return MCPBypassHour
	}
	return MCPBypassAsk
}

type mcpAssistantStore struct {
	Assistants map[string]MCPAssistant `json:"assistants"`
}

var ErrMCPAssistantNotFound = errors.New("assistant not found")

// MCPConnectTool is the Tool of the transaction that asks the user to allow
// a new assistant.
const MCPConnectTool = "connect"

// mcpDefaultAssistantPerms are what a newly allowed assistant may use. Tools
// that change things without asking first are left out; the user can add
// them later.
var mcpDefaultAssistantPerms = []string{
	"list_vault",
	"search_vault",
	"get_entry",
	"decrypt_entry",
	"get_totp",
	"generate_password",
	"add_entry",
	"edit_entry",
	"delete_entry",
	"tx_list",
	"tx_abort",
}

// MCPConnectAccess is what the connect prompt tells the user an assistant
// gets with the default permissions.
var MCPConnectAccess = []string{
	"Read item names and search",
	"Read secrets and 2FA codes",
	"Ask you before every change",
}

func DefaultMCPAssistantPerms() []string {
	return append([]string{}, mcpDefaultAssistantPerms...)
}

// ValidateMCPToolPerms checks that every entry names an MCP tool and returns
// them without duplicates, in tool order.
func ValidateMCPToolPerms(perms []string) ([]string, error) {
	want := map[string]bool{}
	for _, p := range perms {
		p = strings.TrimSpace(p)
		known := false
		for _, t := range mcpToolPermissions {
			if t == p {
				known = true
				break
			}
		}
		if !known {
			return nil, fmt.Errorf("unknown permission %q", p)
		}
		want[p] = true
	}
	out := []string{}
	for _, t := range mcpToolPermissions {
		if want[t] {
			out = append(out, t)
		}
	}
	return out, nil
}

func getMCPAssistantFile() string {
	configDir, _ := os.UserConfigDir()
	apmDir := filepath.Join(configDir, "apm")
	if err := os.MkdirAll(apmDir, 0700); err != nil {
		// Best-effort; the caller will surface the write error.
	}
	return filepath.Join(apmDir, "mcp_assistants.json")
}

func readMCPAssistantStore() (*mcpAssistantStore, error) {
	data, err := os.ReadFile(getMCPAssistantFile())
	if os.IsNotExist(err) {
		return &mcpAssistantStore{Assistants: map[string]MCPAssistant{}}, nil
	}
	if err != nil {
		return nil, err
	}
	store := &mcpAssistantStore{}
	if err := json.Unmarshal(data, store); err != nil {
		return nil, err
	}
	if store.Assistants == nil {
		store.Assistants = map[string]MCPAssistant{}
	}
	return store, nil
}

func saveMCPAssistantStore(store *mcpAssistantStore) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	path := getMCPAssistantFile()
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// updateMCPAssistantStore runs fn on the store under the same kind of
// cross-process lock as the request store. The store is saved only when fn
// succeeds.
func updateMCPAssistantStore(fn func(store *mcpAssistantStore) error) error {
	unlock, err := lockMCPFile(getMCPAssistantFile())
	if err != nil {
		return err
	}
	defer unlock()
	store, err := readMCPAssistantStore()
	if err != nil {
		return err
	}
	if err := fn(store); err != nil {
		return err
	}
	return saveMCPAssistantStore(store)
}

// ListMCPAssistants returns the allowed assistants, newest first.
func ListMCPAssistants() ([]MCPAssistant, error) {
	store, err := readMCPAssistantStore()
	if err != nil {
		return nil, err
	}
	out := make([]MCPAssistant, 0, len(store.Assistants))
	for _, a := range store.Assistants {
		out = append(out, a)
	}
	sort.Slice(out, func(i, j int) bool {
		if out[i].CreatedAt.Equal(out[j].CreatedAt) {
			return out[i].ID < out[j].ID
		}
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	return out, nil
}

func GetMCPAssistant(id string) (*MCPAssistant, error) {
	store, err := readMCPAssistantStore()
	if err != nil {
		return nil, err
	}
	a, ok := store.Assistants[strings.TrimSpace(id)]
	if !ok {
		return nil, ErrMCPAssistantNotFound
	}
	return &a, nil
}

func findMCPAssistant(store *mcpAssistantStore, harness, clientID string) (MCPAssistant, bool) {
	for _, a := range store.Assistants {
		if a.Harness == harness && a.ClientID == clientID {
			return a, true
		}
	}
	return MCPAssistant{}, false
}

// FindMCPAssistant looks up the grant for a harness and MCP client name.
func FindMCPAssistant(harness, clientID string) (*MCPAssistant, error) {
	store, err := readMCPAssistantStore()
	if err != nil {
		return nil, err
	}
	a, ok := findMCPAssistant(store, strings.TrimSpace(harness), strings.TrimSpace(clientID))
	if !ok {
		return nil, ErrMCPAssistantNotFound
	}
	return &a, nil
}

// AllowMCPAssistant records a grant with perms (the policy's default
// permissions when nil). An
// existing grant for the same harness and client is kept as it is.
func AllowMCPAssistant(name, clientID, harness string, perms []string) (MCPAssistant, error) {
	name, clientID, harness = strings.TrimSpace(name), strings.TrimSpace(clientID), strings.TrimSpace(harness)
	if name == "" {
		name = clientID
	}
	if perms == nil {
		policy, err := LoadMCPPolicy()
		if err != nil {
			return MCPAssistant{}, err
		}
		perms = policy.DefaultPerms
	}
	perms, err := ValidateMCPToolPerms(perms)
	if err != nil {
		return MCPAssistant{}, err
	}
	var out MCPAssistant
	err = updateMCPAssistantStore(func(store *mcpAssistantStore) error {
		if a, ok := findMCPAssistant(store, harness, clientID); ok {
			out = a
			return nil
		}
		randID, err := GenerateRandomHex(12)
		if err != nil {
			return err
		}
		out = MCPAssistant{
			ID:        "asst_" + randID,
			Name:      name,
			ClientID:  clientID,
			Harness:   harness,
			Perms:     perms,
			CreatedAt: time.Now(),
		}
		store.Assistants[out.ID] = out
		return nil
	})
	return out, err
}

// RevokeMCPAssistant removes a grant by id or (case-insensitive) name. It
// reports false when nothing matched.
func RevokeMCPAssistant(query string) (MCPAssistant, bool, error) {
	query = strings.TrimSpace(query)
	var out MCPAssistant
	found := false
	err := updateMCPAssistantStore(func(store *mcpAssistantStore) error {
		out, found = findMCPAssistantByQuery(store, query)
		if found {
			delete(store.Assistants, out.ID)
		}
		return nil
	})
	if err != nil {
		return MCPAssistant{}, false, err
	}
	if found {
		LogAction("MCP_ASSISTANT_REVOKED", fmt.Sprintf("Revoked assistant '%s'", out.Name))
	}
	return out, found, nil
}

// SetMCPAssistantPerms replaces what an assistant may use. It applies from the
// assistant's next tool call.
func SetMCPAssistantPerms(id string, perms []string) (MCPAssistant, error) {
	perms, err := ValidateMCPToolPerms(perms)
	if err != nil {
		return MCPAssistant{}, err
	}
	var out MCPAssistant
	err = updateMCPAssistantStore(func(store *mcpAssistantStore) error {
		a, ok := store.Assistants[strings.TrimSpace(id)]
		if !ok {
			return ErrMCPAssistantNotFound
		}
		a.Perms = perms
		store.Assistants[a.ID] = a
		out = a
		return nil
	})
	if err != nil {
		return MCPAssistant{}, err
	}
	LogAction("MCP_ASSISTANT_PERMS_CHANGED", fmt.Sprintf("Assistant '%s' may use: %s", out.Name, strings.Join(perms, ", ")))
	return out, nil
}

// findMCPAssistantByQuery matches a grant by id or (case-insensitive) name.
func findMCPAssistantByQuery(store *mcpAssistantStore, query string) (MCPAssistant, bool) {
	query = strings.TrimSpace(query)
	if a, ok := store.Assistants[query]; ok {
		return a, true
	}
	for _, a := range store.Assistants {
		if strings.EqualFold(a.Name, query) {
			return a, true
		}
	}
	return MCPAssistant{}, false
}

// ParseMCPBypassMode accepts ask, always, and hour (also 1h).
func ParseMCPBypassMode(mode string) (string, error) {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "ask":
		return MCPBypassAsk, nil
	case "always":
		return MCPBypassAlways, nil
	case "hour", "1h":
		return MCPBypassHour, nil
	}
	return "", fmt.Errorf("unknown bypass %q: use ask, always or 1h", mode)
}

// SetMCPAssistantBypass sets whether an assistant's changes are approved
// automatically. query is the grant's id or name; mode is ask, always or
// hour (approved automatically for the next hour). Logged as
// MCP_ASSISTANT_BYPASS.
func SetMCPAssistantBypass(query, mode string) (MCPAssistant, error) {
	mode, err := ParseMCPBypassMode(mode)
	if err != nil {
		return MCPAssistant{}, err
	}
	var out MCPAssistant
	err = updateMCPAssistantStore(func(store *mcpAssistantStore) error {
		a, ok := findMCPAssistantByQuery(store, query)
		if !ok {
			return ErrMCPAssistantNotFound
		}
		switch mode {
		case MCPBypassAlways:
			a.Bypass, a.BypassUntil = MCPBypassAlways, time.Time{}
		case MCPBypassHour:
			a.Bypass, a.BypassUntil = MCPBypassAsk, time.Now().Add(time.Hour)
		default:
			a.Bypass, a.BypassUntil = MCPBypassAsk, time.Time{}
		}
		store.Assistants[a.ID] = a
		out = a
		return nil
	})
	if err != nil {
		return MCPAssistant{}, err
	}
	LogAction("MCP_ASSISTANT_BYPASS", fmt.Sprintf("Assistant '%s': %s", out.Name, MCPBypassDescription(out, time.Now())))
	return out, nil
}

// MCPBypassDescription says in words how an assistant's changes are approved.
func MCPBypassDescription(a MCPAssistant, now time.Time) string {
	switch a.BypassMode(now) {
	case MCPBypassAlways:
		return "changes are approved without asking"
	case MCPBypassHour:
		return "changes are approved without asking until " + a.BypassUntil.Format("15:04")
	}
	return "every change asks first"
}

// TouchMCPAssistant adds uses tool calls made at the given time.
func TouchMCPAssistant(id string, uses int, at time.Time) error {
	return updateMCPAssistantStore(func(store *mcpAssistantStore) error {
		a, ok := store.Assistants[strings.TrimSpace(id)]
		if !ok {
			return ErrMCPAssistantNotFound
		}
		a.Uses += uses
		if at.After(a.LastUsedAt) {
			a.LastUsedAt = at
		}
		store.Assistants[a.ID] = a
		return nil
	})
}

// MCPConnectArgs are the arguments of a connect transaction.
type MCPConnectArgs struct {
	Client   string   `json:"client"`
	ClientID string   `json:"client_id"`
	Version  string   `json:"version"`
	Harness  string   `json:"harness"`
	Access   []string `json:"access"`
}

// CreateMCPConnectTransaction asks the user to allow a new assistant.
func CreateMCPConnectTransaction(args MCPConnectArgs, ttl time.Duration) (MCPTransaction, error) {
	if args.Access == nil {
		args.Access = append([]string{}, MCPConnectAccess...)
	}
	raw, err := json.Marshal(args)
	if err != nil {
		return MCPTransaction{}, err
	}
	return CreateMCPTransaction(args.Client, MCPConnectTool, raw, "Connect "+args.Client+" to APM", ttl)
}

// CompleteMCPConnect turns an approved connect request into a grant and
// marks the request committed. who is "serve" or "desktop". It reports
// false when the request is not approved or someone else is completing it.
func CompleteMCPConnect(id, who string) (MCPAssistant, bool, error) {
	tx, ok, err := ClaimMCPTransaction(id, who)
	if err != nil || !ok {
		return MCPAssistant{}, false, err
	}
	if tx.Tool != MCPConnectTool {
		_ = ReleaseMCPTransaction(id)
		return MCPAssistant{}, false, fmt.Errorf("transaction %s is not a connect request", id)
	}
	var args MCPConnectArgs
	if err := json.Unmarshal(tx.Args, &args); err != nil {
		_ = FailMCPTransaction(id, err.Error())
		return MCPAssistant{}, false, err
	}
	a, err := AllowMCPAssistant(args.Client, args.ClientID, args.Harness, nil)
	if err != nil {
		_ = FailMCPTransaction(id, err.Error())
		return MCPAssistant{}, false, err
	}
	if _, err := FinalizeMCPTransaction(id, "Allowed "+a.Name, true); err != nil {
		return a, true, err
	}
	LogAction("MCP_ASSISTANT_ALLOWED", fmt.Sprintf("Allowed assistant '%s' (%s)", a.Name, a.ClientID))
	return a, true, nil
}
