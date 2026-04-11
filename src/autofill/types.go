package autofill

import "time"

const (
	ErrVaultLocked = "VaultLockedError"
)

const (
	ResponseStatusOK       = "ok"
	ResponseStatusMultiple = "multiple_matches"
)

const (
	ContextBrowser = "browser"
	ContextSystem  = "system"
)

const DefaultSequenceTemplate = "{USERNAME}{TAB}{PASSWORD}{ENTER}"

type RequestContext struct {
	Kind         string   `json:"kind"`
	Domain       string   `json:"domain,omitempty"`
	DomainHints  []string `json:"domain_hints,omitempty"`
	WindowTitle  string   `json:"window_title,omitempty"`
	ProcessName  string   `json:"process_name,omitempty"`
	ProcessPath  string   `json:"process_path,omitempty"`
	FocusedName  string   `json:"focused_name,omitempty"`
	FocusedValue string   `json:"focused_value,omitempty"`
	EmailHints   []string `json:"email_hints,omitempty"`
}

type FillRequest struct {
	Context        RequestContext `json:"context"`
	SelectionID    string         `json:"selection_id,omitempty"`
	IncludeTOTP    bool           `json:"include_totp,omitempty"`
	MailOnly       bool           `json:"mail_only,omitempty"`
	Sequence       string         `json:"sequence,omitempty"`
	ExplicitAction bool           `json:"explicit_action"`
}

type MatchCandidate struct {
	ProfileID string `json:"profile_id"`
	Service   string `json:"service"`
	Domain    string `json:"domain,omitempty"`
	Username  string `json:"username,omitempty"`
}

type FillResponse struct {
	Status     string           `json:"status"`
	Error      string           `json:"error,omitempty"`
	ProfileID  string           `json:"profile_id,omitempty"`
	Service    string           `json:"service,omitempty"`
	Domain     string           `json:"domain,omitempty"`
	Username   string           `json:"username,omitempty"`
	Password   string           `json:"password,omitempty"`
	TOTP       string           `json:"totp,omitempty"`
	Sequence   string           `json:"sequence,omitempty"`
	Candidates []MatchCandidate `json:"candidates,omitempty"`
}

type UnlockRequest struct {
	MasterPassword       string `json:"master_password"`
	SessionTimeoutSec    int    `json:"session_timeout_sec,omitempty"`
	InactivityTimeoutSec int    `json:"inactivity_timeout_sec,omitempty"`
}

type DaemonStatus struct {
	PID              int       `json:"pid"`
	StartedAt        time.Time `json:"started_at"`
	Locked           bool      `json:"locked"`
	Hotkey           string    `json:"hotkey"`
	MailHotkey       string    `json:"mail_hotkey"`
	SystemEngine     string    `json:"system_engine"`
	ProfileCount     int       `json:"profile_count"`
	PendingSelection int       `json:"pending_selection"`
}

type SimpleResponse struct {
	OK    bool   `json:"ok"`
	Error string `json:"error,omitempty"`
}

type Profile struct {
	ID             string   `json:"id"`
	Service        string   `json:"service"`
	Domain         string   `json:"domain,omitempty"`
	Domains        []string `json:"domains,omitempty"`
	EntryAccount   string   `json:"entry_account"`
	EntryUsername  string   `json:"entry_username,omitempty"`
	TOTPAccount    string   `json:"totp_account,omitempty"`
	ProcessNames   []string `json:"process_names,omitempty"`
	WindowContains []string `json:"window_contains,omitempty"`
	Sequence       string   `json:"sequence,omitempty"`
}

type daemonState struct {
	PID       int       `json:"pid"`
	Addr      string    `json:"addr"`
	Token     string    `json:"token"`
	StartedAt time.Time `json:"started_at"`
}
