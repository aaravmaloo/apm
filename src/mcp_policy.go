package apm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"time"

	"github.com/aaravmaloo/apm/src/touchid"
)

// MCPPolicy is how APM treats every assistant. It lives next to the grant
// store; a missing file or field means the default.
type MCPPolicy struct {
	// Paused refuses every tool call from every assistant.
	Paused bool `json:"paused"`
	// ApproveWith is "any" (Touch ID, Space or click) or "touchid" (on a Mac
	// with Touch ID only a touch approves; elsewhere it acts like "any").
	ApproveWith string `json:"approve_with"`
	// ExpiryMinutes is how long a new write request waits for an answer.
	ExpiryMinutes int `json:"expiry_minutes"`
	// NewAssistants is "ask" (the connect prompt) or "block" (unknown
	// assistants are refused without a prompt).
	NewAssistants string `json:"new_assistants"`
	// AskBeforeSecrets makes get_entry, decrypt_entry, get_totp and
	// search_vault ask first.
	AskBeforeSecrets bool `json:"ask_before_secrets"`
	// DefaultPerms are what a newly allowed assistant may use.
	DefaultPerms []string `json:"default_perms"`
}

const (
	MCPApproveAny     = "any"
	MCPApproveTouchID = "touchid"
	MCPNewAsk         = "ask"
	MCPNewBlock       = "block"
)

// MCPExpiryChoices are the request lifetimes the settings offer, in minutes.
var MCPExpiryChoices = []int{5, 15, 30, 60}

// Refusals the server sends when the settings say no.
const (
	MCPPausedText     = "APM has paused MCP access. Resume it in APM settings."
	MCPBlockedNewText = "APM isn't accepting new assistants. Allow them in APM settings."
	MCPReadDeniedText = "Not allowed in APM."
)

func DefaultMCPPolicy() MCPPolicy {
	return MCPPolicy{
		ApproveWith:   MCPApproveAny,
		ExpiryMinutes: 15,
		NewAssistants: MCPNewAsk,
		DefaultPerms:  DefaultMCPAssistantPerms(),
	}
}

// Expiry is the lifetime of a new write request.
func (p MCPPolicy) Expiry() time.Duration {
	if p.ExpiryMinutes <= 0 {
		return 15 * time.Minute
	}
	return time.Duration(p.ExpiryMinutes) * time.Minute
}

// Validate reports the first setting APM doesn't know.
func (p MCPPolicy) Validate() error {
	switch p.ApproveWith {
	case MCPApproveAny, MCPApproveTouchID:
	default:
		return fmt.Errorf("approve with must be any or touchid, not %q", p.ApproveWith)
	}
	if !validMCPExpiry(p.ExpiryMinutes) {
		return fmt.Errorf("requests can expire after 5, 15, 30 or 60 minutes, not %d", p.ExpiryMinutes)
	}
	switch p.NewAssistants {
	case MCPNewAsk, MCPNewBlock:
	default:
		return fmt.Errorf("new assistants must be ask or block, not %q", p.NewAssistants)
	}
	if _, err := ValidateMCPToolPerms(p.DefaultPerms); err != nil {
		return err
	}
	return nil
}

func validMCPExpiry(m int) bool {
	for _, c := range MCPExpiryChoices {
		if c == m {
			return true
		}
	}
	return false
}

// mcpPolicyFile mirrors MCPPolicy with every field optional, so a partly
// filled file keeps the defaults for what it leaves out.
type mcpPolicyFile struct {
	Paused           *bool     `json:"paused"`
	ApproveWith      *string   `json:"approve_with"`
	ExpiryMinutes    *int      `json:"expiry_minutes"`
	NewAssistants    *string   `json:"new_assistants"`
	AskBeforeSecrets *bool     `json:"ask_before_secrets"`
	DefaultPerms     *[]string `json:"default_perms"`
}

func getMCPPolicyFile() string {
	configDir, _ := os.UserConfigDir()
	apmDir := filepath.Join(configDir, "apm")
	if err := os.MkdirAll(apmDir, 0700); err != nil {
		// Best-effort; the caller will surface the write error.
	}
	return filepath.Join(apmDir, "mcp_policy.json")
}

// readMCPPolicy loads the policy. Fields that are missing or hold a value
// APM doesn't know keep their default; a file that isn't JSON is an error,
// so a damaged file never quietly turns a pause off.
func readMCPPolicy() (MCPPolicy, error) {
	p := DefaultMCPPolicy()
	data, err := os.ReadFile(getMCPPolicyFile())
	if os.IsNotExist(err) {
		return p, nil
	}
	if err != nil {
		return p, err
	}
	if strings.TrimSpace(string(data)) == "" {
		return p, nil
	}
	var f mcpPolicyFile
	if err := json.Unmarshal(data, &f); err != nil {
		return p, fmt.Errorf("APM's MCP settings file is damaged: %w", err)
	}
	if f.Paused != nil {
		p.Paused = *f.Paused
	}
	if f.ApproveWith != nil {
		if v := strings.TrimSpace(*f.ApproveWith); v == MCPApproveAny || v == MCPApproveTouchID {
			p.ApproveWith = v
		}
	}
	if f.ExpiryMinutes != nil && validMCPExpiry(*f.ExpiryMinutes) {
		p.ExpiryMinutes = *f.ExpiryMinutes
	}
	if f.NewAssistants != nil {
		if v := strings.TrimSpace(*f.NewAssistants); v == MCPNewAsk || v == MCPNewBlock {
			p.NewAssistants = v
		}
	}
	if f.AskBeforeSecrets != nil {
		p.AskBeforeSecrets = *f.AskBeforeSecrets
	}
	if f.DefaultPerms != nil {
		if perms, err := ValidateMCPToolPerms(*f.DefaultPerms); err == nil {
			p.DefaultPerms = perms
		}
	}
	return p, nil
}

// LoadMCPPolicy returns the current MCP settings.
func LoadMCPPolicy() (MCPPolicy, error) {
	return readMCPPolicy()
}

func saveMCPPolicy(p MCPPolicy) error {
	if p.DefaultPerms == nil {
		p.DefaultPerms = []string{}
	}
	data, err := json.MarshalIndent(p, "", "  ")
	if err != nil {
		return err
	}
	path := getMCPPolicyFile()
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

// SaveMCPPolicy validates p and replaces the settings with it.
func SaveMCPPolicy(p MCPPolicy) error {
	if err := p.Validate(); err != nil {
		return err
	}
	unlock, err := lockMCPFile(getMCPPolicyFile())
	if err != nil {
		return err
	}
	defer unlock()
	return saveMCPPolicy(p)
}

// MCPPolicyPatch changes some settings; nil fields stay as they are. The
// JSON names are the ones the desktop app sends.
type MCPPolicyPatch struct {
	Paused           *bool     `json:"paused,omitempty"`
	ApproveWith      *string   `json:"approveWith,omitempty"`
	ExpiryMinutes    *int      `json:"expiryMinutes,omitempty"`
	NewAssistants    *string   `json:"newAssistants,omitempty"`
	AskBeforeSecrets *bool     `json:"askBeforeSecrets,omitempty"`
	DefaultPerms     *[]string `json:"defaultPerms,omitempty"`
}

// Empty reports whether the patch changes nothing.
func (patch MCPPolicyPatch) Empty() bool {
	return patch.Paused == nil && patch.ApproveWith == nil && patch.ExpiryMinutes == nil &&
		patch.NewAssistants == nil && patch.AskBeforeSecrets == nil && patch.DefaultPerms == nil
}

// Apply returns p with the patch applied, or an error naming a value APM
// doesn't know.
func (p MCPPolicy) Apply(patch MCPPolicyPatch) (MCPPolicy, error) {
	out := p
	out.DefaultPerms = append([]string{}, p.DefaultPerms...)
	if patch.Paused != nil {
		out.Paused = *patch.Paused
	}
	if patch.ApproveWith != nil {
		out.ApproveWith = strings.ToLower(strings.TrimSpace(*patch.ApproveWith))
	}
	if patch.ExpiryMinutes != nil {
		out.ExpiryMinutes = *patch.ExpiryMinutes
	}
	if patch.NewAssistants != nil {
		out.NewAssistants = strings.ToLower(strings.TrimSpace(*patch.NewAssistants))
	}
	if patch.AskBeforeSecrets != nil {
		out.AskBeforeSecrets = *patch.AskBeforeSecrets
	}
	if patch.DefaultPerms != nil {
		perms, err := ValidateMCPToolPerms(*patch.DefaultPerms)
		if err != nil {
			return p, err
		}
		out.DefaultPerms = perms
	}
	if err := out.Validate(); err != nil {
		return p, err
	}
	return out, nil
}

// MCPPolicyLoosens lists, in plain words, every way after is less strict
// than before. Loosening needs the user's presence; tightening doesn't.
func MCPPolicyLoosens(before, after MCPPolicy) []string {
	var out []string
	if before.Paused && !after.Paused {
		out = append(out, "resume MCP access")
	}
	if before.ApproveWith == MCPApproveTouchID && after.ApproveWith != MCPApproveTouchID {
		out = append(out, "approve without Touch ID")
	}
	if after.ExpiryMinutes > before.ExpiryMinutes {
		out = append(out, "keep requests open longer")
	}
	if before.NewAssistants == MCPNewBlock && after.NewAssistants != MCPNewBlock {
		out = append(out, "accept new assistants")
	}
	if before.AskBeforeSecrets && !after.AskBeforeSecrets {
		out = append(out, "stop asking before secrets are read")
	}
	had := map[string]bool{}
	for _, p := range before.DefaultPerms {
		had[p] = true
	}
	for _, p := range after.DefaultPerms {
		if !had[p] {
			out = append(out, "give new assistants more permissions")
			break
		}
	}
	return out
}

func mcpApproveWithLabel(v string) string {
	if v == MCPApproveTouchID {
		return "Touch ID only"
	}
	return "Touch ID, Space or click"
}

func mcpExpiryLabel(m int) string {
	if m == 60 {
		return "1 hour"
	}
	return fmt.Sprintf("%d minutes", m)
}

func mcpOnOff(b bool) string {
	if b {
		return "on"
	}
	return "off"
}

// MCPPolicyLines describes the settings one per line, for pm mcp settings.
func MCPPolicyLines(p MCPPolicy) [][2]string {
	access := "on"
	if p.Paused {
		access = "paused"
	}
	newA := "ask first"
	if p.NewAssistants == MCPNewBlock {
		newA = "blocked"
	}
	perms := strings.Join(p.DefaultPerms, ", ")
	if perms == "" {
		perms = "none"
	}
	return [][2]string{
		{"MCP access", access},
		{"Approve with", mcpApproveWithLabel(p.ApproveWith)},
		{"Requests expire after", mcpExpiryLabel(p.ExpiryMinutes)},
		{"New assistants", newA},
		{"Ask before secrets", mcpOnOff(p.AskBeforeSecrets)},
		{"New assistants may use", perms},
	}
}

// DescribeMCPPolicyChanges lists what changed between two policies, for the
// audit log and the CLI.
func DescribeMCPPolicyChanges(before, after MCPPolicy) []string {
	var out []string
	if before.Paused != after.Paused {
		if after.Paused {
			out = append(out, "MCP access paused")
		} else {
			out = append(out, "MCP access resumed")
		}
	}
	if before.ApproveWith != after.ApproveWith {
		out = append(out, fmt.Sprintf("Approve with: %s (was %s)", mcpApproveWithLabel(after.ApproveWith), mcpApproveWithLabel(before.ApproveWith)))
	}
	if before.ExpiryMinutes != after.ExpiryMinutes {
		out = append(out, fmt.Sprintf("Requests expire after %s (was %s)", mcpExpiryLabel(after.ExpiryMinutes), mcpExpiryLabel(before.ExpiryMinutes)))
	}
	if before.NewAssistants != after.NewAssistants {
		if after.NewAssistants == MCPNewBlock {
			out = append(out, "New assistants: blocked (was ask first)")
		} else {
			out = append(out, "New assistants: ask first (was blocked)")
		}
	}
	if before.AskBeforeSecrets != after.AskBeforeSecrets {
		out = append(out, fmt.Sprintf("Ask before secrets: %s (was %s)", mcpOnOff(after.AskBeforeSecrets), mcpOnOff(before.AskBeforeSecrets)))
	}
	if strings.Join(before.DefaultPerms, ",") != strings.Join(after.DefaultPerms, ",") {
		perms := strings.Join(after.DefaultPerms, ", ")
		if perms == "" {
			perms = "none"
		}
		out = append(out, "New assistants may use: "+perms)
	}
	return out
}

// UpdateMCPPolicy applies patch under the lock and returns the settings
// before and after. When the patch would loosen anything and allowLoosen is
// false it changes nothing and returns ErrMCPPolicyLoosens. A change is
// logged as MCP_POLICY_CHANGED; where says who made it.
func UpdateMCPPolicy(patch MCPPolicyPatch, allowLoosen bool, where string) (before, after MCPPolicy, err error) {
	unlock, err := lockMCPFile(getMCPPolicyFile())
	if err != nil {
		return before, after, err
	}
	defer unlock()
	before, err = readMCPPolicy()
	if err != nil {
		return before, before, err
	}
	after, err = before.Apply(patch)
	if err != nil {
		return before, before, err
	}
	if !allowLoosen && len(MCPPolicyLoosens(before, after)) > 0 {
		return before, before, ErrMCPPolicyLoosens
	}
	changes := DescribeMCPPolicyChanges(before, after)
	if len(changes) == 0 {
		return before, after, nil
	}
	if err := saveMCPPolicy(after); err != nil {
		return before, before, err
	}
	details := strings.Join(changes, "; ")
	if where != "" {
		details += " (" + where + ")"
	}
	LogAction("MCP_POLICY_CHANGED", details)
	return before, after, nil
}

// ErrMCPPolicyLoosens is returned when a change would make MCP access less
// strict without the user's presence.
var ErrMCPPolicyLoosens = fmt.Errorf("loosening MCP settings needs you to confirm it's you")

// Touch ID availability for the approve-with rule. Checking it runs a
// helper, so the answer is kept for the life of the process.
var (
	mcpTouchIDOnce  sync.Once
	mcpTouchIDValue bool
)

// MCPTouchIDAvailable reports whether this Mac can approve with Touch ID.
// Tests replace it.
var MCPTouchIDAvailable = func() bool {
	if strings.TrimSpace(os.Getenv("APM_DESKTOP_NO_TOUCHID")) != "" {
		return false
	}
	mcpTouchIDOnce.Do(func() { mcpTouchIDValue = touchid.IsAvailable() })
	return mcpTouchIDValue
}

// MCPApprovalAllowed reports whether an approval made via counts for tx.
// A request created under "approve with Touch ID only" can be approved only
// by a touch when Touch ID is available; rejecting always works.
func MCPApprovalAllowed(tx MCPTransaction, via string, touchIDAvailable bool) bool {
	if tx.ApproveWith != MCPApproveTouchID || !touchIDAvailable {
		return true
	}
	return strings.TrimSpace(via) == "touchid"
}

// The read tools that ask first when ask_before_secrets is on.
var mcpReadTools = map[string]bool{"get_entry": true, "decrypt_entry": true, "get_totp": true, "search_vault": true}

// The tools whose approved requests change the vault.
var mcpWriteTools = map[string]bool{"add_entry": true, "edit_entry": true, "delete_entry": true}

// IsMCPReadTool reports whether a transaction is a read request: approved,
// the waiting tool call runs, and there is nothing to apply.
func IsMCPReadTool(tool string) bool { return mcpReadTools[tool] }

// IsMCPWriteTool reports whether an approved transaction changes the vault
// and so must be applied by whoever has it open.
func IsMCPWriteTool(tool string) bool { return mcpWriteTools[tool] }
