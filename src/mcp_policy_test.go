package apm

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"reflect"
	"strconv"
	"strings"
	"sync"
	"testing"
	"time"
)

func writeMCPPolicyFile(t *testing.T, body string) {
	t.Helper()
	if err := os.WriteFile(getMCPPolicyFile(), []byte(body), 0600); err != nil {
		t.Fatal(err)
	}
}

func setMCPPolicy(t *testing.T, fn func(p *MCPPolicy)) {
	t.Helper()
	p, err := LoadMCPPolicy()
	if err != nil {
		t.Fatal(err)
	}
	fn(&p)
	if err := SaveMCPPolicy(p); err != nil {
		t.Fatalf("SaveMCPPolicy: %v", err)
	}
}

func TestMCPPolicyDefaultsLoadSave(t *testing.T) {
	isolateMCPState(t)
	want := MCPPolicy{ApproveWith: "any", ExpiryMinutes: 15, NewAssistants: "ask", DefaultPerms: DefaultMCPAssistantPerms()}

	// Missing file: the defaults.
	got, err := LoadMCPPolicy()
	if err != nil || !reflect.DeepEqual(got, want) {
		t.Fatalf("defaults = %+v (%v)", got, err)
	}
	if got.Expiry() != 15*time.Minute {
		t.Fatalf("default expiry = %v", got.Expiry())
	}

	// A partly filled file keeps the defaults for what it leaves out, and
	// values APM doesn't know fall back to the default.
	writeMCPPolicyFile(t, `{"paused": true, "expiry_minutes": 7, "approve_with": "face", "new_assistants": "block"}`)
	got, err = LoadMCPPolicy()
	if err != nil {
		t.Fatal(err)
	}
	if !got.Paused || got.ExpiryMinutes != 15 || got.ApproveWith != "any" || got.NewAssistants != "block" || !reflect.DeepEqual(got.DefaultPerms, want.DefaultPerms) {
		t.Fatalf("partial file = %+v", got)
	}

	// A damaged file is an error, so a pause is never lost quietly.
	writeMCPPolicyFile(t, `{"paused": tr`)
	if _, err := LoadMCPPolicy(); err == nil {
		t.Fatal("a damaged settings file loaded")
	}

	// Save validates and round-trips.
	p := DefaultMCPPolicy()
	p.ExpiryMinutes = 7
	if err := SaveMCPPolicy(p); err == nil {
		t.Fatal("saved an expiry of 7 minutes")
	}
	for _, bad := range []MCPPolicy{
		{ApproveWith: "face", ExpiryMinutes: 15, NewAssistants: "ask"},
		{ApproveWith: "any", ExpiryMinutes: 15, NewAssistants: "maybe"},
		{ApproveWith: "any", ExpiryMinutes: 15, NewAssistants: "ask", DefaultPerms: []string{"install_plugin"}},
	} {
		if err := bad.Validate(); err == nil {
			t.Fatalf("validated %+v", bad)
		}
	}
	p = MCPPolicy{Paused: true, ApproveWith: "touchid", ExpiryMinutes: 60, NewAssistants: "block", AskBeforeSecrets: true, DefaultPerms: []string{"list_vault", "get_entry"}}
	if err := SaveMCPPolicy(p); err != nil {
		t.Fatal(err)
	}
	got, err = LoadMCPPolicy()
	if err != nil || !reflect.DeepEqual(got, p) {
		t.Fatalf("round trip = %+v (%v)", got, err)
	}
	var onDisk map[string]any
	data, _ := os.ReadFile(getMCPPolicyFile())
	_ = json.Unmarshal(data, &onDisk)
	for _, k := range []string{"paused", "approve_with", "expiry_minutes", "new_assistants", "ask_before_secrets", "default_perms"} {
		if _, ok := onDisk[k]; !ok {
			t.Fatalf("%s missing from the file: %s", k, data)
		}
	}
}

func TestMCPPolicyApplyAndLoosens(t *testing.T) {
	isolateMCPState(t)
	strict := MCPPolicy{Paused: true, ApproveWith: "touchid", ExpiryMinutes: 5, NewAssistants: "block", AskBeforeSecrets: true, DefaultPerms: []string{"list_vault"}}
	loose := DefaultMCPPolicy()
	if l := MCPPolicyLoosens(loose, strict); len(l) != 0 {
		t.Fatalf("tightening counted as loosening: %v", l)
	}
	if l := MCPPolicyLoosens(strict, loose); len(l) != 6 {
		t.Fatalf("loosening = %v", l)
	}
	bad := 7
	if _, err := loose.Apply(MCPPolicyPatch{ExpiryMinutes: &bad}); err == nil {
		t.Fatal("applied an unknown expiry")
	}

	// Through the store: tightening works without presence, loosening is
	// refused and changes nothing.
	paused := true
	before, after, err := UpdateMCPPolicy(MCPPolicyPatch{Paused: &paused}, false, "test")
	if err != nil || before.Paused || !after.Paused {
		t.Fatalf("pause = %+v -> %+v (%v)", before, after, err)
	}
	if changes := DescribeMCPPolicyChanges(before, after); !reflect.DeepEqual(changes, []string{"MCP access paused"}) {
		t.Fatalf("changes = %v", changes)
	}
	resume := false
	if _, _, err := UpdateMCPPolicy(MCPPolicyPatch{Paused: &resume}, false, "test"); !errors.Is(err, ErrMCPPolicyLoosens) {
		t.Fatalf("resume without presence = %v", err)
	}
	if p, _ := LoadMCPPolicy(); !p.Paused {
		t.Fatal("a refused resume changed the settings")
	}
	if _, after, err := UpdateMCPPolicy(MCPPolicyPatch{Paused: &resume}, true, "test"); err != nil || after.Paused {
		t.Fatalf("resume with presence = %+v (%v)", after, err)
	}
	logs, _ := GetAuditLogs(20)
	n := 0
	for _, l := range logs {
		if l.Action == "MCP_POLICY_CHANGED" {
			n++
		}
	}
	if n != 2 {
		t.Fatalf("MCP_POLICY_CHANGED logged %d times, want 2", n)
	}
}

func TestMCPPolicyNewGrantsUseDefaultPerms(t *testing.T) {
	isolateMCPState(t)
	setMCPPolicy(t, func(p *MCPPolicy) { p.DefaultPerms = []string{"list_vault", "tx_list"} })
	a, err := AllowMCPAssistant("Zed", "zed", "zed", nil)
	if err != nil || !reflect.DeepEqual(a.Perms, []string{"list_vault", "tx_list"}) {
		t.Fatalf("grant = %+v (%v)", a, err)
	}
}

func TestMCPAssistantBypassModes(t *testing.T) {
	isolateMCPState(t)
	a, err := AllowMCPAssistant("Claude Code", "claude-code", "claude-code", nil)
	if err != nil {
		t.Fatal(err)
	}
	now := time.Now()
	if a.BypassActive(now) || a.BypassMode(now) != "ask" {
		t.Fatalf("a new grant bypasses: %+v", a)
	}
	data, _ := os.ReadFile(getMCPAssistantFile())
	if strings.Contains(string(data), "bypass_until") {
		t.Fatalf("an unset bypass_until was written: %s", data)
	}
	got, err := SetMCPAssistantBypass("claude code", "always")
	if err != nil || got.Bypass != "always" || !got.BypassActive(now) || !got.BypassUntil.IsZero() {
		t.Fatalf("always = %+v (%v)", got, err)
	}
	got, err = SetMCPAssistantBypass(a.ID, "1h")
	if err != nil || got.Bypass != "ask" || got.BypassMode(time.Now()) != "hour" || time.Until(got.BypassUntil) < 59*time.Minute {
		t.Fatalf("hour = %+v (%v)", got, err)
	}
	if got.BypassActive(time.Now().Add(61 * time.Minute)) {
		t.Fatal("the hour bypass outlived its hour")
	}
	got, err = SetMCPAssistantBypass(a.ID, "ask")
	if err != nil || got.BypassActive(time.Now()) || !got.BypassUntil.IsZero() {
		t.Fatalf("ask = %+v (%v)", got, err)
	}
	if _, err := SetMCPAssistantBypass(a.ID, "sometimes"); err == nil {
		t.Fatal("accepted an unknown bypass")
	}
	if _, err := SetMCPAssistantBypass("nobody", "ask"); !errors.Is(err, ErrMCPAssistantNotFound) {
		t.Fatalf("unknown assistant = %v", err)
	}
}

func TestMCPApproveWithTouchIDPromptAnswer(t *testing.T) {
	isolateMCPState(t)
	prev := MCPTouchIDAvailable
	t.Cleanup(func() { MCPTouchIDAvailable = prev })
	available := true
	MCPTouchIDAvailable = func() bool { return available }

	setMCPPolicy(t, func(p *MCPPolicy) { p.ApproveWith = "touchid" })
	tx := newTestTx(t, time.Minute)
	if tx.ApproveWith != "touchid" {
		t.Fatalf("request did not copy approve_with: %+v", tx)
	}
	// A click or key on a Mac with Touch ID counts as no answer.
	recordPromptAnswer(tx, true, "click")
	recordPromptAnswer(tx, true, "keyboard")
	recordPromptAnswer(tx, true, "dialog")
	if s := txStatus(t, tx.ID); s != MCPTxPending {
		t.Fatalf("a click approved a Touch ID only request: %s", s)
	}
	recordPromptAnswer(tx, true, "touchid")
	if s := txStatus(t, tx.ID); s != MCPTxApproved {
		t.Fatalf("touch did not approve: %s", s)
	}
	// Rejecting works however it's done.
	tx2 := newTestTx(t, time.Minute)
	recordPromptAnswer(tx2, false, "keyboard")
	if s := txStatus(t, tx2.ID); s != MCPTxRejected {
		t.Fatalf("Esc did not reject: %s", s)
	}
	// Without Touch ID the rule falls back to any.
	available = false
	tx3 := newTestTx(t, time.Minute)
	recordPromptAnswer(tx3, true, "click")
	if s := txStatus(t, tx3.ID); s != MCPTxApproved {
		t.Fatalf("click without Touch ID: %s", s)
	}
	// Requests made under "any" take any approval.
	available = true
	setMCPPolicy(t, func(p *MCPPolicy) { p.ApproveWith = "any" })
	tx4 := newTestTx(t, time.Minute)
	if tx4.ApproveWith != "any" {
		t.Fatalf("approve_with = %q", tx4.ApproveWith)
	}
	recordPromptAnswer(tx4, true, "keyboard")
	if s := txStatus(t, tx4.ID); s != MCPTxApproved {
		t.Fatalf("keyboard under any: %s", s)
	}
}

// observeApprover replaces notifyApprover for the test and returns the
// requests that would have shown a prompt.
func observeApprover(t *testing.T) func() []MCPTransaction {
	t.Helper()
	var mu sync.Mutex
	var seen []MCPTransaction
	prev := notifyApprover
	notifyApprover = func(tx MCPTransaction) {
		mu.Lock()
		seen = append(seen, tx)
		mu.Unlock()
	}
	t.Cleanup(func() { notifyApprover = prev })
	return func() []MCPTransaction {
		mu.Lock()
		defer mu.Unlock()
		return append([]MCPTransaction{}, seen...)
	}
}

var mcpAllTools = []string{
	"list_vault", "get_entry", "search_vault", "decrypt_entry", "get_totp", "add_entry", "delete_entry", "edit_entry",
	"manage_profiles", "manage_spaces", "cloud_config", "get_history", "generate_password", "cloud_sync", "get_audit_logs",
	"tx_list", "tx_abort",
}

func TestMCPPausedRefusesEveryTool(t *testing.T) {
	h := startMCPServe(t, false)
	setMCPPolicy(t, func(p *MCPPolicy) { p.Paused = true })
	before, _ := os.ReadFile(h.vaultPath)
	for _, tool := range mcpAllTools {
		r := h.wait(h.callAsync(tool, map[string]any{"name": "existing", "type": "password", "query": "x", "tx_id": "tx_x"}))
		if !r.isError || r.text != MCPPausedText {
			t.Fatalf("%s while paused = %+v", tool, r)
		}
	}
	if txs, _ := ListMCPTransactions(0); len(txs) != 0 {
		t.Fatalf("a paused server queued requests: %+v", txs)
	}
	if after, _ := os.ReadFile(h.vaultPath); string(after) != string(before) {
		t.Fatal("a paused server changed the vault")
	}

	// A new paired assistant isn't asked about while paused either.
	dir := isolateMCPState(t)
	setMCPPolicy(t, func(p *MCPPolicy) { p.Paused = true })
	p := startPairedServe(t, dir, "cursor", "cursor")
	if r := p.call("generate_password", map[string]any{"length": 8}); !r.isError || r.text != MCPPausedText {
		t.Fatalf("paired call while paused = %+v", r)
	}
	if txs, _ := ListMCPTransactions(0); len(txs) != 0 {
		t.Fatalf("a paused server asked to connect: %+v", txs)
	}
	// Resuming applies to the next call without a restart.
	setMCPPolicy(t, func(p *MCPPolicy) { p.Paused = false })
	call := p.callAsync("generate_password", map[string]any{"length": 8})
	tx := p.pendingConnect()
	if _, err := DecideMCPTransaction(tx.ID, true, "touchid"); err != nil {
		t.Fatal(err)
	}
	if r := p.wait(call); r.isError || len(r.text) != 8 {
		t.Fatalf("after resume = %+v", r)
	}
}

func TestMCPNewAssistantsBlocked(t *testing.T) {
	dir := isolateMCPState(t)
	setMCPPolicy(t, func(p *MCPPolicy) { p.NewAssistants = "block" })
	seen := observeApprover(t)
	h := startPairedServe(t, dir, "codex", "codex")
	for i := 0; i < 2; i++ {
		if r := h.call("list_vault", nil); !r.isError || r.text != MCPBlockedNewText {
			t.Fatalf("blocked assistant = %+v", r)
		}
	}
	if txs, _ := ListMCPTransactions(0); len(txs) != 0 {
		t.Fatalf("a blocked assistant created a request: %+v", txs)
	}
	if len(seen()) != 0 {
		t.Fatal("a blocked assistant was shown to the user")
	}

	// A known assistant still works while new ones are blocked.
	if _, err := AllowMCPAssistant("Codex", "codex", "codex", nil); err != nil {
		t.Fatal(err)
	}
	if r := h.call("list_vault", nil); r.isError || !strings.Contains(r.text, "existing") {
		t.Fatalf("known assistant while blocked = %+v", r)
	}
}

func TestMCPAskBeforeSecrets(t *testing.T) {
	dir := isolateMCPState(t)
	setMCPPolicy(t, func(p *MCPPolicy) { p.AskBeforeSecrets = true })
	seen := observeApprover(t)
	if _, err := AllowMCPAssistant("Claude Code", "claude-code", "claude-code", nil); err != nil {
		t.Fatal(err)
	}
	h := startPairedServe(t, dir, "claude-code", "claude-code")
	v := h.vault()
	if err := v.AddTOTPEntry("github", "JBSWY3DPEHPK3PXP"); err != nil {
		t.Fatal(err)
	}
	data, _ := EncryptVault(v, mcpTestPassword)
	_ = os.WriteFile(h.vaultPath, data, 0600)
	// The assistant may bypass changes; reads still ask.
	if _, err := SetMCPAssistantBypass("Claude Code", "always"); err != nil {
		t.Fatal(err)
	}

	// list_vault isn't a secret read and doesn't ask.
	if r := h.call("list_vault", nil); r.isError {
		t.Fatalf("list_vault = %+v", r)
	}

	ask := func(tool string, args map[string]any, wantPreview, wantArgs string, approve bool) mcpCallResult {
		t.Helper()
		call := h.callAsync(tool, args)
		tx := h.pendingTx()
		var compact bytes.Buffer
		_ = json.Compact(&compact, tx.Args)
		if tx.Tool != tool || tx.Preview != wantPreview || compact.String() != wantArgs || tx.TokenName != "Claude Code" {
			t.Fatalf("%s request = %+v (args %s)", tool, tx, tx.Args)
		}
		if life := tx.ExpiresAt.Sub(tx.CreatedAt); life != 2*time.Minute {
			t.Fatalf("%s request lives %v", tool, life)
		}
		if _, err := DecideMCPTransaction(tx.ID, approve, "touchid"); err != nil {
			t.Fatal(err)
		}
		r := h.wait(call)
		got, _ := GetMCPTransaction(tx.ID)
		if approve && (got == nil || got.Status != MCPTxCommitted) {
			t.Fatalf("approved %s request was not closed: %+v", tool, got)
		}
		return r
	}

	r := ask("get_entry", map[string]any{"name": "existing"}, `Read the secrets of "existing"`, `{"name":"existing"}`, true)
	if r.isError || !strings.HasPrefix(r.text, "Data for Password 'existing' encrypted at ") {
		t.Fatalf("get_entry = %+v", r)
	}
	// Data for Password 'existing' encrypted at <path>. Reference: <key>. Use ...
	rest := strings.TrimPrefix(r.text, "Data for Password 'existing' encrypted at ")
	path := rest[:strings.Index(rest, ". Reference: ")]
	ref := strings.TrimSuffix(rest[strings.Index(rest, ". Reference: ")+len(". Reference: "):], ". Use decrypt_entry to view.")

	r = ask("decrypt_entry", map[string]any{"path": path, "reference": ref}, `Read the secrets of "existing"`, `{"name":"existing"}`, true)
	if r.isError || !strings.Contains(r.text, "pw-existing") {
		t.Fatalf("decrypt_entry = %+v", r)
	}

	r = ask("get_totp", map[string]any{"name": "github"}, `Get the 2FA code for "github"`, `{"name":"github"}`, false)
	if !r.isError || r.text != MCPReadDeniedText {
		t.Fatalf("rejected get_totp = %+v", r)
	}
	r = ask("get_totp", map[string]any{"name": "github"}, `Get the 2FA code for "github"`, `{"name":"github"}`, true)
	if r.isError || !strings.HasPrefix(r.text, "TOTP Code for github: ") {
		t.Fatalf("get_totp = %+v", r)
	}

	r = ask("search_vault", map[string]any{"query": "exist"}, `Search the vault for "exist"`, `{"query":"exist"}`, false)
	if !r.isError || r.text != MCPReadDeniedText {
		t.Fatalf("rejected search_vault = %+v", r)
	}
	r = ask("search_vault", map[string]any{"query": "exist"}, `Search the vault for "exist"`, `{"query":"exist"}`, true)
	if r.isError || !strings.Contains(r.text, "existing") {
		t.Fatalf("search_vault = %+v", r)
	}
	if n := len(seen()); n != 6 {
		t.Fatalf("%d read requests were shown, want 6", n)
	}

	// A request nobody answers expires and is refused.
	prev := mcpReadRequestTTL
	mcpReadRequestTTL = 300 * time.Millisecond
	t.Cleanup(func() { mcpReadRequestTTL = prev })
	if r := h.call("get_entry", map[string]any{"name": "existing"}); !r.isError || r.text != MCPReadDeniedText {
		t.Fatalf("expired get_entry = %+v", r)
	}
}

func TestMCPBypassAutoApprovesWrites(t *testing.T) {
	dir := isolateMCPState(t)
	seen := observeApprover(t)
	if _, err := AllowMCPAssistant("Claude Code", "claude-code", "claude-code", nil); err != nil {
		t.Fatal(err)
	}
	setMCPPolicy(t, func(p *MCPPolicy) { p.ExpiryMinutes = 30 })
	h := startPairedServe(t, dir, "claude-code", "claude-code")

	add := func(name string) mcpCallResult {
		return h.call("add_entry", map[string]any{"type": "password", "name": name, "password": "pw-" + name})
	}
	findTx := func(name string) MCPTransaction {
		t.Helper()
		txs, _ := ListMCPTransactions(0)
		for _, tx := range txs {
			if strings.Contains(tx.Preview, strconv.Quote(name)) {
				return tx
			}
		}
		t.Fatalf("no request for %s", name)
		return MCPTransaction{}
	}

	if _, err := SetMCPAssistantBypass("Claude Code", "always"); err != nil {
		t.Fatal(err)
	}
	if r := add("auto1"); r.isError || !strings.HasPrefix(r.text, `Approved. Added "auto1". Receipt rcpt_`) {
		t.Fatalf("bypass always = %+v", r)
	}
	tx := findTx("auto1")
	if tx.Status != MCPTxCommitted || tx.DecidedVia != "bypass" || tx.ClaimedBy != "serve" {
		t.Fatalf("bypassed request = %+v", tx)
	}
	if life := tx.ExpiresAt.Sub(tx.CreatedAt); life != 30*time.Minute {
		t.Fatalf("write request lives %v, want the policy's 30 minutes", life)
	}

	if _, err := SetMCPAssistantBypass("Claude Code", "1h"); err != nil {
		t.Fatal(err)
	}
	if r := add("auto2"); r.isError || !strings.HasPrefix(r.text, `Approved. Added "auto2".`) {
		t.Fatalf("bypass hour = %+v", r)
	}
	if !hasEntry(h.vault(), "auto1") || !hasEntry(h.vault(), "auto2") {
		t.Fatal("bypassed changes are not in the vault")
	}
	if n := len(seen()); n != 0 {
		t.Fatalf("a bypassed request was shown %d times", n)
	}
	logs, _ := GetAuditLogs(50)
	auto := 0
	for _, l := range logs {
		if l.Action == "MCP_TX_AUTO_APPROVED" {
			auto++
		}
	}
	if auto != 2 {
		t.Fatalf("MCP_TX_AUTO_APPROVED logged %d times, want 2", auto)
	}

	// Once the hour is over, changes ask again.
	err := updateMCPAssistantStore(func(store *mcpAssistantStore) error {
		for id, a := range store.Assistants {
			a.BypassUntil = time.Now().Add(-time.Second)
			store.Assistants[id] = a
		}
		return nil
	})
	if err != nil {
		t.Fatal(err)
	}
	call := h.callAsync("add_entry", map[string]any{"type": "password", "name": "asks", "password": "pw"})
	pending := h.pendingTx()
	if pending.DecidedVia != "" || len(seen()) != 1 {
		t.Fatalf("after the hour: %+v, shown %d", pending, len(seen()))
	}
	if _, err := DecideMCPTransaction(pending.ID, false, "click"); err != nil {
		t.Fatal(err)
	}
	if r := h.wait(call); r.text != "Rejected in APM. Nothing changed." {
		t.Fatalf("after the hour = %+v", r)
	}
}
