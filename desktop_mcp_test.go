package main

import (
	"bytes"
	"encoding/json"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"

	src "github.com/aaravmaloo/apm/src"
)

type desktopEvent struct {
	name string
	data map[string]any
}

// TestDesktopMCPDecide checks that mcp.tx.decide records an approval while the
// vault is locked without touching the vault, that the request is applied once
// the vault is unlocked, and that approving while unlocked commits at once.
func TestDesktopMCPDecide(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	for k, v := range map[string]string{"HOME": dir, "XDG_CONFIG_HOME": filepath.Join(dir, ".config"), "APPDATA": filepath.Join(dir, "AppData"), "APM_STATE_DIR": dir, "APM_SESSION_ID": "", "APM_EPHEMERAL_ID": "", "APM_DESKTOP_NO_TOUCHID": "1", "APM_ICONS_OFFLINE": "1", "APM_MCP_NO_APPROVER": "1"} {
		t.Setenv(k, v)
	}
	prevPath := vaultPath
	vaultPath = filepath.Join(dir, "vault.dat")
	t.Cleanup(func() { vaultPath = prevPath })

	const pw = "ValidPass123!"
	v := &src.Vault{Profile: "standard", Spaces: []string{"default"}}
	if err := v.AddEntry("github", "alice", "s3cret"); err != nil {
		t.Fatal(err)
	}
	data, err := src.EncryptVault(v, pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultPath, data, 0600); err != nil {
		t.Fatal(err)
	}

	s := newDesktopServer(nil)
	var mu sync.Mutex
	var events []desktopEvent
	s.sink = func(name string, d any) {
		m, _ := d.(map[string]any)
		mu.Lock()
		events = append(events, desktopEvent{name, m})
		mu.Unlock()
	}
	lastEvent := func(name string) map[string]any {
		mu.Lock()
		defer mu.Unlock()
		for i := len(events) - 1; i >= 0; i-- {
			if events[i].name == name {
				return events[i].data
			}
		}
		return nil
	}
	queue := func(name string) src.MCPTransaction {
		args, _ := json.Marshal(map[string]any{"type": "password", "name": name, "username": "bot", "password": "pw-" + name})
		tx, err := src.CreateMCPTransaction("agent", "add_entry", args, "Add password entry '"+name+"'", 0)
		if err != nil {
			t.Fatal(err)
		}
		return tx
	}
	decide := func(id string, approve bool) map[string]any {
		params, _ := json.Marshal(map[string]any{"id": id, "approve": approve, "via": "touchid"})
		res, err := hMCPTxDecide(s, params)
		if err != nil {
			t.Fatalf("mcp.tx.decide: %v", err)
		}
		return res.(map[string]any)
	}
	vaultHas := func(name string) bool {
		data, err := os.ReadFile(vaultPath)
		if err != nil {
			t.Fatal(err)
		}
		v, err := src.DecryptVault(data, pw, 1)
		if err != nil {
			t.Fatal(err)
		}
		for _, e := range v.Entries {
			if e.Account == name {
				return true
			}
		}
		return false
	}

	// Locked: the request is announced and listed, and approving it only
	// records the decision.
	first := queue("first")
	s.pollMCPOnce()
	if ev := lastEvent("mcp.pending"); ev == nil || ev["tx"].(map[string]any)["id"] != first.ID {
		t.Fatalf("mcp.pending was not emitted while locked: %v", ev)
	}
	pending, err := hMCPTxPending(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	if list := pending.(map[string]any)["tx"].([]map[string]any); len(list) != 1 || list[0]["id"] != first.ID {
		t.Fatalf("mcp.tx.pending = %v", list)
	}
	if res := decide(first.ID, true); res["status"] != "approved" {
		t.Fatalf("locked decide = %v", res)
	}
	if got, _ := os.ReadFile(vaultPath); !bytes.Equal(got, data) {
		t.Fatal("a locked decide wrote the vault")
	}
	if tx, _ := src.GetMCPTransaction(first.ID); tx.Status != src.MCPTxApproved || tx.DecidedVia != "touchid" {
		t.Fatalf("unexpected request after locked decide: %+v", tx)
	}
	s.pollMCPOnce()
	if ev := lastEvent("mcp.resolved"); ev == nil || ev["id"] != first.ID || ev["status"] != "approved" {
		t.Fatalf("mcp.resolved = %v", ev)
	}

	// Unlocking lets the next poll apply the approved request.
	unlocked, err := src.DecryptVault(data, pw, 1)
	if err != nil {
		t.Fatal(err)
	}
	s.finishUnlock(pw, unlocked, "test", false)
	s.pollMCPOnce()
	if tx, _ := src.GetMCPTransaction(first.ID); tx.Status != src.MCPTxCommitted || tx.ClaimedBy != "desktop" {
		t.Fatalf("approved request was not applied after unlock: %+v", tx)
	}
	if !vaultHas("first") {
		t.Fatal("the request approved while locked is not in the vault")
	}

	// Unlocked: approving commits right away.
	second := queue("second")
	res := decide(second.ID, true)
	if res["status"] != "committed" || res["receipt"] == "" {
		t.Fatalf("unlocked decide = %v", res)
	}
	if !vaultHas("second") {
		t.Fatal("the request approved while unlocked is not in the vault")
	}

	// Rejecting changes nothing, and a second answer is refused.
	third := queue("third")
	if res := decide(third.ID, false); res["status"] != "rejected" {
		t.Fatalf("reject = %v", res)
	}
	params, _ := json.Marshal(map[string]any{"id": third.ID, "approve": true, "via": "click"})
	if _, err := hMCPTxDecide(s, params); err == nil {
		t.Fatal("a rejected request was approved")
	}
	if vaultHas("third") {
		t.Fatal("a rejected request reached the vault")
	}
}

// newLockedDesktopForMCP sets up an isolated vault and a pm desktop backend
// that hasn't unlocked it, and returns an unlock function.
func newLockedDesktopForMCP(t *testing.T) (*desktopServer, func()) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	for k, v := range map[string]string{"HOME": dir, "XDG_CONFIG_HOME": filepath.Join(dir, ".config"), "APPDATA": filepath.Join(dir, "AppData"), "APM_STATE_DIR": dir, "APM_SESSION_ID": "", "APM_EPHEMERAL_ID": "", "APM_DESKTOP_NO_TOUCHID": "1", "APM_ICONS_OFFLINE": "1", "APM_MCP_NO_APPROVER": "1"} {
		t.Setenv(k, v)
	}
	prevPath := vaultPath
	vaultPath = filepath.Join(dir, "vault.dat")
	t.Cleanup(func() { vaultPath = prevPath })
	const pw = "ValidPass123!"
	v := &src.Vault{Profile: "standard", Spaces: []string{"default"}}
	if err := v.AddEntry("github", "alice", "s3cret"); err != nil {
		t.Fatal(err)
	}
	data, err := src.EncryptVault(v, pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	s := newDesktopServer(nil)
	s.sink = func(string, any) {}
	return s, func() {
		unlocked, err := src.DecryptVault(data, pw, 1)
		if err != nil {
			t.Fatal(err)
		}
		s.finishUnlock(pw, unlocked, "test", false)
	}
}

func rpcCode(err error) string {
	if e, ok := err.(*rpcError); ok {
		return e.Code
	}
	return ""
}

func TestDesktopMCPPolicySet(t *testing.T) {
	s, unlock := newLockedDesktopForMCP(t)
	set := func(params string) (map[string]any, error) {
		res, err := hMCPPolicySet(s, json.RawMessage(params))
		if err != nil {
			return nil, err
		}
		return res.(map[string]any), nil
	}

	// Locked: tightening is accepted, loosening isn't.
	res, err := set(`{"paused": true, "newAssistants": "block", "askBeforeSecrets": true, "approveWith": "touchid", "expiryMinutes": 5}`)
	if err != nil {
		t.Fatalf("locked tightening: %v", err)
	}
	if pol := res["policy"].(map[string]any); pol["paused"] != true || pol["approveWith"] != "touchid" || pol["expiryMinutes"] != 5 || pol["newAssistants"] != "block" || pol["askBeforeSecrets"] != true {
		t.Fatalf("policy after tightening = %v", pol)
	}
	for _, loosen := range []string{`{"paused": false}`, `{"approveWith": "any"}`, `{"expiryMinutes": 15}`, `{"newAssistants": "ask"}`, `{"askBeforeSecrets": false}`, `{"defaultPerms": ["list_vault","manage_profiles"]}`} {
		if _, err := set(loosen); rpcCode(err) != "locked" {
			t.Fatalf("locked %s = %v", loosen, err)
		}
	}
	if p, _ := src.LoadMCPPolicy(); !p.Paused || p.ApproveWith != "touchid" || p.ExpiryMinutes != 5 {
		t.Fatalf("a refused change was saved: %+v", p)
	}
	for _, bad := range []string{`{"expiryMinutes": 7}`, `{"approveWith": "face"}`, `{"newAssistants": "maybe"}`, `{"defaultPerms": ["install"]}`, `{"paused": "yes"}`} {
		if _, err := set(bad); rpcCode(err) != "invalid" {
			t.Fatalf("%s = %v", bad, err)
		}
	}

	// Unlocked: loosening works and the snapshot carries the policy.
	unlock()
	res, err = set(`{"paused": false, "approveWith": "any", "expiryMinutes": 60, "newAssistants": "ask", "askBeforeSecrets": false, "defaultPerms": ["list_vault", "add_entry"]}`)
	if err != nil {
		t.Fatalf("unlocked loosening: %v", err)
	}
	snap := res["snapshot"].(map[string]any)
	pol := snap["mcp"].(map[string]any)["policy"].(map[string]any)
	want := map[string]any{"paused": false, "approveWith": "any", "expiryMinutes": 60, "newAssistants": "ask", "askBeforeSecrets": false, "defaultPerms": []string{"list_vault", "add_entry"}}
	for k, v := range want {
		if got, _ := json.Marshal(pol[k]); string(got) != mustJSON(v) {
			t.Fatalf("snapshot policy %s = %s, want %s", k, got, mustJSON(v))
		}
	}
	logs, _ := src.GetAuditLogs(50)
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

func mustJSON(v any) string {
	b, _ := json.Marshal(v)
	return string(b)
}

func TestDesktopMCPAssistantBypass(t *testing.T) {
	s, unlock := newLockedDesktopForMCP(t)
	a, err := src.AllowMCPAssistant("Claude Code", "claude-code", "claude-code", nil)
	if err != nil {
		t.Fatal(err)
	}
	bypass := func(mode string) (map[string]any, error) {
		params, _ := json.Marshal(map[string]any{"id": a.ID, "mode": mode})
		res, err := hMCPAssistantBypass(s, params)
		if err != nil {
			return nil, err
		}
		return res.(map[string]any), nil
	}
	// Locked: only going back to asking is accepted.
	for _, mode := range []string{"always", "hour"} {
		if _, err := bypass(mode); rpcCode(err) != "locked" {
			t.Fatalf("locked bypass %s = %v", mode, err)
		}
	}
	if _, err := bypass("ask"); err != nil {
		t.Fatalf("locked bypass ask: %v", err)
	}
	if _, err := bypass("sometimes"); rpcCode(err) != "invalid" {
		t.Fatalf("unknown mode = %v", err)
	}

	unlock()
	view := func(res map[string]any) map[string]any {
		for _, v := range res["snapshot"].(map[string]any)["mcp"].(map[string]any)["assistants"].([]map[string]any) {
			if v["id"] == a.ID {
				return v
			}
		}
		t.Fatal("assistant missing from the snapshot")
		return nil
	}
	res, err := bypass("always")
	if err != nil {
		t.Fatal(err)
	}
	if v := view(res); v["bypass"] != "always" || v["bypassUntil"] != int64(0) {
		t.Fatalf("always = %v", v)
	}
	res, err = bypass("hour")
	if err != nil {
		t.Fatal(err)
	}
	v := view(res)
	until, _ := v["bypassUntil"].(int64)
	if v["bypass"] != "ask" || until < time.Now().Add(59*time.Minute).UnixMilli() || until > time.Now().Add(61*time.Minute).UnixMilli() {
		t.Fatalf("hour = %v", v)
	}
	if params, _ := json.Marshal(map[string]any{"id": "asst_missing", "mode": "ask"}); true {
		if _, err := hMCPAssistantBypass(s, params); rpcCode(err) != "not_found" {
			t.Fatalf("missing assistant = %v", err)
		}
	}
	logs, _ := src.GetAuditLogs(50)
	n := 0
	for _, l := range logs {
		if l.Action == "MCP_ASSISTANT_BYPASS" {
			n++
		}
	}
	if n != 3 {
		t.Fatalf("MCP_ASSISTANT_BYPASS logged %d times, want 3", n)
	}
}

func TestDesktopMCPApproveWithTouchID(t *testing.T) {
	s, unlock := newLockedDesktopForMCP(t)
	unlock()
	prev := desktopHasTouchID
	t.Cleanup(func() { desktopHasTouchID = prev })
	hasTouch := true
	desktopHasTouchID = func(*desktopServer) bool { return hasTouch }

	touchOnly := "touchid"
	if _, _, err := src.UpdateMCPPolicy(src.MCPPolicyPatch{ApproveWith: &touchOnly}, false, "test"); err != nil {
		t.Fatal(err)
	}
	queue := func(name string) src.MCPTransaction {
		args, _ := json.Marshal(map[string]any{"type": "password", "name": name, "password": "pw"})
		tx, err := src.CreateMCPTransaction("agent", "add_entry", args, "Add password entry '"+name+"'", 0)
		if err != nil {
			t.Fatal(err)
		}
		if tx.ApproveWith != "touchid" {
			t.Fatalf("approve_with = %q", tx.ApproveWith)
		}
		return tx
	}
	decide := func(id string, approve bool, via string) (map[string]any, error) {
		params, _ := json.Marshal(map[string]any{"id": id, "approve": approve, "via": via})
		res, err := hMCPTxDecide(s, params)
		if err != nil {
			return nil, err
		}
		return res.(map[string]any), nil
	}
	tx := queue("one")
	if view := mcpTxView(tx); view["approveWith"] != "touchid" {
		t.Fatalf("view approveWith = %v", view["approveWith"])
	}
	for _, via := range []string{"click", "keyboard"} {
		_, err := decide(tx.ID, true, via)
		if e, ok := err.(*rpcError); !ok || e.Code != "invalid" || e.Message != "This request needs Touch ID." {
			t.Fatalf("approve via %s = %v", via, err)
		}
	}
	params, _ := json.Marshal(map[string]any{"id": tx.ID})
	if _, err := hMCPTxApprove(s, params); rpcCode(err) != "invalid" {
		t.Fatalf("mcp.tx.approve on a Touch ID request = %v", err)
	}
	if got, _ := src.GetMCPTransaction(tx.ID); got.Status != src.MCPTxPending {
		t.Fatalf("refused approvals changed the request: %+v", got)
	}
	if res, err := decide(tx.ID, true, "touchid"); err != nil || res["status"] != "committed" {
		t.Fatalf("approve via touchid = %v (%v)", res, err)
	}
	// Rejecting works by any means.
	two := queue("two")
	if res, err := decide(two.ID, false, "keyboard"); err != nil || res["status"] != "rejected" {
		t.Fatalf("reject via keyboard = %v (%v)", res, err)
	}
	// Without Touch ID on this Mac the rule falls back to any.
	hasTouch = false
	three := queue("three")
	if res, err := decide(three.ID, true, "click"); err != nil || res["status"] != "committed" {
		t.Fatalf("click without Touch ID = %v (%v)", res, err)
	}
}

// TestDesktopMCPReadRequestsAreNotApplied checks that the backend records the
// answer to a read request but never claims or applies it; the pm mcp serve
// waiting on it does that.
func TestDesktopMCPReadRequestsAreNotApplied(t *testing.T) {
	s, unlock := newLockedDesktopForMCP(t)
	unlock()
	for _, tool := range []string{"get_entry", "decrypt_entry", "get_totp", "search_vault"} {
		tx, err := src.CreateMCPTransaction("agent", tool, json.RawMessage(`{"name":"github"}`), "Read the secrets of \"github\"", 0)
		if err != nil {
			t.Fatal(err)
		}
		s.pollMCPOnce()
		params, _ := json.Marshal(map[string]any{"id": tx.ID, "approve": true, "via": "touchid"})
		res, err := hMCPTxDecide(s, params)
		if err != nil || res.(map[string]any)["status"] != "approved" {
			t.Fatalf("%s decide = %v (%v)", tool, res, err)
		}
		s.pollMCPOnce()
		got, _ := src.GetMCPTransaction(tx.ID)
		if got.Status != src.MCPTxApproved || got.ClaimedBy != "" {
			t.Fatalf("%s request after poll: %+v", tool, got)
		}
	}
}
