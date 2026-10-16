package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	src "github.com/aaravmaloo/apm/src"
)

func watchtowerTestServer(t *testing.T) (*desktopServer, string) {
	t.Helper()
	dir := t.TempDir()
	t.Chdir(dir)
	for k, v := range map[string]string{"HOME": dir, "TMPDIR": dir, "APM_STATE_DIR": dir, "APM_SESSION_ID": "wtrpc", "APM_EPHEMERAL_ID": "", "APM_DESKTOP_NO_TOUCHID": "1", "APM_ICONS_OFFLINE": "1"} {
		t.Setenv(k, v)
	}
	prevPath := vaultPath
	vaultPath = filepath.Join(dir, "vault.dat")
	t.Cleanup(func() { vaultPath = prevPath; _ = src.KillSession() })

	const pw = "ValidPass123!"
	v := &src.Vault{Profile: "standard", Spaces: []string{"default"}}
	_ = v.AddEntry("GitHub", "alice", "password")
	_ = v.AddEntry("GitLab", "alice", "password")
	_ = v.AddEntry("Bank", "alice", "Zq!8f3e1c0a9b7d6e5f4")
	data, err := src.EncryptVault(v, pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	s := newDesktopServer(nil)
	s.sink = func(string, any) {}
	return s, pw
}

func call(t *testing.T, s *desktopServer, method string, params any) (map[string]any, *rpcError) {
	t.Helper()
	raw, _ := json.Marshal(params)
	m, ok := desktopMethods[method]
	if !ok {
		t.Fatalf("%s is not registered", method)
	}
	if !m.long {
		s.mu.Lock()
	}
	res, err := m.fn(s, raw)
	if !m.long {
		s.mu.Unlock()
	}
	if err != nil {
		var re *rpcError
		if errors.As(err, &re) {
			return nil, re
		}
		t.Fatalf("%s: %v", method, err)
	}
	b, _ := json.Marshal(res)
	var out map[string]any
	_ = json.Unmarshal(b, &out)
	return out, nil
}

func TestDesktopWatchtowerRPC(t *testing.T) {
	s, pw := watchtowerTestServer(t)

	if _, e := call(t, s, "watchtower.scan", map[string]any{}); e == nil || e.Code != "locked" {
		t.Fatalf("scan needs an unlocked vault: %v", e)
	}

	// Two wrong passwords, then the right one reports them.
	for i := 1; i <= 2; i++ {
		_, e := call(t, s, "vault.unlock", map[string]any{"password": "nope"})
		if e == nil || e.Code != "wrong_password" || e.Data["failures"] != i || e.Data["wait"] != 0 {
			t.Fatalf("wrong password %d: %+v", i, e)
		}
	}
	st, _ := call(t, s, "vault.status", nil)
	if st["failures"] != float64(2) || st["cooldown"] != float64(0) {
		t.Fatalf("status = %v", st)
	}
	res, e := call(t, s, "vault.unlock", map[string]any{"password": pw})
	if e != nil {
		t.Fatal(e)
	}
	fs, _ := res["failedSince"].(map[string]any)
	if fs == nil || fs["count"] != float64(2) || fs["last"].(float64) <= 0 || len(fs["sources"].([]any)) != 1 {
		t.Fatalf("failedSince = %v", res["failedSince"])
	}
	meta := res["snapshot"].(map[string]any)["meta"].(map[string]any)
	if meta["breachCheck"] != false || meta["lockoutAfter"] != float64(0) {
		t.Fatalf("meta = %v", meta)
	}

	rep, e := call(t, s, "watchtower.scan", map[string]any{"space": ""})
	if e != nil {
		t.Fatal(e)
	}
	for _, k := range []string{"score", "grade", "generated", "itemsChecked", "categories", "findings", "setup", "trust", "history", "breach"} {
		if _, ok := rep[k]; !ok {
			t.Fatalf("scan is missing %q", k)
		}
	}
	if len(rep["history"].([]any)) != 1 || rep["itemsChecked"] != float64(3) || len(rep["trust"].([]any)) != 3 {
		t.Fatalf("history/items/trust = %v %v %d", rep["history"], rep["itemsChecked"], len(rep["trust"].([]any)))
	}
	raw, _ := json.Marshal(rep)
	if strings.Contains(string(raw), "Zq!8f3e1c0a9b7d6e5f4") {
		t.Fatal("the scan must not include secret values")
	}
	var weakID string
	for _, f := range rep["findings"].([]any) {
		fm := f.(map[string]any)
		for _, k := range []string{"id", "kind", "severity", "title", "body", "fixes", "impact", "dismissed", "space"} {
			if _, ok := fm[k]; !ok {
				t.Fatalf("finding missing %q: %v", k, fm)
			}
		}
		if fm["kind"] == "weak" && fm["itemTitle"] == "GitHub" {
			weakID = fm["id"].(string)
		}
	}
	if weakID == "" {
		t.Fatal("GitHub's common password should be weak")
	}

	score := rep["score"].(float64)
	if _, e := call(t, s, "watchtower.dismiss", map[string]any{"id": weakID, "reason": "Test account", "days": 0}); e != nil {
		t.Fatal(e)
	}
	rep, _ = call(t, s, "watchtower.scan", map[string]any{})
	found := false
	for _, f := range rep["findings"].([]any) {
		fm := f.(map[string]any)
		if fm["id"] == weakID {
			d, _ := fm["dismissed"].(map[string]any)
			found = d != nil && d["reason"] == "Test account" && d["until"] == float64(0)
		}
	}
	if !found || rep["score"].(float64) <= score {
		t.Fatalf("dismissed finding: found=%v score %v -> %v", found, score, rep["score"])
	}
	if _, e := call(t, s, "watchtower.restore", map[string]any{"id": weakID}); e != nil {
		t.Fatal(e)
	}

	// markExposed flags an item; the scan lists it.
	ref, _ := s.vault.FindItem(src.ItemID("password", "", "Bank"))
	if _, e := call(t, s, "watchtower.markExposed", map[string]any{"itemId": ref.ID, "exposed": true}); e != nil {
		t.Fatal(e)
	}
	rep, _ = call(t, s, "watchtower.scan", map[string]any{"space": "default"})
	exposed := false
	for _, f := range rep["findings"].([]any) {
		fm := f.(map[string]any)
		exposed = exposed || (fm["kind"] == "exposed" && fm["itemId"] == ref.ID)
	}
	if !exposed {
		t.Fatal("markExposed should show an exposed finding")
	}

	// Breach check is opt-in.
	if _, e := call(t, s, "watchtower.breachCheck", map[string]any{}); e == nil || e.Code != "breach_off" {
		t.Fatalf("breachCheck while off: %v", e)
	}
	if res, e := call(t, s, "watchtower.breach", map[string]any{"enabled": true}); e != nil || res["snapshot"].(map[string]any)["meta"].(map[string]any)["breachCheck"] != true {
		t.Fatalf("breach on: %v %v", res, e)
	}

	// Lockout through vault.meta.
	if _, e := call(t, s, "vault.meta", map[string]any{"lockoutAfter": 3}); e == nil || e.Code != "invalid" {
		t.Fatalf("lockout 3 is refused: %v", e)
	}
	if _, e := call(t, s, "vault.meta", map[string]any{"lockoutAfter": 10}); e == nil || e.Code != "invalid" || e.Data["needRecovery"] != true {
		t.Fatalf("lockout without a recovery key is refused: %v", e)
	}
	s.vault.SetRecoveryEmail("alice@example.com")
	if _, e := call(t, s, "recovery.key.create", map[string]any{}); e != nil {
		t.Fatal(e)
	}
	res, e = call(t, s, "vault.meta", map[string]any{"lockoutAfter": 10})
	if e != nil || res["snapshot"].(map[string]any)["meta"].(map[string]any)["lockoutAfter"] != float64(10) {
		t.Fatalf("lockout 10: %v %v", res, e)
	}
	if data, _ := os.ReadFile(vaultPath); src.ReadVaultLockoutAfter(data) != 10 {
		t.Fatal("the lockout must be readable from the header before unlock")
	}

	// Activity lists the wrong passwords; ack marks them.
	act, e := call(t, s, "activity.list", map[string]any{"limit": 10})
	if e != nil {
		t.Fatal(e)
	}
	events := act["events"].([]any)
	if act["unacknowledged"].(float64) < 1 || len(events) < 1 {
		t.Fatalf("activity = %v", act)
	}
	var failedID string
	for _, ev := range events {
		em := ev.(map[string]any)
		for _, k := range []string{"id", "kind", "severity", "title", "body", "at", "source", "actor", "acknowledged"} {
			if _, ok := em[k]; !ok {
				t.Fatalf("event missing %q: %v", k, em)
			}
		}
		if em["kind"] == "failed_unlocks" {
			failedID = em["id"].(string)
		}
	}
	if failedID == "" {
		t.Fatalf("expected a failed_unlocks event: %v", events)
	}
	if _, e := call(t, s, "activity.ack", map[string]any{"id": failedID}); e != nil {
		t.Fatal(e)
	}
	if _, e := call(t, s, "activity.ack", map[string]any{"id": "evt_missing"}); e == nil || e.Code != "not_found" {
		t.Fatalf("unknown event: %v", e)
	}
	if _, e := call(t, s, "activity.ackAll", map[string]any{}); e != nil {
		t.Fatal(e)
	}
	act, _ = call(t, s, "activity.list", map[string]any{})
	if act["unacknowledged"] != float64(0) || len(act["events"].([]any)) != 0 {
		t.Fatalf("after ackAll = %v", act)
	}
	act, _ = call(t, s, "activity.list", map[string]any{"includeAcknowledged": true})
	if len(act["events"].([]any)) == 0 {
		t.Fatal("includeAcknowledged lists them again")
	}
}

func TestDesktopUnlockCooldownAndLockout(t *testing.T) {
	s, pw := watchtowerTestServer(t)
	for i := 1; i <= 3; i++ {
		call(t, s, "vault.unlock", map[string]any{"password": "nope"})
	}
	_, e := call(t, s, "vault.unlock", map[string]any{"password": "nope"})
	if e == nil || e.Code != "wrong_password" || e.Data["failures"] != 4 || e.Data["wait"] != 30 {
		t.Fatalf("fourth failure: %+v", e)
	}
	_, e = call(t, s, "vault.unlock", map[string]any{"password": pw})
	if e == nil || e.Code != "cooldown" || e.Data["failures"] != 4 || e.Data["wait"].(int) < 1 {
		t.Fatalf("during the wait: %+v", e)
	}
	if code, ok := bridgeHTTPStatus["recovery_required"]; !ok || code != 423 {
		t.Fatal("the bridge maps recovery_required")
	}
	if _, ok := bridgeHTTPStatus["breach_lock"]; ok {
		t.Fatal("breach_lock is gone")
	}
}
