package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	src "github.com/aaravmaloo/apm/src"
)

// skipGuardWait ends the current wait in the shared guard file, as if the
// time had passed, so a test can make the next try without sleeping.
func skipGuardWait(t *testing.T) {
	t.Helper()
	path := filepath.Join(os.Getenv("APM_STATE_DIR"), ".apm_lock")
	raw, err := os.ReadFile(path)
	if err != nil {
		t.Fatal(err)
	}
	var st map[string]any
	if err := json.Unmarshal(raw, &st); err != nil {
		t.Fatal(err)
	}
	delete(st, "next_allowed")
	raw, _ = json.Marshal(st)
	if err := os.WriteFile(path, raw, 0600); err != nil {
		t.Fatal(err)
	}
}

// tripLockout enters wrong passwords until the vault asks for recovery.
func tripLockout(t *testing.T, s *desktopServer, after int) {
	t.Helper()
	for i := 1; i <= after; i++ {
		skipGuardWait(t)
		_, e := call(t, s, "vault.unlock", map[string]any{"password": "nope"})
		if i < after && (e == nil || e.Code != "wrong_password") {
			t.Fatalf("wrong password %d: %+v", i, e)
		}
		if i == after && (e == nil || e.Code != "recovery_required") {
			t.Fatalf("wrong password %d should need recovery: %+v", i, e)
		}
	}
}

func lockoutOf(t *testing.T, res map[string]any) any {
	t.Helper()
	return res["snapshot"].(map[string]any)["meta"].(map[string]any)["lockoutAfter"]
}

// The lockout is only accepted with a way back in, and a vault that trips it
// opens again with trustee shares.
func TestDesktopLockoutNeedsRecoveryAndRecoversWithShares(t *testing.T) {
	s, pw := watchtowerTestServer(t)
	if _, e := call(t, s, "vault.unlock", map[string]any{"password": pw}); e != nil {
		t.Fatal(e)
	}
	if _, e := call(t, s, "vault.meta", map[string]any{"lockoutAfter": 5}); e == nil || e.Code != "invalid" || e.Data["needRecovery"] != true {
		t.Fatalf("no recovery, no lockout: %+v", e)
	}
	if _, e := call(t, s, "recovery.codes.generate", map[string]any{"count": 3}); e != nil {
		t.Fatal(e)
	}
	if _, e := call(t, s, "vault.meta", map[string]any{"lockoutAfter": 5}); e == nil || e.Code != "invalid" {
		t.Fatalf("recovery codes alone can't open the vault: %+v", e)
	}

	// The recovery email is normally verified by an emailed code.
	s.vault.SetRecoveryEmail("alice@example.com")
	res, e := call(t, s, "recovery.key.create", map[string]any{})
	if e != nil {
		t.Fatal(e)
	}
	key := res["key"].(string)
	res, e = call(t, s, "recovery.quorum.setup", map[string]any{"threshold": 2, "shares": 3, "key": key})
	if e != nil {
		t.Fatal(e)
	}
	shares := res["shares"].([]any)
	res, e = call(t, s, "vault.meta", map[string]any{"lockoutAfter": 5})
	if e != nil || lockoutOf(t, res) != float64(5) {
		t.Fatalf("lockout with a recovery key: %v %v", res, e)
	}

	call(t, s, "vault.lock", map[string]any{})
	tripLockout(t, s, 5)
	if _, e := call(t, s, "vault.unlock", map[string]any{"password": pw}); e == nil || e.Code != "recovery_required" {
		t.Fatalf("the right password is refused once recovery is required: %+v", e)
	}

	res, e = call(t, s, "recover.start", map[string]any{})
	if e != nil {
		t.Fatal(e)
	}
	if m := res["methods"].(map[string]any); m["quorum"] != true || m["key"] != true {
		t.Fatalf("methods = %v", m)
	}
	res, e = call(t, s, "recover.verify", map[string]any{"method": "quorum", "email": "alice@example.com", "shares": []any{shares[0], shares[2]}})
	if e != nil || res["ready"] != true {
		t.Fatalf("shares: %v %+v", res, e)
	}
	const newPw = "NewValidPass456!"
	if _, e := call(t, s, "recover.reset", map[string]any{"password": newPw}); e != nil {
		t.Fatal(e)
	}
	call(t, s, "vault.lock", map[string]any{})
	res, e = call(t, s, "vault.unlock", map[string]any{"password": newPw})
	if e != nil || lockoutOf(t, res) != float64(5) {
		t.Fatalf("the new password opens the vault and the lockout stays: %v %+v", res, e)
	}

	// Removing recovery turns the lockout off with it.
	res, e = call(t, s, "recovery.reset", map[string]any{})
	if e != nil || lockoutOf(t, res) != float64(0) {
		t.Fatalf("recovery.reset: %v %+v", res, e)
	}
	if data, _ := os.ReadFile(vaultPath); src.ReadVaultLockoutAfter(data) != 0 {
		t.Fatal("the header no longer asks for recovery")
	}
}

// The recovery key path: email, the emailed code, the key and, with
// one-time codes set up, a code as the second check.
func TestDesktopLockoutRecoversWithKey(t *testing.T) {
	s, pw := watchtowerTestServer(t)
	if _, e := call(t, s, "vault.unlock", map[string]any{"password": pw}); e != nil {
		t.Fatal(e)
	}
	s.vault.SetRecoveryEmail("alice@example.com")
	res, e := call(t, s, "recovery.key.create", map[string]any{})
	if e != nil {
		t.Fatal(e)
	}
	key := res["key"].(string)
	res, e = call(t, s, "recovery.codes.generate", map[string]any{"count": 3})
	if e != nil {
		t.Fatal(e)
	}
	code := res["codes"].([]any)[0].(string)
	if _, e := call(t, s, "vault.meta", map[string]any{"lockoutAfter": 5}); e != nil {
		t.Fatal(e)
	}
	// A later password unlock saves the vault without the header's masked
	// copy of the key. Recovery must not need it.
	call(t, s, "vault.lock", map[string]any{})
	if _, e := call(t, s, "vault.unlock", map[string]any{"password": pw}); e != nil {
		t.Fatal(e)
	}
	if data, _ := os.ReadFile(vaultPath); func() bool { rec, _ := src.ParseVaultHeaderRecovery(data); return len(rec.ObfuscatedKey) > 0 }() {
		t.Fatal("expected the masked key copy to be gone after a password unlock")
	}
	call(t, s, "vault.lock", map[string]any{})
	tripLockout(t, s, 5)

	if _, e := call(t, s, "recover.start", map[string]any{}); e != nil {
		t.Fatal(e)
	}
	if _, e := call(t, s, "recover.email.send", map[string]any{"email": "alice@example.com", "send": false}); e != nil {
		t.Fatal(e)
	}
	// The 6-digit code goes out by email (SMTP), which a test can't read.
	s.rec.codeVerified = true
	if res, e := call(t, s, "recover.verify", map[string]any{"method": "key", "value": key}); e != nil || res["ready"] == true {
		t.Fatalf("with one-time codes set up, the key alone isn't enough: %v %+v", res, e)
	}
	if res, e := call(t, s, "recover.verify", map[string]any{"method": "code", "value": code}); e != nil || res["ready"] != true {
		t.Fatalf("code: %v %+v", res, e)
	}
	if _, e := call(t, s, "recover.reset", map[string]any{"password": "NewValidPass456!"}); e != nil {
		t.Fatal(e)
	}
	if wait, failures := src.UnlockWait(); wait != 0 || failures != 0 {
		t.Fatalf("recovery clears the guard: wait %v, failures %d", wait, failures)
	}
}
