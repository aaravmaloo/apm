package apm

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// isolate points every state, config and session path at a temp dir and
// gives the test its own clock.
func isolate(t *testing.T) (dir string, clock *time.Time) {
	t.Helper()
	dir = t.TempDir()
	for k, v := range map[string]string{
		"HOME": dir, "TMPDIR": dir, "APM_STATE_DIR": dir, "APM_VAULT_PATH": "",
		"APM_SESSION_ID": "guardtest" + strings.ReplaceAll(t.Name(), "/", ""), "APM_EPHEMERAL_ID": "",
		"XDG_CONFIG_HOME": filepath.Join(dir, "config"),
	} {
		t.Setenv(k, v)
	}
	now := time.Date(2026, 3, 10, 14, 0, 0, 0, time.Local)
	clock = &now
	prevGuard, prevWatch, prevAlert, prevActAlert := guardNow, watchNow, guardAlert, activityAlert
	guardNow = func() time.Time { return *clock }
	watchNow = func() time.Time { return *clock }
	guardAlert = func(*Vault, int, string, string) {}
	activityAlert = func(*Vault, int, string, string) {}
	prevDevice := currentDeviceFunc
	currentDeviceFunc = func() Device { return Device{ID: "dev-a", Label: "Laptop (alice)"} }
	t.Cleanup(func() {
		guardNow, watchNow, guardAlert, activityAlert = prevGuard, prevWatch, prevAlert, prevActAlert
		currentDeviceFunc = prevDevice
	})
	return dir, clock
}

func TestUnlockBackoffSchedule(t *testing.T) {
	want := map[int]time.Duration{0: 0, 1: 0, 2: 0, 3: 0, 4: 30 * time.Second, 5: time.Minute, 6: 5 * time.Minute, 7: 15 * time.Minute, 8: time.Hour, 9: time.Hour, 50: time.Hour}
	for n, d := range want {
		if got := UnlockBackoff(n); got != d {
			t.Errorf("UnlockBackoff(%d) = %v, want %v", n, got, d)
		}
	}
}

func TestUnlockGuardWaitsAndClears(t *testing.T) {
	_, clock := isolate(t)
	for i := 1; i <= 3; i++ {
		var wrong *ErrWrongPassword
		if err := RecordUnlockFailure(UnlockSourceCLI, nil); !errors.As(err, &wrong) || wrong.Failures != i || wrong.Wait != 0 {
			t.Fatalf("failure %d: %v", i, err)
		}
		if err := CheckUnlockAllowed(nil); err != nil {
			t.Fatalf("try %d should be free: %v", i+1, err)
		}
	}
	err := RecordUnlockFailure(UnlockSourceDesktop, nil)
	var wrong *ErrWrongPassword
	if !errors.As(err, &wrong) || wrong.Failures != 4 || wrong.Wait != 30*time.Second {
		t.Fatalf("fourth failure: %v", err)
	}
	if !strings.Contains(err.Error(), "Try again in 30 seconds") {
		t.Fatalf("message = %q", err.Error())
	}
	var cool *ErrUnlockCooldown
	if err := CheckUnlockAllowed(nil); !errors.As(err, &cool) || cool.Failures != 4 || cool.WaitSeconds() != 30 {
		t.Fatalf("expected a 30s cooldown, got %v", err)
	}
	*clock = clock.Add(31 * time.Second)
	if err := CheckUnlockAllowed(nil); err != nil {
		t.Fatalf("wait is over: %v", err)
	}
	// Never permanent: even 20 failures only wait an hour.
	for i := 0; i < 16; i++ {
		_ = RecordUnlockFailure(UnlockSourceCLI, nil)
	}
	if wait, n := UnlockWait(); n != 20 || wait != time.Hour {
		t.Fatalf("after 20 failures wait=%v n=%d", wait, n)
	}

	since := RecordUnlockSuccess()
	if since == nil || since.Count != 20 || !since.Last.Equal(*clock) || strings.Join(since.Sources, ",") != "cli,desktop" {
		t.Fatalf("failedSince = %+v", since)
	}
	b, _ := json.Marshal(since)
	if !strings.Contains(string(b), `"count":20`) || !strings.Contains(string(b), `"last":`) || !strings.Contains(string(b), `"sources":["cli","desktop"]`) {
		t.Fatalf("failedSince JSON = %s", b)
	}
	if err := CheckUnlockAllowed(nil); err != nil {
		t.Fatalf("success should clear the wait: %v", err)
	}
	if RecordUnlockSuccess() != nil {
		t.Fatal("a second success has nothing to report")
	}
	if epoch, total := GuardMark(); epoch == "" || total != 20 {
		t.Fatalf("mark = %q %d", epoch, total)
	}
}

func TestUnlockGuardMigratesPlainCounter(t *testing.T) {
	dir, clock := isolate(t)
	path := filepath.Join(dir, ".apm_lock")
	if err := os.WriteFile(path, []byte("6"), 0600); err != nil {
		t.Fatal(err)
	}
	mod := clock.Add(-time.Minute)
	if err := os.Chtimes(path, mod, mod); err != nil {
		t.Fatal(err)
	}
	st := LoadUnlockGuard()
	if st.Failures != 6 || !st.NextAllowed.Equal(mod.Add(5*time.Minute)) {
		t.Fatalf("migrated state = %+v", st)
	}
	var cool *ErrUnlockCooldown
	if err := CheckUnlockAllowed(nil); !errors.As(err, &cool) || cool.Wait != 4*time.Minute {
		t.Fatalf("an old count must keep its wait: %v", err)
	}
	*clock = clock.Add(5 * time.Minute)
	_ = RecordUnlockFailure(UnlockSourceCLI, nil)
	data, _ := os.ReadFile(path)
	var saved UnlockGuardState
	if err := json.Unmarshal(data, &saved); err != nil || saved.Failures != 7 || saved.Epoch == "" {
		t.Fatalf("state file should now be JSON with 7 failures: %s", data)
	}
}

func TestUnlockGuardAlertsOncePerBurst(t *testing.T) {
	_, clock := isolate(t)
	sent := 0
	guardAlert = func(v *Vault, level int, kind, details string) { sent++ }
	v := &Vault{Profile: "standard", AlertsEnabled: true, AlertEmail: "me@example.com"}
	data, err := EncryptVault(v, "ValidPass123!")
	if err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 5; i++ {
		_ = RecordUnlockFailure(UnlockSourceCLI, data)
		*clock = clock.Add(time.Minute)
	}
	if sent != 1 {
		t.Fatalf("a burst should send one email, sent %d", sent)
	}
	*clock = clock.Add(20 * time.Minute)
	_ = RecordUnlockFailure(UnlockSourceDesktop, data)
	if sent != 2 {
		t.Fatalf("a failure after a quiet period should send again, sent %d", sent)
	}
}

func TestLockoutRequiresRecovery(t *testing.T) {
	_, clock := isolate(t)
	v := &Vault{Profile: "standard", LockoutAfter: 5}
	data, err := EncryptVault(v, "ValidPass123!")
	if err != nil {
		t.Fatal(err)
	}
	if got := ReadVaultLockoutAfter(data); got != 5 {
		t.Fatalf("lockout in header = %d", got)
	}
	var err5 error
	for i := 0; i < 5; i++ {
		*clock = clock.Add(2 * time.Hour)
		err5 = RecordUnlockFailure(UnlockSourceCLI, data)
	}
	var rec *ErrRecoveryRequired
	if !errors.As(err5, &rec) || rec.Failures != 5 {
		t.Fatalf("fifth failure should need recovery: %v", err5)
	}
	*clock = clock.Add(2 * time.Hour)
	if err := CheckUnlockAllowed(data); !errors.As(err, &rec) {
		t.Fatalf("the lockout outlasts the wait: %v", err)
	}
	if err := ValidateLockoutAfter(3); err == nil {
		t.Fatal("a lockout of 3 is too easy to trip")
	}
	if ValidateLockoutAfter(0) != nil || ValidateLockoutAfter(10) != nil {
		t.Fatal("0 and 10 are valid")
	}
}

// TestCorrectPasswordAlwaysOpensRealVault is the decoy's removal: after many
// failures the right password opens the real vault once the wait is over.
func TestCorrectPasswordAlwaysOpensRealVault(t *testing.T) {
	dir, clock := isolate(t)
	const pw = "ValidPass123!"
	path := filepath.Join(dir, "vault.dat")
	v := &Vault{Profile: "standard", Spaces: []string{"default"}}
	if err := v.AddEntry("github", "alice", "real-secret-1"); err != nil {
		t.Fatal(err)
	}
	data, err := EncryptVault(v, pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(path, data, 0600); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 9; i++ {
		*clock = clock.Add(2 * time.Hour)
		if _, err := UnlockWithPassword(path, "wrong-"+string(rune('a'+i))); err == nil {
			t.Fatal("a wrong password must fail")
		}
	}
	if _, err := UnlockWithPassword(path, pw); !IsUnlockGuardError(err) {
		t.Fatalf("during the wait even the right password waits: %v", err)
	}
	*clock = clock.Add(2 * time.Hour)
	res, err := UnlockWithPassword(path, pw)
	if err != nil {
		t.Fatalf("right password after 9 failures: %v", err)
	}
	if res.ReadOnly || len(res.Vault.Entries) != 1 || res.Vault.Entries[0].Password != "real-secret-1" {
		t.Fatalf("expected the real, writable vault: %+v", res.Vault.Entries)
	}
	if res.FailedSince == nil || res.FailedSince.Count != 9 {
		t.Fatalf("failedSince = %+v", res.FailedSince)
	}

	// A read-only session reads the real vault, and MCP saves refuse it.
	if err := CreateSession(pw, time.Hour, true, time.Hour); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = KillSession() })
	mv, mpw, err := unlockVaultForMCP(path)
	if err != nil {
		t.Fatal(err)
	}
	if len(mv.Entries) != 1 || mv.Entries[0].Password != "real-secret-1" {
		t.Fatalf("MCP read-only session should see the real vault: %+v", mv.Entries)
	}
	if err := saveVault(mv, mpw, path); !errors.Is(err, ErrMCPReadOnly) {
		t.Fatalf("MCP save in a read-only session: %v", err)
	}
	sess, err := AttemptUnlockWithSession(path)
	if err != nil || !sess.ReadOnly || len(sess.Vault.Entries) != 1 || sess.Vault.Entries[0].Password != "real-secret-1" {
		t.Fatalf("read-only session unlock = %+v, %v", sess, err)
	}
}

func TestOldVaultKeysStillDecode(t *testing.T) {
	raw := `{"salt":null,"entries":[{"account":"a","username":"u","password":"p"}],"failed_attempts":4,"emergency_mode":true,"decoy_mode":true,"decoy_session_count":3,"spaces":["default"]}`
	var v Vault
	if err := json.Unmarshal([]byte(raw), &v); err != nil {
		t.Fatalf("a vault with the removed decoy fields must still decode: %v", err)
	}
	if len(v.Entries) != 1 || v.Entries[0].Password != "p" {
		t.Fatalf("entries = %+v", v.Entries)
	}
}

// The CLI keeps the guard next to the vault it was pointed at, like pm desktop,
// so switching between them never looks like a reset counter.
func TestStateDirFollowsVault(t *testing.T) {
	dir, _ := isolate(t)
	t.Setenv("APM_STATE_DIR", "")
	vault := filepath.Join(dir, "elsewhere", "vault.dat")
	SetStateVaultPath(vault)
	t.Cleanup(func() { SetStateVaultPath("") })
	if got := apmStateDir(); got != filepath.Dir(vault) {
		t.Fatalf("state dir = %q, want %q", got, filepath.Dir(vault))
	}
	t.Setenv("APM_STATE_DIR", filepath.Join(dir, "explicit"))
	if got := apmStateDir(); got != filepath.Join(dir, "explicit") {
		t.Fatalf("APM_STATE_DIR should win, got %q", got)
	}
}
