package apm

import (
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

var testAuditKey = []byte("0123456789abcdef0123456789abcdef")

// signedLog builds audit entries signed like LogAction does.
func signedLog(entries ...AuditEntry) []AuditEntry {
	prev := ""
	for i := range entries {
		e := &entries[i]
		e.PrevHash = prev
		sum := sha256.Sum256([]byte(fmt.Sprintf("%d:%s:%s:%s:%s:%s", e.Timestamp.UnixNano(), e.Action, e.Details, e.User, e.Hostname, e.PrevHash)))
		e.Hash = hex.EncodeToString(sum[:])
		mac := hmac.New(sha256.New, testAuditKey)
		mac.Write([]byte(e.Hash))
		e.Signature = hex.EncodeToString(mac.Sum(nil))
		prev = e.Hash
	}
	return entries
}

func withAudit(t *testing.T, logs *[]AuditEntry) {
	t.Helper()
	prevLogs, prevKey := activityAuditLogs, auditKey
	activityAuditLogs = func() []AuditEntry { return *logs }
	auditKey = func() ([]byte, error) { return testAuditKey, nil }
	t.Cleanup(func() { activityAuditLogs, auditKey = prevLogs, prevKey })
}

func kindsOf(events []ActivityEvent) map[string]ActivityEvent {
	out := map[string]ActivityEvent{}
	for _, e := range events {
		out[e.Kind] = e
	}
	return out
}

func TestActivityUnlockSignals(t *testing.T) {
	_, clock := isolate(t)
	logs := []AuditEntry{}
	withAudit(t, &logs)
	v := &Vault{Profile: "standard"}

	// The first unlock knows the device and sets the baseline.
	if ev := RecordUnlockActivity(v, UnlockActivity{Source: UnlockSourceCLI}); len(ev) != 0 {
		t.Fatalf("a first unlock is quiet: %+v", ev)
	}

	// Wrong passwords before an unlock.
	for i := 0; i < 5; i++ {
		_ = RecordUnlockFailure(UnlockSourceDesktop, nil)
	}
	failed := RecordUnlockSuccess()
	ev := kindsOf(RecordUnlockActivity(v, UnlockActivity{Source: UnlockSourceCLI, FailedSince: failed}))
	if e, ok := ev[ActivityFailedUnlocks]; !ok || e.Severity != SeverityMedium || e.Title != "5 wrong passwords before this unlock" || !strings.Contains(e.Body, "desktop app") {
		t.Fatalf("failed_unlocks = %+v", e)
	}
	if _, ok := ev[ActivitySuccessAfterFailures]; !ok {
		t.Fatal("success after 5 failures should be flagged")
	}

	// A new device.
	currentDeviceFunc = func() Device { return Device{ID: "dev-b", Label: "Desktop (bob)"} }
	ev = kindsOf(RecordUnlockActivity(v, UnlockActivity{Source: UnlockSourceDesktop}))
	if e, ok := ev[ActivityNewDevice]; !ok || !strings.Contains(e.Body, "Desktop (bob)") {
		t.Fatalf("new_device = %+v", ev)
	}
	if ev = kindsOf(RecordUnlockActivity(v, UnlockActivity{Source: UnlockSourceDesktop})); len(ev) != 0 {
		t.Fatalf("a known device is quiet: %+v", ev)
	}

	// The failure counter deleted between unlocks.
	_ = RecordUnlockFailure(UnlockSourceCLI, nil)
	os.Remove(filepath.Join(os.Getenv("APM_STATE_DIR"), ".apm_lock"))
	_ = RecordUnlockFailure(UnlockSourceCLI, nil)
	failed = RecordUnlockSuccess()
	if _, ok := kindsOf(RecordUnlockActivity(v, UnlockActivity{FailedSince: failed}))[ActivityCounterReset]; !ok {
		t.Fatal("a deleted failure counter should be flagged")
	}

	// The clock going back.
	*clock = clock.Add(-2 * time.Hour)
	if _, ok := kindsOf(RecordUnlockActivity(v, UnlockActivity{}))[ActivityClockRollback]; !ok {
		t.Fatal("a clock rollback should be flagged")
	}
}

func TestActivityUnusualHour(t *testing.T) {
	_, clock := isolate(t)
	logs := []AuditEntry{}
	withAudit(t, &logs)
	v := &Vault{Profile: "standard"}
	day := time.Date(2026, 3, 1, 0, 0, 0, 0, time.Local)
	// Three weeks of unlocks at 9:00 and 18:00, none at night.
	for d := 0; d < 21; d++ {
		for _, h := range []int{9, 18} {
			*clock = day.AddDate(0, 0, d).Add(time.Duration(h) * time.Hour)
			if ev := kindsOf(RecordUnlockActivity(v, UnlockActivity{})); len(ev) > 0 {
				t.Fatalf("usual hours are quiet: %+v", ev)
			}
		}
	}
	*clock = day.AddDate(0, 0, 21).Add(3 * time.Hour)
	ev := kindsOf(RecordUnlockActivity(v, UnlockActivity{Source: UnlockSourceCLI}))
	e, ok := ev[ActivityUnusualHour]
	if !ok {
		t.Fatal("03:00 should be unusual")
	}
	// "This was me" teaches the baseline that hour.
	if !AckActivity(v, e.ID) {
		t.Fatal("ack failed")
	}
	*clock = clock.AddDate(0, 0, 1)
	if _, ok := kindsOf(RecordUnlockActivity(v, UnlockActivity{}))[ActivityUnusualHour]; ok {
		t.Fatal("an acknowledged hour is usual now")
	}
	if list, unack := ListActivity(v, 0, false); unack != 0 || len(list) != 0 {
		t.Fatalf("nothing left to review: %d %+v", unack, list)
	}
	if list, _ := ListActivity(v, 0, true); len(list) != 1 || !list[0].Acknowledged {
		t.Fatalf("acknowledged events stay listed with --all: %+v", list)
	}
}

func TestActivityNoBaselineBeforeTwoWeeks(t *testing.T) {
	_, clock := isolate(t)
	logs := []AuditEntry{}
	withAudit(t, &logs)
	v := &Vault{}
	start := *clock
	for i := 0; i < 30; i++ {
		*clock = start.Add(time.Duration(i) * time.Hour / 4)
		RecordUnlockActivity(v, UnlockActivity{})
	}
	*clock = start.Add(11 * time.Hour)
	if _, ok := kindsOf(RecordUnlockActivity(v, UnlockActivity{}))[ActivityUnusualHour]; ok {
		t.Fatal("no unusual hours before 14 days of history")
	}
}

func TestActivityFromAuditAndHistory(t *testing.T) {
	_, clock := isolate(t)
	v := &Vault{Profile: "standard"}
	_ = v.AddEntry("AWS root", "root", "pw-1")
	ref := v.ItemRefs()[0]
	priv := "root"
	v.SetItemTelemetryFlags(ref, &priv, nil)

	now := *clock
	at := func(sec int) time.Time { return now.Add(time.Duration(sec) * time.Second) }
	entries := []AuditEntry{
		{Timestamp: at(1), Action: "DATA_EXPORTED", Details: "File: x.csv, Format: csv, Items: 3, Passkeys: 0, Encrypted: false"},
		{Timestamp: at(2), Action: "MCP_SCOPE_DENIED", Details: "Assistant 'Claude' was refused delete_entry: outside its permissions"},
		{Timestamp: at(3), Action: "MCP_ASSISTANT_DENIED", Details: "Did not allow assistant 'Claude': user said no"},
		{Timestamp: at(4), Action: "MCP_ENTRY_ACCESSED", Details: "Token 'Claude' accessed entry 'AWS root' (Password)"},
	}
	for i := 0; i < 16; i++ {
		entries = append(entries, AuditEntry{Timestamp: at(10 + i), Action: "MCP_ENTRY_ACCESSED", Details: fmt.Sprintf("Token 'Cursor' accessed entry 'item-%d' (Password)", i)})
	}
	logs := signedLog(entries...)
	withAudit(t, &logs)
	for i := 0; i < 12; i++ {
		v.History = append(v.History, HistoryEntry{Timestamp: at(i * 5), Action: "GET", Category: "PASSWORD", Identifier: fmt.Sprintf("s%d", i)})
	}

	*clock = at(120)
	ev := ScanActivity(v, nil)
	got := kindsOf(ev)
	if e := got[ActivityExport]; e.Severity != SeverityHigh {
		t.Errorf("an unencrypted export is high: %+v", e)
	}
	if e := got[ActivityAIDenied]; e.Title != "Claude was refused 2 times" || e.Actor != "Claude" {
		t.Errorf("ai_denied = %+v", e)
	}
	if e := got[ActivityAIFirstPrivileged]; e.Actor != "Claude" || !strings.Contains(e.Body, "AWS root") {
		t.Errorf("ai_first_privileged = %+v", e)
	}
	if e := got[ActivityAIBurst]; e.Actor != "Cursor" {
		t.Errorf("ai_burst = %+v", e)
	}
	if e := got[ActivityBulkReveal]; !strings.HasPrefix(e.Title, "12 secrets revealed") {
		t.Errorf("bulk_reveal = %+v", e)
	}
	if _, ok := got[ActivityLogTampered]; ok {
		t.Error("an intact log isn't tampered")
	}

	// The same entries are not reported twice.
	if again := ScanActivity(v, nil); len(again) != 0 {
		t.Fatalf("a second scan has nothing new: %+v", again)
	}

	// A second read of the same privileged item by the same assistant is quiet.
	logs = signedLog(append(append([]AuditEntry{}, entries...), AuditEntry{Timestamp: at(200), Action: "MCP_ENTRY_ACCESSED", Details: "Token 'Claude' accessed entry 'AWS root' (Password)"})...)
	*clock = at(300)
	if _, ok := kindsOf(ScanActivity(v, nil))[ActivityAIFirstPrivileged]; ok {
		t.Fatal("only the first privileged read is reported")
	}

	// Editing an entry breaks its signature.
	logs[1].Details = "edited"
	*clock = at(400)
	if e, ok := kindsOf(ScanActivity(v, nil))[ActivityLogTampered]; !ok || e.Severity != SeverityCritical {
		t.Fatal("an edited audit entry should be flagged")
	}
	if _, ok := kindsOf(ScanActivity(v, nil))[ActivityLogTampered]; ok {
		t.Fatal("the same tampering is reported once")
	}
}

func TestAuditIntegrityToleratesForkedChain(t *testing.T) {
	logs := []AuditEntry{}
	withAudit(t, &logs)
	now := time.Now()
	a := signedLog(AuditEntry{Timestamp: now, Action: "A"}, AuditEntry{Timestamp: now.Add(time.Second), Action: "B"})
	// Two processes logged at once: C also follows A.
	c := signedLog(AuditEntry{Timestamp: now, Action: "A"}, AuditEntry{Timestamp: now.Add(2 * time.Second), Action: "C"})
	logs = append(a, c[1])
	if bad := AuditIntegrity(logs); bad != -1 {
		t.Fatalf("a one-entry fork is not tampering, got %d", bad)
	}
	// Removing entries leaves a gap.
	long := signedLog(AuditEntry{Timestamp: now, Action: "1"}, AuditEntry{Timestamp: now.Add(1), Action: "2"}, AuditEntry{Timestamp: now.Add(2), Action: "3"},
		AuditEntry{Timestamp: now.Add(3), Action: "4"}, AuditEntry{Timestamp: now.Add(4), Action: "5"}, AuditEntry{Timestamp: now.Add(5), Action: "6"},
		AuditEntry{Timestamp: now.Add(6), Action: "7"}, AuditEntry{Timestamp: now.Add(7), Action: "8"})
	cut := append(append([]AuditEntry{}, long[:1]...), long[7])
	if bad := AuditIntegrity(cut); bad != 1 {
		t.Fatalf("removed entries should be found, got %d", bad)
	}
}

func TestActivityRiskySettings(t *testing.T) {
	_, clock := isolate(t)
	logs := []AuditEntry{}
	withAudit(t, &logs)
	sent := []string{}
	activityAlert = func(v *Vault, level int, kind, details string) { sent = append(sent, details) }
	v := &Vault{Profile: "hardened", AlertsEnabled: true, AlertEmail: "a@example.com", AnomalyDetectionEnabled: true, ActivePolicy: Policy{Name: "corp"}}
	off := false
	ScanActivity(v, &off)

	v.AlertsEnabled = false
	v.Profile = "standard"
	v.ActivePolicy = Policy{}
	v.RecoveryCodeHashes = [][]byte{[]byte("x")}
	on := true
	*clock = clock.Add(time.Minute)
	ev := ScanActivity(v, &on)
	titles := []string{}
	for _, e := range ev {
		if e.Kind != ActivityRiskySetting {
			t.Fatalf("unexpected %+v", e)
		}
		titles = append(titles, e.Title)
	}
	joined := strings.Join(titles, "|")
	for _, want := range []string{"Security alerts turned off", "Encryption profile weakened", "Password policy removed", "Account recovery changed", "Touch ID turned on"} {
		if !strings.Contains(joined, want) {
			t.Errorf("missing %q in %v", want, titles)
		}
	}
	// Alerts are off now, so nothing is emailed.
	if len(sent) != 0 {
		t.Fatalf("no email with alerts off: %v", sent)
	}

	v.AlertsEnabled = true
	v.RecoveryCodeHashes = nil
	*clock = clock.Add(time.Minute)
	ScanActivity(v, &on)
	if len(sent) != 1 || !strings.Contains(sent[0], "Account recovery changed") {
		t.Fatalf("one batched email for high events: %v", sent)
	}
}

func TestActivityEventsAreBounded(t *testing.T) {
	isolate(t)
	v := &Vault{}
	w := v.watchtower()
	base := time.Now()
	for i := 0; i < 600; i++ {
		w.add(event(ActivityExport, SeverityLow, "x", "", base.Add(time.Duration(i)*time.Second), "", ""))
	}
	if len(w.Events) != maxActivityEvents || !w.Events[len(w.Events)-1].At.Equal(base.Add(599*time.Second)) {
		t.Fatalf("keeps the newest %d events, has %d", maxActivityEvents, len(w.Events))
	}
	if n := AckAllActivity(v); n != maxActivityEvents {
		t.Fatalf("ack all = %d", n)
	}
}
