package apm

import (
	"testing"
	"time"
)

func dayAt(now time.Time, daysAgo int) time.Time {
	d := now.AddDate(0, 0, -daysAgo)
	return time.Date(d.Year(), d.Month(), d.Day(), 0, 0, 0, 0, now.Location())
}

func TestScoreTrendRule(t *testing.T) {
	now := time.Date(2026, 3, 20, 15, 0, 0, 0, time.Local)
	pts := func(days ...int) []ScorePoint {
		var out []ScorePoint
		for i, d := range days {
			out = append(out, ScorePoint{T: dayAt(now, d), Score: 50 + i})
		}
		return out
	}

	if tr := scoreTrend(nil, 80, now); tr != nil {
		t.Fatalf("no history, no trend: %+v", tr)
	}
	if tr := scoreTrend(pts(0), 80, now); tr != nil {
		t.Fatalf("today's own point is not a comparison: %+v", tr)
	}

	// Younger than a week: the oldest earlier day.
	tr := scoreTrend(pts(3, 1, 0), 60, now)
	if tr == nil || tr.Since != dayAt(now, 3).UnixMilli() || tr.Delta != 60-50 {
		t.Fatalf("young history = %+v", tr)
	}

	// Old enough: the newest day at least a week back, not the oldest.
	tr = scoreTrend(pts(40, 9, 7, 6, 2, 0), 70, now)
	if tr == nil || tr.Since != dayAt(now, 7).UnixMilli() || tr.Delta != 70-52 {
		t.Fatalf("week-old point = %+v", tr)
	}
	tr = scoreTrend(pts(30, 12), 45, now)
	if tr == nil || tr.Since != dayAt(now, 12).UnixMilli() || tr.Delta != 45-51 {
		t.Fatalf("gap in history = %+v", tr)
	}
}

func TestScanReportsTrend(t *testing.T) {
	_, clock := isolate(t)
	v := &Vault{Profile: "standard"}
	_ = v.AddEntry("Bank", "alice", strongPassword(t))

	rep := ScanWatchtower(v, WatchtowerOptions{})
	if rep.Trend != nil {
		t.Fatalf("a first scan has nothing to compare with: %+v", rep.Trend)
	}
	RecordWatchtowerHistory(v, 40)
	*clock = clock.AddDate(0, 0, 3)
	rep = ScanWatchtower(v, WatchtowerOptions{})
	if rep.Trend == nil || rep.Trend.Delta != rep.Score-40 || rep.Trend.Since != v.Watchtower.History[0].T.UnixMilli() {
		t.Fatalf("trend = %+v, score %d", rep.Trend, rep.Score)
	}
	if ScanWatchtower(v, WatchtowerOptions{Space: "default"}).Trend != nil {
		t.Fatal("history is for the whole vault, so a one-space scan has no trend")
	}
}

func trustOf(t *testing.T, rep *WatchtowerReport, title string) TrustScore {
	t.Helper()
	for _, ts := range rep.Trust {
		if ts.ItemTitle == title {
			return ts
		}
	}
	t.Fatalf("no trust score for %s", title)
	return TrustScore{}
}

func refByTitle(t *testing.T, v *Vault, title string) VaultItemRef {
	t.Helper()
	for _, r := range v.ItemRefs() {
		if r.Title == title {
			return r
		}
	}
	t.Fatalf("no item %s", title)
	return VaultItemRef{}
}

func TestTrustCountsOpenFindings(t *testing.T) {
	isolate(t)
	v := &Vault{Profile: "standard"}
	_ = v.AddEntry("GitHub", "alice", "Zq!8f3e1c0a9b7d6e5f4")
	_ = v.AddEntry("Bank", "alice", strongPassword(t))
	_ = v.AddEntry("Forum", "alice", "Zq!8f3e1c0a9b7d6e5f5")
	SetBreachCheck(v, true)
	gref := refByTitle(t, v, "GitHub")
	v.Watchtower.Breach.Cache = map[string]BreachCacheEntry{gref.ID: {SHA1: passwordSHA1("Zq!8f3e1c0a9b7d6e5f4"), Count: 12, Checked: watchNow()}}

	rep := ScanWatchtower(v, WatchtowerOptions{})
	gh := trustOf(t, rep, "GitHub")
	if gh.Level == "low" || gh.Level == "medium" {
		t.Fatalf("a breached item can't be low or medium risk: %+v", gh)
	}
	if len(gh.Reasons) == 0 || gh.Reasons[0].Text != "Found in a data breach" || gh.Reasons[0].Delta >= 0 {
		t.Fatalf("the finding is the first reason: %+v", gh.Reasons)
	}
	if bank := trustOf(t, rep, "Bank"); bank.Level != "low" || bank.Score != 100 {
		t.Fatalf("an item without findings or telemetry stays at 100: %+v", bank)
	}
	// Forum's password is one character from GitHub's: a medium "similar"
	// finding makes it medium risk, not low.
	if fo := trustOf(t, rep, "Forum"); fo.Level != "medium" {
		t.Fatalf("forum = %+v", fo)
	}

	// A dismissed finding no longer counts.
	for _, f := range rep.Findings {
		if f.ItemTitle == "GitHub" {
			if err := DismissFinding(v, f.ID, "accepted", 0); err != nil {
				t.Fatal(err)
			}
		}
	}
	if gh := trustOf(t, ScanWatchtower(v, WatchtowerOptions{}), "GitHub"); gh.Score != 100 {
		t.Fatalf("dismissed findings don't lower trust: %+v", gh)
	}

	// An exposed item counts the finding once, not the flag again.
	ref := refByTitle(t, v, "Bank")
	exposed := true
	v.SetItemTelemetryFlags(ref, nil, &exposed)
	bank := trustOf(t, ScanWatchtower(v, WatchtowerOptions{}), "Bank")
	if bank.Level != "critical" || len(bank.Reasons) != 1 || bank.Reasons[0].Delta != trustFindingDelta[SeverityCritical] {
		t.Fatalf("exposed bank = %+v", bank)
	}
	if got := ItemTrust(v, ref); got.Score != bank.Score || got.Level != bank.Level {
		t.Fatalf("ItemTrust matches the scan: %+v vs %+v", got, bank)
	}
}

func TestLockoutRecoveryReady(t *testing.T) {
	isolate(t)
	v := &Vault{Profile: "standard"}
	if LockoutRecoveryReady(v) {
		t.Fatal("no recovery at all")
	}
	if _, err := GenerateOneTimeRecoveryCodes(v, 3); err != nil {
		t.Fatal(err)
	}
	v.RecoveryPasskeyEnabled = true
	v.RecoveryPasskeyCred = []byte("cred")
	if LockoutRecoveryReady(v) {
		t.Fatal("recovery codes and a passkey can't open the vault on their own")
	}
	v.DEK = make([]byte, 32)
	v.SetRecoveryEmail("alice@example.com")
	if err := v.SetRecoveryKey(GenerateRecoveryKey(), make([]byte, 16)); err != nil {
		t.Fatal(err)
	}
	if !LockoutRecoveryReady(v) {
		t.Fatal("email and recovery key are a way back")
	}
	v.RecoveryEmail = ""
	if LockoutRecoveryReady(v) {
		t.Fatal("pm auth recover needs the email as well as the key")
	}
	v.RecoveryShareThreshold, v.RecoveryShareCount = 2, 3
	v.RecoveryShareHashes = map[string][]byte{"1": {1}, "2": {2}, "3": {3}}
	if !LockoutRecoveryReady(v) {
		t.Fatal("trustee shares rebuild the key")
	}

	v.LockoutAfter = 5
	v.ClearRecoveryInfo()
	if v.LockoutAfter != 0 || LockoutRecoveryReady(v) {
		t.Fatalf("removing recovery turns the lockout off: %d", v.LockoutAfter)
	}
}
