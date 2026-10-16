package apm

import (
	"context"
	"crypto/ed25519"
	"crypto/rand"
	"crypto/rsa"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/pem"
	"fmt"
	"math/big"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"golang.org/x/crypto/ssh"
)

func strongPassword(t *testing.T) string {
	t.Helper()
	b := make([]byte, 12)
	if _, err := rand.Read(b); err != nil {
		t.Fatal(err)
	}
	return "Zq!" + hex.EncodeToString(b)
}

func findingsOf(rep *WatchtowerReport, kind string) []Finding {
	var out []Finding
	for _, f := range rep.Findings {
		if f.Kind == kind {
			out = append(out, f)
		}
	}
	return out
}

func TestPasswordStrengthPatterns(t *testing.T) {
	weak := map[string]string{
		"password":    "",
		"P@ssw0rd":    "",
		"Summer2024!": reasonCommonWord,
		"qwertyuiop":  "",
		"zxcvbnm,./":  reasonKeyboard,
		"aaaaaaaaaaa": reasonRepeat,
		"abcdefghij":  "",
		"13579aaaa":   "",
		"alice1990":   "",
		"12/05/1987":  reasonDate,
	}
	for pw, reason := range weak {
		s := PasswordStrength(pw, "alice@example.com", "Example")
		if s.Bits >= 36 {
			t.Errorf("%q should be weak, got %.1f bits (%v)", pw, s.Bits, s.Reasons)
		}
		if reason != "" && !s.Common && !strings.Contains(strings.Join(s.Reasons, ","), reason) {
			t.Errorf("%q should mention %q, got %v", pw, reason, s.Reasons)
		}
	}
	if s := PasswordStrength("password"); !s.Common {
		t.Error("password is a common password")
	}
	if s := PasswordStrength("P@ssw0rd"); !s.Common {
		t.Error("P@ssw0rd is a l33t common password")
	}
	if s := PasswordStrength("examplecorp-7731", "alice", "examplecorp"); !strings.Contains(strings.Join(s.Reasons, ","), reasonUserInput) {
		t.Errorf("site name should be spotted: %v", s.Reasons)
	}
	for _, pw := range []string{"Zq!8f3e1c0a9b7d6e5f4", "correct-Horse-battery-Staple-91x", "t7#Kp2!vQ9mZ"} {
		if s := PasswordStrength(pw); s.Bits < 40 || s.Common {
			t.Errorf("%q should be strong, got %.1f bits (%v)", pw, s.Bits, s.Reasons)
		}
	}
}

func TestWatchtowerScoreIsRatioBased(t *testing.T) {
	isolate(t)
	v := &Vault{Profile: "standard", Spaces: []string{"default"}, AlertsEnabled: true, AlertEmail: "a@example.com"}
	for i := 0; i < 200; i++ {
		if err := v.AddEntry(fmt.Sprintf("site-%03d", i), "alice", strongPassword(t)); err != nil {
			t.Fatal(err)
		}
	}
	for i := 0; i < 3; i++ {
		v.Entries[i].Password = "password"
	}
	rep := ScanWatchtower(v, WatchtowerOptions{})
	weak := findingsOf(rep, "weak")
	if len(weak) != 3 {
		t.Fatalf("expected 3 weak findings, got %d", len(weak))
	}
	if rep.Score < 70 {
		t.Fatalf("200 items with 3 weak ones should keep a fair score, got %d", rep.Score)
	}
	if rep.ItemsChecked != 200 || len(rep.Trust) != 200 {
		t.Fatalf("itemsChecked=%d trust=%d", rep.ItemsChecked, len(rep.Trust))
	}
	if len(rep.Categories) != len(WatchtowerKinds) || rep.Categories[0].Kind != "weak" || rep.Categories[0].Count != 3 {
		t.Fatalf("categories = %+v", rep.Categories)
	}
	reused := findingsOf(rep, "reused")
	if len(reused) != 3 || reused[0].Group == "" || reused[0].Group != reused[1].Group {
		t.Fatalf("the three equal passwords are one reuse group: %+v", reused)
	}
	if weak[0].Impact < 1 {
		t.Fatalf("a weak password should be worth points: %+v", weak[0])
	}

	// Dismissing a finding takes it out of the score but keeps it listed.
	before := rep.Score
	for _, f := range append(weak, reused...) {
		if err := DismissFinding(v, f.ID, "test", 0); err != nil {
			t.Fatal(err)
		}
	}
	rep = ScanWatchtower(v, WatchtowerOptions{})
	if rep.Score <= before {
		t.Fatalf("dismissed findings must not count: %d -> %d", before, rep.Score)
	}
	if got := findingsOf(rep, "weak"); len(got) != 3 || got[0].Dismissed == nil || got[0].Dismissed.Reason != "test" {
		t.Fatalf("dismissed findings stay listed: %+v", got)
	}
	if rep.Categories[0].Count != 0 {
		t.Fatalf("category counts skip dismissed findings: %+v", rep.Categories[0])
	}
	if !RestoreFinding(v, weak[0].ID) || RestoreFinding(v, weak[0].ID) {
		t.Fatal("restore should work once")
	}

	// Only the share matters: everything weak sinks the score.
	for i := range v.Entries {
		v.Entries[i].Password = "123456"
	}
	v.Watchtower.Dismissed = nil
	if rep = ScanWatchtower(v, WatchtowerOptions{}); rep.Score > 70 {
		t.Fatalf("an all-weak vault should score low, got %d", rep.Score)
	}
}

func TestWatchtowerFindingsAcrossCollections(t *testing.T) {
	_, clock := isolate(t)
	v := &Vault{Profile: "legacy", Spaces: []string{"default", "work"}}
	add := func(account, user, pw, site, space string) {
		v.Entries = append(v.Entries, Entry{Account: account, Username: user, Password: pw, Website: site, Space: space})
	}
	add("GitHub", "alice", "Summer2023!x", "https://github.com", "")
	add("Figma", "alice", "Summer2024!x", "figma.com", "work")
	add("Intranet", "alice", strongPassword(t), "http://intranet.example.com", "work")
	add("Router", "admin", strongPassword(t), "http://192.168.1.1", "")
	add("Notes", "alice", strongPassword(t), "", "")
	v.Entries[4].Notes = "deploy key sk_live_" + strings.Repeat("a1B2", 8)
	v.WiFiCredentials = []WiFiEntry{{SSID: "Cafe", SecurityType: "WEP", Password: strongPassword(t)}}
	v.RecoveryCodeItems = []RecoveryCodeEntry{{Service: "Google", Codes: []string{"a", "b", "c", "d"}, Used: []string{"a", "b", "c", "d"}}}
	v.BankingItems = []BankingEntry{{Label: "Visa", Type: "Card", Details: "4111", Expiry: clock.AddDate(0, -2, 0).Format("01/06")}}
	v.GovIDs = []GovIDEntry{{Type: "Passport", Name: "Passport", IDNumber: "X1", Expiry: clock.AddDate(0, 4, 0).Format("2006-01-02")}}
	v.APIKeys = []APIKeyEntry{{Name: "Stripe", Service: "stripe", Key: "k"}}
	v.SecretTelemetry = map[string]SecretTelemetry{
		secretTelemetryKey("APIKEY", "Stripe", ""):   {CreatedAt: clock.AddDate(-2, 0, 0)},
		secretTelemetryKey("PASSWORD", "GitHub", ""): {LastRotation: clock.AddDate(-1, -1, 0), Exposed: true, Privilege: "admin"},
	}

	rep := ScanWatchtower(v, WatchtowerOptions{})
	kinds := map[string][]Finding{}
	for _, f := range rep.Findings {
		kinds[f.Kind] = append(kinds[f.Kind], f)
	}
	for _, k := range []string{"reused", "old", "exposed", "expiring", "insecure_url", "no_2fa", "passkey_available", "wifi", "recovery_codes", "api_key", "setup"} {
		if len(kinds[k]) == 0 {
			t.Errorf("expected a %s finding", k)
		}
	}
	if r := kinds["reused"]; len(r) != 2 || r[0].Group != r[1].Group {
		t.Errorf("near reuse across spaces: %+v", r)
	}
	for _, f := range kinds["reused"] {
		want := SeverityMedium
		if f.ItemTitle == "GitHub" {
			want = SeverityHigh // admin privilege bumps it
		}
		if f.Severity != want || f.Title != "Similar password" {
			t.Errorf("reused %s = %s %q", f.ItemTitle, f.Severity, f.Title)
		}
	}
	if ins := kinds["insecure_url"]; len(ins) != 1 || ins[0].ItemTitle != "Intranet" {
		t.Errorf("only the public http site is insecure: %+v", ins)
	}
	for _, f := range kinds["exposed"] {
		if f.ItemTitle == "GitHub" {
			if f.Severity != SeverityCritical || f.ChangeURL != "https://github.com/.well-known/change-password" {
				t.Errorf("exposed GitHub = %+v", f)
			}
		}
	}
	for _, f := range kinds["old"] {
		if f.ItemTitle == "GitHub" && f.Severity != SeverityHigh {
			t.Errorf("an admin item's old password is bumped to high: %+v", f)
		}
	}
	expTitles := map[string]string{}
	for _, f := range kinds["expiring"] {
		expTitles[f.ItemTitle] = f.Severity + " " + f.Title
	}
	if !strings.HasPrefix(expTitles["Visa"], "high Expired") || !strings.HasPrefix(expTitles["Passport"], "low Expires in") {
		t.Errorf("expiring = %v", expTitles)
	}
	ids := map[string]bool{}
	for _, f := range rep.Findings {
		if ids[f.ID] {
			t.Errorf("duplicate finding id %s", f.ID)
		}
		ids[f.ID] = true
		if f.Fixes == nil {
			t.Errorf("%s has nil fixes", f.ID)
		}
		if f.Kind == "setup" && f.ItemID != "" {
			t.Errorf("setup findings have no item: %+v", f)
		}
	}
	if !ids["setup:profile"] || !ids["setup:recovery"] || !ids["api_key:"+refID(v, "apikey", "Stripe")+":age"] {
		t.Errorf("missing setup or API key age findings: %v", ids)
	}

	work := ScanWatchtower(v, WatchtowerOptions{Space: "work"})
	for _, f := range work.Findings {
		if f.Kind != "setup" && f.Space != "work" {
			t.Errorf("space filter leaked %+v", f)
		}
	}
	def := ScanWatchtower(v, WatchtowerOptions{Space: "default"})
	for _, f := range def.Findings {
		if f.Kind != "setup" && f.Space != "" {
			t.Errorf("default space filter leaked %+v", f)
		}
	}
}

func refID(v *Vault, typ, title string) string {
	for _, r := range v.ItemRefs() {
		if r.Spec.ID == typ && r.Title == title {
			return r.ID
		}
	}
	return ""
}

func TestNearReuse(t *testing.T) {
	if !withinEdits([]rune("Xk9#mQ2vLp"), []rune("Xk9#mQ2vLq"), 2) || withinEdits([]rune("Xk9#mQ2vLp"), []rune("Ab3$zR8wNt"), 2) {
		t.Fatal("edit distance check is off")
	}
	if reuseBase("Summer2023!") != "summer" || reuseBase("ab12") != "" {
		t.Fatal("reuseBase is off")
	}
	items := []*wtItem{}
	for i, pw := range []string{"Xk9#mQ2vLp", "Xk9#mQ2vLq", "Totally-Different-77", "Xk9#mQ2vLp"} {
		items = append(items, &wtItem{ref: VaultItemRef{ID: fmt.Sprintf("id%d", i), Spec: ItemTypes[0]}, title: fmt.Sprintf("Site %d", i), password: pw})
	}
	in := map[string]bool{"id0": true, "id1": true, "id2": true, "id3": true}
	out := reuseFindings(items, in)
	if len(out) != 3 {
		t.Fatalf("expected three linked items, got %+v", out)
	}
	for _, f := range out {
		if f.Group != out[0].Group {
			t.Fatal("one group")
		}
		if f.ItemID == "id1" && f.Severity != SeverityMedium {
			t.Fatalf("the near copy is medium: %+v", f)
		}
		if f.ItemID == "id0" && (f.Severity != SeverityHigh || !strings.Contains(f.Body, "Site 3")) {
			t.Fatalf("the exact copy is high: %+v", f)
		}
	}
}

func TestScoreHistoryOnePerDay(t *testing.T) {
	_, clock := isolate(t)
	v := &Vault{}
	if !RecordWatchtowerHistory(v, 80) || RecordWatchtowerHistory(v, 80) {
		t.Fatal("the same score on the same day is one point")
	}
	if !RecordWatchtowerHistory(v, 82) || len(v.Watchtower.History) != 1 || v.Watchtower.History[0].Score != 82 {
		t.Fatalf("same day updates: %+v", v.Watchtower.History)
	}
	for i := 0; i < 200; i++ {
		*clock = clock.AddDate(0, 0, 1)
		RecordWatchtowerHistory(v, i%100)
	}
	if len(v.Watchtower.History) != 180 {
		t.Fatalf("history keeps 180 days, has %d", len(v.Watchtower.History))
	}
}

func TestBreachCheckHIBP(t *testing.T) {
	isolate(t)
	pwned := "password123"
	hash := passwordSHA1(pwned)
	var calls atomic.Int32
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		calls.Add(1)
		if r.Header.Get("Add-Padding") != "true" {
			t.Errorf("padding header missing")
		}
		prefix := strings.TrimPrefix(r.URL.Path, "/range/")
		if len(prefix) != 5 {
			t.Errorf("only a 5-character prefix may leave the device, got %q", prefix)
		}
		if prefix == hash[:5] {
			fmt.Fprintf(w, "%s:42\r\n0000000000000000000000000000000000A:0\r\n", hash[5:])
			return
		}
		fmt.Fprint(w, "0000000000000000000000000000000000B:0\r\n")
	}))
	defer srv.Close()
	prevURL := hibpRangeURL
	hibpRangeURL = srv.URL + "/range/"
	defer func() { hibpRangeURL = prevURL }()

	v := &Vault{Profile: "standard"}
	_ = v.AddEntry("old", "alice", pwned)
	_ = v.AddEntry("fresh", "alice", strongPassword(t))

	if _, err := RunBreachCheck(context.Background(), v); err != ErrBreachCheckOff {
		t.Fatalf("the check is opt-in: %v", err)
	}
	if calls.Load() != 0 {
		t.Fatal("nothing may be sent while the check is off")
	}
	SetBreachCheck(v, true)
	run, err := RunBreachCheck(context.Background(), v)
	if err != nil || run.Checked != 2 || run.Found != 1 {
		t.Fatalf("run = %+v, %v", run, err)
	}
	rep := ScanWatchtower(v, WatchtowerOptions{})
	b := findingsOf(rep, "breached")
	if len(b) != 1 || b[0].ItemTitle != "old" || !strings.Contains(b[0].Body, "42 times") {
		t.Fatalf("breached = %+v", b)
	}
	if !rep.Breach.Enabled || rep.Breach.Checked != 2 || rep.Breach.Found != 1 || rep.Breach.LastChecked == 0 {
		t.Fatalf("breach summary = %+v", rep.Breach)
	}
	for _, c := range v.Watchtower.Breach.Cache {
		if len(c.SHA1) != 40 {
			t.Fatal("the cache keeps the full hash inside the vault")
		}
	}

	n := calls.Load()
	if run, _ := RunBreachCheck(context.Background(), v); run.Cached != 2 || calls.Load() != n {
		t.Fatalf("unchanged passwords are not re-checked within a week: %+v", run)
	}
	v.Entries[0].Password = strongPassword(t)
	if len(findingsOf(ScanWatchtower(v, WatchtowerOptions{}), "breached")) != 0 {
		t.Fatal("a changed password drops its old answer")
	}

	srv.Close()
	v.Entries[1].Password = strongPassword(t)
	if run, err := RunBreachCheck(context.Background(), v); err == nil || run.Failed == 0 {
		t.Fatalf("a dead server is an error, not a crash: %+v %v", run, err)
	}

	SetBreachCheck(v, false)
	if v.Watchtower.Breach.Cache != nil {
		t.Fatal("turning the check off forgets the answers")
	}
}

func TestSSHAndCertificateChecks(t *testing.T) {
	_, clock := isolate(t)
	// An unencrypted 1024-bit RSA key in PKCS#1 form.
	key := sshTestKey(t, 1024)
	it := &wtItem{ref: VaultItemRef{ID: "k1", Spec: ItemTypes[0]}, title: "old key"}
	f := sshKeyFinding(it, key)
	if f == nil || f.Severity != SeverityHigh || !strings.Contains(f.Body, "1024-bit") || !strings.Contains(f.Body, "no passphrase") {
		t.Fatalf("ssh finding = %+v", f)
	}
	if sshKeyFinding(it, "not a key") != nil {
		t.Fatal("unparseable keys are skipped")
	}
	_, edKey, _ := ed25519.GenerateKey(rand.Reader)
	block, err := ssh.MarshalPrivateKeyWithPassphrase(edKey, "", []byte("hunter2"))
	if err != nil {
		t.Fatal(err)
	}
	if f := sshKeyFinding(it, string(pem.EncodeToMemory(block))); f != nil {
		t.Fatalf("a passphrase-protected Ed25519 key is fine: %+v", f)
	}

	// A certificate with a 1024-bit key that expires in 10 days.
	k, _ := rsa.GenerateKey(rand.Reader, 1024)
	tmpl := &x509.Certificate{SerialNumber: big.NewInt(1), Subject: pkix.Name{CommonName: "old.example.com"}, NotBefore: clock.Add(-time.Hour), NotAfter: clock.AddDate(0, 0, 10)}
	der, err := x509.CreateCertificate(rand.Reader, tmpl, tmpl, &k.PublicKey, k)
	if err != nil {
		t.Fatal(err)
	}
	v := &Vault{Certificates: []CertificateEntry{{Label: "old cert", CertData: string(pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}))}}}
	rep := ScanWatchtower(v, WatchtowerOptions{})
	if c := findingsOf(rep, "certificate"); len(c) != 1 || c[0].Severity != SeverityHigh || !strings.Contains(c[0].Body, "1024-bit") {
		t.Fatalf("certificate = %+v", c)
	}
	if e := findingsOf(rep, "expiring"); len(e) != 1 || !strings.HasPrefix(e[0].Title, "Expires in") {
		t.Fatalf("certificate expiry from the PEM = %+v", e)
	}
}

func TestParseExpiry(t *testing.T) {
	cases := map[string]string{"03/27": "2027-03-31", "2027-03-15": "2027-03-15", "03/2027": "2027-03-31", "2027-03": "2027-03-31"}
	for in, want := range cases {
		got, ok := ParseExpiry(in)
		if !ok || got.Format("2006-01-02") != want {
			t.Errorf("ParseExpiry(%q) = %v %v, want %s", in, got, ok, want)
		}
	}
	if _, ok := ParseExpiry("soon"); ok {
		t.Error("nonsense is not a date")
	}
}

func sshTestKey(t *testing.T, bits int) string {
	t.Helper()
	k, err := rsa.GenerateKey(rand.Reader, bits)
	if err != nil {
		t.Fatal(err)
	}
	return string(pem.EncodeToMemory(&pem.Block{Type: "RSA PRIVATE KEY", Bytes: x509.MarshalPKCS1PrivateKey(k)}))
}
