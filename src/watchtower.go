package apm

import (
	"crypto/sha256"
	"encoding/hex"
	"errors"
	"math"
	"sort"
	"strings"
	"time"
)

// Watchtower checks the whole vault for weak, reused, old, exposed and
// breached passwords, things about to expire, insecure sites, missing
// two-factor and passkeys, risky keys and certificates, and the vault's own
// setup. It scores the vault from 0 to 100 by the share of items affected in
// each category, so a big vault with a few problems keeps a fair score.

// Severities, highest first.
const (
	SeverityCritical = "critical"
	SeverityHigh     = "high"
	SeverityMedium   = "medium"
	SeverityLow      = "low"
)

var severityRank = map[string]int{SeverityLow: 0, SeverityMedium: 1, SeverityHigh: 2, SeverityCritical: 3}
var severityByRank = []string{SeverityLow, SeverityMedium, SeverityHigh, SeverityCritical}
var severityWeight = map[string]float64{SeverityCritical: 1, SeverityHigh: 0.7, SeverityMedium: 0.4, SeverityLow: 0.15}

type watchKind struct {
	Kind   string
	Label  string
	Weight float64
}

// WatchtowerKinds is every finding kind in display order, with the most
// points the kind can take off the score.
var WatchtowerKinds = []watchKind{
	{"weak", "Weak", 20},
	{"reused", "Reused", 15},
	{"breached", "Breached", 20},
	{"exposed", "Exposed", 15},
	{"old", "Old", 6},
	{"expiring", "Expiring", 6},
	{"insecure_url", "Insecure websites", 4},
	{"no_2fa", "Two-factor available", 6},
	{"passkey_available", "Passkey available", 2},
	{"ssh_key", "SSH keys", 5},
	{"certificate", "Certificates", 5},
	{"wifi", "Wi-Fi", 3},
	{"recovery_codes", "Recovery codes", 4},
	{"api_key", "API keys", 6},
	{"setup", "Setup", 0},
}

func kindWeight(kind string) float64 {
	for _, k := range WatchtowerKinds {
		if k.Kind == kind {
			return k.Weight
		}
	}
	return 0
}

// findingWhy says in one sentence why each kind matters.
var findingWhy = map[string]string{
	"weak":              "Attackers try common words, patterns and short passwords first, so these fall quickly.",
	"reused":            "When one site leaks, attackers try the same password everywhere else.",
	"breached":          "Passwords from known breaches are in the lists attackers try first.",
	"exposed":           "A secret that may have leaked works for anyone who has it until you change it.",
	"old":               "The longer a password lives, the more chances it has had to leak.",
	"expiring":          "Expired cards, IDs and certificates stop working, often when you need them.",
	"insecure_url":      "Without HTTPS, the password can be read on the network.",
	"no_2fa":            "Two-factor stops someone who has your password from signing in.",
	"passkey_available": "Passkeys can't be phished, guessed or reused.",
	"ssh_key":           "Weak or unprotected keys give access to every server that trusts them.",
	"certificate":       "Weak signatures and short keys can be forged or broken.",
	"wifi":              "Anyone nearby can join an open or WEP network and watch its traffic.",
	"recovery_codes":    "Without recovery codes, losing your phone can lock you out.",
	"api_key":           "Live keys work for anyone who sees them, and long-lived keys leak.",
	"setup":             "The vault's own settings protect everything in it.",
}

// FindingDismissal is how a finding was dismissed. A zero Until lasts until
// the finding is restored.
type FindingDismissal struct {
	Reason string    `json:"reason,omitempty"`
	At     time.Time `json:"at"`
	Until  time.Time `json:"until,omitzero"`
}

type ScorePoint struct {
	T     time.Time `json:"t"`
	Score int       `json:"score"`
}

type DismissalView struct {
	Reason string `json:"reason"`
	At     int64  `json:"at"`
	Until  int64  `json:"until"`
}

type Finding struct {
	ID        string         `json:"id"`
	Kind      string         `json:"kind"`
	Severity  string         `json:"severity"`
	Title     string         `json:"title"`
	Body      string         `json:"body"`
	Why       string         `json:"why,omitempty"`
	ItemID    string         `json:"itemId,omitempty"`
	ItemType  string         `json:"itemType,omitempty"`
	ItemTitle string         `json:"itemTitle,omitempty"`
	Space     string         `json:"space"`
	Group     string         `json:"group,omitempty"`
	URL       string         `json:"url,omitempty"`
	ChangeURL string         `json:"changeUrl,omitempty"`
	Fixes     []string       `json:"fixes"`
	Impact    int            `json:"impact"`
	Dismissed *DismissalView `json:"dismissed"`

	penalty float64
}

type CategoryCount struct {
	Kind     string `json:"kind"`
	Label    string `json:"label"`
	Count    int    `json:"count"`
	Severity string `json:"severity"`
}

type SetupCheck struct {
	ID     string `json:"id"`
	Label  string `json:"label"`
	OK     bool   `json:"ok"`
	Detail string `json:"detail"`
	Fix    string `json:"fix"`

	severity string
	penalty  float64
}

type TrustReason struct {
	Text  string `json:"text"`
	Delta int    `json:"delta"`
}

type TrustScore struct {
	ItemID    string        `json:"itemId"`
	ItemType  string        `json:"itemType"`
	ItemTitle string        `json:"itemTitle"`
	Space     string        `json:"space"`
	Score     int           `json:"score"`
	Level     string        `json:"level"`
	Reasons   []TrustReason `json:"reasons"`
}

type HistoryPoint struct {
	T     int64 `json:"t"`
	Score int   `json:"score"`
}

// ScoreTrend is how the score moved since an earlier day. See scoreTrend for
// which day it is measured from.
type ScoreTrend struct {
	// Delta is the score now minus the score on the comparison day.
	Delta int `json:"delta"`
	// Since is the comparison day (local midnight, in milliseconds).
	Since int64 `json:"since"`
}

type BreachSummary struct {
	Enabled     bool  `json:"enabled"`
	LastChecked int64 `json:"lastChecked"`
	Checked     int   `json:"checked"`
	Found       int   `json:"found"`
}

// WatchtowerReport is one scan, shaped like the desktop RPC result.
type WatchtowerReport struct {
	Score        int             `json:"score"`
	Grade        string          `json:"grade"`
	Generated    int64           `json:"generated"`
	ItemsChecked int             `json:"itemsChecked"`
	Categories   []CategoryCount `json:"categories"`
	Findings     []Finding       `json:"findings"`
	Setup        []SetupCheck    `json:"setup"`
	Trust        []TrustScore    `json:"trust"`
	History      []HistoryPoint  `json:"history"`
	// Trend is null when there is nothing to compare with: no score from an
	// earlier day yet, or a scan limited to one space (history is kept for
	// the whole vault only).
	Trend  *ScoreTrend   `json:"trend"`
	Breach BreachSummary `json:"breach"`
}

// WatchtowerOptions are the inputs a scan can't read from the vault itself.
type WatchtowerOptions struct {
	// Space limits item findings to one space; empty means every space.
	Space string
	// TouchIDAvailable and TouchIDConfigured describe Touch ID on this Mac.
	TouchIDAvailable  bool
	TouchIDConfigured bool
}

// Grade turns a score into a letter.
func Grade(score int) string {
	switch {
	case score >= 90:
		return "A"
	case score >= 80:
		return "B"
	case score >= 65:
		return "C"
	case score >= 50:
		return "D"
	}
	return "F"
}

func bumpSeverity(sev string) string {
	r := severityRank[sev] + 1
	if r > 3 {
		r = 3
	}
	return severityByRank[r]
}

func spaceMatches(filter, space string) bool {
	filter = strings.TrimSpace(filter)
	if filter == "" {
		return true
	}
	norm := func(s string) string {
		s = strings.ToLower(strings.TrimSpace(s))
		if s == "default" {
			return ""
		}
		return s
	}
	return norm(filter) == norm(space)
}

// ScanWatchtower runs every check and scores the vault.
func ScanWatchtower(v *Vault, opt WatchtowerOptions) *WatchtowerReport {
	now := watchNow()
	items := watchtowerItems(v)
	var scoped []*wtItem
	for _, it := range items {
		if spaceMatches(opt.Space, it.ref.Space) {
			scoped = append(scoped, it)
		}
	}

	eligible := map[string]int{}
	var findings []Finding
	findings = append(findings, checkPasswords(v, items, scoped, now, eligible)...)
	findings = append(findings, checkItems(v, scoped, now, eligible)...)
	setup := checkSetup(v, opt, now)
	for _, s := range setup {
		if s.OK {
			continue
		}
		findings = append(findings, Finding{
			ID: s.ID, Kind: "setup", Severity: s.severity, Title: s.Label, Body: s.Detail,
			Fixes: []string{s.Fix}, penalty: s.penalty,
		})
	}

	for i := range findings {
		findings[i].Why = findingWhy[findings[i].Kind]
	}
	applyDismissals(v, findings, now)
	score := scoreFindings(findings, eligible)

	sort.SliceStable(findings, func(i, j int) bool {
		a, b := findings[i], findings[j]
		if (a.Dismissed == nil) != (b.Dismissed == nil) {
			return a.Dismissed == nil
		}
		if a.Impact != b.Impact {
			return a.Impact > b.Impact
		}
		if severityRank[a.Severity] != severityRank[b.Severity] {
			return severityRank[a.Severity] > severityRank[b.Severity]
		}
		return a.ID < b.ID
	})

	cats := make([]CategoryCount, 0, len(WatchtowerKinds))
	for _, k := range WatchtowerKinds {
		c := CategoryCount{Kind: k.Kind, Label: k.Label, Severity: SeverityLow}
		top := -1
		for _, f := range findings {
			if f.Kind != k.Kind || f.Dismissed != nil {
				continue
			}
			c.Count++
			if severityRank[f.Severity] > top {
				top = severityRank[f.Severity]
			}
		}
		if top >= 0 {
			c.Severity = severityByRank[top]
		}
		cats = append(cats, c)
	}

	open := map[string][]Finding{}
	for _, f := range findings {
		if f.ItemID != "" && f.Dismissed == nil {
			open[f.ItemID] = append(open[f.ItemID], f)
		}
	}
	trust := make([]TrustScore, 0, len(scoped))
	for _, it := range scoped {
		trust = append(trust, trustFor(it, now, open[it.ref.ID]))
	}
	sort.SliceStable(trust, func(i, j int) bool {
		if trust[i].Score != trust[j].Score {
			return trust[i].Score < trust[j].Score
		}
		return strings.ToLower(trust[i].ItemTitle) < strings.ToLower(trust[j].ItemTitle)
	})

	if findings == nil {
		findings = []Finding{}
	}
	rep := &WatchtowerReport{
		Score:        score,
		Grade:        Grade(score),
		Generated:    now.UnixMilli(),
		ItemsChecked: len(scoped),
		Categories:   cats,
		Findings:     findings,
		Setup:        setup,
		Trust:        trust,
		History:      []HistoryPoint{},
		Breach:       breachSummary(v, items),
	}
	if v.Watchtower != nil {
		for _, p := range v.Watchtower.History {
			rep.History = append(rep.History, HistoryPoint{T: p.T.UnixMilli(), Score: p.Score})
		}
		if strings.TrimSpace(opt.Space) == "" {
			rep.Trend = scoreTrend(v.Watchtower.History, score, now)
		}
	}
	return rep
}

// trendDays is how far back the trend looks.
const trendDays = 7

// scoreTrend compares the score with the newest daily score from at least
// trendDays days before today. While the history is younger than that, it
// compares with the oldest score from before today. Today's own point never
// counts, and it returns nil when there is no earlier day. pm and the app
// both show this one value.
func scoreTrend(history []ScorePoint, score int, now time.Time) *ScoreTrend {
	loc := now.Location()
	today := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, loc)
	cutoff := today.AddDate(0, 0, -trendDays)
	var weekOld, oldest *ScorePoint
	for i := range history {
		p := &history[i]
		t := p.T.In(loc)
		if !t.Before(today) {
			continue
		}
		if oldest == nil || t.Before(oldest.T) {
			oldest = p
		}
		if !t.After(cutoff) && (weekOld == nil || t.After(weekOld.T)) {
			weekOld = p
		}
	}
	pick := weekOld
	if pick == nil {
		pick = oldest
	}
	if pick == nil {
		return nil
	}
	return &ScoreTrend{Delta: score - pick.Score, Since: pick.T.UnixMilli()}
}

func breachSummary(v *Vault, items []*wtItem) BreachSummary {
	out := BreachSummary{Enabled: BreachEnabled(v)}
	if !out.Enabled {
		return out
	}
	out.LastChecked = msOrZero(v.Watchtower.Breach.LastChecked)
	for _, it := range items {
		if n, ok := breachCount(v, it.ref.ID, it.password); ok {
			out.Checked++
			if n > 0 {
				out.Found++
			}
		}
	}
	return out
}

func msOrZero(t time.Time) int64 {
	if t.IsZero() {
		return 0
	}
	return t.UnixMilli()
}

func applyDismissals(v *Vault, findings []Finding, now time.Time) {
	if v.Watchtower == nil {
		return
	}
	for i := range findings {
		d, ok := v.Watchtower.Dismissed[findings[i].ID]
		if !ok || (!d.Until.IsZero() && now.After(d.Until)) {
			continue
		}
		findings[i].Dismissed = &DismissalView{Reason: d.Reason, At: msOrZero(d.At), Until: msOrZero(d.Until)}
	}
}

// categoryPenalty grows with the square root of the affected share, so the
// first problems in a category count the most and a few problems in a big
// vault don't sink the score.
func categoryPenalty(kind string, load float64, eligible int) float64 {
	if load <= 0 {
		return 0
	}
	if eligible < 1 {
		eligible = 1
	}
	share := load / float64(eligible)
	if share > 1 {
		share = 1
	}
	return kindWeight(kind) * math.Sqrt(share)
}

// scoreFindings scores the vault and fills each finding's impact: the points
// it gives back once fixed.
func scoreFindings(findings []Finding, eligible map[string]int) int {
	load := map[string]float64{}
	for _, f := range findings {
		if f.Dismissed != nil || f.Kind == "setup" {
			continue
		}
		load[f.Kind] += severityWeight[f.Severity]
	}
	total := 0.0
	for kind, l := range load {
		total += categoryPenalty(kind, l, eligible[kind])
	}
	for _, f := range findings {
		if f.Dismissed == nil && f.Kind == "setup" {
			total += f.penalty
		}
	}
	for i := range findings {
		f := &findings[i]
		var delta float64
		switch {
		case f.Kind == "setup":
			delta = f.penalty
		default:
			l := load[f.Kind]
			if f.Dismissed != nil {
				l += severityWeight[f.Severity]
			}
			delta = categoryPenalty(f.Kind, l, eligible[f.Kind]) - categoryPenalty(f.Kind, l-severityWeight[f.Severity], eligible[f.Kind])
		}
		if delta > 0.05 {
			f.Impact = int(math.Max(1, math.Round(delta)))
		}
	}
	score := int(math.Round(100 - total))
	if score < 0 {
		score = 0
	}
	if score > 100 {
		score = 100
	}
	return score
}

// RecordWatchtowerHistory keeps one score per day, the last 180 days. It
// reports whether the vault changed.
func RecordWatchtowerHistory(v *Vault, score int) bool {
	if v.IsNewerFormat() {
		return false
	}
	now := watchNow()
	w := v.watchtower()
	day := time.Date(now.Year(), now.Month(), now.Day(), 0, 0, 0, 0, now.Location())
	if n := len(w.History); n > 0 {
		last := w.History[n-1].T.In(now.Location())
		if last.Year() == day.Year() && last.YearDay() == day.YearDay() {
			if w.History[n-1].Score == score {
				return false
			}
			w.History[n-1].Score = score
			return true
		}
	}
	w.History = append(w.History, ScorePoint{T: day, Score: score})
	if len(w.History) > 180 {
		w.History = w.History[len(w.History)-180:]
	}
	return true
}

// ErrFindingID is returned for a malformed finding id.
var ErrFindingID = errors.New("that isn't a Watchtower finding id")

// DismissFinding hides a finding from the score. days 0 keeps it dismissed
// until it is restored.
func DismissFinding(v *Vault, id, reason string, days int) error {
	id = strings.TrimSpace(id)
	if id == "" || !strings.Contains(id, ":") {
		return ErrFindingID
	}
	now := watchNow()
	w := v.watchtower()
	if w.Dismissed == nil {
		w.Dismissed = map[string]FindingDismissal{}
	}
	d := FindingDismissal{Reason: strings.TrimSpace(reason), At: now}
	if days > 0 {
		d.Until = now.AddDate(0, 0, days)
	}
	w.Dismissed[id] = d
	PruneDismissals(v)
	return nil
}

// RestoreFinding undoes a dismissal. It reports whether there was one.
func RestoreFinding(v *Vault, id string) bool {
	if v.Watchtower == nil || v.Watchtower.Dismissed == nil {
		return false
	}
	if _, ok := v.Watchtower.Dismissed[id]; !ok {
		return false
	}
	delete(v.Watchtower.Dismissed, id)
	return true
}

// PruneDismissals drops expired dismissals.
func PruneDismissals(v *Vault) {
	if v.Watchtower == nil {
		return
	}
	now := watchNow()
	for id, d := range v.Watchtower.Dismissed {
		if !d.Until.IsZero() && now.After(d.Until) {
			delete(v.Watchtower.Dismissed, id)
		}
	}
}

// ItemTrust is one item's trust score, as the full scan works it out, so
// its open findings count too.
func ItemTrust(v *Vault, ref VaultItemRef) TrustScore {
	for _, t := range ScanWatchtower(v, WatchtowerOptions{}).Trust {
		if t.ItemID == ref.ID {
			return t
		}
	}
	it := &wtItem{ref: ref, title: ref.Title, tel: v.ItemTelemetry(ref)}
	return trustFor(it, watchNow(), nil)
}

func trustLevel(score int) string {
	switch {
	case score >= 80:
		return "low"
	case score >= 55:
		return "medium"
	case score >= 35:
		return "high"
	}
	return "critical"
}

// trustFindingDelta is what an item's open finding takes off its trust, by
// severity. One critical finding alone leaves 30 (critical risk) and one
// high finding 50 (high risk).
var trustFindingDelta = map[string]int{SeverityCritical: -70, SeverityHigh: -50, SeverityMedium: -25, SeverityLow: -10}

// trustFor scores how much an item can be trusted, from its open Watchtower
// findings and its telemetry. Each finding kind adds one reason, from its
// most severe finding; dismissed findings don't count. Items with neither
// start at 100.
func trustFor(it *wtItem, now time.Time, open []Finding) TrustScore {
	t := it.tel
	ts := TrustScore{ItemID: it.ref.ID, ItemType: it.ref.Spec.ID, ItemTitle: it.title, Space: it.ref.Space, Reasons: []TrustReason{}}

	top := map[string]Finding{}
	for _, f := range open {
		if cur, ok := top[f.Kind]; !ok || severityRank[f.Severity] > severityRank[cur.Severity] {
			top[f.Kind] = f
		}
	}

	var tel []TrustReason
	add := func(text string, delta int) {
		tel = append(tel, TrustReason{Text: text, Delta: delta})
	}
	// An open exposed finding says the same thing more strongly.
	if _, ok := top["exposed"]; t.Exposed && !ok {
		add("Marked as exposed", -45)
	}
	since := t.LastRotation
	if since.IsZero() {
		since = t.CreatedAt
	}
	if !since.IsZero() {
		days := now.Sub(since).Hours() / 24
		switch {
		case days > 365:
			add("Not rotated in over a year", -35)
		case days > 180:
			add("Not rotated in 6 months", -20)
		case days > 90:
			add("Not rotated in 90 days", -10)
		}
		if days > 90 {
			// The age is already counted; an "old" finding says it again.
			delete(top, "old")
		}
	}
	switch {
	case t.AccessCount > 200:
		add(itoa(t.AccessCount)+" uses", -20)
	case t.AccessCount > 75:
		add(itoa(t.AccessCount)+" uses", -10)
	}
	switch strings.ToLower(t.Privilege) {
	case "critical", "root", "admin":
		add("Privilege: "+strings.ToLower(t.Privilege), -15)
	case "elevated":
		add("Privilege: elevated", -8)
	}

	for _, k := range WatchtowerKinds {
		if f, ok := top[k.Kind]; ok {
			ts.Reasons = append(ts.Reasons, TrustReason{Text: f.Title, Delta: trustFindingDelta[f.Severity]})
		}
	}
	sort.SliceStable(ts.Reasons, func(i, j int) bool { return ts.Reasons[i].Delta < ts.Reasons[j].Delta })
	ts.Reasons = append(ts.Reasons, tel...)

	score := 100
	for _, r := range ts.Reasons {
		score += r.Delta
	}
	if score < 0 {
		score = 0
	}
	ts.Score = score
	ts.Level = trustLevel(score)
	return ts
}

func shortHash(s string) string {
	sum := sha256.Sum256([]byte(s))
	return hex.EncodeToString(sum[:])[:8]
}
