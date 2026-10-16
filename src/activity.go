package apm

import (
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"regexp"
	"sort"
	"strings"
	"time"
)

// Activity is the vault's record of unusual events: wrong passwords, unlocks
// from new devices or at unusual hours, bulk reveals, exports, assistants
// reaching for privileged secrets, a tampered audit log and risky settings.
// Events are derived from the unlock guard, the vault's own history and the
// signed audit log, and kept inside the encrypted vault with the user's
// acknowledgements.

// Activity kinds, as the desktop app and `pm watchtower activity` show them.
const (
	ActivityFailedUnlocks        = "failed_unlocks"
	ActivitySuccessAfterFailures = "success_after_failures"
	ActivityUnusualHour          = "unusual_hour"
	ActivityNewDevice            = "new_device"
	ActivityBulkReveal           = "bulk_reveal"
	ActivityExport               = "export"
	ActivityAIFirstPrivileged    = "ai_first_privileged"
	ActivityAIDenied             = "ai_denied"
	ActivityAIBurst              = "ai_burst"
	ActivityLogTampered          = "log_tampered"
	ActivityModifiedExternally   = "vault_modified_externally"
	ActivityCounterReset         = "counter_reset"
	ActivityClockRollback        = "clock_rollback"
	ActivityRiskySetting         = "risky_setting"
)

const (
	maxActivityEvents = 500
	// The hour baseline needs this much history before it flags anything.
	baselineMinDays    = 14
	baselineMinUnlocks = 20
	bulkRevealWindow   = 2 * time.Minute
	bulkRevealCount    = 10
	aiBurstWindow      = 5 * time.Minute
	aiBurstCount       = 15
	clockRollbackSlack = 10 * time.Minute
	// A first scan looks back this far instead of replaying the whole log.
	activityLookback = 24 * time.Hour
)

// watchNow is the clock Watchtower and activity use. Tests replace it.
var watchNow = time.Now

// activityAlert sends the batched anomaly email. Tests replace it.
var activityAlert = SendAlert

// activityAuditLogs reads the audit log for activity scans. Tests replace it.
var activityAuditLogs = func() []AuditEntry {
	logs, _ := GetAuditLogs(0)
	return logs
}

// auditKey is the audit log's signing key. Tests replace it.
var auditKey = getAuditSigningKey

type ActivityEvent struct {
	ID           string    `json:"id"`
	Kind         string    `json:"kind"`
	Severity     string    `json:"severity"`
	Title        string    `json:"title"`
	Body         string    `json:"body,omitempty"`
	At           time.Time `json:"at"`
	Source       string    `json:"source"`
	Actor        string    `json:"actor,omitempty"`
	Acknowledged bool      `json:"acknowledged,omitempty"`
	AckAt        time.Time `json:"ack_at,omitzero"`
}

// View is the event as the desktop app and --json read it.
func (e ActivityEvent) View() map[string]any {
	return map[string]any{
		"id":           e.ID,
		"kind":         e.Kind,
		"severity":     e.Severity,
		"title":        e.Title,
		"body":         e.Body,
		"at":           e.At.UnixMilli(),
		"source":       e.Source,
		"actor":        e.Actor,
		"acknowledged": e.Acknowledged,
	}
}

type KnownDevice struct {
	ID        string    `json:"id"`
	Label     string    `json:"label,omitempty"`
	FirstSeen time.Time `json:"first_seen"`
	LastSeen  time.Time `json:"last_seen"`
}

type guardMarkState struct {
	Epoch string `json:"epoch"`
	Total int    `json:"total"`
}

// settingsFingerprint is what the vault last saw of its security settings,
// so a change that weakens them shows up as activity.
type settingsFingerprint struct {
	Alerts   bool   `json:"alerts"`
	Profile  int    `json:"profile"`
	Policy   string `json:"policy,omitempty"`
	Recovery string `json:"recovery,omitempty"`
	TouchID  bool   `json:"touch_id"`
	Known    bool   `json:"known_touch_id,omitempty"`
}

// WatchtowerState is everything Watchtower and activity keep in the vault.
type WatchtowerState struct {
	Dismissed     map[string]FindingDismissal `json:"dismissed,omitempty"`
	History       []ScorePoint                `json:"history,omitempty"`
	Breach        BreachState                 `json:"breach,omitzero"`
	Events        []ActivityEvent             `json:"events,omitempty"`
	Devices       []KnownDevice               `json:"devices,omitempty"`
	Hours         []int                       `json:"hours,omitempty"`
	BaselineSince time.Time                   `json:"baseline_since,omitzero"`
	BaselineCount int                         `json:"baseline_count,omitempty"`
	AuditCursors  map[string]int64            `json:"audit_cursors,omitempty"`
	HistoryCursor time.Time                   `json:"history_cursor,omitzero"`
	GuardMarks    map[string]guardMarkState   `json:"guard_marks,omitempty"`
	LatestSeen    time.Time                   `json:"latest_seen,omitzero"`
	Settings      *settingsFingerprint        `json:"settings,omitempty"`
	AIReads       map[string]time.Time        `json:"ai_reads,omitempty"`
	TamperMark    string                      `json:"tamper_mark,omitempty"`
}

func (v *Vault) watchtower() *WatchtowerState {
	if v.Watchtower == nil {
		v.Watchtower = &WatchtowerState{}
	}
	w := v.Watchtower
	if len(w.Hours) != 24 {
		hours := make([]int, 24)
		copy(hours, w.Hours)
		w.Hours = hours
	}
	return w
}

func newEventID() string {
	b := make([]byte, 8)
	_, _ = rand.Read(b)
	return "evt_" + hex.EncodeToString(b)
}

func (w *WatchtowerState) add(events ...ActivityEvent) {
	w.Events = append(w.Events, events...)
	sort.SliceStable(w.Events, func(i, j int) bool { return w.Events[i].At.Before(w.Events[j].At) })
	if len(w.Events) > maxActivityEvents {
		w.Events = w.Events[len(w.Events)-maxActivityEvents:]
	}
}

func event(kind, severity, title, body string, at time.Time, source, actor string) ActivityEvent {
	if source == "" {
		source = "system"
	}
	return ActivityEvent{ID: newEventID(), Kind: kind, Severity: severity, Title: title, Body: body, At: at, Source: source, Actor: actor}
}

// UnlockActivity describes a successful unlock.
type UnlockActivity struct {
	Source      string
	Via         string
	FailedSince *FailedSince
	// TouchID is whether Touch ID is set up for APM, when the caller knows.
	TouchID *bool
}

// RecordUnlockActivity records what a successful unlock reveals: wrong
// passwords before it, a new device, an unusual hour, a reset failure
// counter. It also runs the activity scan. It returns the new events.
func RecordUnlockActivity(v *Vault, u UnlockActivity) []ActivityEvent {
	if v == nil || v.IsNewerFormat() {
		return nil
	}
	now := watchNow()
	w := v.watchtower()
	dev := CurrentDevice()
	var out []ActivityEvent

	if f := u.FailedSince; f != nil && f.Count > 0 {
		sev := "low"
		switch {
		case f.Count >= 8:
			sev = "high"
		case f.Count >= 4:
			sev = "medium"
		}
		out = append(out, event(ActivityFailedUnlocks, sev,
			fmt.Sprintf("%d wrong %s before this unlock", f.Count, wordFor(f.Count, "password", "passwords")),
			"Last attempt "+HumanWhen(f.Last, now)+" from "+sourceList(f.Sources)+".", f.Last, firstSource(f.Sources), ""))
		if f.Count >= 4 {
			out = append(out, event(ActivitySuccessAfterFailures, "high",
				fmt.Sprintf("Unlocked after %d wrong passwords", f.Count),
				"If this wasn't you guessing, someone may know or be close to your master password. Change it.", now, u.Source, "User"))
		}
	}

	if epoch, total := GuardMark(); epoch != "" {
		if w.GuardMarks == nil {
			w.GuardMarks = map[string]guardMarkState{}
		}
		if mark, ok := w.GuardMarks[dev.ID]; ok && (mark.Epoch != epoch || total < mark.Total) {
			out = append(out, event(ActivityCounterReset, "high", "Wrong-password counter was reset",
				"The file that counts wrong passwords on this device was deleted or rolled back without an unlock. Someone may have tried to get more guesses.", now, "system", ""))
		}
		w.GuardMarks[dev.ID] = guardMarkState{Epoch: epoch, Total: total}
	}

	known := false
	for i := range w.Devices {
		if w.Devices[i].ID == dev.ID {
			w.Devices[i].LastSeen = now
			if dev.Label != "" {
				w.Devices[i].Label = dev.Label
			}
			known = true
		}
	}
	if !known {
		if len(w.Devices) > 0 {
			out = append(out, event(ActivityNewDevice, "high", "Unlocked on a new device",
				dev.Label+" opened this vault for the first time.", now, u.Source, "User"))
		}
		w.Devices = append(w.Devices, KnownDevice{ID: dev.ID, Label: dev.Label, FirstSeen: now, LastSeen: now})
	}

	if w.BaselineSince.IsZero() {
		w.BaselineSince = now
	}
	hour := now.Local().Hour()
	if baselineReady(w, now) && unusualHour(w, hour) {
		out = append(out, event(ActivityUnusualHour, "medium", "Unlocked at an unusual time",
			fmt.Sprintf("You don't usually unlock around %02d:00. Mark it as you to teach APM this hour.", hour), now, u.Source, "User"))
	} else {
		w.Hours[hour]++
		w.BaselineCount++
	}

	w.add(out...)
	out = append(out, scanActivity(v, u.TouchID, now)...)
	alertActivity(v, out)
	return out
}

func baselineReady(w *WatchtowerState, now time.Time) bool {
	return w.BaselineCount >= baselineMinUnlocks && now.Sub(w.BaselineSince) >= baselineMinDays*24*time.Hour
}

// unusualHour flags an hour when it and its neighbours hold under 2% of the
// unlocks seen so far.
func unusualHour(w *WatchtowerState, hour int) bool {
	window := w.Hours[(hour+23)%24] + w.Hours[hour] + w.Hours[(hour+1)%24]
	return window*50 < w.BaselineCount
}

// ScanActivity reads the audit log and vault history since the last scan and
// records new events. touchID may be nil when the caller doesn't know.
func ScanActivity(v *Vault, touchID *bool) []ActivityEvent {
	if v == nil || v.IsNewerFormat() {
		return nil
	}
	out := scanActivity(v, touchID, watchNow())
	alertActivity(v, out)
	return out
}

func scanActivity(v *Vault, touchID *bool, now time.Time) []ActivityEvent {
	w := v.watchtower()
	var out []ActivityEvent

	if !w.LatestSeen.IsZero() && now.Before(w.LatestSeen.Add(-clockRollbackSlack)) {
		out = append(out, event(ActivityClockRollback, "medium", "System clock moved back",
			"This device's clock is behind the last time APM saw ("+w.LatestSeen.Local().Format("Jan 2 15:04")+"). Time-based checks may be off.", now, "system", ""))
	}
	if now.After(w.LatestSeen) {
		w.LatestSeen = now
	}

	out = append(out, scanHistory(v, w, now)...)
	out = append(out, scanAudit(v, w, now)...)
	out = append(out, checkSettings(v, w, touchID, now)...)
	w.add(out...)
	return out
}

// scanHistory looks for bulk reveals in the vault's own signed history.
func scanHistory(v *Vault, w *WatchtowerState, now time.Time) []ActivityEvent {
	since := w.HistoryCursor
	if since.IsZero() {
		since = now.Add(-activityLookback)
	}
	var reveals []reveal
	latest := since
	for _, h := range v.History {
		if !h.Timestamp.After(since) {
			continue
		}
		if h.Timestamp.After(latest) {
			latest = h.Timestamp
		}
		if h.Action == "GET" || h.Action == "VIEW" {
			reveals = append(reveals, reveal{at: h.Timestamp, key: h.Category + "|" + h.Identifier})
		}
	}
	w.HistoryCursor = latest
	return bulkReveals(reveals, "User", "system")
}

type reveal struct {
	at  time.Time
	key string
}

// bulkReveals finds windows where many distinct secrets were revealed.
func bulkReveals(list []reveal, actor, source string) []ActivityEvent {
	sort.Slice(list, func(i, j int) bool { return list[i].at.Before(list[j].at) })
	var out []ActivityEvent
	for i := 0; i < len(list); {
		distinct := map[string]bool{}
		j := i
		for j < len(list) && list[j].at.Sub(list[i].at) <= bulkRevealWindow {
			distinct[list[j].key] = true
			j++
		}
		if len(distinct) >= bulkRevealCount {
			out = append(out, event(ActivityBulkReveal, "high",
				fmt.Sprintf("%d secrets revealed in %d minutes", len(distinct), int(bulkRevealWindow/time.Minute)),
				"Many different secrets were opened or copied in a short time.", list[j-1].at, source, actor))
			i = j
			continue
		}
		i++
	}
	return out
}

var mcpAccessedRe = regexp.MustCompile(`^Token '(.*)' accessed entry '(.*)' \((.*)\)$`)
var assistantInDetails = regexp.MustCompile(`[Aa]ssistant '([^']*)'`)

func scanAudit(v *Vault, w *WatchtowerState, now time.Time) []ActivityEvent {
	logs := activityAuditLogs()
	var out []ActivityEvent
	if ev := checkAuditIntegrity(w, logs, now); ev != nil {
		out = append(out, *ev)
	}

	dev := CurrentDevice().ID
	if w.AuditCursors == nil {
		w.AuditCursors = map[string]int64{}
	}
	cursor := w.AuditCursors[dev]
	if cursor == 0 {
		cursor = now.Add(-activityLookback).UnixNano()
	}
	latest := cursor

	type aiRead struct {
		at    time.Time
		title string
	}
	reads := map[string][]aiRead{}
	denied := map[string][]AuditEntry{}
	var copies []reveal
	for _, e := range logs {
		ts := e.Timestamp.UnixNano()
		if ts <= cursor {
			continue
		}
		if ts > latest {
			latest = ts
		}
		switch e.Action {
		case "DATA_EXPORTED":
			sev, title := "medium", "Vault exported"
			if strings.Contains(e.Details, "Encrypted: false") {
				sev, title = "high", "Vault exported without encryption"
			}
			out = append(out, event(ActivityExport, sev, title, e.Details, e.Timestamp, "system", "User"))
		case "MCP_ENTRY_ACCESSED":
			if m := mcpAccessedRe.FindStringSubmatch(e.Details); m != nil {
				reads[m[1]] = append(reads[m[1]], aiRead{at: e.Timestamp, title: m[2]})
			}
		case "MCP_AUTH_FAILED", "MCP_ASSISTANT_BLOCKED", "MCP_ASSISTANT_DENIED", "MCP_SCOPE_DENIED":
			who := "An assistant"
			if m := assistantInDetails.FindStringSubmatch(e.Details); m != nil && m[1] != "" {
				who = m[1]
			}
			denied[who] = append(denied[who], e)
		case "TOTP_COPIED":
			copies = append(copies, reveal{at: e.Timestamp, key: "TOTP|" + e.Details})
		}
	}
	w.AuditCursors[dev] = latest

	out = append(out, bulkReveals(copies, "User", "cli")...)

	names := make([]string, 0, len(denied))
	for who := range denied {
		names = append(names, who)
	}
	sort.Strings(names)
	for _, who := range names {
		list := denied[who]
		sev := "low"
		for _, e := range list {
			if e.Action == "MCP_AUTH_FAILED" {
				sev = "medium"
			}
		}
		last := list[len(list)-1]
		title := who + " was refused"
		if len(list) > 1 {
			title = fmt.Sprintf("%s was refused %d times", who, len(list))
		}
		out = append(out, event(ActivityAIDenied, sev, title, last.Details, last.Timestamp, UnlockSourceMCP, who))
	}

	if w.AIReads == nil {
		w.AIReads = map[string]time.Time{}
	}
	refs := v.ItemRefs()
	who := make([]string, 0, len(reads))
	for name := range reads {
		who = append(who, name)
	}
	sort.Strings(who)
	for _, name := range who {
		list := reads[name]
		sort.Slice(list, func(i, j int) bool { return list[i].at.Before(list[j].at) })
		for i := 0; i < len(list); {
			j := i
			for j < len(list) && list[j].at.Sub(list[i].at) <= aiBurstWindow {
				j++
			}
			if j-i >= aiBurstCount {
				out = append(out, event(ActivityAIBurst, "high",
					fmt.Sprintf("%s read %d secrets in %d minutes", name, j-i, int(aiBurstWindow/time.Minute)),
					"An assistant read many secrets quickly. Pause MCP in Settings if you didn't ask for this.", list[j-1].at, UnlockSourceMCP, name))
				i = j
				continue
			}
			i++
		}
		for _, r := range list {
			for _, ref := range refs {
				if !strings.EqualFold(strings.TrimSpace(ref.Title), strings.TrimSpace(r.title)) || !privilegedTelemetry(v.ItemTelemetry(ref)) {
					continue
				}
				key := name + "|" + ref.ID
				if _, seen := w.AIReads[key]; seen {
					continue
				}
				w.AIReads[key] = r.at
				out = append(out, event(ActivityAIFirstPrivileged, "high",
					name+" read a privileged secret for the first time",
					fmt.Sprintf("%s is marked %s.", ref.Title, strings.ToLower(v.ItemTelemetry(ref).Privilege)), r.at, UnlockSourceMCP, name))
			}
		}
	}
	return out
}

func privilegedTelemetry(t SecretTelemetry) bool {
	switch strings.ToLower(strings.TrimSpace(t.Privilege)) {
	case "critical", "root", "admin":
		return true
	}
	return false
}

// AuditIntegrity checks the signed audit log. An entry counts as tampered
// when its hash or signature doesn't match, or when it doesn't follow any of
// the few entries before it (two processes logging at once may fork the chain
// by one or two entries, which is not tampering). It returns the index of the
// first bad entry, or -1.
func AuditIntegrity(logs []AuditEntry) int {
	if len(logs) == 0 {
		return -1
	}
	key, err := auditKey()
	if err != nil {
		return -1
	}
	for i, e := range logs {
		if e.Hash == "" && e.Signature == "" {
			continue
		}
		serialized := fmt.Sprintf("%d:%s:%s:%s:%s:%s", e.Timestamp.UnixNano(), e.Action, e.Details, e.User, e.Hostname, e.PrevHash)
		sum := sha256.Sum256([]byte(serialized))
		if !hmac.Equal([]byte(hex.EncodeToString(sum[:])), []byte(e.Hash)) {
			return i
		}
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(e.Hash))
		if !hmac.Equal([]byte(hex.EncodeToString(mac.Sum(nil))), []byte(e.Signature)) {
			return i
		}
		if e.PrevHash == "" || i == 0 {
			continue
		}
		linked := false
		for k := i - 1; k >= 0 && k >= i-5; k-- {
			if logs[k].Hash == e.PrevHash {
				linked = true
				break
			}
		}
		if !linked {
			return i
		}
	}
	return -1
}

func checkAuditIntegrity(w *WatchtowerState, logs []AuditEntry, now time.Time) *ActivityEvent {
	bad := AuditIntegrity(logs)
	if bad < 0 {
		w.TamperMark = ""
		return nil
	}
	mark := logs[bad].Hash
	if mark == w.TamperMark {
		return nil
	}
	w.TamperMark = mark
	ev := event(ActivityLogTampered, "critical", "Audit log was changed",
		fmt.Sprintf("Entry %d of the signed audit log (%s, %s) doesn't match its signature or chain. Entries may have been edited or removed.", bad+1, logs[bad].Action, logs[bad].Timestamp.Local().Format("Jan 2 15:04")), now, "system", "")
	return &ev
}

func profileRank(v *Vault) int {
	name := v.Profile
	if v.CurrentProfileParams != nil && v.CurrentProfileParams.Name != "" {
		name = v.CurrentProfileParams.Name
	}
	switch strings.ToLower(name) {
	case "legacy", "legacy_v1":
		return 0
	case "hardened":
		return 2
	case "paranoid":
		return 3
	}
	return 1
}

func recoveryFingerprint(v *Vault) string {
	h := sha256.New()
	fmt.Fprintf(h, "%x|%x|%t|%x|%d", v.RecoveryHash, sha256.Sum256([]byte(strings.ToLower(v.RecoveryEmail))), v.RecoveryPasskeyEnabled, v.RecoveryPasskeyCred, v.RecoveryShareThreshold)
	for _, c := range v.RecoveryCodeHashes {
		h.Write(c)
	}
	return hex.EncodeToString(h.Sum(nil))[:16]
}

// checkSettings compares the security settings with what the vault last saw
// and records changes that weaken them.
func checkSettings(v *Vault, w *WatchtowerState, touchID *bool, now time.Time) []ActivityEvent {
	cur := settingsFingerprint{
		Alerts:   v.AlertsEnabled,
		Profile:  profileRank(v),
		Policy:   v.ActivePolicy.Name,
		Recovery: recoveryFingerprint(v),
	}
	if touchID != nil {
		cur.TouchID, cur.Known = *touchID, true
	}
	prev := w.Settings
	if prev == nil {
		w.Settings = &cur
		return nil
	}
	var out []ActivityEvent
	risky := func(sev, title, body string) {
		out = append(out, event(ActivityRiskySetting, sev, title, body, now, "system", ""))
	}
	if prev.Alerts && !cur.Alerts {
		risky("medium", "Security alerts turned off", "APM no longer emails you about failed unlocks and unusual activity.")
	}
	if cur.Profile < prev.Profile {
		risky("medium", "Encryption profile weakened", "The vault now uses a weaker key derivation profile.")
	}
	if prev.Policy != "" && cur.Policy == "" {
		risky("medium", "Password policy removed", "The policy "+prev.Policy+" is no longer enforced.")
	}
	if prev.Recovery != cur.Recovery {
		risky("high", "Account recovery changed", "Recovery codes, the recovery key, passkey or email changed. Anyone who controls recovery can reset your master password.")
	}
	if cur.Known {
		if prev.Known && !prev.TouchID && cur.TouchID {
			risky("medium", "Touch ID turned on", "Fingerprints enrolled on this Mac can now unlock the vault.")
		}
	} else {
		cur.TouchID, cur.Known = prev.TouchID, prev.Known
	}
	w.Settings = &cur
	return out
}

// RecordExternalModification notes that the vault file changed without APM
// writing it, for example a sync tool or another program.
func RecordExternalModification(v *Vault, detail string) {
	if v == nil || v.IsNewerFormat() {
		return
	}
	now := watchNow()
	body := "The vault file changed on disk without any APM action logged."
	if detail != "" {
		body += " " + detail
	}
	ev := event(ActivityModifiedExternally, "medium", "Vault changed outside APM", body, now, "system", "")
	v.watchtower().add(ev)
	alertActivity(v, []ActivityEvent{ev})
}

// RecentAuditActivity reports whether APM logged anything in the window
// before t, which means a vault change was APM's own.
func RecentAuditActivity(t time.Time, window time.Duration) bool {
	logs, _ := GetAuditLogs(50)
	for i := len(logs) - 1; i >= 0; i-- {
		if logs[i].Timestamp.After(t.Add(-window)) {
			return true
		}
	}
	return false
}

func alertActivity(v *Vault, events []ActivityEvent) {
	if !v.AlertsEnabled || !v.AnomalyDetectionEnabled || v.AlertEmail == "" {
		return
	}
	var titles []string
	for _, e := range events {
		if e.Severity == "critical" || e.Severity == "high" {
			titles = append(titles, e.Title)
		}
	}
	if len(titles) == 0 {
		return
	}
	activityAlert(v, LevelCritical, "UNUSUAL ACTIVITY", strings.Join(titles, "; ")+". Review it in Watchtower.")
}

// ListActivity returns events newest first and how many are unacknowledged.
func ListActivity(v *Vault, limit int, includeAcknowledged bool) ([]ActivityEvent, int) {
	if v == nil || v.Watchtower == nil {
		return []ActivityEvent{}, 0
	}
	out := []ActivityEvent{}
	unack := 0
	events := v.Watchtower.Events
	for i := len(events) - 1; i >= 0; i-- {
		e := events[i]
		if !e.Acknowledged {
			unack++
		}
		if e.Acknowledged && !includeAcknowledged {
			continue
		}
		if limit > 0 && len(out) >= limit {
			continue
		}
		out = append(out, e)
	}
	return out, unack
}

// AckActivity marks an event as "This was me". For an unusual hour it also
// teaches the baseline that hour.
func AckActivity(v *Vault, id string) bool {
	if v == nil || v.Watchtower == nil {
		return false
	}
	w := v.watchtower()
	for i := range w.Events {
		e := &w.Events[i]
		if e.ID != id {
			continue
		}
		if !e.Acknowledged {
			e.Acknowledged = true
			e.AckAt = watchNow()
			if e.Kind == ActivityUnusualHour {
				w.Hours[e.At.Local().Hour()] += w.BaselineCount/50 + 1
				w.BaselineCount++
			}
		}
		return true
	}
	return false
}

// AckAllActivity acknowledges every event and returns how many changed.
func AckAllActivity(v *Vault) int {
	if v == nil || v.Watchtower == nil {
		return 0
	}
	n := 0
	for _, e := range v.Watchtower.Events {
		if !e.Acknowledged && AckActivity(v, e.ID) {
			n++
		}
	}
	return n
}

// HumanWhen reads like "today 14:02", "yesterday 09:15" or "Mar 4 22:40".
func HumanWhen(t, now time.Time) string {
	if t.IsZero() {
		return "at an unknown time"
	}
	t, now = t.Local(), now.Local()
	y1, m1, d1 := t.Date()
	y2, m2, d2 := now.Date()
	switch {
	case y1 == y2 && m1 == m2 && d1 == d2:
		return "today " + t.Format("15:04")
	case sameDay(t.AddDate(0, 0, 1), now):
		return "yesterday " + t.Format("15:04")
	case y1 == y2:
		return t.Format("Jan 2 15:04")
	}
	return t.Format("Jan 2 2006 15:04")
}

func sameDay(a, b time.Time) bool {
	y1, m1, d1 := a.Date()
	y2, m2, d2 := b.Date()
	return y1 == y2 && m1 == m2 && d1 == d2
}

var sourceNames = map[string]string{
	UnlockSourceCLI:       "the CLI",
	UnlockSourceDesktop:   "the desktop app",
	UnlockSourceExtension: "the browser extension",
	UnlockSourceMCP:       "an assistant",
}

func sourceList(sources []string) string {
	if len(sources) == 0 {
		return "an unknown source"
	}
	names := make([]string, 0, len(sources))
	for _, s := range sources {
		if n, ok := sourceNames[s]; ok {
			names = append(names, n)
		} else {
			names = append(names, s)
		}
	}
	if len(names) == 1 {
		return names[0]
	}
	return strings.Join(names[:len(names)-1], ", ") + " and " + names[len(names)-1]
}

func firstSource(sources []string) string {
	if len(sources) == 0 {
		return "system"
	}
	return sources[len(sources)-1]
}

func wordFor(n int, one, many string) string {
	if n == 1 {
		return one
	}
	return many
}
