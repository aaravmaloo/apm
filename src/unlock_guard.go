package apm

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

// The unlock guard slows down password guessing. It is shared by pm, the
// desktop app, the browser extension and MCP through one state file next to
// the vault. Wrong passwords never lock the vault for good: they only add a
// wait before the next try, and the right password always opens the real vault.

// Unlock sources recorded with each failure.
const (
	UnlockSourceCLI       = "cli"
	UnlockSourceDesktop   = "desktop"
	UnlockSourceMCP       = "mcp"
	UnlockSourceExtension = "extension"
)

// maxGuardAttempts bounds how many failures are kept in detail.
const maxGuardAttempts = 50

// alertQuietPeriod is how long failures must stop before the next one sends
// another alert email.
const alertQuietPeriod = 15 * time.Minute

// guardNow is the clock used by the guard. Tests replace it.
var guardNow = time.Now

// guardAlert sends the failed-unlock email. Tests replace it.
var guardAlert = SendAlert

type UnlockFailure struct {
	At     time.Time `json:"at"`
	Source string    `json:"source"`
}

// UnlockGuardState is what the guard keeps on disk. Epoch is random and set
// when the file is first written, Total counts every failure ever seen on this
// machine. Both let the vault notice when the file was deleted or rolled back.
type UnlockGuardState struct {
	Failures    int             `json:"failures"`
	Attempts    []UnlockFailure `json:"attempts,omitempty"`
	NextAllowed time.Time       `json:"next_allowed,omitzero"`
	LastFailure time.Time       `json:"last_failure,omitzero"`
	LastSuccess time.Time       `json:"last_success,omitzero"`
	Epoch       string          `json:"epoch,omitempty"`
	Total       int             `json:"total,omitempty"`
}

// FailedSince summarizes the wrong passwords entered since the last unlock.
type FailedSince struct {
	Count   int       `json:"count"`
	Last    time.Time `json:"-"`
	Sources []string  `json:"sources"`
}

// MarshalJSON writes Last as milliseconds, like every other desktop time.
func (f FailedSince) MarshalJSON() ([]byte, error) {
	last := int64(0)
	if !f.Last.IsZero() {
		last = f.Last.UnixMilli()
	}
	return json.Marshal(struct {
		Count   int      `json:"count"`
		Last    int64    `json:"last"`
		Sources []string `json:"sources"`
	}{f.Count, last, f.Sources})
}

// ErrUnlockCooldown is returned while the guard asks to wait before the next try.
type ErrUnlockCooldown struct {
	Wait     time.Duration
	Failures int
}

func (e *ErrUnlockCooldown) Error() string {
	return "Too many wrong passwords. Try again in " + HumanWait(e.Wait) + "."
}

// WaitSeconds rounds the wait up to whole seconds.
func (e *ErrUnlockCooldown) WaitSeconds() int {
	return waitSeconds(e.Wait)
}

// ErrRecoveryRequired is returned when the vault asks for recovery after a
// number of wrong passwords (the opt-in lockout setting).
type ErrRecoveryRequired struct {
	Failures int
	After    int
}

func (e *ErrRecoveryRequired) Error() string {
	return fmt.Sprintf("%d wrong passwords. This vault now needs recovery to open.", e.Failures)
}

// ErrWrongPassword is a failed attempt as the guard recorded it.
type ErrWrongPassword struct {
	Failures int
	Wait     time.Duration
}

func (e *ErrWrongPassword) Error() string {
	if e.Wait > 0 {
		return "Wrong password. Try again in " + HumanWait(e.Wait) + "."
	}
	return "Wrong password."
}

func (e *ErrWrongPassword) WaitSeconds() int {
	return waitSeconds(e.Wait)
}

func waitSeconds(d time.Duration) int {
	if d <= 0 {
		return 0
	}
	return int((d + time.Second - 1) / time.Second)
}

// UnlockBackoff is the wait after the given number of consecutive failures:
// the first three are free, then 30s, 1m, 5m, 15m and 60m from the eighth on.
func UnlockBackoff(failures int) time.Duration {
	switch {
	case failures <= 3:
		return 0
	case failures == 4:
		return 30 * time.Second
	case failures == 5:
		return time.Minute
	case failures == 6:
		return 5 * time.Minute
	case failures == 7:
		return 15 * time.Minute
	default:
		return time.Hour
	}
}

// HumanWait reads like "30 seconds", "1 minute" or "5 minutes".
func HumanWait(d time.Duration) string {
	secs := waitSeconds(d)
	switch {
	case secs < 60:
		if secs == 1 {
			return "1 second"
		}
		return fmt.Sprintf("%d seconds", secs)
	default:
		mins := (secs + 59) / 60
		if mins == 1 {
			return "1 minute"
		}
		return fmt.Sprintf("%d minutes", mins)
	}
}

func guardFile() string {
	return failureFiles()[0]
}

// stateVaultPath is the vault the CLI was pointed at (default, APM_VAULT_PATH
// or --vault). The guard lives next to it, where pm desktop keeps it, so both
// read the same file wherever the vault is.
var stateVaultPath string

// SetStateVaultPath tells the guard which vault pm is working on.
func SetStateVaultPath(path string) {
	stateVaultPath = strings.TrimSpace(path)
}

// apmStateDir holds the unlock guard and the device id, next to the vault like
// pm desktop keeps them, so the app and the CLI share one guard. It used to be
// the binary's folder, but pm often lives in an admin-owned one such as
// /usr/local/bin, where a counter it can't save never slows anyone down.
func apmStateDir() string {
	if d := strings.TrimSpace(os.Getenv("APM_STATE_DIR")); d != "" {
		return d
	}
	if stateVaultPath != "" && filepath.IsAbs(stateVaultPath) {
		return filepath.Dir(stateVaultPath)
	}
	if v := strings.TrimSpace(os.Getenv("APM_VAULT_PATH")); v != "" && filepath.IsAbs(v) {
		return filepath.Dir(v)
	}
	if home, err := os.UserHomeDir(); err == nil {
		return filepath.Join(home, ".apm")
	}
	return legacyStateDir()
}

// legacyStateDir is where pm 11 and older kept its state: next to the binary.
func legacyStateDir() string {
	exe, _ := os.Executable()
	return filepath.Dir(exe)
}

func failureFiles() []string {
	files := []string{filepath.Join(apmStateDir(), ".apm_lock")}
	if strings.TrimSpace(os.Getenv("APM_STATE_DIR")) == "" {
		if old := filepath.Join(legacyStateDir(), ".apm_lock"); old != files[0] {
			files = append(files, old)
		}
	}
	return files
}

// readGuardFile reads either the JSON state or the plain failure count older
// pm versions wrote. ok is false when the file does not exist.
func readGuardFile(path string) (UnlockGuardState, bool) {
	data, err := os.ReadFile(path)
	if err != nil {
		return UnlockGuardState{}, false
	}
	trimmed := strings.TrimSpace(string(data))
	var st UnlockGuardState
	if strings.HasPrefix(trimmed, "{") && json.Unmarshal(data, &st) == nil {
		return st, true
	}
	n, _ := strconv.Atoi(trimmed)
	if n < 0 {
		n = 0
	}
	st = UnlockGuardState{Failures: n, Total: n}
	if n > 0 {
		if info, err := os.Stat(path); err == nil {
			st.LastFailure = info.ModTime()
			st.NextAllowed = info.ModTime().Add(UnlockBackoff(n))
		}
	}
	return st, true
}

// LoadUnlockGuard reads the guard state. A plain count left by an older pm,
// here or next to the binary, is carried over so updating doesn't hand out a
// fresh set of attempts.
func LoadUnlockGuard() UnlockGuardState {
	files := failureFiles()
	st, _ := readGuardFile(files[0])
	for _, path := range files[1:] {
		old, ok := readGuardFile(path)
		if !ok {
			continue
		}
		if old.Failures > st.Failures {
			st.Failures = old.Failures
			st.Total += old.Failures
			if old.NextAllowed.After(st.NextAllowed) {
				st.NextAllowed = old.NextAllowed
			}
			if old.LastFailure.After(st.LastFailure) {
				st.LastFailure = old.LastFailure
			}
		}
	}
	return st
}

func saveUnlockGuard(st UnlockGuardState) error {
	files := failureFiles()
	if st.Epoch == "" {
		b := make([]byte, 8)
		_, _ = rand.Read(b)
		st.Epoch = hex.EncodeToString(b)
	}
	data, err := json.MarshalIndent(st, "", "  ")
	if err != nil {
		return err
	}
	if err := os.MkdirAll(filepath.Dir(files[0]), 0700); err != nil {
		return err
	}
	if err := os.WriteFile(files[0], data, 0600); err != nil {
		return err
	}
	// The count next to the binary has been folded in above.
	for _, path := range files[1:] {
		os.Remove(path)
	}
	return nil
}

// CheckUnlockAllowed returns nil when a password may be tried now. It returns
// *ErrUnlockCooldown while a wait is running and *ErrRecoveryRequired when the
// vault's opt-in lockout has been reached. vaultData may be nil.
func CheckUnlockAllowed(vaultData []byte) error {
	st := LoadUnlockGuard()
	if after := ReadVaultLockoutAfter(vaultData); after > 0 && st.Failures >= after {
		return &ErrRecoveryRequired{Failures: st.Failures, After: after}
	}
	if wait := st.NextAllowed.Sub(guardNow()); wait > 0 {
		return &ErrUnlockCooldown{Wait: wait, Failures: st.Failures}
	}
	return nil
}

// UnlockWait is the time left before the next try and the failures so far.
func UnlockWait() (time.Duration, int) {
	st := LoadUnlockGuard()
	wait := st.NextAllowed.Sub(guardNow())
	if wait < 0 {
		wait = 0
	}
	return wait, st.Failures
}

// RecordUnlockFailure counts a wrong password from source and returns the
// error to show. The alert email goes out for the first failure after a quiet
// period, so a burst of guesses sends one email.
func RecordUnlockFailure(source string, vaultData []byte) error {
	now := guardNow()
	st := LoadUnlockGuard()
	quiet := st.LastFailure.IsZero() || now.Sub(st.LastFailure) >= alertQuietPeriod
	st.Failures++
	st.Total++
	st.Attempts = append(st.Attempts, UnlockFailure{At: now, Source: source})
	if len(st.Attempts) > maxGuardAttempts {
		st.Attempts = st.Attempts[len(st.Attempts)-maxGuardAttempts:]
	}
	st.LastFailure = now
	wait := UnlockBackoff(st.Failures)
	st.NextAllowed = now.Add(wait)
	_ = saveUnlockGuard(st)

	if quiet && vaultData != nil {
		if rec, ok := ParseVaultHeaderRecovery(vaultData); ok && rec.AlertsEnabled && rec.AlertEmail != "" {
			guardAlert(&Vault{AlertEmail: rec.AlertEmail, AlertsEnabled: true, SecurityLevel: rec.SecurityLevel}, LevelCritical, "FAILED UNLOCK",
				fmt.Sprintf("A wrong master password was entered (%s). Further failed attempts in the next %d minutes will not send another email.", source, int(alertQuietPeriod/time.Minute)))
		}
	}

	if after := ReadVaultLockoutAfter(vaultData); after > 0 && st.Failures >= after {
		return &ErrRecoveryRequired{Failures: st.Failures, After: after}
	}
	return &ErrWrongPassword{Failures: st.Failures, Wait: wait}
}

// RecordUnlockSuccess clears the failures and returns what happened since the
// last unlock, or nil when nothing did.
func RecordUnlockSuccess() *FailedSince {
	st := LoadUnlockGuard()
	var out *FailedSince
	if st.Failures > 0 {
		out = &FailedSince{Count: st.Failures, Last: st.LastFailure, Sources: []string{}}
		seen := map[string]bool{}
		for _, a := range st.Attempts {
			if a.Source != "" && !seen[a.Source] {
				seen[a.Source] = true
				out.Sources = append(out.Sources, a.Source)
			}
		}
	}
	st.Failures = 0
	st.Attempts = nil
	st.NextAllowed = time.Time{}
	st.LastSuccess = guardNow()
	_ = saveUnlockGuard(st)
	return out
}

// GuardMark identifies the guard file as the vault last saw it on a device.
func GuardMark() (epoch string, total int) {
	st := LoadUnlockGuard()
	return st.Epoch, st.Total
}

// IsUnlockGuardError reports whether err came from the guard rather than from
// opening the vault.
func IsUnlockGuardError(err error) bool {
	var c *ErrUnlockCooldown
	var r *ErrRecoveryRequired
	var w *ErrWrongPassword
	return errors.As(err, &c) || errors.As(err, &r) || errors.As(err, &w)
}

// ReadVaultLockoutAfter reads the opt-in "require recovery after N wrong
// passwords" setting from the vault's plaintext header. 0 means off.
func ReadVaultLockoutAfter(data []byte) int {
	if len(data) == 0 {
		return 0
	}
	rec, ok := ParseVaultHeaderRecovery(data)
	if !ok || rec.LockoutAfter < 0 {
		return 0
	}
	return rec.LockoutAfter
}

// MinLockoutAfter keeps the lockout from tripping on a couple of typos.
const MinLockoutAfter = 5

// ValidateLockoutAfter checks a lockout setting: 0 (off) or at least 5.
func ValidateLockoutAfter(n int) error {
	if n == 0 || (n >= MinLockoutAfter && n <= 100) {
		return nil
	}
	return fmt.Errorf("the lockout must be off (0) or between %d and 100 wrong passwords", MinLockoutAfter)
}

// LockoutRecoveryReady reports whether the vault can still be opened once the
// lockout trips. Only the recovery key opens it without the master password:
// pm auth recover and the app's recovery need the recovery email and the key,
// and trustee recovery rebuilds the key from shares. Recovery codes and a
// recovery passkey are extra checks before the key is used and open nothing
// on their own. pm and the app only let the lockout be turned on when this is
// true.
func LockoutRecoveryReady(v *Vault) bool {
	if v == nil || len(v.RecoveryHash) == 0 || len(v.RecoverySlot) == 0 {
		return false
	}
	quorum := v.RecoveryShareThreshold >= 2 && len(v.RecoveryShareHashes) > 0
	return v.RecoveryEmail != "" || quorum
}
