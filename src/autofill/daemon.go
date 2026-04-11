package autofill

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"net/http"
	"os"
	"strconv"
	"strings"
	"sync"
	"time"

	src "github.com/aaravmaloo/apm/src"
)

type RunOptions struct {
	VaultPath  string
	Hotkey     string
	MailHotkey string
}

type Daemon struct {
	mu sync.Mutex

	vaultPath     string
	token         string
	startedAt     time.Time
	hotkeyRaw     string
	hotkey        Hotkey
	mailHotkeyRaw string
	mailHotkey    Hotkey

	locked            bool
	vault             *src.Vault
	unlockExpiresAt   time.Time
	inactivityTimeout time.Duration
	lastActivity      time.Time

	pendingCandidates []MatchCandidate
	recentNotices     map[string]time.Time
	mailCache         []MailOTPResult
	usedMailCodes     map[string]time.Time
	popupDisabled     bool

	listener net.Listener
	server   *http.Server
	stopCh   chan struct{}
	stopped  bool

	systemEngine SystemEngine
	notifier     PopupNotifier
}

func Run(opts RunOptions) error {
	if strings.TrimSpace(opts.VaultPath) == "" {
		return errors.New("vault path is required")
	}
	if _, err := os.Stat(opts.VaultPath); err != nil {
		return fmt.Errorf("vault path is invalid: %w", err)
	}
	if strings.TrimSpace(opts.Hotkey) == "" {
		opts.Hotkey = "CTRL+SHIFT+L"
	}
	if strings.TrimSpace(opts.MailHotkey) == "" {
		opts.MailHotkey = "CTRL+SHIFT+P"
	}

	hotkey, err := parseHotkey(opts.Hotkey)
	if err != nil {
		return err
	}
	mailHotkey, err := parseHotkey(opts.MailHotkey)
	if err != nil {
		return err
	}

	token, err := generateToken()
	if err != nil {
		return err
	}

	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		return err
	}

	addr := listener.Addr().String()
	// Publish the daemon endpoint through the state file before serving so CLI
	// clients can discover the port chosen by the loopback listener.
	state := daemonState{
		PID:       os.Getpid(),
		Addr:      "http://" + addr,
		Token:     token,
		StartedAt: time.Now().UTC(),
	}
	if err := saveDaemonState(state); err != nil {
		_ = listener.Close()
		return err
	}

	daemon := &Daemon{
		vaultPath:         opts.VaultPath,
		token:             token,
		startedAt:         state.StartedAt,
		hotkeyRaw:         opts.Hotkey,
		hotkey:            hotkey,
		mailHotkeyRaw:     opts.MailHotkey,
		mailHotkey:        mailHotkey,
		locked:            true,
		listener:          listener,
		stopCh:            make(chan struct{}),
		systemEngine:      newSystemEngine(),
		inactivityTimeout: 15 * time.Minute,
		notifier:          newPopupNotifier(),
		recentNotices:     make(map[string]time.Time),
		usedMailCodes:     make(map[string]time.Time),
	}
	if daemon.hotkeyRaw == "" {
		daemon.hotkeyRaw = "CTRL+SHIFT+L"
	}
	if daemon.mailHotkeyRaw == "" {
		daemon.mailHotkeyRaw = "CTRL+SHIFT+P"
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/v1/status", daemon.withAuth(daemon.handleStatus))
	mux.HandleFunc("/v1/stop", daemon.withAuth(daemon.handleStop))
	mux.HandleFunc("/v1/vault/unlock", daemon.withAuth(daemon.handleUnlock))
	mux.HandleFunc("/v1/vault/lock", daemon.withAuth(daemon.handleLock))
	mux.HandleFunc("/v1/autofill/profiles", daemon.withAuth(daemon.handleProfiles))
	mux.HandleFunc("/v1/autofill/request", daemon.withAuth(daemon.handleFillRequest))

	daemon.server = &http.Server{
		Handler:           mux,
		ReadHeaderTimeout: 5 * time.Second,
	}

	if err := daemon.systemEngine.Start(daemon.hotkey, daemon.handleHotkey, daemon.mailHotkey, daemon.handleMailHotkey); err != nil {
		// Keep the HTTP daemon alive even when native hotkey hooks are unavailable.
		daemon.systemEngine = newSystemEngine()
	}

	go daemon.watchLockState()
	go daemon.watchContextHints()

	err = daemon.server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	daemon.shutdownNow()
	return err
}

func (d *Daemon) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		// The daemon is loopback-only and bearer-token protected so a local browser
		// tab cannot drive autofill without the companion client state.
		if !isLoopbackRequest(r.RemoteAddr) {
			writeError(w, http.StatusForbidden, "ForbiddenError")
			return
		}

		auth := strings.TrimSpace(r.Header.Get("Authorization"))
		if !strings.HasPrefix(auth, "Bearer ") {
			writeError(w, http.StatusUnauthorized, "UnauthorizedError")
			return
		}
		token := strings.TrimSpace(strings.TrimPrefix(auth, "Bearer "))
		if !tokenMatches(token, d.token) {
			writeError(w, http.StatusUnauthorized, "UnauthorizedError")
			return
		}
		next(w, r)
	}
}

func (d *Daemon) handleStatus(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()

	profileCount := 0
	if !d.locked && d.vault != nil {
		if profiles, err := buildProfiles(d.vault); err == nil {
			profileCount = len(profiles)
		}
	}

	resp := DaemonStatus{
		PID:              os.Getpid(),
		StartedAt:        d.startedAt,
		Locked:           d.locked,
		Hotkey:           d.hotkeyRaw,
		MailHotkey:       d.mailHotkeyRaw,
		SystemEngine:     d.systemEngine.Name(),
		ProfileCount:     profileCount,
		PendingSelection: len(d.pendingCandidates),
	}
	writeJSON(w, http.StatusOK, resp)
}

func (d *Daemon) handleStop(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
		return
	}
	writeJSON(w, http.StatusOK, SimpleResponse{OK: true})
	go d.shutdownNow()
}

func (d *Daemon) handleUnlock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
		return
	}

	var req UnlockRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "InvalidRequestError")
		return
	}
	if strings.TrimSpace(req.MasterPassword) == "" {
		writeError(w, http.StatusBadRequest, "MasterPasswordRequiredError")
		return
	}

	if src.GetFailureCount() >= 9 {
		writeError(w, http.StatusLocked, "VaultPermanentlyLockedError")
		return
	}

	data, err := src.LoadVault(d.vaultPath)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "VaultLoadError")
		return
	}
	vault, err := src.DecryptVault(data, req.MasterPassword, 1)
	if err != nil {
		src.TrackFailure()
		writeError(w, http.StatusUnauthorized, "UnlockFailedError")
		return
	}

	src.ClearFailures()
	zeroString(&req.MasterPassword)

	timeoutSec := req.SessionTimeoutSec
	if timeoutSec <= 0 {
		timeoutSec = 3600
	}
	inactivitySec := req.InactivityTimeoutSec
	if inactivitySec <= 0 {
		inactivitySec = 900
	}

	now := time.Now().UTC()

	d.mu.Lock()
	// Unlock stores a live vault in memory only for the bounded daemon session;
	// file encryption stays unchanged on disk.
	d.vault = vault
	d.locked = false
	d.popupDisabled = vault.AutocompleteWindowDisabled
	d.unlockExpiresAt = now.Add(time.Duration(timeoutSec) * time.Second)
	d.inactivityTimeout = time.Duration(inactivitySec) * time.Second
	d.lastActivity = now
	d.pendingCandidates = nil
	d.mu.Unlock()

	writeJSON(w, http.StatusOK, SimpleResponse{OK: true})
}

func (d *Daemon) handleLock(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
		return
	}
	d.mu.Lock()
	d.lockVaultLocked()
	d.mu.Unlock()
	writeJSON(w, http.StatusOK, SimpleResponse{OK: true})
}

func (d *Daemon) handleProfiles(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodGet {
		writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
		return
	}

	d.mu.Lock()
	defer d.mu.Unlock()
	if d.locked || d.vault == nil {
		writeError(w, http.StatusLocked, ErrVaultLocked)
		return
	}

	profiles, err := buildProfiles(d.vault)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "ProfileLoadError")
		return
	}

	writeJSON(w, http.StatusOK, map[string]any{
		"profiles": profiles,
	})
}

func (d *Daemon) handleFillRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		writeError(w, http.StatusMethodNotAllowed, "MethodNotAllowed")
		return
	}

	var req FillRequest
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		writeError(w, http.StatusBadRequest, "InvalidRequestError")
		return
	}
	if !req.ExplicitAction {
		writeError(w, http.StatusForbidden, "ExplicitActionRequiredError")
		return
	}

	resp, statusCode := d.resolveFill(req)
	writeJSON(w, statusCode, resp)
}

func (d *Daemon) resolveFill(req FillRequest) (FillResponse, int) {
	d.mu.Lock()
	defer d.mu.Unlock()

	if req.MailOnly {
		return d.resolveMailFillLocked(req)
	}

	if d.locked || d.vault == nil {
		if !d.tryUnlockFromSessionLocked() {
			return FillResponse{
				Status: ResponseStatusOK,
				Error:  ErrVaultLocked,
			}, http.StatusLocked
		}
	}

	d.lastActivity = time.Now().UTC()

	profiles, err := buildProfiles(d.vault)
	if err != nil {
		return FillResponse{
			Status: ResponseStatusOK,
			Error:  "ProfileLoadError",
		}, http.StatusInternalServerError
	}

	matches := matchProfiles(profiles, req.Context)
	if len(matches) == 0 && strings.EqualFold(strings.TrimSpace(req.Context.Kind), ContextSystem) {
		// System contexts do not have DOM metadata, so fall back to the looser
		// heuristic matcher built for desktop apps and native dialogs.
		return d.resolveSystemIntelligentFillLocked(req)
	}
	if len(matches) == 0 {
		return FillResponse{
			Status: ResponseStatusOK,
			Error:  "NoMatchingProfileError",
		}, http.StatusNotFound
	}

	if req.SelectionID == "" && len(matches) > 1 {
		candidates := toCandidates(matches)
		// Persist the candidate list so the client can resolve an explicit second
		// step without recomputing on a different vault state.
		d.pendingCandidates = candidates
		return FillResponse{
			Status:     ResponseStatusMultiple,
			Candidates: candidates,
		}, http.StatusOK
	}

	selected, found := pickProfile(matches, req.SelectionID)
	if !found {
		return FillResponse{
			Status: ResponseStatusOK,
			Error:  "InvalidSelectionError",
		}, http.StatusBadRequest
	}

	cred, err := resolveCredential(d.vault, selected, req.IncludeTOTP)
	if err != nil {
		if errors.Is(err, ErrAmbiguousCredential) {
			return FillResponse{
				Status: ResponseStatusOK,
				Error:  "AmbiguousCredentialError",
			}, http.StatusConflict
		}
		if errors.Is(err, ErrAmbiguousTOTP) {
			return FillResponse{
				Status: ResponseStatusOK,
				Error:  "AmbiguousTOTPError",
			}, http.StatusConflict
		}
		return FillResponse{
			Status: ResponseStatusOK,
			Error:  "CredentialResolutionError",
		}, http.StatusInternalServerError
	}
	sequence := req.Sequence
	if strings.TrimSpace(sequence) == "" {
		sequence = selected.Sequence
	}
	if strings.TrimSpace(sequence) == "" {
		sequence = DefaultSequenceTemplate
	}

	d.pendingCandidates = nil

	return FillResponse{
		Status:    ResponseStatusOK,
		ProfileID: selected.ID,
		Service:   selected.Service,
		Domain:    selected.Domain,
		Username:  cred.Username,
		Password:  cred.Password,
		TOTP:      cred.TOTP,
		Sequence:  sequence,
	}, http.StatusOK
}

func (d *Daemon) tryUnlockFromSessionLocked() bool {
	unlock, err := src.AttemptUnlockWithSession(d.vaultPath)
	if err != nil || unlock == nil || unlock.Vault == nil {
		return false
	}

	now := time.Now().UTC()
	d.vault = unlock.Vault
	d.locked = false
	d.pendingCandidates = nil
	d.lastActivity = now

	if session, err := src.GetSession(); err == nil {
		d.unlockExpiresAt = session.Expiry.UTC()
		d.inactivityTimeout = session.InactivityTimeout
	} else {
		d.unlockExpiresAt = now.Add(1 * time.Hour)
		d.inactivityTimeout = 15 * time.Minute
	}

	return true
}

func (d *Daemon) resolveSystemIntelligentFillLocked(req FillRequest) (FillResponse, int) {
	return resolveSystemIntelligentFill(d.vault, req)
}

func (d *Daemon) lookupMailOTPLocked(ctx RequestContext, consume bool) (string, bool) {
	d.pruneMailArtifactsLocked()

	now := time.Now()
	filtered := d.mailCache[:0]
	for _, item := range d.mailCache {
		if now.Sub(item.ReceivedAt) <= 8*time.Minute && !d.mailCodeConsumedLocked(item) {
			filtered = append(filtered, item)
		}
	}
	d.mailCache = filtered
	if len(d.mailCache) > 0 {
		best := d.mailCache[0]
		best.Score = scoreMailOTPResult(best, ctx)
		for _, item := range d.mailCache[1:] {
			item.Score = scoreMailOTPResult(item, ctx)
			if item.Score > best.Score || (item.Score == best.Score && item.ReceivedAt.After(best.ReceivedAt)) {
				best = item
			}
		}
		if best.Score >= 180 {
			if consume {
				d.consumeMailCodeLocked(best)
			}
			return best.Code, true
		}
	}

	results, err := LookupGmailOTP(context.Background(), ctx, d.usedMailCodes)
	if err != nil || len(results) == 0 {
		return "", false
	}
	d.mailCache = results
	best := results[0]
	if best.Score <= 0 {
		return "", false
	}
	if consume {
		d.consumeMailCodeLocked(best)
	}
	return best.Code, true
}

func (d *Daemon) resolveMailFillLocked(req FillRequest) (FillResponse, int) {
	if inferFieldIntent(req.Context) != fieldIntentMailOTP {
		return FillResponse{
			Status: ResponseStatusOK,
			Error:  "NoMatchingMailOTPError",
		}, http.StatusNotFound
	}
	code, ok := d.lookupMailOTPLocked(req.Context, true)
	if !ok {
		return FillResponse{
			Status: ResponseStatusOK,
			Error:  "NoMatchingMailOTPError",
		}, http.StatusNotFound
	}
	return FillResponse{
		Status:   ResponseStatusOK,
		TOTP:     code,
		Sequence: "{TOTP}",
	}, http.StatusOK
}

func (d *Daemon) consumeMailCodeLocked(item MailOTPResult) {
	expiresAt := item.ReceivedAt.Add(8 * time.Minute)
	if expiresAt.Before(time.Now()) {
		expiresAt = time.Now().Add(8 * time.Minute)
	}
	if strings.TrimSpace(item.MessageID) != "" {
		d.usedMailCodes[strings.TrimSpace(item.MessageID)] = expiresAt
	}
	if strings.TrimSpace(item.Code) != "" {
		d.usedMailCodes["code:"+strings.TrimSpace(item.Code)] = expiresAt
	}

	filtered := d.mailCache[:0]
	for _, cached := range d.mailCache {
		if cached.MessageID == item.MessageID && cached.Code == item.Code {
			continue
		}
		if strings.TrimSpace(cached.Code) != "" && strings.EqualFold(strings.TrimSpace(cached.Code), strings.TrimSpace(item.Code)) {
			continue
		}
		filtered = append(filtered, cached)
	}
	d.mailCache = filtered
}

func (d *Daemon) mailCodeConsumedLocked(item MailOTPResult) bool {
	if strings.TrimSpace(item.MessageID) != "" {
		if expiry, ok := d.usedMailCodes[strings.TrimSpace(item.MessageID)]; ok && time.Now().Before(expiry) {
			return true
		}
	}
	if strings.TrimSpace(item.Code) != "" {
		if expiry, ok := d.usedMailCodes["code:"+strings.TrimSpace(item.Code)]; ok && time.Now().Before(expiry) {
			return true
		}
	}
	return false
}

func (d *Daemon) pruneMailArtifactsLocked() {
	now := time.Now()
	for key, expiry := range d.usedMailCodes {
		if now.After(expiry) {
			delete(d.usedMailCodes, key)
		}
	}
}

func (d *Daemon) handleHotkey(ctx WindowContext) {
	if d.tryHandleHotkeyContext(requestContextFromWindow(ctx)) {
		return
	}

	freshCtx, err := captureActiveWindowContext()
	if err != nil {
		return
	}
	_ = d.tryHandleHotkeyContext(requestContextFromWindow(freshCtx))
}

func (d *Daemon) handleMailHotkey(ctx WindowContext) {
	if d.tryHandleMailHotkeyContext(requestContextFromWindow(ctx)) {
		return
	}

	freshCtx, err := captureActiveWindowContext()
	if err != nil {
		return
	}
	_ = d.tryHandleMailHotkeyContext(requestContextFromWindow(freshCtx))
}

func (d *Daemon) tryHandleHotkeyContext(requestContext RequestContext) bool {
	req := FillRequest{
		Context:        requestContext,
		IncludeTOTP:    true,
		ExplicitAction: true,
	}

	resp, statusCode := d.resolveFill(req)
	if statusCode == http.StatusOK && resp.Status == ResponseStatusMultiple && len(resp.Candidates) > 0 {
		// Hotkey autofill is a single gesture, so prefer the best-ranked candidate
		// instead of stopping for an interactive selection prompt.
		req.SelectionID = resp.Candidates[0].ProfileID
		resp, statusCode = d.resolveFill(req)
	}
	if statusCode != http.StatusOK || resp.Status != ResponseStatusOK || resp.Error != "" {
		return false
	}

	actions := renderSequence(resp.Sequence, resp.Username, resp.Password, resp.TOTP)
	_ = d.systemEngine.Type(actions)
	return true
}

func (d *Daemon) tryHandleMailHotkeyContext(requestContext RequestContext) bool {
	resp, statusCode := d.resolveFill(FillRequest{
		Context:        requestContext,
		IncludeTOTP:    true,
		MailOnly:       true,
		ExplicitAction: true,
	})
	if statusCode != http.StatusOK || resp.Status != ResponseStatusOK || resp.Error != "" {
		return false
	}

	actions := renderSequence("{TOTP}", "", "", resp.TOTP)
	_ = d.systemEngine.Type(actions)
	return true
}

func (d *Daemon) watchContextHints() {
	ticker := time.NewTicker(1500 * time.Millisecond)
	defer ticker.Stop()

	for {
		select {
		case <-ticker.C:
			ctx, err := captureActiveWindowContext()
			if err != nil {
				continue
			}
			requestContext := requestContextFromWindow(ctx)
			contextKey := contextFingerprint(requestContext)

			d.mu.Lock()
			hasMatch := !d.locked && d.vault != nil && len(buildIntelligentCandidates(d.vault, requestContext)) > 0
			d.mu.Unlock()

			if !hasMatch || !contextSuggestsCredentialEntry(requestContext) {
				continue
			}

			if strings.TrimSpace(contextKey) == "" {
				contextKey = "match"
			}

			d.maybeNotify("autocomplete:"+contextKey, fmt.Sprintf("Autocomplete found for the website. Press %s for completion", strings.ToUpper(d.hotkeyRaw)), 20*time.Second)
		case <-d.stopCh:
			return
		}
	}
}

func (d *Daemon) watchLockState() {
	ticker := time.NewTicker(1 * time.Second)
	defer ticker.Stop()
	for {
		select {
		case <-ticker.C:
			d.mu.Lock()
			if !d.locked {
				now := time.Now().UTC()
				if (!d.unlockExpiresAt.IsZero() && now.After(d.unlockExpiresAt)) ||
					(d.inactivityTimeout > 0 && now.Sub(d.lastActivity) > d.inactivityTimeout) {
					// Expiry and inactivity both converge on the same lock path so the
					// in-memory vault is cleared consistently.
					d.lockVaultLocked()
				}
			}
			d.mu.Unlock()
		case <-d.stopCh:
			return
		}
	}
}

func (d *Daemon) maybeNotify(key, message string, cooldown time.Duration) {
	key = strings.TrimSpace(strings.ToLower(key))
	message = strings.TrimSpace(message)
	if key == "" || message == "" {
		return
	}

	now := time.Now().UTC()
	d.mu.Lock()
	if d.popupDisabled {
		d.mu.Unlock()
		return
	}
	lastSeen := d.recentNotices[key]
	if !lastSeen.IsZero() && now.Sub(lastSeen) < cooldown {
		d.mu.Unlock()
		return
	}
	d.recentNotices[key] = now
	d.mu.Unlock()

	d.notifier.Show(message)
}

func (d *Daemon) shutdownNow() {
	d.mu.Lock()
	if d.stopped {
		d.mu.Unlock()
		return
	}
	d.stopped = true
	close(d.stopCh)
	d.lockVaultLocked()
	d.mu.Unlock()

	_ = d.systemEngine.Stop()

	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	_ = d.server.Shutdown(ctx)
	_ = d.listener.Close()
	_ = clearDaemonState()
}

func (d *Daemon) lockVaultLocked() {
	if d.vault != nil {
		wipeVaultSecrets(d.vault)
	}
	d.vault = nil
	d.locked = true
	d.unlockExpiresAt = time.Time{}
	d.inactivityTimeout = 0
	d.lastActivity = time.Time{}
	d.pendingCandidates = nil
}

func toCandidates(matches []Profile) []MatchCandidate {
	out := make([]MatchCandidate, 0, len(matches))
	for _, p := range matches {
		out = append(out, MatchCandidate{
			ProfileID: p.ID,
			Service:   p.Service,
			Domain:    p.Domain,
			Username:  p.EntryUsername,
		})
	}
	return out
}

func requestContextFromWindow(ctx WindowContext) RequestContext {
	return RequestContext{
		Kind:         ContextSystem,
		Domain:       ctx.Domain,
		DomainHints:  ctx.DomainHints,
		WindowTitle:  ctx.WindowTitle,
		ProcessName:  ctx.ProcessName,
		ProcessPath:  ctx.ProcessPath,
		FocusedName:  ctx.FocusedName,
		FocusedValue: ctx.FocusedValue,
		EmailHints:   ctx.EmailHints,
	}
}

func contextSuggestsCredentialEntry(ctx RequestContext) bool {
	windowTitle := strings.ToLower(strings.TrimSpace(ctx.WindowTitle))
	focusedName := strings.ToLower(strings.TrimSpace(ctx.FocusedName))
	signals := strings.TrimSpace(windowTitle + " " + focusedName)

	if containsAny(signals, "inbox", "mailbox", "compose", "message list", "thread list", "chat", "channel", "timeline", "feed") &&
		!containsAny(signals, "login", "log in", "sign in", "signin", "password", "otp", "2fa", "verification", "auth", "security code", "authenticator") {
		return false
	}

	authPageSignals := containsAny(
		windowTitle,
		"login", "log in", "sign in", "signin", "password", "otp", "2fa",
		"verification", "verify", "two-factor", "one-time", "authenticator", "security code",
	)
	focusSignals := containsAny(
		focusedName,
		"email", "username", "user", "login", "password", "passcode", "otp",
		"verification", "code", "pin", "authenticator", "security",
	)

	switch inferFieldIntent(ctx) {
	case fieldIntentTOTP, fieldIntentMailOTP, fieldIntentPassword:
		return true
	case fieldIntentUsername:
		return authPageSignals || focusSignals
	default:
		return authPageSignals && focusSignals
	}
}

func contextIntentBucket(ctx RequestContext) string {
	switch inferFieldIntent(ctx) {
	case fieldIntentTOTP, fieldIntentMailOTP:
		return "otp"
	case fieldIntentPassword:
		return "password"
	case fieldIntentUsername:
		return "username"
	}
	windowSignals := strings.ToLower(strings.TrimSpace(ctx.WindowTitle + " " + ctx.FocusedName))
	if containsAny(windowSignals, "login", "log in", "sign in", "signin", "password", "username", "email", "otp", "2fa", "verification", "auth") {
		return "login"
	}
	return "generic"
}

func contextFingerprint(ctx RequestContext) string {
	domain := normalizeDomain(ctx.Domain)
	if domain == "" && len(ctx.DomainHints) > 0 {
		domain = normalizeDomain(ctx.DomainHints[0])
	}
	process := strings.ToLower(strings.TrimSpace(ctx.ProcessName))
	bucket := contextIntentBucket(ctx)
	if domain == "" && process == "" && bucket == "generic" {
		return ""
	}
	return strings.TrimSpace(domain + "|" + process + "|" + bucket)
}

func pickProfile(matches []Profile, selectionID string) (Profile, bool) {
	if len(matches) == 1 && strings.TrimSpace(selectionID) == "" {
		return matches[0], true
	}
	for _, m := range matches {
		if strings.EqualFold(strings.TrimSpace(m.ID), strings.TrimSpace(selectionID)) {
			return m, true
		}
	}
	return Profile{}, false
}

func isLoopbackRequest(remoteAddr string) bool {
	host, _, err := net.SplitHostPort(strings.TrimSpace(remoteAddr))
	if err != nil {
		return false
	}
	ip := net.ParseIP(host)
	return ip != nil && ip.IsLoopback()
}

func writeJSON(w http.ResponseWriter, statusCode int, payload any) {
	w.Header().Set("Content-Type", "application/json")
	w.WriteHeader(statusCode)
	_ = json.NewEncoder(w).Encode(payload)
}

func writeError(w http.ResponseWriter, statusCode int, errorCode string) {
	writeJSON(w, statusCode, map[string]string{"error": errorCode})
}

func wipeVaultSecrets(v *src.Vault) {
	for i := range v.Entries {
		v.Entries[i].Password = ""
	}
	for i := range v.TOTPEntries {
		v.TOTPEntries[i].Secret = ""
	}
	for i := range v.Tokens {
		v.Tokens[i].Token = ""
	}
	for i := range v.APIKeys {
		v.APIKeys[i].Key = ""
	}
}

func zeroString(value *string) {
	if value == nil {
		return
	}
	buf := []byte(*value)
	for i := range buf {
		buf[i] = 0
	}
	*value = ""
}

func TryStatus(ctx context.Context) (*DaemonStatus, error) {
	client, err := NewClientFromState()
	if err != nil {
		return nil, err
	}
	return client.Status(ctx)
}

func PIDFromState() (int, error) {
	state, err := loadDaemonState()
	if err != nil {
		return 0, err
	}
	return state.PID, nil
}

func PortFromState() (int, error) {
	state, err := loadDaemonState()
	if err != nil {
		return 0, err
	}
	parts := strings.Split(state.Addr, ":")
	if len(parts) == 0 {
		return 0, errors.New("invalid daemon address")
	}
	portText := parts[len(parts)-1]
	port, err := strconv.Atoi(strings.TrimSpace(portText))
	if err != nil {
		return 0, err
	}
	return port, nil
}
