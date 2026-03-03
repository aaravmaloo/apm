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

	src "password-manager/src"
)

type RunOptions struct {
	VaultPath string
	Hotkey    string
}

type Daemon struct {
	mu sync.Mutex

	vaultPath string
	token     string
	startedAt time.Time
	hotkeyRaw string
	hotkey    Hotkey

	locked            bool
	vault             *src.Vault
	unlockExpiresAt   time.Time
	inactivityTimeout time.Duration
	lastActivity      time.Time

	pendingCandidates []MatchCandidate

	listener net.Listener
	server   *http.Server
	stopCh   chan struct{}
	stopped  bool

	systemEngine SystemEngine
}

func Run(opts RunOptions) error {
	if strings.TrimSpace(opts.VaultPath) == "" {
		return errors.New("vault path is required")
	}
	if _, err := os.Stat(opts.VaultPath); err != nil {
		return fmt.Errorf("vault path is invalid: %w", err)
	}

	hotkey, err := parseHotkey(opts.Hotkey)
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
		locked:            true,
		listener:          listener,
		stopCh:            make(chan struct{}),
		systemEngine:      newSystemEngine(),
		inactivityTimeout: 15 * time.Minute,
	}
	if daemon.hotkeyRaw == "" {
		daemon.hotkeyRaw = "CTRL+SHIFT+ALT+A"
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

	if err := daemon.systemEngine.Start(daemon.hotkey, daemon.handleHotkey); err != nil {
		// Keep daemon operational even if global hotkey setup fails.
		daemon.systemEngine = newSystemEngine()
	}

	go daemon.watchLockState()

	err = daemon.server.Serve(listener)
	if errors.Is(err, http.ErrServerClosed) {
		return nil
	}
	daemon.shutdownNow()
	return err
}

func (d *Daemon) withAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
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
	d.vault = vault
	d.locked = false
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

	if d.locked || d.vault == nil {
		return FillResponse{
			Status: ResponseStatusOK,
			Error:  ErrVaultLocked,
		}, http.StatusLocked
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
		return resolveSystemIntelligentFill(d.vault, req)
	}
	if len(matches) == 0 {
		return FillResponse{
			Status: ResponseStatusOK,
			Error:  "NoMatchingProfileError",
		}, http.StatusNotFound
	}

	if req.SelectionID == "" && len(matches) > 1 {
		candidates := toCandidates(matches)
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

func (d *Daemon) handleHotkey(ctx WindowContext) {
	req := FillRequest{
		Context: RequestContext{
			Kind:         ContextSystem,
			Domain:       ctx.Domain,
			DomainHints:  ctx.DomainHints,
			WindowTitle:  ctx.WindowTitle,
			ProcessName:  ctx.ProcessName,
			ProcessPath:  ctx.ProcessPath,
			FocusedName:  ctx.FocusedName,
			FocusedValue: ctx.FocusedValue,
			EmailHints:   ctx.EmailHints,
		},
		IncludeTOTP:    true,
		ExplicitAction: true,
	}

	resp, statusCode := d.resolveFill(req)
	if statusCode != http.StatusOK || resp.Status != ResponseStatusOK || resp.Error != "" {
		return
	}

	actions := renderSequence(resp.Sequence, resp.Username, resp.Password, resp.TOTP)
	_ = d.systemEngine.Type(actions)
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
					d.lockVaultLocked()
				}
			}
			d.mu.Unlock()
		case <-d.stopCh:
			return
		}
	}
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
