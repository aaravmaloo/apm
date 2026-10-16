package main

import (
	"context"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	src "github.com/aaravmaloo/apm/src"
)

// watchtowerScan scans the unlocked vault. A full scan also keeps the day's
// score, saved quietly when the session can write.
func (s *desktopServer) watchtowerScan(space string) *src.WatchtowerReport {
	// "" is every space and "default" the default one.
	opt := src.WatchtowerOptions{Space: strings.TrimSpace(space), TouchIDAvailable: s.touchIDAvailable(), TouchIDConfigured: s.touchIDConfigured()}
	rep := src.ScanWatchtower(s.vault, opt)
	if opt.Space == "" && !s.isReadonly() && !s.vaultNewer() && src.RecordWatchtowerHistory(s.vault, rep.Score) {
		if err := s.saveQuiet(); err == nil {
			rep = src.ScanWatchtower(s.vault, opt)
		}
	}
	return rep
}

func hWatchtowerScan(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Space string `json:"space"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	return s.watchtowerScan(in.Space), nil
}

func hWatchtowerDismiss(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID     string `json:"id"`
		Reason string `json:"reason"`
		Days   int    `json:"days"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	if in.Days < 0 {
		return nil, rpcErr("invalid", "Days can't be negative.")
	}
	if err := src.DismissFinding(s.vault, in.ID, in.Reason, in.Days); err != nil {
		return nil, rpcErr("invalid", err.Error())
	}
	src.PruneDismissals(s.vault)
	if err := s.save("Dismissed a Watchtower finding"); err != nil {
		return nil, err
	}
	src.LogAction("WATCHTOWER_DISMISSED", in.ID)
	return map[string]any{"ok": true}, nil
}

func hWatchtowerRestore(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	if !src.RestoreFinding(s.vault, in.ID) {
		return map[string]any{"ok": true}, nil
	}
	if err := s.save("Restored a Watchtower finding"); err != nil {
		return nil, err
	}
	src.LogAction("WATCHTOWER_RESTORED", in.ID)
	return map[string]any{"ok": true}, nil
}

func hWatchtowerBreach(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Enabled *bool `json:"enabled"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if in.Enabled == nil {
		return nil, rpcErr("invalid", "Say whether the breach check is on.")
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	src.SetBreachCheck(s.vault, *in.Enabled)
	state := "off"
	if *in.Enabled {
		state = "on"
	}
	if err := s.save("Breach check " + state); err != nil {
		return nil, err
	}
	src.LogAction("SETTINGS_CHANGED", "breach check "+state)
	return s.withSnapshot(map[string]any{"ok": true}), nil
}

// hWatchtowerBreachCheck asks HIBP without holding the server lock: the
// vault is read and written under the lock, the network part runs outside it.
func hWatchtowerBreachCheck(s *desktopServer, p json.RawMessage) (any, error) {
	s.mu.Lock()
	if err := s.requireWritable(); err != nil {
		s.mu.Unlock()
		return nil, err
	}
	plan, err := src.PlanBreachCheck(s.vault)
	vault := s.vault
	s.mu.Unlock()
	if errors.Is(err, src.ErrBreachCheckOff) {
		return nil, rpcErr("breach_off", "Turn the breach check on first.")
	}
	if err != nil {
		return nil, err
	}

	plan.Run(context.Background())

	s.mu.Lock()
	defer s.mu.Unlock()
	if s.vault != vault {
		return nil, rpcErr("locked", "The vault changed while checking. Try again.")
	}
	run, aerr := plan.Apply(s.vault)
	if err := s.saveQuiet(); err != nil {
		return nil, err
	}
	src.LogAction("BREACH_CHECK", "checked "+strconv.Itoa(run.Checked)+", found "+strconv.Itoa(run.Found))
	if aerr != nil {
		return nil, rpcErr("network", aerr.Error())
	}
	return s.watchtowerScan(""), nil
}

func hWatchtowerMarkExposed(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ItemID  string `json:"itemId"`
		Exposed *bool  `json:"exposed"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if in.Exposed == nil {
		return nil, rpcErr("invalid", "Say whether the item is exposed.")
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	ref, ok := s.vault.FindItem(in.ItemID)
	if !ok {
		return nil, rpcErr("not_found", "That item no longer exists.")
	}
	s.vault.SetItemTelemetryFlags(ref, nil, in.Exposed)
	note := "Marked " + ref.Title + " as exposed"
	if !*in.Exposed {
		note = "Cleared the exposed flag on " + ref.Title
	}
	if err := s.save(note); err != nil {
		return nil, err
	}
	src.LogAction("ITEM_MARKED", note)
	return s.withSnapshot(map[string]any{"ok": true}), nil
}

// scanActivity reads new audit and history entries into the vault's
// activity, saving quietly when something was added and the session can write.
func (s *desktopServer) scanActivity() {
	touch := s.touchIDConfigured()
	if len(src.ScanActivity(s.vault, &touch)) > 0 && !s.isReadonly() && !s.vaultNewer() {
		_ = s.saveQuiet()
	}
}

func hActivityList(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		Limit               int  `json:"limit"`
		IncludeAcknowledged bool `json:"includeAcknowledged"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireUnlocked(); err != nil {
		return nil, err
	}
	s.scanActivity()
	events, unack := src.ListActivity(s.vault, in.Limit, in.IncludeAcknowledged)
	views := make([]map[string]any, 0, len(events))
	for _, e := range events {
		views = append(views, e.View())
	}
	return map[string]any{"events": views, "unacknowledged": unack}, nil
}

func hActivityAck(s *desktopServer, p json.RawMessage) (any, error) {
	var in struct {
		ID string `json:"id"`
	}
	if err := decodeParams(p, &in); err != nil {
		return nil, err
	}
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	if !src.AckActivity(s.vault, in.ID) {
		return nil, rpcErr("not_found", "That event no longer exists.")
	}
	if err := s.saveQuiet(); err != nil {
		return nil, err
	}
	src.LogAction("ACTIVITY_ACKNOWLEDGED", in.ID)
	return map[string]any{"ok": true}, nil
}

func hActivityAckAll(s *desktopServer, p json.RawMessage) (any, error) {
	if err := s.requireWritable(); err != nil {
		return nil, err
	}
	n := src.AckAllActivity(s.vault)
	if n > 0 {
		if err := s.saveQuiet(); err != nil {
			return nil, err
		}
		src.LogAction("ACTIVITY_ACKNOWLEDGED", strconv.Itoa(n)+" events")
	}
	return map[string]any{"ok": true}, nil
}
