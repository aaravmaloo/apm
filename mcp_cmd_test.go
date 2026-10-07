package main

import (
	"encoding/json"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"testing"
	"time"

	src "github.com/aaravmaloo/apm/src"
	"github.com/spf13/cobra"
)

func TestMCPOpenURLArgv(t *testing.T) {
	url := "cursor://anysphere.cursor-deeplink/mcp/install?name=apm&config=e30="
	cases := map[string][]string{
		"darwin":  {"open", url},
		"linux":   {"xdg-open", url},
		"windows": {"rundll32", "url.dll,FileProtocolHandler", url},
	}
	for goos, want := range cases {
		if got := mcpOpenURLArgv(goos, url); !reflect.DeepEqual(got, want) {
			t.Errorf("%s: %q, want %q", goos, got, want)
		}
	}
	// The link stays one argument whatever it contains.
	odd := "x://a b;rm -rf ~&c=$(id)"
	if got := mcpOpenURLArgv("darwin", odd); len(got) != 2 || got[1] != odd {
		t.Fatalf("link was split: %q", got)
	}
}

func TestMCPGenericConfigAndEntry(t *testing.T) {
	got, _ := json.Marshal(mcpGenericConfig())
	if string(got) != `{"mcpServers":{"apm":{"command":"pm","args":["mcp","serve"]}}}` {
		t.Fatalf("generic config = %s", got)
	}
	entry := mcpServerEntry(src.MCPHarness{ID: "zed"})
	if string(entry) != `{"command":"pm","args":["mcp","serve","--client","zed"]}` {
		t.Fatalf("default entry = %s", entry)
	}
}

func TestMCPAddToFile(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	path := filepath.Join(dir, "mcp.json")
	h := src.MCPHarness{
		ID: "test", Name: "Test", Kind: "file", ConfigKey: "mcpServers", ConfigFormat: "json",
		ConfigFiles: map[string]string{"darwin": path, "linux": path, "win32": path},
		Entry:       json.RawMessage(`{"command":"pm","args":["mcp","serve","--client","test"]}`),
	}
	yes := func(string) bool { return true }

	// Existing servers are kept and the original is backed up.
	original := `{"mcpServers": {"other": {"command": "x"}}, "keep": true}`
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	if !mcpAddToFile(h, yes) {
		t.Fatal("mcpAddToFile failed")
	}
	var cfg map[string]any
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatalf("result is not JSON: %v\n%s", err, data)
	}
	servers := cfg["mcpServers"].(map[string]any)
	if servers["other"] == nil || servers["apm"] == nil || cfg["keep"] != true {
		t.Fatalf("merged config = %s", data)
	}
	if b, _ := os.ReadFile(path + ".apm-backup"); string(b) != original {
		t.Fatalf("backup = %q", b)
	}

	// A file pm can't parse is left alone.
	broken := "{ \"mcpServers\": { // comment\n } }"
	_ = os.WriteFile(path, []byte(broken), 0600)
	_ = os.Remove(path + ".apm-backup")
	if mcpAddToFile(h, yes) {
		t.Fatal("an unparseable file was accepted")
	}
	if b, _ := os.ReadFile(path); string(b) != broken {
		t.Fatal("an unparseable file was changed")
	}
	if _, err := os.Stat(path + ".apm-backup"); !os.IsNotExist(err) {
		t.Fatal("a backup was written for an unchanged file")
	}

	// Saying no changes nothing.
	_ = os.Remove(path)
	if !mcpAddToFile(h, func(string) bool { return false }) {
		t.Fatal("declining should still show the entry")
	}
	if _, err := os.Stat(path); !os.IsNotExist(err) {
		t.Fatal("a file was created after declining")
	}
}

// splitPOSIX splits a command line made of plain words and single-quoted
// strings, the only quoting FormatArgv produces.
func splitPOSIX(t *testing.T, line string) []string {
	t.Helper()
	var out []string
	var cur strings.Builder
	inWord, quoted := false, false
	for i := 0; i < len(line); i++ {
		c := line[i]
		switch {
		case quoted && c == '\'':
			quoted = false
		case quoted:
			cur.WriteByte(c)
		case c == '\'':
			quoted, inWord = true, true
		case c == '\\' && i+1 < len(line):
			i++
			cur.WriteByte(line[i])
			inWord = true
		case c == ' ':
			if inWord {
				out = append(out, cur.String())
				cur.Reset()
				inWord = false
			}
		default:
			cur.WriteByte(c)
			inWord = true
		}
	}
	if quoted {
		t.Fatalf("unterminated quote in %q", line)
	}
	if inWord {
		out = append(out, cur.String())
	}
	return out
}

// The one-line command shown for a harness is exactly the argv pm runs.
func TestMCPHarnessCommandsAreArgv(t *testing.T) {
	for _, h := range src.MCPHarnesses() {
		if h.Kind != "cli" {
			continue
		}
		if got := splitPOSIX(t, h.Command()); !reflect.DeepEqual(got, h.Argv) {
			t.Errorf("%s: %q reads back as %q, not %q", h.ID, h.Command(), got, h.Argv)
		}
		for _, a := range h.Argv {
			if a == "" || strings.ContainsAny(a, "\n\r\x00") {
				t.Errorf("%s: bad argument %q", h.ID, a)
			}
		}
	}
}

func TestMCPFileEntryUsesFullPath(t *testing.T) {
	h, ok := src.GetMCPHarness("claude-desktop")
	if !ok {
		t.Fatal("no claude-desktop harness")
	}
	var entry struct {
		Command string   `json:"command"`
		Args    []string `json:"args"`
	}
	if err := json.Unmarshal(mcpFileEntry(h), &entry); err != nil {
		t.Fatal(err)
	}
	if !filepath.IsAbs(entry.Command) || !reflect.DeepEqual(entry.Args, []string{"mcp", "serve", "--client", "claude-desktop"}) {
		t.Fatalf("file entry = %+v", entry)
	}
}

// TestDesktopMCPConnect checks that the app allows an assistant without the
// vault, and that the Settings page can list, change and revoke it.
func TestDesktopMCPConnect(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir)
	for k, v := range map[string]string{"HOME": dir, "XDG_CONFIG_HOME": filepath.Join(dir, ".config"), "APPDATA": filepath.Join(dir, "AppData"), "APM_STATE_DIR": dir, "APM_SESSION_ID": "", "APM_EPHEMERAL_ID": "", "APM_DESKTOP_NO_TOUCHID": "1", "APM_ICONS_OFFLINE": "1", "APM_MCP_NO_APPROVER": "1"} {
		t.Setenv(k, v)
	}
	prevPath := vaultPath
	vaultPath = filepath.Join(dir, "vault.dat")
	t.Cleanup(func() { vaultPath = prevPath })
	const pw = "ValidPass123!"
	v := &src.Vault{Profile: "standard", Spaces: []string{"default"}}
	data, err := src.EncryptVault(v, pw)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(vaultPath, data, 0600); err != nil {
		t.Fatal(err)
	}
	s := newDesktopServer(nil)
	s.sink = func(string, any) {}

	tx, err := src.CreateMCPConnectTransaction(src.MCPConnectArgs{Client: "Claude Code", ClientID: "claude-code", Version: "2.1.0", Harness: "claude-code"}, 0)
	if err != nil {
		t.Fatal(err)
	}
	view := mcpTxView(tx)
	entry := view["entry"].(map[string]any)
	f := entry["f"].(map[string]any)
	if view["op"] != "connect" || view["client"] != "Claude Code" || entry["type"] != "assistant" || entry["name"] != "Claude Code" || len(f["access"].([]string)) != 3 {
		t.Fatalf("connect view = %v", view)
	}

	// Allowing while locked makes the grant at once.
	params, _ := json.Marshal(map[string]any{"id": tx.ID, "approve": true, "via": "touchid"})
	res, err := hMCPTxDecide(s, params)
	if err != nil || res.(map[string]any)["status"] != "committed" {
		t.Fatalf("decide = %v (%v)", res, err)
	}
	g, err := src.FindMCPAssistant("claude-code", "claude-code")
	if err != nil {
		t.Fatalf("no grant: %v", err)
	}

	unlocked, _ := src.DecryptVault(data, pw, 1)
	s.finishUnlock(pw, unlocked, "test", false)
	list := s.mcpView()["assistants"].([]map[string]any)
	if len(list) != 1 || list[0]["id"] != g.ID || list[0]["harness"] != "claude-code" || list[0]["name"] != "Claude Code" {
		t.Fatalf("assistants view = %v", list)
	}
	for _, k := range []string{"perms", "created", "lastUsed", "uses"} {
		if _, ok := list[0][k]; !ok {
			t.Fatalf("assistants view has no %s: %v", k, list[0])
		}
	}

	bad, _ := json.Marshal(map[string]any{"id": g.ID, "perms": []string{"list_vault", "all"}})
	if _, err := hMCPAssistantPerms(s, bad); err == nil {
		t.Fatal("an unknown permission was accepted")
	}
	good, _ := json.Marshal(map[string]any{"id": g.ID, "perms": []string{"list_vault", "cloud_sync"}})
	if _, err := hMCPAssistantPerms(s, good); err != nil {
		t.Fatal(err)
	}
	if got, _ := src.GetMCPAssistant(g.ID); !reflect.DeepEqual(got.Perms, []string{"list_vault", "cloud_sync"}) {
		t.Fatalf("perms = %v", got.Perms)
	}

	rev, _ := json.Marshal(map[string]any{"id": g.ID})
	if _, err := hMCPAssistantRevoke(s, rev); err != nil {
		t.Fatal(err)
	}
	if _, err := hMCPAssistantRevoke(s, rev); err == nil {
		t.Fatal("revoked twice")
	}

	// Rejecting leaves no grant.
	tx2, _ := src.CreateMCPConnectTransaction(src.MCPConnectArgs{Client: "Cursor", ClientID: "cursor-vscode", Harness: "cursor"}, 0)
	params, _ = json.Marshal(map[string]any{"id": tx2.ID, "approve": false, "via": "keyboard"})
	if res, err := hMCPTxDecide(s, params); err != nil || res.(map[string]any)["status"] != "rejected" {
		t.Fatalf("reject = %v (%v)", res, err)
	}
	if _, err := src.FindMCPAssistant("cursor", "cursor-vscode"); err == nil {
		t.Fatal("a rejected assistant has a grant")
	}

	hs, err := hMCPHarnesses(s, nil)
	if err != nil {
		t.Fatal(err)
	}
	harnesses := hs.(map[string]any)["harnesses"].([]map[string]any)
	if len(harnesses) == 0 || harnesses[0]["id"] == "" || harnesses[0]["command"] == "" {
		t.Fatalf("mcp.harnesses = %v", harnesses)
	}
}

func TestMCPSettingsFlags(t *testing.T) {
	parse := func(args ...string) (src.MCPPolicyPatch, error) {
		c := &cobra.Command{Use: "settings"}
		addMCPSettingsFlags(c)
		if err := c.ParseFlags(args); err != nil {
			t.Fatal(err)
		}
		return parseMCPSettingsFlags(c)
	}
	p, err := parse()
	if err != nil || !p.Empty() {
		t.Fatalf("no flags = %+v (%v)", p, err)
	}
	p, err = parse("--approve-with", "touchid", "--expiry", "1h", "--new-assistants", "block", "--ask-before-secrets", "on")
	if err != nil || *p.ApproveWith != "touchid" || *p.ExpiryMinutes != 60 || *p.NewAssistants != "block" || !*p.AskBeforeSecrets || p.Paused != nil {
		t.Fatalf("all flags = %+v (%v)", p, err)
	}
	p, err = parse("--ask-before-secrets", "off", "--expiry", "5m")
	if err != nil || *p.AskBeforeSecrets || *p.ExpiryMinutes != 5 || p.ApproveWith != nil {
		t.Fatalf("off/5m = %+v (%v)", p, err)
	}
	for _, bad := range [][]string{
		{"--approve-with", "face"},
		{"--expiry", "2h"},
		{"--expiry", "10m"},
		{"--new-assistants", "maybe"},
		{"--ask-before-secrets", "sometimes"},
	} {
		if _, err := parse(bad...); err == nil {
			t.Fatalf("%v parsed", bad)
		}
	}
	for in, want := range map[string]int{"5m": 5, "15m": 15, "30m": 30, "1h": 60, "60m": 60} {
		if got, err := parseMCPExpiry(in); err != nil || got != want {
			t.Fatalf("parseMCPExpiry(%q) = %d (%v)", in, got, err)
		}
	}
}

// TestMCPLooseningNeedsTerminal checks that without a person at the terminal
// tightening works and loosening is refused without changing anything.
func TestMCPLooseningNeedsTerminal(t *testing.T) {
	dir := t.TempDir()
	for k, v := range map[string]string{"HOME": dir, "XDG_CONFIG_HOME": filepath.Join(dir, ".config"), "APPDATA": filepath.Join(dir, "AppData"), "APM_STATE_DIR": dir, "APM_DESKTOP_NO_TOUCHID": "1"} {
		t.Setenv(k, v)
	}
	prev := atTerminal
	atTerminal = func() bool { return false }
	t.Cleanup(func() { atTerminal = prev })

	on, off := true, false
	changes, err := applyMCPPolicyChange(src.MCPPolicyPatch{Paused: &on})
	if err != nil || len(changes) != 1 || changes[0] != "MCP access paused" {
		t.Fatalf("pause = %v (%v)", changes, err)
	}
	touch, five := "touchid", 5
	if _, err := applyMCPPolicyChange(src.MCPPolicyPatch{ApproveWith: &touch, ExpiryMinutes: &five, AskBeforeSecrets: &on}); err != nil {
		t.Fatalf("tightening: %v", err)
	}
	any15, ask := "any", "ask"
	fifteen := 15
	for _, patch := range []src.MCPPolicyPatch{
		{Paused: &off},
		{ApproveWith: &any15},
		{ExpiryMinutes: &fifteen},
		{AskBeforeSecrets: &off},
	} {
		if _, err := applyMCPPolicyChange(patch); err == nil || err.Error() != "Loosening MCP settings needs you at the terminal." {
			t.Fatalf("loosening %+v = %v", patch, err)
		}
	}
	block := "block"
	if _, err := applyMCPPolicyChange(src.MCPPolicyPatch{NewAssistants: &block}); err != nil {
		t.Fatal(err)
	}
	if _, err := applyMCPPolicyChange(src.MCPPolicyPatch{NewAssistants: &ask}); err != errMCPNeedsTerminal {
		t.Fatalf("new assistants ask = %v", err)
	}
	p, _ := src.LoadMCPPolicy()
	if !p.Paused || p.ApproveWith != "touchid" || p.ExpiryMinutes != 5 || !p.AskBeforeSecrets || p.NewAssistants != "block" {
		t.Fatalf("settings after refused loosening = %+v", p)
	}

	if _, err := src.AllowMCPAssistant("Claude Code", "claude-code", "claude-code", nil); err != nil {
		t.Fatal(err)
	}
	for _, mode := range []string{"always", "1h"} {
		if err := setMCPBypass("Claude Code", mode); err != errMCPNeedsTerminal {
			t.Fatalf("bypass %s = %v", mode, err)
		}
	}
	if err := setMCPBypass("Claude Code", "ask"); err != nil {
		t.Fatalf("bypass ask: %v", err)
	}
	if err := setMCPBypass("Nobody", "ask"); err == nil {
		t.Fatal("bypass for an unknown assistant succeeded")
	}
	if err := setMCPBypass("Claude Code", "sometimes"); err == nil {
		t.Fatal("unknown bypass mode accepted")
	}
	list, _ := src.ListMCPAssistants()
	if len(list) != 1 || list[0].BypassActive(time.Now()) {
		t.Fatalf("assistant after refused bypass = %+v", list)
	}
}
