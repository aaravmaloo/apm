package apm

import (
	"bytes"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestMCPAssistantGrants(t *testing.T) {
	isolateMCPState(t)

	if _, err := FindMCPAssistant("claude-code", "claude-code"); !errors.Is(err, ErrMCPAssistantNotFound) {
		t.Fatalf("lookup in an empty store: %v", err)
	}
	a, err := AllowMCPAssistant("Claude Code", "claude-code", "claude-code", nil)
	if err != nil {
		t.Fatalf("AllowMCPAssistant: %v", err)
	}
	if !strings.HasPrefix(a.ID, "asst_") || a.Name != "Claude Code" || a.CreatedAt.IsZero() {
		t.Fatalf("unexpected grant: %+v", a)
	}
	if !reflect.DeepEqual(a.Perms, mustValidPerms(t, DefaultMCPAssistantPerms())) {
		t.Fatalf("new grant perms = %v", a.Perms)
	}
	for _, p := range []string{"manage_profiles", "manage_spaces", "cloud_config", "cloud_sync", "get_history", "get_audit_logs"} {
		if hasPermission(a.Perms, p) {
			t.Fatalf("a new assistant may use %s without the user adding it", p)
		}
	}

	// Allowing the same harness and client again keeps the first grant.
	again, err := AllowMCPAssistant("Other name", "claude-code", "claude-code", []string{"list_vault"})
	if err != nil || again.ID != a.ID || len(again.Perms) != len(a.Perms) {
		t.Fatalf("second allow = %+v (%v)", again, err)
	}
	// A different harness with the same client name is a different grant.
	other, err := AllowMCPAssistant("Cursor", "claude-code", "cursor", nil)
	if err != nil || other.ID == a.ID {
		t.Fatalf("grant for another harness = %+v (%v)", other, err)
	}
	if got, err := FindMCPAssistant("claude-code", "claude-code"); err != nil || got.ID != a.ID {
		t.Fatalf("FindMCPAssistant = %+v (%v)", got, err)
	}

	if _, err := SetMCPAssistantPerms(a.ID, []string{"bogus"}); err == nil {
		t.Fatal("an unknown permission was accepted")
	}
	changed, err := SetMCPAssistantPerms(a.ID, []string{"search_vault", "list_vault", "list_vault"})
	if err != nil || !reflect.DeepEqual(changed.Perms, []string{"list_vault", "search_vault"}) {
		t.Fatalf("SetMCPAssistantPerms = %+v (%v)", changed, err)
	}
	if _, err := SetMCPAssistantPerms("asst_missing", []string{"list_vault"}); !errors.Is(err, ErrMCPAssistantNotFound) {
		t.Fatalf("perms for a missing grant: %v", err)
	}

	now := time.Now()
	if err := TouchMCPAssistant(a.ID, 3, now); err != nil {
		t.Fatal(err)
	}
	if got, _ := GetMCPAssistant(a.ID); got.Uses != 3 || !got.LastUsedAt.Equal(now) {
		t.Fatalf("after touch: %+v", got)
	}

	list, err := ListMCPAssistants()
	if err != nil || len(list) != 2 || list[0].ID != other.ID {
		t.Fatalf("ListMCPAssistants = %+v (%v)", list, err)
	}

	// Revoke by name (any case), then by id.
	if got, ok, err := RevokeMCPAssistant("claude code"); err != nil || !ok || got.ID != a.ID {
		t.Fatalf("revoke by name = %+v %v %v", got, ok, err)
	}
	if _, ok, _ := RevokeMCPAssistant(a.ID); ok {
		t.Fatal("a revoked grant was revoked twice")
	}
	if _, ok, err := RevokeMCPAssistant(other.ID); err != nil || !ok {
		t.Fatalf("revoke by id: %v %v", ok, err)
	}
	if list, _ := ListMCPAssistants(); len(list) != 0 {
		t.Fatalf("grants left after revoking all: %+v", list)
	}
}

func mustValidPerms(t *testing.T, perms []string) []string {
	t.Helper()
	out, err := ValidateMCPToolPerms(perms)
	if err != nil {
		t.Fatal(err)
	}
	return out
}

func TestMCPAssistantConcurrentWrites(t *testing.T) {
	isolateMCPState(t)
	base, err := AllowMCPAssistant("Base", "base", "", nil)
	if err != nil {
		t.Fatal(err)
	}
	const n = 16
	var wg sync.WaitGroup
	errs := make(chan error, 2*n)
	for i := 0; i < n; i++ {
		wg.Add(2)
		go func(i int) {
			defer wg.Done()
			_, err := AllowMCPAssistant(fmt.Sprintf("Assistant %d", i), fmt.Sprintf("client-%d", i), "codex", nil)
			errs <- err
		}(i)
		go func() {
			defer wg.Done()
			errs <- TouchMCPAssistant(base.ID, 1, time.Now())
		}()
	}
	wg.Wait()
	close(errs)
	for err := range errs {
		if err != nil {
			t.Fatalf("concurrent write: %v", err)
		}
	}
	list, err := ListMCPAssistants()
	if err != nil || len(list) != n+1 {
		t.Fatalf("expected %d grants, got %d (%v)", n+1, len(list), err)
	}
	if got, _ := GetMCPAssistant(base.ID); got.Uses != n {
		t.Fatalf("lost updates: uses = %d, want %d", got.Uses, n)
	}
}

func TestMCPConnectTransactionShape(t *testing.T) {
	isolateMCPState(t)
	tx, err := CreateMCPConnectTransaction(MCPConnectArgs{Client: "Claude Code", ClientID: "claude-code", Version: "2.1.0", Harness: "claude-code"}, time.Minute)
	if err != nil {
		t.Fatal(err)
	}
	if tx.Tool != "connect" || tx.TokenName != "Claude Code" || tx.Preview != "Connect Claude Code to APM" || tx.Status != MCPTxPending {
		t.Fatalf("unexpected connect request: %+v", tx)
	}
	var args map[string]any
	if err := json.Unmarshal(tx.Args, &args); err != nil {
		t.Fatal(err)
	}
	want := map[string]any{
		"client": "Claude Code", "client_id": "claude-code", "version": "2.1.0", "harness": "claude-code",
		"access": []any{"Read item names and search", "Read secrets and 2FA codes", "Ask you before every change"},
	}
	if !reflect.DeepEqual(args, want) {
		t.Fatalf("connect args = %v", args)
	}

	// Completing needs an approval, and then makes the grant once.
	if _, ok, _ := CompleteMCPConnect(tx.ID, "serve"); ok {
		t.Fatal("a pending connect request was completed")
	}
	if _, err := DecideMCPTransaction(tx.ID, true, "click"); err != nil {
		t.Fatal(err)
	}
	a, ok, err := CompleteMCPConnect(tx.ID, "desktop")
	if err != nil || !ok || a.Harness != "claude-code" || a.ClientID != "claude-code" {
		t.Fatalf("CompleteMCPConnect = %+v %v %v", a, ok, err)
	}
	if _, ok, _ := CompleteMCPConnect(tx.ID, "serve"); ok {
		t.Fatal("a connect request was completed twice")
	}
	if got, _ := GetMCPTransaction(tx.ID); got.Status != MCPTxCommitted || got.ClaimedBy != "desktop" {
		t.Fatalf("connect request after completing: %+v", got)
	}
}

func TestMCPConfigMergeKeepsOtherServers(t *testing.T) {
	dir, _ := filepath.EvalSymlinks(t.TempDir())
	path := filepath.Join(dir, "mcp.json")
	original := "{\n    \"theme\": \"dark\",\n    \"mcpServers\": {\n        \"other\": {\n            \"command\": \"other-server\",\n            \"args\": [\"--x\"]\n        }\n    },\n    \"zeta\": [1, 2]\n}\n"
	if err := os.WriteFile(path, []byte(original), 0644); err != nil {
		t.Fatal(err)
	}
	entry := json.RawMessage(`{"command":"pm","args":["mcp","serve","--client","cursor"]}`)
	backup, replaced, err := MergeMCPConfigFile(path, "mcpServers", "apm", entry)
	if err != nil || replaced {
		t.Fatalf("merge: replaced=%v err=%v", replaced, err)
	}
	if backup != path+".apm-backup" {
		t.Fatalf("backup path = %q", backup)
	}
	if got, _ := os.ReadFile(backup); string(got) != original {
		t.Fatalf("backup does not hold the original:\n%s", got)
	}
	got, _ := os.ReadFile(path)
	want := "{\n    \"theme\": \"dark\",\n    \"mcpServers\": {\n        \"other\": {\n            \"command\": \"other-server\",\n            \"args\": [\"--x\"]\n        },\n        \"apm\": {\n            \"command\": \"pm\",\n            \"args\": [\n                \"mcp\",\n                \"serve\",\n                \"--client\",\n                \"cursor\"\n            ]\n        }\n    },\n    \"zeta\": [1, 2]\n}\n"
	if string(got) != want {
		t.Fatalf("merged file:\n%s\nwant:\n%s", got, want)
	}
	if st, _ := os.Stat(path); st.Mode().Perm() != 0644 {
		t.Fatalf("file mode changed to %v", st.Mode().Perm())
	}

	// Running it again replaces the entry instead of adding a second one.
	newer := json.RawMessage(`{"command":"pm","args":["mcp","serve"]}`)
	if _, replaced, err := MergeMCPConfigFile(path, "mcpServers", "apm", newer); err != nil || !replaced {
		t.Fatalf("second merge: replaced=%v err=%v", replaced, err)
	}
	var cfg struct {
		MCPServers map[string]struct {
			Args []string `json:"args"`
		} `json:"mcpServers"`
	}
	data, _ := os.ReadFile(path)
	if err := json.Unmarshal(data, &cfg); err != nil {
		t.Fatal(err)
	}
	if len(cfg.MCPServers) != 2 || len(cfg.MCPServers["apm"].Args) != 2 || cfg.MCPServers["other"].Args[0] != "--x" {
		t.Fatalf("after second merge: %+v", cfg)
	}
}

func TestMCPConfigMergeRefusesUnparseableFile(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "settings.json")
	original := "{\n  // comments are not JSON\n  \"servers\": {}\n}\n"
	if err := os.WriteFile(path, []byte(original), 0600); err != nil {
		t.Fatal(err)
	}
	_, _, err := MergeMCPConfigFile(path, "servers", "apm", json.RawMessage(`{"command":"pm"}`))
	if !errors.Is(err, ErrMCPConfigUnparseable) {
		t.Fatalf("expected ErrMCPConfigUnparseable, got %v", err)
	}
	if got, _ := os.ReadFile(path); string(got) != original {
		t.Fatal("an unparseable file was changed")
	}
	if _, err := os.Stat(path + ".apm-backup"); !os.IsNotExist(err) {
		t.Fatal("a backup was written for a file pm did not change")
	}
	for _, bad := range []string{`[1, 2]`, `{"a": 1} {"b": 2}`, `{"servers": 3}`} {
		if err := os.WriteFile(path, []byte(bad), 0600); err != nil {
			t.Fatal(err)
		}
		if _, _, err := MergeMCPConfigFile(path, "servers", "apm", json.RawMessage(`{"command":"pm"}`)); err == nil {
			t.Fatalf("%s was accepted", bad)
		}
		if got, _ := os.ReadFile(path); string(got) != bad {
			t.Fatalf("%s was changed", bad)
		}
	}
}

func TestMCPConfigMergeCreatesFileAndNestedKeys(t *testing.T) {
	dir := t.TempDir()
	path := filepath.Join(dir, "new", "dir", "config.json")
	backup, _, err := MergeMCPConfigFile(path, "mcp/servers", "apm", json.RawMessage(`{"type":"stdio","command":"pm"}`))
	if err != nil || backup != "" {
		t.Fatalf("create: backup=%q err=%v", backup, err)
	}
	got, _ := os.ReadFile(path)
	want := "{\n  \"mcp\": {\n    \"servers\": {\n      \"apm\": {\n        \"type\": \"stdio\",\n        \"command\": \"pm\"\n      }\n    }\n  }\n}\n"
	if string(got) != want {
		t.Fatalf("created file:\n%s", got)
	}
	// An empty file and a null key are treated as empty.
	empty := filepath.Join(dir, "empty.json")
	_ = os.WriteFile(empty, []byte(`{"mcpServers": null}`), 0600)
	if _, _, err := MergeMCPConfigFile(empty, "mcpServers", "apm", json.RawMessage(`{"command":"pm"}`)); err != nil {
		t.Fatal(err)
	}
	if got, _ := os.ReadFile(empty); !bytes.Contains(got, []byte(`"apm": {`)) {
		t.Fatalf("null key not replaced:\n%s", got)
	}
}

// mcpServeWords flattens how a harness starts pm into words: arguments,
// a quoted command line split on spaces, or a JSON server definition.
func mcpServeWords(t *testing.T, parts []string) []string {
	t.Helper()
	var words []string
	for _, p := range parts {
		if strings.HasPrefix(p, "{") {
			var def struct {
				Command any      `json:"command"`
				Args    []string `json:"args"`
			}
			if err := json.Unmarshal([]byte(p), &def); err != nil {
				t.Fatalf("bad JSON argument %q: %v", p, err)
			}
			switch c := def.Command.(type) {
			case string:
				words = append(words, c)
			case []any:
				for _, w := range c {
					words = append(words, w.(string))
				}
			}
			words = append(words, def.Args...)
			continue
		}
		for _, w := range strings.Fields(p) {
			if w != "--" {
				words = append(words, w)
			}
		}
	}
	return words
}

func TestMCPHarnessList(t *testing.T) {
	list := MCPHarnesses()
	if len(list) == 0 {
		t.Fatal("no harnesses")
	}
	seen := map[string]bool{}
	for _, h := range list {
		if h.ID == "" || h.Name == "" || h.Restart == "" || seen[h.ID] {
			t.Fatalf("bad or duplicate harness: %+v", h)
		}
		seen[h.ID] = true
		if got := MCPHarnessName(h.ID); got != h.Name {
			t.Fatalf("MCPHarnessName(%q) = %q", h.ID, got)
		}
		client := h.ID
		if h.AliasOf != "" {
			if _, ok := GetMCPHarness(h.AliasOf); !ok {
				t.Fatalf("%s: alias of unknown %q", h.ID, h.AliasOf)
			}
			client = h.AliasOf
		}
		serve := strings.Join(append([]string{"pm"}, MCPServeArgs(client)...), " ")
		switch h.Kind {
		case "cli":
			if len(h.Argv) == 0 || h.Argv[0] == "pm" || strings.ContainsAny(h.Argv[0], " /\\") {
				t.Fatalf("%s: argv %q", h.ID, h.Argv)
			}
			if got := strings.Join(mcpServeWords(t, h.Argv), " "); !strings.HasSuffix(got, serve) {
				t.Fatalf("%s: argv %q does not start %q", h.ID, h.Argv, serve)
			}
		case "file":
			if got := strings.Join(mcpServeWords(t, []string{string(h.Entry)}), " "); got != serve {
				t.Fatalf("%s: entry %s starts %q, not %q", h.ID, h.Entry, got, serve)
			}
			if h.ConfigKey == "" || len(h.ConfigFiles) == 0 || (h.ConfigFormat != "json" && h.ConfigFormat != "jsonc") {
				t.Fatalf("%s: config %q %q %v", h.ID, h.ConfigFormat, h.ConfigKey, h.ConfigFiles)
			}
			if h.Command() != "pm mcp add "+h.ID {
				t.Fatalf("%s: command = %q", h.ID, h.Command())
			}
		case "deeplink":
			if h.URL == "" || !strings.Contains(h.URL, "://") {
				t.Fatalf("%s: url = %q", h.ID, h.URL)
			}
		default:
			t.Fatalf("%s: unknown kind %q", h.ID, h.Kind)
		}
	}
	if _, ok := GetMCPHarness("nope"); ok {
		t.Fatal("found an unknown harness")
	}
}

func TestMCPEntryWithCommand(t *testing.T) {
	cases := map[string]string{
		`{"command":"pm","args":["mcp","serve"]}`:                        `{"command":"/usr/local/bin/pm","args":["mcp","serve"]}`,
		`{"type":"local","command":["pm","mcp","serve"],"enabled":true}`: `{"type":"local","command":["/usr/local/bin/pm","mcp","serve"],"enabled":true}`,
		`{"command":"other","args":["pm"]}`:                              `{"command":"other","args":["pm"]}`,
	}
	for in, want := range cases {
		got, err := MCPEntryWithCommand(json.RawMessage(in), "/usr/local/bin/pm")
		if err != nil || string(got) != want {
			t.Errorf("MCPEntryWithCommand(%s) = %s (%v), want %s", in, got, err, want)
		}
	}
}

func TestFormatArgv(t *testing.T) {
	cases := map[string][]string{
		"claude mcp add --scope user apm -- pm mcp serve --client claude-code": {"claude", "mcp", "add", "--scope", "user", "apm", "--", "pm", "mcp", "serve", "--client", "claude-code"},
		`code --add-mcp '{"name":"apm","command":"pm"}'`:                       {"code", "--add-mcp", `{"name":"apm","command":"pm"}`},
		`echo 'it'\''s' ''`:       {"echo", "it's", ""},
		`run 'a b' '$HOME' ';rm'`: {"run", "a b", "$HOME", ";rm"},
	}
	for want, argv := range cases {
		if got := FormatArgv(argv); got != want {
			t.Errorf("FormatArgv(%q) = %s, want %s", argv, got, want)
		}
	}
}

func TestExpandMCPConfigPath(t *testing.T) {
	dir := isolateMCPState(t)
	if got := ExpandMCPConfigPath("~/.cursor/mcp.json"); got != filepath.Join(dir, ".cursor", "mcp.json") {
		t.Fatalf("~ expanded to %q", got)
	}
	if got := ExpandMCPConfigPath("%APPDATA%/Claude/c.json"); got != filepath.Join(dir, "AppData", "Claude", "c.json") {
		t.Fatalf("%%APPDATA%% expanded to %q", got)
	}
	if got := ExpandMCPConfigPath("$XDG_CONFIG_HOME/x.json"); got != filepath.Join(dir, ".config", "x.json") {
		t.Fatalf("$XDG_CONFIG_HOME expanded to %q", got)
	}
	if ExpandMCPConfigPath("") != "" {
		t.Fatal("empty path expanded")
	}
}
