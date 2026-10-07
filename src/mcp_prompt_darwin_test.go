//go:build darwin

package apm

import (
	"encoding/json"
	"os"
	"strings"
	"testing"
	"time"
)

func samplePromptTx(tool string, args map[string]any) MCPTransaction {
	raw, _ := json.Marshal(args)
	now := time.Now()
	return MCPTransaction{
		ID:        "tx-sample",
		TokenName: "Claude Code",
		Tool:      tool,
		Args:      raw,
		Preview:   "sample",
		Status:    MCPTxPending,
		CreatedAt: now,
		ExpiresAt: now.Add(15 * time.Minute),
	}
}

func renderPromptForTest(t *testing.T, tx MCPTransaction) string {
	t.Helper()
	html, err := renderApprovalPage(tx, tx.CreatedAt)
	if err != nil {
		t.Fatalf("render: %v", err)
	}
	return html
}

func wantIn(t *testing.T, html string, parts ...string) {
	t.Helper()
	for _, p := range parts {
		if !strings.Contains(html, p) {
			t.Errorf("page is missing %q", p)
		}
	}
}

func TestApprovalPageAddMasksSecrets(t *testing.T) {
	secrets := map[string]string{
		"password": "hunter2-pass", "secret": "otp-seed-xyz", "key": "sk_live_123abc",
		"token_val": "ghp_tokenvalue", "cvv": "cvv-9z7-unique", "secret_key": "aws-secret-key",
		"serial_key": "SERIAL-0001", "content": "my private note", "id_number": "P1234567",
		"details": "acct 0042",
	}
	args := map[string]any{"type": "api_key", "name": "Postmark server token", "space": "Work", "service": "postmark", "router_ip": "10.0.0.1"}
	for k, v := range secrets {
		args[k] = v
	}
	html := renderPromptForTest(t, samplePromptTx("add_entry", args))

	for k, v := range secrets {
		if strings.Contains(html, v) {
			t.Errorf("secret %s leaked into the page", k)
		}
	}
	if n := strings.Count(html, `<span class="mono">••••••</span>`); n != len(secrets) {
		t.Errorf("masked rows = %d, want %d", n, len(secrets))
	}
	wantIn(t, html,
		"Claude Code wants to add “Postmark server token”",
		"A new API key in Work.",
		"via <code>pm mcp serve</code>",
		"token <code>Claude Code</code>",
		`<span id="ttl" class="tnum">15:00</span>`,
		"<dt>Service</dt><dd>postmark</dd>",
		"<dt>Router IP</dt><dd>10.0.0.1</dd>",
		"<dt>Token</dt>",
		"<dt>Space</dt><dd>Work</dd>",
		`data-cap="Touch ID to approve"`,
		`data-done="Approved"`,
		"Press <span class=\"kbd\">Space</span> to approve · <span class=\"kbd\">Esc</span> to reject",
		`class="btn btn-primary" id="approveBtn" type="button">Approve<span`,
		">Reject <span class=\"kbd\">Esc</span>",
		"data:font/woff2;base64,",
		"window.TouchIdGlyph",
	)
	if strings.Contains(html, `"fonts/`) {
		t.Error("page still links a font file instead of inlining it")
	}
}

func TestApprovalPageEditAndDelete(t *testing.T) {
	edit := renderPromptForTest(t, samplePromptTx("edit_entry", map[string]any{
		"type": "password", "name": "Linear", "username": "aarav@maloo.dev", "password": "new-strong-password",
	}))
	wantIn(t, edit,
		"Claude Code wants to change “Linear”",
		"It will change this login.",
		`<span class="mono">••••••</span><span class="badge is-warn">Changed</span>`,
	)
	if strings.Contains(edit, "new-strong-password") {
		t.Error("edit page leaked the new password")
	}

	del := renderPromptForTest(t, samplePromptTx("delete_entry", map[string]any{"name": "Old router"}))
	wantIn(t, del,
		"Claude Code wants to delete “Old router”",
		"You can undo this in History.",
		`data-cap="Touch ID to delete"`,
		`data-done="Deleted"`,
		`class="btn btn-danger" id="approveBtn" type="button">Delete<span`,
		"to delete · <span",
	)
}

func TestApprovalPageConnect(t *testing.T) {
	tx := samplePromptTx("connect", map[string]any{
		"client": "Claude Code", "client_id": "claude-code", "version": "2.1.0", "harness": "claude-code",
		"access": []string{"Read item names and search", "Read secrets and 2FA codes", "Ask you before every change"},
	})
	html := renderPromptForTest(t, tx)
	wantIn(t, html,
		"Claude Code wants to use your vault",
		"It can read your items and ask to change them. You approve every change.",
		"<span>Claude Code 2.1.0</span>",
		`<div class="card-name">Claude Code</div>`,
		`<div class="card-sub">AI assistant</div>`,
		`<dl class="card-rows is-wide">`,
		"<dt>Read item names and search</dt><dd>Allowed</dd>",
		"<dt>Read secrets and 2FA codes</dt><dd>Allowed</dd>",
		"<dt>Ask you before every change</dt><dd>Allowed</dd>",
		`data-cap="Touch ID to allow"`,
		`data-done="Allowed"`,
		`id="approveBtn" type="button">Allow<span`,
		">Don&#39;t allow <span class=\"kbd\">Esc</span>",
	)
	if strings.Contains(html, "token <code>") {
		t.Error("connect page shows a token")
	}
}

func TestApprovalPageReadRequests(t *testing.T) {
	allow := []string{
		`data-cap="Touch ID to allow"`,
		`data-done="Allowed"`,
		`data-rejected="Not allowed"`,
		`id="approveBtn" type="button">Allow<span`,
		">Don&#39;t allow <span class=\"kbd\">Esc</span>",
		"to allow · <span class=\"kbd\">Esc</span> to decline",
		"token <code>Claude Code</code>",
	}
	cases := []struct {
		tool string
		args map[string]any
		want []string
	}{
		{"get_entry", map[string]any{"name": "GitHub", "category": "password"}, []string{
			"Claude Code wants to read “GitHub”", "It will see this item&#39;s secrets.",
			`<div class="card-name">GitHub</div>`, `<div class="card-sub">Login</div>`,
		}},
		{"get_entry", map[string]any{"name": "Stripe"}, []string{
			"Claude Code wants to read “Stripe”", `<div class="card-sub">Vault item</div>`,
		}},
		{"decrypt_entry", map[string]any{"name": "Prod database"}, []string{
			"Claude Code wants to read “Prod database”", "It will see this item&#39;s secrets.",
		}},
		{"get_totp", map[string]any{"name": "GitHub"}, []string{
			"Claude Code wants a 2FA code for “GitHub”", "It will see this item&#39;s secrets.",
			`<div class="card-sub">2FA code</div>`,
		}},
		{"search_vault", map[string]any{"query": "github"}, []string{
			"Claude Code wants to search your vault",
			"It will see the full contents of every item that matches “github”.",
			`<div class="card-name">github</div>`, `<div class="card-sub">Search</div>`,
		}},
	}
	for _, c := range cases {
		html := renderPromptForTest(t, samplePromptTx(c.tool, c.args))
		wantIn(t, html, append(c.want, allow...)...)
		if strings.Contains(html, `<dl class="card-rows`) {
			t.Errorf("%s page shows field rows", c.tool)
		}
		if strings.Contains(html, `class="btn btn-danger" id="approveBtn"`) || strings.Contains(html, ` data-approve-with="touchid">`) || strings.Contains(html, `id="approveHint" hidden>`) {
			t.Errorf("%s page has the wrong approve button state", c.tool)
		}
	}
	icon := func(tool string, args map[string]any) string {
		raw, _ := json.Marshal(args)
		tx := samplePromptTx(tool, nil)
		tx.Args = raw
		return approvalView(tx, tx.CreatedAt).iconName
	}
	if got := icon("get_entry", map[string]any{"name": "GitHub"}); got != "key-round" {
		t.Errorf("get_entry icon = %q, want key-round", got)
	}
	if got := icon("search_vault", map[string]any{"query": "x"}); got != "lock" {
		t.Errorf("search_vault icon = %q, want lock", got)
	}
	for tool, want := range map[string]string{
		"get_entry":    "allow Claude Code to read a secret",
		"get_totp":     "allow Claude Code to read a secret",
		"search_vault": "allow Claude Code to search your vault",
		"connect":      "allow Claude Code to use your vault",
		"add_entry":    "approve a change from Claude Code",
	} {
		if got := mcpPromptReason(samplePromptTx(tool, nil)); got != want {
			t.Errorf("reason for %s = %q, want %q", tool, got, want)
		}
	}
}

func TestApprovalPageTouchIDOnly(t *testing.T) {
	for _, tool := range []string{"add_entry", "delete_entry", "connect", "get_entry"} {
		tx := samplePromptTx(tool, map[string]any{"type": "api_key", "name": "Postmark server token"})
		tx.ApproveWith = MCPApproveTouchID
		html := renderPromptForTest(t, tx)
		wantIn(t, html,
			` data-approve-with="touchid">`,
			`<span class="foot-hint" id="approveHint" hidden>Touch ID required</span>`,
			"function syncApprove()",
		)
		// The page disables Approve itself, and only while Touch ID is there.
		if strings.Contains(html, `id="approveBtn" type="button" disabled`) {
			t.Errorf("%s: Approve is disabled in the markup, before the page knows about Touch ID", tool)
		}
	}
	tx := samplePromptTx("add_entry", map[string]any{"name": "x"})
	tx.ApproveWith = MCPApproveAny
	html := renderPromptForTest(t, tx)
	if strings.Contains(html, ` data-approve-with="touchid">`) || strings.Contains(html, `id="approveHint" hidden>`) {
		t.Error("an approve-with any request has the Touch ID only state")
	}
}

func TestApprovalPageEscapesClientText(t *testing.T) {
	tx := samplePromptTx("add_entry", map[string]any{"type": "note", "name": "<script>alert(1)</script>"})
	tx.TokenName = `<img src=x onerror=alert(1)>`
	html := renderPromptForTest(t, tx)
	if strings.Contains(html, "<script>alert(1)") || strings.Contains(html, "<img src=x") {
		t.Error("client-controlled text reached the page unescaped")
	}
}

func TestParseApprovalAnswer(t *testing.T) {
	cases := []struct {
		out     string
		approve bool
		via     string
		ok      bool
	}{
		{"approve touchid\n", true, "touchid", true},
		{"reject keyboard", false, "keyboard", true},
		{"approve click", true, "click", true},
		{"expired", false, "", false},
		{"error: no approval page", false, "", false},
		{"approve dialog", false, "", false},
		{"", false, "", false},
	}
	for _, c := range cases {
		a, v, ok := parseApprovalAnswer(c.out)
		if a != c.approve || v != c.via || ok != c.ok {
			t.Errorf("parseApprovalAnswer(%q) = %v %q %v", c.out, a, v, ok)
		}
	}
}

// TestApprovalPromptSmoke shows the real panel. It runs only with
// APM_PROMPT_SMOKE set, against a request store in a throwaway HOME:
//
//	APM_PROMPT_SMOKE=answer   waits for an answer (Esc, Space, a click, Touch ID)
//	APM_PROMPT_SMOKE=resolve  resolves the request elsewhere after 4s and checks
//	                          that the panel closes itself
//
// APM_PROMPT_SMOKE_TOOL picks the request (add_entry by default; connect,
// get_entry, get_totp, search_vault ...) and APM_PROMPT_SMOKE_APPROVE_WITH=touchid
// makes it a Touch ID only one. APM_PROMPT_DEBUG=1 logs the helper's Touch ID
// steps to stderr.
//
// APM_PROMPT_DUMP=<file> writes the rendered page there instead, to open it
// in a browser.
func TestApprovalPromptSmoke(t *testing.T) {
	if path := os.Getenv("APM_PROMPT_DUMP"); path != "" {
		tool := os.Getenv("APM_PROMPT_SMOKE_TOOL")
		args := map[string]any{"type": "api_key", "name": "Postmark server token", "space": "Work", "service": "postmark", "key": "sk_live_123"}
		switch tool {
		case "":
			tool = "add_entry"
		case "get_entry", "decrypt_entry", "get_totp":
			args = map[string]any{"name": "GitHub", "category": "password"}
		case "search_vault":
			args = map[string]any{"query": "github"}
		}
		tx := samplePromptTx(tool, args)
		tx.ApproveWith = os.Getenv("APM_PROMPT_SMOKE_APPROVE_WITH")
		html := renderPromptForTest(t, tx)
		if err := os.WriteFile(path, []byte(html), 0600); err != nil {
			t.Fatal(err)
		}
		return
	}
	mode := os.Getenv("APM_PROMPT_SMOKE")
	if mode == "" {
		t.Skip("set APM_PROMPT_SMOKE=answer or resolve to show the real panel")
	}
	t.Setenv("HOME", t.TempDir())
	tool := os.Getenv("APM_PROMPT_SMOKE_TOOL")
	if tool == "" {
		tool = "add_entry"
	}
	args := map[string]any{"type": "api_key", "name": "Postmark server token", "space": "Work", "service": "postmark", "key": "sk_live_123"}
	switch tool {
	case "connect":
		args = map[string]any{"client": "Claude Code", "version": "2.1.0", "access": []string{"Read item names and search", "Ask you before every change"}}
	case "get_entry", "decrypt_entry", "get_totp":
		args = map[string]any{"name": "GitHub"}
	case "search_vault":
		args = map[string]any{"query": "github"}
	}
	if w := os.Getenv("APM_PROMPT_SMOKE_APPROVE_WITH"); w != "" {
		p := DefaultMCPPolicy()
		p.ApproveWith = w
		if err := SaveMCPPolicy(p); err != nil {
			t.Fatalf("policy: %v", err)
		}
	}
	raw, _ := json.Marshal(args)
	tx, err := CreateMCPTransaction("Claude Code", tool, raw, "smoke test", 15*time.Minute)
	if err != nil {
		t.Fatalf("create: %v", err)
	}

	if mode == "resolve" {
		go func() {
			time.Sleep(4 * time.Second)
			if _, err := DecideMCPTransaction(tx.ID, false, "app"); err != nil {
				t.Errorf("decide: %v", err)
			}
		}()
	}
	start := time.Now()
	approve, via, ok := showApprovalPrompt(tx)
	t.Logf("approve=%v via=%q ok=%v after %s", approve, via, ok, time.Since(start).Round(time.Millisecond))
	if mode == "resolve" {
		if ok {
			t.Fatal("the panel answered instead of closing when the request was resolved")
		}
		if d := time.Since(start); d < 3*time.Second || d > 6*time.Second {
			t.Fatalf("the panel closed after %s, want about 4s", d)
		}
	}
}
