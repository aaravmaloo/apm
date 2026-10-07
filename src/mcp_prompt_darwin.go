//go:build darwin

package apm

import (
	"bytes"
	"embed"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"html/template"
	"io"
	"math"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"
	"unicode/utf8"
)

// pm's own approval prompt, for when the APM app isn't running: a JXA helper
// (mcpprompt/prompt.js, run with osascript like the Touch ID check in
// src/touchid) shows the approval sheet in a WKWebView on a floating,
// non-activating panel and arms Touch ID in place over its glyph. pm renders
// the page from the transaction, passes its settings to the helper in the
// APM_PROMPT environment variable and kills the helper once the request is
// answered somewhere else.

//go:embed mcpprompt
var mcpPromptAssets embed.FS

const (
	mcpPromptEnv      = "APM_PROMPT"
	mcpPromptDebugEnv = "APM_PROMPT_DEBUG"
	mcpPromptPoll     = 500 * time.Millisecond
	mcpPromptSecret   = "••••••"
	mcpPromptMaxValue = 160
)

func init() {
	runApprovalPrompt = showApprovalPrompt
}

// One prompt at a time: requests that arrive together queue up, oldest first.
var approvalPromptMu sync.Mutex

// showApprovalPrompt shows the approval panel for tx and blocks until the
// user answers. ok is false when the panel couldn't be shown, the request
// expired, or it stopped being pending elsewhere (the panel is then closed).
func showApprovalPrompt(tx MCPTransaction) (approve bool, via string, ok bool) {
	approvalPromptMu.Lock()
	defer approvalPromptMu.Unlock()
	if !mcpTxStillPending(tx) {
		return false, "", false
	}

	page, err := renderApprovalPage(tx, time.Now())
	if err != nil {
		return false, "", false
	}
	script, err := mcpPromptAssets.ReadFile("mcpprompt/prompt.js")
	if err != nil {
		return false, "", false
	}
	dir, err := os.MkdirTemp("", "apm-approval-*")
	if err != nil {
		return false, "", false
	}
	defer os.RemoveAll(dir)
	pagePath := filepath.Join(dir, "page.html")
	scriptPath := filepath.Join(dir, "prompt.js")
	if os.WriteFile(pagePath, []byte(page), 0600) != nil || os.WriteFile(scriptPath, script, 0600) != nil {
		return false, "", false
	}

	debug := os.Getenv(mcpPromptDebugEnv) == "1"
	settings, err := json.Marshal(map[string]any{
		"page":        pagePath,
		"reason":      mcpPromptReason(tx),
		"approveWith": tx.ApproveWith,
		"debug":       debug,
	})
	if err != nil {
		return false, "", false
	}

	var out bytes.Buffer
	cmd := exec.Command("osascript", "-l", "JavaScript", scriptPath)
	cmd.Env = append(os.Environ(), mcpPromptEnv+"="+string(settings))
	cmd.Stdout = &out
	// pm mcp serve speaks JSON-RPC on stdout, so the helper never writes there.
	cmd.Stderr = io.Discard
	if debug {
		cmd.Stderr = os.Stderr
	}
	if err := cmd.Start(); err != nil {
		return false, "", false
	}
	done := make(chan error, 1)
	go func() { done <- cmd.Wait() }()

	tick := time.NewTicker(mcpPromptPoll)
	defer tick.Stop()
	for {
		select {
		case err := <-done:
			if debug {
				fmt.Fprintf(os.Stderr, "apm-prompt: helper said %q (%v)\n", strings.TrimSpace(out.String()), err)
			}
			if err != nil {
				return false, "", false
			}
			return parseApprovalAnswer(out.String())
		case <-tick.C:
			if !mcpTxStillPending(tx) {
				_ = cmd.Process.Kill()
				<-done
				return false, "", false
			}
		}
	}
}

// mcpTxStillPending reports whether tx still waits for an answer. A store
// that can't be read right now (another process is writing it) counts as
// pending; the next poll looks again.
func mcpTxStillPending(tx MCPTransaction) bool {
	if time.Now().After(tx.ExpiresAt) {
		return false
	}
	cur, err := GetMCPTransaction(tx.ID)
	if errors.Is(err, ErrMCPTxNotFound) || errors.Is(err, ErrMCPTxExpired) {
		return false
	}
	if err != nil {
		return true
	}
	return cur.Status == MCPTxPending
}

// parseApprovalAnswer reads the helper's one-line answer, e.g. "approve touchid".
func parseApprovalAnswer(out string) (approve bool, via string, ok bool) {
	lines := strings.Split(strings.TrimSpace(out), "\n")
	f := strings.Fields(lines[len(lines)-1])
	if len(f) != 2 {
		return false, "", false
	}
	switch f[1] {
	case "touchid", "click", "keyboard":
	default:
		return false, "", false
	}
	switch f[0] {
	case "approve":
		return true, f[1], true
	case "reject":
		return false, f[1], true
	}
	return false, "", false
}

// ---------- the page ----------

type mcpPromptType struct {
	label string // the card's subtitle
	noun  string // in a sentence: "A new <noun> in Work."
	icon  string
}

// The vault item types an MCP client can name, with the labels and icons the
// app uses for them (GUI renderer/src/lib/types.js).
var mcpPromptTypes = map[string]mcpPromptType{
	"password":      {"Login", "login", "globe"},
	"totp":          {"Authenticator", "authenticator", "timer"},
	"token":         {"Token", "token", "ticket"},
	"note":          {"Secure note", "secure note", "sticky-note"},
	"api_key":       {"API key", "API key", "key-round"},
	"ssh_key":       {"SSH key", "SSH key", "key-square"},
	"wifi":          {"Wi-Fi network", "Wi-Fi network", "wifi"},
	"recovery_code": {"Recovery codes", "set of recovery codes", "life-buoy"},
	"certificate":   {"Certificate", "certificate", "file-key"},
	"banking":       {"Card or account", "card or account", "credit-card"},
	"document":      {"Document", "document", "file-lock-2"},
	"gov_id":        {"Government ID", "government ID", "id-card"},
	"medical":       {"Medical record", "medical record", "heart-pulse"},
	"travel":        {"Travel", "travel item", "plane"},
	"contact":       {"Contact", "contact", "contact"},
	"cloud":         {"Cloud credentials", "cloud credential", "cloud"},
	"k8s_secret":    {"Kubernetes", "Kubernetes secret", "ship-wheel"},
	"docker":        {"Docker registry", "Docker registry", "container"},
	"ssh_config":    {"SSH host", "SSH host", "server"},
	"cicd":          {"CI/CD secret", "CI/CD secret", "workflow"},
	"license":       {"Software license", "software license", "award"},
	"contract":      {"Legal contract", "legal contract", "scale"},
	"audio":         {"Audio", "audio file", "music"},
	"video":         {"Video", "video", "video"},
	"photo":         {"Photo", "photo", "image"},
}

// Words that keep their capitals in a field label.
var mcpPromptLabelWords = map[string]string{
	"id": "ID", "ip": "IP", "url": "URL", "ssid": "SSID", "cvv": "CVV", "ssh": "SSH", "env": "Environment",
}

type approvalRow struct {
	Label  string
	Value  string
	Secret bool
	Badge  string
}

type approvalPage struct {
	CSS          template.CSS
	Script       template.JS
	Mark         template.URL
	CloseIcon    template.HTML
	Icon         template.HTML
	Title        string
	Subtitle     string
	Token        string
	TTL          string
	ExpiresMS    int64
	Name         string
	TypeLabel    string
	Rows         []approvalRow
	Caption      string
	DoneLabel    string
	Verb         string
	ApproveLabel string
	Danger       bool
	RejectLabel  string
	RejectVerb   string
	// RejectedLabel is the caption while the sheet leaves after a no.
	RejectedLabel string
	// Connect requests pair an assistant: the meta line names the client
	// and its version instead of a token.
	Connect bool
	Version string
	// TouchOnly: only a touch approves while the Mac has Touch ID (MCP
	// settings "approve with Touch ID"); the page disables Approve and says
	// "Touch ID required".
	TouchOnly bool

	iconName string
}

type mcpPromptArg struct {
	key   string
	value any
}

// renderApprovalPage renders the approval sheet for tx as a self-contained
// HTML page: design tokens, Geist fonts and scripts inlined, secrets masked.
func renderApprovalPage(tx MCPTransaction, now time.Time) (string, error) {
	assets := func(name string) (string, error) {
		b, err := mcpPromptAssets.ReadFile("mcpprompt/" + name)
		return string(b), err
	}
	tmplSrc, err := assets("page.html")
	if err != nil {
		return "", err
	}
	tokens, err := assets("tokens.css")
	if err != nil {
		return "", err
	}
	for _, font := range []string{"Geist-Variable.woff2", "GeistMono-Variable.woff2"} {
		b, err := mcpPromptAssets.ReadFile("mcpprompt/fonts/" + font)
		if err != nil {
			return "", err
		}
		uri := "data:font/woff2;base64," + base64.StdEncoding.EncodeToString(b)
		tokens = strings.ReplaceAll(tokens, `"fonts/`+font+`"`, `"`+uri+`"`)
	}
	sheet, err := assets("sheet.css")
	if err != nil {
		return "", err
	}
	glyph, err := assets("touchid.js")
	if err != nil {
		return "", err
	}
	logic, err := assets("approval.js")
	if err != nil {
		return "", err
	}
	mark, err := mcpPromptAssets.ReadFile("mcpprompt/apm-mark-white.svg")
	if err != nil {
		return "", err
	}
	iconsJSON, err := mcpPromptAssets.ReadFile("mcpprompt/icons.json")
	if err != nil {
		return "", err
	}
	var icons map[string]string
	if err := json.Unmarshal(iconsJSON, &icons); err != nil {
		return "", err
	}
	svg := func(name string) template.HTML {
		return template.HTML(`<svg xmlns="http://www.w3.org/2000/svg" width="16" height="16" viewBox="0 0 24 24" fill="none" ` +
			`stroke="currentColor" stroke-width="1.75" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">` +
			icons[name] + `</svg>`)
	}

	page := approvalView(tx, now)
	page.CSS = template.CSS(tokens + "\n" + sheet)
	page.Script = template.JS(glyph + "\n" + logic)
	page.Mark = template.URL("data:image/svg+xml;base64," + base64.StdEncoding.EncodeToString(mark))
	page.CloseIcon = svg("x")
	page.Icon = svg(page.iconName)

	tmpl, err := template.New("page").Parse(tmplSrc)
	if err != nil {
		return "", err
	}
	var buf bytes.Buffer
	if err := tmpl.Execute(&buf, page); err != nil {
		return "", err
	}
	return buf.String(), nil
}

// approvalView is the sheet's copy for tx. renderApprovalPage adds the
// styles, scripts and icons.
func approvalView(tx MCPTransaction, now time.Time) approvalPage {
	client := mcpPromptClient(tx)
	args := mcpPromptArgs(tx.Args)
	var name, space, typ string
	for _, a := range args {
		switch a.key {
		case "name":
			name = mcpPromptString(a.value)
		case "space":
			space = mcpPromptString(a.value)
		case "type":
			typ = mcpPromptString(a.value)
		}
	}
	kind, known := mcpPromptTypes[typ]
	if !known {
		kind = mcpPromptType{"Vault item", "item", "file"}
	}
	if strings.TrimSpace(name) == "" {
		name = "Untitled"
	}

	p := approvalPage{
		Token:         client,
		Name:          name,
		TypeLabel:     kind.label,
		iconName:      kind.icon,
		Caption:       "Touch ID to approve",
		DoneLabel:     "Approved",
		Verb:          "approve",
		ApproveLabel:  "Approve",
		RejectLabel:   "Reject",
		RejectVerb:    "reject",
		RejectedLabel: "Rejected",
		ExpiresMS:     tx.ExpiresAt.UnixMilli(),
		TTL:           mcpPromptTTL(tx.ExpiresAt.Sub(now)),
		TouchOnly:     tx.ApproveWith == MCPApproveTouchID,
	}
	if IsMCPReadTool(tx.Tool) {
		return readView(p, tx, args)
	}
	badge := ""
	switch tx.Tool {
	case "add_entry":
		p.Title = fmt.Sprintf("%s wants to add “%s”", client, name)
		p.Subtitle = "A new " + kind.noun + "."
		if space != "" {
			p.Subtitle = fmt.Sprintf("A new %s in %s.", kind.noun, space)
		}
	case "edit_entry":
		p.Title = fmt.Sprintf("%s wants to change “%s”", client, name)
		p.Subtitle = "It will change this " + kind.noun + "."
		badge = "Changed"
	case "delete_entry":
		p.Title = fmt.Sprintf("%s wants to delete “%s”", client, name)
		p.Subtitle = "You can undo this in History."
		p.Caption = "Touch ID to delete"
		p.DoneLabel = "Deleted"
		p.Verb = "delete"
		p.ApproveLabel = "Delete"
		p.Danger = true
		if !known {
			p.iconName = "trash-2"
		}
	case "connect":
		return connectView(p, tx, args)
	default:
		p.Title = client + " wants to make a change"
		p.Subtitle = tx.Preview
	}

	for _, a := range args {
		switch a.key {
		case "tx_id", "approve", "type", "name", "space":
			continue
		}
		row := approvalRow{Label: mcpPromptLabel(a.key), Badge: badge}
		if IsMCPSecretArg(a.key) {
			if mcpPromptString(a.value) == "" {
				continue
			}
			row.Value, row.Secret = mcpPromptSecret, true
		} else {
			row.Value = mcpPromptString(a.value)
			if row.Value == "" {
				continue
			}
			if utf8.RuneCountInString(row.Value) > mcpPromptMaxValue {
				row.Value = string([]rune(row.Value)[:mcpPromptMaxValue-1]) + "…"
			}
		}
		p.Rows = append(p.Rows, row)
	}
	if space != "" {
		p.Rows = append(p.Rows, approvalRow{Label: "Space", Value: space})
	}
	return p
}

// connectView is the copy for a connect request: an assistant asking to be
// paired with the vault, with one row per kind of access it gets.
func connectView(p approvalPage, tx MCPTransaction, args []mcpPromptArg) approvalPage {
	client := mcpPromptClient(tx)
	p.Connect = true
	p.Title = client + " wants to use your vault"
	p.Subtitle = "It can read your items and ask to change them. You approve every change."
	p.Name = client
	p.TypeLabel = "AI assistant"
	p.iconName = "bot"
	p.Caption = "Touch ID to allow"
	p.DoneLabel = "Allowed"
	p.Verb = "allow"
	p.ApproveLabel = "Allow"
	p.RejectLabel = "Don't allow"
	p.RejectVerb = "decline"
	p.RejectedLabel = "Not allowed"
	for _, a := range args {
		switch a.key {
		case "version":
			p.Version = mcpPromptString(a.value)
		case "access":
			list, _ := a.value.([]any)
			for _, e := range list {
				if s := mcpPromptString(e); s != "" {
					p.Rows = append(p.Rows, approvalRow{Label: s, Value: "Allowed"})
				}
			}
		}
	}
	return p
}

// readView is the copy for a read request (MCP settings "ask before
// secrets"): an assistant asking to see an item's secrets, a 2FA code, or
// everything a search matches. The card shows what it named; no field rows.
func readView(p approvalPage, tx MCPTransaction, args []mcpPromptArg) approvalPage {
	client := mcpPromptClient(tx)
	var name, path, category, query string
	for _, a := range args {
		switch a.key {
		case "name":
			name = mcpPromptString(a.value)
		case "path":
			path = mcpPromptString(a.value)
		case "category", "type":
			category = mcpPromptString(a.value)
		case "query":
			query = mcpPromptString(a.value)
		}
	}
	if strings.TrimSpace(name) == "" {
		name = path
	}
	name = mcpPromptClip(strings.TrimSpace(name))
	if name == "" {
		name = "Untitled"
	}
	p.Caption = "Touch ID to allow"
	p.DoneLabel = "Allowed"
	p.Verb = "allow"
	p.ApproveLabel = "Allow"
	p.RejectLabel = "Don't allow"
	p.RejectVerb = "decline"
	p.RejectedLabel = "Not allowed"
	p.Rows = nil
	p.Danger = false
	p.iconName = "key-round"
	p.Name = name
	p.TypeLabel = "Vault item"
	if kind, ok := mcpPromptTypes[category]; ok {
		p.TypeLabel = kind.label
	}
	switch tx.Tool {
	case "search_vault":
		query = mcpPromptClip(strings.TrimSpace(query))
		p.Title = client + " wants to search your vault"
		p.Subtitle = fmt.Sprintf("It will see the full contents of every item that matches “%s”.", query)
		p.Name = query
		if p.Name == "" {
			p.Name = "Everything"
		}
		p.TypeLabel = "Search"
		p.iconName = "lock"
	case "get_totp":
		p.Title = fmt.Sprintf("%s wants a 2FA code for “%s”", client, name)
		p.Subtitle = "It will see this item's secrets."
		p.TypeLabel = "2FA code"
	default: // get_entry, decrypt_entry
		p.Title = fmt.Sprintf("%s wants to read “%s”", client, name)
		p.Subtitle = "It will see this item's secrets."
	}
	return p
}

// mcpPromptReason is the reason pm's helper gives LocalAuthentication.
func mcpPromptReason(tx MCPTransaction) string {
	client := mcpPromptClient(tx)
	switch {
	case tx.Tool == MCPConnectTool:
		return "allow " + client + " to use your vault"
	case tx.Tool == "search_vault":
		return "allow " + client + " to search your vault"
	case IsMCPReadTool(tx.Tool):
		return "allow " + client + " to read a secret"
	}
	return "approve a change from " + client
}

func mcpPromptClip(s string) string {
	if utf8.RuneCountInString(s) > 80 {
		return string([]rune(s)[:79]) + "…"
	}
	return s
}

func mcpPromptClient(tx MCPTransaction) string {
	if c := strings.TrimSpace(tx.TokenName); c != "" {
		return c
	}
	return "An agent"
}

// mcpPromptArgs decodes the tool arguments, keeping the order the client sent.
func mcpPromptArgs(raw json.RawMessage) []mcpPromptArg {
	dec := json.NewDecoder(bytes.NewReader(raw))
	if t, err := dec.Token(); err != nil || t != json.Delim('{') {
		return nil
	}
	var args []mcpPromptArg
	for dec.More() {
		t, err := dec.Token()
		if err != nil {
			break
		}
		key, _ := t.(string)
		var v any
		if err := dec.Decode(&v); err != nil {
			break
		}
		args = append(args, mcpPromptArg{key: key, value: v})
	}
	return args
}

func mcpPromptString(v any) string {
	switch t := v.(type) {
	case nil:
		return ""
	case string:
		return t
	case bool:
		if t {
			return "Yes"
		}
		return "No"
	case float64:
		return strconv.FormatFloat(t, 'f', -1, 64)
	case []any:
		parts := make([]string, 0, len(t))
		for _, e := range t {
			if s := mcpPromptString(e); s != "" {
				parts = append(parts, s)
			}
		}
		return strings.Join(parts, ", ")
	default:
		b, _ := json.Marshal(t)
		return string(b)
	}
}

// mcpPromptLabel turns a field name into a label: "router_ip" -> "Router IP".
func mcpPromptLabel(key string) string {
	if key == "token_val" {
		return "Token"
	}
	words := strings.Fields(strings.ReplaceAll(key, "_", " "))
	for i, w := range words {
		if up, ok := mcpPromptLabelWords[w]; ok {
			words[i] = up
		} else if i == 0 {
			words[i] = strings.ToUpper(w[:1]) + w[1:]
		}
	}
	return strings.Join(words, " ")
}

func mcpPromptTTL(left time.Duration) string {
	sec := int(math.Ceil(left.Seconds()))
	if sec < 0 {
		sec = 0
	}
	return fmt.Sprintf("%02d:%02d", sec/60, sec%60)
}
