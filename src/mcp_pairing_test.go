package apm

import (
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

// startPairedServe starts pm mcp serve --client harness (no token) for an
// MCP client that calls itself clientName, over an in-memory transport. The
// vault and pm unlock session are set up the way startMCPServe does.
func startPairedServe(t *testing.T, dir, harness, clientName string) *mcpServeHarness {
	t.Helper()
	vaultPath := filepath.Join(dir, "vault.dat")
	if _, err := os.Stat(vaultPath); os.IsNotExist(err) {
		v := &Vault{Profile: "standard", Spaces: []string{"default"}}
		if err := v.AddEntry("existing", "me", "pw-existing"); err != nil {
			t.Fatal(err)
		}
		data, err := EncryptVault(v, mcpTestPassword)
		if err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(vaultPath, data, 0600); err != nil {
			t.Fatal(err)
		}
		if err := CreateSession(mcpTestPassword, time.Hour, false, 0); err != nil {
			t.Fatalf("CreateSession: %v", err)
		}
		t.Cleanup(func() { _ = KillSession() })
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverT, clientT := mcp.NewInMemoryTransports()
	go func() { _ = ServeMCP(MCPServeOptions{Harness: harness}, vaultPath, serverT) }()
	client := mcp.NewClient(&mcp.Implementation{Name: clientName, Version: "2.1.0"}, nil)
	session, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return &mcpServeHarness{t: t, ctx: ctx, session: session, vaultPath: vaultPath}
}

// pendingConnect waits for the connect request a new client makes.
func (h *mcpServeHarness) pendingConnect() MCPTransaction {
	h.t.Helper()
	tx := h.pendingTx()
	if tx.Tool != MCPConnectTool {
		h.t.Fatalf("pending request is %s, not connect", tx.Tool)
	}
	return tx
}

func (h *mcpServeHarness) call(tool string, args map[string]any) mcpCallResult {
	h.t.Helper()
	return h.wait(h.callAsync(tool, args))
}

func TestMCPPairingApproveAllowsTools(t *testing.T) {
	dir := isolateMCPState(t)
	h := startPairedServe(t, dir, "claude-code", "claude-code")

	// A call made before the user answers waits for the answer.
	early := h.callAsync("generate_password", map[string]any{"length": 12})
	tx := h.pendingConnect()
	if tx.TokenName != "Claude Code" || tx.Preview != "Connect Claude Code to APM" {
		t.Fatalf("connect request = %+v", tx)
	}
	select {
	case r := <-early:
		t.Fatalf("a tool ran before the assistant was allowed: %+v", r)
	case <-time.After(300 * time.Millisecond):
	}
	if _, err := DecideMCPTransaction(tx.ID, true, "touchid"); err != nil {
		t.Fatal(err)
	}
	if r := h.wait(early); r.isError || len(r.text) != 12 {
		t.Fatalf("generate_password after allowing = %+v", r)
	}
	g, err := FindMCPAssistant("claude-code", "claude-code")
	if err != nil || g.Name != "Claude Code" {
		t.Fatalf("no grant after allowing: %+v (%v)", g, err)
	}
	if got, _ := GetMCPTransaction(tx.ID); got.Status != MCPTxCommitted || got.ClaimedBy != "serve" {
		t.Fatalf("connect request after allowing: %+v", got)
	}
	if r := h.call("list_vault", nil); r.isError || !strings.Contains(r.text, "existing") {
		t.Fatalf("list_vault = %+v", r)
	}

	// A write request carries the assistant's name.
	call := h.callAsync("add_entry", map[string]any{"type": "password", "name": "paired", "password": "pw-paired"})
	wtx := h.pendingTx()
	if wtx.Tool != "add_entry" || wtx.TokenName != "Claude Code" {
		t.Fatalf("write request = %+v", wtx)
	}
	if _, err := DecideMCPTransaction(wtx.ID, true, "click"); err != nil {
		t.Fatal(err)
	}
	if r := h.wait(call); r.isError || !strings.HasPrefix(r.text, `Approved. Added "paired".`) {
		t.Fatalf("add_entry = %+v", r)
	}

	// The next session of the same assistant is allowed without asking.
	h.session.Close()
	h2 := startPairedServe(t, dir, "claude-code", "claude-code")
	if r := h2.call("generate_password", map[string]any{"length": 8}); r.isError || len(r.text) != 8 {
		t.Fatalf("second session = %+v", r)
	}
	txs, _ := ListMCPTransactions(0)
	for _, tx := range txs {
		if tx.Tool == MCPConnectTool && tx.Status == MCPTxPending {
			t.Fatal("a known assistant was asked again")
		}
	}
}

func TestMCPPairingRejectDenies(t *testing.T) {
	dir := isolateMCPState(t)
	h := startPairedServe(t, dir, "cursor", "cursor-vscode")
	tx := h.pendingConnect()
	if tx.TokenName != MCPHarnessName("cursor") {
		t.Fatalf("display name = %q", tx.TokenName)
	}
	if _, err := DecideMCPTransaction(tx.ID, false, "keyboard"); err != nil {
		t.Fatal(err)
	}
	want := "APM didn't allow Cursor. Ask again by restarting Cursor."
	for _, tool := range []string{"list_vault", "generate_password"} {
		if r := h.call(tool, nil); !r.isError || r.text != want {
			t.Fatalf("%s after rejecting = %+v", tool, r)
		}
	}
	if _, err := FindMCPAssistant("cursor", "cursor-vscode"); err == nil {
		t.Fatal("a rejected assistant has a grant")
	}
}

func TestMCPPairingExpiryDenies(t *testing.T) {
	dir := isolateMCPState(t)
	setMCPApprovalWait(t, 400*time.Millisecond)
	// An unknown harness falls back to the client's own name.
	h := startPairedServe(t, dir, "", "some-agent")
	tx := h.pendingConnect()
	if tx.TokenName != "some-agent" {
		t.Fatalf("display name = %q", tx.TokenName)
	}
	if r := h.call("generate_password", nil); !r.isError || r.text != "APM didn't allow some-agent. Ask again by restarting some-agent." {
		t.Fatalf("after expiry = %+v", r)
	}
}

func TestMCPPairingRevokeAndPerms(t *testing.T) {
	dir := isolateMCPState(t)
	h := startPairedServe(t, dir, "codex", "codex-mcp-client")
	tx := h.pendingConnect()
	if _, err := DecideMCPTransaction(tx.ID, true, "click"); err != nil {
		t.Fatal(err)
	}
	if r := h.call("generate_password", nil); r.isError {
		t.Fatalf("generate_password = %+v", r)
	}
	g, err := FindMCPAssistant("codex", "codex-mcp-client")
	if err != nil {
		t.Fatal(err)
	}

	// Tools left out of the defaults are denied until the user adds them.
	if r := h.call("get_audit_logs", nil); !r.isError || !strings.Contains(r.text, "isn't allowed to use get_audit_logs") {
		t.Fatalf("get_audit_logs = %+v", r)
	}
	// A permission change applies to the next call.
	if _, err := SetMCPAssistantPerms(g.ID, []string{"list_vault"}); err != nil {
		t.Fatal(err)
	}
	if r := h.call("generate_password", nil); !r.isError || !strings.HasPrefix(r.text, "Denied.") {
		t.Fatalf("generate_password without the permission = %+v", r)
	}
	if r := h.call("list_vault", nil); r.isError {
		t.Fatalf("list_vault = %+v", r)
	}

	// Revoking mid-session denies the next call.
	if _, ok, err := RevokeMCPAssistant(g.ID); err != nil || !ok {
		t.Fatal(ok, err)
	}
	if r := h.call("list_vault", nil); !r.isError || r.text != "APM didn't allow Codex. Ask again by restarting Codex." {
		t.Fatalf("list_vault after revoke = %+v", r)
	}
}

func TestMCPPairingCountsUses(t *testing.T) {
	dir := isolateMCPState(t)
	h := startPairedServe(t, dir, "claude-code", "claude-code")
	tx := h.pendingConnect()
	if _, err := DecideMCPTransaction(tx.ID, true, "click"); err != nil {
		t.Fatal(err)
	}
	for i := 0; i < 3; i++ {
		if r := h.call("generate_password", nil); r.isError {
			t.Fatal(r.text)
		}
	}
	g, _ := FindMCPAssistant("claude-code", "claude-code")
	// The first call is saved at once; later ones wait for the next save.
	if g.Uses != 1 || g.LastUsedAt.IsZero() {
		t.Fatalf("after 3 calls: uses=%d last=%v", g.Uses, g.LastUsedAt)
	}
}

func TestMCPTokenServeStillWorks(t *testing.T) {
	h := startMCPServe(t, false)
	if r := h.call("tx_list", nil); r.isError {
		t.Fatalf("tx_list with a token = %+v", r)
	}
	if r := h.call("list_vault", nil); !r.isError || r.text != "Denied" {
		t.Fatalf("list_vault without the token permission = %+v", r)
	}
	txs, _ := ListMCPTransactions(0)
	if len(txs) != 0 {
		t.Fatalf("a token session made a connect request: %+v", txs)
	}
}

func TestMCPPairingWithdrawnWhenServeStops(t *testing.T) {
	dir := isolateMCPState(t)
	h := startPairedServe(t, dir, "claude-code", "claude-code")
	tx := h.pendingConnect()
	_ = h.session.Close()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		if got, err := GetMCPTransaction(tx.ID); err == nil && got.Status == MCPTxAborted {
			return
		}
		time.Sleep(20 * time.Millisecond)
	}
	t.Fatal("the connect request outlived pm mcp serve")
}
