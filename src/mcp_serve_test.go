package apm

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/modelcontextprotocol/go-sdk/mcp"
)

const mcpTestPassword = "ValidPass123!"

type mcpServeHarness struct {
	t         *testing.T
	ctx       context.Context
	session   *mcp.ClientSession
	vaultPath string
}

// startMCPServe creates a vault, a pm unlock session for it (read-only when
// asked), and a pm mcp serve connected over an in-memory transport.
func startMCPServe(t *testing.T, readonly bool) *mcpServeHarness {
	t.Helper()
	dir := isolateMCPState(t)
	vaultPath := filepath.Join(dir, "vault.dat")
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
	if err := CreateSession(mcpTestPassword, time.Hour, readonly, 0); err != nil {
		t.Fatalf("CreateSession: %v", err)
	}
	t.Cleanup(func() { _ = KillSession() })

	token, err := GenerateMCPToken("test", []string{"add_entry", "delete_entry", "edit_entry", "tx_list"}, 0)
	if err != nil {
		t.Fatalf("GenerateMCPToken: %v", err)
	}
	ctx, cancel := context.WithCancel(context.Background())
	t.Cleanup(cancel)
	serverT, clientT := mcp.NewInMemoryTransports()
	go func() { _ = StartMCPServer(token, vaultPath, serverT) }()
	client := mcp.NewClient(&mcp.Implementation{Name: "test-client", Version: "1"}, nil)
	session, err := client.Connect(ctx, clientT, nil)
	if err != nil {
		t.Fatalf("Connect: %v", err)
	}
	t.Cleanup(func() { _ = session.Close() })
	return &mcpServeHarness{t: t, ctx: ctx, session: session, vaultPath: vaultPath}
}

func setMCPApprovalWait(t *testing.T, d time.Duration) {
	t.Helper()
	prev := mcpApprovalWait
	mcpApprovalWait = d
	t.Cleanup(func() { mcpApprovalWait = prev })
}

type mcpCallResult struct {
	text    string
	isError bool
}

// callAsync calls a tool in the background, as an agent waiting on the user.
func (h *mcpServeHarness) callAsync(tool string, args map[string]any) <-chan mcpCallResult {
	out := make(chan mcpCallResult, 1)
	go func() {
		res, err := h.session.CallTool(h.ctx, &mcp.CallToolParams{Name: tool, Arguments: args})
		if err != nil {
			out <- mcpCallResult{text: err.Error(), isError: true}
			return
		}
		out <- mcpCallResult{text: res.Content[0].(*mcp.TextContent).Text, isError: res.IsError}
	}()
	return out
}

func (h *mcpServeHarness) wait(ch <-chan mcpCallResult) mcpCallResult {
	h.t.Helper()
	select {
	case r := <-ch:
		return r
	case <-time.After(20 * time.Second):
		h.t.Fatal("tool call did not return")
	}
	return mcpCallResult{}
}

// pendingTx waits for the request a tool call queued.
func (h *mcpServeHarness) pendingTx() MCPTransaction {
	h.t.Helper()
	deadline := time.Now().Add(5 * time.Second)
	for time.Now().Before(deadline) {
		txs, _ := ListMCPTransactions(0)
		for _, tx := range txs {
			if tx.Status == MCPTxPending {
				return tx
			}
		}
		time.Sleep(10 * time.Millisecond)
	}
	h.t.Fatal("no pending request was queued")
	return MCPTransaction{}
}

func (h *mcpServeHarness) vault() *Vault {
	h.t.Helper()
	data, err := os.ReadFile(h.vaultPath)
	if err != nil {
		h.t.Fatal(err)
	}
	v, err := DecryptVault(data, mcpTestPassword, 1)
	if err != nil {
		h.t.Fatalf("DecryptVault: %v", err)
	}
	return v
}

func hasEntry(v *Vault, account string) bool {
	for _, e := range v.Entries {
		if e.Account == account {
			return true
		}
	}
	return false
}

func TestMCPServeAppliesApprovedRequest(t *testing.T) {
	h := startMCPServe(t, false)
	call := h.callAsync("add_entry", map[string]any{"type": "password", "name": "example", "username": "me", "password": "pw-example"})
	tx := h.pendingTx()
	if _, err := DecideMCPTransaction(tx.ID, true, "click"); err != nil {
		t.Fatalf("DecideMCPTransaction: %v", err)
	}
	res := h.wait(call)
	if res.isError || !strings.HasPrefix(res.text, `Approved. Added "example". Receipt rcpt_`) {
		t.Fatalf("unexpected result: %+v", res)
	}
	if !hasEntry(h.vault(), "example") {
		t.Fatal("the approved entry is not in the vault")
	}
	got, err := GetMCPTransaction(tx.ID)
	if err != nil || got.Status != MCPTxCommitted || got.ClaimedBy != "serve" || got.Receipt == "" {
		t.Fatalf("unexpected transaction after apply: %+v (%v)", got, err)
	}
	head, err := GetLGitHead()
	if err != nil || head == nil {
		t.Fatalf("no History commit was recorded: %v", err)
	}
	if note := loadLGitNotes()[head.ID].Note; !strings.HasPrefix(note, "Approved test: ") {
		t.Fatalf("unexpected History note %q", note)
	}

	// The same flow removes an entry.
	call = h.callAsync("delete_entry", map[string]any{"name": "example"})
	tx = h.pendingTx()
	if _, err := DecideMCPTransaction(tx.ID, true, "touchid"); err != nil {
		t.Fatal(err)
	}
	if res := h.wait(call); res.isError || !strings.HasPrefix(res.text, `Approved. Deleted "example". Receipt rcpt_`) {
		t.Fatalf("unexpected delete result: %+v", res)
	}
	if hasEntry(h.vault(), "example") {
		t.Fatal("the deleted entry is still in the vault")
	}
}

func TestMCPServeRejectedRequestChangesNothing(t *testing.T) {
	h := startMCPServe(t, false)
	before, _ := os.ReadFile(h.vaultPath)
	call := h.callAsync("add_entry", map[string]any{"type": "password", "name": "example", "password": "pw-example"})
	tx := h.pendingTx()
	if _, err := DecideMCPTransaction(tx.ID, false, "keyboard"); err != nil {
		t.Fatal(err)
	}
	if res := h.wait(call); res.isError || res.text != "Rejected in APM. Nothing changed." {
		t.Fatalf("unexpected result: %+v", res)
	}
	if after, _ := os.ReadFile(h.vaultPath); !bytes.Equal(before, after) {
		t.Fatal("a rejected request changed the vault file")
	}
}

func TestMCPServeTimesOutAndAppliesLater(t *testing.T) {
	h := startMCPServe(t, false)
	setMCPApprovalWait(t, 200*time.Millisecond)
	res := h.wait(h.callAsync("add_entry", map[string]any{"type": "password", "name": "later", "password": "pw-later"}))
	if res.isError || !strings.HasPrefix(res.text, "Still waiting for approval (request tx_") || !strings.Contains(res.text, "Call tx_list later to see the outcome.") {
		t.Fatalf("unexpected result: %+v", res)
	}
	tx := h.pendingTx()
	if _, err := DecideMCPTransaction(tx.ID, true, "click"); err != nil {
		t.Fatal(err)
	}
	// The server keeps watching the request after the call returned.
	deadline := time.Now().Add(10 * time.Second)
	for time.Now().Before(deadline) {
		if got, _ := GetMCPTransaction(tx.ID); got != nil && got.Status == MCPTxCommitted {
			if !hasEntry(h.vault(), "later") {
				t.Fatal("committed, but the entry is not in the vault")
			}
			return
		}
		time.Sleep(50 * time.Millisecond)
	}
	t.Fatal("the late approval was never applied")
}

func TestMCPServeReadOnlySessionLeavesRequestApproved(t *testing.T) {
	h := startMCPServe(t, true)
	before, _ := os.ReadFile(h.vaultPath)
	call := h.callAsync("add_entry", map[string]any{"type": "password", "name": "example", "password": "pw-example"})
	tx := h.pendingTx()
	if _, err := DecideMCPTransaction(tx.ID, true, "click"); err != nil {
		t.Fatal(err)
	}
	if res := h.wait(call); res.isError || res.text != "Approved. APM will make the change when you unlock the vault." {
		t.Fatalf("unexpected result: %+v", res)
	}
	if after, _ := os.ReadFile(h.vaultPath); !bytes.Equal(before, after) {
		t.Fatal("a read-only session wrote the vault")
	}
	if got, _ := GetMCPTransaction(tx.ID); got == nil || got.Status != MCPTxApproved || got.ClaimedBy != "" {
		t.Fatalf("request should be approved and unclaimed: %+v", got)
	}
}
