package apm

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"sync"
	"testing"
	"time"
)

// isolateMCPState points every per-user file the MCP code touches at a fresh
// temporary directory.
func isolateMCPState(t *testing.T) string {
	t.Helper()
	dir := t.TempDir()
	t.Setenv("HOME", dir)
	t.Setenv("XDG_CONFIG_HOME", filepath.Join(dir, ".config"))
	t.Setenv("APPDATA", filepath.Join(dir, "AppData"))
	t.Setenv("APM_STATE_DIR", filepath.Join(dir, "state"))
	t.Setenv("APM_MCP_NO_APPROVER", "1")
	t.Setenv("APM_SESSION_ID", uniqueSessionID("mcp"))
	t.Setenv("APM_EPHEMERAL_ID", "")
	return dir
}

func newTestTx(t *testing.T, ttl time.Duration) MCPTransaction {
	t.Helper()
	tx, err := CreateMCPTransaction("test", "add_entry", json.RawMessage(`{"type":"password","name":"example"}`), "Add password entry 'example'", ttl)
	if err != nil {
		t.Fatalf("CreateMCPTransaction: %v", err)
	}
	return tx
}

func txStatus(t *testing.T, id string) string {
	t.Helper()
	tx, err := GetMCPTransaction(id)
	if err != nil {
		t.Fatalf("GetMCPTransaction: %v", err)
	}
	return tx.Status
}

func TestMCPTransactionDecideClaimFinalize(t *testing.T) {
	isolateMCPState(t)
	tx := newTestTx(t, 0)

	if _, _, err := ClaimMCPTransaction(tx.ID, "serve"); err != nil {
		t.Fatalf("claim of a pending request: %v", err)
	}
	if got := txStatus(t, tx.ID); got != MCPTxPending {
		t.Fatalf("a pending request was claimed: %s", got)
	}

	decided, err := DecideMCPTransaction(tx.ID, true, "touchid")
	if err != nil {
		t.Fatalf("DecideMCPTransaction: %v", err)
	}
	if decided.Status != MCPTxApproved || decided.DecidedVia != "touchid" || decided.DecidedAt.IsZero() {
		t.Fatalf("unexpected decision: %+v", decided)
	}
	again, err := DecideMCPTransaction(tx.ID, false, "click")
	if !errors.Is(err, ErrMCPTxNotPending) || again.Status != MCPTxApproved {
		t.Fatalf("second decision should fail and report approved, got %v (%s)", err, again.Status)
	}
	if err := AbortMCPTransaction(tx.ID); !errors.Is(err, ErrMCPTxNotPending) {
		t.Fatalf("an agent aborted an approved request: %v", err)
	}

	claimed, ok, err := ClaimMCPTransaction(tx.ID, "serve")
	if err != nil || !ok || claimed.Status != MCPTxApplying || claimed.ClaimedBy != "serve" {
		t.Fatalf("claim: ok=%v err=%v tx=%+v", ok, err, claimed)
	}
	if _, ok, err := ClaimMCPTransaction(tx.ID, "desktop"); err != nil || ok {
		t.Fatalf("double claim: ok=%v err=%v", ok, err)
	}

	if err := ReleaseMCPTransaction(tx.ID); err != nil {
		t.Fatalf("ReleaseMCPTransaction: %v", err)
	}
	if got, _ := GetMCPTransaction(tx.ID); got.Status != MCPTxApproved || got.ClaimedBy != "" {
		t.Fatalf("release should leave it approved and unclaimed: %+v", got)
	}
	if _, ok, _ := ClaimMCPTransaction(tx.ID, "desktop"); !ok {
		t.Fatal("a released request could not be claimed again")
	}

	receipt, err := FinalizeMCPTransaction(tx.ID, "added:example", true)
	if err != nil || receipt == "" {
		t.Fatalf("FinalizeMCPTransaction: %q %v", receipt, err)
	}
	if got := txStatus(t, tx.ID); got != MCPTxCommitted {
		t.Fatalf("expected committed, got %s", got)
	}
	if err := FailMCPTransaction(tx.ID, "late"); err == nil {
		t.Fatal("a committed request was marked failed")
	}
	if err := ReleaseMCPTransaction(tx.ID); err == nil {
		t.Fatal("a committed request was released")
	}
}

func TestMCPTransactionFailRejectAbort(t *testing.T) {
	isolateMCPState(t)

	failing := newTestTx(t, 0)
	if _, err := ApproveAndClaimMCPTransaction(failing.ID, "keyboard", "desktop"); err != nil {
		t.Fatalf("ApproveAndClaimMCPTransaction: %v", err)
	}
	if err := FailMCPTransaction(failing.ID, "entry exists"); err != nil {
		t.Fatalf("FailMCPTransaction: %v", err)
	}
	got, _ := GetMCPTransaction(failing.ID)
	if got.Status != MCPTxFailed || got.Error != "entry exists" || got.ClaimedBy != "desktop" {
		t.Fatalf("unexpected failed request: %+v", got)
	}
	if _, err := FinalizeMCPTransaction(failing.ID, "", true); err == nil {
		t.Fatal("a failed request was committed")
	}

	rejected := newTestTx(t, 0)
	if _, err := DecideMCPTransaction(rejected.ID, false, "click"); err != nil {
		t.Fatalf("reject: %v", err)
	}
	if _, ok, _ := ClaimMCPTransaction(rejected.ID, "serve"); ok {
		t.Fatal("a rejected request was claimed")
	}
	if got := txStatus(t, rejected.ID); got != MCPTxRejected {
		t.Fatalf("expected rejected, got %s", got)
	}

	aborted := newTestTx(t, 0)
	if err := AbortMCPTransaction(aborted.ID); err != nil {
		t.Fatalf("AbortMCPTransaction: %v", err)
	}
	if _, err := DecideMCPTransaction(aborted.ID, true, "click"); !errors.Is(err, ErrMCPTxNotPending) {
		t.Fatalf("an aborted request was approved: %v", err)
	}
}

func TestMCPTransactionDecideAfterExpiry(t *testing.T) {
	isolateMCPState(t)
	tx := newTestTx(t, 30*time.Millisecond)
	time.Sleep(60 * time.Millisecond)
	_, err := DecideMCPTransaction(tx.ID, true, "click")
	if !errors.Is(err, ErrMCPTxNotFound) && !errors.Is(err, ErrMCPTxExpired) {
		t.Fatalf("expected an expired request to be refused, got %v", err)
	}
	if txs, _ := ListMCPTransactions(0); len(txs) != 0 {
		t.Fatalf("expired request is still listed: %+v", txs)
	}
}

func TestMCPTransactionClaimIsExclusive(t *testing.T) {
	isolateMCPState(t)
	tx := newTestTx(t, 0)
	if _, err := DecideMCPTransaction(tx.ID, true, "click"); err != nil {
		t.Fatal(err)
	}
	var wg sync.WaitGroup
	var mu sync.Mutex
	wins := 0
	for i := 0; i < 8; i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			if _, ok, err := ClaimMCPTransaction(tx.ID, "serve"); err == nil && ok {
				mu.Lock()
				wins++
				mu.Unlock()
			}
		}()
	}
	wg.Wait()
	if wins != 1 {
		t.Fatalf("expected exactly one claim to win, got %d", wins)
	}
}

func TestMCPTransactionStaleLockIsBroken(t *testing.T) {
	isolateMCPState(t)
	lock := getMCPTransactionFile() + ".lock"
	if err := os.WriteFile(lock, []byte("1"), 0600); err != nil {
		t.Fatal(err)
	}
	old := time.Now().Add(-time.Minute)
	if err := os.Chtimes(lock, old, old); err != nil {
		t.Fatal(err)
	}
	newTestTx(t, 0)
	if _, err := os.Stat(lock); !os.IsNotExist(err) {
		t.Fatalf("lock file left behind: %v", err)
	}
}
