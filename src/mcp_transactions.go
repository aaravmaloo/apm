package apm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"
)

// An MCP transaction moves through these states. A pending request is
// decided by the user (approved or rejected) or aborted by the agent; an
// approved one is claimed by whoever has the vault open (applying) and ends
// committed or failed. Every transaction is removed once it expires.
const (
	MCPTxPending   = "pending"
	MCPTxApproved  = "approved"
	MCPTxRejected  = "rejected"
	MCPTxAborted   = "aborted"
	MCPTxApplying  = "applying"
	MCPTxCommitted = "committed"
	MCPTxFailed    = "failed"
)

var (
	ErrMCPTxNotFound   = errors.New("transaction not found")
	ErrMCPTxExpired    = errors.New("transaction expired")
	ErrMCPTxNotPending = errors.New("transaction is no longer pending")
	ErrMCPTxBusy       = errors.New("the MCP request store is busy")
)

type MCPTransaction struct {
	ID         string          `json:"id"`
	TokenName  string          `json:"token_name"`
	Tool       string          `json:"tool"`
	Args       json.RawMessage `json:"args"`
	Preview    string          `json:"preview"`
	Status     string          `json:"status"`
	Receipt    string          `json:"receipt,omitempty"`
	CreatedAt  time.Time       `json:"created_at"`
	ExpiresAt  time.Time       `json:"expires_at"`
	UpdatedAt  time.Time       `json:"updated_at"`
	DecidedAt  time.Time       `json:"decided_at,omitempty"`
	DecidedVia string          `json:"decided_via,omitempty"`
	Error      string          `json:"error,omitempty"`
	ClaimedBy  string          `json:"claimed_by,omitempty"`
	// ApproveWith is the policy's approve_with when the request was made:
	// "touchid" means only a touch approves it on a Mac with Touch ID.
	ApproveWith string `json:"approve_with,omitempty"`
}

type MCPTransactionStore struct {
	Transactions map[string]MCPTransaction `json:"transactions"`
}

// The store is shared by every pm mcp serve process and the pm desktop
// backend, so each read-modify-write holds a lock file next to it.
const (
	mcpTxLockWait  = 3 * time.Second
	mcpTxLockRetry = 10 * time.Millisecond
	mcpTxLockStale = 10 * time.Second
)

func getMCPTransactionFile() string {
	configDir, _ := os.UserConfigDir()
	apmDir := filepath.Join(configDir, "apm")
	if err := os.MkdirAll(apmDir, 0700); err != nil {
		// Best-effort; the caller will surface the write error.
	}
	return filepath.Join(apmDir, "mcp_transactions.json")
}

func lockMCPTransactionStore() (func(), error) {
	return lockMCPFile(getMCPTransactionFile())
}

// lockMCPFile takes the lock file next to path, waiting for another process
// that holds it.
func lockMCPFile(path string) (func(), error) {
	lockPath := path + ".lock"
	deadline := time.Now().Add(mcpTxLockWait)
	for {
		f, err := os.OpenFile(lockPath, os.O_CREATE|os.O_EXCL|os.O_WRONLY, 0600)
		if err == nil {
			_, _ = f.WriteString(strconv.Itoa(os.Getpid()))
			_ = f.Close()
			return func() { _ = os.Remove(lockPath) }, nil
		}
		if !os.IsExist(err) {
			return nil, err
		}
		// A holder that crashed leaves its lock behind; no operation holds it
		// anywhere near this long.
		if st, statErr := os.Stat(lockPath); statErr == nil && time.Since(st.ModTime()) > mcpTxLockStale {
			_ = os.Remove(lockPath)
			continue
		}
		if time.Now().After(deadline) {
			return nil, ErrMCPTxBusy
		}
		time.Sleep(mcpTxLockRetry)
	}
}

func readMCPTransactionStore() (*MCPTransactionStore, error) {
	data, err := os.ReadFile(getMCPTransactionFile())
	if os.IsNotExist(err) {
		return &MCPTransactionStore{Transactions: map[string]MCPTransaction{}}, nil
	}
	if err != nil {
		return nil, err
	}
	store := &MCPTransactionStore{}
	if err := json.Unmarshal(data, store); err != nil {
		return nil, err
	}
	if store.Transactions == nil {
		store.Transactions = map[string]MCPTransaction{}
	}
	return store, nil
}

// saveMCPTransactionStore replaces the file in one rename so readers that
// skip the lock never see half a store.
func saveMCPTransactionStore(store *MCPTransactionStore) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	path := getMCPTransactionFile()
	tmp := fmt.Sprintf("%s.%d.tmp", path, os.Getpid())
	if err := os.WriteFile(tmp, data, 0600); err != nil {
		return err
	}
	if err := os.Rename(tmp, path); err != nil {
		_ = os.Remove(tmp)
		return err
	}
	return nil
}

// updateMCPTransactionStore runs fn on the store under the lock, drops expired
// transactions, and saves the result.
func updateMCPTransactionStore(fn func(store *MCPTransactionStore) error) error {
	unlock, err := lockMCPTransactionStore()
	if err != nil {
		return err
	}
	defer unlock()
	store, err := readMCPTransactionStore()
	if err != nil {
		return err
	}
	now := time.Now()
	for id, tx := range store.Transactions {
		if now.After(tx.ExpiresAt) {
			delete(store.Transactions, id)
		}
	}
	fnErr := fn(store)
	if err := saveMCPTransactionStore(store); err != nil {
		return err
	}
	return fnErr
}

// updateMCPTransaction loads one live transaction under the lock, lets fn
// change it, and stores it. fn returning an error leaves it unchanged.
func updateMCPTransaction(id string, fn func(tx *MCPTransaction) error) (MCPTransaction, error) {
	id = strings.TrimSpace(id)
	var out MCPTransaction
	err := updateMCPTransactionStore(func(store *MCPTransactionStore) error {
		tx, ok := store.Transactions[id]
		if !ok {
			return ErrMCPTxNotFound
		}
		out = tx
		if err := fn(&tx); err != nil {
			return err
		}
		tx.UpdatedAt = time.Now()
		store.Transactions[id] = tx
		out = tx
		return nil
	})
	return out, err
}

// CreateMCPTransaction queues a request for the user's answer. It carries
// the policy's approve_with at the time it was made.
func CreateMCPTransaction(tokenName, tool string, args json.RawMessage, preview string, ttl time.Duration) (MCPTransaction, error) {
	return createMCPTransaction(tokenName, tool, args, preview, ttl, "")
}

// createMCPTransaction queues a request. With autoVia set the request is
// stored already approved by that method (an assistant's bypass), in the same
// write, so no prompt ever sees it pending.
func createMCPTransaction(tokenName, tool string, args json.RawMessage, preview string, ttl time.Duration, autoVia string) (MCPTransaction, error) {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	randID, err := GenerateRandomHex(24)
	if err != nil {
		return MCPTransaction{}, err
	}
	approveWith := MCPApproveAny
	if p, err := LoadMCPPolicy(); err == nil {
		approveWith = p.ApproveWith
	}
	now := time.Now()
	tx := MCPTransaction{
		ID:          "tx_" + randID,
		TokenName:   tokenName,
		Tool:        strings.TrimSpace(tool),
		Args:        append(json.RawMessage{}, args...),
		Preview:     strings.TrimSpace(preview),
		Status:      MCPTxPending,
		CreatedAt:   now,
		ExpiresAt:   now.Add(ttl),
		UpdatedAt:   now,
		ApproveWith: approveWith,
	}
	if autoVia != "" {
		tx.Status = MCPTxApproved
		tx.DecidedAt = now
		tx.DecidedVia = autoVia
	}
	err = updateMCPTransactionStore(func(store *MCPTransactionStore) error {
		store.Transactions[tx.ID] = tx
		return nil
	})
	if err != nil {
		return MCPTransaction{}, err
	}
	return tx, nil
}

func GetMCPTransaction(id string) (*MCPTransaction, error) {
	store, err := readMCPTransactionStore()
	if err != nil {
		return nil, err
	}
	tx, ok := store.Transactions[strings.TrimSpace(id)]
	if !ok {
		return nil, ErrMCPTxNotFound
	}
	if time.Now().After(tx.ExpiresAt) {
		return nil, ErrMCPTxExpired
	}
	return &tx, nil
}

func decideMCPTransaction(tx *MCPTransaction, approve bool, via string) error {
	if time.Now().After(tx.ExpiresAt) {
		return ErrMCPTxExpired
	}
	if tx.Status != MCPTxPending {
		return ErrMCPTxNotPending
	}
	tx.Status = MCPTxRejected
	if approve {
		tx.Status = MCPTxApproved
	}
	tx.DecidedAt = time.Now()
	tx.DecidedVia = strings.TrimSpace(via)
	return nil
}

// DecideMCPTransaction records the user's answer to a pending request. On
// ErrMCPTxNotPending the returned transaction shows its current status.
func DecideMCPTransaction(id string, approve bool, via string) (MCPTransaction, error) {
	return updateMCPTransaction(id, func(tx *MCPTransaction) error {
		return decideMCPTransaction(tx, approve, via)
	})
}

// ApproveAndClaimMCPTransaction approves a pending request and claims it for
// who in one step, so no other process can claim it in between.
func ApproveAndClaimMCPTransaction(id, via, who string) (MCPTransaction, error) {
	return updateMCPTransaction(id, func(tx *MCPTransaction) error {
		if err := decideMCPTransaction(tx, true, via); err != nil {
			return err
		}
		tx.Status = MCPTxApplying
		tx.ClaimedBy = who
		return nil
	})
}

// ClaimMCPTransaction moves an approved request to applying for who. It
// reports false when the request is not approved or someone else claimed it.
func ClaimMCPTransaction(id, who string) (MCPTransaction, bool, error) {
	claimed := false
	tx, err := updateMCPTransaction(id, func(tx *MCPTransaction) error {
		if tx.Status != MCPTxApproved || tx.ClaimedBy != "" {
			return nil
		}
		tx.Status = MCPTxApplying
		tx.ClaimedBy = who
		claimed = true
		return nil
	})
	if err != nil {
		return tx, false, err
	}
	return tx, claimed, nil
}

// ReleaseMCPTransaction hands a claimed request back when the claimer could
// not open the vault, so whoever unlocks it next applies it.
func ReleaseMCPTransaction(id string) error {
	_, err := updateMCPTransaction(id, func(tx *MCPTransaction) error {
		if tx.Status != MCPTxApplying {
			return fmt.Errorf("transaction is %s, not applying", tx.Status)
		}
		tx.Status = MCPTxApproved
		tx.ClaimedBy = ""
		return nil
	})
	return err
}

// FailMCPTransaction records that applying a claimed request failed.
func FailMCPTransaction(id, errMsg string) error {
	_, err := updateMCPTransaction(id, func(tx *MCPTransaction) error {
		if tx.Status != MCPTxApplying {
			return fmt.Errorf("transaction is %s, not applying", tx.Status)
		}
		tx.Status = MCPTxFailed
		tx.Error = strings.TrimSpace(errMsg)
		return nil
	})
	return err
}

// FinalizeMCPTransaction commits an approved request with a receipt, or
// (committed false) aborts a pending one.
func FinalizeMCPTransaction(id, resultSummary string, committed bool) (string, error) {
	tx, err := updateMCPTransaction(id, func(tx *MCPTransaction) error {
		if committed {
			if tx.Status != MCPTxApplying && tx.Status != MCPTxApproved {
				return fmt.Errorf("transaction is %s, not approved", tx.Status)
			}
			h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%d", tx.ID, tx.Tool, resultSummary, time.Now().UnixNano())))
			tx.Receipt = "rcpt_" + hex.EncodeToString(h[:16])
			tx.Status = MCPTxCommitted
			return nil
		}
		if tx.Status != MCPTxPending {
			return ErrMCPTxNotPending
		}
		tx.Status = MCPTxAborted
		return nil
	})
	if err != nil {
		return "", err
	}
	return tx.Receipt, nil
}

func AbortMCPTransaction(id string) error {
	_, err := FinalizeMCPTransaction(id, "aborted", false)
	return err
}

func ListMCPTransactions(limit int) ([]MCPTransaction, error) {
	store, err := readMCPTransactionStore()
	if err != nil {
		return nil, err
	}
	out := make([]MCPTransaction, 0, len(store.Transactions))
	for _, tx := range store.Transactions {
		if !time.Now().After(tx.ExpiresAt) {
			out = append(out, tx)
		}
	}
	sort.Slice(out, func(i, j int) bool {
		return out[i].CreatedAt.After(out[j].CreatedAt)
	})
	if limit > 0 && len(out) > limit {
		out = out[:limit]
	}
	return out, nil
}

// MCPAuditAction is the audit action logged when an approved request is
// applied to the vault.
func MCPAuditAction(tool string) string {
	switch tool {
	case "add_entry":
		return "MCP_ENTRY_ADDED"
	case "edit_entry":
		return "MCP_ENTRY_EDITED"
	case "delete_entry":
		return "MCP_ENTRY_DELETED"
	}
	return "MCP_TX_APPROVED"
}
