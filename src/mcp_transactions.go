package apm

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strings"
	"time"
)

type MCPTransaction struct {
	ID        string          `json:"id"`
	TokenName string          `json:"token_name"`
	Tool      string          `json:"tool"`
	Args      json.RawMessage `json:"args"`
	Preview   string          `json:"preview"`
	Status    string          `json:"status"`
	Receipt   string          `json:"receipt,omitempty"`
	CreatedAt time.Time       `json:"created_at"`
	ExpiresAt time.Time       `json:"expires_at"`
	UpdatedAt time.Time       `json:"updated_at"`
}

type MCPTransactionStore struct {
	Transactions map[string]MCPTransaction `json:"transactions"`
}

func getMCPTransactionFile() string {
	configDir, _ := os.UserConfigDir()
	apmDir := filepath.Join(configDir, "apm")
	_ = os.MkdirAll(apmDir, 0700)
	return filepath.Join(apmDir, "mcp_transactions.json")
}

func loadMCPTransactionStore() (*MCPTransactionStore, error) {
	path := getMCPTransactionFile()
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return &MCPTransactionStore{Transactions: map[string]MCPTransaction{}}, nil
	}
	data, err := os.ReadFile(path)
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
	now := time.Now()
	changed := false
	for id, tx := range store.Transactions {
		if now.After(tx.ExpiresAt) {
			delete(store.Transactions, id)
			changed = true
		}
	}
	if changed {
		_ = saveMCPTransactionStore(store)
	}
	return store, nil
}

func saveMCPTransactionStore(store *MCPTransactionStore) error {
	data, err := json.MarshalIndent(store, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(getMCPTransactionFile(), data, 0600)
}

func CreateMCPTransaction(tokenName, tool string, args json.RawMessage, preview string, ttl time.Duration) (MCPTransaction, error) {
	if ttl <= 0 {
		ttl = 15 * time.Minute
	}
	randID, err := GenerateRandomHex(24)
	if err != nil {
		return MCPTransaction{}, err
	}
	now := time.Now()
	tx := MCPTransaction{
		ID:        "tx_" + randID,
		TokenName: tokenName,
		Tool:      strings.TrimSpace(tool),
		Args:      append(json.RawMessage{}, args...),
		Preview:   strings.TrimSpace(preview),
		Status:    "pending",
		CreatedAt: now,
		ExpiresAt: now.Add(ttl),
		UpdatedAt: now,
	}
	store, err := loadMCPTransactionStore()
	if err != nil {
		return MCPTransaction{}, err
	}
	store.Transactions[tx.ID] = tx
	if err := saveMCPTransactionStore(store); err != nil {
		return MCPTransaction{}, err
	}
	return tx, nil
}

func GetMCPTransaction(id string) (*MCPTransaction, error) {
	store, err := loadMCPTransactionStore()
	if err != nil {
		return nil, err
	}
	tx, ok := store.Transactions[strings.TrimSpace(id)]
	if !ok {
		return nil, fmt.Errorf("transaction not found")
	}
	if time.Now().After(tx.ExpiresAt) {
		delete(store.Transactions, tx.ID)
		_ = saveMCPTransactionStore(store)
		return nil, fmt.Errorf("transaction expired")
	}
	return &tx, nil
}

func FinalizeMCPTransaction(id, resultSummary string, committed bool) (string, error) {
	store, err := loadMCPTransactionStore()
	if err != nil {
		return "", err
	}
	tx, ok := store.Transactions[strings.TrimSpace(id)]
	if !ok {
		return "", fmt.Errorf("transaction not found")
	}
	if committed {
		h := sha256.Sum256([]byte(fmt.Sprintf("%s|%s|%s|%d", tx.ID, tx.Tool, resultSummary, time.Now().UnixNano())))
		tx.Receipt = "rcpt_" + hex.EncodeToString(h[:16])
		tx.Status = "committed"
	} else {
		tx.Status = "aborted"
	}
	tx.UpdatedAt = time.Now()
	store.Transactions[tx.ID] = tx
	if err := saveMCPTransactionStore(store); err != nil {
		return "", err
	}
	return tx.Receipt, nil
}

func AbortMCPTransaction(id string) error {
	_, err := FinalizeMCPTransaction(id, "aborted", false)
	return err
}

func ListMCPTransactions(limit int) ([]MCPTransaction, error) {
	store, err := loadMCPTransactionStore()
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
