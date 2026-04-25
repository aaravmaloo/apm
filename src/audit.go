package apm

import (
	"bufio"
	"crypto/hmac"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type AuditEntry struct {
	Timestamp time.Time `json:"timestamp"`
	Action    string    `json:"action"`
	Details   string    `json:"details"`
	User      string    `json:"user"`
	Hostname  string    `json:"hostname"`
	PrevHash  string    `json:"prev_hash,omitempty"`
	Hash      string    `json:"hash,omitempty"`
	Signature string    `json:"signature,omitempty"`
}

func getAuditFile() string {
	apmDir, _ := getAPMConfigDir()
	return filepath.Join(apmDir, "audit.json")
}

func getAuditSigningKey() ([]byte, error) {
	apmDir, err := getAPMConfigDir()
	if err != nil {
		return nil, err
	}
	return loadOrCreateSigningKey(filepath.Join(apmDir, "audit_signing.key"))
}

func getLastAuditHash() string {
	logs, err := GetAuditLogs(1)
	if err != nil || len(logs) == 0 {
		return ""
	}
	return logs[len(logs)-1].Hash
}

func LogAction(action, details string) {
	entry := AuditEntry{
		Timestamp: time.Now(),
		Action:    action,
		Details:   details,
		PrevHash:  getLastAuditHash(),
	}

	if u, err := os.UserHomeDir(); err == nil {
		entry.User = filepath.Base(u)
	}
	if h, err := os.Hostname(); err == nil {
		entry.Hostname = h
	}

	serialized := fmt.Sprintf("%d:%s:%s:%s:%s:%s", entry.Timestamp.UnixNano(), entry.Action, entry.Details, entry.User, entry.Hostname, entry.PrevHash)
	hash := sha256.Sum256([]byte(serialized))
	entry.Hash = hex.EncodeToString(hash[:])

	if key, err := getAuditSigningKey(); err == nil {
		mac := hmac.New(sha256.New, key)
		mac.Write([]byte(entry.Hash))
		entry.Signature = hex.EncodeToString(mac.Sum(nil))
	}

	f, err := os.OpenFile(getAuditFile(), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err != nil {
		fmt.Printf("Failed to write to audit log: %v\n", err)
		return
	}
	defer f.Close()

	data, _ := json.Marshal(entry)
	if _, err := f.WriteString(string(data) + "\n"); err != nil {
		fmt.Printf("Failed to write to audit log: %v\n", err)
	}
}

func GetAuditLogs(limit int) ([]AuditEntry, error) {
	file := getAuditFile()
	if _, err := os.Stat(file); os.IsNotExist(err) {
		return []AuditEntry{}, nil
	}

	f, err := os.Open(file)
	if err != nil {
		return nil, err
	}
	defer f.Close()

	var logs []AuditEntry
	scanner := bufio.NewScanner(f)
	for scanner.Scan() {
		line := scanner.Bytes()
		if len(line) == 0 {
			continue
		}
		var entry AuditEntry
		if err := json.Unmarshal(line, &entry); err == nil {
			logs = append(logs, entry)
		}
	}
	if err := scanner.Err(); err != nil {
		return nil, err
	}

	if limit > 0 && len(logs) > limit {
		return logs[len(logs)-limit:], nil
	}

	return logs, nil
}

func VerifyAuditLogs(logs []AuditEntry) []bool {
	out := make([]bool, len(logs))
	key, err := getAuditSigningKey()
	if err != nil {
		return out
	}

	prevHash := ""
	for i, e := range logs {
		ok := e.Hash != "" && e.Signature != ""
		if ok {
			serialized := fmt.Sprintf("%d:%s:%s:%s:%s:%s", e.Timestamp.UnixNano(), e.Action, e.Details, e.User, e.Hostname, e.PrevHash)
			hash := sha256.Sum256([]byte(serialized))
			expectedHash := hex.EncodeToString(hash[:])
			if !hmac.Equal([]byte(expectedHash), []byte(e.Hash)) {
				ok = false
			}
		}
		if ok {
			mac := hmac.New(sha256.New, key)
			mac.Write([]byte(e.Hash))
			expectedSig := hex.EncodeToString(mac.Sum(nil))
			if !hmac.Equal([]byte(expectedSig), []byte(e.Signature)) {
				ok = false
			}
		}
		if ok && e.PrevHash != "" && e.PrevHash != prevHash {
			ok = false
		}
		out[i] = ok
		prevHash = e.Hash
	}
	return out
}
