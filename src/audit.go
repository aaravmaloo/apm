package apm

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

type AuditEntry struct {
	Timestamp	time.Time		`json:"timestamp"`
	Action	string		`json:"action"`
	Details	string		`json:"details"`
	User	string		`json:"user"`
	Hostname	string		`json:"hostname"`
}

func getAuditFile() string {
	configDir, _ := os.UserConfigDir()
	apmDir := filepath.Join(configDir, "apm")
	_ = os.MkdirAll(apmDir, 0700)
	return filepath.Join(apmDir, "audit.json")
}

func LogAction(action, details string) {
	entry := AuditEntry{
		Timestamp:	time.Now(),
		Action:	action,
		Details:	details,
	}

	if u, err := os.UserHomeDir(); err == nil {
		entry.User = filepath.Base(u)
	}
	if h, err := os.Hostname(); err == nil {
		entry.Hostname = h
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
	decoder := json.NewDecoder(f)
	for decoder.More() {
		var entry AuditEntry
		err := decoder.Decode(&entry)
		if err == nil {
			logs = append(logs, entry)
		}
	}

	if limit > 0 && len(logs) > limit {

		return logs[len(logs)-limit:], nil
	}

	return logs, nil
}
