package apm

import (
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"os"
	"strings"
	"time"
)

// AnomalyDetection checks for unusual patterns.

type AccessLog struct {
	Timestamp  int64
	DeviceHash string
	Action     string // "UNLOCK", "FAIL", "EXPORT"
}

func GetDeviceHash() string {
	// Simple stable ID: Hostname + Username
	host, _ := os.Hostname()
	user := os.Getenv("USERNAME")
	if user == "" {
		user = os.Getenv("USER")
	}

	raw := fmt.Sprintf("%s-%s", host, user)
	hash := sha256.Sum256([]byte(raw))
	return hex.EncodeToString(hash[:])
}

func LogAccess(action string) {
	// Log to .apm_adup (simple line based: TIMESTAMP|HASH|ACTION)
	entry := fmt.Sprintf("%d|%s|%s\n", time.Now().Unix(), GetDeviceHash(), action)

	exe, _ := os.Executable()
	path := "apm_audit.log" // Keep in CWD or beside exe? Requirement: "Store timestamps...".
	// Let's put it beside exe for now to be persistent.
	path = strings.Replace(exe, "pm.exe", "apm_audit.log", 1)

	f, err := os.OpenFile(path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		defer f.Close()
		f.WriteString(entry)
	}
}

func CheckAnomalies(vault *Vault) []string {
	// 1. Check if current device is new?
	// Need to read history.
	// For simplicity in this iteration: Just return empty or mock check.
	// Real implementation needs to parse log.

	var alerts []string

	// Unlocks at unusual hours (2AM - 5AM)
	h := time.Now().Hour()
	if h >= 2 && h <= 5 {
		alerts = append(alerts, fmt.Sprintf("Unusual activity time (%02d:00)", h))
	}

	return alerts
}
