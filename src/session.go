package apm

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type Session struct {
	MasterPassword    string        `json:"master_password"`
	ReadOnly          bool          `json:"readonly"`
	Expiry            time.Time     `json:"expiry"`
	LastUsed          time.Time     `json:"last_used"`
	InactivityTimeout time.Duration `json:"inactivity_timeout"`
}

func getSessionFile() string {
	sessionID := os.Getenv("APM_SESSION_ID")
	if sessionID == "" {
		return filepath.Join(os.TempDir(), "pm_session_global.json")
	}
	// Sanitize sessionID to avoid path traversal or invalid filenames
	sanitizedID := ""
	for _, char := range sessionID {
		if (char >= 'a' && char <= 'z') || (char >= 'A' && char <= 'Z') || (char >= '0' && char <= '9') {
			sanitizedID += string(char)
		}
	}
	if sanitizedID == "" {
		sanitizedID = "unknown"
	}
	return filepath.Join(os.TempDir(), fmt.Sprintf("pm_session_%s.json", sanitizedID))
}

func CreateSession(password string, duration time.Duration, readonly bool, inactivity time.Duration) error {
	session := Session{
		MasterPassword:    password,
		ReadOnly:          readonly,
		Expiry:            time.Now().Add(duration),
		LastUsed:          time.Now(),
		InactivityTimeout: inactivity,
	}

	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	sessionFile := getSessionFile()
	if err := os.WriteFile(sessionFile, data, 0600); err != nil {
		return err
	}

	go func() {
		time.Sleep(duration)
		_ = os.Remove(sessionFile)
	}()

	cleanupCmd(duration, sessionFile)

	return nil
}

func cleanupCmd(duration time.Duration, sessionFile string) {
	seconds := int(duration.Seconds())
	var cmd *exec.Cmd
	//nolint:gosec // Command arguments are integer duration and sanitized file path
	if filepath.Separator == '\\' {
		cmd = exec.Command("cmd", "/c", fmt.Sprintf("timeout /t %d /nobreak && del \"%s\"", seconds, sessionFile))
	} else {
		cmd = exec.Command("sh", "-c", fmt.Sprintf("sleep %d && rm -f \"%s\"", seconds, sessionFile))
	}

	err := cmd.Start()
	if err != nil {
		fmt.Printf("Warning: Could not start background cleanup: %v\n", err)
	}
}

func GetSession() (*Session, error) {
	sessionFile := getSessionFile()
	if _, err := os.Stat(sessionFile); os.IsNotExist(err) {
		return nil, errors.New("no active session")
	}

	//nolint:gosec // sessionFile is constructed from safe TempDir and alphanumeric ID
	data, err := os.ReadFile(sessionFile)
	if err != nil {
		return nil, err
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	now := time.Now()
	if now.After(session.Expiry) {
		_ = os.Remove(sessionFile)
		return nil, errors.New("session expired")
	}

	if session.InactivityTimeout > 0 && now.Sub(session.LastUsed) > session.InactivityTimeout {
		_ = os.Remove(sessionFile)
		return nil, errors.New("session locked due to inactivity")
	}

	// Update last used time
	session.LastUsed = now
	updatedData, _ := json.Marshal(session)
	_ = os.WriteFile(sessionFile, updatedData, 0600)

	return &session, nil
}

func KillSession() error {
	return os.Remove(getSessionFile())
}
