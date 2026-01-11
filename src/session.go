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
	MasterPassword string    `json:"master_password"`
	ReadOnly       bool      `json:"readonly"`
	Expiry         time.Time `json:"expiry"`
}

var sessionFile = filepath.Join(os.TempDir(), "pm_session.json")

func CreateSession(password string, duration time.Duration, readonly bool) error {
	session := Session{
		MasterPassword: password,
		ReadOnly:       readonly,
		Expiry:         time.Now().Add(duration),
	}

	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	if err := os.WriteFile(sessionFile, data, 0600); err != nil {
		return err
	}

	go func() {
		time.Sleep(duration)
		os.Remove(sessionFile)
	}()

	cleanupCmd(duration)

	return nil
}

func cleanupCmd(duration time.Duration) {
	seconds := int(duration.Seconds())
	var cmd *exec.Cmd
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
	if _, err := os.Stat(sessionFile); os.IsNotExist(err) {
		return nil, errors.New("no active session")
	}

	data, err := os.ReadFile(sessionFile)
	if err != nil {
		return nil, err
	}

	var session Session
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	if time.Now().After(session.Expiry) {
		os.Remove(sessionFile)
		return nil, errors.New("session expired")
	}

	return &session, nil
}

func KillSession() error {
	return os.Remove(sessionFile)
}
