package main

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"time"
)

type TeamSession struct {
	UserID       string    `json:"user_id"`
	Username     string    `json:"username"`
	Role         Role      `json:"role"`
	ActiveDeptID string    `json:"active_dept_id"`
	DeptKey      []byte    `json:"dept_key"`
	OrgID        string    `json:"org_id"`
	Expiry       time.Time `json:"expiry"`
}

var SessionFile = filepath.Join(os.TempDir(), "pm_team_session.json")

func CreateSession(user TeamUser, deptKey []byte, orgID string) error {
	session := TeamSession{
		UserID:       user.ID,
		Username:     user.Username,
		Role:         user.Role,
		ActiveDeptID: user.ActiveDepartmentID,
		DeptKey:      deptKey,
		OrgID:        orgID,
		Expiry:       time.Now().Add(15 * time.Minute),
	}

	data, err := json.Marshal(session)
	if err != nil {
		return err
	}

	if err := os.WriteFile(SessionFile, data, 0600); err != nil {
		return err
	}

	duration := time.Until(session.Expiry)
	go func() {
		time.Sleep(duration)
		os.Remove(SessionFile)
	}()

	cleanupCmd(duration)

	return nil
}

func cleanupCmd(duration time.Duration) {
	seconds := int(duration.Seconds())
	var cmd *exec.Cmd
	if filepath.Separator == '\\' {
		cmd = exec.Command("cmd", "/c", fmt.Sprintf("timeout /t %d /nobreak && del \"%s\"", seconds, SessionFile))
	} else {
		cmd = exec.Command("sh", "-c", fmt.Sprintf("sleep %d && rm -f \"%s\"", seconds, SessionFile))
	}

	err := cmd.Start()
	if err != nil {
		fmt.Printf("Warning: Could not start background cleanup: %v\n", err)
	}
}

func GetSession() (*TeamSession, error) {
	if _, err := os.Stat(SessionFile); os.IsNotExist(err) {
		return nil, errors.New("no active session")
	}

	data, err := os.ReadFile(SessionFile)
	if err != nil {
		return nil, err
	}

	var session TeamSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	if time.Now().After(session.Expiry) {
		os.Remove(SessionFile)
		return nil, errors.New("session expired")
	}

	return &session, nil
}

func EndSession() error {
	return os.Remove(SessionFile)
}
