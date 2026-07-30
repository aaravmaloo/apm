package main

import (
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"time"
)

type TeamSession struct {
	UserID       string          `json:"user_id"`
	Username     string          `json:"username"`
	Role         Role            `json:"role"`
	ActiveDeptID string          `json:"active_dept_id"`
	DeptKey      []byte          `json:"dept_key"`
	OrgID        string          `json:"org_id"`
	Expiry       time.Time       `json:"expiry"`
	Permissions  map[string]bool `json:"permissions"`
}

var SessionFile string

func init() {
	exe, _ := os.Executable()
	SessionFile = filepath.Join(filepath.Dir(exe), "pm_team_session.json")
}

func CreateSession(user TeamUser, deptKey []byte, orgID string) error {
	session := TeamSession{
		UserID:       user.ID,
		Username:     user.Username,
		Role:         user.Role,
		ActiveDeptID: user.ActiveDepartmentID,
		DeptKey:      deptKey,
		OrgID:        orgID,
		Expiry:       time.Now().Add(15 * time.Minute),
		Permissions:  user.Permissions,
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

	return nil
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
