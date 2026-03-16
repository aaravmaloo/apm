package inject

import (
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
)

var ErrSessionNotFound = errors.New("inject session not found")

type InjectionSession struct {
	ID         string    `json:"id"`
	VarNames   []string  `json:"var_names"`
	InjectedAt time.Time `json:"injected_at"`
	ShellPID   int       `json:"shell_pid"`
}

func StartSession(entries []ResolvedEntry, shell string) (string, error) {
	if len(entries) == 0 {
		return "", errors.New("no entries to inject")
	}

	sessionID, err := generateSessionID()
	if err != nil {
		return "", err
	}

	varNames := make([]string, 0, len(entries))
	for _, e := range entries {
		if e.EnvVarName == "" {
			continue
		}
		varNames = append(varNames, e.EnvVarName)
	}

	session := &InjectionSession{
		ID:         sessionID,
		VarNames:   varNames,
		InjectedAt: time.Now(),
		ShellPID:   os.Getppid(),
	}

	if err := WriteSession(session); err != nil {
		return "", err
	}

	detected, _ := DetectShellFromEnv(shell)
	eval := WriteExports(entries, sessionID, detected)

	for i := range entries {
		zeroBytes(entries[i].Value)
		entries[i].Value = nil
	}

	return eval, nil
}

func KillSession() (string, error) {
	session, err := ReadSession()
	if err != nil {
		return "", err
	}

	varNames := make([]string, 0, len(session.VarNames)+1)
	seen := make(map[string]struct{})
	for _, name := range session.VarNames {
		if name == "" {
			continue
		}
		if _, ok := seen[name]; ok {
			continue
		}
		seen[name] = struct{}{}
		varNames = append(varNames, name)
	}
	if _, ok := seen["APM_INJECT_SESSION"]; !ok {
		varNames = append(varNames, "APM_INJECT_SESSION")
	}

	eval := WriteUnsets(varNames, DetectShell())

	if err := ClearSession(); err != nil {
		return "", err
	}

	return eval, nil
}

func ReadSession() (*InjectionSession, error) {
	path, err := sessionFilePath()
	if err != nil {
		return nil, err
	}

	data, err := os.ReadFile(path)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, ErrSessionNotFound
		}
		return nil, err
	}

	var session InjectionSession
	if err := json.Unmarshal(data, &session); err != nil {
		return nil, err
	}

	return &session, nil
}

func WriteSession(s *InjectionSession) error {
	path, err := sessionFilePath()
	if err != nil {
		return err
	}

	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}

	data, err := json.Marshal(s)
	if err != nil {
		return err
	}

	return os.WriteFile(path, data, 0600)
}

func ClearSession() error {
	path, err := sessionFilePath()
	if err != nil {
		return err
	}
	if err := os.Remove(path); err != nil && !os.IsNotExist(err) {
		return err
	}
	return nil
}

func sessionFilePath() (string, error) {
	if dir := os.Getenv("APM_DATA_DIR"); dir != "" {
		return filepath.Join(dir, "inject_session"), nil
	}
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(configDir, "apm", "inject_session"), nil
}

func generateSessionID() (string, error) {
	b := make([]byte, 8)
	if _, err := rand.Read(b); err != nil {
		return "", fmt.Errorf("failed to generate session id: %w", err)
	}
	return hex.EncodeToString(b), nil
}
