package autofill

import (
	"os"
	"path/filepath"
)

func autofillDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	dir := filepath.Join(configDir, "apm", "autofill")
	if err := os.MkdirAll(dir, 0700); err != nil {
		return "", err
	}
	return dir, nil
}

func stateFilePath() (string, error) {
	dir, err := autofillDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "daemon_state.json"), nil
}

func profileFilePath() (string, error) {
	dir, err := autofillDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "profiles.json"), nil
}

func mailConfigFilePath() (string, error) {
	dir, err := autofillDir()
	if err != nil {
		return "", err
	}
	return filepath.Join(dir, "mail.json"), nil
}
