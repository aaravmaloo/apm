package apm

import (
	"crypto/rand"
	"os"
	"path/filepath"
)

func getAPMConfigDir() (string, error) {
	configDir, err := os.UserConfigDir()
	if err != nil {
		return "", err
	}
	apmDir := filepath.Join(configDir, "apm")
	if err := os.MkdirAll(apmDir, 0700); err != nil {
		return "", err
	}
	return apmDir, nil
}

func loadOrCreateSigningKey(filePath string) ([]byte, error) {
	if b, err := os.ReadFile(filePath); err == nil && len(b) >= 32 {
		return b, nil
	}

	key := make([]byte, 32)
	if _, err := rand.Read(key); err != nil {
		return nil, err
	}
	if err := os.WriteFile(filePath, key, 0600); err != nil {
		return nil, err
	}
	return key, nil
}
