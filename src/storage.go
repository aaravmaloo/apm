package apm

import (
	"os"
)

func SaveVault(path string, data []byte) error {
	return os.WriteFile(path, data, 0600)
}

func LoadVault(path string) ([]byte, error) {
	if _, err := os.Stat(path); os.IsNotExist(err) {
		return nil, err
	}
	return os.ReadFile(path)
}

func VaultExists(path string) bool {
	_, err := os.Stat(path)
	return !os.IsNotExist(err)
}
