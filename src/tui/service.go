package tui

import (
	"fmt"
	src "github.com/aaravmaloo/apm/src"
)

func saveVault(vault *src.Vault, masterPassword, vaultPath string) error {
	data, err := src.EncryptVault(vault, masterPassword)
	if err != nil {
		return fmt.Errorf("encrypt failed: %w", err)
	}
	if err := src.SaveVault(vaultPath, data); err != nil {
		return fmt.Errorf("save failed: %w", err)
	}
	return nil
}
