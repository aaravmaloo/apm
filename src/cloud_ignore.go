package apm

import (
	"os"
	"strings"
)

func PrepareCloudUploadVaultPath(vault *Vault, masterPassword, vaultPath, provider string) (string, func(), error) {
	cleanup := func() {}

	cfg, _, err := LoadIgnoreConfigForVault(vaultPath)
	if err != nil {
		return "", cleanup, err
	}
	if cfg.IsEmpty() || vault == nil {
		return vaultPath, cleanup, nil
	}

	filtered := cfg.FilterVaultForProvider(vault, strings.ToLower(strings.TrimSpace(provider)))
	data, err := EncryptVault(filtered, masterPassword)
	if err != nil {
		return "", cleanup, err
	}

	tmp, err := os.CreateTemp("", "apm-cloud-upload-*.dat")
	if err != nil {
		return "", cleanup, err
	}
	tmpPath := tmp.Name()
	if _, err := tmp.Write(data); err != nil {
		tmp.Close()
		_ = os.Remove(tmpPath)
		return "", cleanup, err
	}
	if err := tmp.Close(); err != nil {
		_ = os.Remove(tmpPath)
		return "", cleanup, err
	}

	cleanup = func() {
		_ = os.Remove(tmpPath)
	}
	return tmpPath, cleanup, nil
}
