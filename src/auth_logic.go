package apm

import (
	"fmt"
	"os"
	"strings"
	"time"
)

// UnlockResult represents the result of an unlock attempt
type UnlockResult struct {
	MasterPassword string
	Vault          *Vault
	ReadOnly       bool
	IsEphemeral    bool
	// FailedSince lists the wrong passwords entered since the last unlock.
	FailedSince *FailedSince
}

// AttemptUnlockWithSession tries to unlock the vault using existing sessions or ephemeral IDs
func AttemptUnlockWithSession(vaultPath string) (*UnlockResult, error) {
	if !VaultExists(vaultPath) {
		return nil, fmt.Errorf("vault not found")
	}

	if ephID := strings.TrimSpace(os.Getenv("APM_EPHEMERAL_ID")); ephID != "" {
		eph, err := ValidateEphemeralSession(ephID, os.Getpid(), strings.TrimSpace(os.Getenv("APM_EPHEMERAL_AGENT")))
		if err == nil {
			data, lerr := LoadVault(vaultPath)
			if lerr == nil {
				vault, derr := DecryptVault(data, eph.MasterPassword, 1)
				if derr == nil {
					vault.readOnly = eph.Scope == "read"
					return &UnlockResult{
						MasterPassword: eph.MasterPassword,
						Vault:          vault,
						ReadOnly:       eph.Scope == "read",
						IsEphemeral:    true,
					}, nil
				}
			}
		}
	}

	if session, err := GetSession(); err == nil {
		data, err := LoadVault(vaultPath)
		if err == nil {
			vault, err := DecryptVault(data, session.MasterPassword, 1)
			if err == nil {
				if vault.NeedsRepair && !vault.IsNewerFormat() && !session.ReadOnly {
					updatedData, _ := EncryptVault(vault, session.MasterPassword)
					SaveVault(vaultPath, updatedData)
				}
				vault.readOnly = session.ReadOnly
				return &UnlockResult{
					MasterPassword: session.MasterPassword,
					Vault:          vault,
					ReadOnly:       session.ReadOnly,
					IsEphemeral:    false,
				}, nil
			}
		}
		KillSession()
	}

	return nil, fmt.Errorf("no active session")
}

// UnlockWithPassword attempts to unlock the vault with the provided password.
// Wrong passwords go through the unlock guard, which may ask to wait before
// the next try. The right password always opens the real vault.
func UnlockWithPassword(vaultPath, password string) (*UnlockResult, error) {
	data, err := LoadVault(vaultPath)
	if err != nil {
		return nil, err
	}
	if err := CheckUnlockAllowed(data); err != nil {
		return nil, err
	}

	vault, err := DecryptVault(data, password, 1)
	if err != nil {
		return nil, RecordUnlockFailure(UnlockSourceCLI, data)
	}

	failed := RecordUnlockSuccess()
	RecordUnlockActivity(vault, UnlockActivity{Source: UnlockSourceCLI, Via: "password", FailedSince: failed})

	// A vault from a newer engine opens read-only, so it is not rewritten here.
	if !vault.IsNewerFormat() {
		updatedData, _ := EncryptVault(vault, password)
		SaveVault(vaultPath, updatedData)
	}

	CreateSession(password, 1*time.Hour, false, 15*time.Minute)

	return &UnlockResult{
		MasterPassword: password,
		Vault:          vault,
		ReadOnly:       false,
		IsEphemeral:    false,
		FailedSince:    failed,
	}, nil
}
