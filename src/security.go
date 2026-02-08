package apm

import (
	"fmt"
	"os"
	"time"
)

func ChangeProfile(vault *Vault, newProfileName string, masterPassword string, vaultPath string) error {
	if _, ok := Profiles[newProfileName]; !ok {
		return fmt.Errorf("unknown profile: %s", newProfileName)
	}

	vault.Profile = newProfileName

	data, err := EncryptVault(vault, masterPassword)
	if err != nil {
		return fmt.Errorf("re-encryption failed: %v", err)
	}

	if err := os.WriteFile(vaultPath, data, 0600); err != nil {
		return fmt.Errorf("failed to save vault: %v", err)
	}

	return nil
}

func GetAvailableProfiles() []string {
	var names []string
	for k := range Profiles {
		names = append(names, k)
	}
	return names
}

func ConfigureAlerts(vault *Vault, enabled bool, email string, masterPassword string, vaultPath string) error {
	vault.AlertsEnabled = enabled
	if enabled && email != "" {
		vault.AlertEmail = email
	}

	data, err := EncryptVault(vault, masterPassword)
	if err != nil {
		return err
	}
	return os.WriteFile(vaultPath, data, 0600)
}

const (
	LevelCritical = 1
	LevelSettings = 2
	LevelAll      = 3
)

func SendAlert(vault *Vault, requiredLevel int, eventType, details string) {
	if !vault.AlertsEnabled || vault.AlertEmail == "" {
		return
	}

	// Default to level 1 for safety if not set
	vLevel := vault.SecurityLevel
	if vLevel < 1 {
		vLevel = 1
	}

	if vLevel < requiredLevel {
		return
	}

	maskedEmail := maskEmail(vault.AlertEmail)

	msg := fmt.Sprintf("[%s] ALERT (Level %d - %s): %s - Sent to %s\n", time.Now().Format(time.RFC3339), requiredLevel, eventType, details, maskedEmail)

	f, err := os.OpenFile("email.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		defer f.Close()
		_, _ = f.WriteString(msg)
	}

}

func maskEmail(email string) string {
	if len(email) <= 4 {
		return "****"
	}
	at := 0
	for i, c := range email {
		if c == '@' {
			at = i
			break
		}
	}
	if at == 0 {
		return "****"
	}
	return string(email[0]) + "****" + email[at:]
}
