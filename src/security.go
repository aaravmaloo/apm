package apm

import (
	"fmt"
	"os"
	"time"
)

func ChangeProfile(vault *Vault, newProfileName string, masterPassword string, vaultPath string) error {
	// Validate profile exists
	if _, ok := Profiles[newProfileName]; !ok {
		return fmt.Errorf("unknown profile: %s", newProfileName)
	}

	vault.Profile = newProfileName

	data, err := EncryptVault(vault, masterPassword)
	if err != nil {
		return fmt.Errorf("re-encryption failed: %v", err)
	}

	// Save
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

// Alerts

func ConfigureAlerts(vault *Vault, enabled bool, email string, masterPassword string, vaultPath string) error {
	vault.AlertsEnabled = enabled
	if enabled && email != "" {
		vault.AlertEmail = email
	}

	// Save changes
	data, err := EncryptVault(vault, masterPassword)
	if err != nil {
		return err
	}
	return os.WriteFile(vaultPath, data, 0600)
}

func SendAlert(vault *Vault, eventType, details string) {
	if !vault.AlertsEnabled || vault.AlertEmail == "" {
		return
	}

	// Obfuscate Email for logging
	maskedEmail := maskEmail(vault.AlertEmail)

	// Log to local file (Mock Service)
	msg := fmt.Sprintf("[%s] ALERT (%s): %s - Sent to %s\n", time.Now().Format(time.RFC3339), eventType, details, maskedEmail)

	f, err := os.OpenFile("email.log", os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
	if err == nil {
		defer f.Close()
		f.WriteString(msg)
	}

	// In real implementation, use smtp.SendMail here.
}

func maskEmail(email string) string {
	if len(email) <= 4 {
		return "****"
	}
	// Simple mask: a***@gmail.com
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
