package tui

import (
	"fmt"
	src "password-manager/src"
)

func RenderCloud(vault *src.Vault) string {
	var s string
	s += TitleStyle.Render(" Cloud Synchronization ") + "\n\n"

	s += "Active Providers:\n"
	if vault.CloudFileID != "" {
		s += fmt.Sprintf("- Google Drive: Active (Mode: %s)\n", vault.DriveSyncMode)
	}
	if vault.GitHubToken != "" {
		s += fmt.Sprintf("- GitHub: Active (Repo: %s)\n", vault.GitHubRepo)
	}
	if vault.DropboxToken != nil {
		s += fmt.Sprintf("- Dropbox: Active (Mode: %s)\n", vault.DropboxSyncMode)
	}

	if vault.CloudFileID == "" && vault.GitHubToken == "" && vault.DropboxToken == nil {
		s += "No cloud synchronization configured.\n"
	}

	s += "\n" + GrayStyle.Render("Cloud actions are now available directly in the Cloud page.")

	return BorderStyle.Render(s)
}

func RenderSettings(vault *src.Vault) string {
	var s string
	s += TitleStyle.Render(" Application Settings ") + "\n\n"

	s += fmt.Sprintf("Security Level: %d\n", vault.SecurityLevel)
	s += fmt.Sprintf("Alerts Enabled: %v\n", vault.AlertsEnabled)
	if vault.AlertEmail != "" {
		s += fmt.Sprintf("Alert Email:    %s\n", vault.AlertEmail)
	}
	s += fmt.Sprintf("Active Space:   %s\n", vault.CurrentSpace)
	s += fmt.Sprintf("Profile:        %s\n", vault.Profile)

	s += "\n" + GrayStyle.Render("Settings are editable directly in this TUI.")

	return BorderStyle.Render(s)
}
