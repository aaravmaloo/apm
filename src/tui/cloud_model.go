package tui

import (
	"fmt"
	src "password-manager/src"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type CloudModel struct {
	vault          *src.Vault
	masterPassword string
	vaultPath      string
	providers      []string
	providerIdx    int
	modes          []string
	modeIdx        int
	inputs         []textinput.Model
	focus          int
	keyConsent     bool
	status         string
	err            string
}

func NewCloudModel(vault *src.Vault, masterPassword, vaultPath string) CloudModel {
	key := textinput.New()
	key.Placeholder = "retrieval key (optional)"
	key.Focus()
	key.Width = 40

	ghToken := textinput.New()
	ghToken.Placeholder = "github token"
	ghToken.Width = 44

	ghRepo := textinput.New()
	ghRepo.Placeholder = "github repo (owner/repo)"
	ghRepo.SetValue(strings.TrimSpace(vault.GitHubRepo))
	ghRepo.Width = 36

	dbToken := textinput.New()
	dbToken.Placeholder = "dropbox access token (optional for self-hosted)"
	dbToken.Width = 44

	appKey := textinput.New()
	appKey.Placeholder = "dropbox app key (self-hosted browser auth)"
	appKey.Width = 44

	appSecret := textinput.New()
	appSecret.Placeholder = "dropbox app secret (self-hosted browser auth)"
	appSecret.Width = 44

	m := CloudModel{
		vault:          vault,
		masterPassword: masterPassword,
		vaultPath:      vaultPath,
		providers:      []string{"gdrive", "github", "dropbox"},
		modes:          []string{"apm_public", "self_hosted"},
		inputs:         []textinput.Model{key, ghToken, ghRepo, dbToken, appKey, appSecret},
		focus:          0,
		keyConsent:     vault.DriveKeyMetadataConsent || vault.DropboxKeyMetadataConsent,
	}
	if strings.EqualFold(vault.DriveSyncMode, "self_hosted") || strings.EqualFold(vault.DropboxSyncMode, "self_hosted") {
		m.modeIdx = 1
	}
	return m
}

func (m CloudModel) Vault() *src.Vault {
	return m.vault
}

func (m CloudModel) Update(msg tea.Msg) (CloudModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab":
			m.inputs[m.focus].Blur()
			m.focus = (m.focus + 1) % len(m.inputs)
			m.inputs[m.focus].Focus()
			return m, nil
		case "shift+tab":
			m.inputs[m.focus].Blur()
			m.focus = (m.focus - 1 + len(m.inputs)) % len(m.inputs)
			m.inputs[m.focus].Focus()
			return m, nil
		case "ctrl+left":
			m.providerIdx = (m.providerIdx - 1 + len(m.providers)) % len(m.providers)
			m.status = ""
			m.err = ""
			return m, nil
		case "ctrl+right":
			m.providerIdx = (m.providerIdx + 1) % len(m.providers)
			m.status = ""
			m.err = ""
			return m, nil
		case "ctrl+o":
			m.modeIdx = (m.modeIdx + 1) % len(m.modes)
			m.status = fmt.Sprintf("Mode set to %s", m.currentMode())
			m.err = ""
			return m, nil
		case "ctrl+k":
			m.keyConsent = !m.keyConsent
			m.status = fmt.Sprintf("Store key metadata: %v", m.keyConsent)
			m.err = ""
			return m, nil
		case "ctrl+y":
			if err := setupCloudProvider(
				m.vault,
				m.masterPassword,
				m.vaultPath,
				m.currentProvider(),
				m.currentMode(),
				m.inputs[0].Value(),
				m.inputs[1].Value(),
				m.inputs[2].Value(),
				m.inputs[3].Value(),
				m.inputs[4].Value(),
				m.inputs[5].Value(),
				m.keyConsent,
			); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.status = fmt.Sprintf("%s initialized", m.currentProvider())
			m.err = ""
			return m, nil
		case "ctrl+f":
			if err := syncCloudProvider(m.vault, m.masterPassword, m.vaultPath, m.currentProvider()); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.status = fmt.Sprintf("%s synced", m.currentProvider())
			m.err = ""
			return m, nil
		case "ctrl+x":
			if err := resetCloudMetadata(m.vault, m.masterPassword, m.vaultPath); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.status = "Cloud metadata reset"
			m.err = ""
			return m, nil
		}
	}

	cmds := make([]tea.Cmd, len(m.inputs))
	for i := range m.inputs {
		m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
	}
	return m, tea.Batch(cmds...)
}

func (m CloudModel) View() string {
	var b strings.Builder
	configured := m.vault.CloudFileID != "" || m.vault.GitHubRepo != "" || m.vault.DropboxFileID != ""

	if !configured {
		b.WriteString(TitleStyle.Render(" Cloud Setup "))
		b.WriteString("\n\n")
		b.WriteString("Cloud sync is not configured yet.\n")
		b.WriteString("Complete setup below, then press 'i' to initialize.\n\n")
	} else {
		b.WriteString(TitleStyle.Render(" Cloud Sync "))
		b.WriteString("\n\n")
	}

	b.WriteString(fmt.Sprintf("Provider: %s (left/right)\n", m.currentProvider()))
	b.WriteString(fmt.Sprintf("Mode:     %s (m to toggle)\n", m.currentMode()))
	b.WriteString(fmt.Sprintf("Store key metadata hash: %v (k to toggle)\n\n", m.keyConsent))

	b.WriteString("Retrieval Key: ")
	b.WriteString(m.inputs[0].View())
	b.WriteString("\n")
	if m.currentProvider() == "github" {
		b.WriteString("GitHub Token:  ")
		b.WriteString(m.inputs[1].View())
		b.WriteString("\n")
		b.WriteString("GitHub Repo:   ")
		b.WriteString(m.inputs[2].View())
		b.WriteString("\n")
	}
	if m.currentProvider() == "dropbox" && m.currentMode() == "self_hosted" {
		b.WriteString("Dropbox Token: ")
		b.WriteString(m.inputs[3].View())
		b.WriteString("\n")
		b.WriteString("App Key:       ")
		b.WriteString(m.inputs[4].View())
		b.WriteString("\n")
		b.WriteString("App Secret:    ")
		b.WriteString(m.inputs[5].View())
		b.WriteString("\n")
	}

	b.WriteString("\nCurrent state:\n")
	if m.vault.CloudFileID != "" {
		b.WriteString(fmt.Sprintf("- Google Drive: active (mode=%s, file=%s)\n", m.vault.DriveSyncMode, m.vault.CloudFileID))
	}
	if m.vault.GitHubRepo != "" {
		b.WriteString(fmt.Sprintf("- GitHub: active (repo=%s)\n", m.vault.GitHubRepo))
	}
	if m.vault.DropboxFileID != "" {
		b.WriteString(fmt.Sprintf("- Dropbox: active (mode=%s, file=%s)\n", m.vault.DropboxSyncMode, m.vault.DropboxFileID))
	}
	if m.vault.CloudFileID == "" && m.vault.GitHubRepo == "" && m.vault.DropboxFileID == "" {
		b.WriteString("- No providers configured\n")
	}

	b.WriteString("\n")
	if m.err != "" {
		b.WriteString(ErrorStyle.Render("Error: " + m.err))
		b.WriteString("\n")
	}
	if m.status != "" {
		b.WriteString(SuccessStyle.Render(m.status))
		b.WriteString("\n")
	}

	b.WriteString("\n")
	if !configured {
		b.WriteString(GrayStyle.Render("ctrl+y: initialize cloud setup | ctrl+left/right: provider | ctrl+o: mode | ctrl+k: key-consent | tab: field"))
	} else {
		b.WriteString(GrayStyle.Render("ctrl+y: re-initialize provider | ctrl+f: sync provider | ctrl+x: reset all cloud metadata | ctrl+left/right: provider | ctrl+o: mode | ctrl+k: key-consent | tab: field"))
	}
	return BorderStyle.Render(b.String())
}

func (m CloudModel) currentProvider() string {
	return m.providers[m.providerIdx]
}

func (m CloudModel) currentMode() string {
	return m.modes[m.modeIdx]
}
