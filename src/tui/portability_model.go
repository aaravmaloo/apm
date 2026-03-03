package tui

import (
	"fmt"
	src "password-manager/src"
	"path/filepath"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type PortabilityModel struct {
	vault          *src.Vault
	masterPassword string
	vaultPath      string
	fileInput      textinput.Model
	passInput      textinput.Model
	focus          int
	status         string
	err            string
}

func NewPortabilityModel(vault *src.Vault, masterPassword, vaultPath string) PortabilityModel {
	file := textinput.New()
	file.Placeholder = "file path (e.g. export.json or import.csv)"
	file.Focus()
	file.Width = 60

	pass := textinput.New()
	pass.Placeholder = "optional import decrypt/export encrypt password"
	pass.Width = 50

	return PortabilityModel{
		vault:          vault,
		masterPassword: masterPassword,
		vaultPath:      vaultPath,
		fileInput:      file,
		passInput:      pass,
	}
}

func (m PortabilityModel) Vault() *src.Vault {
	return m.vault
}

func (m PortabilityModel) Update(msg tea.Msg) (PortabilityModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab":
			if m.focus == 0 {
				m.fileInput.Blur()
				m.passInput.Focus()
				m.focus = 1
			} else {
				m.passInput.Blur()
				m.fileInput.Focus()
				m.focus = 0
			}
			return m, nil
		case "ctrl+e":
			if err := m.exportToFile(); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.status = "Export complete"
			m.err = ""
			return m, nil
		case "ctrl+y":
			if err := m.importFromFile(); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.status = "Import complete"
			m.err = ""
			return m, nil
		}
	}

	if m.focus == 0 {
		var cmd tea.Cmd
		m.fileInput, cmd = m.fileInput.Update(msg)
		return m, cmd
	}
	var cmd tea.Cmd
	m.passInput, cmd = m.passInput.Update(msg)
	return m, cmd
}

func (m PortabilityModel) exportToFile() error {
	path := strings.TrimSpace(m.fileInput.Value())
	if path == "" {
		path = "export.json"
		m.fileInput.SetValue(path)
	}
	ext := strings.ToLower(filepath.Ext(path))
	pass := strings.TrimSpace(m.passInput.Value())

	switch ext {
	case ".txt":
		return src.ExportToTXT(m.vault, path, false)
	case ".csv":
		return src.ExportToCSV(m.vault, path)
	default:
		return src.ExportToJSON(m.vault, path, pass)
	}
}

func (m PortabilityModel) importFromFile() error {
	path := strings.TrimSpace(m.fileInput.Value())
	if path == "" {
		return fmt.Errorf("file path is required")
	}
	ext := strings.ToLower(filepath.Ext(path))
	pass := strings.TrimSpace(m.passInput.Value())

	switch ext {
	case ".json":
		if err := src.ImportFromJSON(m.vault, path, pass); err != nil {
			return err
		}
	case ".csv":
		if err := src.ImportFromCSV(m.vault, path); err != nil {
			return err
		}
	case ".txt":
		if err := src.ImportFromTXT(m.vault, path); err != nil {
			return err
		}
	default:
		return fmt.Errorf("unsupported extension '%s' (use .json/.csv/.txt)", ext)
	}

	return saveVault(m.vault, m.masterPassword, m.vaultPath)
}

func (m PortabilityModel) View() string {
	var b strings.Builder
	b.WriteString(TitleStyle.Render(" Import / Export "))
	b.WriteString("\n\n")
	b.WriteString("File:     ")
	b.WriteString(m.fileInput.View())
	b.WriteString("\n")
	b.WriteString("Password: ")
	b.WriteString(m.passInput.View())
	b.WriteString("\n\n")
	b.WriteString("Actions:\n")
	b.WriteString("- Press 'ctrl+e' to export\n")
	b.WriteString("- Press 'ctrl+y' to import\n")
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
	b.WriteString(GrayStyle.Render("Supported formats: .json .csv .txt | tab: switch field"))
	return BorderStyle.Render(b.String())
}
