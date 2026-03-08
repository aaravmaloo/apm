package tui

import (
	"fmt"
	src "github.com/aaravmaloo/apm/src"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type SettingsModel struct {
	vault          *src.Vault
	masterPassword string
	vaultPath      string
	inputs         []textinput.Model
	focus          int
	status         string
	err            string
	available      []string
}

func NewSettingsModel(vault *src.Vault, masterPassword, vaultPath string) SettingsModel {
	profile := textinput.New()
	profile.Placeholder = "profile (standard/hardened/paranoid/legacy)"
	profile.SetValue(strings.TrimSpace(vault.Profile))
	profile.Focus()

	level := textinput.New()
	level.Placeholder = "security level (1-3)"
	level.SetValue(strconv.Itoa(vault.SecurityLevel))

	email := textinput.New()
	email.Placeholder = "alert email"
	email.SetValue(strings.TrimSpace(vault.AlertEmail))

	space := textinput.New()
	space.Placeholder = "active space (blank for default)"
	space.SetValue(strings.TrimSpace(vault.CurrentSpace))

	newSpace := textinput.New()
	newSpace.Placeholder = "new space name"

	policy := textinput.New()
	policy.Placeholder = "policy name (from policies/*.yaml)"
	policy.SetValue(strings.TrimSpace(vault.ActivePolicy.Name))

	m := SettingsModel{
		vault:          vault,
		masterPassword: masterPassword,
		vaultPath:      vaultPath,
		inputs:         []textinput.Model{profile, level, email, space, newSpace, policy},
		focus:          0,
	}
	m.refreshPolicies()
	return m
}

func (m SettingsModel) Vault() *src.Vault {
	return m.vault
}

func (m SettingsModel) Update(msg tea.Msg) (SettingsModel, tea.Cmd) {
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
		case "ctrl+a":
			m.vault.AlertsEnabled = !m.vault.AlertsEnabled
			m.status = fmt.Sprintf("Alerts enabled set to %v (press Enter to save)", m.vault.AlertsEnabled)
			m.err = ""
			return m, nil
		case "ctrl+n":
			name := strings.TrimSpace(m.inputs[4].Value())
			if name == "" {
				m.err = "new space name is empty"
				m.status = ""
				return m, nil
			}
			exists := false
			for _, s := range m.vault.Spaces {
				if strings.EqualFold(s, name) {
					exists = true
					break
				}
			}
			if !exists {
				m.vault.Spaces = append(m.vault.Spaces, name)
			}
			m.vault.CurrentSpace = name
			m.inputs[3].SetValue(name)
			if err := saveVault(m.vault, m.masterPassword, m.vaultPath); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.inputs[4].SetValue("")
			m.status = "Space created and activated"
			m.err = ""
			return m, nil
		case "ctrl+p":
			policyName := strings.TrimSpace(m.inputs[5].Value())
			if policyName == "" {
				m.err = "policy name is empty"
				m.status = ""
				return m, nil
			}
			policies, err := src.LoadPolicies(filepath.Join(filepath.Dir(m.vaultPath), "policies"))
			if err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			found := false
			for _, pol := range policies {
				if strings.EqualFold(pol.Name, policyName) {
					m.vault.ActivePolicy = pol
					m.inputs[5].SetValue(pol.Name)
					found = true
					break
				}
			}
			if !found {
				m.err = fmt.Sprintf("policy '%s' not found", policyName)
				m.status = ""
				return m, nil
			}
			if err := saveVault(m.vault, m.masterPassword, m.vaultPath); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.status = "Policy loaded"
			m.err = ""
			return m, nil
		case "ctrl+d":
			m.vault.ActivePolicy = src.Policy{}
			m.inputs[5].SetValue("")
			if err := saveVault(m.vault, m.masterPassword, m.vaultPath); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.status = "Policy cleared"
			m.err = ""
			return m, nil
		case "ctrl+r":
			m.refreshPolicies()
			m.status = "Policy list refreshed"
			m.err = ""
			return m, nil
		case "enter":
			updated, err := m.applyGeneral()
			if err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m = updated
			m.status = "Settings saved"
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

func (m SettingsModel) applyGeneral() (SettingsModel, error) {
	profile := strings.ToLower(strings.TrimSpace(m.inputs[0].Value()))
	if profile == "" {
		profile = "standard"
	}

	levelRaw := strings.TrimSpace(m.inputs[1].Value())
	level, err := strconv.Atoi(levelRaw)
	if err != nil || level < 1 || level > 3 {
		return m, fmt.Errorf("security level must be 1, 2, or 3")
	}

	email := strings.TrimSpace(m.inputs[2].Value())
	space := strings.TrimSpace(m.inputs[3].Value())

	if profile != strings.ToLower(strings.TrimSpace(m.vault.Profile)) {
		if err := src.ChangeProfile(m.vault, profile, m.masterPassword, m.vaultPath); err != nil {
			return m, err
		}
	}

	m.vault.SecurityLevel = level
	m.vault.AlertEmail = email
	m.vault.CurrentSpace = space

	if space != "" {
		exists := false
		for _, s := range m.vault.Spaces {
			if strings.EqualFold(s, space) {
				exists = true
				break
			}
		}
		if !exists {
			m.vault.Spaces = append(m.vault.Spaces, space)
		}
	}

	if err := saveVault(m.vault, m.masterPassword, m.vaultPath); err != nil {
		return m, err
	}
	return m, nil
}

func (m *SettingsModel) refreshPolicies() {
	policies, err := src.LoadPolicies(filepath.Join(filepath.Dir(m.vaultPath), "policies"))
	if err != nil {
		m.available = []string{}
		m.err = err.Error()
		return
	}
	names := make([]string, 0, len(policies))
	for _, p := range policies {
		names = append(names, p.Name)
	}
	sort.Strings(names)
	m.available = names
}

func (m SettingsModel) View() string {
	var b strings.Builder
	b.WriteString(TitleStyle.Render(" Application Settings "))
	b.WriteString("\n\n")
	b.WriteString("Toggle alerts: press 'a'\n")
	b.WriteString(fmt.Sprintf("Alerts Enabled: %v\n", m.vault.AlertsEnabled))
	b.WriteString(fmt.Sprintf("Current Policy: %s\n", strings.TrimSpace(m.vault.ActivePolicy.Name)))
	b.WriteString(fmt.Sprintf("Spaces: %s\n\n", strings.Join(m.vault.Spaces, ", ")))

	labels := []string{"Profile", "Security Level", "Alert Email", "Active Space", "New Space", "Policy Name"}
	for i := range m.inputs {
		b.WriteString(fmt.Sprintf("%s: %s\n", labels[i], m.inputs[i].View()))
	}

	if len(m.available) > 0 {
		b.WriteString("\nAvailable Policies: ")
		b.WriteString(strings.Join(m.available, ", "))
		b.WriteString("\n")
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
	b.WriteString(GrayStyle.Render("enter: save profile/security/alerts/space | ctrl+n: add space | ctrl+p: load policy | ctrl+d: clear policy | ctrl+r: refresh policies | ctrl+a: toggle alerts"))
	return BorderStyle.Render(b.String())
}
