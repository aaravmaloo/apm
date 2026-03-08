package tui

import (
	src "github.com/aaravmaloo/apm/src"
	"sort"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type MCPModel struct {
	vaultPath   string
	inputs      []textinput.Model
	focus       int
	tokens      []src.MCPToken
	configFiles []string
	status      string
	err         string
}

func NewMCPModel(vaultPath string) MCPModel {
	name := textinput.New()
	name.Placeholder = "token name"
	name.Focus()
	name.Width = 24

	perms := textinput.New()
	perms.Placeholder = "permissions comma-separated"
	perms.SetValue(strings.Join(src.MCPToolPermissions(), ","))
	perms.Width = 56

	exp := textinput.New()
	exp.Placeholder = "expiry minutes (0=no expiry)"
	exp.SetValue("0")
	exp.Width = 24

	revoke := textinput.New()
	revoke.Placeholder = "revoke token or name"
	revoke.Width = 36

	cfg := textinput.New()
	cfg.Placeholder = "config path (optional)"
	cfg.Width = 64

	m := MCPModel{vaultPath: vaultPath, inputs: []textinput.Model{name, perms, exp, revoke, cfg}}
	m.refresh()
	if len(m.configFiles) > 0 {
		m.inputs[4].SetValue(m.configFiles[0])
	}
	return m
}

func (m MCPModel) Update(msg tea.Msg) (MCPModel, tea.Cmd) {
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
		case "r", "ctrl+r":
			m.refresh()
			m.err = ""
			m.status = "MCP state refreshed"
			return m, nil
		case "ctrl+t":
			if err := m.createToken(); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.refresh()
			m.err = ""
			m.status = "MCP token created"
			return m, nil
		case "ctrl+x":
			ok, err := src.RevokeMCPToken(strings.TrimSpace(m.inputs[3].Value()))
			if err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			if !ok {
				m.err = "token/name not found"
				m.status = ""
				return m, nil
			}
			m.refresh()
			m.err = ""
			m.status = "MCP token revoked"
			return m, nil
		case "ctrl+w":
			if err := m.writeConfig(); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.err = ""
			m.status = "MCP config updated"
			return m, nil
		}
	}

	cmds := make([]tea.Cmd, len(m.inputs))
	for i := range m.inputs {
		m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
	}
	return m, tea.Batch(cmds...)
}

func (m *MCPModel) refresh() {
	list, err := src.ListMCPTokens()
	if err == nil {
		sort.Slice(list, func(i, j int) bool { return list[i].Name < list[j].Name })
		m.tokens = list
	}
	m.configFiles = src.FindMCPConfigFiles()
}

func (m MCPModel) createToken() error {
	name := strings.TrimSpace(m.inputs[0].Value())
	if name == "" {
		return srcErr("token name is required")
	}
	expMin, err := strconv.Atoi(strings.TrimSpace(m.inputs[2].Value()))
	if err != nil || expMin < 0 {
		return srcErr("expiry must be >= 0")
	}
	permRaw := strings.TrimSpace(m.inputs[1].Value())
	if permRaw == "" {
		return srcErr("permissions are required")
	}
	parts := strings.Split(permRaw, ",")
	perms := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			perms = append(perms, p)
		}
	}
	_, err = src.GenerateMCPToken(name, perms, expMin)
	return err
}

func (m MCPModel) writeConfig() error {
	path := strings.TrimSpace(m.inputs[4].Value())
	if path == "" {
		return srcErr("config path is required")
	}
	if len(m.tokens) == 0 {
		return srcErr("no MCP token exists; create one first")
	}
	return src.UpdateMCPConfigWithToken(path, m.tokens[0].Token)
}

func (m MCPModel) View() string {
	configured := len(m.tokens) > 0
	var b strings.Builder
	if !configured {
		b.WriteString(TitleStyle.Render(" MCP Setup "))
		b.WriteString("\n\nNo MCP tokens found. Create one to configure MCP clients.\n\n")
	} else {
		b.WriteString(TitleStyle.Render(" MCP Manager "))
		b.WriteString("\n\n")
	}

	b.WriteString("Token Name: " + m.inputs[0].View() + "\n")
	b.WriteString("Permissions:" + m.inputs[1].View() + "\n")
	b.WriteString("Expiry Min: " + m.inputs[2].View() + "\n")
	b.WriteString("Revoke Key: " + m.inputs[3].View() + "\n")
	b.WriteString("Config Path:" + m.inputs[4].View() + "\n")

	b.WriteString("\nDetected MCP config files:\n")
	if len(m.configFiles) == 0 {
		b.WriteString("- none\n")
	} else {
		for _, p := range m.configFiles {
			b.WriteString("- " + p + "\n")
		}
	}

	b.WriteString("\nTokens:\n")
	if len(m.tokens) == 0 {
		b.WriteString("- none\n")
	} else {
		for _, t := range m.tokens {
			exp := "never"
			if !t.ExpiresAt.IsZero() {
				exp = t.ExpiresAt.Format("2006-01-02 15:04")
			}
			b.WriteString("- " + t.Name + " | expires=" + exp + " | uses=" + strconv.Itoa(t.UsageCount) + "\n")
		}
	}

	b.WriteString("\n")
	if m.err != "" {
		b.WriteString(ErrorStyle.Render("Error: "+m.err) + "\n")
	}
	if m.status != "" {
		b.WriteString(SuccessStyle.Render(m.status) + "\n")
	}
	b.WriteString("\n")
	b.WriteString(GrayStyle.Render("ctrl+t: create token | ctrl+x: revoke token/name | ctrl+w: write first token to config file | ctrl+r: refresh"))
	return BorderStyle.Render(b.String())
}

func srcErr(msg string) error { return &simpleErr{msg: msg} }

type simpleErr struct{ msg string }

func (e *simpleErr) Error() string { return e.msg }
