package tui

import (
	"fmt"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type PluginsModel struct {
	vaultPath   string
	master      string
	installed   []string
	marketplace []string
	commands    []string
	commandDefs []PluginCommandSpec
	marketIdx   int
	installIdx  int
	commandIdx  int
	listFocus   int
	nameInput   textinput.Model
	localInput  textinput.Model
	pushInput   textinput.Model
	commandIn   textinput.Model
	flagsInput  textinput.Model
	focus       int
	status      string
	err         string
}

func NewPluginsModel(masterPassword, vaultPath string) PluginsModel {
	name := textinput.New()
	name.Placeholder = "plugin name"
	name.Focus()
	name.Width = 32

	local := textinput.New()
	local.Placeholder = "local plugin directory"
	local.Width = 48

	push := textinput.New()
	push.Placeholder = "push source path (optional)"
	push.Width = 48

	cmdIn := textinput.New()
	cmdIn.Placeholder = "command name (or selected)"
	cmdIn.Width = 32

	flags := textinput.New()
	flags.Placeholder = "flags as key=value key2=value2"
	flags.Width = 48

	m := PluginsModel{
		vaultPath:  vaultPath,
		master:     masterPassword,
		nameInput:  name,
		localInput: local,
		pushInput:  push,
		commandIn:  cmdIn,
		flagsInput: flags,
		focus:      0,
	}
	m = m.refreshWithStatus("Plugin state loaded")
	return m
}

func (m PluginsModel) Update(msg tea.Msg) (PluginsModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab":
			m.blurAll()
			m.focus = (m.focus + 1) % 5
			m.focusCurrent()
			return m, nil
		case "shift+tab":
			m.blurAll()
			m.focus = (m.focus - 1 + 5) % 5
			m.focusCurrent()
			return m, nil
		case "ctrl+r":
			m = m.refreshWithStatus("Plugin lists refreshed")
			return m, nil
		case "ctrl+left":
			m.listFocus = (m.listFocus - 1 + 3) % 3
			return m, nil
		case "ctrl+right":
			m.listFocus = (m.listFocus + 1) % 3
			return m, nil
		case "ctrl+up":
			if m.listFocus == 0 && len(m.marketplace) > 0 {
				m.marketIdx = (m.marketIdx - 1 + len(m.marketplace)) % len(m.marketplace)
			}
			if m.listFocus == 1 && len(m.installed) > 0 {
				m.installIdx = (m.installIdx - 1 + len(m.installed)) % len(m.installed)
				m = m.refreshCommands()
			}
			if m.listFocus == 2 && len(m.commands) > 0 {
				m.commandIdx = (m.commandIdx - 1 + len(m.commands)) % len(m.commands)
				if m.commandIdx < len(m.commandDefs) {
					m.commandIn.SetValue(m.commandDefs[m.commandIdx].Name)
				}
			}
			return m, nil
		case "ctrl+down":
			if m.listFocus == 0 && len(m.marketplace) > 0 {
				m.marketIdx = (m.marketIdx + 1) % len(m.marketplace)
			}
			if m.listFocus == 1 && len(m.installed) > 0 {
				m.installIdx = (m.installIdx + 1) % len(m.installed)
				m = m.refreshCommands()
			}
			if m.listFocus == 2 && len(m.commands) > 0 {
				m.commandIdx = (m.commandIdx + 1) % len(m.commands)
				if m.commandIdx < len(m.commandDefs) {
					m.commandIn.SetValue(m.commandDefs[m.commandIdx].Name)
				}
			}
			return m, nil
		case "ctrl+g":
			name := strings.TrimSpace(m.nameInput.Value())
			if name == "" && len(m.marketplace) > 0 {
				name = m.marketplace[m.marketIdx]
				m.nameInput.SetValue(name)
			}
			if err := installMarketplacePlugin(name); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m = m.refreshWithStatus("Marketplace plugin installed")
			return m, nil
		case "ctrl+u":
			name := strings.TrimSpace(m.nameInput.Value())
			if name == "" && len(m.installed) > 0 {
				name = m.installed[m.installIdx]
				m.nameInput.SetValue(name)
			}
			if err := removeInstalledPlugin(name); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m = m.refreshWithStatus("Plugin removed")
			return m, nil
		case "ctrl+l":
			name, err := installLocalPlugin(m.localInput.Value())
			if err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.nameInput.SetValue(name)
			m = m.refreshWithStatus("Local plugin installed")
			return m, nil
		case "ctrl+p":
			if err := pushPluginToMarketplace(m.nameInput.Value(), m.pushInput.Value()); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m = m.refreshWithStatus("Plugin pushed to marketplace")
			return m, nil
		case "ctrl+x":
			pluginName := strings.TrimSpace(m.nameInput.Value())
			if pluginName == "" && len(m.installed) > 0 {
				pluginName = m.installed[m.installIdx]
				m.nameInput.SetValue(pluginName)
			}
			commandName := strings.TrimSpace(m.commandIn.Value())
			if commandName == "" && len(m.commandDefs) > 0 && m.commandIdx < len(m.commandDefs) {
				commandName = m.commandDefs[m.commandIdx].Name
				m.commandIn.SetValue(commandName)
			}
			if err := executeInstalledPluginCommand(pluginName, commandName, m.flagsInput.Value(), m.master, m.vaultPath); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.err = ""
			m.status = fmt.Sprintf("Executed %s/%s", pluginName, commandName)
			return m, nil
		}
	}

	var cmd tea.Cmd
	switch m.focus {
	case 0:
		m.nameInput, cmd = m.nameInput.Update(msg)
	case 1:
		m.localInput, cmd = m.localInput.Update(msg)
	case 2:
		m.pushInput, cmd = m.pushInput.Update(msg)
	case 3:
		m.commandIn, cmd = m.commandIn.Update(msg)
	case 4:
		m.flagsInput, cmd = m.flagsInput.Update(msg)
	}
	return m, cmd
}

func (m PluginsModel) View() string {
	var b strings.Builder
	b.WriteString(TitleStyle.Render(" Plugins "))
	b.WriteString("\n\n")
	b.WriteString("Name:       ")
	b.WriteString(m.nameInput.View())
	b.WriteString("\n")
	b.WriteString("Local Path: ")
	b.WriteString(m.localInput.View())
	b.WriteString("\n")
	b.WriteString("Push Path:  ")
	b.WriteString(m.pushInput.View())
	b.WriteString("\n\n")

	b.WriteString("Installed:\n")
	if len(m.installed) == 0 {
		b.WriteString("- (none)\n")
	} else {
		for i, p := range m.installed {
			prefix := "  "
			if m.listFocus == 1 && i == m.installIdx {
				prefix = "> "
			}
			b.WriteString(prefix + p + "\n")
		}
	}

	b.WriteString("\nMarketplace (Google Drive):\n")
	if len(m.marketplace) == 0 {
		b.WriteString("- (none or unavailable)\n")
	} else {
		for i, p := range m.marketplace {
			prefix := "  "
			if m.listFocus == 0 && i == m.marketIdx {
				prefix = "> "
			}
			b.WriteString(prefix + p + "\n")
		}
	}

	b.WriteString("\nRegistered Commands (selected installed plugin):\n")
	if len(m.commands) == 0 {
		b.WriteString("- (none)\n")
	} else {
		for i, cmd := range m.commands {
			prefix := "  "
			if m.listFocus == 2 && i == m.commandIdx {
				prefix = "> "
			}
			b.WriteString(prefix + cmd + "\n")
		}
	}
	b.WriteString("\nCommand:    ")
	b.WriteString(m.commandIn.View())
	b.WriteString("\n")
	b.WriteString("Cmd Flags:  ")
	b.WriteString(m.flagsInput.View())
	b.WriteString("\n")

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
	b.WriteString(GrayStyle.Render("ctrl+g: install marketplace | ctrl+l: install local | ctrl+u: uninstall | ctrl+p: push | ctrl+x: run selected command | ctrl+left/right: list focus | ctrl+up/down: select | ctrl+r: refresh"))
	return BorderStyle.Render(b.String())
}

func (m PluginsModel) refreshWithStatus(status string) PluginsModel {
	installed, iErr := listInstalledPlugins()
	marketplace, mErr := listMarketplacePlugins()

	m.installed = installed
	m.marketplace = marketplace
	m.status = status
	m.err = ""
	if iErr != nil {
		m.err = fmt.Sprintf("installed list failed: %v", iErr)
		m.status = ""
		return m
	}
	if len(m.installed) > 0 {
		if m.installIdx >= len(m.installed) {
			m.installIdx = len(m.installed) - 1
		}
		if m.installIdx < 0 {
			m.installIdx = 0
		}
	} else {
		m.installIdx = 0
	}
	if len(m.marketplace) > 0 {
		if m.marketIdx >= len(m.marketplace) {
			m.marketIdx = len(m.marketplace) - 1
		}
		if m.marketIdx < 0 {
			m.marketIdx = 0
		}
	} else {
		m.marketIdx = 0
	}
	m = m.refreshCommands()
	if mErr != nil {
		m.err = fmt.Sprintf("marketplace list failed: %v", mErr)
	}
	return m
}

func (m PluginsModel) refreshCommands() PluginsModel {
	m.commands = []string{}
	m.commandDefs = []PluginCommandSpec{}
	if len(m.installed) == 0 {
		return m
	}
	specs, err := getInstalledPluginCommandSpecs(m.installed[m.installIdx])
	if err != nil {
		m.err = fmt.Sprintf("command list failed: %v", err)
		return m
	}
	rows := make([]string, 0, len(specs))
	for _, spec := range specs {
		if strings.TrimSpace(spec.Description) == "" {
			rows = append(rows, spec.Name)
		} else {
			rows = append(rows, fmt.Sprintf("%s - %s", spec.Name, spec.Description))
		}
	}
	m.commandDefs = specs
	m.commands = rows
	if len(m.commandDefs) > 0 {
		if m.commandIdx >= len(m.commandDefs) {
			m.commandIdx = len(m.commandDefs) - 1
		}
		if m.commandIdx < 0 {
			m.commandIdx = 0
		}
		m.commandIn.SetValue(m.commandDefs[m.commandIdx].Name)
	} else {
		m.commandIdx = 0
		m.commandIn.SetValue("")
	}
	return m
}

func (m *PluginsModel) blurAll() {
	m.nameInput.Blur()
	m.localInput.Blur()
	m.pushInput.Blur()
	m.commandIn.Blur()
	m.flagsInput.Blur()
}

func (m *PluginsModel) focusCurrent() {
	switch m.focus {
	case 0:
		m.nameInput.Focus()
	case 1:
		m.localInput.Focus()
	case 2:
		m.pushInput.Focus()
	case 3:
		m.commandIn.Focus()
	case 4:
		m.flagsInput.Focus()
	}
}
