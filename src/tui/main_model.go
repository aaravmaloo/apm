package tui

import (
	"fmt"
	src "password-manager/src"
	"strings"
	"unicode/utf8"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type Page int

const (
	PageVault Page = iota
	PageTOTP
	PageGenerator
	PageCloud
	PageAudit
	PageTrust
	PageHealth
	PageSession
	PageAuth
	PageMCP
	PageInfo
	PagePortability
	PageSettings
	PagePlugins
)

type MainModel struct {
	vault          *src.Vault
	masterPassword string
	vaultPath      string
	currentPage    Page
	sidebarItems   []string
	vaultList      VaultListModel
	totp           TOTPModel
	generator      GeneratorModel
	cloud          CloudModel
	portability    PortabilityModel
	settings       SettingsModel
	plugins        PluginsModel
	trust          TrustModel
	session        SessionModel
	auth           AuthModel
	mcp            MCPModel
	info           InfoModel
	width          int
	height         int
}

func NewMainModel(res *src.UnlockResult, vaultPath string) MainModel {
	return MainModel{
		vault:          res.Vault,
		masterPassword: res.MasterPassword,
		vaultPath:      vaultPath,
		currentPage:    PageVault,
		vaultList:      NewVaultListModel(res.Vault, res.MasterPassword, vaultPath),
		totp:           NewTOTPModel(res.Vault, res.MasterPassword, vaultPath),
		generator:      NewGeneratorModel(),
		cloud:          NewCloudModel(res.Vault, res.MasterPassword, vaultPath),
		portability:    NewPortabilityModel(res.Vault, res.MasterPassword, vaultPath),
		settings:       NewSettingsModel(res.Vault, res.MasterPassword, vaultPath),
		plugins:        NewPluginsModel(res.MasterPassword, vaultPath),
		trust:          NewTrustModel(res.Vault),
		session:        NewSessionModel(res.MasterPassword),
		auth:           NewAuthModel(res.Vault, res.MasterPassword, vaultPath),
		mcp:            NewMCPModel(vaultPath),
		info:           NewInfoModel(vaultPath),
		sidebarItems: []string{
			"Vault",
			"TOTP",
			"Password Generator",
			"Cloud Sync",
			"Audit Logs",
			"Trust",
			"Security Health",
			"Session",
			"Auth",
			"MCP",
			"Info / Crypto",
			"Import/Export",
			"Settings",
			"Plugins",
		},
	}
}

func (m MainModel) Init() tea.Cmd {
	return nil
}

func (m MainModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	var cmds []tea.Cmd

	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "ctrl+c", "ctrl+q":
			return m, tea.Quit
		case "ctrl+up", "pgup":
			if m.currentPage > 0 {
				m.currentPage--
			}
		case "ctrl+down", "pgdown":
			if int(m.currentPage) < len(m.sidebarItems)-1 {
				m.currentPage++
			}
		}
	case tea.WindowSizeMsg:
		m.width = msg.Width
		m.height = msg.Height
		sidebarWidth := m.sidebarWidth()
		contentWidth := m.contentWidth(sidebarWidth)
		m.vaultList.SetSize(contentWidth-2, m.height-10)
		m.totp.SetSize(contentWidth-2, m.height-10)
	}

	switch m.currentPage {
	case PageVault:
		m.vaultList, cmd = m.vaultList.Update(msg)
		cmds = append(cmds, cmd)
	case PageGenerator:
		m.generator, cmd = m.generator.Update(msg)
		cmds = append(cmds, cmd)
	case PageTOTP:
		m.totp, cmd = m.totp.Update(msg)
		cmds = append(cmds, cmd)
		m.vault = m.totp.vault
	case PageCloud:
		m.cloud, cmd = m.cloud.Update(msg)
		cmds = append(cmds, cmd)
		m.vault = m.cloud.Vault()
	case PagePortability:
		m.portability, cmd = m.portability.Update(msg)
		cmds = append(cmds, cmd)
		m.vault = m.portability.Vault()
	case PageSettings:
		m.settings, cmd = m.settings.Update(msg)
		cmds = append(cmds, cmd)
		m.vault = m.settings.Vault()
	case PagePlugins:
		m.plugins, cmd = m.plugins.Update(msg)
		cmds = append(cmds, cmd)
	case PageTrust:
		m.trust, cmd = m.trust.Update(msg)
		cmds = append(cmds, cmd)
	case PageSession:
		m.session, cmd = m.session.Update(msg)
		cmds = append(cmds, cmd)
	case PageAuth:
		m.auth, cmd = m.auth.Update(msg)
		cmds = append(cmds, cmd)
		m.vault = m.auth.Vault()
	case PageMCP:
		m.mcp, cmd = m.mcp.Update(msg)
		cmds = append(cmds, cmd)
	case PageInfo:
		m.info, cmd = m.info.Update(msg)
		cmds = append(cmds, cmd)
	}

	return m, tea.Batch(cmds...)
}

func (m MainModel) View() string {
	if m.width == 0 || m.height == 0 {
		return "Initializing..."
	}
	header := m.renderHeader()

	var sidebarContent string
	for i, item := range m.sidebarItems {
		if Page(i) == m.currentPage {
			sidebarContent += SelectedStyle.Render("> "+item) + "\n"
		} else {
			sidebarContent += NormalStyle.Render("  "+item) + "\n"
		}
	}

	sidebarWidth := m.sidebarWidth()
	contentWidth := m.contentWidth(sidebarWidth)
	bodyHeight := m.bodyHeight()
	sidebar := SidebarStyle.
		Width(sidebarWidth).
		MaxWidth(sidebarWidth).
		Height(bodyHeight).
		MaxHeight(bodyHeight).
		Render(sidebarContent)

	var content string
	switch m.currentPage {
	case PageVault:
		content = m.vaultList.View()
	case PageTOTP:
		content = m.totp.View()
	case PageGenerator:
		content = m.generator.View()
	case PageCloud:
		content = m.cloud.View()
	case PageAudit:
		content = RenderAudit(m.vault)
	case PageTrust:
		content = m.trust.View()
	case PageHealth:
		content = RenderHealth(m.vault)
	case PageSession:
		content = m.session.View()
	case PageAuth:
		content = m.auth.View()
	case PageMCP:
		content = m.mcp.View()
	case PageInfo:
		content = m.info.View()
	case PagePortability:
		content = m.portability.View()
	case PageSettings:
		content = m.settings.View()
	case PagePlugins:
		content = m.plugins.View()
	}

	safeContentWidth := contentWidth - 4
	if safeContentWidth < 20 {
		safeContentWidth = 20
	}
	clamped := lipgloss.NewStyle().
		Width(safeContentWidth).
		MaxWidth(safeContentWidth).
		MaxHeight(bodyHeight).
		Render(content)

	mainContent := ContentStyle.
		Width(contentWidth).
		MaxWidth(contentWidth).
		Height(bodyHeight).
		MaxHeight(bodyHeight).
		Render(clamped)
	body := lipgloss.JoinHorizontal(lipgloss.Top, sidebar, mainContent)
	footer := lipgloss.NewStyle().
		MaxWidth(m.width - 4).
		Render(GrayStyle.Render("\n\npgup/pgdown: sections | tab: field | ctrl+q: quit"))

	return MainStyle.Render(header + "\n\n" + body + footer)
}

func (m MainModel) sidebarWidth() int {
	maxLen := 20
	for _, item := range m.sidebarItems {
		if len(item)+4 > maxLen {
			maxLen = len(item) + 4
		}
	}
	if maxLen < 20 {
		maxLen = 20
	}
	if maxLen > 32 {
		maxLen = 32
	}
	return maxLen
}

func (m MainModel) contentWidth(sidebarWidth int) int {
	w := m.width - sidebarWidth - 12
	if w < 40 {
		w = 40
	}
	return w
}

func (m MainModel) bodyHeight() int {
	h := m.height - 6
	if h < 12 {
		h = 12
	}
	return h
}

func (m MainModel) renderHeader() string {
	title := TitleStyle.Render(" APM - Advanced Password Manager ")
	prefix := "Vault: "
	extra := 4
	maxHeader := m.width - extra
	if maxHeader < 40 {
		maxHeader = 40
	}
	titleWidth := lipgloss.Width(title)
	availablePath := maxHeader - titleWidth - 2 - utf8.RuneCountInString(prefix)
	if availablePath < 12 {
		availablePath = 12
	}
	path := truncateMiddle(m.vaultPath, availablePath)
	return title + "  " + GrayStyle.Render(fmt.Sprintf("%s%s", prefix, path))
}

func truncateMiddle(s string, maxRunes int) string {
	if maxRunes <= 0 {
		return ""
	}
	runes := []rune(s)
	if len(runes) <= maxRunes {
		return s
	}
	if maxRunes <= 3 {
		return strings.Repeat(".", maxRunes)
	}
	left := (maxRunes - 3) / 2
	right := maxRunes - 3 - left
	return string(runes[:left]) + "..." + string(runes[len(runes)-right:])
}

func RunTUI(res *src.UnlockResult, vaultPath string) error {
	p := tea.NewProgram(NewMainModel(res, vaultPath), tea.WithAltScreen())
	_, err := p.Run()
	return err
}
