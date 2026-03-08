package tui

import (
	src "github.com/aaravmaloo/apm/src"
	"strings"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type totpItem struct {
	account string
	secret  string
}

func (i totpItem) Title() string       { return i.account }
func (i totpItem) Description() string { return "TOTP" }
func (i totpItem) FilterValue() string { return i.account }

type TOTPModel struct {
	vault          *src.Vault
	masterPassword string
	vaultPath      string
	list           list.Model
	addMode        bool
	inputs         []textinput.Model
	focus          int
	status         string
	err            string
}

func NewTOTPModel(vault *src.Vault, masterPassword, vaultPath string) TOTPModel {
	items := make([]list.Item, 0, len(vault.TOTPEntries))
	for _, e := range vault.TOTPEntries {
		items = append(items, totpItem{account: e.Account, secret: e.Secret})
	}
	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "TOTP Accounts"
	l.SetShowHelp(false)
	l.SetShowPagination(false)
	l.SetFilteringEnabled(true)
	l.Styles.Title = TitleStyle

	acc := textinput.New()
	acc.Placeholder = "Account"
	acc.Focus()
	acc.Width = 32

	secret := textinput.New()
	secret.Placeholder = "Secret"
	secret.Width = 44

	return TOTPModel{
		vault:          vault,
		masterPassword: masterPassword,
		vaultPath:      vaultPath,
		list:           l,
		inputs:         []textinput.Model{acc, secret},
	}
}

func (m *TOTPModel) SetSize(width, height int) {
	m.list.SetSize(width, height)
}

func (m TOTPModel) Update(msg tea.Msg) (TOTPModel, tea.Cmd) {
	if m.addMode {
		return m.updateAdd(msg)
	}

	if m.list.FilterState() == list.Filtering {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "a":
			m.addMode = true
			m.status = "Add mode"
			m.err = ""
			return m, nil
		case "d":
			item, ok := m.list.SelectedItem().(totpItem)
			if !ok {
				m.err = "no TOTP selected"
				m.status = ""
				return m, nil
			}
			if !m.vault.DeleteTOTPEntry(item.account) {
				m.err = "entry not found"
				m.status = ""
				return m, nil
			}
			if err := saveVault(m.vault, m.masterPassword, m.vaultPath); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.refresh()
			m.status = "TOTP deleted"
			m.err = ""
			return m, nil
		case "c":
			item, ok := m.list.SelectedItem().(totpItem)
			if !ok {
				m.err = "no TOTP selected"
				m.status = ""
				return m, nil
			}
			code, err := src.GenerateTOTP(item.secret)
			if err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			if err := clipboard.WriteAll(code); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.status = "Current TOTP copied"
			m.err = ""
			return m, nil
		case "r", "ctrl+r":
			m.refresh()
			m.status = "TOTP list refreshed"
			m.err = ""
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m TOTPModel) updateAdd(msg tea.Msg) (TOTPModel, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "esc":
			m.addMode = false
			m.inputs[0].SetValue("")
			m.inputs[1].SetValue("")
			return m, nil
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
		case "enter":
			acc := strings.TrimSpace(m.inputs[0].Value())
			sec := strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(m.inputs[1].Value()), " ", ""))
			if acc == "" || sec == "" {
				m.err = "account and secret are required"
				m.status = ""
				return m, nil
			}
			if err := m.vault.AddTOTPEntry(acc, sec); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			if err := saveVault(m.vault, m.masterPassword, m.vaultPath); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.inputs[0].SetValue("")
			m.inputs[1].SetValue("")
			m.addMode = false
			m.refresh()
			m.status = "TOTP added"
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

func (m *TOTPModel) refresh() {
	items := make([]list.Item, 0, len(m.vault.TOTPEntries))
	for _, e := range m.vault.TOTPEntries {
		items = append(items, totpItem{account: e.Account, secret: e.Secret})
	}
	m.list.SetItems(items)
}

func (m TOTPModel) View() string {
	out := m.list.View()
	if m.addMode {
		var b strings.Builder
		b.WriteString(TitleStyle.Render(" Add TOTP "))
		b.WriteString("\n\n")
		b.WriteString("Account: " + m.inputs[0].View() + "\n")
		b.WriteString("Secret:  " + m.inputs[1].View() + "\n\n")
		b.WriteString(GrayStyle.Render("enter: save | tab: next field | esc: cancel"))
		out += "\n\n" + BorderStyle.Render(b.String())
	}
	if m.err != "" {
		out += "\n" + ErrorStyle.Render("Error: "+m.err)
	}
	if m.status != "" {
		out += "\n" + SuccessStyle.Render(m.status)
	}
	out += "\n" + GrayStyle.Render("a: add | d: delete selected | c: copy current code | r: refresh")
	return out
}
