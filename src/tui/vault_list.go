package tui

import (
	"fmt"
	src "password-manager/src"
	"strings"
	"time"

	"github.com/atotto/clipboard"
	"github.com/charmbracelet/bubbles/list"
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type entryItem struct {
	res         src.SearchResult
	displayName string
}

type clearClipboardMsg struct {
	secret string
}

func (i entryItem) Title() string       { return i.displayName }
func (i entryItem) Description() string { return i.res.Type }
func (i entryItem) FilterValue() string { return i.res.Identifier }

type VaultListModel struct {
	list           list.Model
	vault          *src.Vault
	masterPassword string
	vaultPath      string
	status         string
	err            string
	selected       map[string]bool
	showDetails    bool
	detailsText    string
	lastCopied     string

	editMode       bool
	editInputs     []textinput.Model
	editFocus      int
	editType       string
	editIdentifier string

	addMode   bool
	addInputs []textinput.Model
	addFocus  int

	width, height int
}

func NewVaultListModel(vault *src.Vault, masterPassword, vaultPath string) VaultListModel {
	results := vault.SearchAll("")
	items := make([]list.Item, len(results))
	for i, res := range results {
		items[i] = entryItem{res: res}
	}

	l := list.New(items, list.NewDefaultDelegate(), 0, 0)
	l.Title = "Vault Entries"
	l.SetShowStatusBar(true)
	l.SetShowHelp(false)
	l.SetShowPagination(false)
	l.SetFilteringEnabled(true)
	l.Styles.Title = TitleStyle

	m := VaultListModel{
		list:           l,
		vault:          vault,
		masterPassword: masterPassword,
		vaultPath:      vaultPath,
		selected:       map[string]bool{},
	}
	m.Refresh()
	return m
}

func (m VaultListModel) Init() tea.Cmd { return nil }

func (m VaultListModel) Update(msg tea.Msg) (VaultListModel, tea.Cmd) {
	if clipMsg, ok := msg.(clearClipboardMsg); ok {
		current, err := clipboard.ReadAll()
		if err == nil && current == clipMsg.secret {
			_ = clipboard.WriteAll("")
			m.status = "Clipboard auto-cleared"
		}
		return m, nil
	}

	if m.addMode {
		return m.updateAdd(msg)
	}
	if m.editMode {
		return m.updateEdit(msg)
	}

	if m.list.FilterState() == list.Filtering {
		var cmd tea.Cmd
		m.list, cmd = m.list.Update(msg)
		return m, cmd
	}

	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "a":
			m.startAdd()
			m.err = ""
			m.status = "Add mode"
			return m, nil
		case " ":
			m.toggleSelection()
			m.Refresh()
			return m, nil
		case "D":
			count, err := m.deleteSelectedBatch()
			if err != nil {
				m.err = err.Error()
				m.status = ""
			} else {
				m.err = ""
				m.status = fmt.Sprintf("Deleted %d selected entries", count)
			}
			m.Refresh()
			return m, nil
		case "v", "enter":
			m.toggleDetails()
			return m, nil
		case "c":
			if err := m.copySelectedSecret(); err != nil {
				m.err = err.Error()
				m.status = ""
			} else {
				m.err = ""
				m.status = "Copied to clipboard (auto-clear in 20s)"
				return m, tea.Tick(20*time.Second, func(time.Time) tea.Msg {
					return clearClipboardMsg{secret: m.lastCopiedSecret()}
				})
			}
			return m, nil
		case "e":
			if err := m.startEdit(); err != nil {
				m.err = err.Error()
				m.status = ""
			} else {
				m.err = ""
				m.status = "Edit mode"
			}
			return m, nil
		case "d":
			if err := m.deleteSelected(); err != nil {
				m.err = err.Error()
				m.status = ""
			} else {
				m.status = "Entry deleted"
				m.err = ""
				m.Refresh()
			}
			return m, nil
		case "r", "ctrl+r":
			m.Refresh()
			m.status = "List refreshed"
			m.err = ""
			return m, nil
		}
	}

	var cmd tea.Cmd
	m.list, cmd = m.list.Update(msg)
	return m, cmd
}

func (m VaultListModel) View() string {
	out := m.list.View()
	if m.showDetails && m.detailsText != "" {
		out += "\n\n" + BorderStyle.Render(m.detailsText)
	}
	if m.editMode {
		var b strings.Builder
		b.WriteString(TitleStyle.Render(" Edit Entry "))
		b.WriteString("\n\n")
		for i := range m.editInputs {
			b.WriteString(m.editInputs[i].View() + "\n")
		}
		b.WriteString("\n")
		b.WriteString(GrayStyle.Render("enter: save edit | tab: next field | esc: cancel"))
		out += "\n\n" + BorderStyle.Render(b.String())
	}
	if m.addMode {
		var b strings.Builder
		b.WriteString(TitleStyle.Render(" Add Entry "))
		b.WriteString("\n\n")
		b.WriteString("Type values: password | totp | token | note | apikey | ssh | wifi | recovery\n\n")
		b.WriteString("Type:   " + m.addInputs[0].View() + "\n")
		b.WriteString("Field1: " + m.addInputs[1].View() + "\n")
		b.WriteString("Field2: " + m.addInputs[2].View() + "\n")
		b.WriteString("Field3: " + m.addInputs[3].View() + "\n")
		b.WriteString("\n")
		b.WriteString(GrayStyle.Render("enter: save new entry | tab: next field | esc: cancel"))
		out += "\n\n" + BorderStyle.Render(b.String())
	}
	if m.err != "" {
		out += "\n" + ErrorStyle.Render("Error: "+m.err)
	}
	if m.status != "" {
		out += "\n" + SuccessStyle.Render(m.status)
	}
	out += "\n" + GrayStyle.Render("a:add | space: multi-select | v/enter:view | c:copy | e:edit | d:delete current | D:delete selected | r:refresh")
	return out
}

func (m *VaultListModel) SetSize(width, height int) {
	m.width = width
	m.height = height
	m.list.SetSize(width, height)
}

func (m *VaultListModel) Refresh() {
	results := m.vault.SearchAll("")
	items := make([]list.Item, len(results))
	for i, res := range results {
		label := res.Identifier
		if m.selected[m.entryKey(res)] {
			label = "[x] " + label
		} else {
			label = "[ ] " + label
		}
		items[i] = entryItem{res: res, displayName: label}
	}
	m.list.SetItems(items)
}

func (m *VaultListModel) startAdd() {
	m.addMode = true
	m.addFocus = 0
	m.addInputs = nil
	mk := func(ph string, focus bool) textinput.Model {
		ti := textinput.New()
		ti.Placeholder = ph
		ti.Width = 56
		if focus {
			ti.Focus()
		}
		return ti
	}
	m.addInputs = []textinput.Model{
		mk("type", true),
		mk("field1", false),
		mk("field2", false),
		mk("field3", false),
	}
}

func (m VaultListModel) updateAdd(msg tea.Msg) (VaultListModel, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "esc":
			m.addMode = false
			m.addInputs = nil
			return m, nil
		case "tab":
			m.addInputs[m.addFocus].Blur()
			m.addFocus = (m.addFocus + 1) % len(m.addInputs)
			m.addInputs[m.addFocus].Focus()
			return m, nil
		case "shift+tab":
			m.addInputs[m.addFocus].Blur()
			m.addFocus = (m.addFocus - 1 + len(m.addInputs)) % len(m.addInputs)
			m.addInputs[m.addFocus].Focus()
			return m, nil
		case "enter":
			if err := m.applyAdd(); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.addMode = false
			m.addInputs = nil
			m.err = ""
			m.status = "Entry added"
			m.Refresh()
			return m, nil
		}
	}
	cmds := make([]tea.Cmd, len(m.addInputs))
	for i := range m.addInputs {
		m.addInputs[i], cmds[i] = m.addInputs[i].Update(msg)
	}
	return m, tea.Batch(cmds...)
}

func (m *VaultListModel) applyAdd() error {
	t := strings.ToLower(strings.TrimSpace(m.addInputs[0].Value()))
	f1 := strings.TrimSpace(m.addInputs[1].Value())
	f2 := m.addInputs[2].Value()
	f3 := strings.TrimSpace(m.addInputs[3].Value())

	if t == "" {
		return fmt.Errorf("type is required")
	}
	var err error
	switch t {
	case "password":
		err = m.vault.AddEntry(f1, strings.TrimSpace(f2), f3)
	case "totp":
		err = m.vault.AddTOTPEntry(f1, strings.ToUpper(strings.ReplaceAll(strings.TrimSpace(f2), " ", "")))
	case "token":
		err = m.vault.AddToken(f1, f2, f3)
	case "note":
		err = m.vault.AddSecureNote(f1, f2)
	case "apikey":
		err = m.vault.AddAPIKey(f1, strings.TrimSpace(f2), f3)
	case "ssh":
		err = m.vault.AddSSHKey(f1, f2)
	case "wifi":
		err = m.vault.AddWiFi(f1, f2, f3)
	case "recovery":
		parts := strings.Split(f2, ",")
		codes := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				codes = append(codes, p)
			}
		}
		err = m.vault.AddRecoveryCode(f1, codes)
	default:
		return fmt.Errorf("unsupported add type '%s'", t)
	}
	if err != nil {
		return err
	}
	return saveVault(m.vault, m.masterPassword, m.vaultPath)
}

func (m *VaultListModel) deleteSelected() error {
	selected := m.list.SelectedItem()
	if selected == nil {
		return fmt.Errorf("no entry selected")
	}
	item, ok := selected.(entryItem)
	if !ok {
		return fmt.Errorf("unsupported selection")
	}

	id := item.res.Identifier
	removed := false
	switch item.res.Type {
	case "Password":
		removed = m.vault.DeleteEntry(id)
	case "TOTP":
		removed = m.vault.DeleteTOTPEntry(id)
	case "Token":
		removed = m.vault.DeleteToken(id)
	case "Note":
		removed = m.vault.DeleteSecureNote(id)
	case "API Key":
		removed = m.vault.DeleteAPIKey(id)
	case "SSH Key":
		removed = m.vault.DeleteSSHKey(id)
	case "Wi-Fi":
		removed = m.vault.DeleteWiFi(id)
	case "Recovery Codes":
		removed = m.vault.DeleteRecoveryCode(id)
	case "Certificate":
		removed = m.vault.DeleteCertificate(id)
	case "Banking":
		removed = m.vault.DeleteBankingItem(id)
	case "Document":
		removed = m.vault.DeleteDocument(id)
	case "Audio":
		removed = m.vault.DeleteAudio(id)
	case "Video":
		removed = m.vault.DeleteVideo(id)
	case "Photo":
		removed = m.vault.DeletePhoto(id)
	case "Government ID":
		removed = m.vault.DeleteGovID(id)
	case "Medical Record":
		removed = m.vault.DeleteMedicalRecord(id)
	case "Travel":
		removed = m.vault.DeleteTravelDoc(id)
	case "Contact":
		removed = m.vault.DeleteContact(id)
	case "Cloud Credentials":
		removed = m.vault.DeleteCloudCredential(id)
	case "Kubernetes Secret":
		removed = m.vault.DeleteK8sSecret(id)
	case "Docker Registry":
		removed = m.vault.DeleteDockerRegistry(id)
	case "SSH Config":
		removed = m.vault.DeleteSSHConfig(id)
	case "CI/CD Secret":
		removed = m.vault.DeleteCICDSecret(id)
	case "Software License":
		removed = m.vault.DeleteSoftwareLicense(id)
	case "Legal Contract":
		removed = m.vault.DeleteLegalContract(id)
	default:
		return fmt.Errorf("delete not supported for type '%s' in TUI yet", item.res.Type)
	}

	if !removed {
		return fmt.Errorf("entry not found")
	}
	return saveVault(m.vault, m.masterPassword, m.vaultPath)
}

func (m *VaultListModel) toggleSelection() {
	res, err := m.currentResult()
	if err != nil {
		return
	}
	k := m.entryKey(res)
	m.selected[k] = !m.selected[k]
	if !m.selected[k] {
		delete(m.selected, k)
	}
}

func (m *VaultListModel) deleteSelectedBatch() (int, error) {
	if len(m.selected) == 0 {
		return 0, fmt.Errorf("no selected entries")
	}
	results := m.vault.SearchAll("")
	count := 0
	for _, res := range results {
		if !m.selected[m.entryKey(res)] {
			continue
		}
		_ = m.deleteByTypeAndID(res.Type, res.Identifier)
		count++
	}
	m.selected = map[string]bool{}
	if count == 0 {
		return 0, fmt.Errorf("no matching selected entries in current space")
	}
	if err := saveVault(m.vault, m.masterPassword, m.vaultPath); err != nil {
		return 0, err
	}
	return count, nil
}

func (m *VaultListModel) toggleDetails() {
	res, err := m.currentResult()
	if err != nil {
		return
	}
	m.showDetails = !m.showDetails
	if m.showDetails {
		m.detailsText = RenderDetails(res)
	}
}

func (m *VaultListModel) copySelectedSecret() error {
	res, err := m.currentResult()
	if err != nil {
		return err
	}
	var secret string
	switch res.Type {
	case "Password":
		e := res.Data.(src.Entry)
		secret = e.Password
	case "TOTP":
		e := res.Data.(src.TOTPEntry)
		code, err := src.GenerateTOTP(e.Secret)
		if err != nil {
			return err
		}
		secret = code
	case "Token":
		e := res.Data.(src.TokenEntry)
		secret = e.Token
	case "API Key":
		e := res.Data.(src.APIKeyEntry)
		secret = e.Key
	case "SSH Key":
		e := res.Data.(src.SSHKeyEntry)
		secret = e.PrivateKey
	case "Wi-Fi":
		e := res.Data.(src.WiFiEntry)
		secret = e.Password
	case "Recovery Codes":
		e := res.Data.(src.RecoveryCodeEntry)
		secret = strings.Join(e.Codes, "\n")
	default:
		return fmt.Errorf("copy is not supported for type '%s' yet", res.Type)
	}
	if strings.TrimSpace(secret) == "" {
		return fmt.Errorf("selected secret is empty")
	}
	m.status = ""
	m.err = ""
	m.setLastCopiedSecret(secret)
	return clipboard.WriteAll(secret)
}

func (m *VaultListModel) setLastCopiedSecret(secret string) {
	m.lastCopied = secret
}

func (m *VaultListModel) lastCopiedSecret() string {
	return m.lastCopied
}

func (m *VaultListModel) startEdit() error {
	res, err := m.currentResult()
	if err != nil {
		return err
	}
	m.editInputs = nil
	m.editFocus = 0
	m.editType = res.Type
	m.editIdentifier = res.Identifier

	add := func(placeholder, value string, focus bool) {
		ti := textinput.New()
		ti.Placeholder = placeholder
		ti.SetValue(value)
		if focus {
			ti.Focus()
		}
		ti.Width = 56
		m.editInputs = append(m.editInputs, ti)
	}

	switch res.Type {
	case "Password":
		e := res.Data.(src.Entry)
		add("Account", e.Account, true)
		add("Username", e.Username, false)
		add("Password", e.Password, false)
	case "TOTP":
		e := res.Data.(src.TOTPEntry)
		add("Account", e.Account, true)
		add("Secret", e.Secret, false)
	case "Token":
		e := res.Data.(src.TokenEntry)
		add("Name", e.Name, true)
		add("Token", e.Token, false)
		add("Type", e.Type, false)
	case "Note":
		e := res.Data.(src.SecureNoteEntry)
		add("Name", e.Name, true)
		add("Content", e.Content, false)
	case "API Key":
		e := res.Data.(src.APIKeyEntry)
		add("Name", e.Name, true)
		add("Service", e.Service, false)
		add("Key", e.Key, false)
	case "SSH Key":
		e := res.Data.(src.SSHKeyEntry)
		add("Name", e.Name, true)
		add("Private Key", e.PrivateKey, false)
	case "Wi-Fi":
		e := res.Data.(src.WiFiEntry)
		add("SSID", e.SSID, true)
		add("Password", e.Password, false)
		add("Security Type", e.SecurityType, false)
	case "Recovery Codes":
		e := res.Data.(src.RecoveryCodeEntry)
		add("Service", e.Service, true)
		add("Codes (comma separated)", strings.Join(e.Codes, ","), false)
	default:
		return fmt.Errorf("edit is not supported for type '%s' yet", res.Type)
	}
	m.editMode = true
	return nil
}

func (m VaultListModel) updateEdit(msg tea.Msg) (VaultListModel, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "esc":
			m.editMode = false
			m.editInputs = nil
			return m, nil
		case "tab":
			m.editInputs[m.editFocus].Blur()
			m.editFocus = (m.editFocus + 1) % len(m.editInputs)
			m.editInputs[m.editFocus].Focus()
			return m, nil
		case "shift+tab":
			m.editInputs[m.editFocus].Blur()
			m.editFocus = (m.editFocus - 1 + len(m.editInputs)) % len(m.editInputs)
			m.editInputs[m.editFocus].Focus()
			return m, nil
		case "enter":
			if err := m.applyEdit(); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.editMode = false
			m.editInputs = nil
			m.err = ""
			m.status = "Entry updated"
			m.Refresh()
			return m, nil
		}
	}
	cmds := make([]tea.Cmd, len(m.editInputs))
	for i := range m.editInputs {
		m.editInputs[i], cmds[i] = m.editInputs[i].Update(msg)
	}
	return m, tea.Batch(cmds...)
}

func (m *VaultListModel) applyEdit() error {
	if err := m.deleteByTypeAndID(m.editType, m.editIdentifier); err != nil {
		return err
	}
	switch m.editType {
	case "Password":
		return m.vault.AddEntry(strings.TrimSpace(m.editInputs[0].Value()), strings.TrimSpace(m.editInputs[1].Value()), m.editInputs[2].Value())
	case "TOTP":
		return m.vault.AddTOTPEntry(strings.TrimSpace(m.editInputs[0].Value()), strings.TrimSpace(m.editInputs[1].Value()))
	case "Token":
		return m.vault.AddToken(strings.TrimSpace(m.editInputs[0].Value()), m.editInputs[1].Value(), strings.TrimSpace(m.editInputs[2].Value()))
	case "Note":
		return m.vault.AddSecureNote(strings.TrimSpace(m.editInputs[0].Value()), m.editInputs[1].Value())
	case "API Key":
		return m.vault.AddAPIKey(strings.TrimSpace(m.editInputs[0].Value()), strings.TrimSpace(m.editInputs[1].Value()), m.editInputs[2].Value())
	case "SSH Key":
		return m.vault.AddSSHKey(strings.TrimSpace(m.editInputs[0].Value()), m.editInputs[1].Value())
	case "Wi-Fi":
		return m.vault.AddWiFi(strings.TrimSpace(m.editInputs[0].Value()), m.editInputs[1].Value(), strings.TrimSpace(m.editInputs[2].Value()))
	case "Recovery Codes":
		raw := strings.TrimSpace(m.editInputs[1].Value())
		parts := strings.Split(raw, ",")
		codes := make([]string, 0, len(parts))
		for _, p := range parts {
			p = strings.TrimSpace(p)
			if p != "" {
				codes = append(codes, p)
			}
		}
		return m.vault.AddRecoveryCode(strings.TrimSpace(m.editInputs[0].Value()), codes)
	default:
		return fmt.Errorf("edit apply not supported for '%s'", m.editType)
	}
}

func (m *VaultListModel) deleteByTypeAndID(t, id string) error {
	ok := false
	switch t {
	case "Password":
		ok = m.vault.DeleteEntry(id)
	case "TOTP":
		ok = m.vault.DeleteTOTPEntry(id)
	case "Token":
		ok = m.vault.DeleteToken(id)
	case "Note":
		ok = m.vault.DeleteSecureNote(id)
	case "API Key":
		ok = m.vault.DeleteAPIKey(id)
	case "SSH Key":
		ok = m.vault.DeleteSSHKey(id)
	case "Wi-Fi":
		ok = m.vault.DeleteWiFi(id)
	case "Recovery Codes":
		ok = m.vault.DeleteRecoveryCode(id)
	case "Certificate":
		ok = m.vault.DeleteCertificate(id)
	case "Banking":
		ok = m.vault.DeleteBankingItem(id)
	case "Document":
		ok = m.vault.DeleteDocument(id)
	case "Audio":
		ok = m.vault.DeleteAudio(id)
	case "Video":
		ok = m.vault.DeleteVideo(id)
	case "Photo":
		ok = m.vault.DeletePhoto(id)
	case "Government ID":
		ok = m.vault.DeleteGovID(id)
	case "Medical Record":
		ok = m.vault.DeleteMedicalRecord(id)
	case "Travel":
		ok = m.vault.DeleteTravelDoc(id)
	case "Contact":
		ok = m.vault.DeleteContact(id)
	case "Cloud Credentials":
		ok = m.vault.DeleteCloudCredential(id)
	case "Kubernetes Secret":
		ok = m.vault.DeleteK8sSecret(id)
	case "Docker Registry":
		ok = m.vault.DeleteDockerRegistry(id)
	case "SSH Config":
		ok = m.vault.DeleteSSHConfig(id)
	case "CI/CD Secret":
		ok = m.vault.DeleteCICDSecret(id)
	case "Software License":
		ok = m.vault.DeleteSoftwareLicense(id)
	case "Legal Contract":
		ok = m.vault.DeleteLegalContract(id)
	}
	if !ok {
		return fmt.Errorf("entry not found")
	}
	return saveVault(m.vault, m.masterPassword, m.vaultPath)
}

func (m *VaultListModel) currentResult() (src.SearchResult, error) {
	selected := m.list.SelectedItem()
	if selected == nil {
		return src.SearchResult{}, fmt.Errorf("no entry selected")
	}
	item, ok := selected.(entryItem)
	if !ok {
		return src.SearchResult{}, fmt.Errorf("unsupported selection")
	}
	return item.res, nil
}

func (m *VaultListModel) entryKey(res src.SearchResult) string {
	return strings.ToLower(strings.TrimSpace(res.Type + "|" + res.Identifier + "|" + res.Space))
}
