package tui

import (
	"fmt"
	src "github.com/aaravmaloo/apm/src"
	"strconv"
	"strings"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type AuthModel struct {
	vault          *src.Vault
	masterPassword string
	vaultPath      string
	inputs         []textinput.Model
	guardInput     textinput.Model
	confirmInput   textinput.Model
	gateUnlocked   bool
	focus          int
	status         string
	err            string
	lastCodes      []string
}

func NewAuthModel(vault *src.Vault, masterPassword, vaultPath string) AuthModel {
	recoveryEmail := textinput.New()
	recoveryEmail.Placeholder = "recovery email"
	recoveryEmail.Focus()
	recoveryEmail.Width = 38

	securityLevel := textinput.New()
	securityLevel.Placeholder = "security level (1-3)"
	securityLevel.SetValue(strconv.Itoa(vault.SecurityLevel))
	securityLevel.Width = 20

	codesCount := textinput.New()
	codesCount.Placeholder = "recovery code count"
	codesCount.SetValue("10")
	codesCount.Width = 20

	newPass := textinput.New()
	newPass.Placeholder = "new master password"
	newPass.EchoMode = textinput.EchoPassword
	newPass.Width = 36

	confirmPass := textinput.New()
	confirmPass.Placeholder = "confirm new password"
	confirmPass.EchoMode = textinput.EchoPassword
	confirmPass.Width = 36

	threshold := textinput.New()
	threshold.Placeholder = "quorum threshold"
	threshold.SetValue("2")
	threshold.Width = 20

	shares := textinput.New()
	shares.Placeholder = "quorum shares"
	shares.SetValue("3")
	shares.Width = 20

	qkey := textinput.New()
	qkey.Placeholder = "optional recovery key for quorum"
	qkey.Width = 36

	guard := textinput.New()
	guard.Placeholder = "current master password (required for sensitive actions)"
	guard.EchoMode = textinput.EchoPassword
	guard.Width = 48

	confirm := textinput.New()
	confirm.Placeholder = "type CONFIRM for destructive actions"
	confirm.Width = 36

	return AuthModel{
		vault:          vault,
		masterPassword: masterPassword,
		vaultPath:      vaultPath,
		inputs:         []textinput.Model{recoveryEmail, securityLevel, codesCount, newPass, confirmPass, threshold, shares, qkey},
		guardInput:     guard,
		confirmInput:   confirm,
	}
}

func (m AuthModel) Vault() *src.Vault { return m.vault }

func (m AuthModel) Update(msg tea.Msg) (AuthModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "tab":
			if m.focus < len(m.inputs) {
				m.inputs[m.focus].Blur()
			} else if m.focus == len(m.inputs) {
				m.guardInput.Blur()
			} else {
				m.confirmInput.Blur()
			}
			m.focus = (m.focus + 1) % (len(m.inputs) + 2)
			if m.focus < len(m.inputs) {
				m.inputs[m.focus].Focus()
			} else if m.focus == len(m.inputs) {
				m.guardInput.Focus()
			} else {
				m.confirmInput.Focus()
			}
			return m, nil
		case "shift+tab":
			if m.focus < len(m.inputs) {
				m.inputs[m.focus].Blur()
			} else if m.focus == len(m.inputs) {
				m.guardInput.Blur()
			} else {
				m.confirmInput.Blur()
			}
			m.focus = (m.focus - 1 + len(m.inputs) + 2) % (len(m.inputs) + 2)
			if m.focus < len(m.inputs) {
				m.inputs[m.focus].Focus()
			} else if m.focus == len(m.inputs) {
				m.guardInput.Focus()
			} else {
				m.confirmInput.Focus()
			}
			return m, nil
		case "ctrl+t":
			if m.gateUnlocked {
				m.gateUnlocked = false
				m.guardInput.SetValue("")
				m.status = "Sensitive actions locked"
				m.err = ""
				return m, nil
			}
			if strings.TrimSpace(m.guardInput.Value()) == "" {
				m.err = "enter current master password in security gate field, then press ctrl+t"
				m.status = ""
				return m, nil
			}
			if m.guardInput.Value() != m.masterPassword {
				m.err = "security gate unlock failed: current master password mismatch"
				m.status = ""
				return m, nil
			}
			m.gateUnlocked = true
			m.guardInput.SetValue("")
			m.err = ""
			m.status = "Sensitive actions unlocked"
			return m, nil
		case "ctrl+e":
			if err := m.requireGate("setup recovery"); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			if err := m.setupRecovery(); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.err = ""
			m.status = "Recovery configured"
			return m, nil
		case "ctrl+x":
			if err := m.requireGate("reset recovery"); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			if err := m.requireConfirm("reset recovery"); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.vault.ClearRecoveryInfo()
			if err := saveVault(m.vault, m.masterPassword, m.vaultPath); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.err = ""
			m.status = "Recovery metadata cleared"
			return m, nil
		case "ctrl+a":
			m.vault.AlertsEnabled = !m.vault.AlertsEnabled
			if err := saveVault(m.vault, m.masterPassword, m.vaultPath); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.err = ""
			m.status = fmt.Sprintf("Alerts set to %v", m.vault.AlertsEnabled)
			return m, nil
		case "ctrl+l":
			level, err := strconv.Atoi(strings.TrimSpace(m.inputs[1].Value()))
			if err != nil || level < 1 || level > 3 {
				m.err = "security level must be 1..3"
				m.status = ""
				return m, nil
			}
			m.vault.SecurityLevel = level
			if err := saveVault(m.vault, m.masterPassword, m.vaultPath); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.err = ""
			m.status = fmt.Sprintf("Security level set to %d", level)
			return m, nil
		case "ctrl+g":
			count, err := strconv.Atoi(strings.TrimSpace(m.inputs[2].Value()))
			if err != nil || count <= 0 {
				m.err = "invalid code count"
				m.status = ""
				return m, nil
			}
			codes, err := src.GenerateOneTimeRecoveryCodes(m.vault, count)
			if err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			if err := saveVault(m.vault, m.masterPassword, m.vaultPath); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.lastCodes = codes
			m.err = ""
			m.status = fmt.Sprintf("Generated %d recovery codes", len(codes))
			return m, nil
		case "ctrl+u":
			if err := m.requireGate("change master password"); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			if err := m.requireConfirm("change master password"); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			np := m.inputs[3].Value()
			cp := m.inputs[4].Value()
			if np == "" || cp == "" || np != cp {
				m.err = "new password and confirmation must match"
				m.status = ""
				return m, nil
			}
			data, err := src.UpdateMasterPassword(m.vault, m.masterPassword, np)
			if err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			if err := src.SaveVault(m.vaultPath, data); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.masterPassword = np
			m.gateUnlocked = false
			m.inputs[3].SetValue("")
			m.inputs[4].SetValue("")
			m.guardInput.SetValue("")
			m.confirmInput.SetValue("")
			m.err = ""
			m.status = "Master password updated"
			return m, nil
		case "ctrl+o":
			if err := m.requireGate("setup quorum recovery"); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			th, err1 := strconv.Atoi(strings.TrimSpace(m.inputs[5].Value()))
			sh, err2 := strconv.Atoi(strings.TrimSpace(m.inputs[6].Value()))
			if err1 != nil || err2 != nil {
				m.err = "invalid quorum numbers"
				m.status = ""
				return m, nil
			}
			_, err := src.SetupRecoveryQuorumWithKey(m.vault, strings.TrimSpace(m.inputs[7].Value()), th, sh)
			if err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			if err := saveVault(m.vault, m.masterPassword, m.vaultPath); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.err = ""
			m.status = fmt.Sprintf("Quorum configured: %d-of-%d", th, sh)
			return m, nil
		case "ctrl+p":
			uid, cred, err := src.RunRecoveryPasskeyRegistration()
			if err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.vault.RecoveryPasskeyEnabled = true
			m.vault.RecoveryPasskeyUserID = uid
			m.vault.RecoveryPasskeyCred = cred
			if err := saveVault(m.vault, m.masterPassword, m.vaultPath); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.err = ""
			m.status = "Recovery passkey registered"
			return m, nil
		case "ctrl+v":
			info := src.RecoveryData{RecoveryPasskeyEnabled: m.vault.RecoveryPasskeyEnabled, RecoveryPasskeyUserID: m.vault.RecoveryPasskeyUserID, RecoveryPasskeyCred: m.vault.RecoveryPasskeyCred}
			if err := src.VerifyRecoveryPasskeyFromHeader(info); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.err = ""
			m.status = "Recovery passkey verified"
			return m, nil
		case "ctrl+b":
			if err := m.requireGate("disable recovery passkey"); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			if err := m.requireConfirm("disable recovery passkey"); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.vault.RecoveryPasskeyEnabled = false
			m.vault.RecoveryPasskeyUserID = nil
			m.vault.RecoveryPasskeyCred = nil
			if err := saveVault(m.vault, m.masterPassword, m.vaultPath); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.err = ""
			m.status = "Recovery passkey disabled"
			return m, nil
		}
	}

	cmds := make([]tea.Cmd, 0, len(m.inputs)+1)
	for i := range m.inputs {
		var cmd tea.Cmd
		m.inputs[i], cmd = m.inputs[i].Update(msg)
		cmds = append(cmds, cmd)
	}
	var guardCmd tea.Cmd
	m.guardInput, guardCmd = m.guardInput.Update(msg)
	cmds = append(cmds, guardCmd)
	var confirmCmd tea.Cmd
	m.confirmInput, confirmCmd = m.confirmInput.Update(msg)
	cmds = append(cmds, confirmCmd)
	return m, tea.Batch(cmds...)
}

func (m *AuthModel) setupRecovery() error {
	email := strings.ToLower(strings.TrimSpace(m.inputs[0].Value()))
	if email == "" || !strings.Contains(email, "@") {
		return fmt.Errorf("valid recovery email is required")
	}
	m.vault.SetRecoveryEmail(email)
	if m.vault.CurrentProfileParams == nil {
		p := src.GetProfile(m.vault.Profile)
		m.vault.CurrentProfileParams = &p
	}
	salt, err := src.GenerateSalt(m.vault.CurrentProfileParams.SaltLen)
	if err != nil {
		return err
	}
	key := src.GenerateRecoveryKey()
	m.vault.SetRecoveryKey(key, salt)
	if err := saveVault(m.vault, m.masterPassword, m.vaultPath); err != nil {
		return err
	}
	m.status = "Recovery configured. Save this key offline: " + key
	return nil
}

func (m AuthModel) View() string {
	configured := m.vault.RecoveryEmail != "" || len(m.vault.RecoveryHash) > 0
	var b strings.Builder
	if !configured {
		b.WriteString(TitleStyle.Render(" Auth Setup "))
		b.WriteString("\n\nRecovery is not configured.\n")
		b.WriteString("Set recovery email and press 'e' to initialize recovery key.\n\n")
	} else {
		b.WriteString(TitleStyle.Render(" Auth Security "))
		b.WriteString("\n\n")
	}
	b.WriteString(fmt.Sprintf("Alerts: %v | Security Level: %d\n", m.vault.AlertsEnabled, m.vault.SecurityLevel))
	total := len(m.vault.RecoveryCodeHashes)
	if total > 0 {
		remaining := src.CountRemainingRecoveryCodes(m.vault)
		b.WriteString(fmt.Sprintf("Recovery Codes: %d total, %d remaining\n", total, remaining))
	}
	b.WriteString("\nRecovery Email: " + m.inputs[0].View() + "\n")
	b.WriteString("Security Level: " + m.inputs[1].View() + "\n")
	b.WriteString("Codes Count:    " + m.inputs[2].View() + "\n")
	b.WriteString("New Password:   " + m.inputs[3].View() + "\n")
	b.WriteString("Confirm Pass:   " + m.inputs[4].View() + "\n")
	b.WriteString("Quorum Thres:   " + m.inputs[5].View() + "\n")
	b.WriteString("Quorum Shares:  " + m.inputs[6].View() + "\n")
	b.WriteString("Quorum Key:     " + m.inputs[7].View() + "\n")
	b.WriteString("Danger Confirm: " + m.confirmInput.View() + "\n")
	if m.gateUnlocked {
		b.WriteString("Security Gate:  " + SuccessStyle.Render("UNLOCKED") + " (ctrl+t to lock)\n")
	} else {
		b.WriteString("Security Gate:  " + m.guardInput.View() + "\n")
	}

	if len(m.lastCodes) > 0 {
		b.WriteString("\nGenerated recovery codes (shown once):\n")
		for _, c := range m.lastCodes {
			b.WriteString("- " + c + "\n")
		}
	}

	b.WriteString("\n")
	b.WriteString("CLI Auth Coverage:\n")
	b.WriteString("- auth email -> ctrl+e (recovery setup)\n")
	b.WriteString("- auth alerts -> ctrl+a\n")
	b.WriteString("- auth level -> ctrl+l\n")
	b.WriteString("- auth change -> ctrl+u (guard + confirm)\n")
	b.WriteString("- auth reset -> ctrl+x (guard + confirm)\n")
	b.WriteString("- auth codes generate/status -> ctrl+g + status panel\n")
	b.WriteString("- auth passkey register/verify/disable -> ctrl+p / ctrl+v / ctrl+b\n")
	b.WriteString("- auth quorum-setup -> ctrl+o\n")
	b.WriteString("- auth recover/quorum-recover -> recovery flow (done outside unlocked vault TUI)\n")
	b.WriteString("\n")
	if m.err != "" {
		b.WriteString(ErrorStyle.Render("Error: "+m.err) + "\n")
	}
	if m.status != "" {
		b.WriteString(SuccessStyle.Render(m.status) + "\n")
	}
	b.WriteString("\n")
	b.WriteString(GrayStyle.Render("ctrl+t: unlock/lock sensitive actions | type CONFIRM in Danger Confirm for destructive actions | ctrl+e: setup recovery | ctrl+x: reset recovery | ctrl+a: toggle alerts | ctrl+l: set level | ctrl+g: gen codes | ctrl+u: change master password | ctrl+o: setup quorum | ctrl+p/v/b: passkey register/verify/disable"))
	return BorderStyle.Render(b.String())
}

func (m AuthModel) requireGate(action string) error {
	if m.gateUnlocked {
		return nil
	}
	return fmt.Errorf("%s blocked: unlock security gate first (enter current master password, then ctrl+t)", action)
}

func (m *AuthModel) requireConfirm(action string) error {
	if strings.EqualFold(strings.TrimSpace(m.confirmInput.Value()), "CONFIRM") {
		m.confirmInput.SetValue("")
		return nil
	}
	return fmt.Errorf("%s blocked: type CONFIRM in Danger Confirm field", action)
}
