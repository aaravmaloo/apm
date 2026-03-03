package tui

import (
	"fmt"
	"os"
	src "password-manager/src"
	"strconv"
	"strings"
	"time"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type SessionModel struct {
	masterPassword string
	inputs         []textinput.Model
	focus          int
	ephemeral      []src.EphemeralSession
	status         string
	err            string
}

func NewSessionModel(masterPassword string) SessionModel {
	label := textinput.New()
	label.Placeholder = "label"
	label.Focus()

	scope := textinput.New()
	scope.Placeholder = "scope: read|write"
	scope.SetValue("read")

	agent := textinput.New()
	agent.Placeholder = "agent name"
	agent.SetValue("tui")

	ttl := textinput.New()
	ttl.Placeholder = "ttl minutes"
	ttl.SetValue("60")

	revoke := textinput.New()
	revoke.Placeholder = "revoke session id"

	m := SessionModel{masterPassword: masterPassword, inputs: []textinput.Model{label, scope, agent, ttl, revoke}}
	m.refresh()
	return m
}

func (m SessionModel) Update(msg tea.Msg) (SessionModel, tea.Cmd) {
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
			m.status = "Session state refreshed"
			m.err = ""
			return m, nil
		case "ctrl+y":
			s, err := m.issueEphemeral()
			if err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.inputs[4].SetValue(s.ID)
			m.refresh()
			m.status = "Ephemeral session issued: " + s.ID
			m.err = ""
			return m, nil
		case "ctrl+v":
			id := strings.TrimSpace(m.inputs[4].Value())
			if id == "" {
				m.err = "revoke id is empty"
				m.status = ""
				return m, nil
			}
			ok, err := src.RevokeEphemeralSession(id)
			if err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			if !ok {
				m.err = "session not found"
				m.status = ""
				return m, nil
			}
			m.refresh()
			m.status = "Ephemeral session revoked"
			m.err = ""
			return m, nil
		case "ctrl+k":
			if err := src.KillSession(); err != nil {
				m.err = err.Error()
				m.status = ""
				return m, nil
			}
			m.refresh()
			m.status = "Primary session locked"
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

func (m SessionModel) issueEphemeral() (src.EphemeralSession, error) {
	ttlMin, err := strconv.Atoi(strings.TrimSpace(m.inputs[3].Value()))
	if err != nil || ttlMin <= 0 {
		return src.EphemeralSession{}, fmt.Errorf("ttl minutes must be a positive integer")
	}
	scope := strings.ToLower(strings.TrimSpace(m.inputs[1].Value()))
	if scope == "" {
		scope = "read"
	}
	return src.IssueEphemeralSession(
		m.masterPassword,
		strings.TrimSpace(m.inputs[0].Value()),
		scope,
		strings.TrimSpace(m.inputs[2].Value()),
		time.Duration(ttlMin)*time.Minute,
		true,
		os.Getpid(),
	)
}

func (m *SessionModel) refresh() {
	list, err := src.ListEphemeralSessions()
	if err != nil {
		m.err = err.Error()
		return
	}
	m.ephemeral = list
}

func (m SessionModel) View() string {
	var b strings.Builder
	b.WriteString(TitleStyle.Render(" Session Manager "))
	b.WriteString("\n\n")
	if sess, err := src.GetSession(); err == nil {
		b.WriteString(fmt.Sprintf("Active session: readonly=%v expires=%s\n", sess.ReadOnly, sess.Expiry.Format(time.RFC3339)))
	} else {
		b.WriteString("Active session: none\n")
	}
	b.WriteString("\nIssue Ephemeral Session:\n")
	b.WriteString("Label:      " + m.inputs[0].View() + "\n")
	b.WriteString("Scope:      " + m.inputs[1].View() + "\n")
	b.WriteString("Agent:      " + m.inputs[2].View() + "\n")
	b.WriteString("TTL mins:   " + m.inputs[3].View() + "\n")
	b.WriteString("Revoke ID:  " + m.inputs[4].View() + "\n")

	b.WriteString("\nEphemeral Sessions:\n")
	if len(m.ephemeral) == 0 {
		b.WriteString("- none\n")
	} else {
		for _, s := range m.ephemeral {
			b.WriteString(fmt.Sprintf("- %s | scope=%s | revoked=%v | expires=%s\n", s.ID, s.Scope, s.Revoked, s.ExpiresAt.Format(time.RFC3339)))
		}
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
	b.WriteString(GrayStyle.Render("ctrl+y: issue ephemeral | ctrl+v: revoke by id | ctrl+k: lock primary session | ctrl+r: refresh | tab: field"))
	return BorderStyle.Render(b.String())
}
