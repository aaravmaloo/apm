package tui

import (
	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type FormModel struct {
	inputs  []textinput.Model
	focus   int
	title   string
	onLabel string
}

func NewPasswordForm() FormModel {
	acc := textinput.New()
	acc.Placeholder = "Account Name"
	acc.Focus()

	user := textinput.New()
	user.Placeholder = "Username"

	pass := textinput.New()
	pass.Placeholder = "Password (leave blank to generate)"
	pass.EchoMode = textinput.EchoPassword

	return FormModel{inputs: []textinput.Model{acc, user, pass}, title: "Add Password", onLabel: "Save"}
}

func (m FormModel) Init() tea.Cmd { return textinput.Blink }

func (m FormModel) Update(msg tea.Msg) (FormModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyTab, tea.KeyDown:
			m.inputs[m.focus].Blur()
			m.focus = (m.focus + 1) % len(m.inputs)
			m.inputs[m.focus].Focus()
		case tea.KeyUp:
			m.inputs[m.focus].Blur()
			m.focus = (m.focus - 1 + len(m.inputs)) % len(m.inputs)
			m.inputs[m.focus].Focus()
		}
	}

	cmds := make([]tea.Cmd, len(m.inputs))
	for i := range m.inputs {
		m.inputs[i], cmds[i] = m.inputs[i].Update(msg)
	}
	return m, tea.Batch(cmds...)
}

func (m FormModel) View() string {
	var s string
	s += TitleStyle.Render(" "+m.title+" ") + "\n\n"
	for i := range m.inputs {
		s += m.inputs[i].View() + "\n"
	}
	s += "\n" + GrayStyle.Render("enter: "+m.onLabel+" | esc: cancel")
	return BorderStyle.Render(s)
}
