package tui

import (
	"fmt"
	src "github.com/aaravmaloo/apm/src"

	"github.com/charmbracelet/bubbles/textinput"
	tea "github.com/charmbracelet/bubbletea"
)

type UnlockModel struct {
	textInput textinput.Model
	err       error
	vaultPath string
	result    *src.UnlockResult
}

func NewUnlockModel(vaultPath string) UnlockModel {
	ti := textinput.New()
	ti.Placeholder = "Master Password"
	ti.EchoMode = textinput.EchoPassword
	ti.EchoCharacter = '*'
	ti.Focus()
	ti.CharLimit = 128
	ti.Width = 30

	return UnlockModel{textInput: ti, vaultPath: vaultPath}
}

func (m UnlockModel) Init() tea.Cmd { return textinput.Blink }

func (m UnlockModel) Update(msg tea.Msg) (tea.Model, tea.Cmd) {
	var cmd tea.Cmd
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.Type {
		case tea.KeyEnter:
			res, err := src.UnlockWithPassword(m.vaultPath, m.textInput.Value())
			if err != nil {
				m.err = err
				m.textInput.SetValue("")
				return m, nil
			}
			m.result = res
			return m, tea.Quit
		case tea.KeyCtrlC, tea.KeyEsc:
			return m, tea.Quit
		}
	case error:
		m.err = msg
		return m, nil
	}
	m.textInput, cmd = m.textInput.Update(msg)
	return m, cmd
}

func (m UnlockModel) View() string {
	var s string
	s += TitleStyle.Render(" APM UNLOCK ") + "\n\n"
	s += "Please enter your master password to unlock the vault.\n\n"
	s += m.textInput.View() + "\n\n"
	if m.err != nil {
		s += ErrorStyle.Render(fmt.Sprintf("Error: %v", m.err)) + "\n"
	}
	s += GrayStyle.Render("Press Esc to quit.")
	return BorderStyle.Render(s)
}

func RunUnlock(vaultPath string) (*src.UnlockResult, error) {
	res, err := src.AttemptUnlockWithSession(vaultPath)
	if err == nil {
		return res, nil
	}

	p := tea.NewProgram(NewUnlockModel(vaultPath))
	model, err := p.Run()
	if err != nil {
		return nil, err
	}
	unlockModel := model.(UnlockModel)
	if unlockModel.result == nil {
		return nil, fmt.Errorf("unlock cancelled")
	}
	return unlockModel.result, nil
}
