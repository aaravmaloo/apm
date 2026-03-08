package tui

import (
	"fmt"
	src "github.com/aaravmaloo/apm/src"

	tea "github.com/charmbracelet/bubbletea"
	"github.com/charmbracelet/lipgloss"
)

type GeneratorModel struct {
	length   int
	password string
}

func NewGeneratorModel() GeneratorModel {
	p, _ := src.GeneratePassword(16)
	return GeneratorModel{length: 16, password: p}
}

func (m GeneratorModel) Init() tea.Cmd { return nil }

func (m GeneratorModel) Update(msg tea.Msg) (GeneratorModel, tea.Cmd) {
	switch msg := msg.(type) {
	case tea.KeyMsg:
		switch msg.String() {
		case "r", "enter":
			m.password, _ = src.GeneratePassword(m.length)
		case "left", "h":
			if m.length > 4 {
				m.length--
				m.password, _ = src.GeneratePassword(m.length)
			}
		case "right", "l":
			if m.length < 64 {
				m.length++
				m.password, _ = src.GeneratePassword(m.length)
			}
		}
	}
	return m, nil
}

func (m GeneratorModel) View() string {
	var s string
	s += TitleStyle.Render(" Password Generator ") + "\n\n"
	s += fmt.Sprintf("Length: %d (use left/right to adjust)\n\n", m.length)
	s += lipgloss.NewStyle().Foreground(lipgloss.Color("#00FF00")).Bold(true).Render(m.password) + "\n\n"
	s += GrayStyle.Render("r/enter: regenerate")
	return BorderStyle.Render(s)
}
