package tui

import (
	"fmt"
	src "password-manager/src"
	"strings"

	tea "github.com/charmbracelet/bubbletea"
)

type TrustModel struct {
	vault  *src.Vault
	scores []src.SecretTrustScore
}

func NewTrustModel(vault *src.Vault) TrustModel {
	m := TrustModel{vault: vault}
	m.refresh()
	return m
}

func (m TrustModel) Update(msg tea.Msg) (TrustModel, tea.Cmd) {
	if km, ok := msg.(tea.KeyMsg); ok {
		switch km.String() {
		case "r", "ctrl+r":
			m.refresh()
		}
	}
	return m, nil
}

func (m *TrustModel) refresh() {
	m.scores = m.vault.ComputeSecretTrustScores()
}

func (m TrustModel) View() string {
	var b strings.Builder
	b.WriteString(TitleStyle.Render(" Trust Scores "))
	b.WriteString("\n\n")
	if len(m.scores) == 0 {
		b.WriteString("No trust telemetry available yet.\n")
		b.WriteString("Use vault entries and revisit this page.\n")
	} else {
		b.WriteString("Lowest scores first:\n\n")
		for i, s := range m.scores {
			if i >= 20 {
				b.WriteString("... truncated, showing first 20\n")
				break
			}
			b.WriteString(fmt.Sprintf("[%3d] %-8s %-24s  %-8s  score=%d\n", s.Score, s.Category, s.Identifier, s.Risk, s.Score))
			if len(s.Reasons) > 0 {
				b.WriteString("      reasons: " + strings.Join(s.Reasons, "; ") + "\n")
			}
		}
	}
	b.WriteString("\n")
	b.WriteString(GrayStyle.Render("r: refresh trust scores"))
	return BorderStyle.Render(b.String())
}
