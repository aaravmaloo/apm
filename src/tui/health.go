package tui

import (
	"fmt"
	"github.com/charmbracelet/lipgloss"
	src "password-manager/src"
)

func RenderHealth(vault *src.Vault) string {
	score, report := src.CalculateHealth(vault)

	var s string
	s += TitleStyle.Render(" Security Health Dashboard ") + "\n\n"

	scoreColor := SuccessColor
	if score < 50 {
		scoreColor = ErrorColor
	} else if score < 80 {
		scoreColor = AccentColor
	}

	s += fmt.Sprintf("Overall Score: %s/100\n\n", lipgloss.NewStyle().Foreground(scoreColor).Bold(true).Render(fmt.Sprintf("%d", score)))

	s += "Issues and Recommendations:\n"
	for _, r := range report {
		s += fmt.Sprintf("- %s\n", r)
	}

	return BorderStyle.Render(s)
}

func RenderAudit(vault *src.Vault) string {
	var s string
	s += TitleStyle.Render(" Audit Logs ") + "\n\n"

	if len(vault.History) == 0 {
		s += "No audit logs found.\n"
	} else {
		// Show last 15 logs
		start := len(vault.History) - 15
		if start < 0 {
			start = 0
		}

		for i := len(vault.History) - 1; i >= start; i-- {
			h := vault.History[i]
			s += fmt.Sprintf("%s | %-7s | %s\n",
				h.Timestamp.Format("15:04:05"),
				h.Action,
				h.Identifier)
		}
	}

	return BorderStyle.Render(s)
}
