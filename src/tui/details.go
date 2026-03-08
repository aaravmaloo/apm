package tui

import (
	"fmt"
	src "github.com/aaravmaloo/apm/src"
	"strings"
)

func RenderDetails(res src.SearchResult) string {
	var b strings.Builder

	b.WriteString(TitleStyle.Render(fmt.Sprintf(" %s Details ", res.Type)) + "\n\n")
	b.WriteString(fmt.Sprintf("Identifier: %s\n", res.Identifier))
	b.WriteString(fmt.Sprintf("Space:      %s\n", res.Space))
	b.WriteString("--------------------------------\n\n")

	switch res.Type {
	case "Password":
		e := res.Data.(src.Entry)
		b.WriteString(fmt.Sprintf("Account:  %s\n", e.Account))
		b.WriteString(fmt.Sprintf("Username: %s\n", e.Username))
		b.WriteString(fmt.Sprintf("Password: %s\n", strings.Repeat("*", 12)))
	case "TOTP":
		e := res.Data.(src.TOTPEntry)
		b.WriteString(fmt.Sprintf("Account: %s\n", e.Account))
		// We could generate code here if we want real-time updates
	case "Token":
		e := res.Data.(src.TokenEntry)
		b.WriteString(fmt.Sprintf("Name: %s\n", e.Name))
		b.WriteString(fmt.Sprintf("Type: %s\n", e.Type))
	case "Note":
		e := res.Data.(src.SecureNoteEntry)
		b.WriteString(fmt.Sprintf("Name:    %s\n", e.Name))
		b.WriteString(fmt.Sprintf("Content:\n%s\n", e.Content))
	default:
		b.WriteString(fmt.Sprintf("Details for %s are partially shown in TUI. Use CLI for full view.\n", res.Type))
	}

	b.WriteString("\n" + GrayStyle.Render("Press v to view, c to copy, e to edit, d to delete, esc to go back."))

	return b.String()
}
