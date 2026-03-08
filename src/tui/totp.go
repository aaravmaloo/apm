package tui

import (
	"fmt"
	src "github.com/aaravmaloo/apm/src"
)

func RenderTOTPList(vault *src.Vault) string {
	var s string
	s += TitleStyle.Render(" TOTP Accounts ") + "\n\n"

	if len(vault.TOTPEntries) == 0 {
		s += "No TOTP accounts found.\n"
	} else {
		for _, e := range vault.TOTPEntries {
			code, err := src.GenerateTOTP(e.Secret)
			if err != nil {
				code = "INVALID"
			}
			s += fmt.Sprintf("%-20s | %s\n", e.Account, code)
		}
	}

	return BorderStyle.Render(s)
}
