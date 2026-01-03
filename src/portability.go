package apm

import (
	"encoding/csv"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"strings"
)

type ExportData struct {
	Entries     []Entry     `json:"entries"`
	TOTPEntries []TOTPEntry `json:"totp_entries"`
}

func ExportToJSON(vault *Vault, filename string) error {
	data := ExportData{
		Entries:     vault.Entries,
		TOTPEntries: vault.TOTPEntries,
	}
	bytes, err := json.MarshalIndent(data, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(filename, bytes, 0600)
}

func ExportToTXT(vault *Vault, filename string, withoutPassword bool) error {
	var sb strings.Builder
	sb.WriteString("APM Export\n")
	sb.WriteString("==========\n\n")

	sb.WriteString("PASSWORDS:\n")
	for _, e := range vault.Entries {
		if withoutPassword {
			sb.WriteString(fmt.Sprintf("Account: %s | Username: %s\n", e.Account, e.Username))
		} else {
			sb.WriteString(fmt.Sprintf("Account: %s | Username: %s | Password: %s\n", e.Account, e.Username, e.Password))
		}
	}

	sb.WriteString("\nTOTP:\n")
	for _, t := range vault.TOTPEntries {
		if withoutPassword {
			sb.WriteString(fmt.Sprintf("Account: %s\n", t.Account))
		} else {
			sb.WriteString(fmt.Sprintf("Account: %s | Secret: %s\n", t.Account, t.Secret))
		}
	}

	return os.WriteFile(filename, []byte(sb.String()), 0600)
}

func ImportFromJSON(vault *Vault, filename string) error {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	var data ExportData
	if err := json.Unmarshal(bytes, &data); err != nil {
		return err
	}
	for _, e := range data.Entries {
		vault.AddEntry(e.Account, e.Username, e.Password)
	}
	for _, t := range data.TOTPEntries {
		vault.AddTOTPEntry(t.Account, t.Secret)
	}
	return nil
}

func ImportFromCSV(vault *Vault, filename string) error {
	file, err := os.Open(filename)
	if err != nil {
		return err
	}
	defer file.Close()

	reader := csv.NewReader(file)
	reader.FieldsPerRecord = -1
	records, err := reader.ReadAll()
	if err != nil {
		return err
	}

	for _, record := range records {
		if len(record) < 3 {
			continue
		}
		// Expecting: Type, Account, Username/Secret, [Password]
		dataType := strings.ToUpper(strings.TrimSpace(record[0]))
		account := strings.TrimSpace(record[1])

		switch dataType {
		case "ENTRY", "PASSWORD":
			if len(record) >= 4 {
				vault.AddEntry(account, strings.TrimSpace(record[2]), strings.TrimSpace(record[3]))
			}
		case "TOTP":
			vault.AddTOTPEntry(account, strings.TrimSpace(record[2]))
		}
	}
	return nil
}

func ImportFromTXT(vault *Vault, filename string) error {
	bytes, err := os.ReadFile(filename)
	if err != nil {
		return err
	}
	lines := strings.Split(string(bytes), "\n")
	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "APM Export") || strings.HasPrefix(line, "=") || strings.HasSuffix(line, ":") {
			continue
		}

		if strings.HasPrefix(line, "otpauth://") {
			u, err := url.Parse(line)
			if err != nil {
				continue
			}
			label := strings.TrimPrefix(u.Path, "/")
			if strings.HasPrefix(label, "totp/") {
				label = strings.TrimPrefix(label, "totp/")
			} else if strings.HasPrefix(label, "hotp/") {
				label = strings.TrimPrefix(label, "hotp/")
			}

			label, _ = url.PathUnescape(label)

			secret := u.Query().Get("secret")
			if label != "" && secret != "" {
				vault.AddTOTPEntry(label, secret)
			}
			continue
		}

		if strings.Contains(line, "Password:") {
			// Account: ... | Username: ... | Password: ...
			parts := strings.Split(line, "|")
			var acc, user, pass string
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.HasPrefix(p, "Account:") {
					acc = strings.TrimPrefix(p, "Account:")
				} else if strings.HasPrefix(p, "Username:") {
					user = strings.TrimPrefix(p, "Username:")
				} else if strings.HasPrefix(p, "Password:") {
					pass = strings.TrimPrefix(p, "Password:")
				}
			}
			if acc != "" {
				vault.AddEntry(strings.TrimSpace(acc), strings.TrimSpace(user), strings.TrimSpace(pass))
			}
		} else if strings.Contains(line, "Secret:") {
			// Account: ... | Secret: ...
			parts := strings.Split(line, "|")
			var acc, secret string
			for _, p := range parts {
				p = strings.TrimSpace(p)
				if strings.HasPrefix(p, "Account:") {
					acc = strings.TrimPrefix(p, "Account:")
				} else if strings.HasPrefix(p, "Secret:") {
					secret = strings.TrimPrefix(p, "Secret:")
				}
			}
			if acc != "" {
				vault.AddTOTPEntry(strings.TrimSpace(acc), strings.TrimSpace(secret))
			}
		}
	}
	return nil
}
