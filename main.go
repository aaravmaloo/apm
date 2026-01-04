package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"

	src "password-manager/src"
)

var vaultPath string

func init() {
	exe, err := os.Executable()
	if err != nil {
		fmt.Printf("Error getting executable path: %v\n", err)
		os.Exit(1)
	}
	vaultPath = filepath.Join(filepath.Dir(exe), "vault.dat")
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "pm",
		Short: "A simple password manager CLI",
	}

	var initCmd = &cobra.Command{
		Use:   "init",
		Short: "Initialize a new vault",
		Run: func(cmd *cobra.Command, args []string) {
			if src.VaultExists(vaultPath) {
				fmt.Println("Vault already exists.")
				return
			}

			var masterPassword string
			for {
				fmt.Print("Create Master Password: ")
				var err error
				masterPassword, err = readPassword()
				if err != nil {
					fmt.Printf("\nError reading password: %v\n", err)
					return
				}
				fmt.Println()

				if err := src.ValidateMasterPassword(masterPassword); err != nil {
					fmt.Printf("Invalid password: %v\n", err)
					continue
				}
				break
			}

			salt, err := src.GenerateSalt()
			if err != nil {
				fmt.Printf("Error generating salt: %v\n", err)
				return
			}

			vault := &src.Vault{Salt: salt}
			data, err := vault.Serialize(masterPassword)
			if err != nil {
				fmt.Printf("Error encrypting vault: %v\n", err)
				return
			}

			if err := src.SaveVault(vaultPath, data); err != nil {
				fmt.Printf("Error saving vault: %v\n", err)
				return
			}

			fmt.Println("Vault initialized successfully.")
		},
	}

	var addCmd = &cobra.Command{
		Use:   "add",
		Short: "Add a new entry to the vault interactively",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Select type to add:")
			fmt.Println("1. Password")
			fmt.Println("2. TOTP")
			fmt.Println("3. Token (GitHub, PyPI, etc.)")
			fmt.Println("4. Secure Note")
			fmt.Println("5. API Key")
			fmt.Println("6. SSH Key")
			fmt.Println("7. Wi-Fi Credentials")
			fmt.Println("8. Recovery Codes")
			fmt.Print("Selection (1-8): ")
			choice := readInput()

			masterPassword, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			switch choice {
			case "1":
				fmt.Print("Account Name: ")
				acc := readInput()
				fmt.Print("Username: ")
				user := readInput()
				fmt.Print("Password (leave blank to generate): ")
				pass, _ := readPassword()
				fmt.Println()
				if pass == "" {
					pass, _ = src.GeneratePassword(16)
					fmt.Printf("Generated password: %s\n", pass)
				}
				vault.AddEntry(acc, user, pass)
			case "2":
				fmt.Print("Account Name: ")
				acc := readInput()
				fmt.Print("Secret: ")
				sec := readInput()
				vault.AddTOTPEntry(acc, sec)
			case "3":
				fmt.Print("Token Name: ")
				name := readInput()
				fmt.Print("Service: ")
				svc := readInput()
				fmt.Print("Token: ")
				tok := readInput()
				fmt.Print("Type (e.g. GitHub): ")
				tType := readInput()
				vault.AddToken(name, svc, tok, tType)
			case "4":
				fmt.Print("Note Name: ")
				name := readInput()
				fmt.Println("Content (end with empty line):")
				var contentLines []string
				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					line := scanner.Text()
					if line == "" {
						break
					}
					contentLines = append(contentLines, line)
				}
				vault.AddSecureNote(name, strings.Join(contentLines, "\n"))
			case "5":
				fmt.Print("Label: ")
				name := readInput()
				fmt.Print("Service: ")
				svc := readInput()
				fmt.Print("API Key: ")
				key := readInput()
				vault.AddAPIKey(name, svc, key)
			case "6":
				fmt.Print("Key Label: ")
				name := readInput()
				fmt.Println("Enter Private Key (end with empty line):")
				var keyLines []string
				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					line := scanner.Text()
					if line == "" {
						break
					}
					keyLines = append(keyLines, line)
				}
				vault.AddSSHKey(name, strings.Join(keyLines, "\n"))
			case "7":
				fmt.Print("SSID: ")
				ssid := readInput()
				fmt.Print("Password: ")
				pass := readInput()
				fmt.Print("Security (WPA2/WPA3): ")
				sec := readInput()
				vault.AddWiFi(ssid, pass, sec)
			case "8":
				fmt.Print("Service: ")
				svc := readInput()
				fmt.Println("Enter Codes (one per line, end with empty line):")
				var codes []string
				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					line := scanner.Text()
					if line == "" {
						break
					}
					codes = append(codes, line)
				}
				vault.AddRecoveryCode(svc, codes)
			default:
				fmt.Println("Invalid selection.")
				return
			}

			data, err := vault.Serialize(masterPassword)
			if err != nil {
				fmt.Printf("Error encrypting vault: %v\n", err)
				return
			}
			src.SaveVault(vaultPath, data)
			fmt.Println("Entry saved.")
		},
	}

	var getCmd = &cobra.Command{
		Use:   "get [name]",
		Short: "Retrieve an entry from the vault",
		Run: func(cmd *cobra.Command, args []string) {
			name := ""
			if len(args) > 0 {
				name = args[0]
			} else {
				fmt.Print("Search Name/Account: ")
				name = readInput()
			}

			_, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			// Try each type
			if e, ok := vault.GetEntry(name); ok {
				fmt.Printf("Type: Password\nAccount: %s\nUser: %s\n", e.Account, e.Username)
				copyToClipboard(e.Password)
				fmt.Println("Password copied to clipboard.")
				return
			}
			if t, ok := vault.GetTOTPEntry(name); ok {
				code, _ := src.GenerateTOTP(t.Secret)
				fmt.Printf("Type: TOTP\nAccount: %s\nCode: %s\n", t.Account, code)
				return
			}
			if tok, ok := vault.GetToken(name); ok {
				fmt.Printf("Type: Token\nName: %s\nService: %s\n", tok.Name, tok.Service)
				copyToClipboard(tok.Token)
				fmt.Println("Token copied to clipboard.")
				return
			}
			if n, ok := vault.GetSecureNote(name); ok {
				fmt.Printf("Type: Secure Note\nName: %s\nContent:\n%s\n", n.Name, n.Content)
				return
			}
			if k, ok := vault.GetAPIKey(name); ok {
				fmt.Printf("Type: API Key\nLabel: %s\nService: %s\n", k.Name, k.Service)
				copyToClipboard(k.Key)
				fmt.Println("Key copied to clipboard.")
				return
			}
			if s, ok := vault.GetSSHKey(name); ok {
				fmt.Printf("Type: SSH Key\nLabel: %s\n", s.Name)
				copyToClipboard(s.PrivateKey)
				fmt.Println("Private Key copied to clipboard.")
				return
			}
			if w, ok := vault.GetWiFi(name); ok {
				fmt.Printf("Type: Wi-Fi\nSSID: %s\nSecurity: %s\n", w.SSID, w.SecurityType)
				copyToClipboard(w.Password)
				fmt.Println("Password copied to clipboard.")
				return
			}
			if r, ok := vault.GetRecoveryCode(name); ok {
				fmt.Printf("Type: Recovery Codes\nService: %s\nCodes:\n", r.Service)
				for _, c := range r.Codes {
					fmt.Printf("- %s\n", c)
				}
				return
			}

			fmt.Printf("Entry '%s' not found.\n", name)
		},
	}

	var delCmd = &cobra.Command{
		Use:   "del [name]",
		Short: "Delete an entry from the vault",
		Run: func(cmd *cobra.Command, args []string) {
			name := ""
			if len(args) > 0 {
				name = args[0]
			} else {
				fmt.Print("Delete Name/Account: ")
				name = readInput()
			}

			masterPassword, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			deleted := false
			if vault.DeleteEntry(name) {
				deleted = true
			} else if vault.DeleteTOTPEntry(name) {
				deleted = true
			} else if vault.DeleteToken(name) {
				deleted = true
			} else if vault.DeleteSecureNote(name) {
				deleted = true
			} else if vault.DeleteAPIKey(name) {
				deleted = true
			} else if vault.DeleteSSHKey(name) {
				deleted = true
			} else if vault.DeleteWiFi(name) {
				deleted = true
			} else if vault.DeleteRecoveryCode(name) {
				deleted = true
			}

			if deleted {
				data, err := vault.Serialize(masterPassword)
				if err != nil {
					fmt.Printf("Error encrypting vault: %v\n", err)
					return
				}
				src.SaveVault(vaultPath, data)
				fmt.Printf("Deleted '%s'.\n", name)
			} else {
				fmt.Printf("Entry '%s' not found.\n", name)
			}
		},
	}

	var editCmd = &cobra.Command{
		Use:   "edit [name]",
		Short: "Edit an existing entry",
		Run: func(cmd *cobra.Command, args []string) {
			name := ""
			if len(args) > 0 {
				name = args[0]
			} else {
				fmt.Print("Edit Name/Account: ")
				name = readInput()
			}

			masterPassword, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			// This is a bit complex due to different types, but we can detect type and prompt
			if e, ok := vault.GetEntry(name); ok {
				fmt.Printf("Editing Password Entry: %s\n", name)
				fmt.Printf("New Username [%s]: ", e.Username)
				if u := readInput(); u != "" {
					e.Username = u
				}
				fmt.Print("New Password (leave blank to keep): ")
				if p, _ := readPassword(); p != "" {
					e.Password = p
				}
				fmt.Println()
				vault.AddEntry(e.Account, e.Username, e.Password)
			} else if t, ok := vault.GetTOTPEntry(name); ok {
				fmt.Printf("Editing TOTP Entry: %s\n", name)
				fmt.Print("New Secret (leave blank to keep): ")
				if s := readInput(); s != "" {
					t.Secret = s
				}
				vault.AddTOTPEntry(t.Account, t.Secret)
			} else if tok, ok := vault.GetToken(name); ok {
				fmt.Printf("Editing Token Entry: %s\n", name)
				fmt.Printf("New Service [%s]: ", tok.Service)
				if s := readInput(); s != "" {
					tok.Service = s
				}
				fmt.Print("New Token (leave blank to keep): ")
				if t := readInput(); t != "" {
					tok.Token = t
				}
				vault.AddToken(tok.Name, tok.Service, tok.Token, tok.Type)
			} else if n, ok := vault.GetSecureNote(name); ok {
				fmt.Printf("Editing Note: %s\n", name)
				fmt.Println("Enter New Content (end with empty line, blank to keep):")
				var contentLines []string
				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					line := scanner.Text()
					if line == "" {
						break
					}
					contentLines = append(contentLines, line)
				}
				if len(contentLines) > 0 {
					n.Content = strings.Join(contentLines, "\n")
				}
				vault.AddSecureNote(n.Name, n.Content)
			} else if k, ok := vault.GetAPIKey(name); ok {
				fmt.Printf("Editing API Key: %s\n", name)
				fmt.Printf("New Service [%s]: ", k.Service)
				if s := readInput(); s != "" {
					k.Service = s
				}
				fmt.Print("Key (blank to keep): ")
				if val := readInput(); val != "" {
					k.Key = val
				}
				vault.AddAPIKey(k.Name, k.Service, k.Key)
			} else if s, ok := vault.GetSSHKey(name); ok {
				fmt.Printf("Editing SSH Key: %s\n", name)
				fmt.Println("Enter New Private Key (end with empty line, blank to keep):")
				var keyLines []string
				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					line := scanner.Text()
					if line == "" {
						break
					}
					keyLines = append(keyLines, line)
				}
				if len(keyLines) > 0 {
					s.PrivateKey = strings.Join(keyLines, "\n")
				}
				vault.AddSSHKey(s.Name, s.PrivateKey)
			} else if w, ok := vault.GetWiFi(name); ok {
				fmt.Printf("Editing Wi-Fi: %s\n", name)
				fmt.Printf("New Password (blank to keep): ")
				if val := readInput(); val != "" {
					w.Password = val
				}
				fmt.Printf("New Security [%s]: ", w.SecurityType)
				if val := readInput(); val != "" {
					w.SecurityType = val
				}
				vault.AddWiFi(w.SSID, w.Password, w.SecurityType)
			} else if r, ok := vault.GetRecoveryCode(name); ok {
				fmt.Printf("Editing Recovery Codes: %s\n", name)
				fmt.Println("Enter New Codes (end with empty line, blank to keep):")
				var codes []string
				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					line := scanner.Text()
					if line == "" {
						break
					}
					codes = append(codes, line)
				}
				if len(codes) > 0 {
					r.Codes = codes
				}
				vault.AddRecoveryCode(r.Service, r.Codes)
			} else {
				fmt.Printf("Entry '%s' not found.\n", name)
				return
			}

			data, err := vault.Serialize(masterPassword)
			if err != nil {
				fmt.Printf("Error encrypting vault: %v\n", err)
				return
			}
			src.SaveVault(vaultPath, data)
			fmt.Println("Update successful.")
		},
	}

	var modeCmd = &cobra.Command{
		Use:   "mode",
		Short: "Manage operational modes",
	}

	var openCmd = &cobra.Command{
		Use:   "open <mins>",
		Short: "Activate session mode for a given duration in minutes",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			mins := 0
			_, err := fmt.Sscanf(args[0], "%d", &mins)
			if err != nil || mins <= 0 {
				fmt.Println("Please provide a valid number of minutes.")
				return
			}

			fmt.Println("Confirming access for open mode...")
			masterPassword, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			duration := time.Duration(mins) * time.Minute
			if err := src.CreateSession(masterPassword, duration); err != nil {
				fmt.Printf("Error creating session: %v\n", err)
				return
			}

			fmt.Printf("Open mode activated for %d minutes.\n", mins)
		},
	}

	var lockCmd = &cobra.Command{
		Use:   "lock",
		Short: "Immediately lock the vault (terminate session)",
		Run: func(cmd *cobra.Command, args []string) {
			if err := src.KillSession(); err != nil {
				fmt.Println("No active session to lock.")
			} else {
				fmt.Println("Vault locked. Session terminated.")
			}
		},
	}

	var compromiseCmd = &cobra.Command{
		Use:   "compromise",
		Short: "EMERGENCY: Permanently delete the vault and all traces",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print("WARNING: This will PERMANENTLY DELETE your vault. Are you sure? (type 'DESTROY' to confirm): ")
			confirm := readInput()
			if confirm != "DESTROY" {
				fmt.Println("Aborted.")
				return
			}

			// Securely erase vault.dat
			if src.VaultExists(vaultPath) {
				f, err := os.OpenFile(vaultPath, os.O_WRONLY, 0)
				if err == nil {
					info, _ := f.Stat()
					size := info.Size()
					randomData := make([]byte, size)
					rand.Read(randomData)
					f.Write(randomData)
					f.Sync()
					f.Close()
				}
				os.Remove(vaultPath)
				fmt.Println("Vault file securely erased.")
			}

			src.KillSession()
			fmt.Println("Session terminated.")
			fmt.Println("Emergency lockdown complete.")
		},
	}

	modeCmd.AddCommand(openCmd, lockCmd, compromiseCmd)

	var genCmd = &cobra.Command{
		Use:   "gen",
		Short: "Generate a random secure password",
		Run: func(cmd *cobra.Command, args []string) {
			length, _ := cmd.Flags().GetInt("length")
			password, _ := src.GeneratePassword(length)
			fmt.Println(password)
		},
	}

	var totpCmd = &cobra.Command{
		Use:   "totp",
		Short: "Manage TOTP accounts",
	}

	var totpShowCmd = &cobra.Command{
		Use:   "show [account]",
		Short: "Show TOTP code(s) with live updates",
		Run: func(cmd *cobra.Command, args []string) {
			company, _ := cmd.Flags().GetString("company")

			_, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			var targets []src.TOTPEntry
			if len(args) == 0 || args[0] == "all" {
				targets = vault.TOTPEntries
			} else {
				entry, ok := vault.GetTOTPEntry(args[0])
				if !ok {
					fmt.Printf("TOTP account %s not found.\n", args[0])
					return
				}
				targets = append(targets, entry)
			}

			if company != "" {
				var filtered []src.TOTPEntry
				for _, t := range targets {
					if strings.Contains(strings.ToLower(t.Account), strings.ToLower(company)) {
						filtered = append(filtered, t)
					}
				}
				targets = filtered
			}

			if len(targets) == 0 {
				fmt.Println("No matching TOTP accounts found.")
				return
			}

			fmt.Println("\x1b[?25lPress Ctrl+C to stop.") // Hide cursor
			defer fmt.Print("\x1b[?25h")                  // Show cursor on exit

			for {
				remaining := src.TimeRemaining()
				fmt.Printf("\r\x1b[KUpdating in %ds... (Progress: [", remaining)
				for i := 0; i < 30; i++ {
					if i < (30 - remaining) {
						fmt.Print("=")
					} else {
						fmt.Print(" ")
					}
				}
				fmt.Println("])")

				for _, entry := range targets {
					code, _ := src.GenerateTOTP(entry.Secret)
					fmt.Printf("\r\x1b[K  %-40s : \x1b[1;32m%s\x1b[0m\n", entry.Account, code)
				}
				time.Sleep(1 * time.Second)
				fmt.Printf("\033[%dA", len(targets)+1)
			}
		},
	}
	totpShowCmd.Flags().StringP("company", "c", "", "Filter by company name")
	totpCmd.AddCommand(totpShowCmd)

	var importCmd = &cobra.Command{
		Use:   "import <file>",
		Short: "Import data from JSON, CSV, or TXT file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			filename := args[0]
			encryptPass, _ := cmd.Flags().GetString("encrypt-pass")

			masterPassword, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			ext := strings.ToLower(filepath.Ext(filename))
			if ext != "" {
				ext = ext[1:]
			}

			var importErr error
			switch ext {
			case "json":
				importErr = src.ImportFromJSON(vault, filename, encryptPass)
			case "csv":
				importErr = src.ImportFromCSV(vault, filename)
			case "txt":
				importErr = src.ImportFromTXT(vault, filename)
			default:
				fmt.Printf("Unsupported file extension: %s\n", ext)
				return
			}

			if importErr != nil {
				fmt.Printf("Error during import: %v\n", importErr)
				return
			}

			data, err := vault.Serialize(masterPassword)
			if err != nil {
				fmt.Printf("Error encrypting vault: %v\n", err)
				return
			}
			src.SaveVault(vaultPath, data)
			fmt.Printf("Successfully imported data from %s.\n", filename)
		},
	}

	var exportCmd = &cobra.Command{
		Use:   "export",
		Short: "Export vault data safely",
		Run: func(cmd *cobra.Command, args []string) {
			withoutPass, _ := cmd.Flags().GetBool("without-password")
			output, _ := cmd.Flags().GetString("output")
			encryptPass, _ := cmd.Flags().GetString("encrypt-pass")

			_, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			if output == "" {
				output = "export.json"
				if withoutPass {
					output = "export.txt"
				}
			}

			var exportErr error
			ext := strings.ToLower(filepath.Ext(output))
			if withoutPass || ext == ".txt" {
				exportErr = src.ExportToTXT(vault, output, withoutPass)
			} else if ext == ".csv" {
				exportErr = src.ExportToCSV(vault, output)
			} else {
				exportErr = src.ExportToJSON(vault, output, encryptPass)
			}

			if exportErr != nil {
				fmt.Printf("Error during export: %v\n", exportErr)
				return
			}

			fmt.Printf("Successfully exported vault data to %s.\n", output)
		},
	}

	importCmd.Flags().StringP("encrypt-pass", "e", "", "Password for decryption")
	exportCmd.Flags().StringP("output", "o", "", "Output filename")
	exportCmd.Flags().StringP("encrypt-pass", "e", "", "Password for encryption")
	exportCmd.Flags().Bool("without-password", false, "Exclude secrets")

	genCmd.Flags().IntP("length", "l", 16, "Password length")

	var vhistoryCmd = &cobra.Command{
		Use:   "vhistory",
		Short: "Show the history of changes made to the vault",
		Run: func(cmd *cobra.Command, args []string) {
			_, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			if len(vault.History) == 0 {
				fmt.Println("No history found.")
				return
			}

			fmt.Println("Vault History:")
			for _, h := range vault.History {
				fmt.Printf("[%s] %s %s: %s\n", h.Timestamp.Format("2006-01-02 15:04:05"), h.Action, h.Category, h.Identifier)
			}
		},
	}

	var infoCmd = &cobra.Command{
		Use:   "info",
		Short: "Show information about APM",
		Run: func(cmd *cobra.Command, args []string) {
			homeDir, err := os.UserHomeDir()
			if err != nil {
				fmt.Printf("Error getting home directory: %v\n", err)
				return
			}
			homeName := filepath.Base(homeDir)
			processedHomeName := strings.ToLower(strings.ReplaceAll(homeName, " ", ""))

			exe, _ := os.Executable()
			installDir := filepath.Dir(exe)

			fmt.Println("APM Alpha (Not Stable)")
			fmt.Println(processedHomeName)
			fmt.Println("v4 -- Command Overhaul and Security FIxes")
			fmt.Printf("Installed: %s\n", installDir)
			fmt.Printf("Vault Path: %s\n", vaultPath)
			fmt.Println("https://github.com/aaravmaloo/apm")
			fmt.Println("Contact: aaravmaloo06@gmail.com")
		},
	}

	rootCmd.AddCommand(initCmd, addCmd, getCmd, delCmd, editCmd, genCmd, modeCmd, totpCmd, importCmd, exportCmd, infoCmd, vhistoryCmd)
	rootCmd.Execute()
}

func readInput() string {
	reader := bufio.NewReader(os.Stdin)
	input, _ := reader.ReadString('\n')
	return strings.TrimSpace(input)
}

func readPassword() (string, error) {
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytePassword)), nil
}

func copyToClipboard(text string) {
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "Set-Clipboard", "-Value", fmt.Sprintf("'%s'", strings.ReplaceAll(text, "'", "''")))
		cmd.Run()
	} else if runtime.GOOS == "darwin" {
		cmd := exec.Command("pbcopy")
		cmd.Stdin = strings.NewReader(text)
		cmd.Run()
	} else {
		// Try xclip or xsel for linux
		cmd := exec.Command("xclip", "-selection", "clipboard")
		cmd.Stdin = strings.NewReader(text)
		if err := cmd.Run(); err != nil {
			cmd = exec.Command("xsel", "--clipboard", "--input")
			cmd.Stdin = strings.NewReader(text)
			cmd.Run()
		}
	}
}

func src_unlockVault() (string, *src.Vault, error) {
	if !src.VaultExists(vaultPath) {
		return "", nil, fmt.Errorf("Vault does not exist. Run 'pm init' first.")
	}

	data, err := src.LoadVault(vaultPath)
	if err != nil {
		return "", nil, err
	}

	salt := data[:16]
	ciphertext := data[16:]

	if sessionPass, err := src.GetSession(); err == nil {
		vault, err := src.DecryptVault(ciphertext, sessionPass, salt)
		if err == nil {
			return sessionPass, vault, nil
		}
		src.KillSession()
	}

	for i := 0; i < 3; i++ {
		fmt.Printf("Master Password (attempt %d/3): ", i+1)
		masterPassword, err := readPassword()
		if err != nil {
			return "", nil, err
		}
		fmt.Println()

		vault, err := src.DecryptVault(ciphertext, masterPassword, salt)
		if err == nil {
			return masterPassword, vault, nil
		}
		fmt.Printf("Error: %v\n", err)
	}

	return "", nil, fmt.Errorf("too many failed attempts")
}
