package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
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
				if err := vault.AddEntry(acc, user, pass); err != nil {
					fmt.Printf("Error: %v\n", err)
					return
				}
			case "2":
				fmt.Print("Account Name: ")
				acc := readInput()
				fmt.Print("Secret: ")
				sec := readInput()
				if err := vault.AddTOTPEntry(acc, sec); err != nil {
					fmt.Printf("Error: %v\n", err)
					return
				}
			case "3":
				fmt.Print("Token Name: ")
				name := readInput()
				fmt.Print("Service: ")
				svc := readInput()
				fmt.Print("Token: ")
				tok := readInput()
				fmt.Print("Type (e.g. GitHub): ")
				tType := readInput()
				if err := vault.AddToken(name, svc, tok, tType); err != nil {
					fmt.Printf("Error: %v\n", err)
					return
				}
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
				if err := vault.AddSecureNote(name, strings.Join(contentLines, "\n")); err != nil {
					fmt.Printf("Error: %v\n", err)
					return
				}
			case "5":
				fmt.Print("Label: ")
				name := readInput()
				fmt.Print("Service: ")
				svc := readInput()
				fmt.Print("API Key: ")
				key := readInput()
				if err := vault.AddAPIKey(name, svc, key); err != nil {
					fmt.Printf("Error: %v\n", err)
					return
				}
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
				if err := vault.AddSSHKey(name, strings.Join(keyLines, "\n")); err != nil {
					fmt.Printf("Error: %v\n", err)
					return
				}
			case "7":
				fmt.Print("SSID: ")
				ssid := readInput()
				fmt.Print("Password: ")
				pass := readInput()
				fmt.Print("Security (WPA2/WPA3): ")
				sec := readInput()
				if err := vault.AddWiFi(ssid, pass, sec); err != nil {
					fmt.Printf("Error: %v\n", err)
					return
				}
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
				if err := vault.AddRecoveryCode(svc, codes); err != nil {
					fmt.Printf("Error: %v\n", err)
					return
				}
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
			}

			showPass, _ := cmd.Flags().GetBool("show-pass")

			_, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			if name != "" {
				// Try exact match first
				if e, ok := vault.GetEntry(name); ok {
					displayEntry(src.SearchResult{Type: "Password", Identifier: e.Account, Data: e}, showPass)
					return
				}
				if t, ok := vault.GetTOTPEntry(name); ok {
					displayEntry(src.SearchResult{Type: "TOTP", Identifier: t.Account, Data: t}, showPass)
					return
				}
				if tok, ok := vault.GetToken(name); ok {
					displayEntry(src.SearchResult{Type: "Token", Identifier: tok.Name, Data: tok}, showPass)
					return
				}
				if n, ok := vault.GetSecureNote(name); ok {
					displayEntry(src.SearchResult{Type: "Note", Identifier: n.Name, Data: n}, showPass)
					return
				}
				if k, ok := vault.GetAPIKey(name); ok {
					displayEntry(src.SearchResult{Type: "API Key", Identifier: k.Name, Data: k}, showPass)
					return
				}
				if s, ok := vault.GetSSHKey(name); ok {
					displayEntry(src.SearchResult{Type: "SSH Key", Identifier: s.Name, Data: s}, showPass)
					return
				}
				if w, ok := vault.GetWiFi(name); ok {
					displayEntry(src.SearchResult{Type: "Wi-Fi", Identifier: w.SSID, Data: w}, showPass)
					return
				}
				if r, ok := vault.GetRecoveryCode(name); ok {
					displayEntry(src.SearchResult{Type: "Recovery Codes", Identifier: r.Service, Data: r}, showPass)
					return
				}
			}

			// No exact match or no name provided, ask for type
			fmt.Println("Select type to search (or 'all'):")
			fmt.Println("1. Password        2. TOTP")
			fmt.Println("3. Token           4. Secure Note")
			fmt.Println("5. API Key         6. SSH Key")
			fmt.Println("7. Wi-Fi           8. Recovery Codes")
			fmt.Println("9. All")
			fmt.Print("Choice (1-9) [9]: ")
			typeChoice := readInput()
			if typeChoice == "" {
				typeChoice = "9"
			}

			query := name
			if query == "" {
				fmt.Print("Search Query (leave blank for all): ")
				query = readInput()
			}

			typeName := ""
			switch typeChoice {
			case "1":
				typeName = "Password"
			case "2":
				typeName = "TOTP"
			case "3":
				typeName = "Token"
			case "4":
				typeName = "Note"
			case "5":
				typeName = "API Key"
			case "6":
				typeName = "SSH Key"
			case "7":
				typeName = "Wi-Fi"
			case "8":
				typeName = "Recovery Codes"
			}

			allResults := vault.SearchAll(query)
			var results []src.SearchResult
			if typeName != "" {
				for _, res := range allResults {
					if res.Type == typeName {
						results = append(results, res)
					}
				}
			} else {
				results = allResults
			}

			if len(results) == 0 {
				fmt.Println("No matching entries found.")
				return
			}

			if len(results) == 1 {
				displayEntry(results[0], showPass)
				return
			}

			fmt.Println("\nMatching entries:")
			for i, res := range results {
				fmt.Printf("[%d] %s (%s)\n", i+1, res.Identifier, res.Type)
			}
			fmt.Print("Select a number: ")
			choiceStr := readInput()
			choice, err := strconv.Atoi(choiceStr)
			if err != nil || choice < 1 || choice > len(results) {
				fmt.Println("Invalid selection.")
				return
			}
			fmt.Println()
			displayEntry(results[choice-1], showPass)
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

			updated := false
			if e, ok := vault.GetEntry(name); ok {
				fmt.Printf("Editing Password Entry: %s\n", name)
				fmt.Printf("New Account [%s]: ", e.Account)
				newAcc := readInput()
				if newAcc == "" {
					newAcc = e.Account
				}
				fmt.Printf("New Username [%s]: ", e.Username)
				newUser := readInput()
				if newUser == "" {
					newUser = e.Username
				}
				fmt.Print("New Password (leave blank to keep): ")
				newPass, _ := readPassword()
				fmt.Println()
				if newPass == "" {
					newPass = e.Password
				}

				if err := vault.AddEntry(newAcc, newUser, newPass); err != nil {
					fmt.Printf("Error: %v\n", err)
					return
				}
				if newAcc != e.Account {
					vault.DeleteEntry(e.Account)
				}
				updated = true
			} else if t, ok := vault.GetTOTPEntry(name); ok {
				fmt.Printf("Editing TOTP Entry: %s\n", name)
				fmt.Printf("New Account [%s]: ", t.Account)
				newAcc := readInput()
				if newAcc == "" {
					newAcc = t.Account
				}
				fmt.Printf("New Secret (leave blank to keep): ")
				newSec := readInput()
				if newSec == "" {
					newSec = t.Secret
				}
				if err := vault.AddTOTPEntry(newAcc, newSec); err != nil {
					fmt.Printf("Error: %v\n", err)
					return
				}
				if newAcc != t.Account {
					vault.DeleteTOTPEntry(t.Account)
				}
				updated = true
			} else if tok, ok := vault.GetToken(name); ok {
				fmt.Printf("Editing Token Entry: %s\n", name)
				fmt.Printf("New Name [%s]: ", tok.Name)
				newName := readInput()
				if newName == "" {
					newName = tok.Name
				}
				fmt.Printf("New Service [%s]: ", tok.Service)
				newSvc := readInput()
				if newSvc == "" {
					newSvc = tok.Service
				}
				fmt.Printf("New Token (blank to keep): ")
				newTok := readInput()
				if newTok == "" {
					newTok = tok.Token
				}
				fmt.Printf("New Type [%s]: ", tok.Type)
				newType := readInput()
				if newType == "" {
					newType = tok.Type
				}
				if err := vault.AddToken(newName, newSvc, newTok, newType); err != nil {
					fmt.Printf("Error: %v\n", err)
					return
				}
				if newName != tok.Name {
					vault.DeleteToken(tok.Name)
				}
				updated = true
			} else if n, ok := vault.GetSecureNote(name); ok {
				fmt.Printf("Editing Note: %s\n", name)
				fmt.Printf("New Name [%s]: ", n.Name)
				newName := readInput()
				if newName == "" {
					newName = n.Name
				}
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
				newContent := n.Content
				if len(contentLines) > 0 {
					newContent = strings.Join(contentLines, "\n")
				}
				if err := vault.AddSecureNote(newName, newContent); err != nil {
					fmt.Printf("Error: %v\n", err)
					return
				}
				if newName != n.Name {
					vault.DeleteSecureNote(n.Name)
				}
				updated = true
			} else if k, ok := vault.GetAPIKey(name); ok {
				fmt.Printf("Editing API Key: %s\n", name)
				fmt.Printf("New Label [%s]: ", k.Name)
				newName := readInput()
				if newName == "" {
					newName = k.Name
				}
				fmt.Printf("New Service [%s]: ", k.Service)
				newSvc := readInput()
				if newSvc == "" {
					newSvc = k.Service
				}
				fmt.Print("New Key (blank to keep): ")
				newKey := readInput()
				if newKey == "" {
					newKey = k.Key
				}
				if err := vault.AddAPIKey(newName, newSvc, newKey); err != nil {
					fmt.Printf("Error: %v\n", err)
					return
				}
				if newName != k.Name {
					vault.DeleteAPIKey(k.Name)
				}
				updated = true
			} else if s, ok := vault.GetSSHKey(name); ok {
				fmt.Printf("Editing SSH Key: %s\n", name)
				fmt.Printf("New Label [%s]: ", s.Name)
				newName := readInput()
				if newName == "" {
					newName = s.Name
				}
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
				newKey := s.PrivateKey
				if len(keyLines) > 0 {
					newKey = strings.Join(keyLines, "\n")
				}
				if err := vault.AddSSHKey(newName, newKey); err != nil {
					fmt.Printf("Error: %v\n", err)
					return
				}
				if newName != s.Name {
					vault.DeleteSSHKey(s.Name)
				}
				updated = true
			} else if w, ok := vault.GetWiFi(name); ok {
				fmt.Printf("Editing Wi-Fi: %s\n", name)
				fmt.Printf("New SSID [%s]: ", w.SSID)
				newSSID := readInput()
				if newSSID == "" {
					newSSID = w.SSID
				}
				fmt.Printf("New Password (blank to keep): ")
				newPass := readInput()
				if newPass == "" {
					newPass = w.Password
				}
				fmt.Printf("New Security [%s]: ", w.SecurityType)
				newSec := readInput()
				if newSec == "" {
					newSec = w.SecurityType
				}
				if err := vault.AddWiFi(newSSID, newPass, newSec); err != nil {
					fmt.Printf("Error: %v\n", err)
					return
				}
				if newSSID != w.SSID {
					vault.DeleteWiFi(w.SSID)
				}
				updated = true
			} else if r, ok := vault.GetRecoveryCode(name); ok {
				fmt.Printf("Editing Recovery Codes: %s\n", name)
				fmt.Printf("New Service [%s]: ", r.Service)
				newSvc := readInput()
				if newSvc == "" {
					newSvc = r.Service
				}
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
				newCodes := r.Codes
				if len(codes) > 0 {
					newCodes = codes
				}
				if err := vault.AddRecoveryCode(newSvc, newCodes); err != nil {
					fmt.Printf("Error: %v\n", err)
					return
				}
				if newSvc != r.Service {
					vault.DeleteRecoveryCode(r.Service)
				}
				updated = true
			} else {
				fmt.Printf("Entry '%s' not found.\n", name)
				return
			}

			if updated {
				data, err := vault.Serialize(masterPassword)
				if err != nil {
					fmt.Printf("Error encrypting vault: %v\n", err)
					return
				}
				src.SaveVault(vaultPath, data)
				fmt.Println("Update successful.")
			}
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
	getCmd.Flags().Bool("show-pass", false, "Show password in output")

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

func displayEntry(res src.SearchResult, showPass bool) {
	switch res.Type {
	case "Password":
		e := res.Data.(src.Entry)
		fmt.Printf("Type: Password\nAccount: %s\nUser: %s\n", e.Account, e.Username)
		if showPass {
			fmt.Printf("Password: %s\n", e.Password)
		}
		copyToClipboard(e.Password)
		fmt.Println("Password copied to clipboard.")
	case "TOTP":
		t := res.Data.(src.TOTPEntry)
		code, _ := src.GenerateTOTP(t.Secret)
		fmt.Printf("Type: TOTP\nAccount: %s\nCode: %s\n", t.Account, code)
	case "Token":
		tok := res.Data.(src.TokenEntry)
		fmt.Printf("Type: Token\nName: %s\nService: %s\n", tok.Name, tok.Service)
		if showPass {
			fmt.Printf("Token: %s\n", tok.Token)
		}
		copyToClipboard(tok.Token)
		fmt.Println("Token copied to clipboard.")
	case "Note":
		n := res.Data.(src.SecureNoteEntry)
		fmt.Printf("Type: Secure Note\nName: %s\nContent:\n%s\n", n.Name, n.Content)
	case "API Key":
		k := res.Data.(src.APIKeyEntry)
		fmt.Printf("Type: API Key\nLabel: %s\nService: %s\n", k.Name, k.Service)
		if showPass {
			fmt.Printf("Key: %s\n", k.Key)
		}
		copyToClipboard(k.Key)
		fmt.Println("Key copied to clipboard.")
	case "SSH Key":
		s := res.Data.(src.SSHKeyEntry)
		fmt.Printf("Type: SSH Key\nLabel: %s\n", s.Name)
		if showPass {
			fmt.Printf("Private Key:\n%s\n", s.PrivateKey)
		}
		copyToClipboard(s.PrivateKey)
		fmt.Println("Private Key copied to clipboard.")
	case "Wi-Fi":
		w := res.Data.(src.WiFiEntry)
		fmt.Printf("Type: Wi-Fi\nSSID: %s\nSecurity: %s\n", w.SSID, w.SecurityType)
		if showPass {
			fmt.Printf("Password: %s\n", w.Password)
		}
		copyToClipboard(w.Password)
		fmt.Println("Password copied to clipboard.")
	case "Recovery Codes":
		r := res.Data.(src.RecoveryCodeEntry)
		fmt.Printf("Type: Recovery Codes\nService: %s\nCodes:\n", r.Service)
		for _, c := range r.Codes {
			fmt.Printf("- %s\n", c)
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
