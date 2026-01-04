package main

import (
	"bufio"
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

var (
	vaultPath string
	vaultName string = "default"
	appPath   string
)

func updateVaultPath() {
	exeDir := filepath.Dir(appPath)
	vaultPath = filepath.Join(exeDir, "vault_"+vaultName+".dat")
}

func copyToClipboard(val string) {
	var cmd *exec.Cmd

	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell", "-command", fmt.Sprintf("Set-Clipboard -Value '%s'", val))
	} else if runtime.GOOS == "darwin" {
		cmd = exec.Command("pbcopy")
		cmd.Stdin = strings.NewReader(val)
	} else {
		cmd = exec.Command("xclip", "-selection", "clipboard")
		cmd.Stdin = strings.NewReader(val)
	}
	cmd.Run()
}

func spawnClearClipboard(mins int) {
	if mins <= 0 {
		return
	}
	fmt.Printf("Password copied to clipboard. It will be cleared in %d minutes.\n", mins)
	if runtime.GOOS == "windows" {
		cmd := exec.Command("powershell", "-WindowStyle", "Hidden", "-Command",
			fmt.Sprintf("Start-Sleep -Seconds %d; Set-Clipboard -Value $null", mins*60))
		cmd.Start()
	} else {
		// Simple background sleep for unix
		go func() {
			time.Sleep(time.Duration(mins) * time.Minute)
			copyToClipboard("")
		}()
	}
}

func init() {
	exe, err := os.Executable()
	if err != nil {
		fmt.Printf("Error getting executable path: %v\n", err)
		os.Exit(1)
	}
	appPath = exe
	vaultPath = filepath.Join(filepath.Dir(exe), "vault_"+vaultName+".dat")
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "pm",
		Short: "A simple password manager CLI",
		CompletionOptions: cobra.CompletionOptions{
			DisableDefaultCmd: true,
		},
	}

	var initCmd = &cobra.Command{
		Use:   "init [vault_name]",
		Short: "Initialize a new vault",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) > 0 {
				vaultName = args[0]
				updateVaultPath()
			}

			if src.VaultExists(vaultPath) {
				fmt.Printf("Vault '%s' already exists.\n", vaultName)
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

			fmt.Printf("Vault '%s' initialized successfully.\n", vaultName)
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
			fmt.Println("4. SSH Key")
			fmt.Println("5. Wi-Fi Credentials")
			fmt.Println("6. Recovery Codes")
			fmt.Print("Selection (1-6): ")
			choice := readInput()

			masterPassword, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			switch choice {
			case "1":
				fmt.Print("Account: ")
				account := readInput()
				fmt.Print("Username: ")
				username := readInput()
				fmt.Print("Password (leave blank to generate): ")
				password, _ := readPassword()
				fmt.Println()
				if password == "" {
					password, _ = src.GeneratePassword(16)
					fmt.Printf("Generated password: %s\n", password)
				}
				vault.AddEntry(account, username, password)
				fmt.Printf("Added password for %s.\n", account)
			case "2":
				fmt.Print("Account: ")
				account := readInput()
				fmt.Print("Secret: ")
				secret := readInput()
				vault.AddTOTPEntry(account, secret)
				fmt.Printf("Added TOTP for %s.\n", account)
			case "3":
				fmt.Print("Name (e.g. My GitHub Token): ")
				name := readInput()
				fmt.Print("Service (e.g. GitHub): ")
				service := readInput()
				fmt.Print("Token: ")
				token := readInput()
				fmt.Print("Type (e.g. Personal Access Token): ")
				tokenType := readInput()
				vault.AddToken(name, service, token, tokenType)
				fmt.Printf("Added token '%s'.\n", name)
			case "4":
				fmt.Print("Key Name: ")
				name := readInput()
				fmt.Print("Private Key (end with empty line):\n")
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
				fmt.Printf("Added SSH key '%s'.\n", name)
			case "5":
				fmt.Print("SSID: ")
				ssid := readInput()
				fmt.Print("Password: ")
				pass := readInput()
				fmt.Print("Security Type (e.g. WPA2): ")
				sec := readInput()
				vault.AddWiFi(ssid, pass, sec)
				fmt.Printf("Added Wi-Fi credentials for %s.\n", ssid)
			case "6":
				fmt.Print("Service Name: ")
				name := readInput()
				fmt.Print("Recovery Codes (one per line, end with empty line):\n")
				var codes []string
				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					line := scanner.Text()
					if line == "" {
						break
					}
					codes = append(codes, line)
				}
				vault.AddRecoveryCode(name, codes)
				fmt.Printf("Added recovery codes for %s.\n", name)
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
		},
	}

	var getCmd = &cobra.Command{
		Use:   "get",
		Short: "Retrieve an entry from the vault",
		Run: func(cmd *cobra.Command, args []string) {
			showPass, _ := cmd.Flags().GetBool("show_pass")
			clearMins, _ := cmd.Flags().GetInt("clear")
			if clearMins == 0 {
				clearMins = 3 // Default
			}

			account, _ := cmd.Flags().GetString("account")
			if account == "" {
				fmt.Print("Account/Name: ")
				account = readInput()
			}

			_, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			if entry, ok := vault.GetEntry(account); ok {
				fmt.Printf("Account:  %s\n", entry.Account)
				fmt.Printf("Username: %s\n", entry.Username)
				if showPass {
					fmt.Printf("Password: %s\n", entry.Password)
				} else {
					copyToClipboard(entry.Password)
					spawnClearClipboard(clearMins)
				}
				return
			}

			if tok, ok := vault.GetToken(account); ok {
				fmt.Printf("Name:    %s\n", tok.Name)
				fmt.Printf("Service: %s\n", tok.Service)
				fmt.Printf("Type:    %s\n", tok.Type)
				if showPass {
					fmt.Printf("Token:   %s\n", tok.Token)
				} else {
					copyToClipboard(tok.Token)
					spawnClearClipboard(clearMins)
				}
				return
			}

			if key, ok := vault.GetSSHKey(account); ok {
				fmt.Printf("Name: %s\n", key.Name)
				if showPass {
					fmt.Printf("Private Key:\n%s\n", key.PrivateKey)
				} else {
					copyToClipboard(key.PrivateKey)
					spawnClearClipboard(clearMins)
				}
				return
			}

			if wifi, ok := vault.GetWiFi(account); ok {
				fmt.Printf("SSID:     %s\n", wifi.SSID)
				fmt.Printf("Security: %s\n", wifi.SecurityType)
				if showPass {
					fmt.Printf("Password: %s\n", wifi.Password)
				} else {
					copyToClipboard(wifi.Password)
					spawnClearClipboard(clearMins)
				}
				return
			}

			if rec, ok := vault.GetRecoveryCode(account); ok {
				fmt.Printf("Service: %s\n", rec.Service)
				fmt.Println("Recovery Codes:")
				for _, c := range rec.Codes {
					fmt.Printf("  - %s\n", c)
				}
				return
			}

			fmt.Printf("Entry '%s' not found.\n", account)
		},
	}

	var delCmd = &cobra.Command{
		Use:   "del",
		Short: "Delete an entry from the vault interactively",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("1. Password")
			fmt.Println("2. TOTP")
			fmt.Println("3. Token")
			fmt.Println("4. SSH Key")
			fmt.Println("5. Wi-Fi")
			fmt.Println("6. Recovery Codes")
			fmt.Print("Selection (1-6): ")
			choice := readInput()

			masterPassword, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			fmt.Print("Enter Account/Name to delete: ")
			target := readInput()

			deleted := false
			switch choice {
			case "1":
				deleted = vault.DeleteEntry(target)
			case "2":
				deleted = vault.DeleteTOTPEntry(target)
			case "3":
				deleted = vault.DeleteToken(target)
			case "4":
				deleted = vault.DeleteSSHKey(target)
			case "5":
				deleted = vault.DeleteWiFi(target)
			case "6":
				deleted = vault.DeleteRecoveryCode(target)
			default:
				fmt.Println("Invalid selection.")
				return
			}

			if deleted {
				data, err := vault.Serialize(masterPassword)
				if err != nil {
					fmt.Printf("Error encrypting vault: %v\n", err)
					return
				}
				src.SaveVault(vaultPath, data)
				fmt.Printf("Deleted entry '%s'.\n", target)
			} else {
				fmt.Printf("Entry '%s' not found.\n", target)
			}
		},
	}

	var editCmd = &cobra.Command{
		Use:   "edit",
		Short: "Edit an existing entry interactively",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Select type to edit:")
			fmt.Println("1. Password")
			fmt.Println("2. TOTP")
			fmt.Println("3. Token")
			fmt.Println("4. SSH Key")
			fmt.Println("5. Wi-Fi")
			fmt.Println("6. Recovery Codes")
			fmt.Print("Selection (1-6): ")
			choice := readInput()

			masterPassword, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			fmt.Print("Enter Account/Name to edit: ")
			target := readInput()

			switch choice {
			case "1":
				entry, ok := vault.GetEntry(target)
				if !ok {
					fmt.Println("Not found.")
					return
				}
				fmt.Printf("Current User: %s | New (enter to keep): ", entry.Username)
				if u := readInput(); u != "" {
					entry.Username = u
				}
				fmt.Print("New Password (enter to keep): ")
				if p, _ := readPassword(); p != "" {
					entry.Password = p
				}
				fmt.Println()
				vault.AddEntry(entry.Account, entry.Username, entry.Password)
			case "2":
				entry, ok := vault.GetTOTPEntry(target)
				if !ok {
					fmt.Println("Not found.")
					return
				}
				fmt.Printf("Current Secret: %s | New (enter to keep): ", entry.Secret)
				if s := readInput(); s != "" {
					entry.Secret = s
				}
				vault.AddTOTPEntry(entry.Account, entry.Secret)
			case "3":
				entry, ok := vault.GetToken(target)
				if !ok {
					fmt.Println("Not found.")
					return
				}
				fmt.Printf("Current Service: %s | New (enter to keep): ", entry.Service)
				if s := readInput(); s != "" {
					entry.Service = s
				}
				fmt.Printf("Current Token: %s | New (enter to keep): ", entry.Token)
				if t := readInput(); t != "" {
					entry.Token = t
				}
				fmt.Printf("Current Type: %s | New (enter to keep): ", entry.Type)
				if t := readInput(); t != "" {
					entry.Type = t
				}
				vault.AddToken(entry.Name, entry.Service, entry.Token, entry.Type)
			case "4":
				entry, ok := vault.GetSSHKey(target)
				if !ok {
					fmt.Println("Not found.")
					return
				}
				fmt.Println("New Private Key (enter to keep, end with empty line):")
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
					entry.PrivateKey = strings.Join(keyLines, "\n")
				}
				vault.AddSSHKey(entry.Name, entry.PrivateKey)
			case "5":
				entry, ok := vault.GetWiFi(target)
				if !ok {
					fmt.Println("Not found.")
					return
				}
				fmt.Printf("Current SSID: %s | New (enter to keep): ", entry.SSID)
				if s := readInput(); s != "" {
					entry.SSID = s
				}
				fmt.Printf("Current Security: %s | New (enter to keep): ", entry.SecurityType)
				if s := readInput(); s != "" {
					entry.SecurityType = s
				}
				fmt.Print("New Password (enter to keep): ")
				if p := readInput(); p != "" {
					entry.Password = p
				}
				vault.AddWiFi(entry.SSID, entry.Password, entry.SecurityType)
			case "6":
				entry, ok := vault.GetRecoveryCode(target)
				if !ok {
					fmt.Println("Not found.")
					return
				}
				fmt.Println("Enter New Recovery Codes (enter to keep, end with empty line):")
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
					entry.Codes = codes
				}
				vault.AddRecoveryCode(entry.Service, entry.Codes)
			}

			data, err := vault.Serialize(masterPassword)
			if err != nil {
				fmt.Printf("Error encrypting vault: %v\n", err)
				return
			}
			src.SaveVault(vaultPath, data)
			fmt.Println("Entry updated.")
		},
	}

	var vswitchCmd = &cobra.Command{
		Use:   "vswitch [vault_name]",
		Short: "Switch to a different vault",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) == 0 {
				fmt.Printf("Current vault: %s\n", vaultName)
				return
			}
			vaultName = args[0]
			updateVaultPath()
			fmt.Printf("Switched to vault: %s\n", vaultName)
		},
	}

	var infoCmd = &cobra.Command{
		Use:   "info",
		Short: "Display application info",
		Run: func(cmd *cobra.Command, args []string) {
			user := os.Getenv("USERNAME")
			if user == "" {
				user = os.Getenv("USER")
			}
			user = strings.ReplaceAll(strings.ToLower(user), " ", "")
			fmt.Println("Production-v4 (Stable)")
			fmt.Printf("%s@pm\n", user)
			fmt.Println("v4: Overhauled Commands and Security update")
			fmt.Println("https://github.com/aaravmaloo/apm")
			fmt.Println("Contact: aaravmaloo06@gmail.com")

		},
	}

	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all accounts in the vault",
		Run: func(cmd *cobra.Command, args []string) {
			filter, _ := cmd.Flags().GetString("filter")

			_, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			entries := vault.FilterEntries(filter)
			if len(entries) == 0 {
				fmt.Println("No accounts found.")
				return
			}

			fmt.Printf("%-20s %-20s\n", "ACCOUNT", "USERNAME")
			fmt.Println(strings.Repeat("-", 40))
			for _, entry := range entries {
				fmt.Printf("%-20s %-20s\n", entry.Account, entry.Username)
			}
		},
	}

	var modeCmd = &cobra.Command{
		Use:   "mode",
		Short: "Manage operation modes (open, close, compromise)",
	}

	var openCmd = &cobra.Command{
		Use:   "open [mins]",
		Short: "Open the vault for a given duration (default: 5 mins)",
		Run: func(cmd *cobra.Command, args []string) {
			mins := 5 // Default
			if len(args) > 0 {
				fmt.Sscanf(args[0], "%d", &mins)
			}

			fmt.Println("Confirming access...")
			masterPassword, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			duration := time.Duration(mins) * time.Minute
			if err := src.CreateSession(masterPassword, duration); err != nil {
				fmt.Printf("Error opening vault: %v\n", err)
				return
			}

			fmt.Printf("Vault opened for %d minutes.\n", mins)
		},
	}

	var closeCmd = &cobra.Command{
		Use:   "close",
		Short: "Close the vault immediately",
		Run: func(cmd *cobra.Command, args []string) {
			if err := src.KillSession(); err != nil {
				fmt.Println("No active session to close.")
				return
			}
			fmt.Println("Vault closed.")
		},
	}

	var compromiseCmd = &cobra.Command{
		Use:   "compromise",
		Short: "URGENT: Permanently delete application and all vaults",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print("WARNING: This will PERMANENTLY delete the application and all vaults. Type 'DELETE' to confirm: ")
			if readInput() != "DELETE" {
				fmt.Println("Cancelled.")
				return
			}

			files, _ := filepath.Glob(filepath.Join(filepath.Dir(appPath), "vault_*.dat"))
			for _, f := range files {
				os.Remove(f)
			}

			if runtime.GOOS == "windows" {
				cmd := exec.Command("cmd", "/c", fmt.Sprintf("timeout /t 1 /nobreak && del \"%s\"", appPath))
				cmd.Start()
			} else {
				os.Remove(appPath)
			}
			fmt.Println("Compromise protocol active. Application and vaults will be deleted.")
			os.Exit(0)
		},
	}

	modeCmd.AddCommand(openCmd, closeCmd, compromiseCmd)

	var vsettingsCmd = &cobra.Command{
		Use:   "vsettings",
		Short: "Configure vault settings (clear time, inactivity)",
		Run: func(cmd *cobra.Command, args []string) {
			// For now, using simple input prompts or flags if added later
			fmt.Println("Currently settings are defaults (Clear: 3m, Inactivity: 5m).")
			fmt.Println("This command will be expanded to persist settings in future updates.")
		},
	}

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

	var totpAddCmd = &cobra.Command{
		Use:   "add",
		Short: "Add a new TOTP account",
		Run: func(cmd *cobra.Command, args []string) {
			secret, _ := cmd.Flags().GetString("secret")
			account, _ := cmd.Flags().GetString("account")

			if secret == "" {
				fmt.Print("Secret: ")
				secret = readInput()
			}
			if account == "" {
				fmt.Print("Account: ")
				account = readInput()
			}

			masterPassword, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			vault.AddTOTPEntry(account, secret)
			data, err := vault.Serialize(masterPassword)
			if err != nil {
				fmt.Printf("Error encrypting vault: %v\n", err)
				return
			}

			if err := src.SaveVault(vaultPath, data); err != nil {
				fmt.Printf("Error saving vault: %v\n", err)
				return
			}

			fmt.Printf("Added TOTP for %s.\n", account)
		},
	}

	var totpShowCmd = &cobra.Command{
		Use:   "show [account]",
		Short: "Show and copy TOTP code(s)",
		Run: func(cmd *cobra.Command, args []string) {
			_, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			if len(args) == 0 {

				fmt.Println("Choose account to copy (type 'copy_account: <name>'):")
				for _, t := range vault.TOTPEntries {
					code, _ := src.GenerateTOTP(t.Secret)
					fmt.Printf("  %-20s : %s\n", t.Account, code)
				}
				input := readInput()
				if strings.HasPrefix(input, "copy_account: ") {
					acc := strings.TrimPrefix(input, "copy_account: ")
					if t, ok := vault.GetTOTPEntry(acc); ok {
						code, _ := src.GenerateTOTP(t.Secret)
						copyToClipboard(code)
						fmt.Printf("Copied code for %s.\n", acc)
					}
				}
				return
			}

			account := args[0]
			entry, ok := vault.GetTOTPEntry(account)
			if !ok {
				fmt.Printf("TOTP account %s not found.\n", account)
				return
			}

			fmt.Printf("Monitoring TOTP for %s. Code copied to clipboard.\n", account)
			var lastCode string
			for {
				code, _ := src.GenerateTOTP(entry.Secret)
				if code != lastCode {
					copyToClipboard(code)
					lastCode = code
				}
				remaining := src.TimeRemaining()
				fmt.Printf("\rCode: \x1b[1;32m%s\x1b[0m | Updating in %ds... ", code, remaining)
				time.Sleep(1 * time.Second)
			}
		},
	}

	var totpDeleteCmd = &cobra.Command{
		Use:   "delete <account>",
		Short: "Delete a TOTP account",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			account := args[0]

			masterPassword, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			fmt.Printf("To delete TOTP for '%s', please type the account name again: ", account)
			confirm := readInput()
			if confirm != account {
				fmt.Println("Account name does not match. Deletion cancelled.")
				return
			}

			if vault.DeleteTOTPEntry(account) {
				data, err := vault.Serialize(masterPassword)
				if err != nil {
					fmt.Printf("Error encrypting vault: %v\n", err)
					return
				}
				if err := src.SaveVault(vaultPath, data); err != nil {
					fmt.Printf("Error saving vault: %v\n", err)
					return
				}
				fmt.Printf("Deleted TOTP for %s.\n", account)
			} else {
				fmt.Printf("TOTP account %s not found.\n", account)
			}
		},
	}

	var totpEditCmd = &cobra.Command{
		Use:   "edit <account>",
		Short: "Edit a TOTP account",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			oldAccount := args[0]
			newAccount, _ := cmd.Flags().GetString("account")
			newSecret, _ := cmd.Flags().GetString("secret")

			masterPassword, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			entry, ok := vault.GetTOTPEntry(oldAccount)
			if !ok {
				fmt.Printf("TOTP account %s not found.\n", oldAccount)
				return
			}

			if newAccount != "" {
				entry.Account = newAccount
			}
			if newSecret != "" {
				entry.Secret = newSecret
			}

			vault.DeleteTOTPEntry(oldAccount)
			vault.AddTOTPEntry(entry.Account, entry.Secret)

			data, err := vault.Serialize(masterPassword)
			if err != nil {
				fmt.Printf("Error encrypting vault: %v\n", err)
				return
			}

			if err := src.SaveVault(vaultPath, data); err != nil {
				fmt.Printf("Error saving vault: %v\n", err)
				return
			}

			fmt.Printf("Updated TOTP for %s.\n", entry.Account)
		},
	}

	totpAddCmd.Flags().StringP("secret", "s", "", "TOTP Secret")
	totpAddCmd.Flags().StringP("account", "a", "", "Account name")
	totpEditCmd.Flags().StringP("secret", "s", "", "New TOTP Secret")
	totpEditCmd.Flags().StringP("account", "a", "", "New account name")

	totpShowCmd.Flags().StringP("company", "c", "", "Filter by company name")
	totpCmd.AddCommand(totpAddCmd, totpShowCmd, totpDeleteCmd, totpEditCmd)

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

			if importErr != nil && encryptPass == "" {

				fmt.Print("This file may be encrypted. Please enter the password to decrypt: ")
				var err error
				encryptPass, err = readPassword()
				fmt.Println()
				if err == nil && encryptPass != "" {
					switch ext {
					case "json":
						importErr = src.ImportFromJSON(vault, filename, encryptPass)
					case "csv":

					case "txt":
					}
				}
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
			if err := src.SaveVault(vaultPath, data); err != nil {
				fmt.Printf("Error saving vault: %v\n", err)
				return
			}

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
				if withoutPass {
					output = "export.txt"
				} else {
					output = "export.json"
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

	importCmd.Flags().StringP("encrypt-pass", "e", "", "Password for decryption (if the import file is encrypted)")
	exportCmd.Flags().StringP("output", "o", "", "Output filename")
	exportCmd.Flags().StringP("encrypt-pass", "e", "", "Password for encryption (to protect the exported JSON)")
	exportCmd.Flags().Bool("without-password", false, "Exclude passwords and secrets (generates .txt)")
	exportCmd.Flags().Bool("without_password", false, "Exclude passwords and secrets (alias)")

	getCmd.Flags().Bool("show_pass", false, "Show password instead of copying to clipboard")
	getCmd.Flags().Int("clear", 3, "Minutes to clear clipboard after copying")
	addCmd.Flags().StringP("account", "a", "", "Account name")
	addCmd.Flags().StringP("user", "u", "", "Username")
	addCmd.Flags().StringP("password", "p", "", "Password")
	getCmd.Flags().StringP("account", "a", "", "Account name")
	delCmd.Flags().StringP("account", "a", "", "Account name")
	listCmd.Flags().StringP("filter", "f", "", "Filter accounts by name or username")
	genCmd.Flags().IntP("length", "l", 16, "Password length")

	var historyCmd = &cobra.Command{
		Use:   "vhistory",
		Short: "View vault change history",
	}

	var historyListCmd = &cobra.Command{
		Use:   "list",
		Short: "List all vault changes",
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
			fmt.Printf("%-5s %-20s %-10s %-15s %-20s\n", "ID", "TIMESTAMP", "ACTION", "CATEGORY", "IDENTIFIER")
			fmt.Println(strings.Repeat("-", 75))
			for i, h := range vault.History {
				fmt.Printf("%-5d %-20s %-10s %-15s %-20s\n", i, h.Timestamp.Format("2006-01-02 15:04:05"), h.Action, h.Category, h.Identifier)
			}
		},
	}

	var historyShowCmd = &cobra.Command{
		Use:   "show <id>",
		Short: "Show details of a specific change",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			id := -1
			fmt.Sscanf(args[0], "%d", &id)
			_, vault, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}
			if id < 0 || id >= len(vault.History) {
				fmt.Printf("Invalid history ID: %d\n", id)
				return
			}
			h := vault.History[id]
			fmt.Printf("ID:         %d\n", id)
			fmt.Printf("Timestamp:  %s\n", h.Timestamp.Format("2006-01-02 15:04:05"))
			fmt.Printf("Action:     %s\n", h.Action)
			fmt.Printf("Category:   %s\n", h.Category)
			fmt.Printf("Identifier: %s\n", h.Identifier)
			if h.OldData != "" {
				fmt.Printf("Previous Value (encoded):\n%s\n", h.OldData)
			}
		},
	}

	historyCmd.AddCommand(historyListCmd, historyShowCmd)

	rootCmd.AddCommand(initCmd, addCmd, getCmd, delCmd, editCmd, listCmd, genCmd, modeCmd, totpCmd, importCmd, exportCmd, vswitchCmd, infoCmd, vsettingsCmd, historyCmd)
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

func src_unlockVault() (string, *src.Vault, error) {
	if !src.VaultExists(vaultPath) {
		return "", nil, fmt.Errorf("Vault does not exist. Run 'pm init' first.")
	}

	data, err := src.LoadVault(vaultPath)
	if err != nil {
		return "", nil, err
	}

	if len(data) < 16 {
		return "", nil, fmt.Errorf("Invalid vault file.")
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
