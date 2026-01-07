package main

import (
	"bufio"
	"crypto/rand"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
	"github.com/spf13/cobra"
	"golang.org/x/term"

	src "password-manager/src"
)

var vaultPath string
var inputReader *bufio.Reader

func init() {
	exe, err := os.Executable()
	if err != nil {
		color.Red("Error getting executable path: %v\n", err)
		os.Exit(1)
	}
	vaultPath = filepath.Join(filepath.Dir(exe), "vault.dat")
	inputReader = bufio.NewReader(os.Stdin)
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
				color.Red("Vault already exists.\n")
				return
			}

			var masterPassword string
			for {
				fmt.Print("Create Master Password: ")
				var err error
				masterPassword, err = readPassword()
				if err != nil {
					color.Red("\nError reading password: %v\n", err)
					return
				}
				fmt.Println()

				if err := src.ValidateMasterPassword(masterPassword); err != nil {
					color.Red("Invalid password: %v\n", err)
					continue
				}
				break
			}

			// Initial encryption (Salt is generated inside EncryptVault)
			vault := &src.Vault{} // Empty vault
			data, err := src.EncryptVault(vault, masterPassword)
			if err != nil {
				fmt.Printf("Error encrypting vault: %v\n", err)
				return
			}

			if err := src.SaveVault(vaultPath, data); err != nil {
				color.Red("Error saving vault: %v\n", err)
				return
			}

			color.Green("Vault initialized successfully.\n")
		},
	}

	var addCmd = &cobra.Command{
		Use:   "add",
		Short: "Add a new entry to the vault interactively",
		Run: func(cmd *cobra.Command, args []string) {
			masterPassword, vault, readonly, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}
			if readonly {
				color.Red("Vault is in READ-ONLY mode. Cannot add entries.")
				return
			}

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
					color.Red("Error: %v\n", err)
					return
				}
			case "2":
				fmt.Print("Account Name: ")
				acc := readInput()
				fmt.Print("Secret: ")
				sec := readInput()
				sec = strings.ReplaceAll(sec, " ", "")
				sec = strings.ToUpper(sec)
				if err := vault.AddTOTPEntry(acc, sec); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
			case "3":
				fmt.Print("Token Name: ")
				name := readInput()
				fmt.Print("Token: ")
				tok := readInput()
				fmt.Print("Type (e.g. GitHub): ")
				tType := readInput()
				if err := vault.AddToken(name, tok, tType); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
			case "4":
				fmt.Print("Note Name: ")
				name := readInput()
				fmt.Println("Content (end with empty line):")
				var contentLines []string
				for {
					line := readInput()
					if line == "" {
						break
					}
					contentLines = append(contentLines, line)
				}
				if err := vault.AddSecureNote(name, strings.Join(contentLines, "\n")); err != nil {
					color.Red("Error: %v\n", err)
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
					color.Red("Error: %v\n", err)
					return
				}
			case "6":
				fmt.Print("Key Label: ")
				name := readInput()
				fmt.Println("Enter Private Key (end with empty line):")
				var keyLines []string
				for {
					line := readInput()
					if line == "" {
						break
					}
					keyLines = append(keyLines, line)
				}
				if err := vault.AddSSHKey(name, strings.Join(keyLines, "\n")); err != nil {
					color.Red("Error: %v\n", err)
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
					color.Red("Error: %v\n", err)
					return
				}
			case "8":
				fmt.Print("Service: ")
				svc := readInput()
				fmt.Println("Enter Codes (one per line, end with empty line):")
				var codes []string
				for {
					line := readInput()
					if line == "" {
						break
					}
					codes = append(codes, line)
				}
				if err := vault.AddRecoveryCode(svc, codes); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
			default:
				color.Red("Invalid selection.\n")
				return
			}

			data, err := src.EncryptVault(vault, masterPassword)
			if err != nil {
				color.Red("Error encrypting vault: %v\n", err)
				return
			}
			if err := src.SaveVault(vaultPath, data); err != nil {
				color.Red("Error saving vault: %v\n", err)
			}
			color.Green("Entry saved.\n")
		},
	}

	var getCmd = &cobra.Command{
		Use:   "get [query]",
		Short: "Fuzzy search and retrieve an entry",
		Run: func(cmd *cobra.Command, args []string) {
			query := ""
			if len(args) > 0 {
				query = args[0]
			}

			showPass, _ := cmd.Flags().GetBool("show-pass")

			_, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			results := vault.SearchAll("")
			var scoredResults []ScoredResult

			for _, res := range results {
				score := rankMatch(query, res.Identifier)
				if score > 0 {
					scoredResults = append(scoredResults, ScoredResult{res, score})
				}
			}

			if len(scoredResults) == 0 {
				fmt.Println("No matching entries found.")
				return
			}

			// Sort by score desc, then identifier asc
			sort.Slice(scoredResults, func(i, j int) bool {
				if scoredResults[i].Score == scoredResults[j].Score {
					return scoredResults[i].Result.Identifier < scoredResults[j].Result.Identifier
				}
				return scoredResults[i].Score > scoredResults[j].Score
			})

			if len(scoredResults) == 1 && query != "" {
				displayEntry(scoredResults[0].Result, showPass)
				return
			}

			fmt.Println("Ranked Matches:")
			for i, sr := range scoredResults {
				fmt.Printf("[%d] %-20s (%s)\n", i+1, sr.Result.Identifier, sr.Result.Type)
			}
			fmt.Print("Select a number: ")
			choiceStr := readInput()
			choice, err := strconv.Atoi(choiceStr)
			if err != nil || choice < 1 || choice > len(scoredResults) {
				fmt.Println("Invalid selection.")
				return
			}
			fmt.Println()
			displayEntry(scoredResults[choice-1].Result, showPass)
		},
	}
	getCmd.Flags().Bool("show-pass", false, "Show password in output")

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

			masterPassword, vault, readonly, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}
			if readonly {
				color.Red("Vault is READ-ONLY. Cannot delete entries.")
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
				data, err := src.EncryptVault(vault, masterPassword)
				if err != nil {
					fmt.Printf("Error encrypting vault: %v\n", err)
					return
				}
				src.SaveVault(vaultPath, data)
				color.Green("Deleted '%s'.\n", name)
			} else {
				color.Red("Entry '%s' not found.\n", name)
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

			masterPassword, vault, readonly, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}
			if readonly {
				color.Red("Vault is READ-ONLY. Cannot edit entries.")
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
				fmt.Print("New Password (blank to keep): ")
				newPass, _ := readPassword()
				fmt.Println()
				if newPass == "" {
					newPass = e.Password
				}
				vault.DeleteEntry(e.Account)
				vault.AddEntry(newAcc, newUser, newPass)
				updated = true
			} else if t, ok := vault.GetTOTPEntry(name); ok {
				fmt.Printf("Editing TOTP: %s\n", name)
				fmt.Printf("New Secret (blank to keep): ")
				s := readInput()
				if s == "" {
					s = t.Secret
				}
				vault.DeleteTOTPEntry(t.Account)
				vault.AddTOTPEntry(t.Account, s)
				updated = true
			} else {
				color.Red("Edit not fully supported for this type in this version, or entry not found.\n")
				return
			}

			if updated {
				data, err := src.EncryptVault(vault, masterPassword)
				if err != nil {
					fmt.Printf("Save error: %v\n", err)
					return
				}
				src.SaveVault(vaultPath, data)
				color.Green("Update successful.")
			}
		},
	}

	var unlockCmd = &cobra.Command{
		Use:   "unlock <mins>",
		Short: "Unlock the vault for a set time (RW mode)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			mins := 0
			_, err := fmt.Sscanf(args[0], "%d", &mins)
			if err != nil || mins <= 0 {
				fmt.Println("Please provide a valid number of minutes.")
				return
			}

			fmt.Println("Confirming access for RW mode...")
			masterPassword, _, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			duration := time.Duration(mins) * time.Minute
			if err := src.CreateSession(masterPassword, duration, false); err != nil {
				fmt.Printf("Error creating session: %v\n", err)
				return
			}

			fmt.Printf("Vault unlocked for %d minutes (RW).\n", mins)
		},
	}

	var readonlyCmd = &cobra.Command{
		Use:   "readonly <mins>",
		Short: "Unlock the vault in READ-ONLY mode",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			mins := 0
			_, err := fmt.Sscanf(args[0], "%d", &mins)
			if err != nil || mins <= 0 {
				fmt.Println("Please provide a valid number of minutes.")
				return
			}

			fmt.Println("Confirming access for READ-ONLY mode...")
			masterPassword, _, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			duration := time.Duration(mins) * time.Minute
			if err := src.CreateSession(masterPassword, duration, true); err != nil {
				fmt.Printf("Error creating session: %v\n", err)
				return
			}

			fmt.Printf("Vault unlocked for %d minutes (READ-ONLY).\n", mins)
		},
	}

	var lockCmd = &cobra.Command{
		Use:   "lock",
		Short: "Immediately lock the vault",
		Run: func(cmd *cobra.Command, args []string) {
			src.KillSession()
			fmt.Println("Vault locked.")
		},
	}

	var cinfoCmd = &cobra.Command{
		Use:   "cinfo",
		Short: "Show cryptographic parameters",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("APM Crypto Configuration")
			fmt.Println("========================")
			fmt.Println("KDF:       Argon2id")
			fmt.Printf("  Time:    %d\n", src.ArgonTime)
			fmt.Printf("  Memory:  %d KB\n", src.ArgonMemory)
			fmt.Printf("  Threads: %d\n", src.ArgonParallelism)
			fmt.Println("Cipher:    AES-256-GCM")
			fmt.Println("Integrity: HMAC-SHA256 (Encrypt-then-MAC)")
			fmt.Println("Format:    APMVAULT v1")
		},
	}

	var scanCmd = &cobra.Command{
		Use:   "scan",
		Short: "Offline password health check",
		Run: func(cmd *cobra.Command, args []string) {
			_, vault, _, err := src_unlockVault()
			if err != nil {
				return
			}

			fmt.Println("Scanning Vault Health...")
			fmt.Println("------------------------")

			weakCount := 0
			reuseMap := make(map[string][]string)

			for _, e := range vault.Entries {
				score := 0
				if len(e.Password) >= 12 {
					score += 20
				}
				if strings.ContainsAny(e.Password, "ABCDEFGHIJKLMNOPQRSTUVWXYZ") && strings.ContainsAny(e.Password, "abcdefghijklmnopqrstuvwxyz") {
					score += 10
				}
				if strings.ContainsAny(e.Password, "0123456789") {
					score += 10
				}
				if strings.ContainsAny(e.Password, "!@#$%^&*()-_=+") {
					score += 15
				}

				if score < 40 {
					fmt.Printf("[WEAK] %s: Score %d/55\n", e.Account, score)
					weakCount++
				}
				reuseMap[e.Password] = append(reuseMap[e.Password], e.Account)
			}

			reusedCount := 0
			for _, accs := range reuseMap {
				if len(accs) > 1 {
					fmt.Printf("[REUSE] Password reused on: %s\n", strings.Join(accs, ", "))
					reusedCount++
				}
			}

			if weakCount == 0 && reusedCount == 0 {
				color.Green("All clear! No weak or reused passwords found.")
			} else {
				fmt.Printf("\nFound %d weak passwords and %d reused groups.\n", weakCount, reusedCount)
			}
		},
	}

	var auditCmd = &cobra.Command{
		Use:   "audit",
		Short: "View secure access logs",
		Run: func(cmd *cobra.Command, args []string) {
			_, vault, _, err := src_unlockVault()
			if err != nil {
				return
			}
			if len(vault.History) == 0 {
				fmt.Println("No audit logs found.")
				return
			}
			fmt.Println("Timestamp           Action  Category      Identifier")
			fmt.Println("----------------------------------------------------")
			for _, h := range vault.History {
				fmt.Printf("%s %-7s %-12s %s\n", h.Timestamp.Format("2006-01-02 15:04"), h.Action, h.Category, h.Identifier)
			}
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
	genCmd.Flags().IntP("length", "l", 16, "Password length")

	var compromiseCmd = &cobra.Command{
		Use:   "compromise",
		Short: "EMERGENCY: Permanently delete the vault",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Print("WARNING: PERMANENTLY DELETE VAULT? Type 'DESTROY': ")
			if readInput() != "DESTROY" {
				return
			}
			if src.VaultExists(vaultPath) {
				f, _ := os.OpenFile(vaultPath, os.O_WRONLY, 0)
				info, _ := f.Stat()
				data := make([]byte, info.Size())
				rand.Read(data)
				f.Write(data)
				f.Close()
				os.Remove(vaultPath)
				color.Green("Vault nuked.")
			}
			src.KillSession()
		},
	}

	// --- Restored Commands ---

	var totpCmd = &cobra.Command{
		Use:   "totp",
		Short: "Manage TOTP accounts",
	}

	var totpShowCmd = &cobra.Command{
		Use:   "show [account]",
		Short: "Show TOTP code(s) with live updates",
		Run: func(cmd *cobra.Command, args []string) {
			company, _ := cmd.Flags().GetString("company")
			_, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}
			// Search targets
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
				remaining := 30 - (time.Now().Unix() % 30)
				fmt.Printf("\r\x1b[KUpdating in %ds... [", remaining)
				// Bar
				for i := 0; i < 30; i++ {
					if i < int(remaining) {
						fmt.Print("=")
					} else {
						fmt.Print(" ")
					}
				}
				fmt.Println("]")

				for _, entry := range targets {
					code, err := src.GenerateTOTP(entry.Secret)
					if err != nil {
						fmt.Printf("\r\x1b[K  %-20s : INVALID\n", entry.Account)
					} else {
						fmt.Printf("\r\x1b[K  %-20s : \x1b[1;32m%s\x1b[0m\n", entry.Account, code)
					}
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

			masterPassword, vault, readonly, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}
			if readonly {
				color.Red("Vault is READ-ONLY. Cannot import data.")
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

			data, err := src.EncryptVault(vault, masterPassword)
			if err != nil {
				fmt.Printf("Error encrypting vault: %v\n", err)
				return
			}
			src.SaveVault(vaultPath, data)
			color.Green("Successfully imported data from %s.\n", filename)
		},
	}
	importCmd.Flags().StringP("encrypt-pass", "e", "", "Password for decryption")

	var exportCmd = &cobra.Command{
		Use:   "export",
		Short: "Export vault data safely",
		Run: func(cmd *cobra.Command, args []string) {
			withoutPass, _ := cmd.Flags().GetBool("without-password")
			output, _ := cmd.Flags().GetString("output")
			encryptPass, _ := cmd.Flags().GetString("encrypt-pass")

			_, vault, _, err := src_unlockVault()
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

			color.Green("Successfully exported vault data to %s.\n", output)
		},
	}
	exportCmd.Flags().StringP("output", "o", "", "Output filename")
	exportCmd.Flags().StringP("encrypt-pass", "e", "", "Password for encryption")
	exportCmd.Flags().Bool("without-password", false, "Exclude secrets")

	var modeCmd = &cobra.Command{Use: "mode", Short: "Manage modes"}
	modeCmd.AddCommand(unlockCmd, readonlyCmd, lockCmd, compromiseCmd)

	rootCmd.AddCommand(initCmd, addCmd, getCmd, delCmd, editCmd, genCmd, modeCmd, cinfoCmd, scanCmd, auditCmd, unlockCmd, readonlyCmd, lockCmd, totpCmd, importCmd, exportCmd)
	rootCmd.Execute()
}

func readInput() string {
	input, _ := inputReader.ReadString('\n')
	return strings.TrimSpace(input)
}

func readPassword() (string, error) {
	bytePassword, err := term.ReadPassword(int(syscall.Stdin))
	if err != nil {
		return "", err
	}
	return strings.TrimSpace(string(bytePassword)), nil
}

func copyToClipboardWithExpiry(text string) {
	if text == "" {
		return
	}
	copyToClipboard(text)
	color.Green("Copied to clipboard.")
	color.Yellow("Warning: Clipboard will auto-clear in 20 seconds.")
	go func() {
		time.Sleep(20 * time.Second)
		copyToClipboard("")
	}()
}

func copyToClipboard(text string) {
	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("powershell", "Set-Clipboard", "-Value", fmt.Sprintf("'%s'", strings.ReplaceAll(text, "'", "''")))
	} else if runtime.GOOS == "darwin" {
		cmd = exec.Command("pbcopy")
		cmd.Stdin = strings.NewReader(text)
	} else {
		cmd = exec.Command("xclip", "-selection", "clipboard")
		cmd.Stdin = strings.NewReader(text)
	}
	cmd.Run()
}

func src_unlockVault() (string, *src.Vault, bool, error) {
	if !src.VaultExists(vaultPath) {
		return "", nil, false, fmt.Errorf("Vault not found. Run 'pm init'.")
	}

	if session, err := src.GetSession(); err == nil {
		data, err := src.LoadVault(vaultPath)
		if err == nil {
			vault, err := src.DecryptVault(data, session.MasterPassword)
			if err == nil {
				return session.MasterPassword, vault, session.ReadOnly, nil
			}
		}
		src.KillSession()
	}

	data, err := src.LoadVault(vaultPath)
	if err != nil {
		return "", nil, false, err
	}

	for i := 0; i < 3; i++ {
		fmt.Printf("Master Password (attempt %d/3): ", i+1)
		pass, _ := readPassword()
		fmt.Println()

		vault, err := src.DecryptVault(data, pass)
		if err == nil {
			return pass, vault, false, nil
		}
		fmt.Printf("Error: %v\n", err)
	}

	return "", nil, false, fmt.Errorf("too many failed attempts")
}

type ScoredResult struct {
	Result src.SearchResult
	Score  int
}

func rankMatch(query, target string) int {
	if query == "" {
		return 1
	}
	q := strings.ToLower(query)
	t := strings.ToLower(target)

	if q == t {
		return 100
	}
	if strings.HasPrefix(t, q) {
		return 50
	}
	if strings.Contains(t, q) {
		return 10
	}

	qi := 0
	ti := 0
	matches := 0
	for qi < len(q) && ti < len(t) {
		if q[qi] == t[ti] {
			matches++
			qi++
		}
		ti++
	}
	if matches == len(q) {
		return 5
	}

	return 0
}

func displayEntry(res src.SearchResult, showPass bool) {
	fmt.Println("---")
	switch res.Type {
	case "Password":
		e := res.Data.(src.Entry)
		fmt.Printf("Type: Password\nAccount: %s\nUser: %s\n", e.Account, e.Username)
		if showPass {
			fmt.Printf("Password: %s\n", e.Password)
		}
		copyToClipboardWithExpiry(e.Password)
	case "TOTP":
		t := res.Data.(src.TOTPEntry)
		code, err := src.GenerateTOTP(t.Secret)
		if err != nil {
			code = "INVALID SECRET"
		}
		fmt.Printf("Type: TOTP\nAccount: %s\nCode: %s\n", t.Account, code)
	case "Token":
		tok := res.Data.(src.TokenEntry)
		fmt.Printf("Type: Token\nName: %s\n", tok.Name)
		if showPass {
			fmt.Printf("Token: %s\n", tok.Token)
		}
		copyToClipboardWithExpiry(tok.Token)
	case "Note":
		n := res.Data.(src.SecureNoteEntry)
		fmt.Printf("Type: Note\nName: %s\nContent:\n%s\n", n.Name, n.Content)
	case "API Key":
		k := res.Data.(src.APIKeyEntry)
		fmt.Printf("Type: API Key\nLabel: %s\nService: %s\n", k.Name, k.Service)
		if showPass {
			fmt.Printf("Key: %s\n", k.Key)
		}
		copyToClipboardWithExpiry(k.Key)
	case "SSH Key":
		s := res.Data.(src.SSHKeyEntry)
		fmt.Printf("Type: SSH Key\nLabel: %s\n", s.Name)
		if showPass {
			fmt.Printf("Private Key:\n%s\n", s.PrivateKey)
		}
		copyToClipboardWithExpiry(s.PrivateKey)
	case "Wi-Fi":
		w := res.Data.(src.WiFiEntry)
		fmt.Printf("Type: Wi-Fi\nSSID: %s\nSecurity: %s\n", w.SSID, w.SecurityType)
		if showPass {
			fmt.Printf("Password: %s\n", w.Password)
		}
		copyToClipboardWithExpiry(w.Password)
	case "Recovery Codes":
		r := res.Data.(src.RecoveryCodeEntry)
		fmt.Printf("Type: Recovery\nService: %s\nCodes: %v\n", r.Service, r.Codes)
	}
	fmt.Println("---")
}
