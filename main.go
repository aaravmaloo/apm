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

	"context"
	src "password-manager/src"

	"github.com/fatih/color"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	"golang.org/x/term"
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

			vault := &src.Vault{}
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
			fmt.Println("9. Certificate (SSL/SSH)")
			fmt.Println("10. Banking/Finance Item")
			fmt.Println("11. Encrypted Document (PDF)")
			fmt.Print("Selection (1-11): ")
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
			case "9":
				fmt.Print("Label: ")
				label := readInput()
				fmt.Print("Issuer: ")
				issuer := readInput()
				fmt.Print("Expiry Date (YYYY-MM-DD): ")
				expiryStr := readInput()
				expiry, err := time.Parse("2006-01-02", expiryStr)
				if err != nil {
					color.Red("Invalid date format. Use YYYY-MM-DD.\n")
					return
				}
				fmt.Println("Enter Certificate Data (end with empty line):")
				var certLines []string
				for {
					line := readInput()
					if line == "" {
						break
					}
					certLines = append(certLines, line)
				}
				fmt.Println("Enter Private Key (end with empty line, blank if none):")
				var keyLines []string
				for {
					line := readInput()
					if line == "" {
						break
					}
					keyLines = append(keyLines, line)
				}
				if err := vault.AddCertificate(label, strings.Join(certLines, "\n"), strings.Join(keyLines, "\n"), issuer, expiry); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
			case "10":
				fmt.Print("Label: ")
				label := readInput()
				fmt.Print("Type (Card/IBAN/SWIFT): ")
				bType := readInput()
				fmt.Print("Details (Number/IBAN): ")
				details := readInput()
				fmt.Print("CVV (blank if none): ")
				cvv := readInput()
				fmt.Print("Expiry (MM/YY, blank if none): ")
				exp := readInput()
				if err := vault.AddBankingItem(label, bType, details, cvv, exp); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
			case "11":
				fmt.Print("Document Name: ")
				name := readInput()
				fmt.Print("Path to PDF: ")
				path := readInput()
				content, err := os.ReadFile(path)
				if err != nil {
					color.Red("Error reading file: %v\n", err)
					return
				}
				fmt.Print("Create a password for this document: ")
				docPass, _ := readPassword()
				fmt.Println()
				if err := vault.AddDocument(name, filepath.Base(path), content, docPass); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
				color.HiYellow("Document stored successfully and safely. Please delete the original file: %s\n", path)
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
			showPass, _ := cmd.Flags().GetBool("show-pass")

			_, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			if len(args) == 0 {
				fmt.Println("Select type to retrieve:")
				fmt.Println("1. Password")
				fmt.Println("2. TOTP")
				fmt.Println("3. Token")
				fmt.Println("4. Secure Note")
				fmt.Println("5. API Key")
				fmt.Println("6. SSH Key")
				fmt.Println("7. Wi-Fi Credentials")
				fmt.Println("8. Recovery Codes")
				fmt.Println("9. Certificate")
				fmt.Println("10. Banking Item")
				fmt.Println("11. Document")
				fmt.Print("Selection (1-11): ")
				choice := readInput()

				var results []src.SearchResult
				var category string
				switch choice {
				case "1":
					category = "Password"
					for _, e := range vault.Entries {
						results = append(results, src.SearchResult{Type: "Password", Identifier: e.Account, Data: e})
					}
				case "2":
					category = "TOTP"
					for _, e := range vault.TOTPEntries {
						results = append(results, src.SearchResult{Type: "TOTP", Identifier: e.Account, Data: e})
					}
				case "3":
					category = "Token"
					for _, e := range vault.Tokens {
						results = append(results, src.SearchResult{Type: "Token", Identifier: e.Name, Data: e})
					}
				case "4":
					category = "Note"
					for _, e := range vault.SecureNotes {
						results = append(results, src.SearchResult{Type: "Note", Identifier: e.Name, Data: e})
					}
				case "5":
					category = "API Key"
					for _, e := range vault.APIKeys {
						results = append(results, src.SearchResult{Type: "API Key", Identifier: e.Name, Data: e})
					}
				case "6":
					category = "SSH Key"
					for _, e := range vault.SSHKeys {
						results = append(results, src.SearchResult{Type: "SSH Key", Identifier: e.Name, Data: e})
					}
				case "7":
					category = "Wi-Fi"
					for _, e := range vault.WiFiCredentials {
						results = append(results, src.SearchResult{Type: "Wi-Fi", Identifier: e.SSID, Data: e})
					}
				case "8":
					category = "Recovery Codes"
					for _, e := range vault.RecoveryCodeItems {
						results = append(results, src.SearchResult{Type: "Recovery Codes", Identifier: e.Service, Data: e})
					}
				case "9":
					category = "Certificate"
					for _, e := range vault.Certificates {
						results = append(results, src.SearchResult{Type: "Certificate", Identifier: e.Label, Data: e})
					}
				case "10":
					category = "Banking"
					for _, e := range vault.BankingItems {
						results = append(results, src.SearchResult{Type: "Banking", Identifier: e.Label, Data: e})
					}
				case "11":
					category = "Document"
					for _, e := range vault.Documents {
						results = append(results, src.SearchResult{Type: "Document", Identifier: e.Name, Data: e})
					}
				default:
					color.Red("Invalid selection.\n")
					return
				}

				if len(results) == 0 {
					color.Yellow("No entries found for %s.\n", category)
					return
				}

				sort.Slice(results, func(i, j int) bool {
					return results[i].Identifier < results[j].Identifier
				})

				fmt.Printf("\nExisting %s entries:\n", category)
				for i, res := range results {
					fmt.Printf("[%d] %s\n", i+1, res.Identifier)
				}
				fmt.Print("Select a number: ")
				choiceStr := readInput()
				choiceIdx, err := strconv.Atoi(choiceStr)
				if err != nil || choiceIdx < 1 || choiceIdx > len(results) {
					fmt.Println("Invalid selection.")
					return
				}
				fmt.Println()
				displayEntry(results[choiceIdx-1], showPass)
				return
			}

			query := args[0]
			allResults := vault.SearchAll("")
			var scoredResults []ScoredResult

			for _, res := range allResults {
				score := rankMatch(query, res.Identifier)
				if score > 0 {
					scoredResults = append(scoredResults, ScoredResult{res, score})
				}
			}

			if len(scoredResults) == 0 {
				fmt.Println("No matching entries found.")
				return
			}

			sort.Slice(scoredResults, func(i, j int) bool {
				if scoredResults[i].Score == scoredResults[j].Score {
					return scoredResults[i].Result.Identifier < scoredResults[j].Result.Identifier
				}
				return scoredResults[i].Score > scoredResults[j].Score
			})

			if len(scoredResults) == 1 {
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
			} else if vault.DeleteCertificate(name) {
				deleted = true
			} else if vault.DeleteBankingItem(name) {
				deleted = true
			} else if vault.DeleteDocument(name) {
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
		Short: "Edit an existing entry interactively",
		Run: func(cmd *cobra.Command, args []string) {
			masterPassword, vault, readonly, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}
			if readonly {
				color.Red("Vault is READ-ONLY. Cannot edit entries.")
				return
			}

			fmt.Println("Select type to edit:")
			fmt.Println("1. Password")
			fmt.Println("2. TOTP")
			fmt.Println("3. Token")
			fmt.Println("4. Secure Note")
			fmt.Println("5. API Key")
			fmt.Println("6. SSH Key")
			fmt.Println("7. Wi-Fi Credentials")
			fmt.Println("8. Recovery Codes")
			fmt.Print("Selection (1-8): ")
			choice := readInput()

			identifier := ""
			if len(args) > 0 {
				identifier = args[0]
			} else {
				fmt.Print("Enter Name/Account to edit: ")
				identifier = readInput()
			}

			updated := false
			switch choice {
			case "1":
				if e, ok := vault.GetEntry(identifier); ok {
					fmt.Printf("Editing Password: %s\n", identifier)
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
				}
			case "2":
				if e, ok := vault.GetTOTPEntry(identifier); ok {
					fmt.Printf("Editing TOTP: %s\n", identifier)
					fmt.Printf("New Account [%s]: ", e.Account)
					newAcc := readInput()
					if newAcc == "" {
						newAcc = e.Account
					}
					fmt.Printf("New Secret [%s]: ", e.Secret)
					newSec := readInput()
					if newSec == "" {
						newSec = e.Secret
					}
					vault.DeleteTOTPEntry(e.Account)
					vault.AddTOTPEntry(newAcc, newSec)
					updated = true
				}
			case "3":
				if e, ok := vault.GetToken(identifier); ok {
					fmt.Printf("Editing Token: %s\n", identifier)
					fmt.Printf("New Name [%s]: ", e.Name)
					newName := readInput()
					if newName == "" {
						newName = e.Name
					}
					fmt.Printf("New Token [%s]: ", e.Token)
					newTok := readInput()
					if newTok == "" {
						newTok = e.Token
					}
					fmt.Printf("New Type [%s]: ", e.Type)
					newType := readInput()
					if newType == "" {
						newType = e.Type
					}
					vault.DeleteToken(e.Name)
					vault.AddToken(newName, newTok, newType)
					updated = true
				}
			case "4":
				if e, ok := vault.GetSecureNote(identifier); ok {
					fmt.Printf("Editing Note: %s\n", identifier)
					fmt.Printf("New Name [%s]: ", e.Name)
					newName := readInput()
					if newName == "" {
						newName = e.Name
					}
					fmt.Println("New Content (end with empty line, blank to keep current):")
					var contentLines []string
					for {
						line := readInput()
						if line == "" {
							break
						}
						contentLines = append(contentLines, line)
					}
					newContent := strings.Join(contentLines, "\n")
					if newContent == "" {
						newContent = e.Content
					}
					vault.DeleteSecureNote(e.Name)
					vault.AddSecureNote(newName, newContent)
					updated = true
				}
			case "5":
				if e, ok := vault.GetAPIKey(identifier); ok {
					fmt.Printf("Editing API Key: %s\n", identifier)
					fmt.Printf("New Label [%s]: ", e.Name)
					newName := readInput()
					if newName == "" {
						newName = e.Name
					}
					fmt.Printf("New Service [%s]: ", e.Service)
					newSvc := readInput()
					if newSvc == "" {
						newSvc = e.Service
					}
					fmt.Printf("New Key [%s]: ", e.Key)
					newKey := readInput()
					if newKey == "" {
						newKey = e.Key
					}
					vault.DeleteAPIKey(e.Name)
					vault.AddAPIKey(newName, newSvc, newKey)
					updated = true
				}
			case "6":
				if e, ok := vault.GetSSHKey(identifier); ok {
					fmt.Printf("Editing SSH Key: %s\n", identifier)
					fmt.Printf("New Label [%s]: ", e.Name)
					newName := readInput()
					if newName == "" {
						newName = e.Name
					}
					fmt.Println("Enter New Private Key (end with empty line, blank to keep current):")
					var keyLines []string
					for {
						line := readInput()
						if line == "" {
							break
						}
						keyLines = append(keyLines, line)
					}
					newKey := strings.Join(keyLines, "\n")
					if newKey == "" {
						newKey = e.PrivateKey
					}
					vault.DeleteSSHKey(e.Name)
					vault.AddSSHKey(newName, newKey)
					updated = true
				}
			case "7":
				if e, ok := vault.GetWiFi(identifier); ok {
					fmt.Printf("Editing Wi-Fi: %s\n", identifier)
					fmt.Printf("New SSID [%s]: ", e.SSID)
					newSSID := readInput()
					if newSSID == "" {
						newSSID = e.SSID
					}
					fmt.Printf("New Password [%s]: ", e.Password)
					newPass := readInput()
					if newPass == "" {
						newPass = e.Password
					}
					fmt.Printf("New Security [%s]: ", e.SecurityType)
					newSec := readInput()
					if newSec == "" {
						newSec = e.SecurityType
					}
					vault.DeleteWiFi(e.SSID)
					vault.AddWiFi(newSSID, newPass, newSec)
					updated = true
				}
			case "8":
				if e, ok := vault.GetRecoveryCode(identifier); ok {
					fmt.Printf("Editing Recovery Codes: %s\n", identifier)
					fmt.Printf("New Service [%s]: ", e.Service)
					newSvc := readInput()
					if newSvc == "" {
						newSvc = e.Service
					}
					fmt.Println("Enter New Codes (one per line, end with empty line, blank to keep current):")
					var codes []string
					for {
						line := readInput()
						if line == "" {
							break
						}
						codes = append(codes, line)
					}
					newCodes := codes
					if len(newCodes) == 0 {
						newCodes = e.Codes
					}
					vault.DeleteRecoveryCode(e.Service)
					vault.AddRecoveryCode(newSvc, newCodes)
					updated = true
				}
			case "9":
				if e, ok := vault.GetCertificate(identifier); ok {
					fmt.Printf("Editing Certificate: %s\n", identifier)
					fmt.Printf("New Label [%s]: ", e.Label)
					newLabel := readInput()
					if newLabel == "" {
						newLabel = e.Label
					}
					fmt.Printf("New Issuer [%s]: ", e.Issuer)
					newIssuer := readInput()
					if newIssuer == "" {
						newIssuer = e.Issuer
					}
					fmt.Printf("New Expiry [%s]: ", e.Expiry.Format("2006-01-02"))
					newExpiryStr := readInput()
					newExpiry := e.Expiry
					if newExpiryStr != "" {
						newExpiry, _ = time.Parse("2006-01-02", newExpiryStr)
					}
					vault.DeleteCertificate(e.Label)
					vault.AddCertificate(newLabel, e.CertData, e.PrivateKey, newIssuer, newExpiry)
					updated = true
				}
			case "10":
				if e, ok := vault.GetBankingItem(identifier); ok {
					fmt.Printf("Editing Banking: %s\n", identifier)
					fmt.Printf("New Label [%s]: ", e.Label)
					newLabel := readInput()
					if newLabel == "" {
						newLabel = e.Label
					}
					fmt.Printf("New Details [%s]: ", e.Details)
					newDetails := readInput()
					if newDetails == "" {
						newDetails = e.Details
					}
					vault.DeleteBankingItem(e.Label)
					vault.AddBankingItem(newLabel, e.Type, newDetails, e.CVV, e.Expiry)
					updated = true
				}
			case "11":
				if e, ok := vault.GetDocument(identifier); ok {
					fmt.Printf("Editing Document Metadata: %s\n", identifier)
					fmt.Printf("New Name [%s]: ", e.Name)
					newName := readInput()
					if newName == "" {
						newName = e.Name
					}
					vault.DeleteDocument(e.Name)
					vault.AddDocument(newName, e.FileName, e.Content, e.Password)
					updated = true
				}
			}

			if !updated {
				color.Red("Entry not found or selection invalid.\n")
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
			color.Green("Entry updated successfully.\n")
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

	var infoCmd = &cobra.Command{
		Use:   "info",
		Short: "Show information about your current version of APM",
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

			fmt.Println("APM Stable v7")
			fmt.Println(processedHomeName, "@apm")
			fmt.Printf("Installed: %s\n", installDir)
			fmt.Printf("Vault Path: %s\n", vaultPath)
			fmt.Println("https://github.com/aaravmaloo/apm")
			fmt.Println("Contact: aaravmaloo06@gmail.com")
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
			_, vault, _, err := src_unlockVault()
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

			fmt.Println("\x1b[?25lPress Ctrl+C to stop.")
			defer fmt.Print("\x1b[?25h")
			for {
				remaining := 30 - (time.Now().Unix() % 30)
				fmt.Printf("\r\x1b[KUpdating in %ds... [", remaining)

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

	var cloudCmd = &cobra.Command{
		Use:   "cloud",
		Short: "Sync and retrieve vaults from Google Drive",
	}

	var cloudInitCmd = &cobra.Command{
		Use:   "init",
		Short: "Setup cloud sync and generate retrieval key",
		Run: func(cmd *cobra.Command, args []string) {
			masterPassword, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			if vault.RetrievalKey != "" {
				color.Yellow("Cloud sync already initialized. Key: %s\n", vault.RetrievalKey)
				return
			}

			color.Cyan("\n--- Cloud Setup Tips ---")
			fmt.Println("1. Use a retrieval key that is easy for you to remember but impossible for others to guess.")
			fmt.Println("2. Something personal like 'MyOldLibraryID-2024' or a unique passphrase is good.")
			fmt.Println("3. LEAVE BLANK to generate a random secure ID (recommended for maximum security). \n")

			fmt.Print("Enter custom Retrieval Key (or ENTER for random): ")
			customKey := readInput()

			cm, err := getCloudManager(context.Background(), vault, masterPassword)
			if err != nil {
				color.Red("Cloud Error: %v\n", err)
				return
			}

			fileID, err := cm.UploadVault(vaultPath)
			if err != nil {
				color.Red("Upload failed: %v\n", err)
				return
			}

			actualKey := fileID
			if customKey != "" {
				actualKey = customKey
			}

			vault.RetrievalKey = actualKey
			vault.CloudFileID = fileID

			data, _ := src.EncryptVault(vault, masterPassword)
			src.SaveVault(vaultPath, data)

			color.Green("Cloud sync initialized!")
			color.HiCyan("Retrieval Key: %s\n", actualKey)
			color.Yellow("Keep this key safe! It's required to pull your vault on other devices.")
		},
	}

	var cloudSyncCmd = &cobra.Command{
		Use:   "sync",
		Short: "Manually sync current vault to cloud",
		Run: func(cmd *cobra.Command, args []string) {
			masterPassword, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			if vault.RetrievalKey == "" {
				color.Red("Cloud sync not initialized. Run 'pm cloud init'.")
				return
			}

			cm, err := getCloudManager(context.Background(), vault, masterPassword)
			if err != nil {
				color.Red("Cloud Error: %v\n", err)
				return
			}

			targetFileID := vault.CloudFileID
			if targetFileID == "" {
				targetFileID = vault.RetrievalKey
			}

			err = cm.SyncVault(vaultPath, targetFileID)
			if err != nil {
				color.Red("Sync failed: %v\n", err)
				return
			}
			color.Green("Vault synced to cloud.")
		},
	}

	var cloudAutoSyncCmd = &cobra.Command{
		Use:   "auto-sync",
		Short: "Start background auto-sync watcher",
		Run: func(cmd *cobra.Command, args []string) {
			enabled, _ := cmd.Flags().GetBool("true")
			if !enabled {
				fmt.Println("Usage: pm cloud auto-sync --true")
				return
			}

			masterPassword, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			if vault.RetrievalKey == "" {
				color.Red("Cloud sync not initialized.")
				return
			}

			key := vault.RetrievalKey
			cm, err := getCloudManager(context.Background(), vault, masterPassword)
			if err != nil {
				color.Red("Cloud Error: %v\n", err)
				return
			}

			watcher, err := fsnotify.NewWatcher()
			if err != nil {
				fmt.Println(err)
				return
			}
			defer watcher.Close()

			done := make(chan bool)
			go func() {
				lastSync := time.Now()
				for {
					select {
					case event, ok := <-watcher.Events:
						if !ok {
							return
						}
						if event.Op&fsnotify.Write == fsnotify.Write {
							if time.Since(lastSync) > 5*time.Second {
								fmt.Printf("[%s] Change detected, syncing...\n", time.Now().Format("15:04:05"))
								targetFileID := vault.CloudFileID
								if targetFileID == "" {
									targetFileID = key
								}
								err := cm.SyncVault(vaultPath, targetFileID)
								if err != nil {
									color.Red("Auto-sync failed: %v\n", err)
								} else {
									color.Green("Auto-sync successful.")
									lastSync = time.Now()
								}
							}
						}
					case err, ok := <-watcher.Errors:
						if !ok {
							return
						}
						fmt.Println("error:", err)
					}
				}
			}()

			err = watcher.Add(vaultPath)
			if err != nil {
				fmt.Println(err)
				return
			}
			color.Cyan("Auto-sync watcher started for %s. Press Ctrl+C to stop.", vaultPath)
			<-done
		},
	}
	cloudAutoSyncCmd.Flags().Bool("true", false, "Enable auto-sync")

	var cloudGetCmd = &cobra.Command{
		Use:   "get [retrieval_key]",
		Short: "Download vault from cloud",
		Run: func(cmd *cobra.Command, args []string) {
			var key string
			if len(args) > 0 {
				key = args[0]
			} else {
				fmt.Print("Enter Retrieval Key: ")
				key = readInput()
			}

			data, err := src.DownloadPublicVault(key)
			if err != nil {
				color.Red("Download failed: %v\n", err)
				color.Yellow("Note: Only uploader needs credentials.json. For public retrieval, ensure the key is correct.")
				return
			}

			fmt.Print("Verify Master Password for downloaded vault: ")
			pass, _ := readPassword()
			fmt.Println()
			_, err = src.DecryptVault(data, pass, 1)
			if err != nil {
				color.Red("Decryption failed. Vault not saved locally: %v\n", err)
				return
			}

			err = src.SaveVault(vaultPath, data)
			if err != nil {
				color.Red("Error saving vault: %v\n", err)
				return
			}
			color.Green("Vault retrieved and saved successfully.")
		},
	}

	var cloudDeleteCmd = &cobra.Command{
		Use:   "delete",
		Short: "Permanently delete vault from cloud",
		Run: func(cmd *cobra.Command, args []string) {
			masterPassword, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			if vault.RetrievalKey == "" {
				color.Red("Cloud sync not initialized.")
				return
			}

			fmt.Printf("ARE YOU SURE? This will delete the vault '%s' from Drive. (y/n): ", vault.RetrievalKey)
			if strings.ToLower(readInput()) != "y" {
				return
			}

			cm, err := getCloudManager(context.Background(), vault, masterPassword)
			if err != nil {
				color.Red("Cloud Error: %v\n", err)
				return
			}

			targetFileID := vault.CloudFileID
			if targetFileID == "" {
				targetFileID = vault.RetrievalKey
			}

			err = cm.DeleteVault(targetFileID)
			if err != nil {
				color.Red("Deletion failed: %v\n", err)
				return
			}
			color.Green("Cloud vault deleted.")
		},
	}

	var cloudResetCmd = &cobra.Command{
		Use:   "reset",
		Short: "Clear local cloud metadata (Retrieval Key)",
		Run: func(cmd *cobra.Command, args []string) {
			masterPassword, vault, readonly, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}
			if readonly {
				color.Red("Vault is READ-ONLY. Cannot reset cloud metadata.")
				return
			}

			if vault.RetrievalKey == "" {
				color.Yellow("Cloud sync is not initialized (no key found).")
				return
			}

			fmt.Printf("This will clear the local Retrieval Key: %s\n", vault.RetrievalKey)
			fmt.Print("Are you sure? (y/n): ")
			if strings.ToLower(readInput()) != "y" {
				return
			}

			vault.RetrievalKey = ""
			data, err := src.EncryptVault(vault, masterPassword)
			if err != nil {
				color.Red("Error encrypting vault: %v\n", err)
				return
			}

			if err := src.SaveVault(vaultPath, data); err != nil {
				color.Red("Error saving vault: %v\n", err)
				return
			}

			color.Green("Cloud metadata reset successfully. You can now run 'pm cloud init' again.")
		},
	}

	cloudCmd.AddCommand(cloudInitCmd, cloudSyncCmd, cloudAutoSyncCmd, cloudGetCmd, cloudDeleteCmd, cloudResetCmd)

	var methodCmd = &cobra.Command{Use: "method", Short: "Manage authentication methods"}
	var helloCmd = &cobra.Command{
		Use:   "hello",
		Short: "Setup Windows Hello (biometric/PIN) for vault unlocking",
		Run: func(cmd *cobra.Command, args []string) {
			disable, _ := cmd.Flags().GetBool("disable")
			if disable {
				if err := src.DisableHello(); err != nil {
					color.Red("Error: %v\n", err)
				} else {
					color.Green("Windows Hello support disabled.\n")
				}
				return
			}

			if src.IsHelloConfigured() {
				color.Yellow("Windows Hello is already configured. Reconfiguring will overwrite existing setup.")
			}

			fmt.Print("Enter Master Password to authorize Windows Hello: ")
			masterPass, err := readPassword()
			fmt.Println()
			if err != nil {
				color.Red("Error reading password: %v\n", err)
				return
			}

			// Verify password by attempting to load/decrypt vault
			if !src.VaultExists(vaultPath) {
				color.Red("Vault not found. Please init vault first.")
				return
			}
			data, err := src.LoadVault(vaultPath)
			if err != nil {
				color.Red("Error loading vault: %v\n", err)
				return
			}

			_, err = src.DecryptVault(data, masterPass, 1)
			if err != nil {
				color.Red("Authentication failed (incorrect master password).")
				return
			}

			color.Cyan("Setting up Windows Hello... Please complete the biometric challenge.")
			if err := src.SetupHello(masterPass); err != nil {
				color.Red("Error: %v\n", err)
				return
			}

			color.Green("Windows Hello successfully configured. You can now unlock your vault with your face, fingerprint, or PIN.")
		},
	}
	helloCmd.Flags().Bool("disable", false, "Disable Windows Hello support")
	methodCmd.AddCommand(helloCmd)

	var modeCmd = &cobra.Command{Use: "mode", Short: "Manage modes"}
	modeCmd.AddCommand(unlockCmd, readonlyCmd, lockCmd, compromiseCmd)

	rootCmd.AddCommand(initCmd, addCmd, getCmd, delCmd, editCmd, genCmd, modeCmd, cinfoCmd, scanCmd, auditCmd, totpCmd, importCmd, exportCmd, infoCmd, cloudCmd, methodCmd)
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})
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
	color.Green("Secret copied to clipboard.")
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
			vault, err := src.DecryptVault(data, session.MasterPassword, 1)
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

	// Biometric Authentication Attempt
	if src.IsHelloConfigured() {
		color.HiBlue("[Windows Hello configured. Authenticating...]")
		
		helloResult := make(chan string, 1)
		go func() {
			pass, err := src.GetMasterPasswordWithHello()
			if err == nil {
				helloResult <- pass
			}
		}()

		// Wait briefly to see if biometric is immediate, otherwise continue to password input
		select {
		case pass := <-helloResult:
			vault, err := src.DecryptVault(data, pass, 1)
			if err == nil {
				color.Green("Authenticated via Windows Hello.")
				return pass, vault, false, nil
			}
		case <-time.After(500 * time.Millisecond):
			// Proceed to manual input but keep checking helloResult in background
			fmt.Println("Type Master Password or wait for Windows Hello...")
		}
		
		// If we are here, we are doing manual input
		// But we still want to allow the goroutine to finish and "interrupt" the input if possible
	}

	for i := 0; i < 3; i++ {
		localFailures := src.GetFailureCount()
		costMultiplier := 1
		if localFailures >= 6 {
			costMultiplier = 4
			time.Sleep(5 * time.Second)
		}

		fmt.Printf("Master Password (attempt %d/3): ", i+1)
		pass, _ := readPassword()
		fmt.Println()

		vault, err := src.DecryptVault(data, pass, costMultiplier)
		if err == nil {
			// Success
			if vault.EmergencyMode || localFailures >= 6 {
				color.HiRed("\nCRITICAL: MULTIPLE FAILED LOGIN ATTEMPS DETECTED. EMERGENCY MODE WAS ACTIVE.\n")
			}
			vault.FailedAttempts = 0
			vault.EmergencyMode = false
			src.ClearFailures()

			updatedData, _ := src.EncryptVault(vault, pass)
			src.SaveVault(vaultPath, updatedData)

			return pass, vault, false, nil
		}

		src.TrackFailure()

		fmt.Printf("Error: %v\n", err)
	}

	return "", nil, false, fmt.Errorf("too many failed attempts")
}

func setupWindowsHello() {
	if !src.VaultExists(vaultPath) {
		color.Red("Vault not found. Please run 'pm init' first.")
		return
	}

	fmt.Print("Enter Master Password to authorize Windows Hello: ")
	masterPassword, err := readPassword()
	fmt.Println()
	if err != nil {
		color.Red("Error reading password: %v", err)
		return
	}

	data, err := src.LoadVault(vaultPath)
	if err != nil {
		color.Red("Error loading vault: %v", err)
		return
	}

	_, err = src.DecryptVault(data, masterPassword, 1)
	if err != nil {
		color.Red("Invalid master password.")
		return
	}

	color.Cyan("Setting up Windows Hello... Please complete the biometric challenge.")
	
	if err := src.SetupHello(masterPassword); err != nil {
		color.Red("Error: %v\n", err)
		return
	}

	color.Green("Windows Hello successfully configured. You can now unlock your vault with your face, fingerprint, or PIN.")
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
	case "Certificate":
		c := res.Data.(src.CertificateEntry)
		fmt.Printf("Type: Certificate\nLabel: %s\nIssuer: %s\nExpiry: %s\n", c.Label, c.Issuer, c.Expiry.Format("2006-01-02"))
		if time.Until(c.Expiry) < 30*24*time.Hour {
			color.Red("  [ALERT] Certificate is expiring soon! (%s left)\n", time.Until(c.Expiry).Truncate(time.Hour))
		}
		if showPass {
			fmt.Printf("Cert Data:\n%s\n", c.CertData)
			if c.PrivateKey != "" {
				fmt.Printf("Private Key:\n%s\n", c.PrivateKey)
			}
		}
	case "Banking":
		b := res.Data.(src.BankingEntry)
		fmt.Printf("Type: Banking (%s)\nLabel: %s\n", b.Type, b.Label)
		displayDetails := b.Details

		if b.Type == "Card" && len(displayDetails) > 4 {
			displayDetails = "**** **** **** " + displayDetails[len(displayDetails)-4:]
		} else if len(displayDetails) > 4 {
			displayDetails = displayDetails[:4] + " **** **** ****"
		}
		fmt.Printf("Details (Redacted): %s\n", displayDetails)
		if showPass {
			fmt.Printf("Full Details: %s\n", b.Details)
			if b.CVV != "" {
				fmt.Printf("CVV: %s\n", b.CVV)
			}
			if b.Expiry != "" {
				fmt.Printf("Expiry: %s\n", b.Expiry)
			}
		}
	case "Document":
		d := res.Data.(src.DocumentEntry)
		fmt.Printf("Type: Document\nName: %s\nFile: %s\n", d.Name, d.FileName)
		fmt.Print("This is a secure document. Open it? (y/n): ")
		if strings.ToLower(readInput()) == "y" {
			fmt.Print("Enter Document Password: ")
			docPass, _ := readPassword()
			fmt.Println()
			if docPass == d.Password {
				tmpDir := os.TempDir()
				tmpFile := filepath.Join(tmpDir, d.FileName)
				err := os.WriteFile(tmpFile, d.Content, 0600)
				if err != nil {
					color.Red("Error writing temporary file: %v\n", err)
					return
				}
				defer func() {
					time.Sleep(5 * time.Second)
					os.Remove(tmpFile)
				}()
				color.Green("Opening document...")
				var cmd *exec.Cmd
				if runtime.GOOS == "windows" {
					cmd = exec.Command("cmd", "/c", "start", "", tmpFile)
				} else if runtime.GOOS == "darwin" {
					cmd = exec.Command("open", tmpFile)
				} else {
					cmd = exec.Command("xdg-open", tmpFile)
				}
				cmd.Run()
			} else {
				color.Red("Incorrect document password.")
			}
		}
	}
	fmt.Println("---")
}

func getCloudManager(ctx context.Context, vault *src.Vault, masterPassword string) (*src.CloudManager, error) {
	exe, _ := os.Executable()
	installDir := filepath.Dir(exe)

	migrated := false
	if len(vault.CloudCredentials) == 0 {
		credsPath := filepath.Join(installDir, "credentials.json")
		if data, err := os.ReadFile(credsPath); err == nil {
			vault.CloudCredentials = data
			migrated = true
			color.Yellow("Migrating credentials.json to encrypted vault...")
		} else {
			vault.CloudCredentials = src.GetDefaultCreds()
			migrated = true
		}
	}
	if len(vault.CloudToken) == 0 {
		tokenPath := filepath.Join(installDir, "token.json")
		if data, err := os.ReadFile(tokenPath); err == nil {
			vault.CloudToken = data
			migrated = true
			color.Yellow("Migrating token.json to encrypted vault...")
		} else {
			vault.CloudToken = src.GetDefaultToken()
			migrated = true
		}
	}

	if migrated {
		data, err := src.EncryptVault(vault, masterPassword)
		if err == nil {
			src.SaveVault(vaultPath, data)
			color.Green("Cloud credentials securely stored in vault.")
		}
	}

	return src.NewCloudManager(ctx, vault.CloudCredentials, vault.CloudToken)
}
