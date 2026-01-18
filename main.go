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
	"time"

	"context"
	src "password-manager/src"
	"password-manager/src/plugins"

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

	exe, _ := os.Executable()
	pluginMgr := plugins.NewPluginManager(filepath.Dir(exe))

	if err := pluginMgr.LoadPlugins(); err != nil {
		color.Red("Error loading plugins: %v\n", err)
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

			fmt.Println("if this program even helps you, please consider donating to the developer.")
			fmt.Println("for donations contact: aaravmaloo06@gmail.com")
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

			hookData := map[string]interface{}{
				"command": "add",
			}

			if err := pluginMgr.ExecuteHooks("pre", "add", hookData); err != nil {
				color.Red("Hook executing blocked action: %v", err)
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
			fmt.Println("11. Encrypted Document")
			fmt.Println("12. Government ID")
			fmt.Println("13. Medical/Health Record")
			fmt.Println("14. Travel Doc")
			fmt.Println("15. Contact/Emergency Info")
			fmt.Println("16. Cloud Credentials")
			fmt.Println("17. Kubernetes Secret")
			fmt.Println("18. Docker Registry")
			fmt.Println("19. SSH Config Snippet")
			fmt.Println("20. CI/CD Pipeline Secret")
			fmt.Println("21. Software License")
			fmt.Println("22. Legal Contract/NDA")
			fmt.Print("Selection (1-22): ")
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
				fmt.Print("Router IP: ")
				rip := readInput()
				if err := vault.AddWiFi(ssid, pass, sec); err == nil {
					for i, w := range vault.WiFiCredentials {
						if w.SSID == ssid {
							vault.WiFiCredentials[i].RouterIP = rip
						}
					}
				} else {
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
				fmt.Print("Path to File: ")
				path := readInput()
				content, err := os.ReadFile(path)
				if err != nil {
					color.Red("Error reading file: %v\n", err)
					return
				}
				fmt.Print("Create a password for this document: ")
				docPass, _ := readPassword()
				fmt.Println()
				fmt.Print("Tags (comma separated): ")
				tagsRaw := readInput()
				var tags []string
				if tagsRaw != "" {
					tags = strings.Split(tagsRaw, ",")
					for i := range tags {
						tags[i] = strings.TrimSpace(tags[i])
					}
				}
				fmt.Print("Expiry Date (e.g. YYYY-MM-DD, blank if none): ")
				exp := readInput()
				if err := vault.AddDocument(name, filepath.Base(path), content, docPass, tags, exp); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
				color.HiYellow("Document stored successfully and safely. Please delete the original file: %s\n", path)
			case "12":
				fmt.Print("Type (Passport/Driver's License/Voter ID): ")
				tType := readInput()
				fmt.Print("ID Number: ")
				num := readInput()
				fmt.Print("Full Name: ")
				name := readInput()
				fmt.Print("Expiry Date: ")
				exp := readInput()
				vault.AddGovID(src.GovIDEntry{Type: tType, IDNumber: num, Name: name, Expiry: exp})
			case "13":
				fmt.Print("Label: ")
				label := readInput()
				fmt.Print("Insurance ID: ")
				iid := readInput()
				fmt.Print("Prescriptions: ")
				pres := readInput()
				fmt.Print("Allergies: ")
				all := readInput()
				vault.AddMedicalRecord(src.MedicalRecordEntry{Label: label, InsuranceID: iid, Prescriptions: pres, Allergies: all})
			case "14":
				fmt.Print("Label: ")
				label := readInput()
				fmt.Print("Ticket Number: ")
				tick := readInput()
				fmt.Print("Booking Code: ")
				code := readInput()
				fmt.Print("Loyalty Program: ")
				loy := readInput()
				vault.AddTravelDoc(src.TravelEntry{Label: label, TicketNumber: tick, BookingCode: code, LoyaltyProgram: loy})
			case "15":
				fmt.Print("Name: ")
				name := readInput()
				fmt.Print("Phone: ")
				phone := readInput()
				fmt.Print("Email: ")
				email := readInput()
				fmt.Print("Address: ")
				addr := readInput()
				fmt.Print("Is Emergency Contact? (y/n): ")
				em := strings.ToLower(readInput()) == "y"
				vault.AddContact(src.ContactEntry{Name: name, Phone: phone, Email: email, Address: addr, Emergency: em})
			case "16":
				fmt.Print("Label: ")
				label := readInput()
				fmt.Print("Access Key: ")
				ak := readInput()
				fmt.Print("Secret Key: ")
				sk := readInput()
				fmt.Print("Region: ")
				reg := readInput()
				fmt.Print("Account ID: ")
				aid := readInput()
				fmt.Print("Role: ")
				role := readInput()
				fmt.Print("Expiration: ")
				exp := readInput()
				vault.AddCloudCredential(src.CloudCredentialEntry{Label: label, AccessKey: ak, SecretKey: sk, Region: reg, AccountID: aid, Role: role, Expiration: exp})
			case "17":
				fmt.Print("Name: ")
				name := readInput()
				fmt.Print("Cluster URL: ")
				url := readInput()
				fmt.Print("Namespace: ")
				ns := readInput()
				fmt.Print("Expiration: ")
				exp := readInput()
				vault.AddK8sSecret(src.K8sSecretEntry{Name: name, ClusterURL: url, Namespace: ns, Expiration: exp})
			case "18":
				fmt.Print("Name: ")
				name := readInput()
				fmt.Print("Registry URL: ")
				url := readInput()
				fmt.Print("Username: ")
				user := readInput()
				fmt.Print("Token: ")
				tok := readInput()
				vault.AddDockerRegistry(src.DockerRegistryEntry{Name: name, RegistryURL: url, Username: user, Token: tok})
			case "19":
				fmt.Print("Alias: ")
				alias := readInput()
				fmt.Print("Host: ")
				host := readInput()
				fmt.Print("User: ")
				user := readInput()
				fmt.Print("Port: ")
				port := readInput()
				fmt.Print("Key Path: ")
				kp := readInput()
				fmt.Print("Fingerprint: ")
				fp := readInput()
				fmt.Println("Enter Private Key (end with empty line):")
				var pkLines []string
				for {
					line := readInput()
					if line == "" {
						break
					}
					pkLines = append(pkLines, line)
				}
				vault.AddSSHConfig(src.SSHConfigEntry{Alias: alias, Host: host, User: user, Port: port, KeyPath: kp, PrivateKey: strings.Join(pkLines, "\n"), Fingerprint: fp})
			case "20":
				fmt.Print("Name: ")
				name := readInput()
				fmt.Print("Webhook URL: ")
				wh := readInput()
				fmt.Print("Environment Variables (comma separated): ")
				ev := readInput()
				vault.AddCICDSecret(src.CICDSecretEntry{Name: name, Webhook: wh, EnvVars: ev})
			case "21":
				fmt.Print("Product Name: ")
				prod := readInput()
				fmt.Print("Serial Key: ")
				key := readInput()
				fmt.Print("Activation Info: ")
				act := readInput()
				fmt.Print("Expiration: ")
				exp := readInput()
				vault.AddSoftwareLicense(src.SoftwareLicenseEntry{ProductName: prod, SerialKey: key, ActivationInfo: act, Expiration: exp})
			case "22":
				fmt.Print("Name: ")
				name := readInput()
				fmt.Print("Summary: ")
				sum := readInput()
				fmt.Print("Parties Involved: ")
				part := readInput()
				fmt.Print("Signed Date: ")
				date := readInput()
				vault.AddLegalContract(src.LegalContractEntry{Name: name, Summary: sum, PartiesInvolved: part, SignedDate: date})
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
				fmt.Println("12. Government ID")
				fmt.Println("13. Medical Record")
				fmt.Println("14. Travel Doc")
				fmt.Println("15. Contact")
				fmt.Println("16. Cloud Credentials")
				fmt.Println("17. Kubernetes Secret")
				fmt.Println("18. Docker Registry")
				fmt.Println("19. SSH Config")
				fmt.Println("20. CI/CD Secret")
				fmt.Println("21. Software License")
				fmt.Println("22. Legal Contract")
				fmt.Print("Selection (1-22): ")
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
				case "12":
					category = "Government ID"
					for _, e := range vault.GovIDs {
						results = append(results, src.SearchResult{Type: "Government ID", Identifier: e.IDNumber, Data: e})
					}
				case "13":
					category = "Medical Record"
					for _, e := range vault.MedicalRecords {
						results = append(results, src.SearchResult{Type: "Medical Record", Identifier: e.Label, Data: e})
					}
				case "14":
					category = "Travel"
					for _, e := range vault.TravelDocs {
						results = append(results, src.SearchResult{Type: "Travel", Identifier: e.Label, Data: e})
					}
				case "15":
					category = "Contact"
					for _, e := range vault.Contacts {
						results = append(results, src.SearchResult{Type: "Contact", Identifier: e.Name, Data: e})
					}
				case "16":
					category = "Cloud Credentials"
					for _, e := range vault.CloudCredentialsItems {
						results = append(results, src.SearchResult{Type: "Cloud Credentials", Identifier: e.Label, Data: e})
					}
				case "17":
					category = "Kubernetes Secret"
					for _, e := range vault.K8sSecrets {
						results = append(results, src.SearchResult{Type: "Kubernetes Secret", Identifier: e.Name, Data: e})
					}
				case "18":
					category = "Docker Registry"
					for _, e := range vault.DockerRegistries {
						results = append(results, src.SearchResult{Type: "Docker Registry", Identifier: e.Name, Data: e})
					}
				case "19":
					category = "SSH Config"
					for _, e := range vault.SSHConfigs {
						results = append(results, src.SearchResult{Type: "SSH Config", Identifier: e.Alias, Data: e})
					}
				case "20":
					category = "CI/CD Secret"
					for _, e := range vault.CICDSecrets {
						results = append(results, src.SearchResult{Type: "CI/CD Secret", Identifier: e.Name, Data: e})
					}
				case "21":
					category = "Software License"
					for _, e := range vault.SoftwareLicenses {
						results = append(results, src.SearchResult{Type: "Software License", Identifier: e.ProductName, Data: e})
					}
				case "22":
					category = "Legal Contract"
					for _, e := range vault.LegalContracts {
						results = append(results, src.SearchResult{Type: "Legal Contract", Identifier: e.Name, Data: e})
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
			} else if vault.DeleteGovID(name) {
				deleted = true
			} else if vault.DeleteMedicalRecord(name) {
				deleted = true
			} else if vault.DeleteTravelDoc(name) {
				deleted = true
			} else if vault.DeleteContact(name) {
				deleted = true
			} else if vault.DeleteCloudCredential(name) {
				deleted = true
			} else if vault.DeleteK8sSecret(name) {
				deleted = true
			} else if vault.DeleteDockerRegistry(name) {
				deleted = true
			} else if vault.DeleteSSHConfig(name) {
				deleted = true
			} else if vault.DeleteCICDSecret(name) {
				deleted = true
			} else if vault.DeleteSoftwareLicense(name) {
				deleted = true
			} else if vault.DeleteLegalContract(name) {
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
			fmt.Println("9. Certificate")
			fmt.Println("10. Banking Item")
			fmt.Println("11. Document")
			fmt.Println("12. Government ID")
			fmt.Println("13. Medical Record")
			fmt.Println("14. Travel Doc")
			fmt.Println("15. Contact")
			fmt.Println("16. Cloud Credentials")
			fmt.Println("17. Kubernetes Secret")
			fmt.Println("18. Docker Registry")
			fmt.Println("19. SSH Config")
			fmt.Println("20. CI/CD Secret")
			fmt.Println("21. Software License")
			fmt.Println("22. Legal Contract")
			fmt.Print("Selection (1-22): ")
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
					fmt.Printf("New Router IP [%s]: ", e.RouterIP)
					newRip := readInput()
					if newRip == "" {
						newRip = e.RouterIP
					}
					vault.DeleteWiFi(e.SSID)
					vault.AddWiFi(newSSID, newPass, newSec)
					for i, w := range vault.WiFiCredentials {
						if w.SSID == newSSID {
							vault.WiFiCredentials[i].RouterIP = newRip
						}
					}
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
					fmt.Printf("New Tags [%s]: ", strings.Join(e.Tags, ", "))
					newTagsRaw := readInput()
					newTags := e.Tags
					if newTagsRaw != "" {
						newTags = strings.Split(newTagsRaw, ",")
						for i := range newTags {
							newTags[i] = strings.TrimSpace(newTags[i])
						}
					}
					fmt.Printf("New Expiry [%s]: ", e.Expiry)
					newExp := readInput()
					if newExp == "" {
						newExp = e.Expiry
					}
					vault.DeleteDocument(e.Name)
					vault.AddDocument(newName, e.FileName, e.Content, e.Password, newTags, newExp)
					updated = true
				}
			case "12":
				for i, e := range vault.GovIDs {
					if e.IDNumber == identifier {
						fmt.Printf("Editing Gov ID: %s\n", identifier)
						fmt.Printf("New Type [%s]: ", e.Type)
						newType := readInput()
						if newType == "" {
							newType = e.Type
						}
						fmt.Printf("New ID Number [%s]: ", e.IDNumber)
						newNum := readInput()
						if newNum == "" {
							newNum = e.IDNumber
						}
						fmt.Printf("New Name [%s]: ", e.Name)
						newName := readInput()
						if newName == "" {
							newName = e.Name
						}
						fmt.Printf("New Expiry [%s]: ", e.Expiry)
						newExp := readInput()
						if newExp == "" {
							newExp = e.Expiry
						}
						vault.GovIDs[i] = src.GovIDEntry{Type: newType, IDNumber: newNum, Name: newName, Expiry: newExp}
						updated = true
						break
					}
				}
			case "13":
				for i, e := range vault.MedicalRecords {
					if e.Label == identifier {
						fmt.Printf("Editing Medical Record: %s\n", identifier)
						fmt.Printf("New Label [%s]: ", e.Label)
						newLabel := readInput()
						if newLabel == "" {
							newLabel = e.Label
						}
						fmt.Printf("New Insurance ID [%s]: ", e.InsuranceID)
						newIID := readInput()
						if newIID == "" {
							newIID = e.InsuranceID
						}
						fmt.Printf("New Prescriptions [%s]: ", e.Prescriptions)
						newPres := readInput()
						if newPres == "" {
							newPres = e.Prescriptions
						}
						fmt.Printf("New Allergies [%s]: ", e.Allergies)
						newAll := readInput()
						if newAll == "" {
							newAll = e.Allergies
						}
						vault.MedicalRecords[i] = src.MedicalRecordEntry{Label: newLabel, InsuranceID: newIID, Prescriptions: newPres, Allergies: newAll}
						updated = true
						break
					}
				}
			case "14":
				for i, e := range vault.TravelDocs {
					if e.Label == identifier {
						fmt.Printf("Editing Travel Doc: %s\n", identifier)
						fmt.Printf("New Label [%s]: ", e.Label)
						newLabel := readInput()
						if newLabel == "" {
							newLabel = e.Label
						}
						fmt.Printf("New Ticket Number [%s]: ", e.TicketNumber)
						newTick := readInput()
						if newTick == "" {
							newTick = e.TicketNumber
						}
						fmt.Printf("New Booking Code [%s]: ", e.BookingCode)
						newCode := readInput()
						if newCode == "" {
							newCode = e.BookingCode
						}
						fmt.Printf("New Loyalty Program [%s]: ", e.LoyaltyProgram)
						newLoy := readInput()
						if newLoy == "" {
							newLoy = e.LoyaltyProgram
						}
						vault.TravelDocs[i] = src.TravelEntry{Label: newLabel, TicketNumber: newTick, BookingCode: newCode, LoyaltyProgram: newLoy}
						updated = true
						break
					}
				}
			case "15":
				for i, e := range vault.Contacts {
					if e.Name == identifier {
						fmt.Printf("Editing Contact: %s\n", identifier)
						fmt.Printf("New Name [%s]: ", e.Name)
						newName := readInput()
						if newName == "" {
							newName = e.Name
						}
						fmt.Printf("New Phone [%s]: ", e.Phone)
						newPhone := readInput()
						if newPhone == "" {
							newPhone = e.Phone
						}
						fmt.Printf("New Email [%s]: ", e.Email)
						newEmail := readInput()
						if newEmail == "" {
							newEmail = e.Email
						}
						fmt.Printf("New Address [%s]: ", e.Address)
						newAddr := readInput()
						if newAddr == "" {
							newAddr = e.Address
						}
						fmt.Printf("Emergency Contact (y/n) [%v]: ", e.Emergency)
						newEmRaw := readInput()
						newEm := e.Emergency
						if newEmRaw != "" {
							newEm = strings.ToLower(newEmRaw) == "y"
						}
						vault.Contacts[i] = src.ContactEntry{Name: newName, Phone: newPhone, Email: newEmail, Address: newAddr, Emergency: newEm}
						updated = true
						break
					}
				}
			case "16":
				for i, e := range vault.CloudCredentialsItems {
					if e.Label == identifier {
						fmt.Printf("Editing Cloud Cred: %s\n", identifier)
						fmt.Printf("New Label [%s]: ", e.Label)
						newLabel := readInput()
						if newLabel == "" {
							newLabel = e.Label
						}
						fmt.Printf("New Access Key [%s]: ", e.AccessKey)
						newAK := readInput()
						if newAK == "" {
							newAK = e.AccessKey
						}
						fmt.Printf("New Secret Key [%s]: ", e.SecretKey)
						newSK := readInput()
						if newSK == "" {
							newSK = e.SecretKey
						}
						fmt.Printf("New Region [%s]: ", e.Region)
						newReg := readInput()
						if newReg == "" {
							newReg = e.Region
						}
						fmt.Printf("New Account ID [%s]: ", e.AccountID)
						newAID := readInput()
						if newAID == "" {
							newAID = e.AccountID
						}
						fmt.Printf("New Role [%s]: ", e.Role)
						newRole := readInput()
						if newRole == "" {
							newRole = e.Role
						}
						fmt.Printf("New Expiration [%s]: ", e.Expiration)
						newExp := readInput()
						if newExp == "" {
							newExp = e.Expiration
						}
						vault.CloudCredentialsItems[i] = src.CloudCredentialEntry{Label: newLabel, AccessKey: newAK, SecretKey: newSK, Region: newReg, AccountID: newAID, Role: newRole, Expiration: newExp}
						updated = true
						break
					}
				}
			case "17":
				for i, e := range vault.K8sSecrets {
					if e.Name == identifier {
						fmt.Printf("Editing K8s Secret: %s\n", identifier)
						fmt.Printf("New Name [%s]: ", e.Name)
						newName := readInput()
						if newName == "" {
							newName = e.Name
						}
						fmt.Printf("New Cluster URL [%s]: ", e.ClusterURL)
						newURL := readInput()
						if newURL == "" {
							newURL = e.ClusterURL
						}
						fmt.Printf("New Namespace [%s]: ", e.Namespace)
						newNS := readInput()
						if newNS == "" {
							newNS = e.Namespace
						}
						fmt.Printf("New Expiration [%s]: ", e.Expiration)
						newExp := readInput()
						if newExp == "" {
							newExp = e.Expiration
						}
						vault.K8sSecrets[i] = src.K8sSecretEntry{Name: newName, ClusterURL: newURL, Namespace: newNS, Expiration: newExp}
						updated = true
						break
					}
				}
			case "18":
				for i, e := range vault.DockerRegistries {
					if e.Name == identifier {
						fmt.Printf("Editing Docker Registry: %s\n", identifier)
						fmt.Printf("New Name [%s]: ", e.Name)
						newName := readInput()
						if newName == "" {
							newName = e.Name
						}
						fmt.Printf("New Registry URL [%s]: ", e.RegistryURL)
						newURL := readInput()
						if newURL == "" {
							newURL = e.RegistryURL
						}
						fmt.Printf("New Username [%s]: ", e.Username)
						newUser := readInput()
						if newUser == "" {
							newUser = e.Username
						}
						fmt.Printf("New Token [%s]: ", e.Token)
						newTok := readInput()
						if newTok == "" {
							newTok = e.Token
						}
						vault.DockerRegistries[i] = src.DockerRegistryEntry{Name: newName, RegistryURL: newURL, Username: newUser, Token: newTok}
						updated = true
						break
					}
				}
			case "19":
				for i, e := range vault.SSHConfigs {
					if e.Alias == identifier {
						fmt.Printf("Editing SSH Config: %s\n", identifier)
						fmt.Printf("New Alias [%s]: ", e.Alias)
						newAlias := readInput()
						if newAlias == "" {
							newAlias = e.Alias
						}
						fmt.Printf("New Host [%s]: ", e.Host)
						newHost := readInput()
						if newHost == "" {
							newHost = e.Host
						}
						fmt.Printf("New User [%s]: ", e.User)
						newUser := readInput()
						if newUser == "" {
							newUser = e.User
						}
						fmt.Printf("New Port [%s]: ", e.Port)
						newPort := readInput()
						if newPort == "" {
							newPort = e.Port
						}
						fmt.Printf("New Key Path [%s]: ", e.KeyPath)
						newKP := readInput()
						if newKP == "" {
							newKP = e.KeyPath
						}
						fmt.Printf("New Fingerprint [%s]: ", e.Fingerprint)
						newFP := readInput()
						if newFP == "" {
							newFP = e.Fingerprint
						}
						fmt.Println("Enter New Private Key (end with empty line, blank to keep):")
						var kLines []string
						for {
							line := readInput()
							if line == "" {
								break
							}
							kLines = append(kLines, line)
						}
						newPK := strings.Join(kLines, "\n")
						if newPK == "" {
							newPK = e.PrivateKey
						}
						vault.SSHConfigs[i] = src.SSHConfigEntry{Alias: newAlias, Host: newHost, User: newUser, Port: newPort, KeyPath: newKP, PrivateKey: newPK, Fingerprint: newFP}
						updated = true
						break
					}
				}
			case "20":
				for i, e := range vault.CICDSecrets {
					if e.Name == identifier {
						fmt.Printf("Editing CI/CD Secret: %s\n", identifier)
						fmt.Printf("New Name [%s]: ", e.Name)
						newName := readInput()
						if newName == "" {
							newName = e.Name
						}
						fmt.Printf("New Webhook [%s]: ", e.Webhook)
						newWH := readInput()
						if newWH == "" {
							newWH = e.Webhook
						}
						fmt.Printf("New Env Vars [%s]: ", e.EnvVars)
						newEV := readInput()
						if newEV == "" {
							newEV = e.EnvVars
						}
						vault.CICDSecrets[i] = src.CICDSecretEntry{Name: newName, Webhook: newWH, EnvVars: newEV}
						updated = true
						break
					}
				}
			case "21":
				for i, e := range vault.SoftwareLicenses {
					if e.ProductName == identifier {
						fmt.Printf("Editing License: %s\n", identifier)
						fmt.Printf("New Product [%s]: ", e.ProductName)
						newProd := readInput()
						if newProd == "" {
							newProd = e.ProductName
						}
						fmt.Printf("New Serial Key [%s]: ", e.SerialKey)
						newKey := readInput()
						if newKey == "" {
							newKey = e.SerialKey
						}
						fmt.Printf("New Activation Info [%s]: ", e.ActivationInfo)
						newAct := readInput()
						if newAct == "" {
							newAct = e.ActivationInfo
						}
						fmt.Printf("New Expiration [%s]: ", e.Expiration)
						newExp := readInput()
						if newExp == "" {
							newExp = e.Expiration
						}
						vault.SoftwareLicenses[i] = src.SoftwareLicenseEntry{ProductName: newProd, SerialKey: newKey, ActivationInfo: newAct, Expiration: newExp}
						updated = true
						break
					}
				}
			case "22":
				for i, e := range vault.LegalContracts {
					if e.Name == identifier {
						fmt.Printf("Editing Contract: %s\n", identifier)
						fmt.Printf("New Name [%s]: ", e.Name)
						newName := readInput()
						if newName == "" {
							newName = e.Name
						}
						fmt.Printf("New Summary [%s]: ", e.Summary)
						newSum := readInput()
						if newSum == "" {
							newSum = e.Summary
						}
						fmt.Printf("New Parties [%s]: ", e.PartiesInvolved)
						newParties := readInput()
						if newParties == "" {
							newParties = e.PartiesInvolved
						}
						fmt.Printf("New Signed Date [%s]: ", e.SignedDate)
						newDate := readInput()
						if newDate == "" {
							newDate = e.SignedDate
						}
						vault.LegalContracts[i] = src.LegalContractEntry{Name: newName, Summary: newSum, PartiesInvolved: newParties, SignedDate: newDate}
						updated = true
						break
					}
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
			if !src.VaultExists(vaultPath) {
				color.Red("No vault found.")
				return
			}
			data, err := src.LoadVault(vaultPath)
			if err != nil {
				color.Red("Error loading vault: %v", err)
				return
			}

			p, ver, err := src.GetVaultParams(data)
			if err != nil {
				color.Red("Error reading header: %v", err)
				return
			}

			fmt.Println("APM Crypto Configuration")
			fmt.Println("========================")
			fmt.Printf("Format:    APMVAULT v%d\n", ver)
			fmt.Printf("Profile:   %s\n", p.Name)
			fmt.Println("KDF:       Argon2id")
			fmt.Printf("  Time:    %d\n", p.Time)
			fmt.Printf("  Memory:  %d KB\n", p.Memory/1024)
			fmt.Printf("  Threads: %d\n", p.Parallelism)
			fmt.Println("Cipher:    AES-256-GCM")
			fmt.Printf("  Nonce:   %d bytes\n", p.NonceLen)
			fmt.Printf("  Salt:    %d bytes\n", p.SaltLen)
			fmt.Println("Integrity: HMAC-SHA256 (Encrypt-then-MAC)")
		},
	}

	var vsettingsCmd = &cobra.Command{
		Use:   "vsettings",
		Short: "Manage vault security settings",
		Run: func(cmd *cobra.Command, args []string) {
			modify, _ := cmd.Flags().GetBool("modify")
			alerts, _ := cmd.Flags().GetBool("alerts")

			masterPassword, vault, readonly, err := src_unlockVault()
			if err != nil {
				return
			}

			if modify {
				if readonly {
					color.Red("Vault is READ-ONLY. Cannot modify settings.")
					return
				}
				fmt.Println("Interactive Security Settings")
				fmt.Println("-----------------------------")
				fmt.Printf("Current Profile: %s\n", vault.Profile)
				fmt.Print("New Profile (leave blank to skip): ")
				newProf := readInput()
				if newProf != "" {
					err := src.ChangeProfile(vault, newProf, masterPassword, vaultPath)
					if err != nil {
						color.Red("Error: %v", err)
					} else {
						color.Green("Profile updated to %s.", newProf)
					}
				}
			}

			if cmd.Flags().Changed("alerts") {
				if readonly {
					color.Red("Vault is READ-ONLY. Cannot toggle alerts.")
					return
				}
				err := src.ConfigureAlerts(vault, alerts, "", masterPassword, vaultPath)
				if err != nil {
					color.Red("Error: %v", err)
				} else {
					color.Green("Alerts set to %v", alerts)
				}
			}

			fmt.Printf("\nVault Settings:\n")
			fmt.Printf("  Profile: %s\n", vault.Profile)
			fmt.Printf("  Alerts:  %v\n", vault.AlertsEnabled)
			if vault.AlertsEnabled {
				fmt.Printf("  Email:   %s\n", vault.AlertEmail)
			}
		},
	}
	vsettingsCmd.Flags().Bool("modify", false, "Modify settings interactively")
	vsettingsCmd.Flags().Bool("alerts", false, "Enable/disable alerts")

	var profileCmd = &cobra.Command{
		Use:   "profile",
		Short: "Manage encryption profiles",
	}

	var profileSetCmd = &cobra.Command{
		Use:   "set <name>",
		Short: "Switch to a different profile",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			masterPassword, vault, readonly, err := src_unlockVault()
			if err != nil {
				return
			}
			if readonly {
				color.Red("Vault is READ-ONLY.")
				return
			}
			err = src.ChangeProfile(vault, args[0], masterPassword, vaultPath)
			if err != nil {
				color.Red("Error: %v", err)
			} else {
				color.Green("Profile switched to %s.", args[0])
			}
		},
	}

	var profileCreateCmd = &cobra.Command{
		Use:   "create <name>",
		Short: "Create a custom profile",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			masterPassword, vault, readonly, err := src_unlockVault()
			if err != nil {
				return
			}
			if readonly {
				color.Red("Vault is READ-ONLY.")
				return
			}

			fmt.Println("\n--- Custom Security Profile Creation ---")
			fmt.Println("You are about to customize the underlying cryptographic parameters of your vault.")
			fmt.Println("Each field below affects how hard it is for an attacker to crack your vault,")
			fmt.Println("Do this at your own risk.")
			fmt.Println("but also how long it takes for you to unlock it.")

			fmt.Println("\n[1] Memory (Argon2 Memory Cost)")
			fmt.Println("Explanation: The amount of RAM required to derive your encryption keys.")
			fmt.Println("Security: Higher memory cost protects against GPU/ASIC brute-force attacks.")
			fmt.Println("Tip: 64MB is standard. 256MB+ is hardened. Use what your system can comfortably spare.")
			fmt.Print("Memory (MB) [64]: ")
			memStr := readInput()
			mem := uint32(64)
			if memStr != "" {
				fmt.Sscanf(memStr, "%d", &mem)
			}

			fmt.Println("\n[2] Time (Argon2 Iterations)")
			fmt.Println("Explanation: The number of times the hashing function is repeated.")
			fmt.Println("Security: More iterations mean a slower hash, making brute-force much slower.")
			fmt.Println("Tip: 3 is standard. Increase this if you want the 'unlock' process to take longer (more secure).")
			fmt.Print("Time (Iterations) [3]: ")
			timeStr := readInput()
			t := uint32(3)
			if timeStr != "" {
				fmt.Sscanf(timeStr, "%d", &t)
			}

			fmt.Println("\n[3] Parallelism (Argon2 Threads)")
			fmt.Println("Explanation: The number of CPU threads used during key derivation.")
			fmt.Println("Security: Typically matched to your CPU's core count.")
			fmt.Println("Tip: 2-4 is usually ideal. Higher values don't necessarily increase security but use more CPU power.")
			fmt.Print("Parallelism [2]: ")
			parStr := readInput()
			p := uint8(2)
			if parStr != "" {
				fmt.Sscanf(parStr, "%d", &p)
			}

			fmt.Println("\n[4] Salt Length")
			fmt.Println("Explanation: Random data added to your password before hashing.")
			fmt.Println("Security: Prevents 'Rainbow Table' attacks where pre-computed hashes are used.")
			fmt.Println("Tip: 16 bytes is standard. 32 bytes is very secure. Increasing this has negligible performance hit.")
			fmt.Print("Salt Length (Bytes) [16]: ")
			saltLenStr := readInput()
			saltLen := 16
			if saltLenStr != "" {
				fmt.Sscanf(saltLenStr, "%d", &saltLen)
			}

			fmt.Println("\n[5] Nonce Length (IV Size)")
			fmt.Println("Explanation: A 'Number used ONCE' for the AES-GCM encryption process.")
			fmt.Println("Security: Ensures that the same data encrypted twice looks different.")
			fmt.Println("Tip: 12 bytes is standard for AES-GCM. 24 bytes is used for XChaCha20 (not yet supported) or special cases.")
			fmt.Print("Nonce Length (Bytes) [12]: ")
			nonceLenStr := readInput()
			nonceLen := 12
			if nonceLenStr != "" {
				fmt.Sscanf(nonceLenStr, "%d", &nonceLen)
			}

			customProfile := src.CryptoProfile{
				Name:        args[0],
				KDF:         "argon2id",
				Memory:      mem * 1024,
				Time:        t,
				Parallelism: p,
				SaltLen:     saltLen,
				NonceLen:    nonceLen,
			}

			vault.CurrentProfileParams = &customProfile
			vault.Profile = args[0]

			data, err := src.EncryptVault(vault, masterPassword)
			if err != nil {
				color.Red("Encryption failed: %v", err)
				return
			}
			src.SaveVault(vaultPath, data)
			color.Green("Custom profile '%s' applied.", args[0])
		},
	}
	profileCmd.AddCommand(profileSetCmd, profileCreateCmd)

	var healthCmd = &cobra.Command{
		Use:   "health",
		Short: "Security health dashboard",
		Run: func(cmd *cobra.Command, args []string) {
			_, vault, _, err := src_unlockVault()
			if err != nil {
				return
			}
			score, report := src.CalculateHealth(vault)
			fmt.Println("\nAPM SECURITY HEALTH DASHBOARD")
			fmt.Println("=============================")
			fmt.Printf("OVERALL SCORE: %d/100\n\n", score)
			for _, r := range report {
				fmt.Printf("- %s\n", r)
			}
		},
	}

	var adupCmd = &cobra.Command{
		Use:   "adup",
		Short: "Check for security anomalies",
		Run: func(cmd *cobra.Command, args []string) {
			_, vault, _, err := src_unlockVault()
			if err != nil {
				return
			}
			alerts := src.CheckAnomalies(vault)
			if len(alerts) == 0 {
				color.Green("No anomalies detected. Your account is likely safe.")
			} else {
				color.Red("⚠ ANOMALIES DETECTED:")
				for _, a := range alerts {
					color.Red("  - %s", a)
				}
			}
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
			fmt.Println("Type entry number to copy to clipboard.")
			defer fmt.Print("\x1b[?25h")

			inputChan := make(chan string)
			go func() {
				scanner := bufio.NewScanner(os.Stdin)
				for scanner.Scan() {
					inputChan <- scanner.Text()
				}
			}()

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

				for i, entry := range targets {
					code, err := src.GenerateTOTP(entry.Secret)
					if err != nil {
						fmt.Printf("\r\x1b[K[%d] %-20s : INVALID\n", i+1, entry.Account)
					} else {
						fmt.Printf("\r\x1b[K[%d] %-20s : \x1b[1;32m%s\x1b[0m\n", i+1, entry.Account, code)
					}
				}

				select {
				case input := <-inputChan:
					num, err := strconv.Atoi(input)
					if err == nil && num >= 1 && num <= len(targets) {
						targetEntry := targets[num-1]
						code, _ := src.GenerateTOTP(targetEntry.Secret)
						copyToClipboard(code)
						fmt.Printf("\r\x1b[K\x1b[1;36m>> Copied TOTP for %s to clipboard!\x1b[0m\n", targetEntry.Account)
						time.Sleep(1 * time.Second)
						fmt.Printf("\033[%dA", len(targets)+2)
					} else {
						fmt.Printf("\033[%dA", len(targets)+1)
					}
				default:
					time.Sleep(500 * time.Millisecond)
					fmt.Printf("\033[%dA", len(targets)+1)
				}
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
		Short: "Sync and retrieve vaults from cloud (Google Drive or Dropbox)",
	}

	var cloudInitCmd = &cobra.Command{
		Use:   "init [dropbox|gdrive]",
		Short: "Setup cloud sync and generate retrieval key",
		Run: func(cmd *cobra.Command, args []string) {
			provider := "gdrive"
			if len(args) > 0 {
				provider = args[0]
			}

			masterPassword, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			if vault.RetrievalKey != "" {
				color.Yellow("Cloud sync already initialized. Key: %s\n", vault.RetrievalKey)
				return
			}

			color.Cyan("Generating secure retrieval key...")
			customKey, err := src.GenerateRetrievalKey()
			if err != nil {
				color.Red("Key generation failed: %v\n", err)
				return
			}

			cm, err := getCloudManagerEx(context.Background(), vault, masterPassword, provider)
			if err != nil {
				color.Red("Cloud Error: %v\n", err)
				return
			}

			fileID, err := cm.UploadVault(vaultPath, customKey)
			if err != nil {
				color.Red("Upload failed: %v\n", err)
				return
			}

			vault.RetrievalKey = customKey
			vault.CloudFileID = fileID
			vault.LastCloudProvider = provider

			data, _ := src.EncryptVault(vault, masterPassword)
			src.SaveVault(vaultPath, data)

			color.Green("Cloud sync initialized (%s)!", provider)
			color.HiCyan("Retrieval Key: %s\n", customKey)
			color.Yellow("Keep this key safe! It's required to pull your vault on other devices.")
		},
	}

	var cloudSyncCmd = &cobra.Command{
		Use:   "sync [dropbox|gdrive]",
		Short: "Sync local vault to cloud",
		Run: func(cmd *cobra.Command, args []string) {
			masterPassword, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			if vault.RetrievalKey == "" {
				color.Red("Cloud sync not initialized. Run 'pm cloud init' first.")
				return
			}

			provider := vault.LastCloudProvider
			if len(args) > 0 {
				provider = args[0]
			}
			if provider == "" {
				provider = "gdrive"
			}

			cm, err := getCloudManagerEx(context.Background(), vault, masterPassword, provider)
			if err != nil {
				color.Red("Cloud Error: %v\n", err)
				return
			}

			err = cm.SyncVault(vaultPath, vault.CloudFileID)
			if err != nil {
				color.Red("Sync failed: %v\n", err)
				return
			}
			color.Green("Vault synced to cloud (%s).", provider)
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
			provider := vault.LastCloudProvider
			if provider == "" {
				provider = "gdrive"
			}
			cm, err := getCloudManagerEx(context.Background(), vault, masterPassword, provider)
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
		Use:   "get [dropbox|gdrive] [retrieval_key]",
		Short: "Download vault from cloud",
		Run: func(cmd *cobra.Command, args []string) {
			provider := "gdrive"
			var key string

			if len(args) == 0 {
				fmt.Print("Enter Provider (dropbox/gdrive) [gdrive]: ")
				pInput := readInput()
				if pInput != "" {
					provider = pInput
				}
				fmt.Print("Enter Retrieval Key: ")
				key, _ = readPassword()
				fmt.Println()
			} else if len(args) == 1 {
				provider = args[0]
				fmt.Print("Enter Retrieval Key: ")
				key, _ = readPassword()
				fmt.Println()
			} else {
				provider = args[0]
				key = args[1]
			}

			cp, err := src.GetCloudProvider(provider, context.Background(), nil, nil)
			if err != nil {
				color.Red("Cloud Error: %v\n", err)
				return
			}

			fileID, err := cp.ResolveKeyToID(key)
			if err != nil {
				color.Red("Key resolution failed: %v\n", err)
				return
			}

			data, err := cp.DownloadVault(fileID)
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
		Use:   "delete [dropbox|gdrive]",
		Short: "Delete current vault from cloud",
		Run: func(cmd *cobra.Command, args []string) {
			masterPassword, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			if vault.CloudFileID == "" {
				color.Red("Cloud file not found in vault metadata.")
				return
			}

			provider := vault.LastCloudProvider
			if len(args) > 0 {
				provider = args[0]
			}
			if provider == "" {
				provider = "gdrive"
			}

			cm, err := getCloudManagerEx(context.Background(), vault, masterPassword, provider)
			if err != nil {
				color.Red("Cloud Error: %v\n", err)
				return
			}

			err = cm.DeleteVault(vault.CloudFileID)
			if err != nil {
				color.Red("Delete failed: %v\n", err)
				return
			}

			vault.RetrievalKey = ""
			vault.CloudFileID = ""
			vault.LastCloudProvider = ""
			data, _ := src.EncryptVault(vault, masterPassword)
			src.SaveVault(vaultPath, data)

			color.Green("Vault deleted from cloud.")
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

	var modeCmd = &cobra.Command{Use: "mode", Short: "Manage modes"}
	modeCmd.AddCommand(unlockCmd, readonlyCmd, lockCmd, compromiseCmd)

	rootCmd.AddCommand(initCmd, addCmd, getCmd, delCmd, editCmd, genCmd, modeCmd, cinfoCmd, scanCmd, auditCmd, totpCmd, importCmd, exportCmd, infoCmd, cloudCmd, vsettingsCmd, profileCmd, healthCmd, adupCmd)
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})

	var pluginsCmd = &cobra.Command{
		Use:   "plugins",
		Short: "Manage APM plugins",
	}

	var pluginsInstalledCmd = &cobra.Command{
		Use:   "installed",
		Short: "List installed plugins",
		Run: func(cmd *cobra.Command, args []string) {
			list := pluginMgr.ListPlugins()
			if len(list) == 0 {
				fmt.Println("No plugins installed locally.")
				return
			}
			fmt.Println("Installed Plugins:")
			for _, p := range list {
				fmt.Printf("- %s\n", p)
			}
		},
	}

	var pluginsListCmd = &cobra.Command{
		Use:   "list",
		Short: "List available plugins in Marketplace (Multi-Cloud)",
		Run: func(cmd *cobra.Command, args []string) {
			providers := []string{"gdrive", "dropbox"}
			allPlugins := make(map[string]bool)

			fmt.Println("Fetching plugins from Marketplace...")
			for _, p := range providers {
				cm, err := getCloudManagerEx(context.Background(), nil, "", p)
				if err != nil {
					continue
				}
				plugins, err := cm.ListMarketplacePlugins()
				if err != nil {
					continue
				}
				for _, name := range plugins {
					allPlugins[name] = true
				}
			}

			if len(allPlugins) == 0 {
				fmt.Println("No plugins found in Marketplace.")
				return
			}
			fmt.Println("Available Plugins:")
			var names []string
			for name := range allPlugins {
				names = append(names, name)
			}
			sort.Strings(names)
			for _, n := range names {
				fmt.Printf("- %s\n", n)
			}
		},
	}

	var pluginsAddCmd = &cobra.Command{
		Use:   "add [name]",
		Short: "Install a plugin from Marketplace",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				color.Red("Usage: pm plugins add <name>")
				return
			}
			name := args[0]

			providers := []string{"gdrive", "dropbox"}
			success := false

			targetDir := filepath.Join(pluginMgr.PluginsDir, name)

			for _, p := range providers {
				cm, err := getCloudManagerEx(context.Background(), nil, "", p)
				if err != nil {
					continue
				}

				fmt.Printf("Attempting to download '%s' from %s...\n", name, p)
				if err := cm.DownloadPlugin(name, targetDir); err == nil {
					success = true
					break
				} else {
					os.RemoveAll(targetDir)
				}
			}

			if !success {
				color.Red("Failed to install plugin '%s' from any marketplace.", name)
				return
			}

			color.Green("Plugin '%s' installed successfully.", name)
		},
	}

	var pluginsRemoveCmd = &cobra.Command{
		Use:   "remove [name]",
		Short: "Remove a plugin",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				color.Red("Usage: pm plugins remove <name>")
				return
			}
			name := args[0]
			if err := pluginMgr.RemovePlugin(name); err != nil {
				color.Red("Error removing plugin: %v\n", err)
				return
			}
			color.Green("Plugin %s removed successfully.\n", name)
		},
	}

	var pluginsPushCmd = &cobra.Command{
		Use:   "push [name]",
		Short: "Push a plugin to Marketplace (Multi-Cloud)",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				color.Red("Usage: pm plugins push <name>")
				return
			}
			pluginName := args[0]
			cwd, _ := os.Getwd()
			pluginPath := filepath.Join(cwd, "plugins", pluginName)

			if _, err := os.Stat(pluginPath); os.IsNotExist(err) {
				color.Red("Plugin %s not found in current directory.", pluginName)
				return
			}

			def, err := plugins.LoadPluginDef(filepath.Join(pluginPath, "plugin.json"))
			if err != nil {
				color.Red("Invalid plugin.json: %v", err)
				return
			}

			fmt.Printf("Validating plugin '%s' v%s...\n", def.Name, def.Version)

			providers := []string{"gdrive", "dropbox"}
			anySuccess := false

			for _, p := range providers {
				fmt.Printf("Uploading to %s...\n", p)
				cm, err := getCloudManagerEx(context.Background(), nil, "", p)
				if err != nil {
					color.Yellow("Skipping %s: authentication failed", p)
					continue
				}

				if err := cm.UploadPlugin(pluginName, pluginPath); err != nil {
					color.Yellow("Failed to upload to %s: %v", p, err)
					continue
				}
				anySuccess = true
			}

			if !anySuccess {
				color.Red("Failed to push plugin to any marketplace.")
				return
			}

			color.Green("Successfully pushed plugin '%s' to marketplace!", pluginName)
		},
	}

	pluginsCmd.AddCommand(pluginsListCmd, pluginsInstalledCmd, pluginsAddCmd, pluginsRemoveCmd, pluginsPushCmd)
	rootCmd.AddCommand(pluginsCmd)

	for _, plugin := range pluginMgr.Loaded {
		for cmdKey, cmdDef := range plugin.Definition.Commands {
			cmdName := cmdKey
			desc := cmdDef.Description

			dynamicCmd := &cobra.Command{
				Use:   cmdName,
				Short: desc,
				Run: func(c *cobra.Command, args []string) {
					ctx := plugins.NewExecutionContext()

					for flagName, flagDef := range cmdDef.Flags {
						val, _ := c.Flags().GetString(flagName)
						if val == "" {
							val = flagDef.Default
						}
						ctx.Variables[flagName] = val
					}

					_, vault, _, err := src_unlockVault()
					if err != nil {
						color.Red("Error unlocking vault for plugin: %v\n", err)
						return
					}
					executor := plugins.NewStepExecutor(ctx, vault)

					if err := executor.ExecuteSteps(cmdDef.Steps, plugin.Definition.Permissions); err != nil {
						color.Red("Plugin execution error: %v\n", err)
					}
				},
			}

			for flagName, flagDef := range cmdDef.Flags {
				dynamicCmd.Flags().String(flagName, flagDef.Default, flagName)
			}

			rootCmd.AddCommand(dynamicCmd)
		}
	}

	rootCmd.Execute()
}

func readInput() string {
	input, _ := inputReader.ReadString('\n')
	return strings.TrimSpace(input)
}

func readPassword() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(bytePassword)), nil
	}
	return readInput(), nil
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

	src.LogAccess("ATTEMPT")
	alerts := src.CheckAnomalies(nil)
	if len(alerts) > 0 {
		color.Red("\n⚠ SECURITY WARNING: Unusual activity detected!")
		for _, a := range alerts {
			color.Red("  - %s", a)
		}
		fmt.Println()
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
			src.LogAccess("UNLOCK")
			if vault.EmergencyMode || localFailures >= 6 {
				color.HiRed("\nCRITICAL: MULTIPLE FAILED LOGIN ATTEMPS DETECTED. EMERGENCY MODE WAS ACTIVE.\n")
			}
			vault.FailedAttempts = 0
			vault.EmergencyMode = false
			src.ClearFailures()

			if vault.AlertsEnabled && vault.AnomalyDetectionEnabled && len(alerts) > 0 {
				src.SendAlert(vault, "ANOMALY", fmt.Sprintf("Unusual activity detected during unlock: %v", alerts))
			}

			updatedData, _ := src.EncryptVault(vault, pass)
			src.SaveVault(vaultPath, updatedData)

			return pass, vault, false, nil
		}

		src.LogAccess("FAIL")
		src.TrackFailure()

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
	case "Government ID":
		g := res.Data.(src.GovIDEntry)
		fmt.Printf("Type: %s\nID Number: %s\nName: %s\nExpiry: %s\n", g.Type, g.IDNumber, g.Name, g.Expiry)
		copyToClipboardWithExpiry(g.IDNumber)
	case "Medical Record":
		m := res.Data.(src.MedicalRecordEntry)
		fmt.Printf("Type: Medical Record\nLabel: %s\nInsurance ID: %s\nPrescriptions: %s\nAllergies: %s\n", m.Label, m.InsuranceID, m.Prescriptions, m.Allergies)
	case "Travel":
		t := res.Data.(src.TravelEntry)
		fmt.Printf("Type: Travel\nLabel: %s\nTicket: %s\nBooking Code: %s\nLoyalty: %s\n", t.Label, t.TicketNumber, t.BookingCode, t.LoyaltyProgram)
		copyToClipboardWithExpiry(t.BookingCode)
	case "Contact":
		c := res.Data.(src.ContactEntry)
		fmt.Printf("Type: Contact\nName: %s\nPhone: %s\nEmail: %s\nAddress: %s\nEmergency: %v\n", c.Name, c.Phone, c.Email, c.Address, c.Emergency)
	case "Cloud Credentials":
		c := res.Data.(src.CloudCredentialEntry)
		fmt.Printf("Type: Cloud Credentials\nLabel: %s\nRegion: %s\nAccount ID: %s\nRole: %s\nExpiration: %s\n", c.Label, c.Region, c.AccountID, c.Role, c.Expiration)
		if showPass {
			fmt.Printf("Access Key: %s\nSecret Key: %s\n", c.AccessKey, c.SecretKey)
		}
		copyToClipboardWithExpiry(c.SecretKey)
	case "Kubernetes Secret":
		k := res.Data.(src.K8sSecretEntry)
		fmt.Printf("Type: K8s Secret\nName: %s\nCluster URL: %s\nNamespace: %s\nExpiration: %s\n", k.Name, k.ClusterURL, k.Namespace, k.Expiration)
	case "Docker Registry":
		d := res.Data.(src.DockerRegistryEntry)
		fmt.Printf("Type: Docker Registry\nName: %s\nRegistry URL: %s\nUsername: %s\n", d.Name, d.RegistryURL, d.Username)
		if showPass {
			fmt.Printf("Token: %s\n", d.Token)
		}
		copyToClipboardWithExpiry(d.Token)
	case "SSH Config":
		s := res.Data.(src.SSHConfigEntry)
		fmt.Printf("Type: SSH Config\nAlias: %s\nHost: %s\nUser: %s\nPort: %s\nKey Path: %s\nFingerprint: %s\n", s.Alias, s.Host, s.User, s.Port, s.KeyPath, s.Fingerprint)
		if showPass {
			fmt.Printf("Private Key:\n%s\n", s.PrivateKey)
		}
		copyToClipboardWithExpiry(s.PrivateKey)
	case "CI/CD Secret":
		c := res.Data.(src.CICDSecretEntry)
		fmt.Printf("Type: CI/CD Secret\nName: %s\nWebhook: %s\nEnv Vars: %s\n", c.Name, c.Webhook, c.EnvVars)
	case "Software License":
		s := res.Data.(src.SoftwareLicenseEntry)
		fmt.Printf("Type: Software License\nProduct: %s\nSerial Key: %s\nActivation: %s\nExpiration: %s\n", s.ProductName, s.SerialKey, s.ActivationInfo, s.Expiration)
	case "Legal Contract":
		l := res.Data.(src.LegalContractEntry)
		fmt.Printf("Type: Legal Contract\nName: %s\nSummary: %s\nParties: %s\nSigned: %s\n", l.Name, l.Summary, l.PartiesInvolved, l.SignedDate)
	}
	fmt.Println("---")
}

func getCloudManagerEx(ctx context.Context, vault *src.Vault, masterPassword string, provider string) (src.CloudProvider, error) {
	exe, _ := os.Executable()
	installDir := filepath.Dir(exe)

	migrated := false
	if provider == "gdrive" {
		if len(vault.CloudCredentials) == 0 {
			credsPath := filepath.Join(installDir, "credentials.json")
			if data, err := os.ReadFile(credsPath); err == nil {
				vault.CloudCredentials = data
				migrated = true
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
			} else {
				vault.CloudToken = src.GetDefaultToken()
				migrated = true
			}
		}
	} else if provider == "dropbox" {
		if len(vault.CloudToken) == 0 {
			vault.CloudToken = src.GetDefaultDropboxToken()
			migrated = true
		}
	}

	if migrated {
		data, err := src.EncryptVault(vault, masterPassword)
		if err == nil {
			src.SaveVault(vaultPath, data)
		}
	}

	return src.GetCloudProvider(provider, ctx, vault.CloudCredentials, vault.CloudToken)
}
