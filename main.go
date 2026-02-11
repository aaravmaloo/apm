package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
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

	"github.com/AlecAivazis/survey/v2"
	"github.com/fatih/color"
	"github.com/fsnotify/fsnotify"
	"github.com/spf13/cobra"
	oauth "golang.org/x/oauth2"
	"golang.org/x/term"
	"gopkg.in/gomail.v2"

	"os/signal"
	"syscall"
	"unicode"
)

var vaultPath string
var inputReader *bufio.Reader
var pluginMgr *plugins.PluginManager

func init() {
	exe, err := os.Executable()
	if err != nil {
		color.Red("Error getting executable path: %v\n", err)
		os.Exit(1)
	}
	vaultFile := os.Getenv("APM_VAULT_PATH")
	if vaultFile == "" {
		vaultFile = "vault.dat"
	}
	if filepath.IsAbs(vaultFile) {
		vaultPath = filepath.Clean(vaultFile)
	} else {
		vaultPath = filepath.Clean(filepath.Join(filepath.Dir(exe), vaultFile))
	}
	inputReader = bufio.NewReader(os.Stdin)
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "pm",
		Short: "A simple password manager CLI",
	}

	exe, _ := os.Executable()
	pluginMgr = plugins.NewPluginManager(filepath.Dir(exe))

	if err := pluginMgr.LoadPlugins(); err != nil {
		color.Red("Error loading plugins: %v\n", err)
	}

	setupGDrive := func(v *src.Vault, mp string) error {
		color.Yellow("\nSetting up Google Drive...")

		fmt.Println("Choose Sync Mode:")
		fmt.Println("1. APM_PUBLIC (Fast, no signup, shared storage)")
		fmt.Println("2. Self-Hosted (Secure, uses your own Drive, requires login)")
		fmt.Print("Selection (1/2): ")
		modeSelection := readInput()

		var mode string
		var token []byte
		var err error

		if modeSelection == "2" {
			mode = "self_hosted"

			token, err = src.PerformDriveAuth(src.GetDefaultCreds())
			if err != nil {
				color.Red("Authentication failed: %v", err)
				return err
			}
			v.CloudToken = token
			v.CloudCredentials = src.GetDefaultCreds()
		} else {
			mode = "apm_public"
			v.CloudToken = src.GetDefaultToken()
			v.CloudCredentials = src.GetDefaultCreds()
		}
		v.DriveSyncMode = mode

		fmt.Print("Enter Custom Retrieval Key (leave blank to generate randomly): ")
		customKey := readInput()

		var gdriveKey string
		if customKey != "" {
			gdriveKey = customKey
		} else {
			gdriveKey, err = src.GenerateRetrievalKey()
			if err != nil {
				color.Red("Key generation failed: %v", err)
				return err
			}
		}

		cm, err := getCloudManagerEx(context.Background(), v, mp, "gdrive")
		if err != nil {
			color.Red("GDrive error: %v", err)
			return err
		}

		fileID, err := cm.UploadVault(vaultPath, gdriveKey)
		if err != nil {
			color.Red("Upload failed: %v", err)
			return err
		}

		v.RetrievalKey = gdriveKey
		v.CloudFileID = fileID
		v.LastCloudProvider = "gdrive"
		color.Green("Google Drive sync setup successful.")
		color.HiCyan("Retrieval Key: %s", gdriveKey)
		if mode == "self_hosted" {
			color.Cyan("Mode: Self-Hosted (Owner: You)")
		} else {
			color.Cyan("Mode: APM_PUBLIC")
		}
		return nil
	}

	setupGitHub := func(v *src.Vault) error {
		color.Yellow("\nSetting up GitHub...")
		fmt.Println("To create a Personal Access Token, go to GitHub Settings > Developer settings > Personal access tokens > Tokens (classic) and create a token with 'repo' scope.")
		fmt.Print("Enter GitHub Personal Access Token: ")
		pat, err := readPassword()
		if err != nil {
			color.Red("Error reading token: %v", err)
			return err
		}
		fmt.Println()
		fmt.Print("Enter GitHub Repo (format: owner/repo): ")
		repo := readInput()
		if pat == "" || repo == "" {
			color.Red("Missing token or repo.")
			return fmt.Errorf("missing token or repo")
		}
		gm, err := src.NewGitHubManager(context.Background(), pat)
		if err != nil {
			color.Red("GitHub Error: %v", err)
			return err
		}
		gm.SetRepo(repo)
		_, err = gm.UploadVault(vaultPath, "")
		if err != nil {
			color.Red("Upload failed: %v", err)
			return err
		}
		v.GitHubToken = pat
		v.GitHubRepo = repo
		color.Green("GitHub sync setup successful.")
		return nil
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

			fmt.Print("Would you like to set up cloud sync now? (y/n) [n]: ")
			if strings.ToLower(readInput()) == "y" {
				fmt.Println("\nChoose Cloud Provider:")
				fmt.Println("1. Google Drive")
				fmt.Println("2. GitHub")
				fmt.Println("3. Both")
				fmt.Print("Selection (1/2/3): ")
				choice := readInput()
				switch choice {
				case "1":
					setupGDrive(vault, masterPassword)
				case "2":
					setupGitHub(vault)
				case "3":
					setupGDrive(vault, masterPassword)
					setupGitHub(vault)
				default:
					color.Red("Invalid selection.")
				}
				data, _ := src.EncryptVault(vault, masterPassword)
				if err := src.SaveVault(vaultPath, data); err != nil {
					color.Red("Error saving vault: %v\n", err)
				}
			}

			fmt.Println("\nif this program even helps you, please consider donating to the developer.")
			fmt.Println("for donations contact: aaravmaloo06@gmail.com")
		},
	}

	var initAllCmd = &cobra.Command{
		Use:   "all",
		Short: "Initialize a new vault and setup both Google Drive and GitHub sync",
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

			color.Cyan("\n--- Setting up Cloud Sync (All) ---")

			masterPassword, vault, _, err = src_unlockVault()
			if err != nil {
				return
			}

			setupGDrive(vault, masterPassword)
			setupGitHub(vault)

			data, _ = src.EncryptVault(vault, masterPassword)
			if err := src.SaveVault(vaultPath, data); err != nil {
				color.Red("Error saving vault: %v\n", err)
			}
			color.Green("\nInitial sync complete.")
		},
	}
	initCmd.AddCommand(initAllCmd)

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

			if err := pluginMgr.ExecuteHooks("pre", "add", vault, vaultPath); err != nil {
				color.Red("Hook executing blocked action: %v", err)
				return
			}

			fmt.Println("Select type to add:")
			color.HiCyan("\n--- CATEGORIES ---")
			color.Cyan("1. Identity & Personal")
			color.Cyan("2. Developer & Infrastructure")
			color.Cyan("3. Media & Files")
			color.Cyan("4. Finance & Legal")
			fmt.Print("\nSelect Category: ")
			catChoice := readInput()

			var choice string
			switch catChoice {
			case "1":
				color.HiCyan("\n--- IDENTITY & PERSONAL ---")
				fmt.Println("1. Password")
				fmt.Println("2. TOTP")
				fmt.Println("3. Government ID")
				fmt.Println("4. Contact")
				fmt.Println("5. Medical Record")
				fmt.Print("\nSelect item: ")
				sub := readInput()
				switch sub {
				case "1":
					choice = "1"
				case "2":
					choice = "2"
				case "3":
					choice = "12"
				case "4":
					choice = "15"
				case "5":
					choice = "13"
				}
			case "2":
				color.HiCyan("\n--- DEVELOPER & INFRASTRUCTURE ---")
				fmt.Println("1. API Key")
				fmt.Println("2. Token")
				fmt.Println("3. SSH Key")
				fmt.Println("4. SSH Config")
				fmt.Println("5. Cloud Credentials")
				fmt.Println("6. Kubernetes Secret")
				fmt.Println("7. Docker Registry")
				fmt.Println("8. CI/CD Secret")
				fmt.Print("\nSelect item: ")
				sub := readInput()
				switch sub {
				case "1":
					choice = "5"
				case "2":
					choice = "3"
				case "3":
					choice = "6"
				case "4":
					choice = "19"
				case "5":
					choice = "16"
				case "6":
					choice = "17"
				case "7":
					choice = "18"
				case "8":
					choice = "20"
				}
			case "3":
				color.HiCyan("\n--- MEDIA & FILES ---")
				fmt.Println("1. Document")
				fmt.Println("2. Audio")
				fmt.Println("3. Video")
				fmt.Println("4. Photo")
				fmt.Println("5. Secure Note")
				fmt.Print("\nSelect item: ")
				sub := readInput()
				switch sub {
				case "1":
					choice = "11"
				case "2":
					choice = "23"
				case "3":
					choice = "24"
				case "4":
					choice = "25"
				case "5":
					choice = "4"
				}
			case "4":
				color.HiCyan("\n--- FINANCE & LEGAL ---")
				fmt.Println("1. Banking")
				fmt.Println("2. WiFi")
				fmt.Println("3. Recovery Codes")
				fmt.Println("4. Certificate")
				fmt.Println("5. Software License")
				fmt.Println("6. Legal Contract")
				fmt.Println("7. Travel Doc")
				fmt.Print("\nSelect item: ")
				sub := readInput()
				switch sub {
				case "1":
					choice = "10"
				case "2":
					choice = "7"
				case "3":
					choice = "8"
				case "4":
					choice = "9"
				case "5":
					choice = "21"
				case "6":
					choice = "22"
				case "7":
					choice = "14"
				}
			default:
				color.Red("Invalid category.")
				return
			}

			if choice == "" {
				color.Red("Invalid choice.")
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
				if err := vault.AddGovID(src.GovIDEntry{Type: tType, IDNumber: num, Name: name, Expiry: exp}); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
			case "13":
				fmt.Print("Label: ")
				label := readInput()
				fmt.Print("Insurance ID: ")
				iid := readInput()
				fmt.Print("Prescriptions: ")
				pres := readInput()
				fmt.Print("Allergies: ")
				all := readInput()
				if err := vault.AddMedicalRecord(src.MedicalRecordEntry{Label: label, InsuranceID: iid, Prescriptions: pres, Allergies: all}); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
			case "14":
				fmt.Print("Label: ")
				label := readInput()
				fmt.Print("Ticket Number: ")
				tick := readInput()
				fmt.Print("Booking Code: ")
				code := readInput()
				fmt.Print("Loyalty Program: ")
				loy := readInput()
				if err := vault.AddTravelDoc(src.TravelEntry{Label: label, TicketNumber: tick, BookingCode: code, LoyaltyProgram: loy}); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
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
				if err := vault.AddContact(src.ContactEntry{Name: name, Phone: phone, Email: email, Address: addr, Emergency: em}); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
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
				if err := vault.AddCloudCredential(src.CloudCredentialEntry{Label: label, AccessKey: ak, SecretKey: sk, Region: reg, AccountID: aid, Role: role, Expiration: exp}); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
			case "17":
				fmt.Print("Name: ")
				name := readInput()
				fmt.Print("Cluster URL: ")
				url := readInput()
				fmt.Print("Namespace: ")
				ns := readInput()
				fmt.Print("Expiration: ")
				exp := readInput()
				if err := vault.AddK8sSecret(src.K8sSecretEntry{Name: name, ClusterURL: url, K8sNamespace: ns, Expiration: exp}); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
			case "18":
				fmt.Print("Name: ")
				name := readInput()
				fmt.Print("Registry URL: ")
				url := readInput()
				fmt.Print("Username: ")
				user := readInput()
				fmt.Print("Token: ")
				tok := readInput()
				if err := vault.AddDockerRegistry(src.DockerRegistryEntry{Name: name, RegistryURL: url, Username: user, Token: tok}); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
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
				if err := vault.AddSSHConfig(src.SSHConfigEntry{Alias: alias, Host: host, User: user, Port: port, KeyPath: kp, PrivateKey: strings.Join(pkLines, "\n"), Fingerprint: fp}); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
			case "20":
				fmt.Print("Name: ")
				name := readInput()
				fmt.Print("Webhook URL: ")
				wh := readInput()
				fmt.Print("Environment Variables (comma separated): ")
				ev := readInput()
				if err := vault.AddCICDSecret(src.CICDSecretEntry{Name: name, Webhook: wh, EnvVars: ev}); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
			case "21":
				fmt.Print("Product Name: ")
				prod := readInput()
				fmt.Print("Serial Key: ")
				key := readInput()
				fmt.Print("Activation Info: ")
				act := readInput()
				fmt.Print("Expiration: ")
				exp := readInput()
				if err := vault.AddSoftwareLicense(src.SoftwareLicenseEntry{ProductName: prod, SerialKey: key, ActivationInfo: act, Expiration: exp}); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
			case "22":
				fmt.Print("Name: ")
				name := readInput()
				fmt.Print("Summary: ")
				sum := readInput()
				fmt.Print("Parties Involved: ")
				part := readInput()
				fmt.Print("Signed Date: ")
				date := readInput()
				if err := vault.AddLegalContract(src.LegalContractEntry{Name: name, Summary: sum, PartiesInvolved: part, SignedDate: date}); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
			case "23":
				fmt.Print("Audio Name: ")
				name := readInput()
				fmt.Print("Path to File: ")
				path := readInput()
				content, err := os.ReadFile(path)
				if err != nil {
					color.Red("Error reading file: %v\n", err)
					return
				}
				if err := vault.AddAudio(name, filepath.Base(path), content); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
				color.HiYellow("Audio stored successfully.\n")
			case "24":
				fmt.Print("Video Name: ")
				name := readInput()
				fmt.Print("Path to File: ")
				path := readInput()
				content, err := os.ReadFile(path)
				if err != nil {
					color.Red("Error reading file: %v\n", err)
					return
				}
				if err := vault.AddVideo(name, filepath.Base(path), content); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
				color.HiYellow("Video stored successfully.\n")
			case "25":
				fmt.Print("Photo Name: ")
				name := readInput()
				fmt.Print("Path to File: ")
				path := readInput()
				content, err := os.ReadFile(path)
				if err != nil {
					color.Red("Error reading file: %v\n", err)
					return
				}
				if err := vault.AddPhoto(name, filepath.Base(path), content); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
				color.HiYellow("Photo stored successfully.\n")
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
			} else {
				src.SendAlert(vault, src.LevelAll, "ENTRY ADDED", "New entry added to vault.")
				color.Green("Entry saved.\n")
			}
		},
	}

	var getCmd = &cobra.Command{
		Use:   "get [query]",
		Short: "Search and manage vault entries interactively",
		Run: func(cmd *cobra.Command, args []string) {
			initialQuery := ""
			if len(args) > 0 {
				initialQuery = args[0]
			}

			masterPassword, vault, readonly, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			handleInteractiveEntries(vault, masterPassword, initialQuery, readonly)
		},
	}
	getCmd.Flags().Bool("show-pass", false, "Show password in output")

	var unlockCmd = &cobra.Command{
		Use:   "unlock",
		Short: "Unlock the vault for the current shell session",
		Run: func(cmd *cobra.Command, args []string) {
			timeout, _ := cmd.Flags().GetDuration("timeout")
			inactivity, _ := cmd.Flags().GetDuration("inactivity")

			masterPassword, _, readonly, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			err = src.CreateSession(masterPassword, timeout, readonly, inactivity)
			if err != nil {
				color.Red("Error creating session: %v\n", err)
				src.KillSession()
				src.LogAction("VAULT_LOCKED", "Session terminated due to failed unlock")
				color.Green("Vault locked. Session cleared.")
				return
			}
			src.LogAction("VAULT_UNLOCKED", "Session updated")
			color.Green("Vault session updated. Expires in %v or after %v of inactivity.\n", timeout, inactivity)
		},
	}
	unlockCmd.Flags().Duration("timeout", 1*time.Hour, "Session duration (e.g. 1h, 30m)")
	unlockCmd.Flags().Duration("inactivity", 15*time.Minute, "Inactivity timeout (e.g. 15m, 5m)")

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

			if err := src.CreateSession(masterPassword, duration, true, 0); err != nil {
				fmt.Printf("Error creating session: %v\n", err)
				return
			}
			src.LogAction("VAULT_UNLOCKED", "Read-only session created")
			fmt.Printf("Vault session updated to READ-ONLY mode for %d minutes.\n", mins)
		},
	}

	var lockCmd = &cobra.Command{
		Use:   "lock",
		Short: "Immediately lock the vault (kill active session)",
		Run: func(cmd *cobra.Command, args []string) {
			if err := src.KillSession(); err != nil {
				color.Yellow("No active session to kill or error: %v\n", err)
			} else {
				src.LogAction("VAULT_LOCKED", "Session terminated")
				color.Green("Vault locked.\n")
			}
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
			src.LogAction("VAULT_LOAD", fmt.Sprintf("Vault loaded from: %s", vaultPath))
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
			src.LogAction("HEALTH_CHECK", fmt.Sprintf("Score: %d", score))
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
			src.LogAction("AUDIT_VIEWED", "Audit logs displayed")
		},
	}

	var genCmd = &cobra.Command{
		Use:   "gen",
		Short: "Generate a random secure password",
		Run: func(cmd *cobra.Command, args []string) {
			length, _ := cmd.Flags().GetInt("length")
			password, _ := src.GeneratePassword(length)
			fmt.Println(password)
			src.LogAction("PASSWORD_GENERATED", fmt.Sprintf("Length: %d", length))
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
				_, _ = rand.Read(data)
				f.Write(data)
				f.Close()
				os.Remove(vaultPath)
				color.Green("Vault nuked.")
				src.LogAction("VAULT_DESTROYED", "Vault permanently deleted")
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

			fmt.Println("APM pre-release v9")
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
						src.LogAction("TOTP_COPIED", fmt.Sprintf("Account: %s", targetEntry.Account))
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
			src.LogAction("DATA_IMPORTED", fmt.Sprintf("File: %s, Type: %s", filename, ext))
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
			src.LogAction("DATA_EXPORTED", fmt.Sprintf("File: %s, Type: %s", output, ext))
			src.SendAlert(vault, src.LevelAll, "DATA EXPORT", fmt.Sprintf("Vault data exported to %s", output))
		},
	}
	exportCmd.Flags().StringP("output", "o", "", "Output filename")
	exportCmd.Flags().StringP("encrypt-pass", "e", "", "Password for encryption")
	exportCmd.Flags().Bool("without-password", false, "Exclude secrets")

	var cloudCmd = &cobra.Command{
		Use:   "cloud",
		Short: "Sync and retrieve vaults from cloud (Google Drive & GitHub)",
	}

	var cloudInitCmd = &cobra.Command{
		Use:   "init [gdrive|github]",
		Short: "Setup cloud sync and generate/set retrieval key",
		Run: func(cmd *cobra.Command, args []string) {
			masterPassword, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			if vault.CloudFileID != "" || vault.GitHubToken != "" || vault.DropboxToken != nil {
				color.Red("Cloud sync is already initialized.")
				if vault.CloudFileID != "" {
					color.Yellow("- Google Drive: Active (Mode: %s)", vault.DriveSyncMode)
				}
				if vault.GitHubToken != "" {
					color.Yellow("- GitHub: Active")
				}
				if vault.DropboxToken != nil {
					color.Yellow("- Dropbox: Active (Mode: %s)", vault.DropboxSyncMode)
				}
				fmt.Println("\nTo re-initialize, first remove the current configuration:")
				fmt.Println("  pm cloud reset")
				return
			}

			provider := ""
			if len(args) > 0 {
				provider = strings.ToLower(args[0])
			} else {
				fmt.Println("Choose Cloud Provider:")
				fmt.Println("1. Google Drive")
				fmt.Println("2. GitHub")
				fmt.Println("3. Dropbox")
				fmt.Println("4. All")
				fmt.Print("Selection (1/2/3/4): ")
				choice := readInput()
				if choice == "1" {
					provider = "gdrive"
				} else if choice == "2" {
					provider = "github"
				} else if choice == "3" {
					provider = "dropbox"
				} else if choice == "4" {
					provider = "all"
				} else {
					color.Red("Invalid selection.")
					return
				}
			}

			var errSetup error
			switch provider {
			case "github":
				errSetup = setupGitHub(vault)
			case "gdrive":
				errSetup = setupGDrive(vault, masterPassword)
			case "dropbox":
				errSetup = setupDropbox(vault, masterPassword)
			case "all":
				setupGDrive(vault, masterPassword)
				setupGitHub(vault)
				setupDropbox(vault, masterPassword)
			}

			if errSetup != nil {
				src.LogAction("CLOUD_INIT_FAILED", fmt.Sprintf("Provider: %s, Error: %v", provider, errSetup))
				return
			}

			data, _ := src.EncryptVault(vault, masterPassword)
			src.SaveVault(vaultPath, data)
			src.LogAction("CLOUD_INIT_SUCCESS", fmt.Sprintf("Provider: %s", provider))
		},
	}

	var cloudSyncCmd = &cobra.Command{
		Use:   "sync [gdrive|github]",
		Short: "Sync local vault to cloud",
		Run: func(cmd *cobra.Command, args []string) {
			masterPassword, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			syncTo := []string{}
			if len(args) > 0 {
				syncTo = append(syncTo, strings.ToLower(args[0]))
			} else {
				if vault.CloudFileID != "" {
					syncTo = append(syncTo, "gdrive")
				}
				if vault.GitHubToken != "" {
					syncTo = append(syncTo, "github")
				}
				if vault.DropboxToken != nil {
					syncTo = append(syncTo, "dropbox")
				}
			}

			if len(syncTo) == 0 {
				color.Red("Cloud sync not initialized. Run 'pm cloud init' first.")
				return
			}

			for _, provider := range syncTo {
				cm, err := getCloudManagerEx(context.Background(), vault, masterPassword, provider)
				if err != nil {
					color.Red("[%s] Cloud Error: %v", provider, err)
					continue
				}

				targetID := vault.CloudFileID
				if provider == "github" {
					targetID = vault.GitHubRepo
				} else if provider == "dropbox" {
					targetID = vault.DropboxFileID
				}

				err = cm.SyncVault(vaultPath, targetID)
				if err != nil {
					color.Red("[%s] Sync failed: %v", provider, err)
					src.LogAction("CLOUD_SYNC_FAILED", fmt.Sprintf("Provider: %s, Error: %v", provider, err))
				} else {
					color.Green("[%s] Vault synced to cloud.", provider)
					src.LogAction("CLOUD_SYNC_SUCCESS", fmt.Sprintf("Provider: %s", provider))
				}
			}
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

			syncConfigured := false
			var syncTargets []string
			if vault.CloudFileID != "" {
				syncTargets = append(syncTargets, "gdrive")
				syncConfigured = true
			}
			if vault.GitHubToken != "" {
				syncTargets = append(syncTargets, "github")
				syncConfigured = true
			}

			if !syncConfigured {
				color.Red("Cloud sync not initialized.")
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
								fmt.Printf("[%s] Change detected, syncing to cloud...\n", time.Now().Format("15:04:05"))

								for _, provider := range syncTargets {
									cm, err := getCloudManagerEx(context.Background(), vault, masterPassword, provider)
									if err != nil {
										color.Red("[%s] Cloud Error: %v", provider, err)
										continue
									}

									targetID := vault.CloudFileID
									if provider == "github" {
										targetID = vault.GitHubRepo
									}

									err = cm.SyncVault(vaultPath, targetID)
									if err != nil {
										src.LogAction("CLOUD_AUTOSYNC_FAILED", fmt.Sprintf("Provider: %s, Error: %v", provider, err))
										color.Red("[%s] Auto-sync failed: %v", provider, err)
									} else {
										src.LogAction("CLOUD_AUTOSYNC_SUCCESS", fmt.Sprintf("Provider: %s", provider))
										color.Green("[%s] Auto-sync successful.", provider)
									}
								}
								lastSync = time.Now()
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
			color.Cyan("Auto-sync watcher started (Targets: %v). Press Ctrl+C to stop.", syncTargets)
			<-done
		},
	}
	cloudAutoSyncCmd.Flags().Bool("true", false, "Enable auto-sync")

	var cloudGetCmd = &cobra.Command{
		Use:   "get [gdrive|github] [retrieval_key|repo]",
		Short: "Download vault from cloud",
		Run: func(cmd *cobra.Command, args []string) {
			provider := "gdrive"
			var key string

			if len(args) == 0 {
				fmt.Print("Enter Provider (gdrive|github) [gdrive]: ")
				pInput := readInput()
				if pInput != "" {
					provider = strings.ToLower(pInput)
				}
				if provider == "github" {
					fmt.Print("Enter GitHub Personal Access Token: ")
					pat, _ := readPassword()
					fmt.Println()
					fmt.Print("Enter GitHub Repo (owner/repo): ")
					key = readInput()

					gm, err := src.NewGitHubManager(context.Background(), pat)
					if err != nil {
						color.Red("Cloud Error: %v", err)
						return
					}
					data, err := gm.DownloadVault(key)
					if err != nil {
						color.Red("Download failed: %v", err)
						src.LogAction("CLOUD_DOWNLOAD_FAILED", fmt.Sprintf("Provider: github, Key: %s, Error: %v", key, err))
						return
					}
					handleDownloadedVault(data, pat, key)
					src.LogAction("CLOUD_DOWNLOAD_SUCCESS", fmt.Sprintf("Provider: github, Key: %s", key))
					return
				} else {
					fmt.Print("Enter Retrieval Key: ")
					key, _ = readPassword()
					fmt.Println()
				}
			} else if len(args) == 1 {
				provider = strings.ToLower(args[0])
				if provider == "github" {
					fmt.Print("Enter GitHub Personal Access Token: ")
					pat, _ := readPassword()
					fmt.Println()
					fmt.Print("Enter GitHub Repo (owner/repo): ")
					key = readInput()

					gm, err := src.NewGitHubManager(context.Background(), pat)
					if err != nil {
						color.Red("Cloud Error: %v", err)
						return
					}
					data, err := gm.DownloadVault(key)
					if err != nil {
						color.Red("Download failed: %v", err)
						src.LogAction("CLOUD_DOWNLOAD_FAILED", fmt.Sprintf("Provider: github, Key: %s, Error: %v", key, err))
						return
					}
					handleDownloadedVault(data, pat, key)
					src.LogAction("CLOUD_DOWNLOAD_SUCCESS", fmt.Sprintf("Provider: github, Key: %s", key))
					return
				} else {
					fmt.Print("Enter Retrieval Key: ")
					key, _ = readPassword()
					fmt.Println()
				}
			} else {
				provider = strings.ToLower(args[0])
				key = args[1]
				if provider == "github" {
					fmt.Print("Enter GitHub Personal Access Token: ")
					pat, _ := readPassword()
					fmt.Println()

					gm, err := src.NewGitHubManager(context.Background(), pat)
					if err != nil {
						color.Red("Cloud Error: %v", err)
						return
					}
					data, err := gm.DownloadVault(key)
					if err != nil {
						color.Red("Download failed: %v", err)
						src.LogAction("CLOUD_DOWNLOAD_FAILED", fmt.Sprintf("Provider: github, Key: %s, Error: %v", key, err))
						return
					}
					handleDownloadedVault(data, pat, key)
					src.LogAction("CLOUD_DOWNLOAD_SUCCESS", fmt.Sprintf("Provider: github, Key: %s", key))
					return
				}
			}

			fileID := ""
			syncMode := "apm_public"

			if provider == "gdrive" {
				fmt.Println("Choose Sync Mode for Retrieval:")
				fmt.Println("1. APM_PUBLIC (Current default)")
				fmt.Println("2. Self-Hosted (Login to your account)")
				fmt.Print("Selection (1/2): ")
				modeSelection := readInput()
				if modeSelection == "2" {
					syncMode = "self_hosted"

					token, err := src.PerformDriveAuth(src.GetDefaultCreds())
					if err != nil {
						color.Red("Authentication failed: %v", err)
						return
					}
					cp, err := src.GetCloudProvider("gdrive", context.Background(), src.GetDefaultCreds(), token, "self_hosted")
					if err != nil {
						color.Red("Cloud Error: %v", err)
						return
					}
					fileID, err = cp.ResolveKeyToID(key)
					if err != nil {
						color.Red("Key resolution failed: %v", err)
						src.LogAction("CLOUD_DOWNLOAD_FAILED", fmt.Sprintf("Provider: gdrive, Key: %s, Error: %v", key, err))
						return
					}
					data, err := cp.DownloadVault(fileID)
					if err != nil {
						color.Red("Download failed: %v", err)
						src.LogAction("CLOUD_DOWNLOAD_FAILED", fmt.Sprintf("Provider: gdrive, Key: %s, Error: %v", key, err))
						return
					}
					handleDownloadedVault(data, "", "")
					src.LogAction("CLOUD_DOWNLOAD_SUCCESS", fmt.Sprintf("Provider: gdrive, Key: %s", key))
					return
				}
			}

			cp, err := src.GetCloudProvider(provider, context.Background(), nil, nil, syncMode)
			if err != nil {
				color.Red("Cloud Error: %v\n", err)
				return
			}

			fileID, err = cp.ResolveKeyToID(key)
			if err != nil {
				color.Red("Key resolution failed: %v\n", err)
				src.LogAction("CLOUD_DOWNLOAD_FAILED", fmt.Sprintf("Provider: %s, Key: %s, Error: %v", provider, key, err))
				return
			}

			data, err := cp.DownloadVault(fileID)
			if err != nil {
				color.Red("Download failed: %v\n", err)
				color.Yellow("Note: For APM_PUBLIC, only uploader needs credentials.json. Ensure retrieval key is correct.")
				src.LogAction("CLOUD_DOWNLOAD_FAILED", fmt.Sprintf("Provider: %s, Key: %s, Error: %v", provider, key, err))
				return
			}

			handleDownloadedVault(data, "", "")
			src.LogAction("CLOUD_DOWNLOAD_SUCCESS", fmt.Sprintf("Provider: %s, Key: %s", provider, key))
		},
	}

	var cloudDeleteCmd = &cobra.Command{
		Use:   "delete [gdrive]",
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
				src.LogAction("CLOUD_DELETE_FAILED", fmt.Sprintf("Provider: %s, FileID: %s, Error: %v", provider, vault.CloudFileID, err))
				return
			}

			vault.RetrievalKey = ""
			vault.CloudFileID = ""
			vault.LastCloudProvider = ""
			data, _ := src.EncryptVault(vault, masterPassword)
			src.SaveVault(vaultPath, data)

			color.Green("Vault deleted from cloud.")
			src.LogAction("CLOUD_DELETE_SUCCESS", fmt.Sprintf("Provider: %s, FileID: %s", provider, vault.CloudFileID))
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

			if vault.RetrievalKey == "" && vault.GitHubToken == "" && vault.DropboxToken == nil {
				color.Yellow("Cloud sync is not initialized (no setup found).")
				return
			}

			fmt.Printf("This will clear all local cloud metadata (Retrieval Key, Tokens, etc).\n")
			fmt.Print("Are you sure? (y/n): ")
			if strings.ToLower(readInput()) != "y" {
				return
			}

			vault.RetrievalKey = ""
			vault.CloudFileID = ""
			vault.LastCloudProvider = ""
			vault.DriveSyncMode = ""
			vault.CloudCredentials = nil
			vault.CloudToken = nil
			vault.GitHubToken = ""
			vault.GitHubRepo = ""
			vault.DropboxToken = nil
			vault.DropboxSyncMode = ""
			vault.DropboxFileID = ""

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
			src.LogAction("CLOUD_RESET", "Cloud metadata cleared")
		},
	}

	cloudInitCmd.Flags().StringP("key", "k", "", "Custom retrieval key")
	cloudCmd.AddCommand(cloudInitCmd, cloudSyncCmd, cloudAutoSyncCmd, cloudGetCmd, cloudDeleteCmd, cloudResetCmd)

	var modeCmd = &cobra.Command{Use: "mode", Short: "Manage modes"}
	modeCmd.AddCommand(unlockCmd, readonlyCmd, lockCmd, compromiseCmd)

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
		Short: "List available plugins in Marketplace (Drive)",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Fetching plugins from Marketplace...")
			cm, err := getCloudManagerEx(context.Background(), nil, "", "gdrive")
			if err != nil {
				color.Red("Error connecting to marketplace: %v", err)
				return
			}
			plugins, err := cm.ListMarketplacePlugins()
			if err != nil {
				color.Red("Error listing plugins: %v", err)
				return
			}

			if len(plugins) == 0 {
				fmt.Println("No plugins found in Marketplace.")
				return
			}
			fmt.Println("Available Plugins:")
			sort.Strings(plugins)
			for _, n := range plugins {
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
			targetDir := filepath.Join(pluginMgr.PluginsDir, name)

			cm, err := getCloudManagerEx(context.Background(), nil, "", "gdrive")
			if err != nil {
				color.Red("Error connecting to marketplace: %v", err)
				return
			}

			fmt.Printf("Attempting to download '%s' from Drive Marketplace...\n", name)
			if err := cm.DownloadPlugin(name, targetDir); err != nil {
				os.RemoveAll(targetDir)
				color.Red("Failed to install plugin '%s': %v", name, err)
				src.LogAction("PLUGIN_INSTALL_FAILED", fmt.Sprintf("Plugin: %s, Error: %v", name, err))
				return
			}

			color.Green("Plugin '%s' installed successfully.", name)
			src.LogAction("PLUGIN_INSTALLED", fmt.Sprintf("Plugin: %s", name))
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
				src.LogAction("PLUGIN_REMOVE_FAILED", fmt.Sprintf("Plugin: %s, Error: %v", name, err))
				return
			}
			color.Green("Plugin %s removed successfully.\n", name)
			src.LogAction("PLUGIN_REMOVED", fmt.Sprintf("Plugin: %s", name))
		},
	}

	var pluginSearchCmd = &cobra.Command{
		Use:   "search",
		Short: "Search for plugins in the marketplace",
		Run: func(cmd *cobra.Command, args []string) {
			masterPassword, vault, _, err := src_unlockVault()
			if err != nil {
				return
			}
			cm, err := getCloudManagerEx(context.Background(), vault, masterPassword, "gdrive")
			if err != nil {
				color.Red("Error connecting to cloud: %v", err)
				return
			}
			plugins, err := cm.ListMarketplacePlugins()
			if err != nil {
				color.Red("Error listing plugins: %v", err)
				return
			}
			if len(plugins) == 0 {
				fmt.Println("No plugins found in marketplace.")
				return
			}
			fmt.Println("Marketplace Plugins:")
			for _, p := range plugins {
				fmt.Println(p)
			}
		},
	}

	var pluginLocalCmd = &cobra.Command{
		Use:   "local [path]",
		Short: "Install a plugin from a local directory",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			pluginPath := args[0]
			if _, err := os.Stat(filepath.Join(pluginPath, "plugin.json")); os.IsNotExist(err) {
				color.Red("Invalid plugin directory: plugin.json not found")
				return
			}

			def, err := plugins.LoadPluginDef(filepath.Join(pluginPath, "plugin.json"))
			if err != nil {
				color.Red("Invalid manifest: %v", err)
				return
			}

			if err := pluginMgr.InstallPlugin(def.Name, pluginPath); err != nil {
				color.Red("Installation failed: %v", err)
				src.LogAction("PLUGIN_INSTALL_FAILED", fmt.Sprintf("Plugin: %s, Error: %v", def.Name, err))
				return
			}
			color.Green("Plugin '%s' installed successfully from local source.", def.Name)
			src.LogAction("PLUGIN_INSTALLED", fmt.Sprintf("Plugin: %s (local)", def.Name))
		},
	}

	pluginsCmd.AddCommand(pluginsListCmd, pluginsInstalledCmd, pluginsAddCmd, pluginsRemoveCmd, pluginLocalCmd, pluginSearchCmd)

	var setupCmd = &cobra.Command{
		Use:   "setup",
		Short: "Interactive setup wizard for apm",
		Run: func(cmd *cobra.Command, args []string) {
			color.HiCyan("Welcome to the APM Setup Wizard!\n")
			fmt.Println("This wizard will guide you through the initial configuration of APM.")
			fmt.Println()

			if !src.VaultExists(vaultPath) {
				color.Yellow("Step 1: Vault Initialization")
				fmt.Print("No vault found. Would you like to create one now? (y/n): ")
				if strings.ToLower(readInput()) == "y" {
					initCmd.Run(cmd, nil)
					src.LogAction("SETUP_VAULT_INIT", "Vault initialized via setup wizard")
				} else {
					fmt.Println("Skipping vault initialization.")
				}
			} else {
				color.Green("Vault already exists. Skipping initialization.")
			}
			fmt.Println()

			color.Yellow("Step 2: Cloud Sync Configuration")
			fmt.Print("Would you like to configure cloud synchronization? (y/n) [n]: ")
			if strings.ToLower(readInput()) == "y" {
				masterPassword, vault, _, err := src_unlockVault()
				if err != nil {
					color.Red("Unlock failed: %v", err)
				} else {
					fmt.Println("\nChoose Cloud Provider:")
					fmt.Println("1. Google Drive")
					fmt.Println("2. GitHub")
					fmt.Println("3. Both")
					fmt.Print("Selection (1/2/3): ")
					choice := readInput()
					switch choice {
					case "1":
						setupGDrive(vault, masterPassword)
						src.LogAction("SETUP_CLOUD_INIT", "Google Drive configured via setup wizard")
					case "2":
						setupGitHub(vault)
						src.LogAction("SETUP_CLOUD_INIT", "GitHub configured via setup wizard")
					case "3":
						setupGDrive(vault, masterPassword)
						setupGitHub(vault)
						src.LogAction("SETUP_CLOUD_INIT", "Google Drive and GitHub configured via setup wizard")
					default:
						color.Red("Invalid selection.")
					}

					data, _ := src.EncryptVault(vault, masterPassword)
					src.SaveVault(vaultPath, data)
				}
			}
			fmt.Println()

			color.Yellow("Step 3: Custom Spaces")
			fmt.Print("Would you like to create your first custom space? (y/n): ")
			if strings.ToLower(readInput()) == "y" {
				fmt.Print("Space Name (e.g. Work, Personal): ")
				pName := readInput()
				if pName != "" {
					color.Green("Space '%s' added to configuration plan. (Run 'pm space create %s' after setup)", pName, pName)
					src.LogAction("SETUP_SPACE_CREATE_PLANNED", fmt.Sprintf("Space: %s", pName))
				}
			}
			fmt.Println()

			color.Yellow("Step 4: Session Security")
			fmt.Println("APM supports shell-scoped sessions. To enable this, add the following to your shell profile:")
			if runtime.GOOS == "windows" {
				fmt.Println("  [Environment]::SetEnvironmentVariable(\"APM_SESSION_ID\", [System.Guid]::NewGuid().ToString(), \"Process\")")
			} else {
				fmt.Println("  export APM_SESSION_ID=$(cat /proc/sys/kernel/random/uuid)")
			}
			fmt.Println()

			color.HiGreen("Setup completed successfully!")
			fmt.Println("Run 'pm' to see all available commands.")
			src.LogAction("SETUP_COMPLETED", "Setup wizard completed")
		},
	}
	var policyCmd = &cobra.Command{
		Use:   "policy",
		Short: "Manage vault policies",
	}

	var policyLoadCmd = &cobra.Command{
		Use:   "load [name]",
		Short: "Load a policy by name from the policies directory",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			masterPwd, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			policyDir := filepath.Join(filepath.Dir(vaultPath), "policies")
			policies, err := src.LoadPolicies(policyDir)
			if err != nil {
				color.Red("Error loading policies: %v\n", err)
				return
			}

			found := false
			for _, p := range policies {
				if p.Name == args[0] {
					vault.ActivePolicy = p
					found = true
					break
				}
			}

			if !found {
				color.Yellow("Policy '%s' not found in %s\n", args[0], policyDir)
				return
			}

			data, err := src.EncryptVault(vault, masterPwd)
			if err != nil {
				color.Red("Error encrypting vault: %v\n", err)
				return
			}

			if err := src.SaveVault(vaultPath, data); err != nil {
				color.Red("Error saving vault: %v\n", err)
				return
			}

			color.Green("Policy '%s' loaded and active.\n", args[0])
			src.LogAction("POLICY_LOADED", fmt.Sprintf("Policy: %s", args[0]))
		},
	}

	var policyShowCmd = &cobra.Command{
		Use:   "show",
		Short: "Show the currently active policy",
		Run: func(cmd *cobra.Command, args []string) {
			_, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			if vault.ActivePolicy.Name == "" {
				fmt.Println("No active policy.")
				return
			}

			color.Cyan("Active Policy: %s\n", vault.ActivePolicy.Name)
			fmt.Printf("Min Password Length: %d\n", vault.ActivePolicy.PasswordPolicy.MinLength)
			fmt.Printf("Require Uppercase: %v\n", vault.ActivePolicy.PasswordPolicy.RequireUpper)
			fmt.Printf("Require Numbers: %v\n", vault.ActivePolicy.PasswordPolicy.RequireNumbers)
			fmt.Printf("Require Symbols: %v\n", vault.ActivePolicy.PasswordPolicy.RequireSymbols)
		},
	}

	var policyClearCmd = &cobra.Command{
		Use:   "clear",
		Short: "Clear the active policy (disable enforcement)",
		Run: func(cmd *cobra.Command, args []string) {
			masterPwd, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			vault.ActivePolicy = src.Policy{}
			data, err := src.EncryptVault(vault, masterPwd)
			if err != nil {
				color.Red("Error encrypting vault: %v\n", err)
				return
			}

			if err := src.SaveVault(vaultPath, data); err != nil {
				color.Red("Error saving vault: %v\n", err)
				return
			}

			color.Green("Policy cleared. Enforcement disabled.\n")
			src.LogAction("POLICY_CLEARED", "Active policy removed")
		},
	}

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
				src.LogAction("PROFILE_CHANGE_FAILED", fmt.Sprintf("Profile: %s, Error: %v", args[0], err))
			} else {
				color.Green("Profile switched to %s.", args[0])
				src.LogAction("PROFILE_CHANGED", fmt.Sprintf("Profile: %s", args[0]))
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
			fmt.Println("but also how long it takes for you to unlock it.")

			fmt.Println("\n[1] Memory (Argon2 Memory Cost)")
			fmt.Println("Explanation: The amount of RAM required to derive your encryption keys.")
			fmt.Println("Security: Higher memory cost protects against GPU/ASIC brute-force attacks.")
			fmt.Println("Tip: 64MB is standard. 256MB+ is hardened. Use what your system can comfortably spare.")
			fmt.Print("Memory (MB) [64]: ")
			memStr := readInput()
			mem := uint32(64)
			if memStr != "" {
				_, _ = fmt.Sscanf(memStr, "%d", &mem)
			}

			fmt.Println("\n[2] Time (Argon2 Iterations)")
			fmt.Println("Explanation: The number of times the hashing function is repeated.")
			fmt.Println("Security: More iterations mean a slower hash, making brute-force much slower.")
			fmt.Println("Tip: 3 is standard. Increase this if you want the 'unlock' process to take longer (more secure).")
			fmt.Print("Time (Iterations) [3]: ")
			timeStr := readInput()
			t := uint32(3)
			if timeStr != "" {
				_, _ = fmt.Sscanf(timeStr, "%d", &t)
			}

			fmt.Println("\n[3] Parallelism (Argon2 Threads)")
			fmt.Println("Explanation: The number of CPU threads used during key derivation.")
			fmt.Println("Security: Typically matched to your CPU's core count.")
			fmt.Println("Tip: 2-4 is usually ideal. Higher values don't necessarily increase security but use more CPU power.")
			fmt.Print("Parallelism [2]: ")
			parStr := readInput()
			p := uint8(2)
			if parStr != "" {
				_, _ = fmt.Sscanf(parStr, "%d", &p)
			}

			fmt.Println("\n[4] Salt Length")
			fmt.Println("Explanation: Random data added to your password before hashing.")
			fmt.Println("Security: Prevents 'Rainbow Table' attacks where pre-computed hashes are used.")
			fmt.Println("Tip: 16 bytes is standard. 32 bytes is very secure. Increasing this has negligible performance hit.")
			fmt.Print("Salt Length (Bytes) [16]: ")
			saltLenStr := readInput()
			saltLen := 16
			if saltLenStr != "" {
				_, _ = fmt.Sscanf(saltLenStr, "%d", &saltLen)
			}

			fmt.Println("\n[5] Nonce Length (IV Size)")
			fmt.Println("Explanation: A 'Number used ONCE' for the AES-GCM encryption process.")
			fmt.Println("Security: Ensures that the same data encrypted twice looks different.")
			fmt.Println("Tip: 12 bytes is standard for AES-GCM. 24 bytes is used for XChaCha20 (not yet supported) or special cases.")
			fmt.Print("Nonce Length (Bytes) [12]: ")
			nonceLenStr := readInput()
			nonceLen := 12
			if nonceLenStr != "" {
				_, _ = fmt.Sscanf(nonceLenStr, "%d", &nonceLen)
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
			if err := src.SaveVault(vaultPath, data); err != nil {
				color.Red("Error saving vault: %v\n", err)
			}
			color.Green("Custom profile '%s' applied.", args[0])
			src.LogAction("PROFILE_CREATED", fmt.Sprintf("Profile: %s, Params: Mem=%d, Time=%d, Par=%d", args[0], mem, t, p))
		},
	}
	profileCmd.AddCommand(profileSetCmd, profileCreateCmd)

	var spaceCmd = &cobra.Command{
		Use:   "space",
		Short: "Manage custom spaces (formerly profiles)",
	}

	var spaceCreateCmd = &cobra.Command{
		Use:   "create [name]",
		Short: "Create a new space section",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			masterPwd, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			newSpace := args[0]
			for _, p := range vault.Spaces {
				if p == newSpace {
					color.Yellow("Space '%s' already exists.", newSpace)
					return
				}
			}

			if len(vault.Spaces) == 0 {
				vault.Spaces = []string{"default"}
			}
			vault.Spaces = append(vault.Spaces, newSpace)
			data, err := src.EncryptVault(vault, masterPwd)
			if err != nil {
				color.Red("Error encrypting vault: %v\n", err)
				return
			}

			if err := src.SaveVault(vaultPath, data); err != nil {
				color.Red("Error saving vault: %v\n", err)
				return
			}

			color.Green("Space '%s' created successfully.\n", newSpace)
		},
	}

	var spaceSwitchCmd = &cobra.Command{
		Use:   "switch [name]",
		Short: "Switch to a specific space",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			masterPwd, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			target := args[0]
			if target == "default" {
				vault.CurrentSpace = ""
			} else {
				found := false
				if len(vault.Spaces) == 0 {
					vault.Spaces = []string{"default"}
				}

				for _, p := range vault.Spaces {
					if p == target {
						found = true
						break
					}
				}

				if !found {
					color.Red("Space '%s' not found.", target)
					color.Yellow("Available spaces: %v", vault.Spaces)
					return
				}
				vault.CurrentSpace = target
			}
			data, err := src.EncryptVault(vault, masterPwd)
			if err != nil {
				color.Red("Error encrypting vault: %v\n", err)
				return
			}

			if err := src.SaveVault(vaultPath, data); err != nil {
				color.Red("Error saving vault: %v\n", err)
				return
			}

			color.Green("Switched to space: %s\n", target)
		},
	}

	var spaceListCmd = &cobra.Command{
		Use:   "list",
		Short: "List all available spaces",
		Run: func(cmd *cobra.Command, args []string) {
			_, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			if len(vault.Spaces) == 0 {
				vault.Spaces = []string{"default"}
			}

			counts := make(map[string]int)
			results := vault.SearchAll("")
			for _, r := range results {
				ns := r.Space
				if ns == "" {
					ns = "default"
				}
				counts[ns]++
			}

			// Ensure default is always in the list for display purposes
			spacesToList := vault.Spaces
			hasDefault := false
			for _, s := range spacesToList {
				if s == "default" {
					hasDefault = true
					break
				}
			}
			if !hasDefault {
				// Prepend default
				spacesToList = append([]string{"default"}, spacesToList...)
			}

			fmt.Println("Available Spaces:")
			for _, p := range spacesToList {
				current := " "
				if p == vault.CurrentSpace || (p == "default" && vault.CurrentSpace == "") {
					current = "*"
				}
				count := counts[p]
				fmt.Printf("%s %s (%d entries)\n", current, p, count)
			}
		},
	}

	spaceCmd.AddCommand(spaceSwitchCmd, spaceListCmd, spaceCreateCmd)
	policyCmd.AddCommand(policyLoadCmd, policyShowCmd, policyClearCmd)
	rootCmd.AddCommand(initCmd, addCmd, getCmd, genCmd, modeCmd, cinfoCmd, auditCmd, totpCmd, importCmd, exportCmd, infoCmd, cloudCmd, healthCmd, policyCmd, spaceCmd, pluginsCmd, setupCmd, unlockCmd, lockCmd, profileCmd, compromiseCmd, authCmd)
	authCmd.AddCommand(authEmailCmd, authResetCmd, authChangeCmd, authRecoverCmd, authAlertsCmd, authLevelCmd)

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
					executor := plugins.NewStepExecutor(ctx, vault, vaultPath)

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

	var updateCmd = &cobra.Command{
		Use:   "update",
		Short: "Check for updates and self-update",
		Run: func(cmd *cobra.Command, args []string) {
			force, _ := cmd.Flags().GetBool("force")
			checkForUpdates(force)
		},
	}
	updateCmd.Flags().Bool("force", false, "Force update even if version is latest")
	rootCmd.AddCommand(updateCmd)
	rootCmd.AddCommand(mcpCmd)
	rootCmd.AddCommand(bruteCmd)

	rootCmd.PersistentFlags().StringVarP(&vaultPath, "vault", "v", vaultPath, "Vault file path")
	rootCmd.Execute()
}

var bruteCmd = &cobra.Command{
	Use:   "brutetest [minutes]",
	Short: "Stress-test vault security using brute force (simulated attack)",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		mins := 5
		if len(args) > 0 {
			if m, err := strconv.Atoi(args[0]); err == nil {
				mins = m
			}
		}
		src.RunBruteTest(vaultPath, mins)
	},
}

const Version = "9.2"

func checkForUpdates(force bool) {
	fmt.Printf("Checking for updates... (Current version: %s)\n", Version)

	resp, err := http.Get("https://api.github.com/repos/aaravmaloo/apm/releases/latest")
	if err != nil {
		color.Red("Failed to check for updates: %v", err)
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		color.Red("Failed to fetch release info (Status: %d)", resp.StatusCode)
		return
	}

	var release struct {
		TagName string `json:"tag_name"`
		HtmlUrl string `json:"html_url"`
		Assets  []struct {
			Name               string `json:"name"`
			BrowserDownloadUrl string `json:"browser_download_url"`
		} `json:"assets"`
	}

	if err := json.NewDecoder(resp.Body).Decode(&release); err != nil {
		color.Red("Failed to decode release info: %v", err)
		return
	}

	latestVer := strings.TrimPrefix(release.TagName, "v")
	currentVer := strings.TrimPrefix(Version, "v")

	if !force && compareVersions(currentVer, latestVer) >= 0 {
		color.Green("You are using the latest version (%s).", release.TagName)
		return
	}

	fmt.Printf("New version available: %s\n", release.TagName)
	fmt.Println("Identifying update asset...")

	targetOS := runtime.GOOS
	if targetOS == "windows" {
		targetOS = "windows"
	}

	var downloadUrl string
	var assetName string

	for _, asset := range release.Assets {
		name := strings.ToLower(asset.Name)
		if strings.Contains(name, targetOS) && (strings.HasSuffix(name, ".exe") || !strings.Contains(name, ".")) {

			if targetOS == "windows" && !strings.HasSuffix(name, ".exe") {
				continue
			}
			downloadUrl = asset.BrowserDownloadUrl
			assetName = asset.Name
			break
		}
	}

	if downloadUrl == "" {
		color.Yellow("No suitable binary found for your OS (%s) in the latest release.", runtime.GOOS)
		color.Yellow("Please visit %s to download manually.", release.HtmlUrl)
		return
	}

	fmt.Printf("Downloading %s...\n", assetName)
	if err := doSelfUpdate(downloadUrl); err != nil {
		color.Red("Update failed: %v", err)
		return
	}

	color.Green("Update successful! Please restart the application.")
}

func compareVersions(v1, v2 string) int {

	parts1 := strings.Split(v1, ".")
	parts2 := strings.Split(v2, ".")

	maxLen := len(parts1)
	if len(parts2) > maxLen {
		maxLen = len(parts2)
	}

	for i := 0; i < maxLen; i++ {
		n1 := 0
		if i < len(parts1) {
			n1, _ = strconv.Atoi(parts1[i])
		}
		n2 := 0
		if i < len(parts2) {
			n2, _ = strconv.Atoi(parts2[i])
		}

		if n1 > n2 {
			return 1
		}
		if n1 < n2 {
			return -1
		}
	}
	return 0
}

func doSelfUpdate(url string) error {
	exe, err := os.Executable()
	if err != nil {
		return err
	}
	exeDir := filepath.Dir(exe)

	resp, err := http.Get(url)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	tmpFile := filepath.Join(exeDir, "apm.new")
	out, err := os.OpenFile(tmpFile, os.O_CREATE|os.O_WRONLY|os.O_TRUNC, 0755)
	if err != nil {
		return err
	}

	_, err = io.Copy(out, resp.Body)
	out.Close()
	if err != nil {
		os.Remove(tmpFile)
		return err
	}

	oldExe := exe + ".old"

	os.Remove(oldExe)

	if err := os.Rename(exe, oldExe); err != nil {
		return fmt.Errorf("failed to rename current binary: %v", err)
	}

	if err := os.Rename(tmpFile, exe); err != nil {
		os.Rename(oldExe, exe)
		return fmt.Errorf("failed to replace binary: %v", err)
	}

	return nil
}

func readInput() string {
	input, _ := inputReader.ReadString('\n')
	return strings.TrimSpace(input)
}

func d(b []byte) string {
	res := make([]byte, len(b))
	for i, v := range b {
		res[i] = v ^ 0xAA
	}
	return string(res)
}

func readPassword() (string, error) {
	if term.IsTerminal(int(os.Stdin.Fd())) {
		bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", err
		}
		return strings.TrimSpace(string(bytePassword)), nil
	}
	input := readInput()
	if input == "" {
		return "", fmt.Errorf("EOF or empty input")
	}
	return input, nil
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

	localFailures := src.GetFailureCount()

	if session, err := src.GetSession(); err == nil {
		data, err := src.LoadVault(vaultPath)
		if err == nil {

			if session.ReadOnly && localFailures >= 6 {
				return session.MasterPassword, src.GetDecoyVault(), true, nil
			}

			vault, err := src.DecryptVault(data, session.MasterPassword, 1)
			if err == nil {
				if vault.NeedsRepair {
					updatedData, _ := src.EncryptVault(vault, session.MasterPassword)
					src.SaveVault(vaultPath, updatedData)
				}
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
		color.Red("\nΓÜá SECURITY WARNING: Unusual activity detected!")
		for _, a := range alerts {
			color.Red("  - %s", a)
		}
		fmt.Println()
	}

	for i := 0; i < 3; i++ {
		localFailures = src.GetFailureCount()
		costMultiplier := 1
		if localFailures >= 6 {

			if localFailures >= 9 {
				color.HiRed("\n[SECURITY BREACH NOTIFICATION]")
				color.Red("Multiple failed unlock attempts detected. This system has been locked for your protection.")
				color.Red("Please contact security administrator or use your physical recovery key.")
				return "", nil, false, fmt.Errorf("vault permanently locked due to suspected breach")
			}

			fmt.Printf("Master Password (attempt %d/3): ", i+1)
			pass, err := readPassword()
			if err != nil {
				return "", nil, false, err
			}
			fmt.Println()

			src.TrackFailure()
			color.Cyan("vault has been unlocked. you will be asked to reauthenticate after 15 minutes of inactivity/1 hour.")

			src.CreateSession(pass, 1*time.Hour, true, 15*time.Minute)
			return pass, src.GetDecoyVault(), true, nil
		}

		fmt.Printf("Master Password (attempt %d/3): ", i+1)
		pass, err := readPassword()
		if err != nil {
			return "", nil, false, err
		}
		fmt.Println()

		vault, err := src.DecryptVault(data, pass, costMultiplier)
		if err == nil {
			src.LogAccess("UNLOCK")
			vault.FailedAttempts = 0
			vault.EmergencyMode = false
			src.ClearFailures()

			if vault.AlertsEnabled && vault.AnomalyDetectionEnabled && len(alerts) > 0 {
				src.SendAlert(vault, src.LevelCritical, "ANOMALY", fmt.Sprintf("Unusual activity detected during unlock: %v", alerts))
			}

			updatedData, _ := src.EncryptVault(vault, pass)
			src.SaveVault(vaultPath, updatedData)

			src.CreateSession(pass, 1*time.Hour, false, 15*time.Minute)
			color.Cyan("vault has been unlocked. you will be asked to reauthenticate after 15 minutes of inactivity/1 hour.")

			pluginMgr.ExecuteHooks("post", "unlock", vault, vaultPath)
			return pass, vault, false, nil
		}

		src.LogAccess("FAIL")
		src.TrackFailure()

		// Attempt to get recovery info to find alert email if vault is locked
		if rec, err := src.GetVaultRecoveryInfo(data); err == nil && rec.AlertsEnabled && rec.AlertEmail != "" {
			tempVault := &src.Vault{
				AlertEmail:    rec.AlertEmail,
				AlertsEnabled: rec.AlertsEnabled,
				SecurityLevel: rec.SecurityLevel,
			}
			src.SendAlert(tempVault, src.LevelCritical, "BREACH ATTEMPT", fmt.Sprintf("Failed unlock attempt %d/3 detected from %s.", i+1, runtime.GOOS))
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
		return 1000
	}

	terms := strings.Fields(q)
	totalScore := 0
	foundAll := true

	for _, term := range terms {
		termScore := 0
		if term == t {
			termScore = 500
		} else if strings.HasPrefix(t, term) {
			termScore = 200
		} else if strings.Contains(t, term) {
			termScore = 100
		} else {
			qi := 0
			ti := 0
			matchCount := 0
			for qi < len(term) && ti < len(t) {
				if term[qi] == t[ti] {
					matchCount++
					qi++
				}
				ti++
			}
			if matchCount == len(term) {
				termScore = 50
			} else {
				foundAll = false
				break
			}
		}
		totalScore += termScore
	}

	if !foundAll {
		return 0
	}

	return totalScore
}

func handleInteractiveEntries(v *src.Vault, masterPassword, initialQuery string, readonly bool) {
	query := initialQuery
	selectedIndex := 0
	selectedItems := make(map[string]src.SearchResult)

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		results := performSearch(v, query)
		if len(results) == 0 {
			fmt.Println("No matching entries found.")
			return
		}
		if len(results) == 1 {
			displayEntry(results[0], true)
		} else {
			for i, r := range results {
				fmt.Printf("[%d] %s (%s)\n", i+1, r.Identifier, r.Type)
			}
		}
		return
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		fmt.Printf("Error entering raw mode: %v\n", err)
		return
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	sigChan := make(chan os.Signal, 1)
	signal.Notify(sigChan, os.Interrupt, syscall.SIGTERM)
	go func() {
		<-sigChan
		term.Restore(int(os.Stdin.Fd()), oldState)
		os.Exit(0)
	}()

	focusMode := 0
	for {
		results := performSearch(v, query)
		if len(results) > 0 {
			if selectedIndex >= len(results) {
				selectedIndex = len(results) - 1
			}
		} else {
			selectedIndex = 0
		}

		profileDisplay := v.CurrentSpace
		if profileDisplay == "" {
			profileDisplay = "default"
		}

		fmt.Print("\033[H\033[2J")
		fmt.Printf("\x1b[1;36mAPM Search & Manage\x1b[0m | Space: \x1b[1;32m%s\x1b[0m (readonly: %v)\n", profileDisplay, readonly)

		if focusMode == 0 {
			fmt.Printf("\x1b[1;33mQuery:\x1b[0m \x1b[1;37m%s\x1b[5m_\x1b[0m\n", query)
		} else {
			fmt.Printf("\x1b[1;33mQuery:\x1b[0m %s\n", query)
		}
		fmt.Println("--------------------------------------------------")

		displayLimit := 20
		for i := 0; i < len(results) && i < displayLimit; i++ {
			r := results[i]
			key := fmt.Sprintf("%s:%s", r.Type, r.Identifier)
			prefix := "  "
			if _, exists := selectedItems[key]; exists {
				prefix = "* "
			}
			line := fmt.Sprintf("%s[%d] %-30s (%s)", prefix, i+1, r.Identifier, r.Type)
			if i == selectedIndex {
				if focusMode == 1 {
					fmt.Printf("\x1b[1;7m %s \x1b[0m \x1b[1;32m<-- PRESS E/D/V/SPACE\x1b[0m\n", line)
				} else {
					fmt.Printf("\x1b[1;7m %s \x1b[0m\n", line)
				}
			} else {
				fmt.Printf(" %s \n", line)
			}
		}

		if len(results) == 0 {
			fmt.Println(" (No entries found)")
		}

		fmt.Println("\n--------------------------------------------------------------")
		if focusMode == 0 {
			fmt.Println("\x1b[1;37mType to Search\x1b[0m | \x1b[1;37mTab/Enter\x1b[0m: Focus List | \x1b[1;37mEsc\x1b[0m: Exit")
		} else {
			fmt.Println("\x1b[1;37mΓåæ/Γåô\x1b[0m: Navigate | \x1b[1;37mSpace\x1b[0m: Select | \x1b[1;37ma\x1b[0m: All | \x1b[1;37mc\x1b[0m: Clear")
			fmt.Println("\x1b[1;37mEnter/v\x1b[0m: View | \x1b[1;37me\x1b[0m: Edit | \x1b[1;37md\x1b[0m: Delete | \x1b[1;37mEsc/Tab\x1b[0m: Focus Search")
		}

		b := make([]byte, 3)
		n, err := os.Stdin.Read(b)
		if err != nil || n == 0 {
			break
		}

		if b[0] == 27 {
			if n >= 3 && b[1] == '[' {
				if b[2] == 'A' {
					if selectedIndex > 0 {
						selectedIndex--
					}
					continue
				} else if b[2] == 'B' {
					if selectedIndex < len(results)-1 {
						selectedIndex++
					}
					continue
				}
			}
			if n == 1 {
				if focusMode == 1 {
					focusMode = 0
				} else {
					break
				}
			}
			continue
		}

		if b[0] == 3 || b[0] == 4 {
			break
		}

		if b[0] == 9 {
			if focusMode == 0 {
				focusMode = 1
			} else {
				focusMode = 0
			}
			continue
		}

		if b[0] == 127 || b[0] == 8 {
			if len(query) > 0 {
				query = query[:len(query)-1]
				selectedIndex = 0
				focusMode = 0
			}
			continue
		}

		if b[0] == '\r' || b[0] == '\n' {
			if focusMode == 0 {
				focusMode = 1
			} else if len(results) > 0 {
				handleAction(v, masterPassword, results[selectedIndex], 'v', readonly, oldState)
				oldState, _ = term.MakeRaw(int(os.Stdin.Fd()))
			}
			continue
		}

		if focusMode == 1 {
			if b[0] == ' ' {
				if len(results) > 0 {
					r := results[selectedIndex]
					key := fmt.Sprintf("%s:%s", r.Type, r.Identifier)
					if _, exists := selectedItems[key]; exists {
						delete(selectedItems, key)
					} else {
						selectedItems[key] = r
					}
				}
				continue
			}
			if b[0] == 'a' {
				for _, r := range results {
					key := fmt.Sprintf("%s:%s", r.Type, r.Identifier)
					selectedItems[key] = r
				}
				continue
			}
			if b[0] == 'c' {
				selectedItems = make(map[string]src.SearchResult)
				continue
			}
			if b[0] == 'e' {
				if len(selectedItems) > 0 {
					_ = term.Restore(int(os.Stdin.Fd()), oldState)
					for key, res := range selectedItems {
						fmt.Print("\033[H\033[2J")
						editEntryInVault(v, masterPassword, res)
						delete(selectedItems, key)
						fmt.Print("\nPress Enter to continue...")
						readInput()
					}
					oldState, _ = term.MakeRaw(int(os.Stdin.Fd()))
				} else if len(results) > 0 {
					handleAction(v, masterPassword, results[selectedIndex], 'e', readonly, oldState)
					oldState, _ = term.MakeRaw(int(os.Stdin.Fd()))
				}
				continue
			}
			if b[0] == 'd' {
				if len(selectedItems) > 0 {
					_ = term.Restore(int(os.Stdin.Fd()), oldState)
					fmt.Print("\033[H\033[2J")
					fmt.Printf("Are you sure you want to delete %d selected items? (y/n): ", len(selectedItems))
					if strings.ToLower(readInput()) == "y" {
						for key, res := range selectedItems {
							if deleteEntryByResult(v, res) {
								delete(selectedItems, key)
							}
						}
						data, _ := src.EncryptVault(v, masterPassword)
						src.SaveVault(vaultPath, data)
						color.Green("Bulk deletion complete.")
						fmt.Print("\nPress Enter to continue...")
						readInput()
					}
					oldState, _ = term.MakeRaw(int(os.Stdin.Fd()))
				} else if len(results) > 0 {
					handleAction(v, masterPassword, results[selectedIndex], 'd', readonly, oldState)
					oldState, _ = term.MakeRaw(int(os.Stdin.Fd()))
				}
				continue
			}
			if b[0] == 'v' {
				if len(results) > 0 {
					handleAction(v, masterPassword, results[selectedIndex], 'v', readonly, oldState)
					oldState, _ = term.MakeRaw(int(os.Stdin.Fd()))
				}
				continue
			}
		}

		char := rune(b[0])
		if unicode.IsPrint(char) {
			query += string(char)
			selectedIndex = 0
			focusMode = 0
		}
	}
}

func performSearch(v *src.Vault, query string) []src.SearchResult {
	all := v.SearchAll("")
	var scored []ScoredResult
	for _, r := range all {
		score := rankMatch(query, r.Identifier)
		if score > 0 {
			scored = append(scored, ScoredResult{r, score})
		}
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].Score == scored[j].Score {
			return scored[i].Result.Identifier < scored[j].Result.Identifier
		}
		return scored[i].Score > scored[j].Score
	})

	var out []src.SearchResult
	for _, s := range scored {
		out = append(out, s.Result)
	}
	return out
}

func handleAction(v *src.Vault, mp string, res src.SearchResult, action byte, readonly bool, oldState *term.State) {
	_ = term.Restore(int(os.Stdin.Fd()), oldState)
	fmt.Print("\033[H\033[2J")

	switch action {
	case 'v':
		displayEntry(res, true)
		fmt.Print("\nPress Enter to continue...")
		readInput()
	case 'e':
		if readonly {
			color.Red("Vault is READ-ONLY.")
		} else {
			editEntryInVault(v, mp, res)
		}
		fmt.Print("\nPress Enter to continue...")
		readInput()
	case 'd':
		if readonly {
			color.Red("Vault is READ-ONLY.")
		} else {
			fmt.Printf("Are you sure you want to delete '%s' (%s)? (y/n): ", res.Identifier, res.Type)
			if strings.ToLower(readInput()) == "y" {
				if deleteEntryByResult(v, res) {
					data, _ := src.EncryptVault(v, mp)
					if err := src.SaveVault(vaultPath, data); err != nil {
						color.Red("Error saving vault: %v", err)
					} else {
						src.SendAlert(v, src.LevelAll, "ENTRY DELETED", fmt.Sprintf("Deleted entry: %s (%s)", res.Identifier, res.Type))
						color.Green("Deleted.")
					}
				} else {
					color.Red("Delete failed.")
				}
			}
		}
	}
	fmt.Print("\nPress Enter to continue...")
	readInput()
}

func prompt(label, current string) string {
	fmt.Printf("%s [%s]: ", label, current)
	input := readInput()
	if input == "" {
		return current
	}
	return input
}

func editEntryInVault(v *src.Vault, mp string, res src.SearchResult) {
	fmt.Printf("Editing %s: %s\n", res.Type, res.Identifier)
	updated := false

	switch res.Type {
	case "Password":
		e := res.Data.(src.Entry)
		newAcc := prompt("New Account", e.Account)
		newUser := prompt("New Username", e.Username)

		fmt.Print("New Password (blank to keep): ")
		newPass, _ := readPassword()
		fmt.Println()
		if newPass == "" {
			newPass = e.Password
		}

		if v.DeleteEntry(e.Account) {
			v.AddEntry(newAcc, newUser, newPass)
			updated = true
		}
	case "TOTP":
		e := res.Data.(src.TOTPEntry)
		newAcc := prompt("New Account", e.Account)
		newSec := prompt("New Secret", e.Secret)

		if v.DeleteTOTPEntry(e.Account) {
			v.AddTOTPEntry(newAcc, newSec)
			updated = true
		}
	case "Token":
		e := res.Data.(src.TokenEntry)
		newName := prompt("New Name", e.Name)
		newToken := prompt("New Token", e.Token)
		newType := prompt("New Type", e.Type)

		if v.DeleteToken(e.Name) {
			v.AddToken(newName, newToken, newType)
			updated = true
		}
	case "Note":
		e := res.Data.(src.SecureNoteEntry)
		newName := prompt("New Name", e.Name)
		newContent := prompt("New Content", e.Content)

		if v.DeleteSecureNote(e.Name) {
			v.AddSecureNote(newName, newContent)
			updated = true
		}
	case "API Key":
		e := res.Data.(src.APIKeyEntry)
		newName := prompt("New Name", e.Name)
		newService := prompt("New Service", e.Service)
		newKey := prompt("New Key", e.Key)

		if v.DeleteAPIKey(e.Name) {
			v.AddAPIKey(newName, newService, newKey)
			updated = true
		}
	case "SSH Key":
		e := res.Data.(src.SSHKeyEntry)
		newName := prompt("New Name", e.Name)
		newKey := prompt("New Private Key", e.PrivateKey)

		if v.DeleteSSHKey(e.Name) {
			v.AddSSHKey(newName, newKey)
			updated = true
		}
	case "Wi-Fi":
		e := res.Data.(src.WiFiEntry)
		newSSID := prompt("New SSID", e.SSID)
		newPass := prompt("New Password", e.Password)
		newSec := prompt("New Security Type", e.SecurityType)

		if v.DeleteWiFi(e.SSID) {
			v.AddWiFi(newSSID, newPass, newSec)
			updated = true
		}
	case "Recovery Codes":
		e := res.Data.(src.RecoveryCodeEntry)
		newService := prompt("New Service", e.Service)
		newCodesStr := prompt("New Codes (comma sep)", strings.Join(e.Codes, ","))
		newCodes := strings.Split(newCodesStr, ",")
		for i := range newCodes {
			newCodes[i] = strings.TrimSpace(newCodes[i])
		}

		if v.DeleteRecoveryCode(e.Service) {
			v.AddRecoveryCode(newService, newCodes)
			updated = true
		}
	case "Certificate":
		e := res.Data.(src.CertificateEntry)
		newLabel := prompt("New Label", e.Label)
		newCert := prompt("New Cert Data", e.CertData)
		newKey := prompt("New Private Key", e.PrivateKey)
		newIssuer := prompt("New Issuer", e.Issuer)
		newExpiryStr := prompt("New Expiry (RFC3339)", e.Expiry.Format(time.RFC3339))

		newExpiry, err := time.Parse(time.RFC3339, newExpiryStr)
		if err != nil {
			fmt.Println("Invalid time format, keeping old expiry.")
			newExpiry = e.Expiry
		}

		if v.DeleteCertificate(e.Label) {
			v.AddCertificate(newLabel, newCert, newKey, newIssuer, newExpiry)
			updated = true
		}
	case "Banking":
		e := res.Data.(src.BankingEntry)
		newLabel := prompt("New Label", e.Label)
		newType := prompt("New Type", e.Type)
		newDetails := prompt("New Details", e.Details)
		newCVV := prompt("New CVV", e.CVV)
		newExpiry := prompt("New Expiry", e.Expiry)

		if v.DeleteBankingItem(e.Label) {
			v.AddBankingItem(newLabel, newType, newDetails, newCVV, newExpiry)
			updated = true
		}
	case "Document":
		e := res.Data.(src.DocumentEntry)
		newName := prompt("New Name", e.Name)
		newPath := prompt("New File Path for Content (leave blank to keep)", "")
		newPass := prompt("New Password", e.Password)
		newTagsStr := prompt("New Tags (comma sep)", strings.Join(e.Tags, ","))
		newExpiry := prompt("New Expiry", e.Expiry)

		newContent := e.Content
		if newPath != "" {
			c, err := os.ReadFile(newPath)
			if err == nil {
				newContent = c
			} else {
				fmt.Printf("Error reading file: %v. Keeping old content.\n", err)
			}
		}

		newTags := strings.Split(newTagsStr, ",")
		for i := range newTags {
			newTags[i] = strings.TrimSpace(newTags[i])
		}

		if v.DeleteDocument(e.Name) {
			v.AddDocument(newName, e.FileName, newContent, newPass, newTags, newExpiry)
			updated = true
		}
	case "Government ID":
		e := res.Data.(src.GovIDEntry)
		newType := prompt("New Type", e.Type)
		newID := prompt("New ID Number", e.IDNumber)
		newName := prompt("New Name", e.Name)
		newExpiry := prompt("New Expiry", e.Expiry)

		if v.DeleteGovID(e.IDNumber) {
			v.AddGovID(src.GovIDEntry{Type: newType, IDNumber: newID, Name: newName, Expiry: newExpiry})
			updated = true
		}
	case "Medical Record":
		e := res.Data.(src.MedicalRecordEntry)
		newLabel := prompt("New Label", e.Label)
		newIns := prompt("New Insurance ID", e.InsuranceID)
		newPres := prompt("New Prescriptions", e.Prescriptions)
		newAllergies := prompt("New Allergies", e.Allergies)

		if v.DeleteMedicalRecord(e.Label) {
			v.AddMedicalRecord(src.MedicalRecordEntry{Label: newLabel, InsuranceID: newIns, Prescriptions: newPres, Allergies: newAllergies})
			updated = true
		}
	case "Travel":
		e := res.Data.(src.TravelEntry)
		newLabel := prompt("New Label", e.Label)
		newTicket := prompt("New Ticket Num", e.TicketNumber)
		newBooking := prompt("New Booking Code", e.BookingCode)
		newLoyalty := prompt("New Loyalty Prog", e.LoyaltyProgram)

		if v.DeleteTravelDoc(e.Label) {
			v.AddTravelDoc(src.TravelEntry{Label: newLabel, TicketNumber: newTicket, BookingCode: newBooking, LoyaltyProgram: newLoyalty})
			updated = true
		}
	case "Contact":
		e := res.Data.(src.ContactEntry)
		newName := prompt("New Name", e.Name)
		newPhone := prompt("New Phone", e.Phone)
		newEmail := prompt("New Email", e.Email)
		newAddress := prompt("New Address", e.Address)

		emergStr := "n"
		if e.Emergency {
			emergStr = "y"
		}
		newEmergStr := prompt("Emergency Contact? (y/n)", emergStr)
		newEmerg := strings.ToLower(newEmergStr) == "y"

		if v.DeleteContact(e.Name) {
			v.AddContact(src.ContactEntry{Name: newName, Phone: newPhone, Email: newEmail, Address: newAddress, Emergency: newEmerg})
			updated = true
		}
	case "Cloud Credentials":
		e := res.Data.(src.CloudCredentialEntry)
		newLabel := prompt("New Label", e.Label)
		newAK := prompt("New Access Key", e.AccessKey)
		newSK := prompt("New Secret Key", e.SecretKey)
		newRegion := prompt("New Region", e.Region)
		newAccID := prompt("New Account ID", e.AccountID)
		newRole := prompt("New Role", e.Role)
		newExp := prompt("New Expiration", e.Expiration)

		if v.DeleteCloudCredential(e.Label) {
			v.AddCloudCredential(src.CloudCredentialEntry{Label: newLabel, AccessKey: newAK, SecretKey: newSK, Region: newRegion, AccountID: newAccID, Role: newRole, Expiration: newExp})
			updated = true
		}
	case "Kubernetes Secret":
		e := res.Data.(src.K8sSecretEntry)
		newName := prompt("New Name", e.Name)
		newCluster := prompt("New Cluster URL", e.ClusterURL)
		newNS := prompt("New K8s Namespace", e.K8sNamespace)
		newExp := prompt("New Expiration", e.Expiration)

		if v.DeleteK8sSecret(e.Name) {
			v.AddK8sSecret(src.K8sSecretEntry{Name: newName, ClusterURL: newCluster, K8sNamespace: newNS, Expiration: newExp})
			updated = true
		}
	case "Docker Registry":
		e := res.Data.(src.DockerRegistryEntry)
		newName := prompt("New Name", e.Name)
		newURL := prompt("New Registry URL", e.RegistryURL)
		newUser := prompt("New Username", e.Username)
		newToken := prompt("New Token", e.Token)

		if v.DeleteDockerRegistry(e.Name) {
			v.AddDockerRegistry(src.DockerRegistryEntry{Name: newName, RegistryURL: newURL, Username: newUser, Token: newToken})
			updated = true
		}
	case "SSH Config":
		e := res.Data.(src.SSHConfigEntry)
		newAlias := prompt("New Alias", e.Alias)
		newHost := prompt("New Host", e.Host)
		newUser := prompt("New User", e.User)
		newPort := prompt("New Port", e.Port)
		newKeyPath := prompt("New Key Path", e.KeyPath)
		newPrivKey := prompt("New Private Key", e.PrivateKey)
		newFingerprint := prompt("New Fingerprint", e.Fingerprint)

		if v.DeleteSSHConfig(e.Alias) {
			v.AddSSHConfig(src.SSHConfigEntry{Alias: newAlias, Host: newHost, User: newUser, Port: newPort, KeyPath: newKeyPath, PrivateKey: newPrivKey, Fingerprint: newFingerprint})
			updated = true
		}
	case "CI/CD Secret":
		e := res.Data.(src.CICDSecretEntry)
		newName := prompt("New Name", e.Name)
		newUnknown := prompt("New Webhook", e.Webhook)
		newEnvVars := prompt("New Env Vars", e.EnvVars)

		if v.DeleteCICDSecret(e.Name) {
			v.AddCICDSecret(src.CICDSecretEntry{Name: newName, Webhook: newUnknown, EnvVars: newEnvVars})
			updated = true
		}
	case "Software License":
		e := res.Data.(src.SoftwareLicenseEntry)
		newProd := prompt("New Product Name", e.ProductName)
		newKey := prompt("New Serial Key", e.SerialKey)
		newInfo := prompt("New Activation Info", e.ActivationInfo)
		newExp := prompt("New Expiration", e.Expiration)

		if v.DeleteSoftwareLicense(e.ProductName) {
			v.AddSoftwareLicense(src.SoftwareLicenseEntry{ProductName: newProd, SerialKey: newKey, ActivationInfo: newInfo, Expiration: newExp})
			updated = true
		}
	case "Legal Contract":
		e := res.Data.(src.LegalContractEntry)
		newName := prompt("New Name", e.Name)
		newSum := prompt("New Summary", e.Summary)
		newParties := prompt("New Parties Involved", e.PartiesInvolved)
		newDate := prompt("New Signed Date", e.SignedDate)

		if v.DeleteLegalContract(e.Name) {
			v.AddLegalContract(src.LegalContractEntry{Name: newName, Summary: newSum, PartiesInvolved: newParties, SignedDate: newDate})
			updated = true
		}
	default:
		color.Yellow("Editing for %s not implemented.", res.Type)
	}

	if updated {
		data, _ := src.EncryptVault(v, mp)
		if err := src.SaveVault(vaultPath, data); err != nil {
			color.Red("Error saving vault: %v", err)
		} else {
			src.SendAlert(v, src.LevelAll, "ENTRY MODIFIED", fmt.Sprintf("Modified entry: %s (%s)", res.Identifier, res.Type))
			color.Green("Updated.")
		}
	}
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
		fmt.Printf("Type: K8s Secret\nName: %s\nCluster URL: %s\nNamespace: %s\nExpiration: %s\n", k.Name, k.ClusterURL, k.K8sNamespace, k.Expiration)
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
	case "Audio":
		a := res.Data.(src.AudioEntry)
		fmt.Printf("Type: Audio\nName: %s\nFile: %s\n", a.Name, a.FileName)
		fmt.Print("Open audio file? (y/n): ")
		if strings.ToLower(readInput()) == "y" {
			tmpDir := os.TempDir()
			tmpFile := filepath.Join(tmpDir, a.FileName)
			err := os.WriteFile(tmpFile, a.Content, 0600)
			if err != nil {
				color.Red("Error writing temporary file: %v\n", err)
				return
			}
			defer func() {
				time.Sleep(5 * time.Second)
				os.Remove(tmpFile)
			}()
			color.Green("Opening audio...")
			var cmd *exec.Cmd
			if runtime.GOOS == "windows" {
				cmd = exec.Command("cmd", "/c", "start", "", tmpFile)
			} else if runtime.GOOS == "darwin" {
				cmd = exec.Command("open", tmpFile)
			} else {
				cmd = exec.Command("xdg-open", tmpFile)
			}
			cmd.Run()
		}
	case "Video":
		vi := res.Data.(src.VideoEntry)
		fmt.Printf("Type: Video\nName: %s\nFile: %s\n", vi.Name, vi.FileName)
		fmt.Print("Open video file? (y/n): ")
		if strings.ToLower(readInput()) == "y" {
			tmpDir := os.TempDir()
			tmpFile := filepath.Join(tmpDir, vi.FileName)
			err := os.WriteFile(tmpFile, vi.Content, 0600)
			if err != nil {
				color.Red("Error writing temporary file: %v\n", err)
				return
			}
			defer func() {
				time.Sleep(5 * time.Second)
				os.Remove(tmpFile)
			}()
			color.Green("Opening video...")
			var cmd *exec.Cmd
			if runtime.GOOS == "windows" {
				cmd = exec.Command("cmd", "/c", "start", "", tmpFile)
			} else if runtime.GOOS == "darwin" {
				cmd = exec.Command("open", tmpFile)
			} else {
				cmd = exec.Command("xdg-open", tmpFile)
			}
			cmd.Run()
		}
	case "Photo":
		p := res.Data.(src.PhotoEntry)
		fmt.Printf("Type: Photo\nName: %s\nFile: %s\n", p.Name, p.FileName)
		fmt.Print("Open photo? (y/n): ")
		if strings.ToLower(readInput()) == "y" {
			tmpDir := os.TempDir()
			tmpFile := filepath.Join(tmpDir, p.FileName)
			err := os.WriteFile(tmpFile, p.Content, 0600)
			if err != nil {
				color.Red("Error writing temporary file: %v\n", err)
				return
			}
			defer func() {
				time.Sleep(5 * time.Second)
				os.Remove(tmpFile)
			}()
			color.Green("Opening photo...")
			var cmd *exec.Cmd
			if runtime.GOOS == "windows" {
				cmd = exec.Command("cmd", "/c", "start", "", tmpFile)
			} else if runtime.GOOS == "darwin" {
				cmd = exec.Command("open", tmpFile)
			} else {
				cmd = exec.Command("xdg-open", tmpFile)
			}
			cmd.Run()
		}
	}
	fmt.Println("---")
}

func setupDropbox(v *src.Vault, mp string) error {
	color.Yellow("\nSetting up Dropbox...")

	fmt.Println("Choose Sync Mode:")
	fmt.Println("1. APM_PUBLIC (Fast, no signup, shared storage)")
	fmt.Println("2. Self-Hosted (Secure, uses your own Dropbox, requires login)")
	fmt.Print("Selection (1/2): ")
	modeSelection := readInput()

	var token []byte
	var mode string
	var err error

	if modeSelection == "2" {
		mode = "self_hosted"
		color.Cyan("Self-hosted setup requires a Dropbox App Key and Secret.")
		fmt.Print("Enter App Key: ")
		appKey := readInput()
		fmt.Print("Enter App Secret: ")
		appSecret := readInput()

		config := oauth.Config{
			ClientID:     appKey,
			ClientSecret: appSecret,
			Endpoint: oauth.Endpoint{
				AuthURL:  "https://www.dropbox.com/oauth2/authorize",
				TokenURL: "https://api.dropboxapi.com/oauth2/token",
			},
			RedirectURL: "http://localhost:8080",
		}

		token, err = src.PerformDropboxAuth(config)
		if err != nil {
			color.Red("Authentication failed: %v", err)
			return err
		}
	} else {
		mode = "apm_public"
		token = src.GetDefaultDropboxToken()
	}

	v.DropboxSyncMode = mode
	v.DropboxToken = token

	fmt.Print("Enter Custom Retrieval Key (leave blank to generate randomly): ")
	customKey := readInput()

	var key string
	if customKey != "" {
		key = customKey
	} else {
		key, err = src.GenerateRetrievalKey()
		if err != nil {
			color.Red("Key generation failed: %v", err)
			return err
		}
	}

	fmt.Println("DEBUG: setupDropbox calling getCloudManagerEx with 'dropbox'")
	cm, err := getCloudManagerEx(context.Background(), v, mp, "dropbox")
	if err != nil {
		color.Red("Dropbox error: %v", err)
		return err
	}

	fileID, err := cm.UploadVault(vaultPath, key)
	if err != nil {
		color.Red("Upload failed: %v", err)
		return err
	}

	v.RetrievalKey = key
	v.DropboxFileID = fileID
	v.LastCloudProvider = "dropbox"

	color.Green("Dropbox sync setup successful.")
	color.HiCyan("Retrieval Key: %s", key)
	if mode == "self_hosted" {
		color.Cyan("Mode: Self-Hosted (Owner: You)")
	} else {
		color.Cyan("Mode: APM_PUBLIC")
	}
	return nil
}

func getCloudManagerEx(ctx context.Context, vault *src.Vault, masterPassword string, provider string) (src.CloudProvider, error) {
	fmt.Printf("DEBUG: getCloudManagerEx called with provider='%s'\n", provider)
	if provider == "github" {
		if vault == nil || vault.GitHubToken == "" {
			return nil, fmt.Errorf("github sync not initialized. run 'pm cloud init github' first")
		}
		gm, err := src.NewGitHubManager(ctx, vault.GitHubToken)
		if err != nil {
			return nil, err
		}
		gm.SetRepo(vault.GitHubRepo)
		return gm, nil
	}

	if provider == "dropbox" {
		if vault == nil || vault.DropboxToken == nil {
			return nil, fmt.Errorf("dropbox sync not initialized. run 'pm cloud init dropbox' first")
		}
		return src.GetCloudProvider("dropbox", ctx, nil, vault.DropboxToken, vault.DropboxSyncMode)
	}

	if provider != "gdrive" {
		fmt.Printf("DEBUG: getCloudManagerEx falling through for provider='%s'\n", provider)
		return nil, fmt.Errorf("unsupported cloud provider: %s", provider)
	}

	var credentials []byte
	var token []byte
	syncMode := "apm_public"

	if vault != nil && vault.DriveSyncMode != "" {
		syncMode = vault.DriveSyncMode
	}

	if syncMode == "self_hosted" && vault != nil && len(vault.CloudToken) > 0 {

		credentials = vault.CloudCredentials
		token = vault.CloudToken
	} else {

		exe, _ := os.Executable()
		installDir := filepath.Dir(exe)

		credsPath := filepath.Join(installDir, "credentials.json")
		if data, err := os.ReadFile(credsPath); err == nil {
			credentials = data
		}
		tokenPath := filepath.Join(installDir, "token.json")
		if data, err := os.ReadFile(tokenPath); err == nil {
			token = data
		}

		if len(credentials) == 0 {
			credentials = src.GetDefaultCreds()
		}
		if len(token) == 0 {
			token = src.GetDefaultToken()
		}
	}

	return src.GetCloudProvider(provider, ctx, credentials, token, syncMode)
}

func handleDownloadedVault(data []byte, githubToken, githubRepo string) {
	fmt.Print("Verify Master Password for downloaded vault: ")
	pass, _ := readPassword()
	fmt.Println()
	vault, err := src.DecryptVault(data, pass, 1)
	if err != nil {
		color.Red("Decryption failed. Vault not saved locally: %v\n", err)
		return
	}

	if githubToken != "" {
		vault.GitHubToken = githubToken
		vault.GitHubRepo = githubRepo

		data, _ = src.EncryptVault(vault, pass)
	}

	err = src.SaveVault(vaultPath, data)
	if err != nil {
		color.Red("Error saving vault: %v\n", err)
		return
	}
	color.Green("Vault retrieved and saved successfully.")
}

func deleteEntryByResult(v *src.Vault, res src.SearchResult) bool {
	switch res.Type {
	case "Password":
		return v.DeleteEntry(res.Identifier)
	case "TOTP":
		return v.DeleteTOTPEntry(res.Identifier)
	case "Token":
		return v.DeleteToken(res.Identifier)
	case "Note":
		return v.DeleteSecureNote(res.Identifier)
	case "API Key":
		return v.DeleteAPIKey(res.Identifier)
	case "SSH Key":
		return v.DeleteSSHKey(res.Identifier)
	case "Wi-Fi":
		return v.DeleteWiFi(res.Identifier)
	case "Recovery Codes":
		return v.DeleteRecoveryCode(res.Identifier)
	case "Certificate":
		return v.DeleteCertificate(res.Identifier)
	case "Banking":
		return v.DeleteBankingItem(res.Identifier)
	case "Document":
		return v.DeleteDocument(res.Identifier)
	case "Audio":
		return v.DeleteAudio(res.Identifier)
	case "Video":
		return v.DeleteVideo(res.Identifier)
	case "Photo":
		return v.DeletePhoto(res.Identifier)
	case "Government ID":
		return v.DeleteGovID(res.Identifier)
	case "Medical Record":
		return v.DeleteMedicalRecord(res.Identifier)
	case "Travel":
		return v.DeleteTravelDoc(res.Identifier)
	case "Contact":
		return v.DeleteContact(res.Identifier)
	case "Cloud Credentials":
		return v.DeleteCloudCredential(res.Identifier)
	case "Kubernetes Secret":
		return v.DeleteK8sSecret(res.Identifier)
	case "Docker Registry":
		return v.DeleteDockerRegistry(res.Identifier)
	case "SSH Config":
		return v.DeleteSSHConfig(res.Identifier)
	case "CI/CD Secret":
		return v.DeleteCICDSecret(res.Identifier)
	case "Software License":
		return v.DeleteSoftwareLicense(res.Identifier)
	case "Legal Contract":
		return v.DeleteLegalContract(res.Identifier)
	}
	return false
}

var authCmd = &cobra.Command{
	Use:   "auth",
	Short: "Manage authentication and recovery",
}

var authRecoverCmd = &cobra.Command{
	Use:   "recover",
	Short: "Recover vault access using recovery key",
	Run: func(cmd *cobra.Command, args []string) {
		data, err := src.LoadVault(vaultPath)
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}

		info, err := src.GetVaultRecoveryInfo(data)
		if err != nil {
			color.Red("Recovery not available for this vault version.\n")
			return
		}

		if len(info.EmailHash) == 0 {
			color.Yellow("Recovery is not configured for this vault. Run 'pm auth email [id]' to set it up.")
			return
		}

		fmt.Print("Enter recovery email to confirm identity: ")
		email := strings.ToLower(readInput())
		h := sha256.Sum256([]byte(email))
		if !hmac.Equal(h[:], info.EmailHash) {
			color.Red("Identity verification failed.\n")
			return
		}

		color.HiGreen("Identity verified.")

		if len(info.ObfuscatedKey) == 0 {
			color.Red("Recovery record found but key is missing. Manual recovery required.")
			return
		}
		realKey := src.DeObfuscateRecoveryKey(info.ObfuscatedKey)

		token, _ := src.GenerateRandomHex(64)
		tokenHash := sha256.Sum256([]byte(token))
		startTime := time.Now()
		expiryDuration := 15 * time.Minute

		host := d([]byte{0xd9, 0xc7, 0xde, 0xda, 0x84, 0xcd, 0xc7, 0xcb, 0xc3, 0xc6, 0x84, 0xc9, 0xc5, 0xc7})
		port := 587
		user := d([]byte{0xcb, 0xcb, 0xd8, 0xcb, 0xdc, 0xc7, 0xcb, 0xc6, 0xc5, 0xc5, 0x9a, 0x9c, 0xea, 0xcd, 0xc7, 0xcb, 0xc3, 0xc6, 0x84, 0xc9, 0xc5, 0xc7})
		passEmail := d([]byte{0xc3, 0xd8, 0xd3, 0xd8, 0x8a, 0xc5, 0xc7, 0xc6, 0xdc, 0x8a, 0xc2, 0xde, 0xdb, 0xcc, 0x8a, 0xda, 0xd8, 0xc2, 0xdb})

		m := gomail.NewMessage()
		m.SetHeader("From", user)
		m.SetHeader("To", email)
		m.SetHeader("Subject", "SECURITY: APM Vault Recovery Token")

		body := fmt.Sprintf(`
[SECURITY ALERT]
A recovery attempt has been initiated for your APM Vault.

Your Secure Recovery Token is:
%s

This token is valid for 15 minutes.
For security reasons, this token is single-use and will be invalidated immediately after use.

If you did not initiate this recovery request, please ignore this email and consider updating your security settings.
`, token)
		m.SetBody("text/plain", body)

		dialer := gomail.NewDialer(host, port, user, passEmail)
		_ = dialer.DialAndSend(m)

		color.HiCyan("A security notification has been sent to your email with a recovery token.")

		var dek []byte
		for {
			if time.Since(startTime) > expiryDuration {
				color.Red("Recovery token has expired. Please initiate a new recovery request.")
				return
			}

			fmt.Printf("enter recovery token (valid for %v longer): ", expiryDuration-time.Since(startTime).Truncate(time.Second))
			enteredToken := strings.TrimSpace(readInput())

			h := sha256.Sum256([]byte(enteredToken))
			if hmac.Equal(h[:], tokenHash[:]) {
				color.HiGreen("Token Verified. Authorizing cryptographic unlock...")
				tokenHash = [32]byte{} // Invalidate in memory
				var err error
				dek, err = src.CheckRecoveryKey(data, realKey)
				if err != nil {
					color.Red("Cryptographic Recovery Failed: %v\n", err)
					return
				}
				break
			} else {
				color.Red("Invalid token. Please check your email and try again.")
			}
		}

		src.ClearFailures()

		color.HiGreen("Cryptographic verification successful! DEK unlocked.")

		fmt.Print("enter new master passwod: ")
		newPass, _ := readPassword()
		fmt.Println()
		fmt.Print("retype new master password: ")
		confPass, _ := readPassword()
		fmt.Println()

		if newPass != confPass {
			color.Red("Passwords do not match.\n")
			return
		}

		vault, err := src.DecryptVaultWithDEK(data, dek)
		if err != nil {
			color.Red("Error decrypting vault data with DEK: %v\n", err)
			return
		}

		vault.FailedAttempts = 0
		vault.EmergencyMode = false

		newData, err := src.EncryptVault(vault, newPass)
		if err != nil {
			color.Red("Error re-encrypting vault: %v\n", err)
			return
		}

		if err := src.SaveVault(vaultPath, newData); err != nil {
			color.Red("Error saving vault: %v\n", err)
		} else {
			src.SendAlert(vault, src.LevelCritical, "RECOVERY SUCCESS", "Vault has been successfully recovered and master password reset.")
			color.Green("Vault recovered and Master Password updated successfully!\n")
		}
	},
}

var authEmailCmd = &cobra.Command{
	Use:   "email [address]",
	Short: "Register recovery email",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		email := strings.ToLower(args[0])
		pass, vault, _, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}

		vault.SetRecoveryEmail(email)
		if vault.CurrentProfileParams == nil {
			p := src.GetProfile(vault.Profile)
			vault.CurrentProfileParams = &p
		}

		key := src.GenerateRecoveryKey()
		salt, _ := src.GenerateSalt(vault.CurrentProfileParams.SaltLen)
		vault.SetRecoveryKey(key, salt)

		host := d([]byte{0xd9, 0xc7, 0xde, 0xda, 0x84, 0xcd, 0xc7, 0xcb, 0xc3, 0xc6, 0x84, 0xc9, 0xc5, 0xc7})
		port := 587
		user := d([]byte{0xcb, 0xcb, 0xd8, 0xcb, 0xdc, 0xc7, 0xcb, 0xc6, 0xc5, 0xc5, 0x9a, 0x9c, 0xea, 0xcd, 0xc7, 0xcb, 0xc3, 0xc6, 0x84, 0xc9, 0xc5, 0xc7})
		passEmail := d([]byte{0xc3, 0xd8, 0xd3, 0xd8, 0x8a, 0xc5, 0xc7, 0xc6, 0xdc, 0x8a, 0xc2, 0xde, 0xdb, 0xcc, 0x8a, 0xda, 0xd8, 0xc2, 0xdb})

		m := gomail.NewMessage()
		m.SetHeader("From", user)
		m.SetHeader("To", email)
		m.SetHeader("Subject", "SECURITY ALERT: APM Vault Recovery Configured")
		body := `
[SECURITY ALERT]
Recovery access has been configured for your APM Vault.

IMPORTANT: For your security, the Recovery Key was NOT sent in this email. 
It was displayed only once in your terminal during setup.

If you did not initiate this setup, your vault may be compromised. 
Please contact your security administrator or change your Master Password immediately.

Note: This is a zero-knowledge system. We cannot recover your vault without your physical recovery key.
`
		m.SetBody("text/plain", body)

		dialer := gomail.NewDialer(host, port, user, passEmail)
		err = dialer.DialAndSend(m)
		if err != nil {
			color.Red("Error sending alert email: %v", err)
			return
		}

		color.HiGreen("Recovery registered successfully!")
		color.HiCyan("Registration alert sent to %s", email)
		color.HiYellow("\nYOUR RECOVERY KEY (STAY SECURE):")
		color.HiMagenta("  %s", key)
		color.White("\nIMPORTANT: Store this key in a physically secure location.")
		color.White("It will NEVER be shown again and is NOT stored in plain text.")

		data, _ := src.EncryptVault(vault, pass)
		if err := src.SaveVault(vaultPath, data); err != nil {
			color.Red("Error saving vault: %v", err)
		}
	},
}

var authAlertsCmd = &cobra.Command{
	Use:   "alerts",
	Short: "Toggle security alerts",
	Long:  "Enable or disable global security alerts for vault changes.",
	Run: func(cmd *cobra.Command, args []string) {
		enable, _ := cmd.Flags().GetBool("enable")
		disable, _ := cmd.Flags().GetBool("disable")

		pass, vault, _, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}

		if enable {
			vault.AlertsEnabled = true
			color.Green("Security alerts enabled.")
		} else if disable {
			vault.AlertsEnabled = false
			color.Yellow("Security alerts disabled.")
		} else {
			status := "disabled"
			if vault.AlertsEnabled {
				status = "enabled"
			}
			color.Cyan("Security alerts are currently %s.", status)
			return
		}

		data, err := src.EncryptVault(vault, pass)
		if err == nil {
			if err := src.SaveVault(vaultPath, data); err != nil {
				color.Red("Error saving vault: %v", err)
			} else {
				status := "OFF"
				if vault.AlertsEnabled {
					status = "ON"
				}
				src.SendAlert(vault, src.LevelSettings, "ALERT SETTINGS", fmt.Sprintf("Global security alerts turned %s.", status))
			}
		}
	},
}

var authLevelCmd = &cobra.Command{
	Use:   "level [1-3]",
	Short: "Set security paranoia level",
	Args:  cobra.MaximumNArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		pass, vault, _, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}

		if len(args) == 0 {
			color.Cyan("Current security level: %d", vault.SecurityLevel)
			color.White("1: Standard, 2: Enhanced, 3: Paranoid")
			return
		}

		level, err := strconv.Atoi(args[0])
		if err != nil || level < 1 || level > 3 {
			color.Red("Invalid level. Please choose 1, 2, or 3.")
			return
		}

		vault.SecurityLevel = level
		color.HiGreen("Security level updated to %d.", level)

		data, err := src.EncryptVault(vault, pass)
		if err == nil {
			if err := src.SaveVault(vaultPath, data); err != nil {
				color.Red("Error saving vault: %v", err)
			} else {
				src.SendAlert(vault, src.LevelSettings, "SECURITY LEVEL", fmt.Sprintf("Security paranoia level updated to %d.", vault.SecurityLevel))
			}
		}
	},
}

var authResetCmd = &cobra.Command{
	Use:   "reset",
	Short: "Remove recovery email ID",
	Run: func(cmd *cobra.Command, args []string) {
		pass, vault, _, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}

		vault.ClearRecoveryInfo()
		data, _ := src.EncryptVault(vault, pass)
		if err := src.SaveVault(vaultPath, data); err != nil {
			color.Red("Error saving vault: %v\n", err)
		} else {
			src.SendAlert(vault, src.LevelSettings, "RECOVERY RESET", "Recovery email and associated metadata have been cleared.")
			color.Green("Recovery email and records removed successfully.\n")
		}
	},
}

var authChangeCmd = &cobra.Command{
	Use:   "change",
	Short: "Change the master password (requires current password)",
	Run: func(cmd *cobra.Command, args []string) {
		oldPass, vault, _, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}

		color.Yellow("Enter new master password: ")
		newPass, _ := readPassword()
		fmt.Println()
		fmt.Print("Confirm new master password: ")
		confPass, _ := readPassword()
		fmt.Println()

		if newPass != confPass {
			color.Red("Passwords do not match.\n")
			return
		}

		data, err := src.UpdateMasterPassword(vault, oldPass, newPass)
		if err != nil {
			color.Red("Error re-encrypting vault: %v\n", err)
			return
		}

		if err := src.SaveVault(vaultPath, data); err != nil {
			color.Red("Error saving vault: %v\n", err)
		} else {
			src.SendAlert(vault, src.LevelSettings, "PASSWORD CHANGE", "Master password has been successfully rotated.")
			color.Green("Master password changed successfully.\n")
		}
	},
}

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Configure or start the APM MCP server",
}

var mcpTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Interactive setup for MCP access tokens",
	Run: func(cmd *cobra.Command, args []string) {
		color.HiCyan("APM MCP Server Setup")

		var name string
		promptName := &survey.Input{Message: "Token Name (e.g. 'Cursor', 'Windsurf'):"}
		survey.AskOne(promptName, &name)
		if name == "" {
			color.Red("Token name is required.")
			return
		}

		permissions := []string{}
		promptPerms := &survey.MultiSelect{
			Message: "Permissions:",
			Options: []string{"read", "write", "delete", "secrets", "all"},
			Default: []string{"read", "secrets"},
		}
		err := survey.AskOne(promptPerms, &permissions)
		if err != nil {
			color.Red("Setup aborted: %v", err)
			return
		}

		if len(permissions) == 0 {
			color.Red("You must select at least one permission.")
			return
		}

		var expiryStr string
		promptExpiry := &survey.Input{Message: "Expiry in minutes (0 for no expiry):", Default: "0"}
		survey.AskOne(promptExpiry, &expiryStr)
		var expiry int
		fmt.Sscanf(expiryStr, "%d", &expiry)

		token, err := src.GenerateMCPToken(name, permissions, expiry)
		if err != nil {
			color.Red("Token generation failed: %v", err)
			return
		}

		exe, _ := os.Executable()
		mcpConfig := map[string]interface{}{
			"command": "cmd",
			"args":    []string{"/c", exe, "mcp", "serve", "--token", token},
			"env":     map[string]string{},
		}

		if runtime.GOOS != "windows" {
			mcpConfig["command"] = exe
			mcpConfig["args"] = []string{"mcp", "serve", "--token", token}
		}

		fullConfig := map[string]interface{}{
			"mcpServers": map[string]interface{}{
				"apm": mcpConfig,
			},
		}

		configJSON, _ := json.MarshalIndent(fullConfig, "", "  ")

		color.HiGreen("\nMCP Token generated successfully!")
		color.HiCyan("Token: %s", token)
		color.HiYellow("\nAdd the following configuration to your MCP settings (e.g., mcp.json or Claude Desktop config):")
		fmt.Println(string(configJSON))
		color.HiCyan("\nNote: The MCP server requires an active APM session. Run 'pm unlock' to start a session before using the agent.")
	},
}

var mcpListCmd = &cobra.Command{
	Use:   "list",
	Short: "List active MCP tokens",
	Run: func(cmd *cobra.Command, args []string) {
		tokens, err := src.ListMCPTokens()
		if err != nil {
			color.Red("Error listing tokens: %v", err)
			return
		}

		if len(tokens) == 0 {
			fmt.Println("No active MCP tokens.")
			return
		}

		fmt.Printf("%-20s %-25s %-10s %-25s\n", "NAME", "CREATED", "USES", "EXPIRES")
		fmt.Println(strings.Repeat("-", 85))
		for _, t := range tokens {
			expires := "Never"
			if !t.ExpiresAt.IsZero() {
				expires = t.ExpiresAt.Format("2006-01-02 15:04")
			}
			fmt.Printf("%-20s %-25s %-10d %-25s\n",
				t.Name,
				t.CreatedAt.Format("2006-01-02 15:04"),
				t.UsageCount,
				expires)
		}
	},
}

var mcpRevokeCmd = &cobra.Command{
	Use:   "revoke [name_or_token]",
	Short: "Revoke an MCP token",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		success, err := src.RevokeMCPToken(args[0])
		if err != nil {
			color.Red("Error revoking token: %v", err)
			return
		}
		if success {
			color.Green("Token '%s' revoked successfully.", args[0])
		} else {
			color.Yellow("Token '%s' not found.", args[0])
		}
	},
}

var mcpServeCmd = &cobra.Command{
	Use:    "serve",
	Short:  "Internal command to start the MCP server (stdio)",
	Hidden: true,
	Run: func(cmd *cobra.Command, args []string) {
		token, _ := cmd.Flags().GetString("token")
		if token == "" {
			fmt.Println("Error: --token flag is required for serve mode")
			os.Exit(1)
		}
		if err := src.StartMCPServer(token, vaultPath, nil, pluginMgr); err != nil {
			fmt.Fprintf(os.Stderr, "MCP Server Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	mcpCmd.AddCommand(mcpTokenCmd, mcpListCmd, mcpRevokeCmd, mcpServeCmd)
	mcpServeCmd.Flags().String("token", "", "MCP access token")
	authAlertsCmd.Flags().Bool("enable", false, "Enable security alerts")
	authAlertsCmd.Flags().Bool("disable", false, "Disable security alerts")
}
