package main

import (
	"bufio"
	"bytes"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha256"
	"encoding/json"
	"fmt"
	"html"
	"image"
	_ "image/gif"
	_ "image/jpeg"
	_ "image/png"
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

	src "github.com/aaravmaloo/apm/src"
	"github.com/aaravmaloo/apm/src/autofill"
	"github.com/aaravmaloo/apm/src/autofillcmd"
	"github.com/aaravmaloo/apm/src/plugins"
	"github.com/aaravmaloo/apm/src/tui"

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

		var gdriveKey string
		v.DriveKeyMetadataConsent = promptKeyMetadataConsent("Google Drive")
		if v.DriveKeyMetadataConsent {
			fmt.Print("Enter Custom Retrieval Key (leave blank to generate randomly): ")
			customKey := readInput()
			if customKey != "" {
				gdriveKey = customKey
			} else {
				gdriveKey, err = src.GenerateRetrievalKey()
				if err != nil {
					color.Red("Key generation failed: %v", err)
					return err
				}
			}
		}

		cm, err := getCloudManagerEx(context.Background(), v, mp, "gdrive")
		if err != nil {
			color.Red("GDrive error: %v", err)
			return err
		}

		uploadPath, cleanupUpload, err := src.PrepareCloudUploadVaultPath(v, mp, vaultPath, "gdrive")
		if err != nil {
			color.Red("Failed to apply .apmignore for upload: %v", err)
			return err
		}
		defer cleanupUpload()

		fileID, err := cm.UploadVault(uploadPath, gdriveKey)
		if err != nil {
			color.Red("Upload failed: %v", err)
			return err
		}

		v.RetrievalKey = gdriveKey
		v.CloudFileID = fileID
		v.LastCloudProvider = "gdrive"
		color.Green("Google Drive sync setup successful.")
		if gdriveKey != "" {
			color.HiCyan("Retrieval Key: %s", gdriveKey)
		} else {
			color.Yellow("Retrieval key metadata was not stored by consent choice. Use File ID for recovery: %s", fileID)
		}
		if mode == "self_hosted" {
			color.Cyan("Mode: Self-Hosted (Owner: You)")
		} else {
			color.Cyan("Mode: APM_PUBLIC")
		}
		return nil
	}

	setupGitHub := func(v *src.Vault) error {
		color.Yellow("\nSetting up GitHub...")
		fmt.Println("Choose authentication type:")
		fmt.Println("1. Personal Access Token (classic/fine-grained)")
		fmt.Println("2. OAuth2 Access Token")
		fmt.Print("Selection (1/2) [1]: ")
		authChoice := strings.TrimSpace(readInput())
		tokenLabel := "GitHub token"
		if authChoice == "2" {
			tokenLabel = "GitHub OAuth2 access token"
		}
		fmt.Printf("Enter %s: ", tokenLabel)
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
		uploadPath, cleanupUpload, err := src.PrepareCloudUploadVaultPath(v, pat, vaultPath, "github")
		if err != nil {
			color.Red("Failed to apply .apmignore for upload: %v", err)
			return err
		}
		defer cleanupUpload()

		_, err = gm.UploadVault(uploadPath, "")
		if err != nil {
			color.Red("Upload failed: %v", err)
			return err
		}
		v.GitHubToken = pat
		v.GitHubRepo = repo
		color.Green("GitHub sync setup successful.")
		return nil
	}

	var addCmd = &cobra.Command{
		Use:   "add [type]",
		Short: "Add a new entry to the vault interactively",
		Args:  cobra.MaximumNArgs(1),
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

			var choice string
			resolveAddChoice := func(raw string) string {
				normalized := strings.ToLower(strings.TrimSpace(raw))
				normalized = strings.ReplaceAll(normalized, " ", "")
				normalized = strings.ReplaceAll(normalized, "-", "")
				normalized = strings.ReplaceAll(normalized, "_", "")
				if normalized == "" {
					return ""
				}
				switch normalized {
				case "1", "password", "pass", "login":
					return "1"
				case "2", "totp", "otp", "2fa":
					return "2"
				case "3", "token":
					return "3"
				case "4", "note", "securenote", "notes":
					return "4"
				case "5", "apikey", "api":
					return "5"
				case "6", "ssh", "sshkey":
					return "6"
				case "7", "wifi", "wireless":
					return "7"
				case "8", "recovery", "recoverycode", "recoverycodes":
					return "8"
				case "9", "certificate", "cert":
					return "9"
				case "10", "bank", "banking":
					return "10"
				case "11", "document", "doc", "file":
					return "11"
				case "12", "governmentid", "govid":
					return "12"
				case "13", "medical", "medicalrecord":
					return "13"
				case "14", "travel", "traveldoc":
					return "14"
				case "15", "contact":
					return "15"
				case "16", "cloud", "cloudcredentials":
					return "16"
				case "17", "k8s", "kubernetes", "kubernetessecret":
					return "17"
				case "18", "docker", "dockerregistry":
					return "18"
				case "19", "sshconfig":
					return "19"
				case "20", "cicd", "cicdsecret", "ci", "cd":
					return "20"
				case "21", "softwarelicense", "license":
					return "21"
				case "22", "legal", "legalcontract":
					return "22"
				case "23", "audio":
					return "23"
				case "24", "video":
					return "24"
				case "25", "photo", "image", "picture":
					return "25"
				default:
					return ""
				}
			}

			if len(args) > 0 {
				choice = resolveAddChoice(args[0])
				if choice == "" {
					color.Red("Unknown add type '%s'.", args[0])
					color.Yellow("Try: password, totp, token, note, apikey, sshkey, wifi, recoverycodes, certificate, banking, document, govid, medicalrecord, traveldoc, contact, cloudcredentials, kubernetes, dockerregistry, sshconfig, cicdsecret, softwarelicense, legalcontract, audio, video, photo")
					return
				}
			} else {
				fmt.Println("Select type to add:")
				color.HiCyan("\n--- CATEGORIES ---")
				color.Cyan("1. Identity & Personal")
				color.Cyan("2. Developer & Infrastructure")
				color.Cyan("3. Media & Files")
				color.Cyan("4. Finance & Legal")
				fmt.Print("\nSelect Category: ")
				catChoice := readInput()

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
				fmt.Print("Link domain for autofill (optional, e.g. github.com): ")
				domainLink := normalizeDomainInput(readInput())
				if domainLink != "" {
					if vault.TOTPDomainLinks == nil {
						vault.TOTPDomainLinks = make(map[string]string)
					}
					vault.TOTPDomainLinks[domainLink] = acc
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
				content, err := captureNoteContent(vault, name, "")
				if err != nil {
					color.Red("Note creation canceled: %v\n", err)
					return
				}
				if err := vault.AddSecureNote(name, content); err != nil {
					color.Red("Error: %v\n", err)
					return
				}
				reindexNoteVocabularyIfEnabled(vault)
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
			showPass, _ := cmd.Flags().GetBool("show-pass")
			if len(args) > 0 {
				initialQuery = args[0]
			}

			masterPassword, vault, readonly, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			handleInteractiveEntries(vault, masterPassword, initialQuery, readonly, showPass)
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
			if err := autofillcmd.UnlockDaemonWithPassword(vaultPath, masterPassword, timeout, inactivity, "CTRL+SHIFT+L"); err != nil {
				color.Yellow("Autofill daemon unlock skipped: %v", err)
			}
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
			if err := autofillcmd.LockDaemonIfRunning(); err != nil {
				color.Yellow("Autofill daemon lock failed: %v", err)
			}
		},
	}

	var sessionCmd = &cobra.Command{
		Use:   "session",
		Short: "Manage ephemeral, context-bound secret sessions",
	}

	var sessionIssueCmd = &cobra.Command{
		Use:   "issue",
		Short: "Issue an ephemeral session token bound to host/process/agent",
		Run: func(cmd *cobra.Command, args []string) {
			ttl, _ := cmd.Flags().GetDuration("ttl")
			scope, _ := cmd.Flags().GetString("scope")
			label, _ := cmd.Flags().GetString("label")
			agent, _ := cmd.Flags().GetString("agent")
			bindPID, _ := cmd.Flags().GetBool("bind-pid")
			bindHost, _ := cmd.Flags().GetBool("bind-host")

			masterPassword, _, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			pid := 0
			if bindPID {
				pid = os.Getpid()
			}
			eph, err := src.IssueEphemeralSession(masterPassword, label, scope, agent, ttl, bindHost, pid)
			if err != nil {
				color.Red("Failed to issue ephemeral session: %v", err)
				return
			}

			fmt.Println("Ephemeral session issued.")
			fmt.Printf("ID:         %s\n", eph.ID)
			fmt.Printf("Scope:      %s\n", eph.Scope)
			fmt.Printf("Expires:    %s\n", eph.ExpiresAt.Format(time.RFC3339))
			if eph.BoundHostHash != "" {
				fmt.Println("Host bind:  enabled")
			}
			if eph.BoundPID > 0 {
				fmt.Printf("PID bind:   %d\n", eph.BoundPID)
			}
			if eph.BoundAgent != "" {
				fmt.Printf("Agent bind: %s\n", eph.BoundAgent)
			}
			fmt.Printf("\nExport this for consumers:\n")
			fmt.Printf("  set APM_EPHEMERAL_ID=%s\n", eph.ID)
			if eph.BoundAgent != "" {
				fmt.Printf("  set APM_EPHEMERAL_AGENT=%s\n", eph.BoundAgent)
			}
		},
	}
	sessionIssueCmd.Flags().Duration("ttl", 15*time.Minute, "Lifetime for the ephemeral session (e.g. 10m, 1h)")
	sessionIssueCmd.Flags().String("scope", "read", "Session scope: read or write")
	sessionIssueCmd.Flags().String("label", "", "Optional label for this ephemeral session")
	sessionIssueCmd.Flags().String("agent", "", "Optional agent binding label (e.g. mcp, ci)")
	sessionIssueCmd.Flags().Bool("bind-host", true, "Bind ephemeral session to current host")
	sessionIssueCmd.Flags().Bool("bind-pid", false, "Bind ephemeral session to current process id")

	var sessionListCmd = &cobra.Command{
		Use:   "list",
		Short: "List active ephemeral sessions",
		Run: func(cmd *cobra.Command, args []string) {
			list, err := src.ListEphemeralSessions()
			if err != nil {
				color.Red("Failed to load sessions: %v", err)
				return
			}
			if len(list) == 0 {
				fmt.Println("No active ephemeral sessions.")
				return
			}
			fmt.Printf("%-30s %-6s %-25s %-10s %-8s\n", "ID", "SCOPE", "EXPIRES", "REVOKED", "AGENT")
			fmt.Println(strings.Repeat("-", 85))
			for _, s := range list {
				fmt.Printf("%-30s %-6s %-25s %-10v %-8s\n", s.ID, s.Scope, s.ExpiresAt.Format("2006-01-02 15:04:05"), s.Revoked, s.BoundAgent)
			}
		},
	}

	var sessionRevokeCmd = &cobra.Command{
		Use:   "revoke <id>",
		Short: "Revoke an ephemeral session immediately",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			ok, err := src.RevokeEphemeralSession(args[0])
			if err != nil {
				color.Red("Failed to revoke session: %v", err)
				return
			}
			if !ok {
				color.Yellow("Session not found: %s", args[0])
				return
			}
			color.Green("Ephemeral session revoked: %s", args[0])
		},
	}

	sessionCmd.AddCommand(sessionIssueCmd, sessionListCmd, sessionRevokeCmd)

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
			detailed, _ := cmd.Flags().GetBool("detailed")
			if detailed {
				scores := vault.ComputeSecretTrustScores()
				if len(scores) == 0 {
					fmt.Println("\nNo per-secret trust telemetry yet.")
				} else {
					fmt.Println("\nTop Secret Risks")
					fmt.Println("----------------")
					limit := 10
					if len(scores) < limit {
						limit = len(scores)
					}
					for i := 0; i < limit; i++ {
						s := scores[i]
						space := s.Space
						if space == "" {
							space = "default"
						}
						fmt.Printf("%2d. [%s] %s/%s (space=%s) score=%d\n", i+1, strings.ToUpper(s.Risk), s.Category, s.Identifier, space, s.Score)
					}
				}
			}
			src.LogAction("HEALTH_CHECK", fmt.Sprintf("Score: %d", score))
		},
	}
	healthCmd.Flags().Bool("detailed", false, "Include per-secret trust score details")

	var trustCmd = &cobra.Command{
		Use:   "trust",
		Short: "View trust scores for individual secrets",
		Run: func(cmd *cobra.Command, args []string) {
			_, vault, _, err := src_unlockVault()
			if err != nil {
				return
			}
			scores := vault.ComputeSecretTrustScores()
			if len(scores) == 0 {
				fmt.Println("No trust telemetry available yet. Access or mutate entries to build trust data.")
				return
			}
			fmt.Println("Secret Trust Scores")
			fmt.Println("===================")
			for _, s := range scores {
				space := s.Space
				if space == "" {
					space = "default"
				}
				fmt.Printf("[%s] %-12s %-28s space=%-12s score=%3d", strings.ToUpper(s.Risk), s.Category, s.Identifier, space, s.Score)
				if len(s.Reasons) > 0 {
					fmt.Printf(" | %s", strings.Join(s.Reasons, "; "))
				}
				fmt.Println()
			}
			src.LogAction("TRUST_VIEWED", fmt.Sprintf("Displayed %d trust scores", len(scores)))
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
			infoVersion := "can-v10.0.0-03-11-2026"
			infoBuild := "commits left to be pushed (23-02-2026)"

			vaultAccessible := true
			if _, statErr := os.Stat(vaultPath); statErr != nil {
				vaultAccessible = false
			}
			configValid := installDir != "" && vaultPath != ""
			allSystemsOK := vaultAccessible && configValid

			statusLine := func(ok bool, label string) {
				if ok {
					fmt.Printf("  %s %s\n", color.HiGreenString("✔"), label)
				} else {
					fmt.Printf("  %s %s\n", color.HiRedString("✘"), label)
				}
			}

			fmt.Println("APM Canary Preview Release")
			fmt.Println("────────────────────────────")
			fmt.Println()
			fmt.Printf("User:       %s@apm\n", processedHomeName)
			fmt.Printf("Installed:  %s\n", installDir)
			fmt.Printf("Vault:      %s\n", vaultPath)
			fmt.Println()
			fmt.Printf("Version:    %s\n", infoVersion)
			fmt.Printf("Build:      %s\n", infoBuild)
			fmt.Println()
			fmt.Println("Repo:       github.com/aaravmaloo/apm")
			fmt.Println("Support:    aaravmaloo06@gmail.com")
			fmt.Println()
			fmt.Println("Status:")
			statusLine(vaultAccessible, "Vault accessible")
			statusLine(configValid, "Config valid")
			statusLine(allSystemsOK, "All systems ok.")
		},
	}

	var totpCmd = &cobra.Command{
		Use:   "totp [entry_name]",
		Short: "Show or copy TOTP codes",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			masterPassword, vault, _, err := src_unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			entries := orderedTOTPEntries(vault)
			if len(entries) == 0 {
				fmt.Println("No TOTP entries found.")
				return
			}

			if len(args) == 1 {
				target, ok := findTOTPEntry(entries, args[0])
				if !ok {
					fmt.Printf("TOTP entry '%s' not found.\n", args[0])
					return
				}
				code, err := src.GenerateTOTP(target.Secret)
				if err != nil {
					color.Red("Failed to generate TOTP for %s: %v", target.Account, err)
					return
				}
				copyToClipboard(code)
				color.Green("Copied TOTP for %s to clipboard.", target.Account)
				src.LogAction("TOTP_COPIED", fmt.Sprintf("Account: %s", target.Account))
				return
			}

			runInteractiveTOTP(vault, masterPassword)
		},
	}

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
		Short: "Sync and retrieve vaults from cloud (Google Drive, GitHub, Dropbox)",
	}

	var cloudInitCmd = &cobra.Command{
		Use:   "init [gdrive|github|dropbox|all]",
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
			default:
				color.Red("Unsupported cloud provider '%s'. Use gdrive, github, dropbox, or all.", provider)
				return
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
		Use:   "sync [gdrive|github|dropbox]",
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

				uploadPath, cleanupUpload, prepErr := src.PrepareCloudUploadVaultPath(vault, masterPassword, vaultPath, provider)
				if prepErr != nil {
					color.Red("[%s] Failed to apply .apmignore: %v", provider, prepErr)
					src.LogAction("CLOUD_SYNC_FAILED", fmt.Sprintf("Provider: %s, Error: %v", provider, prepErr))
					continue
				}
				err = cm.SyncVault(uploadPath, targetID)
				cleanupUpload()
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

									uploadPath, cleanupUpload, prepErr := src.PrepareCloudUploadVaultPath(vault, masterPassword, vaultPath, provider)
									if prepErr != nil {
										src.LogAction("CLOUD_AUTOSYNC_FAILED", fmt.Sprintf("Provider: %s, Error: %v", provider, prepErr))
										color.Red("[%s] Failed to apply .apmignore: %v", provider, prepErr)
										continue
									}

									err = cm.SyncVault(uploadPath, targetID)
									cleanupUpload()
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
		Use:   "get [gdrive|github|dropbox] [retrieval_key|repo]",
		Short: "Download vault from cloud",
		Run: func(cmd *cobra.Command, args []string) {
			provider := "gdrive"
			var key string
			authMode, _ := cmd.Flags().GetString("auth-mode")
			tokenFlag, _ := cmd.Flags().GetString("token")
			oauth2TokenFlag, _ := cmd.Flags().GetString("oauth2-token")
			tokenInput := strings.TrimSpace(tokenFlag)
			if tokenInput == "" {
				tokenInput = strings.TrimSpace(oauth2TokenFlag)
			}

			if len(args) == 0 {
				fmt.Print("Enter Provider (gdrive|github|dropbox) [gdrive]: ")
				pInput := strings.TrimSpace(readInput())
				if pInput != "" {
					provider = strings.ToLower(pInput)
				}
			} else {
				provider = strings.ToLower(args[0])
			}

			switch provider {
			case "github":
				if len(args) > 1 {
					key = strings.TrimSpace(args[1])
				} else {
					fmt.Print("Enter GitHub Repo (owner/repo): ")
					key = strings.TrimSpace(readInput())
				}
				if key == "" {
					color.Red("Missing GitHub repo. Use owner/repo.")
					return
				}

				if tokenInput == "" {
					if authMode == "" {
						fmt.Println("Choose authentication type:")
						fmt.Println("1. Personal Access Token")
						fmt.Println("2. OAuth2 Access Token")
						fmt.Print("Selection (1/2) [1]: ")
						choice := strings.TrimSpace(readInput())
						if choice == "2" {
							authMode = "oauth2"
						} else {
							authMode = "pat"
						}
					}
					if authMode == "oauth2" {
						fmt.Print("Enter GitHub OAuth2 access token: ")
					} else {
						fmt.Print("Enter GitHub Personal Access Token: ")
					}
					var err error
					tokenInput, err = readPassword()
					if err != nil {
						color.Red("Error reading token: %v", err)
						return
					}
					fmt.Println()
				}

				gm, err := src.NewGitHubManager(context.Background(), tokenInput)
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
				handleDownloadedVault(data, "github", tokenInput, key)
				src.LogAction("CLOUD_DOWNLOAD_SUCCESS", fmt.Sprintf("Provider: github, Key: %s", key))
				return
			case "gdrive", "dropbox":
				if len(args) > 1 {
					key = strings.TrimSpace(args[1])
				}
				if key == "" {
					if provider == "gdrive" {
						fmt.Print("Enter Retrieval Key or Drive File ID: ")
					} else {
						fmt.Print("Enter Retrieval Key or Dropbox File Path: ")
					}
					var err error
					key, err = readPassword()
					if err != nil {
						color.Red("Error reading retrieval key: %v", err)
						return
					}
					fmt.Println()
				}
				if key == "" {
					color.Red("A retrieval key or direct cloud file identifier is required.")
					return
				}
			default:
				color.Red("Unsupported provider: %s", provider)
				return
			}

			fileID := ""
			syncMode := "apm_public"
			var cp src.CloudProvider
			var err error

			if provider == "gdrive" {
				if authMode == "" {
					fmt.Println("Choose Sync Mode for Retrieval:")
					fmt.Println("1. APM_PUBLIC")
					fmt.Println("2. OAuth2 Self-Hosted")
					fmt.Print("Selection (1/2) [1]: ")
					modeSelection := strings.TrimSpace(readInput())
					if modeSelection == "2" {
						authMode = "oauth2"
					}
				}
				if authMode == "oauth2" {
					syncMode = "self_hosted"
					token, authErr := src.PerformDriveAuth(src.GetDefaultCreds())
					if authErr != nil {
						color.Red("Google OAuth2 authentication failed: %v", authErr)
						return
					}
					cp, err = src.GetCloudProvider("gdrive", context.Background(), src.GetDefaultCreds(), token, syncMode)
				} else {
					cp, err = src.GetCloudProvider("gdrive", context.Background(), nil, nil, syncMode)
				}
			} else {
				if tokenInput != "" {
					syncMode = "self_hosted"
				} else if authMode == "" {
					fmt.Println("Choose Sync Mode for Retrieval:")
					fmt.Println("1. APM_PUBLIC")
					fmt.Println("2. OAuth2 Self-Hosted (Access Token)")
					fmt.Print("Selection (1/2) [1]: ")
					modeSelection := strings.TrimSpace(readInput())
					if modeSelection == "2" {
						authMode = "oauth2"
					}
				}

				if authMode == "oauth2" && tokenInput == "" {
					fmt.Print("Enter Dropbox OAuth2 access token (or token JSON): ")
					var tokenErr error
					tokenInput, tokenErr = readPassword()
					if tokenErr != nil {
						color.Red("Error reading Dropbox token: %v", tokenErr)
						return
					}
					fmt.Println()
					syncMode = "self_hosted"
				}
				cp, err = src.GetCloudProvider("dropbox", context.Background(), nil, []byte(tokenInput), syncMode)
			}

			if err != nil {
				color.Red("Cloud Error: %v", err)
				return
			}

			fileID, err = cp.ResolveKeyToID(key)
			if err != nil {
				color.Red("Key resolution failed: %v", err)
				src.LogAction("CLOUD_DOWNLOAD_FAILED", fmt.Sprintf("Provider: %s, Key: %s, Error: %v", provider, key, err))
				return
			}

			data, err := cp.DownloadVault(fileID)
			if err != nil {
				color.Red("Download failed: %v", err)
				src.LogAction("CLOUD_DOWNLOAD_FAILED", fmt.Sprintf("Provider: %s, Key: %s, Error: %v", provider, key, err))
				return
			}

			handleDownloadedVault(data, provider, "", "")
			src.LogAction("CLOUD_DOWNLOAD_SUCCESS", fmt.Sprintf("Provider: %s, Key: %s", provider, key))
		},
	}
	cloudGetCmd.Flags().String("auth-mode", "", "Auth mode for cloud get: pat|oauth2")
	cloudGetCmd.Flags().String("token", "", "Token for provider authentication")
	cloudGetCmd.Flags().String("oauth2-token", "", "OAuth2 access token (alias of --token)")

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
			vault.DriveKeyMetadataConsent = false
			vault.CloudCredentials = nil
			vault.CloudToken = nil
			vault.GitHubToken = ""
			vault.GitHubRepo = ""
			vault.DropboxToken = nil
			vault.DropboxSyncMode = ""
			vault.DropboxKeyMetadataConsent = false
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
		Short: "List installed plugins (alias of installed)",
		Run: func(cmd *cobra.Command, args []string) {
			list := pluginMgr.ListPlugins()
			if len(list) == 0 {
				fmt.Println("No plugins installed locally.")
				return
			}
			sort.Strings(list)
			fmt.Println("Installed Plugins:")
			for _, n := range list {
				fmt.Printf("- %s\n", n)
			}
		},
	}

	var pluginsMarketCmd = &cobra.Command{
		Use:     "market",
		Aliases: []string{"marketplace"},
		Short:   "List available plugins in Marketplace (Drive)",
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

	var pluginsInstallCmd = &cobra.Command{
		Use:   "install [name]",
		Short: "Install a plugin from Marketplace",
		Run: func(cmd *cobra.Command, args []string) {
			pluginsAddCmd.Run(cmd, args)
		},
	}

	var pluginsPushCmd = &cobra.Command{
		Use:   "push [name]",
		Short: "Push a plugin to the Google Drive marketplace",
		Run: func(cmd *cobra.Command, args []string) {
			if len(args) < 1 {
				color.Red("Usage: pm plugins push <name> [--path <local-plugin-dir>]")
				return
			}
			name := strings.TrimSpace(args[0])
			localPath, _ := cmd.Flags().GetString("path")
			sourcePath := strings.TrimSpace(localPath)
			if sourcePath == "" {
				sourcePath = filepath.Join(pluginMgr.PluginsDir, name)
				if stat, err := os.Stat(sourcePath); err != nil || !stat.IsDir() {
					cwdCandidate := filepath.Join(".", name)
					if cwdStat, cwdErr := os.Stat(cwdCandidate); cwdErr == nil && cwdStat.IsDir() {
						sourcePath = cwdCandidate
					}
				}
			}
			sourcePath = filepath.Clean(sourcePath)
			info, err := os.Stat(sourcePath)
			if err != nil || !info.IsDir() {
				color.Red("Invalid plugin source directory: %s", sourcePath)
				return
			}

			pluginDefPath := filepath.Join(sourcePath, "plugin.json")
			def, loadErr := plugins.LoadPluginDef(pluginDefPath)
			if loadErr != nil {
				color.Red("Invalid plugin source. '%s' is required and must be valid: %v", pluginDefPath, loadErr)
				return
			}
			if strings.TrimSpace(def.Name) != "" && def.Name != name {
				color.Yellow("Plugin manifest name is '%s'. Uploading as '%s'.", def.Name, name)
			}

			cm, err := getCloudManagerEx(context.Background(), nil, "", "gdrive")
			if err != nil {
				color.Red("Error connecting to plugin marketplace: %v", err)
				return
			}

			if err := cm.UploadPlugin(name, sourcePath); err != nil {
				color.Red("Failed to push plugin '%s': %v", name, err)
				return
			}

			color.Green("Plugin '%s' pushed to marketplace successfully.", name)
			src.LogAction("PLUGIN_PUSH", fmt.Sprintf("Plugin '%s' pushed from %s", name, sourcePath))
		},
	}
	pluginsPushCmd.Flags().String("path", "", "Optional local plugin directory (defaults to installed plugin path)")

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

	var pluginAccessCmd = &cobra.Command{
		Use:   "access [plugin] [permission] [on|off]",
		Short: "View or change plugin permission access (2 args toggles)",
		Args:  cobra.MaximumNArgs(3),
		Run: func(cmd *cobra.Command, args []string) {
			pass, vault, readonly, err := src_unlockVault()
			if err != nil {
				color.Red("Error: %v", err)
				return
			}

			resolvePlugin := func(input string) (string, *plugins.Plugin, bool) {
				target := strings.TrimSpace(input)
				for loadedName, loadedPlugin := range pluginMgr.Loaded {
					if strings.EqualFold(strings.TrimSpace(loadedName), target) {
						return loadedName, loadedPlugin, true
					}
				}
				return "", nil, false
			}

			printPluginPermissions := func(displayName string, plugin *plugins.Plugin) {
				fmt.Printf("%s\n", displayName)
				perms := append([]string{}, plugin.Definition.Permissions...)
				sort.Strings(perms)
				for _, permission := range perms {
					status := "ON"
					if !pluginPermissionEnabled(vault, plugin.Definition.Name, permission) {
						status = "OFF"
					}
					fmt.Printf("  %-28s %s\n", permission, status)
				}
			}

			if len(args) == 0 {
				if len(pluginMgr.Loaded) == 0 {
					fmt.Println("No plugins loaded.")
					return
				}
				names := make([]string, 0, len(pluginMgr.Loaded))
				for name := range pluginMgr.Loaded {
					names = append(names, name)
				}
				sort.Strings(names)
				for _, name := range names {
					plugin := pluginMgr.Loaded[name]
					printPluginPermissions(name, plugin)
				}
				fmt.Println("Toggle example: pm plugins access <plugin> <permission>")
				fmt.Println("Set example:    pm plugins access <plugin> <permission> on|off")
				return
			}

			displayName, plugin, ok := resolvePlugin(args[0])
			if !ok {
				color.Red("Plugin '%s' not found.", strings.TrimSpace(args[0]))
				return
			}

			if len(args) == 1 {
				printPluginPermissions(displayName, plugin)
				return
			}

			if len(args) < 2 || len(args) > 3 {
				color.Red("Usage: pm plugins access [plugin] [permission] [on|off]")
				return
			}
			if readonly {
				color.Red("Vault is READ-ONLY. Cannot modify plugin permissions.")
				return
			}

			permission := strings.TrimSpace(args[1])

			known := false
			for _, p := range plugin.Definition.Permissions {
				if strings.EqualFold(p, permission) {
					permission = p
					known = true
					break
				}
			}
			if !known {
				color.Red("Permission '%s' is not declared by plugin '%s'.", permission, displayName)
				return
			}

			stateRaw := ""
			enabled := false
			if len(args) == 2 {
				enabled = !pluginPermissionEnabled(vault, plugin.Definition.Name, permission)
				if enabled {
					stateRaw = "on"
				} else {
					stateRaw = "off"
				}
			} else {
				stateRaw = strings.ToLower(strings.TrimSpace(args[2]))
				switch stateRaw {
				case "on", "true", "1", "yes":
					enabled = true
				case "off", "false", "0", "no":
					enabled = false
				default:
					color.Red("State must be 'on' or 'off'.")
					return
				}
			}

			setPluginPermissionOverride(vault, plugin.Definition.Name, permission, enabled)
			if err := saveVaultState(vault, pass); err != nil {
				color.Red("Failed to save permission change: %v", err)
				return
			}
			color.Green("Plugin '%s' permission '%s' set to %s.", displayName, permission, strings.ToUpper(stateRaw))
		},
	}

	executePluginCommand := func(pluginName string, plugin *plugins.Plugin, commandName string, cmdDef plugins.CommandDef, overrides map[string]string, args []string) error {
		pass, vault, readonly, err := src_unlockVault()
		if err != nil {
			return err
		}
		if readonly {
			return fmt.Errorf("vault is READ-ONLY. Plugin commands are disabled in read-only mode")
		}

		ctx := plugins.NewExecutionContext()
		for flagName, flagDef := range cmdDef.Flags {
			value := strings.TrimSpace(overrides[flagName])
			if value == "" {
				value = flagDef.Default
			}
			ctx.Variables[flagName] = value
		}
		for i, arg := range args {
			ctx.Variables[fmt.Sprintf("arg%d", i+1)] = arg
		}

		effectivePerms := applyPluginPermissionOverrides(vault, plugin.Definition.Name, plugin.Definition.Permissions)
		executor := plugins.NewStepExecutor(ctx, vault, vaultPath)
		if err := executor.ExecuteSteps(cmdDef.Steps, effectivePerms); err != nil {
			return err
		}
		return saveVaultState(vault, pass)
	}

	var pluginRunCmd = &cobra.Command{
		Use:   "run [plugin] [command] [args...]",
		Short: "Run an installed plugin command",
		Args:  cobra.MinimumNArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			pluginInput := strings.TrimSpace(args[0])
			commandInput := strings.TrimSpace(args[1])

			var (
				pluginName string
				plugin     *plugins.Plugin
				found      bool
			)
			for loadedName, loadedPlugin := range pluginMgr.Loaded {
				if strings.EqualFold(strings.TrimSpace(loadedName), pluginInput) {
					pluginName = loadedName
					plugin = loadedPlugin
					found = true
					break
				}
			}
			if !found || plugin == nil || plugin.Definition == nil {
				color.Red("Plugin '%s' not found.", pluginInput)
				return
			}

			var (
				commandName string
				cmdDef      plugins.CommandDef
				cmdFound    bool
			)
			for loadedCommand, loadedDef := range plugin.Definition.Commands {
				if strings.EqualFold(strings.TrimSpace(loadedCommand), commandInput) {
					commandName = loadedCommand
					cmdDef = loadedDef
					cmdFound = true
					break
				}
			}
			if !cmdFound {
				color.Red("Command '%s' not found in plugin '%s'.", commandInput, pluginName)
				return
			}

			rawOverrides, _ := cmd.Flags().GetStringArray("set")
			overrides := make(map[string]string)
			for _, pair := range rawOverrides {
				parts := strings.SplitN(pair, "=", 2)
				if len(parts) != 2 {
					continue
				}
				key := strings.TrimSpace(parts[0])
				value := strings.TrimSpace(parts[1])
				if key == "" {
					continue
				}
				overrides[key] = value
			}

			if err := executePluginCommand(pluginName, plugin, commandName, cmdDef, overrides, args[2:]); err != nil {
				color.Red("Plugin command failed: %v", err)
			}
		},
	}
	pluginRunCmd.Flags().StringArray("set", nil, "Set plugin flag as key=value (repeatable)")

	pluginsCmd.AddCommand(pluginsInstalledCmd, pluginsListCmd, pluginsMarketCmd, pluginsAddCmd, pluginsInstallCmd, pluginsPushCmd, pluginsRemoveCmd, pluginLocalCmd, pluginSearchCmd, pluginAccessCmd, pluginRunCmd)

	var setupCmd = &cobra.Command{
		Use:   "setup",
		Short: "Complete APM setup wizard (vault, profile, spaces, plugins, cloud)",
		Run: func(cmd *cobra.Command, args []string) {
			nonInteractive, _ := cmd.Flags().GetBool("non-interactive")

			totalSteps := 7
			step := 1
			color.HiCyan("APM Setup")
			fmt.Println("Unified setup flow: project configuration, vault initialization, profiles, spaces, plugins, and cloud sync.")
			fmt.Println()

			color.Yellow("[%d/%d] Environment and project checks", step, totalSteps)
			step++
			info := src.DetectSystemProfileInfo()
			fmt.Printf("System: %s/%s, CPU cores: %d", info.OS, info.Arch, info.CPUCores)
			if info.MemoryDetected {
				fmt.Printf(", RAM: %d MB", info.TotalMemoryMB)
			}
			fmt.Println()

			vaultDir := filepath.Dir(vaultPath)
			if err := os.MkdirAll(vaultDir, 0700); err != nil {
				color.Red("Setup failed while creating vault directory '%s': %v", vaultDir, err)
				return
			}
			policyDir := filepath.Join(vaultDir, "policies")
			if err := os.MkdirAll(policyDir, 0750); err != nil {
				color.Red("Setup failed while creating policies directory '%s': %v", policyDir, err)
				return
			}
			if err := os.MkdirAll(pluginMgr.PluginsDir, 0750); err != nil {
				color.Red("Setup failed while creating plugins directory '%s': %v", pluginMgr.PluginsDir, err)
				return
			}
			color.Green("Project directories ready:")
			fmt.Printf("- Vault: %s\n", vaultPath)
			fmt.Printf("- Policies: %s\n", policyDir)
			fmt.Printf("- Plugins: %s\n", pluginMgr.PluginsDir)
			fmt.Println()

			color.Yellow("[%d/%d] Vault initialization and unlock", step, totalSteps)
			step++

			var masterPassword string
			var vault *src.Vault
			var readonly bool
			var err error

			if !src.VaultExists(vaultPath) {
				color.Cyan("No vault detected. Creating a new vault.")
				for {
					fmt.Print("Create Master Password: ")
					masterPassword, err = readPassword()
					if err != nil {
						color.Red("Error reading password: %v", err)
						return
					}
					fmt.Println()
					if err := src.ValidateMasterPassword(masterPassword); err != nil {
						color.Red("Invalid password: %v", err)
						continue
					}
					break
				}

				recommended, reason := src.RecommendProfileForSystem(info)
				selectedProfile := recommended
				fmt.Printf("System recommended profile: %s (%s)\n", recommended, reason)
				if !nonInteractive {
					fmt.Printf("Use '%s'? (Y/n): ", recommended)
					answer := strings.ToLower(strings.TrimSpace(readInput()))
					if answer == "n" || answer == "no" {
						fmt.Printf("Choose profile [%s] (%s): ", recommended, strings.Join(src.GetAvailableProfiles(), ", "))
						choice := strings.ToLower(strings.TrimSpace(readInput()))
						if _, ok := src.Profiles[choice]; ok {
							selectedProfile = choice
						} else if choice != "" {
							color.Yellow("Unknown profile '%s'. Using '%s'.", choice, recommended)
						}
					}
				}
				color.Green("Assigned profile: %s", selectedProfile)

				profileParams := src.GetProfile(selectedProfile)
				vault = &src.Vault{
					Profile:              selectedProfile,
					CurrentProfileParams: &profileParams,
					Spaces:               []string{"default"},
				}
				data, err := src.EncryptVault(vault, masterPassword)
				if err != nil {
					color.Red("Error encrypting new vault: %v", err)
					return
				}
				if err := src.SaveVault(vaultPath, data); err != nil {
					color.Red("Error saving new vault: %v", err)
					return
				}
				color.Green("Vault created at %s.", vaultPath)
			} else {
				masterPassword, vault, readonly, err = src_unlockVault()
				if err != nil {
					color.Red("Failed to unlock existing vault: %v", err)
					return
				}
				if readonly {
					color.Red("Vault is currently read-only. Disable read-only mode before running setup.")
					return
				}
				color.Green("Existing vault unlocked.")
			}
			fmt.Println()

			color.Yellow("[%d/%d] Security profile tuning", step, totalSteps)
			step++
			currentProfile := strings.TrimSpace(vault.Profile)
			if currentProfile == "" {
				currentProfile = "standard"
			}
			recommended, reason := src.RecommendProfileForSystem(info)
			fmt.Printf("Current profile: %s\n", currentProfile)
			fmt.Printf("Recommended for this system: %s (%s)\n", recommended, reason)
			if !nonInteractive {
				fmt.Print("Would you like to switch profile now? (y/n) [n]: ")
				if strings.ToLower(strings.TrimSpace(readInput())) == "y" {
					fmt.Printf("Choose profile [%s] (%s): ", recommended, strings.Join(src.GetAvailableProfiles(), ", "))
					target := strings.ToLower(strings.TrimSpace(readInput()))
					if target == "" {
						target = recommended
					}
					if err := src.ChangeProfile(vault, target, masterPassword, vaultPath); err != nil {
						color.Red("Profile change failed: %v", err)
					} else {
						vault.Profile = target
						color.Green("Profile switched to %s.", target)
					}
				}
			}
			fmt.Println()

			color.Yellow("[%d/%d] Spaces configuration", step, totalSteps)
			step++
			if len(vault.Spaces) == 0 {
				vault.Spaces = []string{"default"}
			}
			fmt.Printf("Current spaces: %s\n", strings.Join(vault.Spaces, ", "))
			if !nonInteractive {
				fmt.Print("Add spaces now? Enter comma-separated names (or leave blank): ")
				rawSpaces := strings.TrimSpace(readInput())
				if rawSpaces != "" {
					for _, part := range strings.Split(rawSpaces, ",") {
						name := strings.TrimSpace(part)
						if name == "" || strings.EqualFold(name, "default") {
							continue
						}
						exists := false
						for _, s := range vault.Spaces {
							if strings.EqualFold(s, name) {
								exists = true
								break
							}
						}
						if !exists {
							vault.Spaces = append(vault.Spaces, name)
						}
					}
				}
				fmt.Printf("Set active space (%s) [default]: ", strings.Join(vault.Spaces, ", "))
				targetSpace := strings.TrimSpace(readInput())
				if targetSpace == "" || strings.EqualFold(targetSpace, "default") {
					vault.CurrentSpace = ""
				} else {
					found := false
					for _, s := range vault.Spaces {
						if strings.EqualFold(s, targetSpace) {
							vault.CurrentSpace = s
							found = true
							break
						}
					}
					if !found {
						color.Yellow("Space '%s' was not found. Keeping default.", targetSpace)
						vault.CurrentSpace = ""
					}
				}
			}
			fmt.Println()

			color.Yellow("[%d/%d] Plugins setup", step, totalSteps)
			step++
			if !nonInteractive {
				fmt.Print("Install plugins during setup? (y/n) [n]: ")
				if strings.ToLower(strings.TrimSpace(readInput())) == "y" {
					fmt.Print("Install from marketplace by name (comma-separated, optional): ")
					pluginNames := strings.TrimSpace(readInput())
					if pluginNames != "" {
						cm, err := getCloudManagerEx(context.Background(), nil, "", "gdrive")
						if err != nil {
							color.Red("Could not connect to plugin marketplace: %v", err)
						} else {
							for _, name := range strings.Split(pluginNames, ",") {
								trimmed := strings.TrimSpace(name)
								if trimmed == "" {
									continue
								}
								targetDir := filepath.Join(pluginMgr.PluginsDir, trimmed)
								if err := cm.DownloadPlugin(trimmed, targetDir); err != nil {
									color.Red("Plugin '%s' install failed: %v", trimmed, err)
								} else {
									color.Green("Plugin '%s' installed.", trimmed)
								}
							}
						}
					}

					fmt.Print("Install local plugin path (optional, leave blank to skip): ")
					localPath := strings.TrimSpace(readInput())
					if localPath != "" {
						if _, err := os.Stat(filepath.Join(localPath, "plugin.json")); err != nil {
							color.Red("Local plugin path invalid: %v", err)
						} else {
							def, err := plugins.LoadPluginDef(filepath.Join(localPath, "plugin.json"))
							if err != nil {
								color.Red("Invalid local plugin manifest: %v", err)
							} else if err := pluginMgr.InstallPlugin(def.Name, localPath); err != nil {
								color.Red("Local plugin install failed: %v", err)
							} else {
								color.Green("Local plugin '%s' installed.", def.Name)
							}
						}
					}
				}
			}
			fmt.Println()

			color.Yellow("[%d/%d] Cloud sync setup", step, totalSteps)
			step++
			if !nonInteractive {
				fmt.Print("Configure cloud sync now? (y/n) [n]: ")
				if strings.ToLower(strings.TrimSpace(readInput())) == "y" {
					fmt.Println("Choose Cloud Provider:")
					fmt.Println("1. Google Drive")
					fmt.Println("2. GitHub")
					fmt.Println("3. Dropbox")
					fmt.Println("4. All")
					fmt.Print("Selection (1/2/3/4): ")
					choice := strings.TrimSpace(readInput())
					switch choice {
					case "1":
						if err := setupGDrive(vault, masterPassword); err != nil {
							color.Red("Google Drive setup failed: %v", err)
						}
					case "2":
						if err := setupGitHub(vault); err != nil {
							color.Red("GitHub setup failed: %v", err)
						}
					case "3":
						if err := setupDropbox(vault, masterPassword); err != nil {
							color.Red("Dropbox setup failed: %v", err)
						}
					case "4":
						if err := setupGDrive(vault, masterPassword); err != nil {
							color.Red("Google Drive setup failed: %v", err)
						}
						if err := setupGitHub(vault); err != nil {
							color.Red("GitHub setup failed: %v", err)
						}
						if err := setupDropbox(vault, masterPassword); err != nil {
							color.Red("Dropbox setup failed: %v", err)
						}
					default:
						color.Yellow("Skipped cloud setup.")
					}
				}
			}
			fmt.Println()

			color.Yellow("[%d/%d] Finalize and save configuration", step, totalSteps)
			data, err := src.EncryptVault(vault, masterPassword)
			if err != nil {
				color.Red("Final save failed during encryption: %v", err)
				return
			}
			if err := src.SaveVault(vaultPath, data); err != nil {
				color.Red("Final save failed: %v", err)
				return
			}

			color.HiGreen("Setup completed successfully.")
			fmt.Printf("Assigned profile: %s\n", vault.Profile)
			activeSpace := vault.CurrentSpace
			if activeSpace == "" {
				activeSpace = "default"
			}
			fmt.Printf("Active space: %s\n", activeSpace)
			src.LogAction("SETUP_COMPLETED", "Unified setup workflow completed")
		},
	}
	setupCmd.Flags().Bool("non-interactive", false, "Run setup with defaults and skip optional prompts")
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
		Short: "View and tune encryption profiles",
	}

	var profileSetCmd = &cobra.Command{
		Use:   "set <name>",
		Short: "Switch to a built-in profile",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			target := strings.ToLower(strings.TrimSpace(args[0]))
			masterPassword, vault, readonly, err := src_unlockVault()
			if err != nil {
				return
			}
			if readonly {
				color.Red("Vault is READ-ONLY.")
				return
			}
			err = src.ChangeProfile(vault, target, masterPassword, vaultPath)
			if err != nil {
				color.Red("Error: %v", err)
				color.Cyan("Available profiles: %s", strings.Join(src.GetAvailableProfiles(), ", "))
				src.LogAction("PROFILE_CHANGE_FAILED", fmt.Sprintf("Profile: %s, Error: %v", target, err))
			} else {
				color.Green("Profile switched to %s.", target)
				src.LogAction("PROFILE_CHANGED", fmt.Sprintf("Profile: %s", target))
			}
		},
	}

	var profileListCmd = &cobra.Command{
		Use:     "list",
		Aliases: []string{"ls"},
		Short:   "List profiles and their parameters",
		Run: func(cmd *cobra.Command, args []string) {
			_, vault, _, err := src_unlockVault()
			if err != nil {
				return
			}

			current := strings.TrimSpace(vault.Profile)
			if current == "" {
				current = "standard"
			}

			fmt.Println("Available profiles")
			fmt.Println("==================")
			for _, name := range src.GetAvailableProfiles() {
				p := src.GetProfile(name)
				currentMark := " "
				if strings.EqualFold(name, current) {
					currentMark = "*"
				}
				fmt.Printf("%s %s  | KDF: %s, Time: %d, Memory: %d MB, Threads: %d, Salt: %d, Nonce: %d\n",
					currentMark, name, p.KDF, p.Time, p.Memory/1024, p.Parallelism, p.SaltLen, p.NonceLen)
			}

			if vault.CurrentProfileParams != nil && !isBuiltinProfileName(current) {
				p := *vault.CurrentProfileParams
				fmt.Printf("* %s (custom active) | KDF: %s, Time: %d, Memory: %d MB, Threads: %d, Salt: %d, Nonce: %d\n",
					p.Name, p.KDF, p.Time, p.Memory/1024, p.Parallelism, p.SaltLen, p.NonceLen)
			}
		},
	}

	var profileCurrentCmd = &cobra.Command{
		Use:     "current",
		Aliases: []string{"status"},
		Short:   "Show the active profile",
		Run: func(cmd *cobra.Command, args []string) {
			_, vault, _, err := src_unlockVault()
			if err != nil {
				return
			}

			p := activeProfileForVault(vault)
			fmt.Println("Current profile")
			fmt.Println("===============")
			fmt.Printf("Name:        %s\n", p.Name)
			fmt.Printf("KDF:         %s\n", p.KDF)
			fmt.Printf("Memory:      %d MB\n", p.Memory/1024)
			fmt.Printf("Time:        %d\n", p.Time)
			fmt.Printf("Parallelism: %d\n", p.Parallelism)
			fmt.Printf("SaltLen:     %d\n", p.SaltLen)
			fmt.Printf("NonceLen:    %d\n", p.NonceLen)
		},
	}

	var profileEditCmd = &cobra.Command{
		Use:   "edit [name]",
		Short: "Interactively tune and apply a custom profile",
		Args:  cobra.MaximumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			masterPassword, vault, readonly, err := src_unlockVault()
			if err != nil {
				return
			}
			if readonly {
				color.Red("Vault is READ-ONLY.")
				return
			}

			base := activeProfileForVault(vault)
			suggestedName := base.Name
			if suggestedName == "" || isBuiltinProfileName(suggestedName) {
				suggestedName = "custom"
			}
			if len(args) == 1 && strings.TrimSpace(args[0]) != "" {
				suggestedName = strings.TrimSpace(args[0])
			}

			fmt.Println("Edit profile values (press Enter to keep defaults)")
			fmt.Printf("Profile name [%s]: ", suggestedName)
			chosenName := strings.TrimSpace(readInput())
			if chosenName == "" {
				chosenName = suggestedName
			}

			memMB := readUint32WithDefault("Memory (MB)", base.Memory/1024)
			t := readUint32WithDefault("Time (iterations)", base.Time)
			par := readUint8WithDefault("Parallelism (threads)", base.Parallelism)
			saltLen := readIntWithDefault("Salt length (bytes)", base.SaltLen)
			nonceLen := readIntWithDefault("Nonce length (bytes)", base.NonceLen)

			if memMB == 0 || t == 0 || par == 0 || saltLen <= 0 || nonceLen <= 0 {
				color.Red("Invalid values provided. Memory/time/parallelism must be > 0 and lengths must be positive.")
				return
			}

			customProfile := src.CryptoProfile{
				Name:        chosenName,
				KDF:         "argon2id",
				Memory:      memMB * 1024,
				Time:        t,
				Parallelism: par,
				SaltLen:     saltLen,
				NonceLen:    nonceLen,
			}

			vault.CurrentProfileParams = &customProfile
			vault.Profile = chosenName
			src.AddCustomProfile(customProfile)

			data, err := src.EncryptVault(vault, masterPassword)
			if err != nil {
				color.Red("Encryption failed: %v", err)
				return
			}
			if err := src.SaveVault(vaultPath, data); err != nil {
				color.Red("Error saving vault: %v\n", err)
				return
			}

			color.Green("Custom profile '%s' applied.", chosenName)
			src.LogAction("PROFILE_EDITED", fmt.Sprintf("Profile: %s, Mem=%dMB, Time=%d, Threads=%d", chosenName, memMB, t, par))
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
			src.AddCustomProfile(customProfile)

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

	profileCmd.AddCommand(profileListCmd, profileCurrentCmd, profileSetCmd, profileEditCmd, profileCreateCmd)

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
	loadedCmd := &cobra.Command{
		Use:   "loaded",
		Short: "Show loaded plugins, policies, and .apmignore state",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Loaded state")
			fmt.Println("============")

			fmt.Println("\n[plugins]")
			if pluginMgr == nil {
				fmt.Println("error: plugin manager unavailable")
			} else {
				if err := pluginMgr.LoadPlugins(); err != nil {
					fmt.Printf("error: %v\n", err)
				}
				list := pluginMgr.ListPlugins()
				if len(list) == 0 {
					fmt.Println("(none)")
				} else {
					sort.Strings(list)
					for _, name := range list {
						fmt.Printf("- %s\n", name)
					}
				}
			}

			fmt.Println("\n[policies]")
			policyDir := filepath.Join(filepath.Dir(vaultPath), "policies")
			policies, policyErr := src.LoadPolicies(policyDir)
			if policyErr != nil {
				fmt.Printf("error: %v\n", policyErr)
			} else if len(policies) == 0 {
				fmt.Printf("(none) dir=%s\n", policyDir)
			} else {
				names := make([]string, 0, len(policies))
				for _, p := range policies {
					label := strings.TrimSpace(p.Name)
					if label == "" {
						label = "(unnamed)"
					}
					names = append(names, label)
				}
				sort.Strings(names)
				fmt.Printf("dir=%s\n", policyDir)
				for _, name := range names {
					fmt.Printf("- %s\n", name)
				}
			}

			fmt.Println("\n[.apmignore]")
			ignoreCfg, ignorePath, ignoreErr := src.LoadIgnoreConfigForVault(vaultPath)
			if ignoreErr != nil {
				fmt.Printf("error: %v\n", ignoreErr)
			} else if ignorePath == "" {
				fmt.Println("(not found)")
			} else {
				fmt.Printf("path=%s\n", ignorePath)
				fmt.Printf("spaces=%d entries=%d vocab=%d cloud-specific=%d misc=%d\n",
					len(ignoreCfg.Spaces), len(ignoreCfg.Entries), len(ignoreCfg.Vocab), len(ignoreCfg.CloudSpecific), len(ignoreCfg.Misc))
			}
		},
	}

	rootCmd.AddCommand(addCmd, getCmd, genCmd, modeCmd, sessionCmd, cinfoCmd, auditCmd, trustCmd, totpCmd, importCmd, exportCmd, infoCmd, cloudCmd, healthCmd, policyCmd, spaceCmd, pluginsCmd, setupCmd, unlockCmd, lockCmd, profileCmd, compromiseCmd, authCmd, vocabCmd, loadedCmd)
	autofillCmd, _ := autofillcmd.NewAutofillAndVaultCommands(autofillcmd.Options{
		VaultPath:    &vaultPath,
		ReadPassword: readPassword,
	})
	autocompleteCmd := &cobra.Command{
		Use:   "autocomplete",
		Short: "Manage autocomplete daemon and hints",
	}
	var autocompleteHotkey string
	autocompleteEnableCmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable autocomplete daemon autostart and start now",
		Run: func(cmd *cobra.Command, args []string) {
			if err := autofillcmd.EnableAutofillAutostart(vaultPath, autocompleteHotkey); err != nil {
				color.Red("Failed to enable autostart: %v", err)
				return
			}
			if err := autofillcmd.EnsureAutofillDaemonRunning(vaultPath, autocompleteHotkey); err != nil {
				color.Red("Failed to start autocomplete daemon: %v", err)
				return
			}
			color.Green("Autocomplete daemon autostart enabled and started.")
		},
	}
	autocompleteEnableCmd.Flags().StringVar(&autocompleteHotkey, "hotkey", "CTRL+SHIFT+L", "Global hotkey for system autofill")
	autocompleteDisableCmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable autocomplete daemon autostart and stop daemon",
		Run: func(cmd *cobra.Command, args []string) {
			if err := autofillcmd.DisableAutofillAutostart(); err != nil {
				color.Red("Failed to disable autostart: %v", err)
				return
			}
			if err := autofillcmd.StopAutofillDaemon(); err != nil {
				color.Yellow("Autofill daemon stop failed: %v", err)
			}
			color.Yellow("Autocomplete daemon autostart disabled.")
		},
	}
	autocompleteStartCmd := &cobra.Command{
		Use:   "start",
		Short: "Start the autocomplete daemon",
		Run: func(cmd *cobra.Command, args []string) {
			if err := autofillcmd.EnsureAutofillDaemonRunning(vaultPath, autocompleteHotkey); err != nil {
				color.Red("Failed to start autocomplete daemon: %v", err)
				return
			}
			color.Green("Autocomplete daemon started.")
		},
	}
	autocompleteStartCmd.Flags().StringVar(&autocompleteHotkey, "hotkey", "CTRL+SHIFT+L", "Global hotkey for system autofill")
	autocompleteStopCmd := &cobra.Command{
		Use:   "stop",
		Short: "Stop the autocomplete daemon",
		Run: func(cmd *cobra.Command, args []string) {
			if err := autofillcmd.StopAutofillDaemon(); err != nil {
				color.Yellow("Autocomplete daemon stop failed: %v", err)
				return
			}
			color.Green("Autocomplete daemon stopped.")
		},
	}
	autocompleteStatusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show autocomplete daemon status",
		Run: func(cmd *cobra.Command, args []string) {
			enabled, err := autofillcmd.AutofillAutostartEnabled()
			if err != nil {
				color.Red("Autostart: error (%v)", err)
			} else if enabled {
				color.Green("Autostart: enabled")
			} else {
				color.Yellow("Autostart: disabled")
			}

			status, err := autofill.TryStatus(context.Background())
			if err != nil || status == nil {
				fmt.Println("Daemon: stopped")
				return
			}
			state := "unlocked"
			if status.Locked {
				state = "locked"
			}
			fmt.Printf("Daemon: %s\n", state)
			fmt.Printf("PID: %d\n", status.PID)
			fmt.Printf("Hotkey: %s\n", status.Hotkey)
			fmt.Printf("System Engine: %s\n", status.SystemEngine)
			fmt.Printf("Profiles: %d\n", status.ProfileCount)
			if status.PendingSelection > 0 {
				fmt.Printf("Pending Selection: %d matches\n", status.PendingSelection)
			}
		},
	}
	autocompleteWindowCmd := &cobra.Command{
		Use:   "window",
		Short: "Manage autocomplete popup window",
	}
	autocompleteWindowEnableCmd := &cobra.Command{
		Use:   "enable",
		Short: "Enable autocomplete popup window",
		Run: func(cmd *cobra.Command, args []string) {
			setAutocompletePopupDisabled(false)
		},
	}
	autocompleteWindowDisableCmd := &cobra.Command{
		Use:   "disable",
		Short: "Disable autocomplete popup window",
		Run: func(cmd *cobra.Command, args []string) {
			setAutocompletePopupDisabled(true)
		},
	}
	autocompleteWindowStatusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show autocomplete popup window status",
		Run: func(cmd *cobra.Command, args []string) {
			_, vault, _, err := src_unlockVault()
			if err != nil {
				color.Red("Error: %v", err)
				return
			}
			if vault.AutocompleteWindowDisabled {
				color.Yellow("Autocomplete popup: disabled")
			} else {
				color.Green("Autocomplete popup: enabled")
			}
		},
	}
	autocompleteLinkTOTPCmd := &cobra.Command{
		Use:   "link-totp",
		Short: "Link a domain to an existing TOTP entry",
		Run: func(cmd *cobra.Command, args []string) {
			pass, vault, readonly, err := src_unlockVault()
			if err != nil {
				color.Red("Error: %v", err)
				return
			}
			if readonly {
				color.Red("Vault is READ-ONLY. Cannot modify links.")
				return
			}

			fmt.Print("domain: ")
			domain := normalizeDomainInput(readInput())
			if domain == "" {
				color.Red("Domain is required.")
				return
			}

			entries := orderedTOTPEntries(vault)
			if len(entries) == 0 {
				color.Red("No TOTP entries found in current space.")
				return
			}
			fmt.Println("Available TOTP entries:")
			for i, entry := range entries {
				fmt.Printf("[%d] %s\n", i+1, entry.Account)
			}
			fmt.Print("link-totp-id: ")
			idInput := strings.TrimSpace(readInput())
			idx, err := strconv.Atoi(idInput)
			if err != nil || idx < 1 || idx > len(entries) {
				color.Red("Invalid link-totp-id.")
				return
			}

			if vault.TOTPDomainLinks == nil {
				vault.TOTPDomainLinks = make(map[string]string)
			}
			selected := entries[idx-1]
			vault.TOTPDomainLinks[domain] = selected.Account
			if err := saveVaultState(vault, pass); err != nil {
				color.Red("Failed to save TOTP link: %v", err)
				return
			}
			color.Green("Linked %s -> %s", domain, selected.Account)
			if err := autofillcmd.UnlockDaemonWithPassword(vaultPath, pass, 1*time.Hour, 15*time.Minute, "CTRL+SHIFT+L"); err != nil {
				color.Yellow("Link saved, but autofill daemon auto-start failed: %v", err)
			} else {
				color.Cyan("Autofill daemon is running and unlocked for autocomplete.")
			}
		},
	}
	autocompleteWindowCmd.AddCommand(autocompleteWindowEnableCmd, autocompleteWindowDisableCmd, autocompleteWindowStatusCmd)
	autocompleteCmd.AddCommand(autocompleteEnableCmd, autocompleteDisableCmd, autocompleteStartCmd, autocompleteStopCmd, autocompleteStatusCmd, autocompleteWindowCmd, autocompleteLinkTOTPCmd)

	rootCmd.AddCommand(autofillCmd, autocompleteCmd)
	authCmd.AddCommand(authEmailCmd, authResetCmd, authChangeCmd, authRecoverCmd, authAlertsCmd, authLevelCmd, authQuorumSetupCmd, authQuorumRecoverCmd, authPasskeyCmd, authCodesCmd)
	authPasskeyCmd.AddCommand(authPasskeyRegisterCmd, authPasskeyVerifyCmd, authPasskeyDisableCmd)
	authCodesCmd.AddCommand(authCodesGenerateCmd, authCodesStatusCmd)
	vocabCmd.AddCommand(vocabEnableCmd, vocabDisableCmd, vocabStatusCmd, vocabAliasCmd, vocabAliasListCmd, vocabAliasRemoveCmd, vocabRankCmd, vocabRemoveCmd, vocabReindexCmd)

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

	var tuiCmd = &cobra.Command{
		Use:   "tui",
		Short: "Start the Advanced Password Manager TUI",
		Run: func(cmd *cobra.Command, args []string) {
			res, err := tui.RunUnlock(vaultPath)
			if err != nil {
				color.Red("Unlock failed: %v", err)
				return
			}
			if err := tui.RunTUI(res, vaultPath); err != nil {
				color.Red("TUI Error: %v", err)
			}
		},
	}
	rootCmd.AddCommand(tuiCmd)

	// Register plugin commands as top-level commands (e.g. "pm hello").
	registerDynamicPluginCommands := func() {
		existingNames := make(map[string]struct{})
		for _, registered := range rootCmd.Commands() {
			existingNames[strings.ToLower(strings.TrimSpace(registered.Name()))] = struct{}{}
			for _, alias := range registered.Aliases {
				existingNames[strings.ToLower(strings.TrimSpace(alias))] = struct{}{}
			}
		}

		pluginNames := make([]string, 0, len(pluginMgr.Loaded))
		for name := range pluginMgr.Loaded {
			pluginNames = append(pluginNames, name)
		}
		sort.Strings(pluginNames)

		for _, pluginName := range pluginNames {
			plugin := pluginMgr.Loaded[pluginName]
			if plugin == nil || plugin.Definition == nil || len(plugin.Definition.Commands) == 0 {
				continue
			}

			commandNames := make([]string, 0, len(plugin.Definition.Commands))
			for commandName := range plugin.Definition.Commands {
				commandNames = append(commandNames, commandName)
			}
			sort.Strings(commandNames)

			for _, commandName := range commandNames {
				cmdDef := plugin.Definition.Commands[commandName]
				useName := strings.TrimSpace(commandName)
				if useName == "" {
					continue
				}

				useKey := strings.ToLower(useName)
				if _, exists := existingNames[useKey]; exists {
					continue
				}

				pluginNameCopy := pluginName
				pluginCopy := plugin
				commandNameCopy := commandName
				cmdDefCopy := cmdDef

				short := strings.TrimSpace(cmdDefCopy.Description)
				if short == "" {
					short = fmt.Sprintf("Plugin command: %s/%s", pluginNameCopy, commandNameCopy)
				}

				registeredCmd := &cobra.Command{
					Use:   useName,
					Short: short,
					Args:  cobra.ArbitraryArgs,
					Run: func(cmd *cobra.Command, args []string) {
						overrides := make(map[string]string)
						for flagName := range cmdDefCopy.Flags {
							value, _ := cmd.Flags().GetString(flagName)
							if strings.TrimSpace(value) != "" {
								overrides[flagName] = value
							}
						}

						if err := executePluginCommand(pluginNameCopy, pluginCopy, commandNameCopy, cmdDefCopy, overrides, args); err != nil {
							color.Red("Plugin command failed: %v", err)
						}
					},
				}

				flagNames := make([]string, 0, len(cmdDefCopy.Flags))
				for flagName := range cmdDefCopy.Flags {
					flagNames = append(flagNames, flagName)
				}
				sort.Strings(flagNames)
				for _, flagName := range flagNames {
					flagDef := cmdDefCopy.Flags[flagName]
					registeredCmd.Flags().String(flagName, flagDef.Default, fmt.Sprintf("Plugin flag (%s)", flagDef.Type))
				}

				rootCmd.AddCommand(registeredCmd)
				existingNames[useKey] = struct{}{}
			}
		}
	}
	registerDynamicPluginCommands()

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

func chooseProfileForInit() string {
	info := src.DetectSystemProfileInfo()
	recommended, reason := src.RecommendProfileForSystem(info)

	fmt.Println("\nProfile recommendation based on system info:")
	fmt.Printf("OS: %s/%s, CPU cores: %d", info.OS, info.Arch, info.CPUCores)
	if info.MemoryDetected {
		fmt.Printf(", RAM: %d MB", info.TotalMemoryMB)
	}
	fmt.Println()
	fmt.Printf("Recommended profile: %s (%s)\n", recommended, reason)
	fmt.Printf("Use '%s'? (Y/n): ", recommended)

	answer := strings.ToLower(strings.TrimSpace(readInput()))
	if answer == "" || answer == "y" || answer == "yes" {
		return recommended
	}

	fmt.Printf("Choose profile [%s] (%s): ", recommended, strings.Join(src.GetAvailableProfiles(), ", "))
	choice := strings.ToLower(strings.TrimSpace(readInput()))
	if choice == "" {
		return recommended
	}
	if _, ok := src.Profiles[choice]; !ok {
		color.Yellow("Unknown profile '%s'. Using '%s'.", choice, recommended)
		return recommended
	}
	return choice
}

func activeProfileForVault(vault *src.Vault) src.CryptoProfile {
	if vault.CurrentProfileParams != nil {
		p := *vault.CurrentProfileParams
		if p.Name == "" {
			if vault.Profile != "" {
				p.Name = vault.Profile
			} else {
				p.Name = "standard"
			}
		}
		if p.KDF == "" {
			p.KDF = "argon2id"
		}
		return p
	}

	name := strings.TrimSpace(vault.Profile)
	if name == "" {
		name = "standard"
	}
	p := src.GetProfile(name)
	if p.Name == "" {
		p.Name = name
	}
	if p.KDF == "" {
		p.KDF = "argon2id"
	}
	return p
}

func isBuiltinProfileName(name string) bool {
	_, ok := src.Profiles[strings.ToLower(strings.TrimSpace(name))]
	return ok
}

func readUint32WithDefault(label string, defaultVal uint32) uint32 {
	fmt.Printf("%s [%d]: ", label, defaultVal)
	raw := strings.TrimSpace(readInput())
	if raw == "" {
		return defaultVal
	}
	var parsed uint32
	if _, err := fmt.Sscanf(raw, "%d", &parsed); err != nil {
		color.Yellow("Invalid value '%s'. Keeping %d.", raw, defaultVal)
		return defaultVal
	}
	return parsed
}

func readUint8WithDefault(label string, defaultVal uint8) uint8 {
	fmt.Printf("%s [%d]: ", label, defaultVal)
	raw := strings.TrimSpace(readInput())
	if raw == "" {
		return defaultVal
	}
	var parsed uint8
	if _, err := fmt.Sscanf(raw, "%d", &parsed); err != nil {
		color.Yellow("Invalid value '%s'. Keeping %d.", raw, defaultVal)
		return defaultVal
	}
	return parsed
}

func readIntWithDefault(label string, defaultVal int) int {
	fmt.Printf("%s [%d]: ", label, defaultVal)
	raw := strings.TrimSpace(readInput())
	if raw == "" {
		return defaultVal
	}
	var parsed int
	if _, err := fmt.Sscanf(raw, "%d", &parsed); err != nil {
		color.Yellow("Invalid value '%s'. Keeping %d.", raw, defaultVal)
		return defaultVal
	}
	return parsed
}

func readInput() string {
	input, _ := inputReader.ReadString('\n')
	return strings.TrimSpace(input)
}

func loadIgnoreConfigOrEmpty() src.IgnoreConfig {
	cfg, _, err := src.LoadIgnoreConfigForVault(vaultPath)
	if err != nil {
		return src.IgnoreConfig{}
	}
	return cfg
}

func reindexNoteVocabularyIfEnabled(vault *src.Vault) {
	if vault == nil || !vault.AutocompleteEnabled {
		return
	}
	ignoreCfg := loadIgnoreConfigOrEmpty()
	_ = vault.ReindexNoteVocabulary(ignoreCfg)
}

func saveVaultState(vault *src.Vault, masterPassword string) error {
	data, err := src.EncryptVault(vault, masterPassword)
	if err != nil {
		return err
	}
	return src.SaveVault(vaultPath, data)
}

func captureNoteContent(vault *src.Vault, title, initial string) (string, error) {
	if !term.IsTerminal(int(os.Stdin.Fd())) {
		if strings.TrimSpace(initial) != "" {
			return initial, nil
		}
		fmt.Println("Content (end with empty line):")
		var contentLines []string
		for {
			line := readInput()
			if line == "" {
				break
			}
			contentLines = append(contentLines, line)
		}
		return strings.Join(contentLines, "\n"), nil
	}

	if title == "" {
		title = "Untitled Note"
	}
	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		return "", err
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	buffer := []rune(initial)
	cursor := len(buffer)
	dismissedSuggestion := ""

	type suggestionState struct {
		prefix string
		word   string
	}

	getWordRangeAtCursor := func() (int, int, string) {
		if cursor == 0 {
			return cursor, cursor, ""
		}
		i := cursor - 1
		for i >= 0 && !isNoteWordRune(buffer[i]) {
			if unicode.IsSpace(buffer[i]) {
				i--
				continue
			}
			return cursor, cursor, ""
		}
		if i < 0 || !isNoteWordRune(buffer[i]) {
			return cursor, cursor, ""
		}
		end := i + 1
		for i >= 0 && isNoteWordRune(buffer[i]) {
			i--
		}
		start := i + 1
		return start, end, string(buffer[start:end])
	}

	insertRunes := func(insert []rune) {
		left := append([]rune{}, buffer[:cursor]...)
		right := append([]rune{}, buffer[cursor:]...)
		buffer = append(left, append(insert, right...)...)
		cursor += len(insert)
	}

	deleteBeforeCursor := func() {
		if cursor == 0 {
			return
		}
		buffer = append(buffer[:cursor-1], buffer[cursor:]...)
		cursor--
	}

	applyWordTransforms := func() {
		start, end, word := getWordRangeAtCursor()
		if word == "" {
			return
		}

		lowerWord := strings.ToLower(word)
		autocorrect := map[string]string{
			"teh":        "the",
			"adn":        "and",
			"recieve":    "receive",
			"seperate":   "separate",
			"definately": "definitely",
		}

		replacement := word
		if corrected, ok := autocorrect[lowerWord]; ok {
			replacement = corrected
		}
		if value, ok := vault.ResolveVocabAlias(lowerWord); ok {
			replacement = value
		}
		if replacement == word {
			return
		}

		left := append([]rune{}, buffer[:start]...)
		right := append([]rune{}, buffer[end:]...)
		insert := []rune(replacement)
		buffer = append(left, append(insert, right...)...)
		cursor = start + len(insert)
	}

	render := func(s suggestionState) {
		fmt.Print("\033[H\033[2J")
		fmt.Printf("APM Note Editor - %s\n", title)
		fmt.Println("Ctrl+S save | Esc cancel | Right accept suggestion | Left dismiss suggestion")
		fmt.Println("Auto: autocorrect, bracket pair (), alias replacement on space")
		fmt.Println("--------------------------------------------------------------")

		ghostSuffix := ""
		if s.word != "" {
			ghostSuffix = strings.TrimPrefix(s.word, strings.ToLower(s.prefix))
		}

		var view strings.Builder
		for i, r := range buffer {
			if i == cursor {
				view.WriteRune('█')
				if ghostSuffix != "" {
					view.WriteString("\033[90m")
					view.WriteString(ghostSuffix)
					view.WriteString("\033[0m")
				}
			}
			view.WriteRune(r)
		}
		if cursor == len(buffer) {
			view.WriteRune('█')
			if ghostSuffix != "" {
				view.WriteString("\033[90m")
				view.WriteString(ghostSuffix)
				view.WriteString("\033[0m")
			}
		}
		if len(buffer) == 0 {
			view.WriteRune('█')
		}
		fmt.Println(view.String())
		fmt.Println("--------------------------------------------------------------")
	}

	buildSuggestion := func() suggestionState {
		if vault == nil || !vault.AutocompleteEnabled {
			return suggestionState{}
		}
		start, end, word := getWordRangeAtCursor()
		_ = start
		if word == "" {
			return suggestionState{}
		}
		if end != cursor {
			return suggestionState{}
		}
		prefix := strings.ToLower(word)
		if dismissedSuggestion == prefix {
			return suggestionState{}
		}
		suggestions, err := vault.SuggestNoteWords(prefix, 1, loadIgnoreConfigOrEmpty())
		if err != nil || len(suggestions) == 0 {
			return suggestionState{}
		}
		return suggestionState{prefix: prefix, word: suggestions[0]}
	}

	for {
		s := buildSuggestion()
		render(s)

		key := make([]byte, 8)
		n, err := os.Stdin.Read(key)
		if err != nil || n == 0 {
			return "", err
		}
		seq := string(key[:n])

		if n == 1 {
			ch := key[0]
			switch ch {
			case 19: // Ctrl+S
				return string(buffer), nil
			case 27: // Esc
				return "", fmt.Errorf("note edit cancelled")
			case 127, 8:
				deleteBeforeCursor()
				dismissedSuggestion = ""
			case '\r', '\n':
				if cursor < len(buffer) && isNoteWordRune(buffer[cursor]) {
					for cursor < len(buffer) && isNoteWordRune(buffer[cursor]) {
						cursor++
					}
				}
				insertRunes([]rune{'\n'})
				dismissedSuggestion = ""
			case ' ':
				applyWordTransforms()
				insertRunes([]rune{' '})
				dismissedSuggestion = ""
			case '(':
				insertRunes([]rune{'(', ')'})
				cursor--
				dismissedSuggestion = ""
			case ')':
				if cursor < len(buffer) && buffer[cursor] == ')' {
					cursor++
				} else {
					insertRunes([]rune{')'})
				}
			default:
				if ch >= 32 && ch <= 126 {
					insertRunes([]rune{rune(ch)})
					dismissedSuggestion = ""
				}
			}
			continue
		}

		switch {
		case strings.Contains(seq, "\x1b[C"):
			if s.word != "" {
				suffix := strings.TrimPrefix(s.word, strings.ToLower(s.prefix))
				if suffix != "" {
					insertRunes([]rune(suffix))
					_ = vault.RecordNoteSuggestionFeedback(s.word, true)
					dismissedSuggestion = ""
				}
			} else if cursor < len(buffer) {
				cursor++
			}
		case strings.Contains(seq, "\x1b[D"):
			if s.word != "" {
				_ = vault.RecordNoteSuggestionFeedback(s.word, false)
				dismissedSuggestion = s.prefix
			} else if cursor > 0 {
				cursor--
			}
		case strings.Contains(seq, "\x1b[A"):
			// Cursor up reserved for future line navigation.
		case strings.Contains(seq, "\x1b[B"):
			// Cursor down reserved for future line navigation.
		}
	}
}

func isNoteWordRune(r rune) bool {
	return unicode.IsLetter(r) || unicode.IsDigit(r) || r == '\''
}

var k_m = []byte("AaravMalooAPMSecureCloudSync2025!")

func d(b []byte) string {
	res := make([]byte, len(b))
	for i, v := range b {
		val := byte(v - 13)
		val = (val >> 3) | (val << 5)
		res[i] = val ^ byte(i) ^ k_m[i%len(k_m)]
	}
	return string(res)
}

func apmSMTPConfig() (string, int, string, string) {
	host := d([]byte{158, 117, 45, 157, 239, 134, 93, 93, 125, 93, 56, 206, 126, 166})
	port := 587
	user := d([]byte{14, 21, 29, 37, 45, 54, 61, 69, 77, 85, 232, 120, 21, 214, 61, 117, 109, 133, 215, 166, 197, 197})
	passEmail := d([]byte{78, 157, 85, 141, 159, 70, 93, 69, 149, 63, 38, 134, 142, 206, 103, 237, 197, 101, 61})
	return host, port, user, passEmail
}

func setAPMEmailBody(msg *gomail.Message, title string, paragraphs []string, code string, tips []string) {
	var textBuilder strings.Builder
	textBuilder.WriteString("APM Security Notification\n\n")
	textBuilder.WriteString(strings.TrimSpace(title))
	textBuilder.WriteString("\n\n")
	for _, p := range paragraphs {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		textBuilder.WriteString(p)
		textBuilder.WriteString("\n\n")
	}
	if code != "" {
		textBuilder.WriteString("Verification code: ")
		textBuilder.WriteString(code)
		textBuilder.WriteString("\n\n")
	}
	if len(tips) > 0 {
		textBuilder.WriteString("Security tips:\n")
		for _, t := range tips {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			textBuilder.WriteString("- ")
			textBuilder.WriteString(t)
			textBuilder.WriteString("\n")
		}
	}
	msg.SetBody("text/plain", strings.TrimSpace(textBuilder.String())+"\n")

	var htmlBuilder strings.Builder
	htmlBuilder.WriteString(`<!doctype html>
<html>
<body style="margin:0;padding:28px;background:linear-gradient(160deg,#f8fafc 0%,#edf2f7 100%);font-family:-apple-system,BlinkMacSystemFont,'Segoe UI',Arial,sans-serif;color:#111827;">
  <table role="presentation" width="100%" cellspacing="0" cellpadding="0" style="max-width:680px;margin:0 auto;">
    <tr>
      <td style="padding:0 0 14px;">
        <div style="display:inline-block;background:#0f172a;color:#ffffff;font-size:12px;letter-spacing:0.08em;padding:6px 10px;border-radius:999px;">APM SECURITY</div>
      </td>
    </tr>
    <tr>
      <td style="background:#ffffff;border:1px solid #e5e7eb;border-radius:14px;padding:34px;box-shadow:0 16px 45px rgba(2,6,23,0.07);">
        <div style="font-size:30px;font-weight:800;letter-spacing:0.06em;margin-bottom:18px;">APM</div>
        <h1 style="font-size:29px;line-height:1.3;margin:0 0 20px;">`)
	htmlBuilder.WriteString(html.EscapeString(strings.TrimSpace(title)))
	htmlBuilder.WriteString(`</h1>`)
	for _, p := range paragraphs {
		p = strings.TrimSpace(p)
		if p == "" {
			continue
		}
		htmlBuilder.WriteString(`<p style="font-size:18px;line-height:1.65;margin:0 0 14px;">`)
		htmlBuilder.WriteString(html.EscapeString(p))
		htmlBuilder.WriteString(`</p>`)
	}
	if code != "" {
		htmlBuilder.WriteString(`<div style="margin:20px 0 16px;"><span style="display:inline-block;padding:18px 24px;border-radius:12px;background:#f3f4f6;color:#111827;font-size:46px;font-weight:800;letter-spacing:0.28em;">`)
		htmlBuilder.WriteString(html.EscapeString(code))
		htmlBuilder.WriteString(`</span></div>`)
	}
	if len(tips) > 0 {
		htmlBuilder.WriteString(`<div style="margin-top:18px;padding:16px 18px;background:#f8fafc;border:1px solid #e5e7eb;border-radius:10px;"><div style="font-size:14px;font-weight:700;color:#334155;letter-spacing:0.04em;margin-bottom:8px;">SECURITY TIPS</div><ul style="padding-left:20px;margin:0;">`)
		for _, t := range tips {
			t = strings.TrimSpace(t)
			if t == "" {
				continue
			}
			htmlBuilder.WriteString(`<li style="font-size:14px;line-height:1.55;color:#475569;margin:0 0 6px;">`)
			htmlBuilder.WriteString(html.EscapeString(t))
			htmlBuilder.WriteString(`</li>`)
		}
		htmlBuilder.WriteString(`</ul></div>`)
	}
	htmlBuilder.WriteString(`</td>
    </tr>
    <tr>
      <td style="padding:14px 2px 0;color:#64748b;font-size:12px;line-height:1.6;">
        This is an automated security message from APM.
      </td>
    </tr>
  </table>
</body>
</html>`)
	msg.AddAlternative("text/html", htmlBuilder.String())
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
		return "", nil, false, fmt.Errorf("Vault not found. Run 'pm setup'.")
	}

	localFailures := src.GetFailureCount()

	if ephID := strings.TrimSpace(os.Getenv("APM_EPHEMERAL_ID")); ephID != "" {
		eph, err := src.ValidateEphemeralSession(ephID, os.Getpid(), strings.TrimSpace(os.Getenv("APM_EPHEMERAL_AGENT")))
		if err == nil {
			data, lerr := src.LoadVault(vaultPath)
			if lerr == nil {
				vault, derr := src.DecryptVault(data, eph.MasterPassword, 1)
				if derr == nil {
					readonly := eph.Scope == "read"
					src.LogAction("EPHEMERAL_UNLOCK", fmt.Sprintf("Unlocked using ephemeral session '%s' scope=%s", eph.ID, eph.Scope))
					return eph.MasterPassword, vault, readonly, nil
				}
			}
		}
	}

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

func handleInteractiveEntries(v *src.Vault, masterPassword, initialQuery string, readonly, showPass bool) {
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
			displayEntry(results[0], showPass, false)
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
					fmt.Printf("\x1b[1;7m %s \x1b[0m \x1b[1;32m<-- PRESS E/D/V/SPACE/S\x1b[0m\n", line)
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
			fmt.Println("\x1b[1;37mUp/Down\x1b[0m: Navigate | \x1b[1;37mSpace\x1b[0m: Quicklook | \x1b[1;37ms\x1b[0m: Select | \x1b[1;37ma\x1b[0m: All | \x1b[1;37mc\x1b[0m: Clear")
			fmt.Println("\x1b[1;37mEnter/v\x1b[0m: View | \x1b[1;37mi\x1b[0m: Metadata | \x1b[1;37me\x1b[0m: Edit | \x1b[1;37md\x1b[0m: Delete | \x1b[1;37mEsc/Tab\x1b[0m: Focus Search")
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
				handleAction(v, masterPassword, results[selectedIndex], 'v', readonly, showPass, oldState)
				oldState, _ = term.MakeRaw(int(os.Stdin.Fd()))
			}
			continue
		}

		if focusMode == 1 {
			if b[0] == ' ' {
				if len(results) > 0 {
					handleAction(v, masterPassword, results[selectedIndex], 'q', readonly, showPass, oldState)
					oldState, _ = term.MakeRaw(int(os.Stdin.Fd()))
				}
				continue
			}
			if b[0] == 's' || b[0] == 'S' {
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
					handleAction(v, masterPassword, results[selectedIndex], 'e', readonly, showPass, oldState)
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
						noteChanged := false
						for key, res := range selectedItems {
							if deleteEntryByResult(v, res) {
								if res.Type == "Note" {
									noteChanged = true
								}
								delete(selectedItems, key)
							}
						}
						if noteChanged {
							reindexNoteVocabularyIfEnabled(v)
						}
						data, _ := src.EncryptVault(v, masterPassword)
						src.SaveVault(vaultPath, data)
						color.Green("Bulk deletion complete.")
						fmt.Print("\nPress Enter to continue...")
						readInput()
					}
					oldState, _ = term.MakeRaw(int(os.Stdin.Fd()))
				} else if len(results) > 0 {
					handleAction(v, masterPassword, results[selectedIndex], 'd', readonly, showPass, oldState)
					oldState, _ = term.MakeRaw(int(os.Stdin.Fd()))
				}
				continue
			}
			if b[0] == 'v' {
				if len(results) > 0 {
					handleAction(v, masterPassword, results[selectedIndex], 'v', readonly, showPass, oldState)
					oldState, _ = term.MakeRaw(int(os.Stdin.Fd()))
				}
				continue
			}
			if b[0] == 'i' {
				if len(selectedItems) > 0 {
					_ = term.Restore(int(os.Stdin.Fd()), oldState)
					for _, res := range selectedItems {
						fmt.Print("\033[H\033[2J")
						displayEntryMetadata(v, res)
						fmt.Print("\nPress Enter to continue...")
						readInput()
					}
					oldState, _ = term.MakeRaw(int(os.Stdin.Fd()))
				} else if len(results) > 0 {
					handleAction(v, masterPassword, results[selectedIndex], 'i', readonly, showPass, oldState)
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

func currentSpaceDisplay(v *src.Vault) string {
	if v == nil || strings.TrimSpace(v.CurrentSpace) == "" {
		return "default"
	}
	return strings.TrimSpace(v.CurrentSpace)
}

func normalizeDomainInput(raw string) string {
	raw = strings.ToLower(strings.TrimSpace(raw))
	raw = strings.TrimPrefix(raw, "http://")
	raw = strings.TrimPrefix(raw, "https://")
	raw = strings.TrimPrefix(raw, "www.")
	if idx := strings.Index(raw, "/"); idx >= 0 {
		raw = raw[:idx]
	}
	return strings.TrimSpace(raw)
}

func totpOrderKey(entry src.TOTPEntry) string {
	space := strings.TrimSpace(entry.Space)
	if space == "" {
		space = "default"
	}
	return strings.ToLower(space + "|" + strings.TrimSpace(entry.Account))
}

func orderedTOTPEntries(v *src.Vault) []src.TOTPEntry {
	if v == nil || len(v.TOTPEntries) == 0 {
		return nil
	}
	current := currentSpaceDisplay(v)
	target := make([]src.TOTPEntry, 0, len(v.TOTPEntries))
	for _, entry := range v.TOTPEntries {
		space := strings.TrimSpace(entry.Space)
		if space == "" {
			space = "default"
		}
		if strings.EqualFold(space, current) {
			target = append(target, entry)
		}
	}

	if len(target) == 0 {
		return target
	}

	orderIndex := make(map[string]int, len(v.TOTPOrder))
	for i, key := range v.TOTPOrder {
		key = strings.ToLower(strings.TrimSpace(key))
		if key != "" {
			orderIndex[key] = i
		}
	}

	sort.SliceStable(target, func(i, j int) bool {
		keyI := totpOrderKey(target[i])
		keyJ := totpOrderKey(target[j])
		idxI, okI := orderIndex[keyI]
		idxJ, okJ := orderIndex[keyJ]
		if okI && okJ {
			return idxI < idxJ
		}
		if okI != okJ {
			return okI
		}
		return strings.ToLower(target[i].Account) < strings.ToLower(target[j].Account)
	})
	return target
}

func persistTOTPOrder(v *src.Vault, masterPassword string, ordered []src.TOTPEntry) error {
	kept := make([]string, 0, len(v.TOTPOrder)+len(ordered))
	seen := make(map[string]struct{}, len(v.TOTPOrder)+len(ordered))

	currentPrefix := strings.ToLower(currentSpaceDisplay(v) + "|")
	for _, entry := range ordered {
		key := totpOrderKey(entry)
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		kept = append(kept, key)
	}
	for _, key := range v.TOTPOrder {
		key = strings.ToLower(strings.TrimSpace(key))
		if key == "" || strings.HasPrefix(key, currentPrefix) {
			continue
		}
		if _, ok := seen[key]; ok {
			continue
		}
		seen[key] = struct{}{}
		kept = append(kept, key)
	}

	v.TOTPOrder = kept
	data, err := src.EncryptVault(v, masterPassword)
	if err != nil {
		return err
	}
	return src.SaveVault(vaultPath, data)
}

func findTOTPEntry(entries []src.TOTPEntry, query string) (src.TOTPEntry, bool) {
	query = strings.TrimSpace(query)
	if query == "" {
		return src.TOTPEntry{}, false
	}
	for _, entry := range entries {
		if strings.EqualFold(entry.Account, query) {
			return entry, true
		}
	}

	lowerQuery := strings.ToLower(query)
	for _, entry := range entries {
		if strings.Contains(strings.ToLower(entry.Account), lowerQuery) {
			return entry, true
		}
	}
	return src.TOTPEntry{}, false
}

func runInteractiveTOTP(v *src.Vault, masterPassword string) {
	entries := orderedTOTPEntries(v)
	if len(entries) == 0 {
		fmt.Println("No TOTP entries found.")
		return
	}

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		for i, entry := range entries {
			code, err := src.GenerateTOTP(entry.Secret)
			if err != nil {
				code = "INVALID"
			}
			fmt.Printf("[%d] %-24s : %s\n", i+1, entry.Account, code)
		}
		return
	}

	oldState, err := term.MakeRaw(int(os.Stdin.Fd()))
	if err != nil {
		color.Red("Failed to initialize interactive TOTP view: %v", err)
		return
	}
	defer term.Restore(int(os.Stdin.Fd()), oldState)

	fmt.Println("\x1b[?25l")
	defer fmt.Print("\x1b[?25h")

	inputCh := make(chan []byte, 16)
	go func() {
		for {
			buf := make([]byte, 8)
			n, err := os.Stdin.Read(buf)
			if err != nil || n == 0 {
				close(inputCh)
				return
			}
			packet := make([]byte, n)
			copy(packet, buf[:n])
			inputCh <- packet
		}
	}()

	selected := 0
	status := ""
	ticker := time.NewTicker(500 * time.Millisecond)
	defer ticker.Stop()

	for {
		entries = orderedTOTPEntries(v)
		if len(entries) == 0 {
			fmt.Print("\033[H\033[2J")
			fmt.Println("No TOTP entries left in the current space.")
			return
		}
		if selected < 0 {
			selected = 0
		}
		if selected >= len(entries) {
			selected = len(entries) - 1
		}

		fmt.Print("\033[H\033[2J")
		fmt.Printf("APM TOTP | Space: %s | Refresh: %ds\n", currentSpaceDisplay(v), src.TimeRemaining())
		fmt.Println("Enter: copy selected | 1-9: copy by number | Shift+Up/Down: reorder | Up/Down: move | q/Esc: exit")
		if status != "" {
			fmt.Printf("%s\n", status)
			status = ""
		}
		fmt.Println("--------------------------------------------------------------")
		for i, entry := range entries {
			code, err := src.GenerateTOTP(entry.Secret)
			if err != nil {
				code = "INVALID"
			}
			marker := " "
			if i == selected {
				marker = ">"
			}
			fmt.Printf("%s [%d] %-26s %s\n", marker, i+1, entry.Account, code)
		}

		select {
		case packet, ok := <-inputCh:
			if !ok {
				return
			}

			if len(packet) == 1 {
				ch := packet[0]
				switch ch {
				case 'q', 'Q', 3, 4, 27:
					return
				case '\r', '\n':
					entry := entries[selected]
					code, err := src.GenerateTOTP(entry.Secret)
					if err != nil {
						status = color.RedString("Failed to generate TOTP for %s", entry.Account)
						break
					}
					copyToClipboard(code)
					src.LogAction("TOTP_COPIED", fmt.Sprintf("Account: %s", entry.Account))
					status = color.GreenString("Copied TOTP for %s", entry.Account)
				default:
					if ch >= '1' && ch <= '9' {
						idx := int(ch - '1')
						if idx >= 0 && idx < len(entries) {
							entry := entries[idx]
							code, err := src.GenerateTOTP(entry.Secret)
							if err != nil {
								status = color.RedString("Failed to generate TOTP for %s", entry.Account)
								break
							}
							copyToClipboard(code)
							src.LogAction("TOTP_COPIED", fmt.Sprintf("Account: %s", entry.Account))
							status = color.GreenString("Copied TOTP for %s", entry.Account)
							selected = idx
						}
					}
				}
				continue
			}

			sequence := string(packet)
			switch {
			case strings.Contains(sequence, "\x1b[1;2A"):
				if selected > 0 {
					entries[selected], entries[selected-1] = entries[selected-1], entries[selected]
					if err := persistTOTPOrder(v, masterPassword, entries); err != nil {
						status = color.RedString("Failed to save TOTP order: %v", err)
					} else {
						selected--
						status = color.CyanString("Moved %s up", entries[selected].Account)
					}
				}
			case strings.Contains(sequence, "\x1b[1;2B"):
				if selected < len(entries)-1 {
					entries[selected], entries[selected+1] = entries[selected+1], entries[selected]
					if err := persistTOTPOrder(v, masterPassword, entries); err != nil {
						status = color.RedString("Failed to save TOTP order: %v", err)
					} else {
						selected++
						status = color.CyanString("Moved %s down", entries[selected].Account)
					}
				}
			case strings.Contains(sequence, "\x1b[A"):
				if selected > 0 {
					selected--
				}
			case strings.Contains(sequence, "\x1b[B"):
				if selected < len(entries)-1 {
					selected++
				}
			}
		case <-ticker.C:
		}
	}
}

func pluginPermissionEnabled(vault *src.Vault, pluginName, permission string) bool {
	if vault == nil || vault.PluginPermissionOverrides == nil {
		return true
	}
	pluginKey := strings.ToLower(strings.TrimSpace(pluginName))
	permKey := strings.ToLower(strings.TrimSpace(permission))
	if pluginKey == "" || permKey == "" {
		return true
	}
	pluginRules := vault.PluginPermissionOverrides[pluginKey]
	if len(pluginRules) == 0 {
		return true
	}
	enabled, exists := pluginRules[permKey]
	if !exists {
		return true
	}
	return enabled
}

func setPluginPermissionOverride(vault *src.Vault, pluginName, permission string, enabled bool) {
	if vault.PluginPermissionOverrides == nil {
		vault.PluginPermissionOverrides = make(map[string]map[string]bool)
	}
	pluginKey := strings.ToLower(strings.TrimSpace(pluginName))
	permKey := strings.ToLower(strings.TrimSpace(permission))
	if pluginKey == "" || permKey == "" {
		return
	}
	if vault.PluginPermissionOverrides[pluginKey] == nil {
		vault.PluginPermissionOverrides[pluginKey] = make(map[string]bool)
	}
	vault.PluginPermissionOverrides[pluginKey][permKey] = enabled
}

func applyPluginPermissionOverrides(vault *src.Vault, pluginName string, declared []string) []string {
	filtered := make([]string, 0, len(declared))
	for _, permission := range declared {
		if pluginPermissionEnabled(vault, pluginName, permission) {
			filtered = append(filtered, permission)
		}
	}
	return filtered
}

func handleAction(v *src.Vault, mp string, res src.SearchResult, action byte, readonly, showPass bool, oldState *term.State) {
	_ = term.Restore(int(os.Stdin.Fd()), oldState)
	fmt.Print("\033[H\033[2J")

	switch action {
	case 'v':
		displayEntry(res, showPass, true)
	case 'q':
		displayQuicklook(res)
	case 'i':
		displayEntryMetadata(v, res)
	case 'e':
		if readonly {
			color.Red("Vault is READ-ONLY.")
		} else {
			editEntryInVault(v, mp, res)
		}
	case 'd':
		if readonly {
			color.Red("Vault is READ-ONLY.")
		} else {
			fmt.Printf("Are you sure you want to delete '%s' (%s)? (y/n): ", res.Identifier, res.Type)
			if strings.ToLower(readInput()) == "y" {
				if deleteEntryByResult(v, res) {
					if res.Type == "Note" {
						reindexNoteVocabularyIfEnabled(v)
					}
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

func displayQuicklook(res src.SearchResult) {
	switch res.Type {
	case "Note":
		n := res.Data.(src.SecureNoteEntry)
		fmt.Printf("Quicklook: Note/%s\n", n.Name)
		fmt.Println("--------------------------------------------------")
		content := strings.TrimSpace(n.Content)
		if content == "" {
			fmt.Println("(empty note)")
			return
		}
		lines := strings.Split(content, "\n")
		limit := 18
		if len(lines) > limit {
			for _, line := range lines[:limit] {
				fmt.Println(line)
			}
			fmt.Printf("... (%d more lines)\n", len(lines)-limit)
			return
		}
		for _, line := range lines {
			fmt.Println(line)
		}
	case "Photo":
		p := res.Data.(src.PhotoEntry)
		fmt.Printf("Quicklook: Photo/%s (%s)\n", p.Name, p.FileName)
		fmt.Println("--------------------------------------------------")
		preview, err := renderPhotoASCIIQuicklook(p.Content, 64)
		if err != nil {
			fmt.Printf("Photo preview unavailable: %v\n", err)
			fmt.Printf("Size: %.2f KB\n", float64(len(p.Content))/1024)
			return
		}
		fmt.Println(preview)
	case "Audio":
		a := res.Data.(src.AudioEntry)
		fmt.Printf("Quicklook: Audio/%s (%s)\n", a.Name, a.FileName)
		fmt.Printf("Size: %.2f KB\n", float64(len(a.Content))/1024)
	case "Video":
		v := res.Data.(src.VideoEntry)
		fmt.Printf("Quicklook: Video/%s (%s)\n", v.Name, v.FileName)
		fmt.Printf("Size: %.2f KB\n", float64(len(v.Content))/1024)
	case "Document":
		d := res.Data.(src.DocumentEntry)
		fmt.Printf("Quicklook: Document/%s (%s)\n", d.Name, d.FileName)
		fmt.Printf("Size: %.2f KB\n", float64(len(d.Content))/1024)
	default:
		fmt.Printf("Quicklook is supported for notes and media entries only. Selected type: %s\n", res.Type)
	}
}

func renderPhotoASCIIQuicklook(content []byte, maxWidth int) (string, error) {
	if maxWidth <= 0 {
		maxWidth = 64
	}
	img, _, err := image.Decode(bytes.NewReader(content))
	if err != nil {
		return "", err
	}
	bounds := img.Bounds()
	width := bounds.Dx()
	height := bounds.Dy()
	if width <= 0 || height <= 0 {
		return "", fmt.Errorf("invalid image dimensions")
	}

	targetWidth := width
	if targetWidth > maxWidth {
		targetWidth = maxWidth
	}
	if targetWidth < 1 {
		targetWidth = 1
	}

	targetHeight := int(float64(height) * (float64(targetWidth) / float64(width)) * 0.5)
	if targetHeight < 1 {
		targetHeight = 1
	}

	palette := []rune(" .:-=+*#%@")
	var b strings.Builder
	b.WriteString(fmt.Sprintf("%dx%d -> %dx%d\n", width, height, targetWidth, targetHeight))
	for y := 0; y < targetHeight; y++ {
		srcY := bounds.Min.Y + (y*height)/targetHeight
		for x := 0; x < targetWidth; x++ {
			srcX := bounds.Min.X + (x*width)/targetWidth
			r, g, bl, _ := img.At(srcX, srcY).RGBA()
			gray := (299*int(r>>8) + 587*int(g>>8) + 114*int(bl>>8)) / 1000
			idx := (gray * (len(palette) - 1)) / 255
			b.WriteRune(palette[idx])
		}
		b.WriteByte('\n')
	}
	return b.String(), nil
}

func resultTypeToHistoryCategory(resultType string) string {
	switch resultType {
	case "Password":
		return "PASSWORD"
	case "TOTP":
		return "TOTP"
	case "Token":
		return "TOKEN"
	case "Note":
		return "NOTE"
	case "API Key":
		return "APIKEY"
	case "SSH Key":
		return "SSHKEY"
	case "Wi-Fi":
		return "WIFI"
	case "Recovery Codes":
		return "RECOVERY"
	case "Certificate":
		return "CERTIFICATE"
	case "Banking":
		return "BANKING"
	case "Document":
		return "DOCUMENT"
	case "Audio":
		return "AUDIO"
	case "Video":
		return "VIDEO"
	case "Photo":
		return "PHOTO"
	case "Government ID":
		return "GOVID"
	case "Medical Record":
		return "MEDICAL"
	case "Travel":
		return "TRAVEL"
	case "Contact":
		return "CONTACT"
	case "Cloud Credentials":
		return "CLOUDCRED"
	case "Kubernetes Secret":
		return "K8S"
	case "Docker Registry":
		return "DOCKER"
	case "SSH Config":
		return "SSHCONFIG"
	case "CI/CD Secret":
		return "CICD"
	case "Software License":
		return "LICENSE"
	case "Legal Contract":
		return "CONTRACT"
	default:
		return strings.ToUpper(strings.ReplaceAll(resultType, " ", ""))
	}
}

func inferCreatorFromAudit(identifier string) string {
	logs, err := src.GetAuditLogs(500)
	if err != nil {
		return ""
	}
	target := "'" + strings.ToLower(identifier) + "'"
	for i := len(logs) - 1; i >= 0; i-- {
		details := strings.ToLower(logs[i].Details)
		if strings.Contains(details, target) && strings.Contains(logs[i].Action, "MCP_ENTRY_ADDED") {
			return "AI (MCP)"
		}
	}
	return ""
}

func displayEntryMetadata(v *src.Vault, res src.SearchResult) {
	category := resultTypeToHistoryCategory(res.Type)
	space := res.Space
	if space == "" {
		space = "default"
	}

	telemetry, hasTelemetry := v.GetSecretTelemetry(category, res.Identifier, res.Space)

	var createdAt time.Time
	var lastAccessed time.Time
	var lastUpdated time.Time
	var createdBy string
	var lastAccessedBy string
	var lastUpdatedBy string
	addCount := 0
	viewCount := 0
	editCount := 0
	deleteCount := 0
	lastAction := ""
	lastActionAt := time.Time{}

	for _, h := range v.History {
		if h.Category != category || h.Identifier != res.Identifier {
			continue
		}
		if createdAt.IsZero() || h.Timestamp.Before(createdAt) {
			createdAt = h.Timestamp
		}
		if h.Timestamp.After(lastActionAt) {
			lastActionAt = h.Timestamp
			lastAction = h.Action
		}
		switch h.Action {
		case "ADD":
			addCount++
			if h.Timestamp.After(lastUpdated) {
				lastUpdated = h.Timestamp
			}
		case "GET", "VIEW":
			viewCount++
			if h.Timestamp.After(lastAccessed) {
				lastAccessed = h.Timestamp
			}
		case "EDIT":
			editCount++
			if h.Timestamp.After(lastUpdated) {
				lastUpdated = h.Timestamp
			}
		case "DEL":
			deleteCount++
		}
	}

	if hasTelemetry {
		if createdAt.IsZero() || (!telemetry.CreatedAt.IsZero() && telemetry.CreatedAt.Before(createdAt)) {
			createdAt = telemetry.CreatedAt
		}
		if telemetry.LastAccessed.After(lastAccessed) {
			lastAccessed = telemetry.LastAccessed
		}
		if telemetry.UpdatedAt.After(lastUpdated) {
			lastUpdated = telemetry.UpdatedAt
		}
		createdBy = telemetry.CreatedBy
		lastAccessedBy = telemetry.LastAccessedBy
		lastUpdatedBy = telemetry.UpdatedBy
	}

	if createdBy == "" {
		createdBy = inferCreatorFromAudit(res.Identifier)
		if createdBy == "" {
			createdBy = "User (history inference)"
		}
	}
	if lastAccessedBy == "" {
		lastAccessedBy = "Unknown"
	}
	if lastUpdatedBy == "" {
		lastUpdatedBy = "Unknown"
	}

	var trustScore *src.SecretTrustScore
	for _, s := range v.ComputeSecretTrustScores() {
		if s.Category == category && s.Identifier == res.Identifier && (s.Space == res.Space || (s.Space == "" && res.Space == "")) {
			copyScore := s
			trustScore = &copyScore
			break
		}
	}

	fmt.Printf("Metadata: %s (%s)\n", res.Identifier, res.Type)
	fmt.Println("--------------------------------------------------")
	fmt.Printf("Space:                %s\n", space)
	fmt.Printf("Category Key:         %s\n", category)
	if !createdAt.IsZero() {
		fmt.Printf("Created At:           %s\n", createdAt.Format(time.RFC3339))
	} else {
		fmt.Println("Created At:           Unknown")
	}
	fmt.Printf("Created By:           %s\n", createdBy)
	if !lastAccessed.IsZero() {
		fmt.Printf("Last Accessed:        %s\n", lastAccessed.Format(time.RFC3339))
	} else {
		fmt.Println("Last Accessed:        Unknown")
	}
	fmt.Printf("Last Accessed By:     %s\n", lastAccessedBy)
	if !lastUpdated.IsZero() {
		fmt.Printf("Last Updated:         %s\n", lastUpdated.Format(time.RFC3339))
	} else {
		fmt.Println("Last Updated:         Unknown")
	}
	fmt.Printf("Last Updated By:      %s\n", lastUpdatedBy)
	if hasTelemetry {
		fmt.Printf("Access Count:         %d\n", telemetry.AccessCount)
		fmt.Printf("Privilege:            %s\n", telemetry.Privilege)
		fmt.Printf("Exposure Flag:        %v\n", telemetry.Exposed)
		fmt.Printf("Telemetry Source:     %s\n", telemetry.Source)
	} else {
		fmt.Println("Access Count:         Unknown (legacy entry)")
		fmt.Println("Privilege:            Unknown")
		fmt.Println("Exposure Flag:        Unknown")
	}
	if trustScore != nil {
		fmt.Printf("Trust Score:          %d (%s)\n", trustScore.Score, strings.ToUpper(trustScore.Risk))
		if len(trustScore.Reasons) > 0 {
			fmt.Printf("Trust Factors:        %s\n", strings.Join(trustScore.Reasons, "; "))
		}
	} else {
		fmt.Println("Trust Score:          Not computed yet")
	}
	fmt.Printf("History Totals:       ADD=%d VIEW=%d EDIT=%d DEL=%d\n", addCount, viewCount, editCount, deleteCount)
	if lastAction != "" {
		fmt.Printf("Last History Action:  %s @ %s\n", lastAction, lastActionAt.Format(time.RFC3339))
	}
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
		newContent, err := captureNoteContent(v, newName, e.Content)
		if err != nil {
			color.Yellow("Note edit canceled.")
			return
		}

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
		if res.Type == "Note" {
			reindexNoteVocabularyIfEnabled(v)
		}
		data, _ := src.EncryptVault(v, mp)
		if err := src.SaveVault(vaultPath, data); err != nil {
			color.Red("Error saving vault: %v", err)
		} else {
			src.SendAlert(v, src.LevelAll, "ENTRY MODIFIED", fmt.Sprintf("Modified entry: %s (%s)", res.Identifier, res.Type))
			color.Green("Updated.")
		}
	}
}

func displayEntry(res src.SearchResult, showPass, promptCopy bool) {
	showField := func(label, value string) {
		if showPass {
			fmt.Printf("%s: %s\n", label, value)
			return
		}
		if strings.TrimSpace(value) == "" {
			fmt.Printf("%s: (empty)\n", label)
			return
		}
		fmt.Printf("%s: ******** (hidden", label)
		if promptCopy {
			fmt.Print(", press Enter to copy)\n")
			fmt.Printf("Copy %s? [Enter=copy, type skip to continue]: ", strings.ToLower(label))
			if strings.ToLower(strings.TrimSpace(readInput())) != "skip" {
				copyToClipboardWithExpiry(value)
			}
			return
		}
		fmt.Println(")")
	}

	fmt.Println("---")
	switch res.Type {
	case "Password":
		e := res.Data.(src.Entry)
		fmt.Printf("Type: Password\nAccount: %s\nUser: %s\n", e.Account, e.Username)
		showField("Password", e.Password)
	case "TOTP":
		t := res.Data.(src.TOTPEntry)
		code, err := src.GenerateTOTP(t.Secret)
		if err != nil {
			code = "INVALID SECRET"
		}
		fmt.Printf("Type: TOTP\nAccount: %s\n", t.Account)
		showField("Code", code)
	case "Token":
		tok := res.Data.(src.TokenEntry)
		fmt.Printf("Type: Token\nName: %s\n", tok.Name)
		showField("Token", tok.Token)
	case "Note":
		n := res.Data.(src.SecureNoteEntry)
		fmt.Printf("Type: Note\nName: %s\nContent:\n%s\n", n.Name, n.Content)
	case "API Key":
		k := res.Data.(src.APIKeyEntry)
		fmt.Printf("Type: API Key\nLabel: %s\nService: %s\n", k.Name, k.Service)
		showField("Key", k.Key)
	case "SSH Key":
		s := res.Data.(src.SSHKeyEntry)
		fmt.Printf("Type: SSH Key\nLabel: %s\n", s.Name)
		showField("Private Key", s.PrivateKey)
	case "Wi-Fi":
		w := res.Data.(src.WiFiEntry)
		fmt.Printf("Type: Wi-Fi\nSSID: %s\nSecurity: %s\n", w.SSID, w.SecurityType)
		showField("Password", w.Password)
	case "Recovery Codes":
		r := res.Data.(src.RecoveryCodeEntry)
		fmt.Printf("Type: Recovery\nService: %s\n", r.Service)
		showField("Codes", strings.Join(r.Codes, ", "))
	case "Certificate":
		c := res.Data.(src.CertificateEntry)
		fmt.Printf("Type: Certificate\nLabel: %s\nIssuer: %s\nExpiry: %s\n", c.Label, c.Issuer, c.Expiry.Format("2006-01-02"))
		if time.Until(c.Expiry) < 30*24*time.Hour {
			color.Red("  [ALERT] Certificate is expiring soon! (%s left)\n", time.Until(c.Expiry).Truncate(time.Hour))
		}
		showField("Cert Data", c.CertData)
		if c.PrivateKey != "" {
			showField("Private Key", c.PrivateKey)
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
		showField("Full Details", b.Details)
		if b.CVV != "" {
			showField("CVV", b.CVV)
		}
		if b.Expiry != "" {
			fmt.Printf("Expiry: %s\n", b.Expiry)
		}
	case "Document":
		d := res.Data.(src.DocumentEntry)
		fmt.Printf("Type: Document\nName: %s\nFile: %s\n", d.Name, d.FileName)
		if promptCopy {
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
						_ = os.Remove(tmpFile)
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
					_ = cmd.Run()
				} else {
					color.Red("Incorrect document password.")
				}
			}
		}
	case "Government ID":
		g := res.Data.(src.GovIDEntry)
		fmt.Printf("Type: %s\nName: %s\nExpiry: %s\n", g.Type, g.Name, g.Expiry)
		showField("ID Number", g.IDNumber)
	case "Medical Record":
		m := res.Data.(src.MedicalRecordEntry)
		fmt.Printf("Type: Medical Record\nLabel: %s\nInsurance ID: %s\nPrescriptions: %s\nAllergies: %s\n", m.Label, m.InsuranceID, m.Prescriptions, m.Allergies)
	case "Travel":
		t := res.Data.(src.TravelEntry)
		fmt.Printf("Type: Travel\nLabel: %s\nTicket: %s\nLoyalty: %s\n", t.Label, t.TicketNumber, t.LoyaltyProgram)
		showField("Booking Code", t.BookingCode)
	case "Contact":
		c := res.Data.(src.ContactEntry)
		fmt.Printf("Type: Contact\nName: %s\nPhone: %s\nEmail: %s\nAddress: %s\nEmergency: %v\n", c.Name, c.Phone, c.Email, c.Address, c.Emergency)
	case "Cloud Credentials":
		c := res.Data.(src.CloudCredentialEntry)
		fmt.Printf("Type: Cloud Credentials\nLabel: %s\nRegion: %s\nAccount ID: %s\nRole: %s\nExpiration: %s\n", c.Label, c.Region, c.AccountID, c.Role, c.Expiration)
		showField("Access Key", c.AccessKey)
		showField("Secret Key", c.SecretKey)
	case "Kubernetes Secret":
		k := res.Data.(src.K8sSecretEntry)
		fmt.Printf("Type: K8s Secret\nName: %s\nCluster URL: %s\nNamespace: %s\nExpiration: %s\n", k.Name, k.ClusterURL, k.K8sNamespace, k.Expiration)
	case "Docker Registry":
		d := res.Data.(src.DockerRegistryEntry)
		fmt.Printf("Type: Docker Registry\nName: %s\nRegistry URL: %s\nUsername: %s\n", d.Name, d.RegistryURL, d.Username)
		showField("Token", d.Token)
	case "SSH Config":
		s := res.Data.(src.SSHConfigEntry)
		fmt.Printf("Type: SSH Config\nAlias: %s\nHost: %s\nUser: %s\nPort: %s\nKey Path: %s\nFingerprint: %s\n", s.Alias, s.Host, s.User, s.Port, s.KeyPath, s.Fingerprint)
		showField("Private Key", s.PrivateKey)
	case "CI/CD Secret":
		c := res.Data.(src.CICDSecretEntry)
		fmt.Printf("Type: CI/CD Secret\nName: %s\nWebhook: %s\nEnv Vars: %s\n", c.Name, c.Webhook, c.EnvVars)
	case "Software License":
		s := res.Data.(src.SoftwareLicenseEntry)
		fmt.Printf("Type: Software License\nProduct: %s\nActivation: %s\nExpiration: %s\n", s.ProductName, s.ActivationInfo, s.Expiration)
		showField("Serial Key", s.SerialKey)
	case "Legal Contract":
		l := res.Data.(src.LegalContractEntry)
		fmt.Printf("Type: Legal Contract\nName: %s\nSummary: %s\nParties: %s\nSigned: %s\n", l.Name, l.Summary, l.PartiesInvolved, l.SignedDate)
	case "Audio":
		a := res.Data.(src.AudioEntry)
		fmt.Printf("Type: Audio\nName: %s\nFile: %s\nSize: %.2f KB\n", a.Name, a.FileName, float64(len(a.Content))/1024)
		if promptCopy {
			fmt.Print("Open audio file? (y/n): ")
			if strings.ToLower(readInput()) == "y" {
				openTempMediaFile(a.FileName, a.Content)
			}
		}
	case "Video":
		vi := res.Data.(src.VideoEntry)
		fmt.Printf("Type: Video\nName: %s\nFile: %s\nSize: %.2f KB\n", vi.Name, vi.FileName, float64(len(vi.Content))/1024)
		if promptCopy {
			fmt.Println("Video quicklook is not available in terminal mode. Use open if needed.")
			fmt.Print("Open video file? (y/n): ")
			if strings.ToLower(readInput()) == "y" {
				openTempMediaFile(vi.FileName, vi.Content)
			}
		}
	case "Photo":
		p := res.Data.(src.PhotoEntry)
		fmt.Printf("Type: Photo\nName: %s\nFile: %s\n", p.Name, p.FileName)
		if preview, err := renderPhotoASCIIQuicklook(p.Content, 80); err == nil {
			fmt.Println(preview)
		}
		if promptCopy {
			fmt.Print("Open photo? (y/n): ")
			if strings.ToLower(readInput()) == "y" {
				openTempMediaFile(p.FileName, p.Content)
			}
		}
	}
	fmt.Println("---")
}

func openTempMediaFile(fileName string, content []byte) {
	tmpDir := os.TempDir()
	tmpFile := filepath.Join(tmpDir, fileName)
	if err := os.WriteFile(tmpFile, content, 0600); err != nil {
		color.Red("Error writing temporary file: %v\n", err)
		return
	}
	defer func() {
		time.Sleep(5 * time.Second)
		_ = os.Remove(tmpFile)
	}()

	var cmd *exec.Cmd
	if runtime.GOOS == "windows" {
		cmd = exec.Command("cmd", "/c", "start", "", tmpFile)
	} else if runtime.GOOS == "darwin" {
		cmd = exec.Command("open", tmpFile)
	} else {
		cmd = exec.Command("xdg-open", tmpFile)
	}
	if err := cmd.Run(); err != nil {
		color.Red("Open failed: %v", err)
	}
}

func promptKeyMetadataConsent(provider string) bool {
	fmt.Printf("%s can store a one-way hash of your retrieval key in cloud metadata for key-based recovery.\n", provider)
	fmt.Print("Allow key hash storage in cloud metadata? (y/n) [n]: ")
	return strings.ToLower(strings.TrimSpace(readInput())) == "y"
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

	var key string
	v.DropboxKeyMetadataConsent = promptKeyMetadataConsent("Dropbox")
	if v.DropboxKeyMetadataConsent {
		fmt.Print("Enter Custom Retrieval Key (leave blank to generate randomly): ")
		customKey := readInput()
		if customKey != "" {
			key = customKey
		} else {
			key, err = src.GenerateRetrievalKey()
			if err != nil {
				color.Red("Key generation failed: %v", err)
				return err
			}
		}
	}

	cm, err := getCloudManagerEx(context.Background(), v, mp, "dropbox")
	if err != nil {
		color.Red("Dropbox error: %v", err)
		return err
	}

	uploadPath, cleanupUpload, err := src.PrepareCloudUploadVaultPath(v, mp, vaultPath, "dropbox")
	if err != nil {
		color.Red("Failed to apply .apmignore for upload: %v", err)
		return err
	}
	defer cleanupUpload()

	fileID, err := cm.UploadVault(uploadPath, key)
	if err != nil {
		color.Red("Upload failed: %v", err)
		return err
	}

	v.RetrievalKey = key
	v.DropboxFileID = fileID
	v.LastCloudProvider = "dropbox"

	color.Green("Dropbox sync setup successful.")
	if key != "" {
		color.HiCyan("Retrieval Key: %s", key)
	} else {
		color.Yellow("Retrieval key metadata was not stored by consent choice. Use File Path for recovery: %s", fileID)
	}
	if mode == "self_hosted" {
		color.Cyan("Mode: Self-Hosted (Owner: You)")
	} else {
		color.Cyan("Mode: APM_PUBLIC")
	}
	return nil
}

func getCloudManagerEx(ctx context.Context, vault *src.Vault, masterPassword string, provider string) (src.CloudProvider, error) {
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

func handleDownloadedVault(data []byte, provider, githubToken, githubRepo string) {
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

	if localData, readErr := os.ReadFile(vaultPath); readErr == nil {
		if !bytes.Equal(localData, data) {
			color.Yellow("Conflict detected: local vault and downloaded cloud vault differ.")
			fmt.Println("APM does whole-vault conflict handling (no entry-level merge).")
			fmt.Println("1. Overwrite local vault with cloud copy")
			fmt.Println("2. Keep local vault and save cloud copy as conflict file")
			fmt.Println("3. Cancel")
			fmt.Print("Selection (1/2/3): ")
			choice := strings.TrimSpace(readInput())
			if choice == "2" {
				conflictPath := fmt.Sprintf("%s.conflict.%s.%s", vaultPath, provider, time.Now().Format("20060102-150405"))
				if saveErr := src.SaveVault(conflictPath, data); saveErr != nil {
					color.Red("Failed to save conflict copy: %v\n", saveErr)
					return
				}
				color.Green("Local vault kept. Cloud copy saved to: %s", conflictPath)
				return
			}
			if choice != "1" {
				color.Yellow("Cloud retrieval cancelled. Local vault unchanged.")
				return
			}
		}
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

var authPasskeyCmd = &cobra.Command{
	Use:   "passkey",
	Short: "Manage WebAuthn passkey recovery factor",
}

var authPasskeyRegisterCmd = &cobra.Command{
	Use:   "register",
	Short: "Register a recovery passkey using WebAuthn",
	Run: func(cmd *cobra.Command, args []string) {
		pass, vault, readonly, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}
		if readonly {
			color.Red("Vault is READ-ONLY. Cannot register passkey.")
			return
		}

		color.Cyan("Opening browser for passkey registration on localhost...")
		userID, credJSON, err := src.RunRecoveryPasskeyRegistration()
		if err != nil {
			color.Red("Passkey registration failed: %v", err)
			return
		}
		vault.RecoveryPasskeyEnabled = true
		vault.RecoveryPasskeyUserID = userID
		vault.RecoveryPasskeyCred = credJSON

		data, err := src.EncryptVault(vault, pass)
		if err != nil {
			color.Red("Error encrypting vault: %v", err)
			return
		}
		if err := src.SaveVault(vaultPath, data); err != nil {
			color.Red("Error saving vault: %v", err)
			return
		}
		src.LogAction("RECOVERY_PASSKEY_REGISTERED", "Registered recovery passkey")
		color.Green("Recovery passkey registered successfully.")
	},
}

var authPasskeyVerifyCmd = &cobra.Command{
	Use:   "verify",
	Short: "Verify current recovery passkey configuration",
	Run: func(cmd *cobra.Command, args []string) {
		_, vault, _, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}
		if !vault.RecoveryPasskeyEnabled || len(vault.RecoveryPasskeyUserID) == 0 || len(vault.RecoveryPasskeyCred) == 0 {
			color.Yellow("Recovery passkey is not configured.")
			return
		}
		info := src.RecoveryData{
			RecoveryPasskeyEnabled: vault.RecoveryPasskeyEnabled,
			RecoveryPasskeyUserID:  vault.RecoveryPasskeyUserID,
			RecoveryPasskeyCred:    vault.RecoveryPasskeyCred,
		}
		color.Cyan("Opening browser for passkey verification...")
		if err := src.VerifyRecoveryPasskeyFromHeader(info); err != nil {
			color.Red("Passkey verification failed: %v", err)
			return
		}
		color.Green("Passkey verification successful.")
	},
}

var authPasskeyDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable recovery passkey factor",
	Run: func(cmd *cobra.Command, args []string) {
		pass, vault, readonly, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}
		if readonly {
			color.Red("Vault is READ-ONLY. Cannot modify recovery factors.")
			return
		}
		vault.RecoveryPasskeyEnabled = false
		vault.RecoveryPasskeyUserID = nil
		vault.RecoveryPasskeyCred = nil
		data, err := src.EncryptVault(vault, pass)
		if err != nil {
			color.Red("Error encrypting vault: %v", err)
			return
		}
		if err := src.SaveVault(vaultPath, data); err != nil {
			color.Red("Error saving vault: %v", err)
			return
		}
		src.LogAction("RECOVERY_PASSKEY_DISABLED", "Disabled recovery passkey")
		color.Green("Recovery passkey disabled.")
	},
}

var authCodesCmd = &cobra.Command{
	Use:   "codes",
	Short: "Manage one-time recovery codes",
}

var authCodesGenerateCmd = &cobra.Command{
	Use:   "generate",
	Short: "Generate one-time recovery codes",
	Run: func(cmd *cobra.Command, args []string) {
		count, _ := cmd.Flags().GetInt("count")
		pass, vault, readonly, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}
		if readonly {
			color.Red("Vault is READ-ONLY. Cannot generate recovery codes.")
			return
		}
		codes, err := src.GenerateOneTimeRecoveryCodes(vault, count)
		if err != nil {
			color.Red("Failed to generate recovery codes: %v", err)
			return
		}
		data, err := src.EncryptVault(vault, pass)
		if err != nil {
			color.Red("Error encrypting vault: %v", err)
			return
		}
		if err := src.SaveVault(vaultPath, data); err != nil {
			color.Red("Error saving vault: %v", err)
			return
		}
		fmt.Println("Recovery codes generated (store these securely; they are shown once):")
		for i, c := range codes {
			fmt.Printf("%2d. %s\n", i+1, c)
		}
		src.LogAction("RECOVERY_CODES_GENERATED", fmt.Sprintf("Generated %d recovery codes", len(codes)))
	},
}

var authCodesStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show recovery code status",
	Run: func(cmd *cobra.Command, args []string) {
		_, vault, _, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}
		total := len(vault.RecoveryCodeHashes)
		if total == 0 {
			fmt.Println("No recovery codes configured.")
			return
		}
		remaining := src.CountRemainingRecoveryCodes(vault)
		fmt.Printf("Recovery codes: %d total, %d remaining, %d used\n", total, remaining, total-remaining)
	},
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
		if len(info.ObfuscatedKey) == 0 {
			color.Red("Recovery record found but key is missing. Manual recovery required.")
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

		codeBytes := make([]byte, 6)
		if _, err := rand.Read(codeBytes); err != nil {
			color.Red("Failed to create verification code: %v", err)
			return
		}
		for i := range codeBytes {
			codeBytes[i] = '0' + (codeBytes[i] % 10)
		}
		verificationCode := string(codeBytes)
		codeHash := sha256.Sum256([]byte(verificationCode))
		startTime := time.Now()
		expiryDuration := 15 * time.Minute

		host, port, user, passEmail := apmSMTPConfig()

		m := gomail.NewMessage()
		m.SetHeader("From", user)
		m.SetHeader("To", email)
		m.SetHeader("Subject", fmt.Sprintf("%s - APM Recovery Verification Code", verificationCode))
		setAPMEmailBody(
			m,
			"Verify your email for vault recovery",
			[]string{
				"We received a recovery attempt for your APM vault.",
				"Enter this 6-digit code in your terminal.",
				"This code expires in 15 minutes and is valid only for this recovery flow.",
			},
			verificationCode,
			[]string{
				"Never share this code.",
				"APM support will never ask for this code.",
				"If this was not you, ignore this message and rotate your master password.",
			},
		)

		dialer := gomail.NewDialer(host, port, user, passEmail)
		if err := dialer.DialAndSend(m); err != nil {
			color.Red("Failed to send recovery verification email: %v", err)
			return
		}

		color.HiCyan("Verification email sent. Complete recovery key check first, then enter the 6-digit code.")

		var dek []byte
		usedRecoveryCodeIndex := -1
		maxRecoveryKeyAttempts := 3
		for attempt := 1; attempt <= maxRecoveryKeyAttempts; attempt++ {
			if time.Since(startTime) > expiryDuration {
				color.Red("Recovery session expired before key verification. Please run 'pm auth recover' again.")
				return
			}
			fmt.Print("Enter recovery key: ")
			enteredRecoveryKey, err := readPassword()
			fmt.Println()
			if err != nil {
				color.Red("Error reading recovery key: %v", err)
				return
			}
			dek, err = src.CheckRecoveryKey(data, strings.TrimSpace(enteredRecoveryKey))
			if err == nil {
				color.HiGreen("Recovery key verified.")
				break
			}
			color.Red("Invalid recovery key. Attempt %d/%d.", attempt, maxRecoveryKeyAttempts)
			if attempt == maxRecoveryKeyAttempts {
				return
			}
		}

		maxCodeAttempts := 5
		emailCodeVerified := false
		for attempt := 1; attempt <= maxCodeAttempts; attempt++ {
			if time.Since(startTime) > expiryDuration {
				color.Red("Email verification code expired. Please initiate a new recovery request.")
				return
			}
			remaining := expiryDuration - time.Since(startTime)
			fmt.Printf("Enter 6-digit email code (attempt %d/%d, expires in %v): ", attempt, maxCodeAttempts, remaining.Truncate(time.Second))
			enteredCode := strings.TrimSpace(strings.ReplaceAll(readInput(), " ", ""))
			h := sha256.Sum256([]byte(enteredCode))
			if hmac.Equal(h[:], codeHash[:]) {
				emailCodeVerified = true
				break
			}
			color.Red("Invalid email code.")
		}
		if !emailCodeVerified {
			color.Red("Too many invalid code attempts. Start recovery again.")
			return
		}

		if info.RecoveryPasskeyEnabled || len(info.RecoveryCodeHashes) > 0 {
			if info.RecoveryPasskeyEnabled && len(info.RecoveryCodeHashes) > 0 {
				fmt.Println("Choose recovery second factor:")
				fmt.Println("1. Passkey (WebAuthn)")
				fmt.Println("2. One-time recovery code")
				fmt.Print("Selection (1/2): ")
				choice := strings.TrimSpace(readInput())
				if choice == "1" {
					color.Cyan("Opening browser for passkey verification...")
					if err := src.VerifyRecoveryPasskeyFromHeader(info); err != nil {
						color.Red("Passkey verification failed: %v", err)
						return
					}
				} else if choice == "2" {
					fmt.Print("Enter one-time recovery code: ")
					code := strings.TrimSpace(readInput())
					idx, ok := src.ValidateRecoveryCodeFromHeader(info, code)
					if !ok {
						color.Red("Invalid or already-used recovery code.")
						return
					}
					usedRecoveryCodeIndex = idx
				} else {
					color.Red("Invalid selection.")
					return
				}
			} else if info.RecoveryPasskeyEnabled {
				color.Cyan("Opening browser for passkey verification...")
				if err := src.VerifyRecoveryPasskeyFromHeader(info); err != nil {
					color.Red("Passkey verification failed: %v", err)
					return
				}
			} else {
				fmt.Print("Enter one-time recovery code: ")
				code := strings.TrimSpace(readInput())
				idx, ok := src.ValidateRecoveryCodeFromHeader(info, code)
				if !ok {
					color.Red("Invalid or already-used recovery code.")
					return
				}
				usedRecoveryCodeIndex = idx
			}
		}

		color.HiGreen("Email code verified. Authorizing cryptographic unlock...")
		codeHash = [32]byte{}

		if len(dek) == 0 {
			color.Red("Recovery key verification state missing. Start recovery again.")
			return
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
		if usedRecoveryCodeIndex >= 0 {
			src.MarkRecoveryCodeUsed(vault, usedRecoveryCodeIndex)
		}

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
		email := strings.ToLower(strings.TrimSpace(args[0]))
		pass, vault, _, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}

		host, port, user, passEmail := apmSMTPConfig()

		codeBytes := make([]byte, 6)
		if _, err := rand.Read(codeBytes); err != nil {
			color.Red("Failed to create verification code: %v", err)
			return
		}
		for i := range codeBytes {
			codeBytes[i] = '0' + (codeBytes[i] % 10)
		}
		verificationCode := string(codeBytes)
		codeHash := sha256.Sum256([]byte(verificationCode))
		verificationStart := time.Now()
		verificationTTL := 15 * time.Minute

		verificationMsg := gomail.NewMessage()
		verificationMsg.SetHeader("From", user)
		verificationMsg.SetHeader("To", email)
		verificationMsg.SetHeader("Subject", fmt.Sprintf("%s - APM Email Verification", verificationCode))
		setAPMEmailBody(
			verificationMsg,
			"Verify your email for recovery setup",
			[]string{
				"Use this code to verify ownership of this email for vault recovery setup.",
				"This code expires in 15 minutes.",
			},
			verificationCode,
			[]string{
				"If you did not request this, ignore this email.",
			},
		)

		dialer := gomail.NewDialer(host, port, user, passEmail)
		if err := dialer.DialAndSend(verificationMsg); err != nil {
			color.Red("Error sending verification email: %v", err)
			return
		}
		color.HiCyan("Verification code sent to %s.", email)

		verified := false
		maxCodeAttempts := 5
		for attempt := 1; attempt <= maxCodeAttempts; attempt++ {
			if time.Since(verificationStart) > verificationTTL {
				color.Red("Verification code expired. Re-run 'pm auth email <address>'.")
				return
			}
			remaining := verificationTTL - time.Since(verificationStart)
			fmt.Printf("Enter 6-digit verification code (attempt %d/%d, expires in %v): ", attempt, maxCodeAttempts, remaining.Truncate(time.Second))
			entered := strings.TrimSpace(strings.ReplaceAll(readInput(), " ", ""))
			h := sha256.Sum256([]byte(entered))
			if hmac.Equal(h[:], codeHash[:]) {
				verified = true
				break
			}
			color.Red("Invalid verification code.")
		}
		if !verified {
			color.Red("Too many invalid verification attempts.")
			return
		}
		codeHash = [32]byte{}

		vault.SetRecoveryEmail(email)
		if vault.CurrentProfileParams == nil {
			p := src.GetProfile(vault.Profile)
			vault.CurrentProfileParams = &p
		}

		key := src.GenerateRecoveryKey()
		salt, _ := src.GenerateSalt(vault.CurrentProfileParams.SaltLen)
		vault.SetRecoveryKey(key, salt)

		m := gomail.NewMessage()
		m.SetHeader("From", user)
		m.SetHeader("To", email)
		m.SetHeader("Subject", "SECURITY ALERT: APM Vault Recovery Configured")
		setAPMEmailBody(
			m,
			"Recovery access has been configured for your APM vault",
			[]string{
				"For your security, the recovery key was not sent in this email.",
				"It was displayed only once in your terminal during setup.",
				"This is a zero-knowledge system: we cannot recover your vault without your physical recovery key.",
			},
			"",
			[]string{
				"If you did not initiate this setup, your vault may be compromised.",
				"Change your master password immediately.",
			},
		)

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

func setNotesAutocompleteEnabled(enabled bool) {
	pass, vault, readonly, err := src_unlockVault()
	if err != nil {
		color.Red("Error: %v\n", err)
		return
	}
	if readonly {
		color.Red("Vault is READ-ONLY. Cannot change autocomplete settings.")
		return
	}

	vault.AutocompleteEnabled = enabled
	if enabled {
		if err := vault.ReindexNoteVocabulary(loadIgnoreConfigOrEmpty()); err != nil {
			color.Yellow("Autocomplete enabled, but indexing failed: %v", err)
		}
	}

	if err := saveVaultState(vault, pass); err != nil {
		color.Red("Error saving vault: %v", err)
		return
	}
	if enabled {
		color.Green("Autocomplete enabled and vocabulary indexed.")
	} else {
		color.Yellow("Autocomplete disabled.")
	}
}

func setAutocompletePopupDisabled(disabled bool) {
	pass, vault, readonly, err := src_unlockVault()
	if err != nil {
		color.Red("Error: %v\n", err)
		return
	}
	if readonly {
		color.Red("Vault is READ-ONLY. Cannot change autocomplete window settings.")
		return
	}

	vault.AutocompleteWindowDisabled = disabled
	if err := saveVaultState(vault, pass); err != nil {
		color.Red("Error saving vault: %v", err)
		return
	}
	if disabled {
		color.Yellow("Autocomplete popup window disabled.")
	} else {
		color.Green("Autocomplete popup window enabled.")
	}

	if status, err := autofill.TryStatus(context.Background()); err == nil && status != nil {
		color.Cyan("Restart or re-unlock the daemon to apply popup changes.")
	}
}

var vocabCmd = &cobra.Command{
	Use:   "vocab",
	Short: "Manage personal note vocabulary and aliases",
	Run: func(cmd *cobra.Command, args []string) {
		_, vault, _, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}

		words, err := vault.ListVocabWords()
		if err != nil {
			color.Red("Failed to load vocab: %v", err)
			return
		}
		aliases, _ := vault.ListVocabAliases()
		ignoreCfg := loadIgnoreConfigOrEmpty()

		type row struct {
			Word  string
			Stats src.VocabWord
		}
		rows := make([]row, 0, len(words))
		for word, stats := range words {
			if ignoreCfg.ShouldIgnoreVocabWord(word) {
				continue
			}
			rows = append(rows, row{Word: word, Stats: stats})
		}
		sort.Slice(rows, func(i, j int) bool {
			if rows[i].Stats.Score == rows[j].Stats.Score {
				return rows[i].Word < rows[j].Word
			}
			return rows[i].Stats.Score > rows[j].Stats.Score
		})

		if len(rows) == 0 {
			fmt.Println("Vocabulary is empty.")
		} else {
			fmt.Printf("%-24s %-8s %-8s %-8s %-8s\n", "WORD", "SCORE", "SEEN", "ACCEPT", "DISMISS")
			fmt.Println(strings.Repeat("-", 62))
			for _, r := range rows {
				fmt.Printf("%-24s %-8d %-8d %-8d %-8d\n", r.Word, r.Stats.Score, r.Stats.Seen, r.Stats.Accepted, r.Stats.Dismissed)
			}
		}

		if len(aliases) > 0 {
			fmt.Println("\nAliases:")
			keys := make([]string, 0, len(aliases))
			for alias := range aliases {
				keys = append(keys, alias)
			}
			sort.Strings(keys)
			for _, alias := range keys {
				fmt.Printf("  %s -> %s\n", alias, aliases[alias])
			}
		}
	},
}

var vocabEnableCmd = &cobra.Command{
	Use:   "enable",
	Short: "Enable note autocomplete indexing",
	Run: func(cmd *cobra.Command, args []string) {
		setNotesAutocompleteEnabled(true)
	},
}

var vocabDisableCmd = &cobra.Command{
	Use:   "disable",
	Short: "Disable note autocomplete indexing",
	Run: func(cmd *cobra.Command, args []string) {
		setNotesAutocompleteEnabled(false)
	},
}

var vocabStatusCmd = &cobra.Command{
	Use:   "status",
	Short: "Show note autocomplete status",
	Run: func(cmd *cobra.Command, args []string) {
		_, vault, _, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v", err)
			return
		}
		if vault.AutocompleteEnabled {
			color.Green("Autocomplete: enabled")
		} else {
			color.Yellow("Autocomplete: disabled")
		}
	},
}

var vocabAliasCmd = &cobra.Command{
	Use:   "alias",
	Short: "Create or update a note alias",
	Run: func(cmd *cobra.Command, args []string) {
		pass, vault, readonly, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}
		if readonly {
			color.Red("Vault is READ-ONLY. Cannot edit aliases.")
			return
		}

		fmt.Print("Alias trigger (typed word): ")
		alias := readInput()
		fmt.Print("Alias replacement value: ")
		value := readInput()

		if strings.TrimSpace(alias) == "" || strings.TrimSpace(value) == "" {
			color.Red("Alias and value are required.")
			return
		}
		if err := vault.UpsertVocabAlias(alias, value); err != nil {
			color.Red("Failed to save alias: %v", err)
			return
		}
		if err := saveVaultState(vault, pass); err != nil {
			color.Red("Error saving vault: %v", err)
			return
		}
		color.Green("Alias saved: %s -> %s", strings.ToLower(strings.TrimSpace(alias)), value)
	},
}

var vocabAliasListCmd = &cobra.Command{
	Use:   "alias-list",
	Short: "List all vocab aliases",
	Run: func(cmd *cobra.Command, args []string) {
		_, vault, _, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}
		aliases, err := vault.ListVocabAliases()
		if err != nil {
			color.Red("Failed to load aliases: %v", err)
			return
		}
		if len(aliases) == 0 {
			fmt.Println("No aliases found.")
			return
		}
		keys := make([]string, 0, len(aliases))
		for alias := range aliases {
			keys = append(keys, alias)
		}
		sort.Strings(keys)
		for _, alias := range keys {
			fmt.Printf("%s -> %s\n", alias, aliases[alias])
		}
	},
}

var vocabAliasRemoveCmd = &cobra.Command{
	Use:   "alias-remove [alias]",
	Short: "Remove an alias",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		pass, vault, readonly, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}
		if readonly {
			color.Red("Vault is READ-ONLY. Cannot remove aliases.")
			return
		}
		if err := vault.DeleteVocabAlias(args[0]); err != nil {
			color.Red("Failed to remove alias: %v", err)
			return
		}
		if err := saveVaultState(vault, pass); err != nil {
			color.Red("Error saving vault: %v", err)
			return
		}
		color.Green("Alias removed.")
	},
}

var vocabRankCmd = &cobra.Command{
	Use:   "rank [word] [delta]",
	Short: "Adjust ranking score for a vocab word",
	Args:  cobra.ExactArgs(2),
	Run: func(cmd *cobra.Command, args []string) {
		pass, vault, readonly, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}
		if readonly {
			color.Red("Vault is READ-ONLY. Cannot rank vocab.")
			return
		}
		delta, err := strconv.Atoi(strings.TrimSpace(args[1]))
		if err != nil {
			color.Red("Delta must be an integer.")
			return
		}
		if err := vault.AdjustVocabWordScore(args[0], delta); err != nil {
			color.Red("Failed to adjust rank: %v", err)
			return
		}
		if err := saveVaultState(vault, pass); err != nil {
			color.Red("Error saving vault: %v", err)
			return
		}
		color.Green("Updated rank for %s by %+d.", strings.ToLower(strings.TrimSpace(args[0])), delta)
	},
}

var vocabRemoveCmd = &cobra.Command{
	Use:   "remove [word]",
	Short: "Remove a word from vocabulary",
	Args:  cobra.ExactArgs(1),
	Run: func(cmd *cobra.Command, args []string) {
		pass, vault, readonly, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}
		if readonly {
			color.Red("Vault is READ-ONLY. Cannot remove vocab words.")
			return
		}
		if err := vault.DeleteVocabWord(args[0]); err != nil {
			color.Red("Failed to remove word: %v", err)
			return
		}
		if err := saveVaultState(vault, pass); err != nil {
			color.Red("Error saving vault: %v", err)
			return
		}
		color.Green("Removed word %s.", strings.ToLower(strings.TrimSpace(args[0])))
	},
}

var vocabReindexCmd = &cobra.Command{
	Use:   "reindex",
	Short: "Rebuild vocabulary from secure notes",
	Run: func(cmd *cobra.Command, args []string) {
		pass, vault, readonly, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}
		if readonly {
			color.Red("Vault is READ-ONLY. Cannot reindex vocabulary.")
			return
		}
		if err := vault.ReindexNoteVocabulary(loadIgnoreConfigOrEmpty()); err != nil {
			color.Red("Reindex failed: %v", err)
			return
		}
		if err := saveVaultState(vault, pass); err != nil {
			color.Red("Error saving vault: %v", err)
			return
		}
		color.Green("Vocabulary reindexed.")
	},
}

var authQuorumSetupCmd = &cobra.Command{
	Use:   "quorum-setup",
	Short: "Split recovery key into threshold shares (e.g. 2-of-3)",
	Run: func(cmd *cobra.Command, args []string) {
		threshold, _ := cmd.Flags().GetInt("threshold")
		shares, _ := cmd.Flags().GetInt("shares")
		recoveryKey, _ := cmd.Flags().GetString("key")

		pass, vault, readonly, err := src_unlockVault()
		if err != nil {
			color.Red("Error: %v\n", err)
			return
		}
		if readonly {
			color.Red("Vault is READ-ONLY. Cannot configure quorum recovery.")
			return
		}

		if vault.RecoveryEmail == "" && len(vault.RecoveryHash) == 0 {
			color.Yellow("Recovery is not configured yet. Run 'pm auth email <address>' first.")
			return
		}

		shareMap, err := src.SetupRecoveryQuorumWithKey(vault, recoveryKey, threshold, shares)
		if err != nil && recoveryKey == "" && strings.Contains(strings.ToLower(err.Error()), "provide the recovery key explicitly") {
			fmt.Print("Recovery key required for this vault. Enter recovery key: ")
			inputKey, rErr := readPassword()
			fmt.Println()
			if rErr != nil {
				color.Red("Failed to read recovery key: %v", rErr)
				return
			}
			shareMap, err = src.SetupRecoveryQuorumWithKey(vault, inputKey, threshold, shares)
		}
		if err != nil {
			color.Red("Failed to configure recovery quorum: %v", err)
			return
		}

		data, err := src.EncryptVault(vault, pass)
		if err != nil {
			color.Red("Error encrypting vault: %v", err)
			return
		}
		if err := src.SaveVault(vaultPath, data); err != nil {
			color.Red("Error saving vault: %v", err)
			return
		}

		fmt.Printf("Recovery quorum configured: %d-of-%d\n", threshold, shares)
		fmt.Println("Distribute these shares to distinct trustees. Each share is shown only here:")
		for i := 1; i <= shares; i++ {
			fmt.Printf("Share %d: %s\n", i, shareMap[i])
		}
		src.LogAction("RECOVERY_QUORUM_CONFIGURED", fmt.Sprintf("Configured %d-of-%d quorum recovery", threshold, shares))
	},
}

var authQuorumRecoverCmd = &cobra.Command{
	Use:   "quorum-recover",
	Short: "Recover vault using trustee shares (threshold recovery)",
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
		if info.RecoveryShareThreshold < 2 || len(info.RecoveryShareHashes) == 0 {
			color.Red("Quorum recovery is not configured for this vault.")
			return
		}

		if len(info.EmailHash) > 0 {
			fmt.Print("Enter recovery email to confirm identity: ")
			email := strings.ToLower(readInput())
			h := sha256.Sum256([]byte(email))
			if !hmac.Equal(h[:], info.EmailHash) {
				color.Red("Identity verification failed.\n")
				return
			}
		}

		tempVault := &src.Vault{
			RecoveryShareThreshold: info.RecoveryShareThreshold,
			RecoveryShareCount:     info.RecoveryShareCount,
			RecoveryShareHashes:    info.RecoveryShareHashes,
		}

		fmt.Printf("Enter at least %d valid shares.\n", info.RecoveryShareThreshold)
		shares := make([]string, 0, info.RecoveryShareThreshold)
		for i := 0; i < info.RecoveryShareThreshold; i++ {
			fmt.Printf("Share %d: ", i+1)
			share := strings.TrimSpace(readInput())
			if share == "" {
				color.Red("Share cannot be empty.")
				return
			}
			shares = append(shares, share)
		}

		recoveryKey, err := src.CombineRecoveryQuorumShares(tempVault, shares)
		if err != nil {
			color.Red("Share verification failed: %v", err)
			return
		}

		dek, err := src.CheckRecoveryKey(data, recoveryKey)
		if err != nil {
			color.Red("Recovery key validation failed: %v", err)
			return
		}

		fmt.Print("Enter new master password: ")
		newPass, _ := readPassword()
		fmt.Println()
		fmt.Print("Retype new master password: ")
		confPass, _ := readPassword()
		fmt.Println()
		if newPass != confPass {
			color.Red("Passwords do not match.")
			return
		}

		vault, err := src.DecryptVaultWithDEK(data, dek)
		if err != nil {
			color.Red("Error decrypting vault with recovered DEK: %v", err)
			return
		}
		vault.FailedAttempts = 0
		vault.EmergencyMode = false

		newData, err := src.EncryptVault(vault, newPass)
		if err != nil {
			color.Red("Error re-encrypting vault: %v", err)
			return
		}
		if err := src.SaveVault(vaultPath, newData); err != nil {
			color.Red("Error saving vault: %v", err)
			return
		}
		src.ClearFailures()
		src.LogAction("RECOVERY_QUORUM_SUCCESS", "Vault recovered with quorum shares")
		color.Green("Vault recovered successfully with trustee quorum.")
	},
}

var mcpCmd = &cobra.Command{
	Use:   "mcp",
	Short: "Configure or start the APM MCP server",
}

func buildMCPConfigForToken(token string) map[string]interface{} {
	return map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"apm": src.BuildMCPServerConfigWithToken(token),
		},
	}
}

func buildMCPSetupConfig() map[string]interface{} {
	cmdStr := "if (! (Get-Command pm -ErrorAction SilentlyContinue)) { iwr -useb https://get.apm.dev/install.ps1 | iex }; pm mcp serve"
	return map[string]interface{}{
		"mcpServers": map[string]interface{}{
			"apm": map[string]interface{}{
				"command": "powershell",
				"args":    []string{"-ExecutionPolicy", "Bypass", "-Command", cmdStr},
				"env":     map[string]string{},
			},
		},
	}
}

var mcpConfigCmd = &cobra.Command{
	Use:   "config",
	Short: "Show first-run MCP setup config",
	Run: func(cmd *cobra.Command, args []string) {
		fullConfig := buildMCPSetupConfig()
		configJSON, _ := json.MarshalIndent(fullConfig, "", "  ")
		color.HiYellow("Copy this to your MCP settings (no bootstrap script file):")
		fmt.Println(string(configJSON))
		color.Cyan("After token setup completes, the config is auto-updated to tokenized `pm mcp serve --token ...` format.")
	},
}

var mcpTokenCmd = &cobra.Command{
	Use:   "token",
	Short: "Interactive setup for MCP access tokens",
	Run: func(cmd *cobra.Command, args []string) {
		auto, _ := cmd.Flags().GetBool("auto")

		color.HiCyan("APM MCP Server Setup")

		var name string
		promptName := &survey.Input{Message: "Token name:"}
		if err := survey.AskOne(promptName, &name, survey.WithValidator(survey.Required)); err != nil {
			color.Red("Setup aborted: %v", err)
			return
		}
		name = strings.TrimSpace(name)
		if name == "" {
			color.Red("Token name is required.")
			return
		}

		var expiryStr string
		promptExpiry := &survey.Input{
			Message: "Expiry in minutes (0 for never):",
			Default: "0",
		}
		err := survey.AskOne(promptExpiry, &expiryStr, survey.WithValidator(func(ans interface{}) error {
			value, ok := ans.(string)
			if !ok {
				return fmt.Errorf("invalid expiry value")
			}
			n, convErr := strconv.Atoi(strings.TrimSpace(value))
			if convErr != nil {
				return fmt.Errorf("expiry must be a whole number")
			}
			if n < 0 {
				return fmt.Errorf("expiry must be 0 or greater")
			}
			return nil
		}))
		if err != nil {
			color.Red("Setup aborted: %v", err)
			return
		}

		expiry, _ := strconv.Atoi(strings.TrimSpace(expiryStr))

		permissions := []string{}
		promptPerms := &survey.MultiSelect{
			Message: "Permissions (space to select, enter to confirm):",
			Options: src.MCPToolPermissions(),
		}
		err = survey.AskOne(promptPerms, &permissions)
		if err != nil {
			color.Red("Setup aborted: %v", err)
			return
		}

		if len(permissions) == 0 {
			color.Red("You must select at least one permission.")
			return
		}

		token, err := src.GenerateMCPToken(name, permissions, expiry)
		if err != nil {
			color.Red("Token generation failed: %v", err)
			return
		}

		if auto {
			files := src.FindMCPConfigFiles()
			updatedAny := false
			for _, f := range files {
				if err := src.UpdateMCPConfigWithToken(f, token); err == nil {
					color.Green("Automatically updated config: %s", f)
					updatedAny = true
				}
			}
			if !updatedAny {
				color.Yellow("Could not automatically find an IDE config to update.")
			}
		}

		color.HiGreen("\nMCP Token generated successfully!")
		color.HiCyan("Token: %s", token)
		fullConfig := buildMCPConfigForToken(token)
		configJSON, _ := json.MarshalIndent(fullConfig, "", "  ")
		color.HiYellow("\nAdd the following configuration to your MCP settings:")
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
			config, _ := src.LoadMCPConfig()
			if len(config.Tokens) == 0 {
				color.Yellow("No MCP token found. Triggering automated setup...")
				exe, _ := os.Executable()
				if runtime.GOOS == "windows" {
					setupCmd := exec.Command("cmd", "/c", "start", "powershell", "-NoExit", "-Command", fmt.Sprintf("& '%s' mcp token --auto", exe))
					setupCmd.Run()
				} else {
					color.Red("Auto-setup currently only supported on Windows.")
				}
				color.Cyan("Please complete the setup in the new window and then restart your agent.")
				os.Exit(0)
			}
			for t := range config.Tokens {
				token = t
				break
			}
		}
		if err := src.StartMCPServer(token, vaultPath, nil, pluginMgr); err != nil {
			fmt.Fprintf(os.Stderr, "MCP Server Error: %v\n", err)
			os.Exit(1)
		}
	},
}

func init() {
	mcpCmd.AddCommand(mcpConfigCmd, mcpTokenCmd, mcpListCmd, mcpRevokeCmd, mcpServeCmd)
	mcpServeCmd.Flags().String("token", "", "MCP access token")
	mcpTokenCmd.Flags().Bool("auto", false, "Automatically configure IDEs")
	authAlertsCmd.Flags().Bool("enable", false, "Enable security alerts")
	authAlertsCmd.Flags().Bool("disable", false, "Disable security alerts")
	authQuorumSetupCmd.Flags().Int("threshold", 2, "Minimum shares required to recover")
	authQuorumSetupCmd.Flags().Int("shares", 3, "Total shares to generate")
	authQuorumSetupCmd.Flags().String("key", "", "Optional recovery key (used if vault cannot auto-resolve it)")
	authCodesGenerateCmd.Flags().Int("count", 10, "Number of one-time recovery codes to generate")
}
