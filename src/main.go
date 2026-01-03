package main

import (
	"bufio"
	"fmt"
	"os"
	"strings"
	"syscall"
	"time"

	"github.com/spf13/cobra"
	"golang.org/x/term"
)

var vaultPath = "vault.dat"

func main() {
	var rootCmd = &cobra.Command{
		Use:   "pm",
		Short: "A simple password manager CLI",
	}

	var initCmd = &cobra.Command{
		Use:   "init",
		Short: "Initialize a new vault",
		Run: func(cmd *cobra.Command, args []string) {
			if VaultExists(vaultPath) {
				fmt.Println("Vault already exists.")
				return
			}

			fmt.Print("Create Master Password: ")
			masterPassword, err := readPassword()
			if err != nil {
				fmt.Printf("\nError reading password: %v\n", err)
				return
			}
			fmt.Println()

			salt, err := GenerateSalt()
			if err != nil {
				fmt.Printf("Error generating salt: %v\n", err)
				return
			}

			vault := &Vault{Salt: salt}
			data, err := vault.Serialize(masterPassword)
			if err != nil {
				fmt.Printf("Error encrypting vault: %v\n", err)
				return
			}

			if err := SaveVault(vaultPath, data); err != nil {
				fmt.Printf("Error saving vault: %v\n", err)
				return
			}

			fmt.Println("Vault initialized successfully.")
		},
	}

	var addCmd = &cobra.Command{
		Use:   "add",
		Short: "Add a new account to the vault",
		Run: func(cmd *cobra.Command, args []string) {
			account, _ := cmd.Flags().GetString("account")
			username, _ := cmd.Flags().GetString("user")
			password, _ := cmd.Flags().GetString("password")

			if account == "" {
				fmt.Print("Account: ")
				account = readInput()
			}
			if username == "" {
				fmt.Print("Username: ")
				username = readInput()
			}
			if password == "" {
				fmt.Print("Password (leave blank to generate): ")
				password, _ = readPassword()
				fmt.Println()
				if password == "" {
					password, _ = GeneratePassword(16)
					fmt.Printf("Generated password: %s\n", password)
				}
			}

			masterPassword, vault, err := unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			vault.AddEntry(account, username, password)
			data, err := vault.Serialize(masterPassword)
			if err != nil {
				fmt.Printf("Error encrypting vault: %v\n", err)
				return
			}

			if err := SaveVault(vaultPath, data); err != nil {
				fmt.Printf("Error saving vault: %v\n", err)
				return
			}

			fmt.Printf("Added entry for %s.\n", account)
		},
	}

	var getCmd = &cobra.Command{
		Use:   "get",
		Short: "Retrieve a password from the vault",
		Run: func(cmd *cobra.Command, args []string) {
			account, _ := cmd.Flags().GetString("account")
			if account == "" {
				fmt.Print("Account: ")
				account = readInput()
			}

			_, vault, err := unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			entry, ok := vault.GetEntry(account)
			if !ok {
				fmt.Printf("Account %s not found.\n", account)
				return
			}

			fmt.Printf("Account:  %s\n", entry.Account)
			fmt.Printf("Username: %s\n", entry.Username)
			fmt.Printf("Password: %s\n", entry.Password)
		},
	}

	var delCmd = &cobra.Command{
		Use:   "del",
		Short: "Delete an account from the vault",
		Run: func(cmd *cobra.Command, args []string) {
			account, _ := cmd.Flags().GetString("account")
			if account == "" {
				fmt.Print("Account: ")
				account = readInput()
			}

			masterPassword, vault, err := unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			if vault.DeleteEntry(account) {
				data, err := vault.Serialize(masterPassword)
				if err != nil {
					fmt.Printf("Error encrypting vault: %v\n", err)
					return
				}
				if err := SaveVault(vaultPath, data); err != nil {
					fmt.Printf("Error saving vault: %v\n", err)
					return
				}
				fmt.Printf("Deleted entry for %s.\n", account)
			} else {
				fmt.Printf("Account %s not found.\n", account)
			}
		},
	}

	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all accounts in the vault",
		Run: func(cmd *cobra.Command, args []string) {
			filter, _ := cmd.Flags().GetString("filter")

			_, vault, err := unlockVault()
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
		Short: "Manage operational modes",
	}

	var sudoCmd = &cobra.Command{
		Use:   "sudo <mins>",
		Short: "Activate sudo mode for a given duration in minutes",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			mins := 0
			_, err := fmt.Sscanf(args[0], "%d", &mins)
			if err != nil || mins <= 0 {
				fmt.Println("Please provide a valid number of minutes.")
				return
			}

			fmt.Println("Confirming access for sudo mode...")
			masterPassword, _, err := unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			duration := time.Duration(mins) * time.Minute
			if err := CreateSession(masterPassword, duration); err != nil {
				fmt.Printf("Error creating sudo session: %v\n", err)
				return
			}

			fmt.Printf("Sudo mode activated for %d minutes.\n", mins)
		},
	}

	modeCmd.AddCommand(sudoCmd)

	var genCmd = &cobra.Command{
		Use:   "gen",
		Short: "Generate a random secure password",
		Run: func(cmd *cobra.Command, args []string) {
			length, _ := cmd.Flags().GetInt("length")
			password, _ := GeneratePassword(length)
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

			masterPassword, vault, err := unlockVault()
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

			if err := SaveVault(vaultPath, data); err != nil {
				fmt.Printf("Error saving vault: %v\n", err)
				return
			}

			fmt.Printf("Added TOTP for %s.\n", account)
		},
	}

	var totpShowCmd = &cobra.Command{
		Use:   "show [account]",
		Short: "Show TOTP code(s)",
		Run: func(cmd *cobra.Command, args []string) {
			_, vault, err := unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			var targets []TOTPEntry
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

			if len(targets) == 0 {
				fmt.Println("No TOTP accounts found.")
				return
			}

			fmt.Println("Press Ctrl+C to stop.")
			for {
				remaining := TimeRemaining()
				for _, entry := range targets {
					code, _ := GenerateTOTP(entry.Secret)
					fmt.Printf("%-20s: %s (%ds/30s remaining)      \n", entry.Account, code, remaining)
				}
				time.Sleep(1 * time.Second)
				fmt.Printf("\033[%dA", len(targets))
			}
		},
	}

	var totpDeleteCmd = &cobra.Command{
		Use:   "delete <account>",
		Short: "Delete a TOTP account",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			account := args[0]

			masterPassword, vault, err := unlockVault()
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
				if err := SaveVault(vaultPath, data); err != nil {
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

			masterPassword, vault, err := unlockVault()
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

			if err := SaveVault(vaultPath, data); err != nil {
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

	totpCmd.AddCommand(totpAddCmd, totpShowCmd, totpDeleteCmd, totpEditCmd)

	var importCmd = &cobra.Command{
		Use:   "import <file>",
		Short: "Import data from JSON, CSV, or TXT file",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			filename := args[0]
			masterPassword, vault, err := unlockVault()
			if err != nil {
				fmt.Println(err)
				return
			}

			ext := strings.ToLower(filename[strings.LastIndex(filename, ".")+1:])
			var importErr error
			switch ext {
			case "json":
				importErr = ImportFromJSON(vault, filename)
			case "csv":
				importErr = ImportFromCSV(vault, filename)
			case "txt":
				importErr = ImportFromTXT(vault, filename)
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
			if err := SaveVault(vaultPath, data); err != nil {
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

			_, vault, err := unlockVault()
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
			if withoutPass || strings.HasSuffix(strings.ToLower(output), ".txt") {
				exportErr = ExportToTXT(vault, output, withoutPass)
			} else {
				exportErr = ExportToJSON(vault, output)
			}

			if exportErr != nil {
				fmt.Printf("Error during export: %v\n", exportErr)
				return
			}

			fmt.Printf("Successfully exported vault data to %s.\n", output)
		},
	}

	importCmd.Flags().StringP("output", "o", "", "Output filename") // Wait, import doesn't need output.
	exportCmd.Flags().StringP("output", "o", "", "Output filename")
	exportCmd.Flags().Bool("without-password", false, "Exclude passwords and secrets (generates .txt)")
	exportCmd.Flags().Bool("without_password", false, "Exclude passwords and secrets (alias)")

	addCmd.Flags().StringP("account", "a", "", "Account name")
	addCmd.Flags().StringP("user", "u", "", "Username")
	addCmd.Flags().StringP("password", "p", "", "Password")
	getCmd.Flags().StringP("account", "a", "", "Account name")
	delCmd.Flags().StringP("account", "a", "", "Account name")
	listCmd.Flags().StringP("filter", "f", "", "Filter accounts by name or username")
	genCmd.Flags().IntP("length", "l", 16, "Password length")

	rootCmd.AddCommand(initCmd, addCmd, getCmd, delCmd, listCmd, genCmd, modeCmd, totpCmd, importCmd, exportCmd)
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

func unlockVault() (string, *Vault, error) {
	if !VaultExists(vaultPath) {
		return "", nil, fmt.Errorf("Vault does not exist. Run 'pm init' first.")
	}

	data, err := LoadVault(vaultPath)
	if err != nil {
		return "", nil, err
	}

	if len(data) < 16 {
		return "", nil, fmt.Errorf("Invalid vault file.")
	}
	salt := data[:16]
	ciphertext := data[16:]

	if sessionPass, err := GetSession(); err == nil {
		vault, err := DecryptVault(ciphertext, sessionPass, salt)
		if err == nil {
			return sessionPass, vault, nil
		}

		KillSession()
	}

	for i := 0; i < 3; i++ {
		fmt.Printf("Master Password (attempt %d/3): ", i+1)
		masterPassword, err := readPassword()
		if err != nil {
			return "", nil, err
		}
		fmt.Println()

		vault, err := DecryptVault(ciphertext, masterPassword, salt)
		if err == nil {
			return masterPassword, vault, nil
		}
		fmt.Printf("Error: %v\n", err)
	}

	return "", nil, fmt.Errorf("too many failed attempts")
}

func (v *Vault) Serialize(masterPassword string) ([]byte, error) {
	ciphertext, err := EncryptVault(v, masterPassword)
	if err != nil {
		return nil, err
	}

	return append(v.Salt, ciphertext...), nil
}
