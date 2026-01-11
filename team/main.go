package main

import (
	"bufio"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"syscall"
	"time"

	"github.com/fatih/color"
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
	vaultPath = filepath.Join(filepath.Dir(exe), "team_vault.dat")
	inputReader = bufio.NewReader(os.Stdin)
}

func main() {
	var rootCmd = &cobra.Command{
		Use:   "pm-team",
		Short: "Team Password Manager - Secure shared credential management",
	}

	var initCmd = &cobra.Command{
		Use:   "init <org_name> <admin_username>",
		Short: "Initialize a new team organization",
		Args:  cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			if vaultExists() {
				color.Red("Team vault already exists.\n")
				return
			}

			orgName := args[0]
			adminUser := args[1]

			fmt.Print("Create Master Password for Admin: ")
			pass, _ := readPassword()
			fmt.Println()

			fmt.Print("Confirm Password: ")
			confirm, _ := readPassword()
			fmt.Println()

			if pass != confirm {
				color.Red("Passwords do not match.\n")
				return
			}

			salt, _ := GenerateSalt()
			dk, _ := GenerateRandomKey()

			ukKeys := DeriveKeys(pass, salt, 1)
			wrappedDK, _ := WrapKey(dk, ukKeys.EncryptionKey)

			dept := Department{
				ID:   "general",
				Name: "General",
			}

			user := TeamUser{
				ID:                 "admin",
				Username:           adminUser,
				Role:               RoleAdmin,
				ActiveDepartmentID: "general",
				WrappedKeys:        map[string][]byte{"general": wrappedDK},
			}

			tv := TeamVault{
				OrganizationID: orgName,
				Departments:    []Department{dept},
				Users:          []TeamUser{user},
				SharedEntries:  SharedEntryStore{},
				Salt:           salt,
			}
			tv.AddAuditEntry(adminUser, "INIT_TEAM", "Organization created")

			if err := saveTeamVault(&tv); err != nil {
				color.Red("Error saving team vault: %v\n", err)
				return
			}

			color.Green("Team Organization '%s' initialized. Admin: %s\n", orgName, adminUser)
			color.Cyan("Run 'pm-team login %s' to start.\n", adminUser)
		},
	}

	var loginCmd = &cobra.Command{
		Use:   "login <username>",
		Short: "Login to team organization",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			username := args[0]

			tv, err := loadTeamVault()
			if err != nil {
				color.Red("Team vault not found. Run 'pm-team init' first.\n")
				return
			}

			var targetUser *TeamUser
			for i := range tv.Users {
				if tv.Users[i].Username == username {
					targetUser = &tv.Users[i]
					break
				}
			}

			if targetUser == nil {
				color.Red("User '%s' not found.\n", username)
				return
			}

			fmt.Printf("Password for %s: ", username)
			pass, _ := readPassword()
			fmt.Println()

			ukKeys := DeriveKeys(pass, tv.Salt, 1)

			wrappedDK, ok := targetUser.WrappedKeys[targetUser.ActiveDepartmentID]
			if !ok {
				color.Red("No key found for active department.\n")
				return
			}

			deptKey, err := UnwrapKey(wrappedDK, ukKeys.EncryptionKey)
			if err != nil {
				color.Red("Authentication failed.\n")
				return
			}

			if err := CreateSession(*targetUser, deptKey, tv.OrganizationID); err != nil {
				color.Red("Error creating session: %v\n", err)
				return
			}

			color.Green("Logged in as %s (%s) in department '%s'.\n", username, targetUser.Role, targetUser.ActiveDepartmentID)
		},
	}

	var whoamiCmd = &cobra.Command{
		Use:   "whoami",
		Short: "Display current session information",
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil {
				color.Red("No active session. Run 'pm-team login' first.\n")
				return
			}

			tv, _ := loadTeamVault()

			color.Cyan("=== Team Vault Session ===\n")
			fmt.Printf("Organization: %s\n", tv.OrganizationID)
			fmt.Printf("Username: %s\n", s.Username)
			fmt.Printf("Role: %s\n", s.Role)
			fmt.Printf("Active Department: %s\n", s.ActiveDeptID)
			fmt.Printf("Session Expires: %s\n", s.Expiry.Format("15:04:05"))
		},
	}

	var logoutCmd = &cobra.Command{
		Use:   "logout",
		Short: "End current session",
		Run: func(cmd *cobra.Command, args []string) {
			if err := EndSession(); err != nil {
				color.Red("No active session.\n")
				return
			}
			color.Green("Logged out successfully.\n")
		},
	}

	var deptCmd = &cobra.Command{
		Use:   "dept",
		Short: "Manage departments",
	}

	var deptListCmd = &cobra.Command{
		Use:   "list",
		Short: "List all departments",
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil {
				color.Red("No active session. Run 'pm-team login' first.\n")
				return
			}

			tv, _ := loadTeamVault()

			color.Cyan("Departments in %s:\n", tv.OrganizationID)
			for _, d := range tv.Departments {
				if s.Role == RoleAdmin || s.ActiveDeptID == d.ID {
					fmt.Printf("- %s (ID: %s)\n", d.Name, d.ID)
				}
			}
		},
	}

	var deptCreateCmd = &cobra.Command{
		Use:   "create <name>",
		Short: "Create a new department (Admin/Manager only)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil || !s.Role.CanManageDepartments() {
				color.Red("Permission denied.\n")
				return
			}

			name := args[0]
			id := strings.ToLower(strings.ReplaceAll(name, " ", "_"))

			tv, _ := loadTeamVault()

			for _, d := range tv.Departments {
				if d.ID == id {
					color.Red("Department '%s' already exists.\n", id)
					return
				}
			}

			tv.Departments = append(tv.Departments, Department{ID: id, Name: name})
			tv.AddAuditEntry(s.Username, "DEPT_CREATE", "Created department: "+name)

			if err := saveTeamVault(tv); err != nil {
				color.Red("Error saving: %v\n", err)
				return
			}

			color.Green("Department '%s' created.\n", name)
		},
	}

	deptCmd.AddCommand(deptListCmd, deptCreateCmd)

	var userCmd = &cobra.Command{
		Use:   "user",
		Short: "Manage team users",
	}

	var userListCmd = &cobra.Command{
		Use:   "list",
		Short: "List all users",
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil {
				color.Red("No active session. Run 'pm-team login' first.\n")
				return
			}

			tv, _ := loadTeamVault()

			color.Cyan("Users in %s:\n", tv.OrganizationID)
			for _, u := range tv.Users {
				if s.Role == RoleAdmin || u.ID == s.UserID {
					fmt.Printf("- %s (%s) - Dept: %s\n", u.Username, u.Role, u.ActiveDepartmentID)
				}
			}
		},
	}

	var userAddCmd = &cobra.Command{
		Use:   "add <username>",
		Short: "Add a new user (Admin/Manager only)",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil || !s.Role.CanManageUsers() {
				color.Red("Permission denied.\n")
				return
			}

			username := args[0]
			roleStr, _ := cmd.Flags().GetString("role")
			deptID, _ := cmd.Flags().GetString("dept")

			fmt.Printf("Set Password for %s: ", username)
			pass, _ := readPassword()
			fmt.Println()

			tv, _ := loadTeamVault()

			userSalt, _ := GenerateSalt()
			ukKeys := DeriveKeys(pass, userSalt, 1)

			wrappedDK, err := WrapKey(s.DeptKey, ukKeys.EncryptionKey)
			if err != nil {
				color.Red("Key wrapping failed: %v\n", err)
				return
			}

			newUser := TeamUser{
				ID:                 fmt.Sprintf("user_%d", time.Now().Unix()),
				Username:           username,
				Role:               Role(strings.ToUpper(roleStr)),
				ActiveDepartmentID: deptID,
				WrappedKeys:        map[string][]byte{deptID: wrappedDK},
			}

			tv.Users = append(tv.Users, newUser)
			tv.AddAuditEntry(s.Username, "USER_ADD", fmt.Sprintf("Added %s as %s in %s", username, roleStr, deptID))

			if err := saveTeamVault(tv); err != nil {
				color.Red("Error saving: %v\n", err)
				return
			}

			color.Green("User '%s' added successfully.\n", username)
		},
	}
	userAddCmd.Flags().String("role", "USER", "User role (ADMIN, MANAGER, USER, AUDITOR, SECURITY)")
	userAddCmd.Flags().String("dept", "general", "Department ID")

	userCmd.AddCommand(userListCmd, userAddCmd)

	var addCmd = &cobra.Command{
		Use:   "add",
		Short: "Add a shared entry (interactive)",
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil || !s.Role.CanAddEntry() {
				color.Red("Permission denied.\n")
				return
			}

			fmt.Println("Select entry type:")
			fmt.Println("1. Password")
			fmt.Println("2. TOTP")
			fmt.Println("3. API Key")
			fmt.Println("4. Token")
			fmt.Println("5. Secure Note")
			fmt.Print("Choice: ")
			choice := readInput()

			tv, _ := loadTeamVault()

			switch choice {
			case "1":
				addSharedPassword(tv, s)
			case "2":
				addSharedTOTP(tv, s)
			case "3":
				addSharedAPIKey(tv, s)
			case "4":
				addSharedToken(tv, s)
			case "5":
				addSharedNote(tv, s)
			default:
				color.Red("Invalid choice.\n")
				return
			}
		},
	}

	var listCmd = &cobra.Command{
		Use:   "list",
		Short: "List all shared entries",
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil {
				color.Red("No active session.\n")
				return
			}

			tv, _ := loadTeamVault()

			color.Cyan("=== Shared Passwords ===\n")
			for _, p := range tv.SharedEntries.Passwords {
				if p.DepartmentID == s.ActiveDeptID || s.Role == RoleAdmin {
					fmt.Printf("- %s (%s) - Dept: %s\n", p.Name, p.Username, p.DepartmentID)
				}
			}

			color.Cyan("\n=== Shared API Keys ===\n")
			for _, k := range tv.SharedEntries.APIKeys {
				if k.DepartmentID == s.ActiveDeptID || s.Role == RoleAdmin {
					fmt.Printf("- %s (%s) - Dept: %s\n", k.Label, k.Service, k.DepartmentID)
				}
			}

			color.Cyan("\n=== Shared TOTPs ===\n")
			for _, t := range tv.SharedEntries.TOTPs {
				if t.DepartmentID == s.ActiveDeptID || s.Role == RoleAdmin {
					fmt.Printf("- %s (%s) - Dept: %s\n", t.Name, t.Issuer, t.DepartmentID)
				}
			}
		},
	}

	var getCmd = &cobra.Command{
		Use:   "get <query>",
		Short: "Search and retrieve a shared entry",
		Args:  cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil {
				color.Red("No active session.\n")
				return
			}

			tv, _ := loadTeamVault()
			query := strings.ToLower(strings.Join(args, " "))

			// Search passwords
			for _, p := range tv.SharedEntries.Passwords {
				if (p.DepartmentID == s.ActiveDeptID || s.Role == RoleAdmin) &&
					strings.Contains(strings.ToLower(p.Name), query) {
					decryptedPass, _ := DecryptData(p.Password, s.DeptKey)
					color.Cyan("\n=== Password: %s ===\n", p.Name)
					fmt.Printf("Username: %s\n", p.Username)
					fmt.Printf("Password: %s\n", string(decryptedPass))
					fmt.Printf("URL: %s\n", p.URL)
					fmt.Printf("Department: %s\n", p.DepartmentID)
					fmt.Printf("Created by: %s on %s\n", p.CreatedBy, p.CreatedAt.Format("2006-01-02"))
					return
				}
			}

			// Search API keys
			for _, k := range tv.SharedEntries.APIKeys {
				if (k.DepartmentID == s.ActiveDeptID || s.Role == RoleAdmin) &&
					strings.Contains(strings.ToLower(k.Label), query) {
					decryptedKey, _ := DecryptData(k.Key, s.DeptKey)
					color.Cyan("\n=== API Key: %s ===\n", k.Label)
					fmt.Printf("Service: %s\n", k.Service)
					fmt.Printf("Key: %s\n", string(decryptedKey))
					fmt.Printf("Department: %s\n", k.DepartmentID)
					fmt.Printf("Created by: %s on %s\n", k.CreatedBy, k.CreatedAt.Format("2006-01-02"))
					return
				}
			}

			// Search TOTPs
			for _, t := range tv.SharedEntries.TOTPs {
				if (t.DepartmentID == s.ActiveDeptID || s.Role == RoleAdmin) &&
					strings.Contains(strings.ToLower(t.Name), query) {
					decryptedSecret, _ := DecryptData(t.Secret, s.DeptKey)
					color.Cyan("\n=== TOTP: %s ===\n", t.Name)
					fmt.Printf("Issuer: %s\n", t.Issuer)
					fmt.Printf("Secret: %s\n", string(decryptedSecret))
					fmt.Printf("Department: %s\n", t.DepartmentID)
					fmt.Printf("Created by: %s on %s\n", t.CreatedBy, t.CreatedAt.Format("2006-01-02"))
					return
				}
			}

			color.Red("No entry found matching '%s'.\n", query)
		},
	}

	var genCmd = &cobra.Command{
		Use:   "gen",
		Short: "Generate a secure random password",
		Run: func(cmd *cobra.Command, args []string) {
			length, _ := cmd.Flags().GetInt("length")
			password := generatePassword(length)
			color.Green("Generated Password: %s\n", password)
		},
	}
	genCmd.Flags().Int("length", 20, "Password length")

	var auditCmd = &cobra.Command{
		Use:   "audit",
		Short: "View organization audit trail",
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil || !s.Role.CanViewAudit() {
				color.Red("Permission denied.\n")
				return
			}

			tv, _ := loadTeamVault()

			color.Cyan("=== Audit Trail for %s ===\n", tv.OrganizationID)
			for _, e := range tv.AuditTrail {
				fmt.Printf("[%s] %s | %s: %s\n",
					e.Timestamp.Format("2006-01-02 15:04:05"),
					e.User,
					e.Action,
					e.Details)
			}
		},
	}

	rootCmd.AddCommand(initCmd, loginCmd, whoamiCmd, logoutCmd, deptCmd, userCmd, addCmd, listCmd, getCmd, genCmd, auditCmd)
	rootCmd.CompletionOptions.DisableDefaultCmd = true
	rootCmd.SetHelpCommand(&cobra.Command{Hidden: true})
	rootCmd.Execute()
}

func vaultExists() bool {
	_, err := os.Stat(vaultPath)
	return err == nil
}

func loadTeamVault() (*TeamVault, error) {
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		return nil, err
	}

	if len(data) < 8 || string(data[:8]) != "APMTEAMV" {
		return nil, fmt.Errorf("invalid team vault format")
	}

	var tv TeamVault
	if err := json.Unmarshal(data[8:], &tv); err != nil {
		return nil, err
	}

	return &tv, nil
}

func saveTeamVault(tv *TeamVault) error {
	jsonData, err := json.Marshal(tv)
	if err != nil {
		return err
	}

	payload := append([]byte("APMTEAMV"), jsonData...)
	return os.WriteFile(vaultPath, payload, 0600)
}

func addSharedPassword(tv *TeamVault, s *TeamSession) {
	fmt.Print("Name: ")
	name := readInput()
	fmt.Print("Username: ")
	username := readInput()
	fmt.Print("Password: ")
	password := readInput()
	fmt.Print("URL: ")
	url := readInput()

	encryptedPass, _ := EncryptData([]byte(password), s.DeptKey)

	entry := SharedPassword{
		ID:           fmt.Sprintf("pwd_%d", time.Now().Unix()),
		Name:         name,
		Username:     username,
		Password:     encryptedPass,
		URL:          url,
		DepartmentID: s.ActiveDeptID,
		CreatedBy:    s.Username,
		CreatedAt:    time.Now(),
	}

	tv.SharedEntries.Passwords = append(tv.SharedEntries.Passwords, entry)
	tv.AddAuditEntry(s.Username, "ADD_PASSWORD", "Added shared password: "+name)

	if err := saveTeamVault(tv); err != nil {
		color.Red("Error saving: %v\n", err)
		return
	}

	color.Green("Shared password '%s' added successfully.\n", name)
}

func addSharedTOTP(tv *TeamVault, s *TeamSession) {
	fmt.Print("Name: ")
	name := readInput()
	fmt.Print("Secret: ")
	secret := readInput()
	fmt.Print("Issuer: ")
	issuer := readInput()

	encryptedSecret, _ := EncryptData([]byte(secret), s.DeptKey)

	entry := SharedTOTP{
		ID:           fmt.Sprintf("totp_%d", time.Now().Unix()),
		Name:         name,
		Secret:       encryptedSecret,
		Issuer:       issuer,
		DepartmentID: s.ActiveDeptID,
		CreatedBy:    s.Username,
		CreatedAt:    time.Now(),
	}

	tv.SharedEntries.TOTPs = append(tv.SharedEntries.TOTPs, entry)
	tv.AddAuditEntry(s.Username, "ADD_TOTP", "Added shared TOTP: "+name)

	if err := saveTeamVault(tv); err != nil {
		color.Red("Error saving: %v\n", err)
		return
	}

	color.Green("Shared TOTP '%s' added successfully.\n", name)
}

func addSharedAPIKey(tv *TeamVault, s *TeamSession) {
	fmt.Print("Label: ")
	label := readInput()
	fmt.Print("Service: ")
	service := readInput()
	fmt.Print("API Key: ")
	key := readInput()

	encryptedKey, _ := EncryptData([]byte(key), s.DeptKey)

	entry := SharedAPIKey{
		ID:           fmt.Sprintf("api_%d", time.Now().Unix()),
		Label:        label,
		Service:      service,
		Key:          encryptedKey,
		DepartmentID: s.ActiveDeptID,
		CreatedBy:    s.Username,
		CreatedAt:    time.Now(),
	}

	tv.SharedEntries.APIKeys = append(tv.SharedEntries.APIKeys, entry)
	tv.AddAuditEntry(s.Username, "ADD_APIKEY", "Added shared API key: "+label)

	if err := saveTeamVault(tv); err != nil {
		color.Red("Error saving: %v\n", err)
		return
	}

	color.Green("Shared API key '%s' added successfully.\n", label)
}

func addSharedToken(tv *TeamVault, s *TeamSession) {
	fmt.Print("Name: ")
	name := readInput()
	fmt.Print("Token: ")
	token := readInput()
	fmt.Print("Type (e.g., GitHub): ")
	tokenType := readInput()

	encryptedToken, _ := EncryptData([]byte(token), s.DeptKey)

	entry := SharedToken{
		ID:           fmt.Sprintf("tok_%d", time.Now().Unix()),
		Name:         name,
		Token:        encryptedToken,
		Type:         tokenType,
		DepartmentID: s.ActiveDeptID,
		CreatedBy:    s.Username,
		CreatedAt:    time.Now(),
	}

	tv.SharedEntries.Tokens = append(tv.SharedEntries.Tokens, entry)
	tv.AddAuditEntry(s.Username, "ADD_TOKEN", "Added shared token: "+name)

	if err := saveTeamVault(tv); err != nil {
		color.Red("Error saving: %v\n", err)
		return
	}

	color.Green("Shared token '%s' added successfully.\n", name)
}

func addSharedNote(tv *TeamVault, s *TeamSession) {
	fmt.Print("Name: ")
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
	content := strings.Join(contentLines, "\n")

	encryptedContent, _ := EncryptData([]byte(content), s.DeptKey)

	entry := SharedNote{
		ID:           fmt.Sprintf("note_%d", time.Now().Unix()),
		Name:         name,
		Content:      encryptedContent,
		DepartmentID: s.ActiveDeptID,
		CreatedBy:    s.Username,
		CreatedAt:    time.Now(),
	}

	tv.SharedEntries.Notes = append(tv.SharedEntries.Notes, entry)
	tv.AddAuditEntry(s.Username, "ADD_NOTE", "Added shared note: "+name)

	if err := saveTeamVault(tv); err != nil {
		color.Red("Error saving: %v\n", err)
		return
	}

	color.Green("Shared note '%s' added successfully.\n", name)
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

func generatePassword(length int) string {
	const charset = "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789!@#$%^&*()-_=+[]{}|;:,.<>?"
	password := make([]byte, length)
	for i := range password {
		randomByte := make([]byte, 1)
		_, _ = rand.Read(randomByte)
		password[i] = charset[int(randomByte[0])%len(charset)]
	}
	return string(password)
}
