package main

import (
	"bufio"
	"crypto/hmac"
	"crypto/rand"
	"crypto/sha1"
	"encoding/base32"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"os"
	"os/signal"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"syscall"
	"time"
	"unicode"

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
		Use:	"pm-team",
		Short:	"Team Password Manager - Secure shared credential management",
	}

	var initCmd = &cobra.Command{
		Use:	"init <org_name> <admin_username>",
		Short:	"Initialize a new team organization",
		Args:	cobra.ExactArgs(2),
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

			ukKeys := DeriveKeys(pass, salt, 3)
			wrappedDK, _ := WrapKey(dk, ukKeys.EncryptionKey)

			dept := Department{
				ID:	"general",
				Name:	"General",
			}

			user := TeamUser{
				ID:	"admin",
				Username:	adminUser,
				Role:	RoleAdmin,
				ActiveDepartmentID:	"general",
				WrappedKeys:	map[string][]byte{"general": wrappedDK},
				Permissions:	make(map[string]bool),
			}

			tv := TeamVault{
				OrganizationID:	orgName,
				Departments:	[]Department{dept},
				Users:	[]TeamUser{user},
				SharedEntries:	SharedEntryStore{},
				Salt:	salt,
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
		Use:	"login <username>",
		Short:	"Login to team organization",
		Args:	cobra.ExactArgs(1),
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

			ukKeys := DeriveKeys(pass, tv.Salt, 3)

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

			if targetUser.Role == RoleAdmin && len(tv.PendingApprovals) > 0 {
				color.Yellow("\n[NOTIFICATION] You have %d pending approval request(s) for sensitive entries.\n", len(tv.PendingApprovals))
				color.Yellow("Run 'pm-team approvals list' to review them.\n")
			}
		},
	}

	var whoamiCmd = &cobra.Command{
		Use:	"whoami",
		Short:	"Display current session information",
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
			if len(s.Permissions) > 0 {
				fmt.Printf("Permission Overrides: %v\n", s.Permissions)
			}
		},
	}

	var logoutCmd = &cobra.Command{
		Use:	"logout",
		Short:	"End current session",
		Run: func(cmd *cobra.Command, args []string) {
			if err := EndSession(); err != nil {
				color.Red("No active session.\n")
				return
			}
			color.Green("Logged out successfully.\n")
		},
	}

	var deptCmd = &cobra.Command{
		Use:	"dept",
		Short:	"Manage departments",
	}

	var deptListCmd = &cobra.Command{
		Use:	"list",
		Short:	"List all departments",
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
		Use:	"create <name>",
		Short:	"Create a new department (Admin/Manager only)",
		Args:	cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil {
				color.Red("No active session. Run 'pm-team login' first.\n")
				return
			}
			tv, _ := loadTeamVault()
			user := getCurrentUser(tv, s)
			if !s.Role.CanManageDepartments(user) {
				color.Red("Permission denied.\n")
				return
			}

			name := args[0]
			id := strings.ToLower(strings.ReplaceAll(name, " ", "_"))

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

	var userCmd = &cobra.Command{
		Use:	"user",
		Short:	"Manage team users",
	}

	var userListCmd = &cobra.Command{
		Use:	"list",
		Short:	"List all users",
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
		Use:	"add <username>",
		Short:	"Add a new user (Admin/Manager only)",
		Args:	cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil {
				color.Red("No active session. Run 'pm-team login' first.\n")
				return
			}
			tv, _ := loadTeamVault()
			user := getCurrentUser(tv, s)
			if !s.Role.CanManageUsers(user) {
				color.Red("Permission denied.\n")
				return
			}

			username := args[0]
			roleStr, _ := cmd.Flags().GetString("role")
			deptID, _ := cmd.Flags().GetString("dept")

			fmt.Printf("Set Password for %s: ", username)
			pass, _ := readPassword()
			fmt.Println()

			userSalt, _ := GenerateSalt()
			ukKeys := DeriveKeys(pass, userSalt, 3)

			wrappedDK, err := WrapKey(s.DeptKey, ukKeys.EncryptionKey)
			if err != nil {
				color.Red("Key wrapping failed: %v\n", err)
				return
			}

			newUser := TeamUser{
				ID:	fmt.Sprintf("user_%d", time.Now().Unix()),
				Username:	username,
				Role:	Role(strings.ToUpper(roleStr)),
				ActiveDepartmentID:	deptID,
				WrappedKeys:	map[string][]byte{deptID: wrappedDK},
				Permissions:	make(map[string]bool),
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

	var userRemoveCmd = &cobra.Command{
		Use:	"remove <username>",
		Short:	"Remove a user from the organization",
		Args:	cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil {
				color.Red("No active session.\n")
				return
			}
			tv, _ := loadTeamVault()
			user := getCurrentUser(tv, s)
			if !s.Role.CanManageUsers(user) {
				color.Red("Permission denied.\n")
				return
			}

			username := args[0]

			foundIdx := -1
			for i, u := range tv.Users {
				if u.Username == username {
					if u.Role == RoleAdmin && s.Role != RoleAdmin {
						color.Red("Only admins can remove other admins.\n")
						return
					}
					foundIdx = i
					break
				}
			}

			if foundIdx == -1 {
				color.Red("User '%s' not found.\n", username)
				return
			}

			tv.Users = append(tv.Users[:foundIdx], tv.Users[foundIdx+1:]...)
			tv.AddAuditEntry(s.Username, "USER_REMOVE", "Removed user: "+username)

			if err := saveTeamVault(tv); err != nil {
				color.Red("Error saving: %v\n", err)
				return
			}

			color.Green("User '%s' removed successfully.\n", username)
		},
	}

	var userPromoteCmd = &cobra.Command{
		Use:	"promote <username> <role>",
		Short:	"Change a user's role (Admin only)",
		Args:	cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil || s.Role != RoleAdmin {
				color.Red("Permission denied. Admin only.\n")
				return
			}

			username := args[0]
			newRole := Role(strings.ToUpper(args[1]))

			tv, _ := loadTeamVault()

			found := false
			for i, u := range tv.Users {
				if u.Username == username {
					tv.Users[i].Role = newRole
					tv.AddAuditEntry(s.Username, "USER_PROMOTE", fmt.Sprintf("Promoted %s to %s", username, newRole))
					found = true
					break
				}
			}

			if !found {
				color.Red("User '%s' not found.\n", username)
				return
			}

			if err := saveTeamVault(tv); err != nil {
				color.Red("Error saving: %v\n", err)
				return
			}

			color.Green("User '%s' promoted to %s.\n", username, newRole)
		},
	}

	var userRoleListCmd = &cobra.Command{
		Use:	"roles",
		Short:	"List all available user roles",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Available Roles:")
			for _, r := range GetRoles() {
				fmt.Printf("- %s\n", r)
			}
		},
	}

	var userPermCmd = &cobra.Command{
		Use:	"permission",
		Short:	"Manage user-specific permission overrides",
	}

	var userPermGrantCmd = &cobra.Command{
		Use:	"grant <username> <permission>",
		Short:	"Grant a specific permission override",
		Args:	cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil || s.Role != RoleAdmin {
				color.Red("Permission denied. Admin only.\n")
				return
			}
			username := args[0]
			perm := args[1]
			tv, _ := loadTeamVault()
			for i, u := range tv.Users {
				if u.Username == username {
					if tv.Users[i].Permissions == nil {
						tv.Users[i].Permissions = make(map[string]bool)
					}
					tv.Users[i].Permissions[perm] = true
					saveTeamVault(tv)
					color.Green("Permission '%s' granted to user '%s'.\n", perm, username)
					return
				}
			}
			color.Red("User '%s' not found.\n", username)
		},
	}

	var userPermRevokeCmd = &cobra.Command{
		Use:	"revoke <username> <permission>",
		Short:	"Revoke a specific permission override",
		Args:	cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil || s.Role != RoleAdmin {
				color.Red("Permission denied. Admin only.\n")
				return
			}
			username := args[0]
			perm := args[1]
			tv, _ := loadTeamVault()
			for i, u := range tv.Users {
				if u.Username == username {
					if tv.Users[i].Permissions == nil {
						tv.Users[i].Permissions = make(map[string]bool)
					}
					tv.Users[i].Permissions[perm] = false
					saveTeamVault(tv)
					color.Green("Permission '%s' revoked from user '%s'.\n", perm, username)
					return
				}
			}
			color.Red("User '%s' not found.\n", username)
		},
	}

	userPermCmd.AddCommand(userPermGrantCmd, userPermRevokeCmd)
	userCmd.AddCommand(userListCmd, userAddCmd, userRemoveCmd, userPromoteCmd, userRoleListCmd, userPermCmd)

	var deptSwitchCmd = &cobra.Command{
		Use:	"switch <username> <dept_id>",
		Short:	"Switch a user's active department (Admin only)",
		Args:	cobra.ExactArgs(2),
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil || s.Role != RoleAdmin {
				color.Red("Permission denied. Admin only.\n")
				return
			}

			username := args[0]
			deptID := args[1]

			tv, _ := loadTeamVault()

			deptExists := false
			for _, d := range tv.Departments {
				if d.ID == deptID {
					deptExists = true
					break
				}
			}

			if !deptExists {
				color.Red("Department '%s' not found.\n", deptID)
				return
			}

			found := false
			for i, u := range tv.Users {
				if u.Username == username {
					tv.Users[i].ActiveDepartmentID = deptID
					tv.AddAuditEntry(s.Username, "DEPT_SWITCH", fmt.Sprintf("Moved %s to %s", username, deptID))
					found = true
					break
				}
			}

			if !found {
				color.Red("User '%s' not found.\n", username)
				return
			}

			if err := saveTeamVault(tv); err != nil {
				color.Red("Error saving: %v\n", err)
				return
			}

			color.Green("User '%s' moved to department '%s'.\n", username, deptID)
		},
	}

	deptCmd.AddCommand(deptListCmd, deptCreateCmd, deptSwitchCmd)

	var addCmd = &cobra.Command{
		Use:	"add",
		Short:	"Add a shared entry (interactive)",
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil {
				color.Red("No active session.\n")
				return
			}
			tv, _ := loadTeamVault()
			user := getCurrentUser(tv, s)
			if !s.Role.CanAddEntry(user) {
				color.Red("Permission denied.\n")
				return
			}

			fmt.Println("Select entry type:")
			fmt.Println("1. Password")
			fmt.Println("2. TOTP")
			fmt.Println("3. API Key")
			fmt.Println("4. Token")
			fmt.Println("5. Secure Note")
			fmt.Println("6. SSH Key")
			fmt.Println("7. Certificate")
			fmt.Println("8. Wi-Fi")
			fmt.Println("9. Recovery Code")
			fmt.Println("10. Banking Item")
			fmt.Println("11. Document")
			fmt.Println("12. Gov ID")
			fmt.Println("13. Medical Record")
			fmt.Println("14. Travel Document")
			fmt.Println("15. Contact")
			fmt.Println("16. Cloud Credential")
			fmt.Println("17. K8s Secret")
			fmt.Println("18. Docker Registry")
			fmt.Println("19. SSH Config")
			fmt.Println("20. CI/CD Secret")
			fmt.Println("21. License Key")
			fmt.Println("22. Legal Contract")
			fmt.Print("Choice (1-22): ")
			choice := readInput()

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
			case "6":
				addSharedSSHKey(tv, s)
			case "7":
				addSharedCertificate(tv, s)
			case "8":
				addSharedWiFi(tv, s)
			case "9":
				addSharedRecoveryCode(tv, s)
			case "10":
				addSharedBankingItem(tv, s)
			case "11":
				addSharedDocument(tv, s)
			case "12":
				addSharedGovID(tv, s)
			case "13":
				addSharedMedicalRecord(tv, s)
			case "14":
				addSharedTravelDoc(tv, s)
			case "15":
				addSharedContact(tv, s)
			case "16":
				addSharedCloudCredential(tv, s)
			case "17":
				addSharedK8s(tv, s)
			case "18":
				addSharedDockerRegistry(tv, s)
			case "19":
				addSharedSSHConfig(tv, s)
			case "20":
				addSharedCICD(tv, s)
			case "21":
				addSharedLicenseKey(tv, s)
			case "22":
				addSharedLegalContract(tv, s)
			default:
				color.Red("Invalid choice.\n")
				return
			}
		},
	}

	var listCmd = &cobra.Command{
		Use:	"list",
		Short:	"List all shared entries",
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
		Use:	"get [query]",
		Short:	"Search and retrieve a shared entry (Interactive TUI if no query)",
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil {
				color.Red("No active session.\n")
				return
			}

			tv, _ := loadTeamVault()
			query := ""
			if len(args) > 0 {
				query = strings.Join(args, " ")
			}

			interactive, _ := cmd.Flags().GetBool("interactive")
			if query == "" || interactive {
				handleInteractiveSharedEntries(tv, s, query)
				return
			}

			results := tv.SearchAll(query, s.ActiveDeptID, s.Role == RoleAdmin)

			if len(results) == 0 {
				color.Red("No entry found matching '%s'.\n", query)
				return
			}

			if len(results) > 1 {
				fmt.Println("Multiple matches found:")
				for i, res := range results {
					fmt.Printf("[%d] %s (%s)\n", i+1, res.Identifier, res.Type)
				}
				fmt.Print("Select a number: ")
				choiceIdx, _ := strconv.Atoi(readInput())
				if choiceIdx < 1 || choiceIdx > len(results) {
					color.Red("Invalid selection.\n")
					return
				}
				displaySharedEntry(results[choiceIdx-1], s.DeptKey)
				return
			}

			displaySharedEntry(results[0], s.DeptKey)
		},
	}
	getCmd.Flags().BoolP("interactive", "i", false, "Use interactive TUI search")

	var genCmd = &cobra.Command{
		Use:	"gen",
		Short:	"Generate a secure random password",
		Run: func(cmd *cobra.Command, args []string) {
			length, _ := cmd.Flags().GetInt("length")
			password := generatePassword(length)
			color.Green("Generated Password: %s\n", password)
		},
	}
	genCmd.Flags().Int("length", 20, "Password length")

	var auditCmd = &cobra.Command{
		Use:	"audit",
		Short:	"View organization audit trail",
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil {
				color.Red("No active session.\n")
				return
			}
			tv, _ := loadTeamVault()
			user := getCurrentUser(tv, s)
			if !s.Role.CanViewAudit(user) {
				color.Red("Permission denied.\n")
				return
			}

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

	var editCmd = &cobra.Command{
		Use:	"edit <entry_name>",
		Short:	"Edit a shared entry",
		Args:	cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil {
				color.Red("No active session.\n")
				return
			}

			tv, _ := loadTeamVault()
			query := strings.Join(args, " ")
			results := tv.SearchAll(query, s.ActiveDeptID, s.Role == RoleAdmin)

			if len(results) == 0 {
				color.Red("No entry found matching '%s'.\n", query)
				return
			}

			res := results[0]
			if len(results) > 1 {
				fmt.Println("Multiple matches. Select one:")
				for i, r := range results {
					fmt.Printf("[%d] %s (%s)\n", i+1, r.Identifier, r.Type)
				}
				idx, _ := strconv.Atoi(readInput())
				if idx < 1 || idx > len(results) {
					return
				}
				res = results[idx-1]
			}

			editSharedEntry(tv, s, res)
		},
	}

	var deleteCmd = &cobra.Command{
		Use:	"delete <entry_name>",
		Short:	"Delete a shared entry",
		Args:	cobra.MinimumNArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil {
				color.Red("No active session.\n")
				return
			}

			tv, _ := loadTeamVault()
			query := strings.Join(args, " ")
			results := tv.SearchAll(query, s.ActiveDeptID, s.Role == RoleAdmin)

			if len(results) == 0 {
				color.Red("No entry found matching '%s'.\n", query)
				return
			}

			res := results[0]
			if len(results) > 1 {
				fmt.Println("Multiple matches. Select one to delete:")
				for i, r := range results {
					fmt.Printf("[%d] %s (%s)\n", i+1, r.Identifier, r.Type)
				}
				idx, _ := strconv.Atoi(readInput())
				if idx < 1 || idx > len(results) {
					return
				}
				res = results[idx-1]
			}

			deleteSharedEntry(tv, s, res)
		},
	}

	var approvalsCmd = &cobra.Command{
		Use:	"approvals",
		Short:	"Manage pending approvals for sensitive entry changes (Admin only)",
	}

	var approvalsListCmd = &cobra.Command{
		Use:	"list",
		Short:	"List all pending approval requests",
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil || s.Role != RoleAdmin {
				color.Red("Permission denied. Admin only.\n")
				return
			}
			tv, _ := loadTeamVault()
			if len(tv.PendingApprovals) == 0 {
				fmt.Println("No pending approval requests.")
				return
			}
			color.Cyan("=== Pending Approvals ===\n")
			for i, req := range tv.PendingApprovals {
				if req.Status == "Pending" {
					fmt.Printf("[%d] ID: %s | Type: %s | Entry: %s (%s) | Requested By: %s\n",
						i+1, req.ID, req.Type, req.EntryID, req.EntryType, req.RequestedBy)
				}
			}
		},
	}

	var approvalsApproveCmd = &cobra.Command{
		Use:	"approve <idx>",
		Short:	"Approve a pending request",
		Args:	cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil || s.Role != RoleAdmin {
				color.Red("Permission denied.\n")
				return
			}
			idx, _ := strconv.Atoi(args[0])
			tv, _ := loadTeamVault()
			if idx < 1 || idx > len(tv.PendingApprovals) {
				color.Red("Invalid index.\n")
				return
			}
			req := &tv.PendingApprovals[idx-1]
			if req.Status != "Pending" {
				color.Red("Request is already %s.\n", req.Status)
				return
			}

			if req.Type == "Create" {
				switch req.EntryType {
				case "Password":
					var p SharedPassword
					json.Unmarshal(req.NewData, &p)
					tv.SharedEntries.Passwords = append(tv.SharedEntries.Passwords, p)
				case "TOTP":
					var t SharedTOTP
					json.Unmarshal(req.NewData, &t)
					tv.SharedEntries.TOTPs = append(tv.SharedEntries.TOTPs, t)
				case "API Key":
					var k SharedAPIKey
					json.Unmarshal(req.NewData, &k)
					tv.SharedEntries.APIKeys = append(tv.SharedEntries.APIKeys, k)
				case "Token":
					var t SharedToken
					json.Unmarshal(req.NewData, &t)
					tv.SharedEntries.Tokens = append(tv.SharedEntries.Tokens, t)
				case "Note":
					var n SharedNote
					json.Unmarshal(req.NewData, &n)
					tv.SharedEntries.Notes = append(tv.SharedEntries.Notes, n)
				case "SSH Key":
					var k SharedSSHKey
					json.Unmarshal(req.NewData, &k)
					tv.SharedEntries.SSHKeys = append(tv.SharedEntries.SSHKeys, k)
				case "Certificate":
					var c SharedCertificate
					json.Unmarshal(req.NewData, &c)
					tv.SharedEntries.Certificates = append(tv.SharedEntries.Certificates, c)
				case "Wi-Fi":
					var w SharedWiFi
					json.Unmarshal(req.NewData, &w)
					tv.SharedEntries.WiFi = append(tv.SharedEntries.WiFi, w)
				case "Recovery Code":
					var r SharedRecoveryCode
					json.Unmarshal(req.NewData, &r)
					tv.SharedEntries.RecoveryCodes = append(tv.SharedEntries.RecoveryCodes, r)
				case "Document":
					var d SharedDocumentEntry
					json.Unmarshal(req.NewData, &d)
					tv.SharedEntries.Documents = append(tv.SharedEntries.Documents, d)
				case "Gov ID":
					var g SharedGovID
					json.Unmarshal(req.NewData, &g)
					tv.SharedEntries.GovIDs = append(tv.SharedEntries.GovIDs, g)
				case "Medical Record":
					var m SharedMedicalRecord
					json.Unmarshal(req.NewData, &m)
					tv.SharedEntries.MedicalRecords = append(tv.SharedEntries.MedicalRecords, m)
				case "Travel":
					var t SharedTravelDoc
					json.Unmarshal(req.NewData, &t)
					tv.SharedEntries.TravelDocs = append(tv.SharedEntries.TravelDocs, t)
				case "Contact":
					var c SharedContact
					json.Unmarshal(req.NewData, &c)
					tv.SharedEntries.Contacts = append(tv.SharedEntries.Contacts, c)
				case "Cloud Credential":
					var c SharedCloudCredential
					json.Unmarshal(req.NewData, &c)
					tv.SharedEntries.CloudCredentials = append(tv.SharedEntries.CloudCredentials, c)
				case "K8s Secret":
					var k SharedK8s
					json.Unmarshal(req.NewData, &k)
					tv.SharedEntries.K8sSecrets = append(tv.SharedEntries.K8sSecrets, k)
				case "Docker Registry":
					var d SharedDockerRegistry
					json.Unmarshal(req.NewData, &d)
					tv.SharedEntries.DockerRegistries = append(tv.SharedEntries.DockerRegistries, d)
				case "SSH Config":
					var s SharedSSHConfig
					json.Unmarshal(req.NewData, &s)
					tv.SharedEntries.SSHConfigs = append(tv.SharedEntries.SSHConfigs, s)
				case "CI/CD Secret":
					var c SharedCICD
					json.Unmarshal(req.NewData, &c)
					tv.SharedEntries.CICDSecrets = append(tv.SharedEntries.CICDSecrets, c)
				case "License Key":
					var l SharedLicenseKey
					json.Unmarshal(req.NewData, &l)
					tv.SharedEntries.LicenseKeys = append(tv.SharedEntries.LicenseKeys, l)
				case "Legal Contract":
					var l SharedLegalContract
					json.Unmarshal(req.NewData, &l)
					tv.SharedEntries.LegalContracts = append(tv.SharedEntries.LegalContracts, l)
				}
				color.Green("Created entry %s.\n", req.EntryID)
			} else if req.Type == "Delete" {

				color.Yellow("Applying deletion of %s (%s)...\n", req.EntryID, req.EntryType)
			}

			req.Status = "Approved"
			tv.AddAuditEntry(s.Username, "APPROVE_REQ", fmt.Sprintf("Approved %s for %s", req.Type, req.EntryID))
			saveTeamVault(tv)
			color.Green("Request approved and applied.\n")
		},
	}

	var approvalsDenyCmd = &cobra.Command{
		Use:	"deny <idx>",
		Short:	"Deny a pending request",
		Args:	cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil || s.Role != RoleAdmin {
				color.Red("Permission denied.\n")
				return
			}
			idx, _ := strconv.Atoi(args[0])
			tv, _ := loadTeamVault()
			if idx < 1 || idx > len(tv.PendingApprovals) {
				color.Red("Invalid index.\n")
				return
			}

			fmt.Print("Reason for denial: ")
			reason := readInput()
			if reason == "" {
				color.Red("Reason is required.\n")
				return
			}

			req := &tv.PendingApprovals[idx-1]
			req.Status = "Denied"
			req.DenialReason = reason
			tv.AddAuditEntry(s.Username, "DENY_REQ", fmt.Sprintf("Denied %s for %s: %s", req.Type, req.EntryID, reason))
			saveTeamVault(tv)
			color.Red("Request denied.\n")
		},
	}

	approvalsCmd.AddCommand(approvalsListCmd, approvalsApproveCmd, approvalsDenyCmd)

	var exportCmd = &cobra.Command{
		Use:	"export",
		Short:	"Export team vault to JSON (Admin only)",
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil || s.Role != RoleAdmin {
				color.Red("Permission denied. Admin only.\n")
				return
			}

			tv, _ := loadTeamVault()

			exportData := map[string]interface{}{
				"organization_id":	tv.OrganizationID,
				"departments":	tv.Departments,
				"users":	tv.Users,
				"entry_counts": map[string]int{
					"passwords":	len(tv.SharedEntries.Passwords),
					"totps":	len(tv.SharedEntries.TOTPs),
					"api_keys":	len(tv.SharedEntries.APIKeys),
					"tokens":	len(tv.SharedEntries.Tokens),
					"notes":	len(tv.SharedEntries.Notes),
				},
				"audit_trail":	tv.AuditTrail,
			}

			jsonData, _ := json.MarshalIndent(exportData, "", "  ")
			fmt.Println(string(jsonData))

			tv.AddAuditEntry(s.Username, "EXPORT", "Exported team vault metadata")
			saveTeamVault(tv)
		},
	}

	var healthCmd = &cobra.Command{
		Use:	"health",
		Short:	"Perform a security audit of the shared vault",
		Run: func(cmd *cobra.Command, args []string) {
			_, err := GetSession()
			if err != nil {
				color.Red("No active session.\n")
				return
			}

			tv, _ := loadTeamVault()
			color.Cyan("=== Team Vault Security Health Check ===\n")

			issues := 0

			sensitiveCount := 0
			results := tv.SearchAll("", "", true)
			for _, r := range results {
				isSensitive := false
				switch v := r.Data.(type) {
				case SharedPassword:
					isSensitive = v.IsSensitive
				case SharedTOTP:
					isSensitive = v.IsSensitive
				}
				if isSensitive {
					sensitiveCount++
				}
			}
			fmt.Printf("Total Sensitive Entries: %d\n", sensitiveCount)

			if len(tv.PendingApprovals) > 0 {
				color.Yellow("[!] Warning: %d pending approval requests.\n", len(tv.PendingApprovals))
				issues++
			} else {
				color.Green("[   ] No pending approval requests.\n")
			}

			adminCount := 0
			for _, u := range tv.Users {
				if u.Role == RoleAdmin {
					adminCount++
				}
			}
			if adminCount > 3 {
				color.Yellow("[!] Tip: Too many admins (%d). Consider reducing for better security.\n", adminCount)
				issues++
			} else {
				color.Green("[   ] Admin count is healthy (%d).\n", adminCount)
			}

			if len(tv.AuditTrail) > 1000 {
				color.Yellow("[!] Tip: Audit trail is becoming large (%d entries). Consider archiving.\n", len(tv.AuditTrail))
				issues++
			}

			fmt.Printf("\nHealth Score: %d/100\n", 100-(issues*10))
			if issues == 0 {
				color.HiGreen("Overall Status: EXCELLENT\n")
			} else if issues < 3 {
				color.HiYellow("Overall Status: GOOD\n")
			} else {
				color.HiRed("Overall Status: NEEDS ATTENTION\n")
			}
		},
	}

	var infoCmd = &cobra.Command{
		Use:	"info",
		Short:	"Display organization information",
		Run: func(cmd *cobra.Command, args []string) {
			_, err := GetSession()
			if err != nil {
				color.Red("No active session.\n")
				return
			}

			tv, _ := loadTeamVault()

			color.Cyan("=== Organization Information ===\n")
			fmt.Printf("Organization: %s\n", tv.OrganizationID)
			fmt.Printf("Departments: %d\n", len(tv.Departments))
			fmt.Printf("Users: %d\n", len(tv.Users))
			fmt.Printf("\nShared Entries:\n")
			fmt.Printf("  Passwords:        %d\n", len(tv.SharedEntries.Passwords))
			fmt.Printf("  TOTPs:            %d\n", len(tv.SharedEntries.TOTPs))
			fmt.Printf("  API Keys:         %d\n", len(tv.SharedEntries.APIKeys))
			fmt.Printf("  Tokens:           %d\n", len(tv.SharedEntries.Tokens))
			fmt.Printf("  Notes:            %d\n", len(tv.SharedEntries.Notes))
			fmt.Printf("  SSH Keys:         %d\n", len(tv.SharedEntries.SSHKeys))
			fmt.Printf("  Certificates:     %d\n", len(tv.SharedEntries.Certificates))
			fmt.Printf("  Wi-Fi Configs:    %d\n", len(tv.SharedEntries.WiFi))
			fmt.Printf("  Recovery Codes:   %d\n", len(tv.SharedEntries.RecoveryCodes))
			fmt.Printf("  Banking Items:    %d\n", len(tv.SharedEntries.BankingItems))
			fmt.Printf("  Documents:        %d\n", len(tv.SharedEntries.Documents))
			fmt.Printf("  Gov IDs:          %d\n", len(tv.SharedEntries.GovIDs))
			fmt.Printf("  Medical Records:  %d\n", len(tv.SharedEntries.MedicalRecords))
			fmt.Printf("  Travel Documents: %d\n", len(tv.SharedEntries.TravelDocs))
			fmt.Printf("  Contacts:         %d\n", len(tv.SharedEntries.Contacts))
			fmt.Printf("  Cloud Creds:      %d\n", len(tv.SharedEntries.CloudCredentials))
			fmt.Printf("  K8s Secrets:      %d\n", len(tv.SharedEntries.K8sSecrets))
			fmt.Printf("  Docker Registries:%d\n", len(tv.SharedEntries.DockerRegistries))
			fmt.Printf("  SSH Configs:      %d\n", len(tv.SharedEntries.SSHConfigs))
			fmt.Printf("  CI/CD Secrets:    %d\n", len(tv.SharedEntries.CICDSecrets))
			fmt.Printf("  License Keys:     %d\n", len(tv.SharedEntries.LicenseKeys))
			fmt.Printf("  Legal Contracts:  %d\n", len(tv.SharedEntries.LegalContracts))
			fmt.Printf("\nAudit Entries: %d\n", len(tv.AuditTrail))
		},
	}

	createTypeCmd := func(use string, short string, resType string, addFunc func(*TeamVault, *TeamSession)) *cobra.Command {
		group := &cobra.Command{Use: use, Short: short}
		group.AddCommand(&cobra.Command{
			Use:	"add",
			Short:	"Add a new " + resType,
			Run: func(cmd *cobra.Command, args []string) {
				s, err := GetSession()
				if err != nil || !s.Role.CanAddEntry(nil) {
					color.Red("Permission denied.\n")
					return
				}
				tv, _ := loadTeamVault()
				addFunc(tv, s)
			},
		})
		group.AddCommand(&cobra.Command{
			Use:	"list",
			Short:	"List all " + resType + "s",
			Run: func(cmd *cobra.Command, args []string) {
				s, err := GetSession()
				if err != nil {
					color.Red("No active session.\n")
					return
				}
				tv, _ := loadTeamVault()
				results := tv.SearchAll("", s.ActiveDeptID, s.Role == RoleAdmin)
				fmt.Printf("=== %s List ===\n", resType)
				for _, r := range results {
					if r.Type == resType {
						fmt.Printf("- %s\n", r.Identifier)
					}
				}
			},
		})
		group.AddCommand(&cobra.Command{
			Use:	"get <query>",
			Short:	"Retrieve a " + resType,
			Args:	cobra.MinimumNArgs(1),
			Run: func(cmd *cobra.Command, args []string) {
				s, err := GetSession()
				if err != nil {
					color.Red("No active session.\n")
					return
				}
				tv, _ := loadTeamVault()
				query := strings.Join(args, " ")
				results := tv.SearchAll(query, s.ActiveDeptID, s.Role == RoleAdmin)
				for _, r := range results {
					if r.Type == resType {
						displaySharedEntry(r, s.DeptKey)
						return
					}
				}
				color.Red("No %s found matching '%s'.\n", resType, query)
			},
		})
		return group
	}

	var passwordCmd = createTypeCmd("password", "Manage shared passwords", "Password", addSharedPassword)
	var totpCmd = createTypeCmd("totp", "Manage shared TOTP accounts", "TOTP", addSharedTOTP)
	var apiKeyCmd = createTypeCmd("apikey", "Manage shared API keys", "API Key", addSharedAPIKey)
	var tokenCmd = createTypeCmd("token", "Manage shared tokens", "Token", addSharedToken)
	var noteCmd = createTypeCmd("note", "Manage shared secure notes", "Note", addSharedNote)
	var sshCmd = createTypeCmd("ssh", "Manage shared SSH keys", "SSH Key", addSharedSSHKey)
	var certCmd = createTypeCmd("cert", "Manage shared certificates", "Certificate", addSharedCertificate)
	var wifiCmd = createTypeCmd("wifi", "Manage shared Wi-Fi credentials", "Wi-Fi", addSharedWiFi)
	var recoveryCmd = createTypeCmd("recovery", "Manage shared recovery codes", "Recovery Code", addSharedRecoveryCode)
	var bankingCmd = createTypeCmd("banking", "Manage shared banking items", "Banking", addSharedBankingItem)
	var docCmd = createTypeCmd("doc", "Manage shared documents", "Document", addSharedDocument)
	var govCmd = createTypeCmd("gov", "Manage shared government IDs", "Government ID", addSharedGovID)
	var medicalCmd = createTypeCmd("medical", "Manage shared medical records", "Medical Record", addSharedMedicalRecord)
	var travelCmd = createTypeCmd("travel", "Manage shared travel documents", "Travel Document", addSharedTravelDoc)
	var contactCmd = createTypeCmd("contact", "Manage shared contacts", "Contact", addSharedContact)
	var cloudCmd = createTypeCmd("cloud", "Manage shared cloud credentials", "Cloud Credential", addSharedCloudCredential)
	var k8sCmd = createTypeCmd("k8s", "Manage shared Kubernetes secrets", "Kubernetes Secret", addSharedK8s)
	var dockerCmd = createTypeCmd("docker", "Manage shared Docker registry credentials", "Docker Registry", addSharedDockerRegistry)
	var sshConfigCmd = createTypeCmd("ssh-config", "Manage shared SSH configurations", "SSH Config", addSharedSSHConfig)
	var cicdCmd = createTypeCmd("cicd", "Manage shared CI/CD secrets", "CI/CD Secret", addSharedCICD)
	var licenseCmd = createTypeCmd("license", "Manage shared license keys", "License Key", addSharedLicenseKey)
	var legalCmd = createTypeCmd("legal", "Manage shared legal contracts", "Legal Contract", addSharedLegalContract)

	rootCmd.AddCommand(
		initCmd, loginCmd, whoamiCmd, logoutCmd, infoCmd, auditCmd, approvalsCmd,
		userCmd, deptCmd, healthCmd,
		passwordCmd, totpCmd, apiKeyCmd, tokenCmd, noteCmd,
		sshCmd, certCmd, wifiCmd, recoveryCmd, bankingCmd, docCmd,
		govCmd, medicalCmd, travelCmd, contactCmd, cloudCmd, k8sCmd,
		dockerCmd, sshConfigCmd, cicdCmd, licenseCmd, legalCmd,
		getCmd, addCmd, listCmd, editCmd, deleteCmd, genCmd, exportCmd,
	)
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

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"

	fmt.Print("Make this entry global (company-wide)? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	passwordEntry := SharedPassword{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("pass_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Name:	name,
		Username:	username,
		Password:	encryptedPass,
		URL:	url,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(passwordEntry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:	fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:	"Create",
			EntryType:	"Password",
			EntryID:	name,
			NewData:	data,
			RequestedBy:	s.Username,
			RequestedAt:	time.Now(),
			Status:	"Pending",
		})
	} else {
		tv.SharedEntries.Passwords = append(tv.SharedEntries.Passwords, passwordEntry)
		tv.AddAuditEntry(s.Username, "ADD_PASS", "Added shared password: "+name)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedTOTP(tv *TeamVault, s *TeamSession) {
	fmt.Print("Name: ")
	name := readInput()
	fmt.Print("Secret: ")
	secret := readInput()
	fmt.Print("Issuer: ")
	issuer := readInput()

	encryptedSecret, _ := EncryptData([]byte(secret), s.DeptKey)

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global (company-wide)? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedTOTP{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("totp_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Name:	name,
		Secret:	encryptedSecret,
		Issuer:	issuer,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:	fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:	"Create",
			EntryType:	"TOTP",
			EntryID:	name,
			NewData:	data,
			RequestedBy:	s.Username,
			RequestedAt:	time.Now(),
			Status:	"Pending",
		})
	} else {
		tv.SharedEntries.TOTPs = append(tv.SharedEntries.TOTPs, entry)
		tv.AddAuditEntry(s.Username, "ADD_TOTP", "Added shared TOTP: "+name)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedAPIKey(tv *TeamVault, s *TeamSession) {
	fmt.Print("Label: ")
	label := readInput()
	fmt.Print("Service: ")
	service := readInput()
	fmt.Print("API Key: ")
	key := readInput()

	encryptedKey, _ := EncryptData([]byte(key), s.DeptKey)

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global (company-wide)? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedAPIKey{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("api_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Label:	label,
		Service:	service,
		Key:	encryptedKey,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:	fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:	"Create",
			EntryType:	"API Key",
			EntryID:	label,
			NewData:	data,
			RequestedBy:	s.Username,
			RequestedAt:	time.Now(),
			Status:	"Pending",
		})
	} else {
		tv.SharedEntries.APIKeys = append(tv.SharedEntries.APIKeys, entry)
		tv.AddAuditEntry(s.Username, "ADD_APIKEY", "Added shared API key: "+label)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedToken(tv *TeamVault, s *TeamSession) {
	fmt.Print("Name: ")
	name := readInput()
	fmt.Print("Token: ")
	token := readInput()
	fmt.Print("Type (e.g., GitHub): ")
	tokenType := readInput()

	encryptedToken, _ := EncryptData([]byte(token), s.DeptKey)

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global (company-wide)? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedToken{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("tok_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Name:	name,
		Token:	encryptedToken,
		Type:	tokenType,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:	fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:	"Create",
			EntryType:	"Token",
			EntryID:	name,
			NewData:	data,
			RequestedBy:	s.Username,
			RequestedAt:	time.Now(),
			Status:	"Pending",
		})
	} else {
		tv.SharedEntries.Tokens = append(tv.SharedEntries.Tokens, entry)
		tv.AddAuditEntry(s.Username, "ADD_TOKEN", "Added shared token: "+name)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
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

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global (company-wide)? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedNote{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("note_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Name:	name,
		Content:	encryptedContent,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:	fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:	"Create",
			EntryType:	"Note",
			EntryID:	name,
			NewData:	data,
			RequestedBy:	s.Username,
			RequestedAt:	time.Now(),
			Status:	"Pending",
		})
	} else {
		tv.SharedEntries.Notes = append(tv.SharedEntries.Notes, entry)
		tv.AddAuditEntry(s.Username, "ADD_NOTE", "Added shared note: "+name)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedSSHKey(tv *TeamVault, s *TeamSession) {
	fmt.Print("Label: ")
	label := readInput()
	fmt.Println("Enter Private Key (end with empty line):")
	var keyLines []string
	for {
		line := readInput()
		if line == "" {
			break
		}
		keyLines = append(keyLines, line)
	}
	key := strings.Join(keyLines, "\n")

	encryptedKey, _ := EncryptData([]byte(key), s.DeptKey)

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global (company-wide)? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedSSHKey{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("ssh_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Label:	label,
		PrivateKey:	encryptedKey,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:	fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:	"Create",
			EntryType:	"SSH Key",
			EntryID:	label,
			NewData:	data,
			RequestedBy:	s.Username,
			RequestedAt:	time.Now(),
			Status:	"Pending",
		})
	} else {
		tv.SharedEntries.SSHKeys = append(tv.SharedEntries.SSHKeys, entry)
		tv.AddAuditEntry(s.Username, "ADD_SSHKEY", "Added shared SSH key: "+label)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedCertificate(tv *TeamVault, s *TeamSession) {
	fmt.Print("Label: ")
	label := readInput()
	fmt.Print("Issuer: ")
	issuer := readInput()
	fmt.Print("Expiry Date (YYYY-MM-DD): ")
	expiryStr := readInput()
	expiry, _ := time.Parse("2006-01-02", expiryStr)

	fmt.Println("Enter Cert Data (end with empty line):")
	certData := readMultilineInput()
	fmt.Println("Enter Private Key (end with empty line, blank if none):")
	privKey := readMultilineInput()

	encCert, _ := EncryptData([]byte(certData), s.DeptKey)
	var encPriv []byte
	if privKey != "" {
		encPriv, _ = EncryptData([]byte(privKey), s.DeptKey)
	}

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global (company-wide)? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedCertificate{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("cert_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Label:	label,
		Issuer:	issuer,
		Expiry:	expiry,
		CertData:	encCert,
		PrivateKey:	encPriv,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:	fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:	"Create",
			EntryType:	"Certificate",
			EntryID:	label,
			NewData:	data,
			RequestedBy:	s.Username,
			RequestedAt:	time.Now(),
			Status:	"Pending",
		})
	} else {
		tv.SharedEntries.Certificates = append(tv.SharedEntries.Certificates, entry)
		tv.AddAuditEntry(s.Username, "ADD_CERT", "Added shared certificate: "+label)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedWiFi(tv *TeamVault, s *TeamSession) {
	fmt.Print("SSID: ")
	ssid := readInput()
	fmt.Print("Password: ")
	pass := readInput()
	fmt.Print("Security (WPA2/WPA3): ")
	sec := readInput()

	encPass, _ := EncryptData([]byte(pass), s.DeptKey)

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global (company-wide)? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedWiFi{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("wifi_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		SSID:	ssid,
		Password:	encPass,
		Security:	sec,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:	fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:	"Create",
			EntryType:	"Wi-Fi",
			EntryID:	ssid,
			NewData:	data,
			RequestedBy:	s.Username,
			RequestedAt:	time.Now(),
			Status:	"Pending",
		})
	} else {
		tv.SharedEntries.WiFi = append(tv.SharedEntries.WiFi, entry)
		tv.AddAuditEntry(s.Username, "ADD_WIFI", "Added shared Wi-Fi: "+ssid)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedRecoveryCode(tv *TeamVault, s *TeamSession) {
	fmt.Print("Service: ")
	svc := readInput()
	fmt.Println("Enter Codes (one per line, end with empty line):")
	codes := readMultilineInput()

	encCodes, _ := EncryptData([]byte(codes), s.DeptKey)

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global (company-wide)? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedRecoveryCode{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("rec_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Service:	svc,
		Codes:	encCodes,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:	fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:	"Create",
			EntryType:	"Recovery Code",
			EntryID:	svc,
			NewData:	data,
			RequestedBy:	s.Username,
			RequestedAt:	time.Now(),
			Status:	"Pending",
		})
	} else {
		tv.SharedEntries.RecoveryCodes = append(tv.SharedEntries.RecoveryCodes, entry)
		tv.AddAuditEntry(s.Username, "ADD_RECOVERY", "Added shared recovery codes: "+svc)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedBankingItem(tv *TeamVault, s *TeamSession) {
	fmt.Print("Label: ")
	label := readInput()
	fmt.Print("Type (Card/IBAN): ")
	bType := readInput()
	fmt.Print("Details (Number/IBAN): ")
	details := readInput()
	fmt.Print("CVV (blank if none): ")
	cvv := readInput()
	fmt.Print("Expiry (MM/YY, blank if none): ")
	exp := readInput()

	encDetails, _ := EncryptData([]byte(details), s.DeptKey)
	var encCVV []byte
	if cvv != "" {
		encCVV, _ = EncryptData([]byte(cvv), s.DeptKey)
	}

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global (company-wide)? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedBankingItem{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("bank_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Label:	label,
		Type:	bType,
		Details:	encDetails,
		CVV:	encCVV,
		Expiry:	exp,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:	fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:	"Create",
			EntryType:	"Banking",
			EntryID:	label,
			NewData:	data,
			RequestedBy:	s.Username,
			RequestedAt:	time.Now(),
			Status:	"Pending",
		})
	} else {
		tv.SharedEntries.BankingItems = append(tv.SharedEntries.BankingItems, entry)
		tv.AddAuditEntry(s.Username, "ADD_BANK", "Added shared banking item: "+label)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func editSharedEntry(tv *TeamVault, s *TeamSession, res SearchResult) {
	var creator string

	switch v := res.Data.(type) {
	case SharedPassword:
		creator = v.CreatedBy
	case SharedTOTP:
		creator = v.CreatedBy
	case SharedAPIKey:
		creator = v.CreatedBy
	case SharedToken:
		creator = v.CreatedBy
	case SharedNote:
		creator = v.CreatedBy
	case SharedSSHKey:
		creator = v.CreatedBy
	case SharedCertificate:
		creator = v.CreatedBy
	case SharedWiFi:
		creator = v.CreatedBy
	case SharedRecoveryCode:
		creator = v.CreatedBy
	case SharedBankingItem:
		creator = v.CreatedBy
	case SharedDocumentEntry:
		creator = v.CreatedBy
	}

	user := getCurrentUser(tv, s)
	if !s.Role.CanEditEntry(creator, s.Username, user) {
		color.Red("Permission denied. Only admins, managers, or the creator can edit this entry.\n")
		return
	}

	fmt.Printf("Editing %s: %s\n", res.Type, res.Identifier)

	switch res.Type {
	case "Password":
		p := res.Data.(SharedPassword)
		fmt.Print("New Name (leave blank to keep): ")
		newName := readInput()
		if newName != "" {
			p.Name = newName
		}
		fmt.Print("New Password (leave blank to keep): ")
		newPass := readInput()
		if newPass != "" {
			enc, _ := EncryptData([]byte(newPass), s.DeptKey)
			p.Password = enc
		}

		for i, item := range tv.SharedEntries.Passwords {
			if item.ID == p.ID {
				item.ModifiedBy = s.Username
				item.ModifiedAt = time.Now()
				tv.SharedEntries.Passwords[i] = p
				break
			}
		}
	case "TOTP":
		t := res.Data.(SharedTOTP)
		fmt.Print("New Secret (leave blank to keep): ")
		newSec := readInput()
		if newSec != "" {
			enc, _ := EncryptData([]byte(newSec), s.DeptKey)
			t.Secret = enc
		}
		for i, item := range tv.SharedEntries.TOTPs {
			if item.ID == t.ID {
				tv.SharedEntries.TOTPs[i] = t
				break
			}
		}

	default:
		color.Yellow("Edit for %s is partially supported. Re-add to change complex fields.\n", res.Type)
		return
	}

	isSensitive := false
	switch v := res.Data.(type) {
	case SharedPassword:
		isSensitive = v.IsSensitive
	case SharedTOTP:
		isSensitive = v.IsSensitive
	case SharedAPIKey:
		isSensitive = v.IsSensitive
	}

	if isSensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Edit request submitted for admin approval.\n")

		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:	fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:	"Edit",
			EntryType:	res.Type,
			EntryID:	res.Identifier,
			RequestedBy:	s.Username,
			RequestedAt:	time.Now(),
			Status:	"Pending",
		})
		saveTeamVault(tv)
		return
	}

	tv.AddAuditEntry(s.Username, "EDIT", fmt.Sprintf("Edited %s: %s", res.Type, res.Identifier))
	saveTeamVault(tv)
	color.Green("Entry updated.\n")
}

func deleteSharedEntry(tv *TeamVault, s *TeamSession, res SearchResult) {
	var creator string
	switch v := res.Data.(type) {
	case SharedPassword:
		creator = v.CreatedBy
	case SharedTOTP:
		creator = v.CreatedBy
	case SharedAPIKey:
		creator = v.CreatedBy
	case SharedToken:
		creator = v.CreatedBy
	case SharedNote:
		creator = v.CreatedBy
	case SharedSSHKey:
		creator = v.CreatedBy
	case SharedCertificate:
		creator = v.CreatedBy
	case SharedWiFi:
		creator = v.CreatedBy
	case SharedRecoveryCode:
		creator = v.CreatedBy
	case SharedBankingItem:
		creator = v.CreatedBy
	case SharedDocumentEntry:
		creator = v.CreatedBy
	case SharedGovID:
		creator = v.CreatedBy
	case SharedMedicalRecord:
		creator = v.CreatedBy
	case SharedTravelDoc:
		creator = v.CreatedBy
	case SharedContact:
		creator = v.CreatedBy
	case SharedCloudCredential:
		creator = v.CreatedBy
	case SharedK8s:
		creator = v.CreatedBy
	case SharedDockerRegistry:
		creator = v.CreatedBy
	case SharedSSHConfig:
		creator = v.CreatedBy
	case SharedCICD:
		creator = v.CreatedBy
	case SharedLicenseKey:
		creator = v.CreatedBy
	case SharedLegalContract:
		creator = v.CreatedBy
	default:
		creator = ""
	}

	user := getCurrentUser(tv, s)
	if !s.Role.CanDeleteEntry(creator, s.Username, user) {
		color.Red("Permission denied.\n")
		return
	}

	isSensitive := false
	switch v := res.Data.(type) {
	case SharedPassword:
		isSensitive = v.IsSensitive
	case SharedTOTP:
		isSensitive = v.IsSensitive
	}

	if isSensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Deletion request submitted for admin approval.\n")
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:	fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:	"Delete",
			EntryType:	res.Type,
			EntryID:	res.Identifier,
			RequestedBy:	s.Username,
			RequestedAt:	time.Now(),
			Status:	"Pending",
		})
		saveTeamVault(tv)
		return
	}

	fmt.Printf("Are you sure you want to delete %s '%s'? (yes/no): ", res.Type, res.Identifier)
	if strings.ToLower(readInput()) != "yes" {
		fmt.Println("Cancelled.")
		return
	}

	deleted := false
	switch res.Type {
	case "Password":
		id := res.Data.(SharedPassword).ID
		for i, p := range tv.SharedEntries.Passwords {
			if p.ID == id {
				tv.SharedEntries.Passwords = append(tv.SharedEntries.Passwords[:i], tv.SharedEntries.Passwords[i+1:]...)
				deleted = true
				break
			}
		}
	case "TOTP":
		id := res.Data.(SharedTOTP).ID
		for i, t := range tv.SharedEntries.TOTPs {
			if t.ID == id {
				tv.SharedEntries.TOTPs = append(tv.SharedEntries.TOTPs[:i], tv.SharedEntries.TOTPs[i+1:]...)
				deleted = true
				break
			}
		}
	case "API Key":
		id := res.Data.(SharedAPIKey).ID
		for i, k := range tv.SharedEntries.APIKeys {
			if k.ID == id {
				tv.SharedEntries.APIKeys = append(tv.SharedEntries.APIKeys[:i], tv.SharedEntries.APIKeys[i+1:]...)
				deleted = true
				break
			}
		}
	case "Token":
		id := res.Data.(SharedToken).ID
		for i, t := range tv.SharedEntries.Tokens {
			if t.ID == id {
				tv.SharedEntries.Tokens = append(tv.SharedEntries.Tokens[:i], tv.SharedEntries.Tokens[i+1:]...)
				deleted = true
				break
			}
		}
	case "Note":
		id := res.Data.(SharedNote).ID
		for i, n := range tv.SharedEntries.Notes {
			if n.ID == id {
				tv.SharedEntries.Notes = append(tv.SharedEntries.Notes[:i], tv.SharedEntries.Notes[i+1:]...)
				deleted = true
				break
			}
		}
	case "SSH Key":
		id := res.Data.(SharedSSHKey).ID
		for i, s := range tv.SharedEntries.SSHKeys {
			if s.ID == id {
				tv.SharedEntries.SSHKeys = append(tv.SharedEntries.SSHKeys[:i], tv.SharedEntries.SSHKeys[i+1:]...)
				deleted = true
				break
			}
		}
	case "Certificate":
		id := res.Data.(SharedCertificate).ID
		for i, c := range tv.SharedEntries.Certificates {
			if c.ID == id {
				tv.SharedEntries.Certificates = append(tv.SharedEntries.Certificates[:i], tv.SharedEntries.Certificates[i+1:]...)
				deleted = true
				break
			}
		}
	case "Wi-Fi":
		id := res.Data.(SharedWiFi).ID
		for i, w := range tv.SharedEntries.WiFi {
			if w.ID == id {
				tv.SharedEntries.WiFi = append(tv.SharedEntries.WiFi[:i], tv.SharedEntries.WiFi[i+1:]...)
				deleted = true
				break
			}
		}
	case "Recovery Code":
		id := res.Data.(SharedRecoveryCode).ID
		for i, r := range tv.SharedEntries.RecoveryCodes {
			if r.ID == id {
				tv.SharedEntries.RecoveryCodes = append(tv.SharedEntries.RecoveryCodes[:i], tv.SharedEntries.RecoveryCodes[i+1:]...)
				deleted = true
				break
			}
		}
	case "Banking":
		id := res.Data.(SharedBankingItem).ID
		for i, b := range tv.SharedEntries.BankingItems {
			if b.ID == id {
				tv.SharedEntries.BankingItems = append(tv.SharedEntries.BankingItems[:i], tv.SharedEntries.BankingItems[i+1:]...)
				deleted = true
				break
			}
		}
	case "Document":
		id := res.Data.(SharedDocumentEntry).ID
		for i, d := range tv.SharedEntries.Documents {
			if d.ID == id {
				tv.SharedEntries.Documents = append(tv.SharedEntries.Documents[:i], tv.SharedEntries.Documents[i+1:]...)
				deleted = true
				break
			}
		}
	case "Gov ID":
		id := res.Data.(SharedGovID).ID
		for i, g := range tv.SharedEntries.GovIDs {
			if g.ID == id {
				tv.SharedEntries.GovIDs = append(tv.SharedEntries.GovIDs[:i], tv.SharedEntries.GovIDs[i+1:]...)
				deleted = true
				break
			}
		}
	case "Medical Record":
		id := res.Data.(SharedMedicalRecord).ID
		for i, m := range tv.SharedEntries.MedicalRecords {
			if m.ID == id {
				tv.SharedEntries.MedicalRecords = append(tv.SharedEntries.MedicalRecords[:i], tv.SharedEntries.MedicalRecords[i+1:]...)
				deleted = true
				break
			}
		}
	case "Travel":
		id := res.Data.(SharedTravelDoc).ID
		for i, t := range tv.SharedEntries.TravelDocs {
			if t.ID == id {
				tv.SharedEntries.TravelDocs = append(tv.SharedEntries.TravelDocs[:i], tv.SharedEntries.TravelDocs[i+1:]...)
				deleted = true
				break
			}
		}
	case "Contact":
		id := res.Data.(SharedContact).ID
		for i, c := range tv.SharedEntries.Contacts {
			if c.ID == id {
				tv.SharedEntries.Contacts = append(tv.SharedEntries.Contacts[:i], tv.SharedEntries.Contacts[i+1:]...)
				deleted = true
				break
			}
		}
	case "Cloud Credential":
		id := res.Data.(SharedCloudCredential).ID
		for i, c := range tv.SharedEntries.CloudCredentials {
			if c.ID == id {
				tv.SharedEntries.CloudCredentials = append(tv.SharedEntries.CloudCredentials[:i], tv.SharedEntries.CloudCredentials[i+1:]...)
				deleted = true
				break
			}
		}
	case "K8s Secret":
		id := res.Data.(SharedK8s).ID
		for i, k := range tv.SharedEntries.K8sSecrets {
			if k.ID == id {
				tv.SharedEntries.K8sSecrets = append(tv.SharedEntries.K8sSecrets[:i], tv.SharedEntries.K8sSecrets[i+1:]...)
				deleted = true
				break
			}
		}
	case "Docker Registry":
		id := res.Data.(SharedDockerRegistry).ID
		for i, d := range tv.SharedEntries.DockerRegistries {
			if d.ID == id {
				tv.SharedEntries.DockerRegistries = append(tv.SharedEntries.DockerRegistries[:i], tv.SharedEntries.DockerRegistries[i+1:]...)
				deleted = true
				break
			}
		}
	case "SSH Config":
		id := res.Data.(SharedSSHConfig).ID
		for i, s := range tv.SharedEntries.SSHConfigs {
			if s.ID == id {
				tv.SharedEntries.SSHConfigs = append(tv.SharedEntries.SSHConfigs[:i], tv.SharedEntries.SSHConfigs[i+1:]...)
				deleted = true
				break
			}
		}
	case "CI/CD Secret":
		id := res.Data.(SharedCICD).ID
		for i, c := range tv.SharedEntries.CICDSecrets {
			if c.ID == id {
				tv.SharedEntries.CICDSecrets = append(tv.SharedEntries.CICDSecrets[:i], tv.SharedEntries.CICDSecrets[i+1:]...)
				deleted = true
				break
			}
		}
	case "License Key":
		id := res.Data.(SharedLicenseKey).ID
		for i, l := range tv.SharedEntries.LicenseKeys {
			if l.ID == id {
				tv.SharedEntries.LicenseKeys = append(tv.SharedEntries.LicenseKeys[:i], tv.SharedEntries.LicenseKeys[i+1:]...)
				deleted = true
				break
			}
		}
	case "Legal Contract":
		id := res.Data.(SharedLegalContract).ID
		for i, l := range tv.SharedEntries.LegalContracts {
			if l.ID == id {
				tv.SharedEntries.LegalContracts = append(tv.SharedEntries.LegalContracts[:i], tv.SharedEntries.LegalContracts[i+1:]...)
				deleted = true
				break
			}
		}
	}

	if deleted {
		tv.AddAuditEntry(s.Username, "DELETE", fmt.Sprintf("Deleted %s: %s", res.Type, res.Identifier))
		saveTeamVault(tv)
		color.Green("Entry deleted.\n")
	}
}

func displaySharedEntry(res SearchResult, deptKey []byte) {
	color.Cyan("\n=== %s: %s ===\n", res.Type, res.Identifier)
	switch res.Type {
	case "Password":
		p := res.Data.(SharedPassword)
		dec, _ := DecryptData(p.Password, deptKey)
		fmt.Printf("Username: %s\n", p.Username)
		fmt.Printf("Password: %s\n", string(dec))
		fmt.Printf("URL: %s\n", p.URL)
		fmt.Printf("Sensitive: %v | Global: %v\n", p.IsSensitive, p.IsGlobal)
	case "TOTP":
		t := res.Data.(SharedTOTP)
		dec, _ := DecryptData(t.Secret, deptKey)
		code := generateTOTP(string(dec))
		fmt.Printf("Issuer: %s\n", t.Issuer)
		fmt.Printf("Current Code: %s\n", code)
		fmt.Printf("Sensitive: %v | Global: %v\n", t.IsSensitive, t.IsGlobal)
	case "API Key":
		k := res.Data.(SharedAPIKey)
		dec, _ := DecryptData(k.Key, deptKey)
		fmt.Printf("Service: %s\n", k.Service)
		fmt.Printf("Key: %s\n", string(dec))
		fmt.Printf("Sensitive: %v | Global: %v\n", k.IsSensitive, k.IsGlobal)
	case "Token":
		t := res.Data.(SharedToken)
		dec, _ := DecryptData(t.Token, deptKey)
		fmt.Printf("Type: %s\n", t.Type)
		fmt.Printf("Token: %s\n", string(dec))
		fmt.Printf("Sensitive: %v | Global: %v\n", t.IsSensitive, t.IsGlobal)
	case "Note":
		n := res.Data.(SharedNote)
		dec, _ := DecryptData(n.Content, deptKey)
		fmt.Printf("Content:\n%s\n", string(dec))
		fmt.Printf("Sensitive: %v | Global: %v\n", n.IsSensitive, n.IsGlobal)
	case "SSH Key":
		s := res.Data.(SharedSSHKey)
		dec, _ := DecryptData(s.PrivateKey, deptKey)
		fmt.Printf("Private Key:\n%s\n", string(dec))
		fmt.Printf("Sensitive: %v | Global: %v\n", s.IsSensitive, s.IsGlobal)
	case "Certificate":
		c := res.Data.(SharedCertificate)
		decCert, _ := DecryptData(c.CertData, deptKey)
		fmt.Printf("Issuer: %s\n", c.Issuer)
		fmt.Printf("Expiry: %s\n", c.Expiry.Format("2006-01-02"))
		fmt.Printf("Certificate Data:\n%s\n", string(decCert))
		if len(c.PrivateKey) > 0 {
			decKey, _ := DecryptData(c.PrivateKey, deptKey)
			fmt.Printf("Private Key:\n%s\n", string(decKey))
		}
		fmt.Printf("Sensitive: %v | Global: %v\n", c.IsSensitive, c.IsGlobal)
	case "Wi-Fi":
		w := res.Data.(SharedWiFi)
		dec, _ := DecryptData(w.Password, deptKey)
		fmt.Printf("SSID: %s\n", w.SSID)
		fmt.Printf("Security: %s\n", w.Security)
		fmt.Printf("Password: %s\n", string(dec))
		fmt.Printf("Sensitive: %v | Global: %v\n", w.IsSensitive, w.IsGlobal)
	case "Recovery Code":
		r := res.Data.(SharedRecoveryCode)
		dec, _ := DecryptData(r.Codes, deptKey)
		fmt.Printf("Service: %s\n", r.Service)
		fmt.Printf("Codes:\n%s\n", string(dec))
		fmt.Printf("Sensitive: %v | Global: %v\n", r.IsSensitive, r.IsGlobal)
	case "Banking":
		b := res.Data.(SharedBankingItem)
		decDetails, _ := DecryptData(b.Details, deptKey)
		fmt.Printf("Type: %s\n", b.Type)
		fmt.Printf("Details: %s\n", string(decDetails))
		if len(b.CVV) > 0 {
			decCVV, _ := DecryptData(b.CVV, deptKey)
			fmt.Printf("CVV: %s\n", string(decCVV))
		}
		fmt.Printf("Expiry: %s\n", b.Expiry)
		fmt.Printf("Sensitive: %v | Global: %v\n", b.IsSensitive, b.IsGlobal)
	case "Gov ID":
		g := res.Data.(SharedGovID)
		fmt.Printf("Type: %s\n", g.Type)
		fmt.Printf("ID Number: %s\n", g.IDNumber)
		fmt.Printf("Name: %s\n", g.Name)
		fmt.Printf("Expiry: %s\n", g.Expiry)
		fmt.Printf("Sensitive: %v | Global: %v\n", g.IsSensitive, g.IsGlobal)
	case "Medical Record":
		m := res.Data.(SharedMedicalRecord)
		decPres, _ := DecryptData(m.Prescriptions, deptKey)
		decAll, _ := DecryptData(m.Allergies, deptKey)
		fmt.Printf("Insurance ID: %s\n", m.InsuranceID)
		fmt.Printf("Prescriptions:\n%s\n", string(decPres))
		fmt.Printf("Allergies:\n%s\n", string(decAll))
		fmt.Printf("Sensitive: %v | Global: %v\n", m.IsSensitive, m.IsGlobal)
	case "Travel":
		t := res.Data.(SharedTravelDoc)
		decCode, _ := DecryptData(t.BookingCode, deptKey)
		fmt.Printf("Ticket Number: %s\n", t.TicketNumber)
		fmt.Printf("Booking Code: %s\n", string(decCode))
		fmt.Printf("Loyalty Program: %s\n", t.LoyaltyProgram)
		fmt.Printf("Sensitive: %v | Global: %v\n", t.IsSensitive, t.IsGlobal)
	case "Contact":
		c := res.Data.(SharedContact)
		fmt.Printf("Phone: %s\n", c.Phone)
		fmt.Printf("Email: %s\n", c.Email)
		fmt.Printf("Address: %s\n", c.Address)
		fmt.Printf("Emergency: %v\n", c.Emergency)
		fmt.Printf("Sensitive: %v | Global: %v\n", c.IsSensitive, c.IsGlobal)
	case "Cloud Credential":
		c := res.Data.(SharedCloudCredential)
		decSecret, _ := DecryptData(c.SecretKey, deptKey)
		fmt.Printf("Access Key: %s\n", c.AccessKey)
		fmt.Printf("Secret Key: %s\n", string(decSecret))
		fmt.Printf("Region: %s\n", c.Region)
		fmt.Printf("Account ID: %s\n", c.AccountID)
		fmt.Printf("Role: %s\n", c.Role)
		fmt.Printf("Expiration: %s\n", c.Expiration)
		fmt.Printf("Sensitive: %v | Global: %v\n", c.IsSensitive, c.IsGlobal)
	case "K8s Secret":
		k := res.Data.(SharedK8s)
		fmt.Printf("Cluster URL: %s\n", k.ClusterURL)
		fmt.Printf("Namespace: %s\n", k.K8sNamespace)
		fmt.Printf("Expiration: %s\n", k.Expiration)
		fmt.Printf("Sensitive: %v | Global: %v\n", k.IsSensitive, k.IsGlobal)
	case "Docker Registry":
		d := res.Data.(SharedDockerRegistry)
		decToken, _ := DecryptData(d.Token, deptKey)
		fmt.Printf("Registry URL: %s\n", d.RegistryURL)
		fmt.Printf("Username: %s\n", d.Username)
		fmt.Printf("Token: %s\n", string(decToken))
		fmt.Printf("Sensitive: %v | Global: %v\n", d.IsSensitive, d.IsGlobal)
	case "SSH Config":
		s := res.Data.(SharedSSHConfig)
		decPriv, _ := DecryptData(s.PrivateKey, deptKey)
		fmt.Printf("Alias: %s\n", s.Alias)
		fmt.Printf("Host: %s\n", s.Host)
		fmt.Printf("User: %s\n", s.User)
		fmt.Printf("Port: %s\n", s.Port)
		fmt.Printf("Key Path: %s\n", s.KeyPath)
		fmt.Printf("Private Key:\n%s\n", string(decPriv))
		fmt.Printf("Fingerprint: %s\n", s.Fingerprint)
		fmt.Printf("Sensitive: %v | Global: %v\n", s.IsSensitive, s.IsGlobal)
	case "CI/CD Secret":
		c := res.Data.(SharedCICD)
		decWebhook, _ := DecryptData(c.Webhook, deptKey)
		decEnv, _ := DecryptData(c.EnvVars, deptKey)
		fmt.Printf("Webhook: %s\n", string(decWebhook))
		fmt.Printf("Env Vars:\n%s\n", string(decEnv))
		fmt.Printf("Sensitive: %v | Global: %v\n", c.IsSensitive, c.IsGlobal)
	case "License Key":
		l := res.Data.(SharedLicenseKey)
		decKey, _ := DecryptData(l.SerialKey, deptKey)
		fmt.Printf("Product: %s\n", l.ProductName)
		fmt.Printf("Key: %s\n", string(decKey))
		fmt.Printf("Info: %s\n", l.ActivationInfo)
		fmt.Printf("Expiry: %s\n", l.Expiration)
		fmt.Printf("Sensitive: %v | Global: %v\n", l.IsSensitive, l.IsGlobal)
	case "Legal Contract":
		l := res.Data.(SharedLegalContract)
		decSummary, _ := DecryptData(l.Summary, deptKey)
		fmt.Printf("Parties: %s\n", l.PartiesInvolved)
		fmt.Printf("Signed: %s\n", l.SignedDate)
		fmt.Printf("Summary:\n%s\n", string(decSummary))
		fmt.Printf("Sensitive: %v | Global: %v\n", l.IsSensitive, l.IsGlobal)
	}
	fmt.Println()

	var createdBy, createdAt string
	switch v := res.Data.(type) {
	case SharedPassword:
		createdBy, createdAt = v.CreatedBy, v.CreatedAt.Format("2006-01-02")
	case SharedTOTP:
		createdBy, createdAt = v.CreatedBy, v.CreatedAt.Format("2006-01-02")

	}
	if createdBy != "" {
		fmt.Printf("\nCreated by: %s on %s\n", createdBy, createdAt)
	}
}

func addSharedDocument(tv *TeamVault, s *TeamSession) {
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

	encContent, _ := EncryptData(content, s.DeptKey)
	encDocPass, _ := EncryptData([]byte(docPass), s.DeptKey)

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global (company-wide)? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedDocumentEntry{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("doc_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Name:	name,
		FileName:	filepath.Base(path),
		Content:	encContent,
		Password:	encDocPass,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:	fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:	"Create",
			EntryType:	"Document",
			EntryID:	name,
			NewData:	data,
			RequestedBy:	s.Username,
			RequestedAt:	time.Now(),
			Status:	"Pending",
		})
	} else {
		tv.SharedEntries.Documents = append(tv.SharedEntries.Documents, entry)
		tv.AddAuditEntry(s.Username, "ADD_DOC", "Added shared document: "+name)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func getCurrentUser(tv *TeamVault, s *TeamSession) *TeamUser {
	for i := range tv.Users {
		if tv.Users[i].Username == s.Username {
			return &tv.Users[i]
		}
	}
	return nil
}

func readMultilineInput() string {
	var lines []string
	for {
		line := readInput()
		if line == "" {
			break
		}
		lines = append(lines, line)
	}
	return strings.Join(lines, "\n")
}

func readInput() string {
	input, _ := inputReader.ReadString('\n')
	return strings.TrimSpace(input)
}

func readPassword() (string, error) {
	if !term.IsTerminal(int(syscall.Stdin)) {
		return readInput(), nil
	}
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

func generateTOTP(secret string) string {
	secret = strings.ToUpper(strings.ReplaceAll(secret, " ", ""))
	key, err := base32.StdEncoding.WithPadding(base32.NoPadding).DecodeString(secret)
	if err != nil {
		return "INVALID"
	}

	timestamp := time.Now().Unix() / 30
	buf := make([]byte, 8)
	binary.BigEndian.PutUint64(buf, uint64(timestamp))

	h := hmac.New(sha1.New, key)
	h.Write(buf)
	sum := h.Sum(nil)

	offset := sum[len(sum)-1] & 0xf
	value := int64(((int(sum[offset]) & 0x7f) << 24) |
		((int(sum[offset+1]) & 0xff) << 16) |
		((int(sum[offset+2]) & 0xff) << 8) |
		(int(sum[offset+3]) & 0xff))

	l6 := value % 1000000
	return fmt.Sprintf("%06d", l6)
}

func addSharedGovID(tv *TeamVault, s *TeamSession) {
	fmt.Print("Type (e.g., Driver License): ")
	t := readInput()
	fmt.Print("ID Number: ")
	id := readInput()
	fmt.Print("Name: ")
	name := readInput()
	fmt.Print("Expiry: ")
	expiry := readInput()

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedGovID{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("gvid_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Type:	t,
		IDNumber:	id,
		Name:	name,
		Expiry:	expiry,
	}

	if sensitive && s.Role != RoleAdmin {
		submitForApproval(tv, s, "Gov ID", entry.Name, entry)
	} else {
		tv.SharedEntries.GovIDs = append(tv.SharedEntries.GovIDs, entry)
		tv.AddAuditEntry(s.Username, "ADD_GVID", "Added shared Gov ID: "+name)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedMedicalRecord(tv *TeamVault, s *TeamSession) {
	fmt.Print("Label: ")
	label := readInput()
	fmt.Print("Insurance ID: ")
	insID := readInput()
	fmt.Println("Enter Prescriptions (end with empty line):")
	prescriptions := readMultilineInput()
	fmt.Println("Enter Allergies (end with empty line):")
	allergies := readMultilineInput()

	encPres, _ := EncryptData([]byte(prescriptions), s.DeptKey)
	encAll, _ := EncryptData([]byte(allergies), s.DeptKey)

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedMedicalRecord{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("med_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Label:	label,
		InsuranceID:	insID,
		Prescriptions:	encPres,
		Allergies:	encAll,
	}

	if sensitive && s.Role != RoleAdmin {
		submitForApproval(tv, s, "Medical Record", label, entry)
	} else {
		tv.SharedEntries.MedicalRecords = append(tv.SharedEntries.MedicalRecords, entry)
		tv.AddAuditEntry(s.Username, "ADD_MED", "Added shared medical record: "+label)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedTravelDoc(tv *TeamVault, s *TeamSession) {
	fmt.Print("Label: ")
	label := readInput()
	fmt.Print("Ticket Number: ")
	ticket := readInput()
	fmt.Print("Booking Code: ")
	code := readInput()
	fmt.Print("Loyalty Program: ")
	loyalty := readInput()

	encCode, _ := EncryptData([]byte(code), s.DeptKey)

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedTravelDoc{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("trv_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Label:	label,
		TicketNumber:	ticket,
		BookingCode:	encCode,
		LoyaltyProgram:	loyalty,
	}

	if sensitive && s.Role != RoleAdmin {
		submitForApproval(tv, s, "Travel", label, entry)
	} else {
		tv.SharedEntries.TravelDocs = append(tv.SharedEntries.TravelDocs, entry)
		tv.AddAuditEntry(s.Username, "ADD_TRV", "Added shared travel document: "+label)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedContact(tv *TeamVault, s *TeamSession) {
	fmt.Print("Name: ")
	name := readInput()
	fmt.Print("Phone: ")
	phone := readInput()
	fmt.Print("Email: ")
	email := readInput()
	fmt.Print("Address: ")
	addr := readInput()
	fmt.Print("Is this an emergency contact? (y/N): ")
	emergency := strings.ToLower(readInput()) == "y"

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedContact{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("con_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Name:	name,
		Phone:	phone,
		Email:	email,
		Address:	addr,
		Emergency:	emergency,
	}

	if sensitive && s.Role != RoleAdmin {
		submitForApproval(tv, s, "Contact", name, entry)
	} else {
		tv.SharedEntries.Contacts = append(tv.SharedEntries.Contacts, entry)
		tv.AddAuditEntry(s.Username, "ADD_CON", "Added shared contact: "+name)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedCloudCredential(tv *TeamVault, s *TeamSession) {
	fmt.Print("Label: ")
	label := readInput()
	fmt.Print("Access Key: ")
	access := readInput()
	fmt.Print("Secret Key: ")
	secret := readInput()
	fmt.Print("Region: ")
	region := readInput()
	fmt.Print("Account ID: ")
	accID := readInput()
	fmt.Print("Role: ")
	role := readInput()
	fmt.Print("Expiration: ")
	expiration := readInput()

	encSecret, _ := EncryptData([]byte(secret), s.DeptKey)

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedCloudCredential{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("cloud_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Label:	label,
		AccessKey:	access,
		SecretKey:	encSecret,
		Region:	region,
		AccountID:	accID,
		Role:	role,
		Expiration:	expiration,
	}

	if sensitive && s.Role != RoleAdmin {
		submitForApproval(tv, s, "Cloud Credential", label, entry)
	} else {
		tv.SharedEntries.CloudCredentials = append(tv.SharedEntries.CloudCredentials, entry)
		tv.AddAuditEntry(s.Username, "ADD_CLOUD", "Added shared cloud credential: "+label)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedK8s(tv *TeamVault, s *TeamSession) {
	fmt.Print("Name: ")
	name := readInput()
	fmt.Print("Cluster URL: ")
	url := readInput()
	fmt.Print("K8s Namespace: ")
	k8sNs := readInput()
	fmt.Print("Expiration: ")
	expiration := readInput()

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedK8s{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("k8s_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Name:	name,
		ClusterURL:	url,
		K8sNamespace:	k8sNs,
		Expiration:	expiration,
	}

	if sensitive && s.Role != RoleAdmin {
		submitForApproval(tv, s, "K8s Secret", name, entry)
	} else {
		tv.SharedEntries.K8sSecrets = append(tv.SharedEntries.K8sSecrets, entry)
		tv.AddAuditEntry(s.Username, "ADD_K8S", "Added shared K8s secret: "+name)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedDockerRegistry(tv *TeamVault, s *TeamSession) {
	fmt.Print("Name: ")
	name := readInput()
	fmt.Print("Registry URL: ")
	url := readInput()
	fmt.Print("Username: ")
	username := readInput()
	fmt.Print("Token: ")
	token := readInput()

	encToken, _ := EncryptData([]byte(token), s.DeptKey)

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedDockerRegistry{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("dock_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Name:	name,
		RegistryURL:	url,
		Username:	username,
		Token:	encToken,
	}

	if sensitive && s.Role != RoleAdmin {
		submitForApproval(tv, s, "Docker Registry", name, entry)
	} else {
		tv.SharedEntries.DockerRegistries = append(tv.SharedEntries.DockerRegistries, entry)
		tv.AddAuditEntry(s.Username, "ADD_DOCKER", "Added shared Docker registry: "+name)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedSSHConfig(tv *TeamVault, s *TeamSession) {
	fmt.Print("Alias: ")
	alias := readInput()
	fmt.Print("Host: ")
	host := readInput()
	fmt.Print("User: ")
	user := readInput()
	fmt.Print("Port: ")
	port := readInput()
	fmt.Print("Key Path: ")
	keyPath := readInput()
	fmt.Println("Enter Private Key (end with empty line):")
	privKey := readMultilineInput()
	fmt.Print("Fingerprint: ")
	fingerprint := readInput()

	encPriv, _ := EncryptData([]byte(privKey), s.DeptKey)

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedSSHConfig{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("sshc_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Alias:	alias,
		Host:	host,
		User:	user,
		Port:	port,
		KeyPath:	keyPath,
		PrivateKey:	encPriv,
		Fingerprint:	fingerprint,
	}

	if sensitive && s.Role != RoleAdmin {
		submitForApproval(tv, s, "SSH Config", alias, entry)
	} else {
		tv.SharedEntries.SSHConfigs = append(tv.SharedEntries.SSHConfigs, entry)
		tv.AddAuditEntry(s.Username, "ADD_SSH_CONFIG", "Added shared SSH config: "+alias)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedCICD(tv *TeamVault, s *TeamSession) {
	fmt.Print("Name: ")
	name := readInput()
	fmt.Print("Webhook URL: ")
	webhook := readInput()
	fmt.Println("Enter Env Vars (end with empty line):")
	envVars := readMultilineInput()

	encWebhook, _ := EncryptData([]byte(webhook), s.DeptKey)
	encEnv, _ := EncryptData([]byte(envVars), s.DeptKey)

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedCICD{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("cicd_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Name:	name,
		Webhook:	encWebhook,
		EnvVars:	encEnv,
	}

	if sensitive && s.Role != RoleAdmin {
		submitForApproval(tv, s, "CI/CD Secret", name, entry)
	} else {
		tv.SharedEntries.CICDSecrets = append(tv.SharedEntries.CICDSecrets, entry)
		tv.AddAuditEntry(s.Username, "ADD_CICD", "Added shared CI/CD secret: "+name)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedLicenseKey(tv *TeamVault, s *TeamSession) {
	fmt.Print("Product Name: ")
	name := readInput()
	fmt.Print("Serial Key: ")
	key := readInput()
	fmt.Print("Activation Info: ")
	info := readInput()
	fmt.Print("Expiration: ")
	expiry := readInput()

	encKey, _ := EncryptData([]byte(key), s.DeptKey)

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedLicenseKey{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("lic_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		ProductName:	name,
		SerialKey:	encKey,
		ActivationInfo:	info,
		Expiration:	expiry,
	}

	if sensitive && s.Role != RoleAdmin {
		submitForApproval(tv, s, "License Key", name, entry)
	} else {
		tv.SharedEntries.LicenseKeys = append(tv.SharedEntries.LicenseKeys, entry)
		tv.AddAuditEntry(s.Username, "ADD_LICENSE", "Added shared license key: "+name)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func addSharedLegalContract(tv *TeamVault, s *TeamSession) {
	fmt.Print("Contract Name: ")
	name := readInput()
	fmt.Println("Enter Summary (end with empty line):")
	summary := readMultilineInput()
	fmt.Print("Parties Involved: ")
	parties := readInput()
	fmt.Print("Signed Date: ")
	signed := readInput()

	encSummary, _ := EncryptData([]byte(summary), s.DeptKey)

	fmt.Print("Make this entry sensitive? (y/N): ")
	sensitive := strings.ToLower(readInput()) == "y"
	fmt.Print("Make this entry global? (y/N): ")
	global := strings.ToLower(readInput()) == "y"

	entry := SharedLegalContract{
		EntryMetadata: EntryMetadata{
			ID:	fmt.Sprintf("leg_%d", time.Now().Unix()),
			DepartmentID:	s.ActiveDeptID,
			CreatedBy:	s.Username,
			CreatedAt:	time.Now(),
			IsSensitive:	sensitive,
			IsGlobal:	global,
		},
		Name:	name,
		Summary:	encSummary,
		PartiesInvolved:	parties,
		SignedDate:	signed,
	}

	if sensitive && s.Role != RoleAdmin {
		submitForApproval(tv, s, "Legal Contract", name, entry)
	} else {
		tv.SharedEntries.LegalContracts = append(tv.SharedEntries.LegalContracts, entry)
		tv.AddAuditEntry(s.Username, "ADD_LEGAL", "Added shared legal contract: "+name)
	}
	saveTeamVault(tv)
	color.Green("Done.\n")
}

func submitForApproval(tv *TeamVault, s *TeamSession, entryType, entryID string, data interface{}) {
	color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
	jsonData, _ := json.Marshal(data)
	tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
		ID:	fmt.Sprintf("req_%d", time.Now().Unix()),
		Type:	"Create",
		EntryType:	entryType,
		EntryID:	entryID,
		NewData:	jsonData,
		RequestedBy:	s.Username,
		RequestedAt:	time.Now(),
		Status:	"Pending",
	})
}

type ScoredSharedResult struct {
	Result	SearchResult
	Score	int
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

func performSharedSearch(v *TeamVault, query, deptID string, isAdmin bool) []SearchResult {
	all := v.SearchAll("", deptID, isAdmin)
	var scored []ScoredSharedResult
	for _, r := range all {
		score := rankMatch(query, r.Identifier)
		if score > 0 {
			scored = append(scored, ScoredSharedResult{r, score})
		}
	}
	sort.Slice(scored, func(i, j int) bool {
		if scored[i].Score == scored[j].Score {
			return scored[i].Result.Identifier < scored[j].Result.Identifier
		}
		return scored[i].Score > scored[j].Score
	})

	var out []SearchResult
	for _, s := range scored {
		out = append(out, s.Result)
	}
	return out
}

func handleInteractiveSharedEntries(tv *TeamVault, s *TeamSession, initialQuery string) {
	query := initialQuery
	selectedIndex := 0

	if !term.IsTerminal(int(os.Stdin.Fd())) {
		results := performSharedSearch(tv, query, s.ActiveDeptID, s.Role == RoleAdmin)
		if len(results) == 0 {
			fmt.Println("No matching entries found.")
			return
		}
		if len(results) == 1 {
			displaySharedEntry(results[0], s.DeptKey)
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

	for {
		results := performSharedSearch(tv, query, s.ActiveDeptID, s.Role == RoleAdmin)
		if len(results) > 0 {
			if selectedIndex >= len(results) {
				selectedIndex = len(results) - 1
			}
		} else {
			selectedIndex = 0
		}

		fmt.Print("\033[H\033[2J")
		fmt.Printf("\x1b[1;36mAPM Team Search & Manage\x1b[0m | Dept ID: \x1b[1;32m%s\x1b[0m\n", s.ActiveDeptID)
		fmt.Printf("\x1b[1;33mQuery:\x1b[0m %s\x1b[5m_\x1b[0m\n", query)
		fmt.Println("--------------------------------------------------")

		displayLimit := 20
		for i := 0; i < len(results) && i < displayLimit; i++ {
			r := results[i]
			line := fmt.Sprintf("[%d] %-30s (%s)", i+1, r.Identifier, r.Type)
			if i == selectedIndex {
				fmt.Printf("\x1b[1;7m %s \x1b[0m\n", line)
			} else {
				fmt.Printf(" %s \n", line)
			}
		}

		if len(results) == 0 {
			fmt.Println(" (No entries found)")
		}

		fmt.Println("\n--------------------------------------------------------------")
		fmt.Println("\x1b[1;37mArrows\x1b[0m: Navigate | \x1b[1;37mEnter\x1b[0m: View | \x1b[1;37md\x1b[0m: Delete | \x1b[1;37mEsc\x1b[0m: Exit")

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
				break
			}
			continue
		}

		if b[0] == 3 || b[0] == 4 {
			break
		}

		if b[0] == 127 || b[0] == 8 {
			if len(query) > 0 {
				query = query[:len(query)-1]
				selectedIndex = 0
			}
			continue
		}

		if b[0] == '\r' || b[0] == '\n' {
			if len(results) > 0 {
				handleSharedAction(tv, s, results[selectedIndex], 'v', oldState)
			}
			continue
		}

		if b[0] == 'd' {
			if len(results) > 0 {
				handleSharedAction(tv, s, results[selectedIndex], 'd', oldState)
			}
			continue
		}

		char := rune(b[0])
		if unicode.IsPrint(char) {
			query += string(char)
			selectedIndex = 0
		}
	}
}

func handleSharedAction(tv *TeamVault, s *TeamSession, res SearchResult, action byte, oldState *term.State) {
	_ = term.Restore(int(os.Stdin.Fd()), oldState)
	fmt.Print("\033[H\033[2J")

	switch action {
	case 'v':
		displaySharedEntry(res, s.DeptKey)
		fmt.Print("\nPress Enter to continue...")
		readInput()
	case 'd':
		deleteSharedEntry(tv, s, res)
		fmt.Print("\nPress Enter to continue...")
		readInput()
	}

	newState, _ := term.MakeRaw(int(os.Stdin.Fd()))
	if newState != nil {
		*oldState = *newState
	}
}
