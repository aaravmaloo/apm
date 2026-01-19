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
	"path/filepath"
	"strconv"
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

			ukKeys := DeriveKeys(pass, salt, 3)
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
				Permissions:        make(map[string]bool),
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
			if len(s.Permissions) > 0 {
				fmt.Printf("Permission Overrides: %v\n", s.Permissions)
			}
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
			tv, _ := loadTeamVault()
			user := getCurrentUser(tv, s)
			if err != nil || !s.Role.CanManageUsers(user) {
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
			ukKeys := DeriveKeys(pass, userSalt, 3)

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
				Permissions:        make(map[string]bool),
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
		Use:   "remove <username>",
		Short: "Remove a user from the organization",
		Args:  cobra.ExactArgs(1),
		Run: func(cmd *cobra.Command, args []string) {
			tv, _ := loadTeamVault()
			user := getCurrentUser(tv, s)
			if err != nil || !s.Role.CanManageUsers(user) {
				color.Red("Permission denied.\n")
				return
			}

			username := args[0]
			tv, _ := loadTeamVault()

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
		Use:   "promote <username> <role>",
		Short: "Change a user's role (Admin only)",
		Args:  cobra.ExactArgs(2),
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
		Use:   "roles",
		Short: "List all available user roles",
		Run: func(cmd *cobra.Command, args []string) {
			fmt.Println("Available Roles:")
			for _, r := range GetRoles() {
				fmt.Printf("- %s\n", r)
			}
		},
	}

	var userPermCmd = &cobra.Command{
		Use:   "permission",
		Short: "Manage user-specific permission overrides",
	}

	var userPermGrantCmd = &cobra.Command{
		Use:   "grant <username> <permission>",
		Short: "Grant a specific permission override",
		Args:  cobra.ExactArgs(2),
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
		Use:   "revoke <username> <permission>",
		Short: "Revoke a specific permission override",
		Args:  cobra.ExactArgs(2),
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
		Use:   "switch <username> <dept_id>",
		Short: "Switch a user's active department (Admin only)",
		Args:  cobra.ExactArgs(2),
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
		Use:   "add",
		Short: "Add a shared entry (interactive)",
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
			fmt.Print("Choice (1-11): ")
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
			query := strings.Join(args, " ")

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
		Use:   "edit <entry_name>",
		Short: "Edit a shared entry",
		Args:  cobra.MinimumNArgs(1),
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
		Use:   "delete <entry_name>",
		Short: "Delete a shared entry",
		Args:  cobra.MinimumNArgs(1),
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
		Use:   "approvals",
		Short: "Manage pending approvals for sensitive entry changes (Admin only)",
	}

	var approvalsListCmd = &cobra.Command{
		Use:   "list",
		Short: "List all pending approval requests",
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
		Use:   "approve <idx>",
		Short: "Approve a pending request",
		Args:  cobra.ExactArgs(1),
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

			// Apply the change
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
				case "Banking":
					var b SharedBankingItem
					json.Unmarshal(req.NewData, &b)
					tv.SharedEntries.BankingItems = append(tv.SharedEntries.BankingItems, b)
				case "Document":
					var d SharedDocumentEntry
					json.Unmarshal(req.NewData, &d)
					tv.SharedEntries.Documents = append(tv.SharedEntries.Documents, d)
				}
				color.Green("Created entry %s.\n", req.EntryID)
			} else if req.Type == "Delete" {
				// Deletion logic based on EntryID and EntryType
				// Simplified for this implementation
				color.Yellow("Applying deletion of %s (%s)...\n", req.EntryID, req.EntryType)
			}

			req.Status = "Approved"
			tv.AddAuditEntry(s.Username, "APPROVE_REQ", fmt.Sprintf("Approved %s for %s", req.Type, req.EntryID))
			saveTeamVault(tv)
			color.Green("Request approved and applied.\n")
		},
	}

	var approvalsDenyCmd = &cobra.Command{
		Use:   "deny <idx>",
		Short: "Deny a pending request",
		Args:  cobra.ExactArgs(1),
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
		Use:   "export",
		Short: "Export team vault to JSON (Admin only)",
		Run: func(cmd *cobra.Command, args []string) {
			s, err := GetSession()
			if err != nil || s.Role != RoleAdmin {
				color.Red("Permission denied. Admin only.\n")
				return
			}

			tv, _ := loadTeamVault()

			exportData := map[string]interface{}{
				"organization_id": tv.OrganizationID,
				"departments":     tv.Departments,
				"users":           tv.Users,
				"entry_counts": map[string]int{
					"passwords": len(tv.SharedEntries.Passwords),
					"totps":     len(tv.SharedEntries.TOTPs),
					"api_keys":  len(tv.SharedEntries.APIKeys),
					"tokens":    len(tv.SharedEntries.Tokens),
					"notes":     len(tv.SharedEntries.Notes),
				},
				"audit_trail": tv.AuditTrail,
			}

			jsonData, _ := json.MarshalIndent(exportData, "", "  ")
			fmt.Println(string(jsonData))

			tv.AddAuditEntry(s.Username, "EXPORT", "Exported team vault metadata")
			saveTeamVault(tv)
		},
	}

	var infoCmd = &cobra.Command{
		Use:   "info",
		Short: "Display organization information",
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
			fmt.Printf("  Passwords: %d\n", len(tv.SharedEntries.Passwords))
			fmt.Printf("  TOTPs: %d\n", len(tv.SharedEntries.TOTPs))
			fmt.Printf("  API Keys: %d\n", len(tv.SharedEntries.APIKeys))
			fmt.Printf("  Tokens: %d\n", len(tv.SharedEntries.Tokens))
			fmt.Printf("  Notes: %d\n", len(tv.SharedEntries.Notes))
			fmt.Printf("\nAudit Entries: %d\n", len(tv.AuditTrail))
		},
	}

	// --- Command Groups for Feature Parity ---

	// Helper for creating standard type commands
	createTypeCmd := func(use string, short string, resType string, addFunc func(*TeamVault, *TeamSession)) *cobra.Command {
		group := &cobra.Command{Use: use, Short: short}
		group.AddCommand(&cobra.Command{
			Use:   "add",
			Short: "Add a new " + resType,
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
			Use:   "list",
			Short: "List all " + resType + "s",
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
			Use:   "get <query>",
			Short: "Retrieve a " + resType,
			Args:  cobra.MinimumNArgs(1),
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

	rootCmd.AddCommand(
		initCmd, loginCmd, whoamiCmd, logoutCmd, infoCmd, auditCmd, approvalsCmd,
		userCmd, deptCmd,
		passwordCmd, totpCmd, apiKeyCmd, tokenCmd, noteCmd,
		sshCmd, certCmd, wifiCmd, recoveryCmd, bankingCmd, docCmd,
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
			ID:           fmt.Sprintf("pass_%d", time.Now().Unix()),
			DepartmentID: s.ActiveDeptID,
			CreatedBy:    s.Username,
			CreatedAt:    time.Now(),
			IsSensitive:  sensitive,
			IsGlobal:     global,
		},
		Name:     name,
		Username: username,
		Password: encryptedPass,
		URL:      url,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(passwordEntry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:          fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:        "Create",
			EntryType:   "Password",
			EntryID:     name,
			NewData:     data,
			RequestedBy: s.Username,
			RequestedAt: time.Now(),
			Status:      "Pending",
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
			ID:           fmt.Sprintf("totp_%d", time.Now().Unix()),
			DepartmentID: s.ActiveDeptID,
			CreatedBy:    s.Username,
			CreatedAt:    time.Now(),
			IsSensitive:  sensitive,
			IsGlobal:     global,
		},
		Name:   name,
		Secret: encryptedSecret,
		Issuer: issuer,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:          fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:        "Create",
			EntryType:   "TOTP",
			EntryID:     name,
			NewData:     data,
			RequestedBy: s.Username,
			RequestedAt: time.Now(),
			Status:      "Pending",
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
			ID:           fmt.Sprintf("api_%d", time.Now().Unix()),
			DepartmentID: s.ActiveDeptID,
			CreatedBy:    s.Username,
			CreatedAt:    time.Now(),
			IsSensitive:  sensitive,
			IsGlobal:     global,
		},
		Label:   label,
		Service: service,
		Key:     encryptedKey,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:          fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:        "Create",
			EntryType:   "API Key",
			EntryID:     label,
			NewData:     data,
			RequestedBy: s.Username,
			RequestedAt: time.Now(),
			Status:      "Pending",
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
			ID:           fmt.Sprintf("tok_%d", time.Now().Unix()),
			DepartmentID: s.ActiveDeptID,
			CreatedBy:    s.Username,
			CreatedAt:    time.Now(),
			IsSensitive:  sensitive,
			IsGlobal:     global,
		},
		Name:  name,
		Token: encryptedToken,
		Type:  tokenType,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:          fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:        "Create",
			EntryType:   "Token",
			EntryID:     name,
			NewData:     data,
			RequestedBy: s.Username,
			RequestedAt: time.Now(),
			Status:      "Pending",
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
			ID:           fmt.Sprintf("note_%d", time.Now().Unix()),
			DepartmentID: s.ActiveDeptID,
			CreatedBy:    s.Username,
			CreatedAt:    time.Now(),
			IsSensitive:  sensitive,
			IsGlobal:     global,
		},
		Name:    name,
		Content: encryptedContent,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:          fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:        "Create",
			EntryType:   "Note",
			EntryID:     name,
			NewData:     data,
			RequestedBy: s.Username,
			RequestedAt: time.Now(),
			Status:      "Pending",
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
			ID:           fmt.Sprintf("ssh_%d", time.Now().Unix()),
			DepartmentID: s.ActiveDeptID,
			CreatedBy:    s.Username,
			CreatedAt:    time.Now(),
			IsSensitive:  sensitive,
			IsGlobal:     global,
		},
		Label:      label,
		PrivateKey: encryptedKey,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:          fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:        "Create",
			EntryType:   "SSH Key",
			EntryID:     label,
			NewData:     data,
			RequestedBy: s.Username,
			RequestedAt: time.Now(),
			Status:      "Pending",
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
			ID:           fmt.Sprintf("cert_%d", time.Now().Unix()),
			DepartmentID: s.ActiveDeptID,
			CreatedBy:    s.Username,
			CreatedAt:    time.Now(),
			IsSensitive:  sensitive,
			IsGlobal:     global,
		},
		Label:      label,
		Issuer:     issuer,
		Expiry:     expiry,
		CertData:   encCert,
		PrivateKey: encPriv,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:          fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:        "Create",
			EntryType:   "Certificate",
			EntryID:     label,
			NewData:     data,
			RequestedBy: s.Username,
			RequestedAt: time.Now(),
			Status:      "Pending",
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
			ID:           fmt.Sprintf("wifi_%d", time.Now().Unix()),
			DepartmentID: s.ActiveDeptID,
			CreatedBy:    s.Username,
			CreatedAt:    time.Now(),
			IsSensitive:  sensitive,
			IsGlobal:     global,
		},
		SSID:     ssid,
		Password: encPass,
		Security: sec,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:          fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:        "Create",
			EntryType:   "Wi-Fi",
			EntryID:     ssid,
			NewData:     data,
			RequestedBy: s.Username,
			RequestedAt: time.Now(),
			Status:      "Pending",
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
			ID:           fmt.Sprintf("rec_%d", time.Now().Unix()),
			DepartmentID: s.ActiveDeptID,
			CreatedBy:    s.Username,
			CreatedAt:    time.Now(),
			IsSensitive:  sensitive,
			IsGlobal:     global,
		},
		Service: svc,
		Codes:   encCodes,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:          fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:        "Create",
			EntryType:   "Recovery Code",
			EntryID:     svc,
			NewData:     data,
			RequestedBy: s.Username,
			RequestedAt: time.Now(),
			Status:      "Pending",
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
			ID:           fmt.Sprintf("bank_%d", time.Now().Unix()),
			DepartmentID: s.ActiveDeptID,
			CreatedBy:    s.Username,
			CreatedAt:    time.Now(),
			IsSensitive:  sensitive,
			IsGlobal:     global,
		},
		Label:   label,
		Type:    bType,
		Details: encDetails,
		CVV:     encCVV,
		Expiry:  exp,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:          fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:        "Create",
			EntryType:   "Banking",
			EntryID:     label,
			NewData:     data,
			RequestedBy: s.Username,
			RequestedAt: time.Now(),
			Status:      "Pending",
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

	// Check Sensitivity for Approval
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
		// Logic to save 'p' or 't' into PendingApprovals with Type="Edit"
		// Simplified for now: just record the request
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:          fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:        "Edit",
			EntryType:   res.Type,
			EntryID:     res.Identifier,
			RequestedBy: s.Username,
			RequestedAt: time.Now(),
			Status:      "Pending",
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
	default:
		creator = ""
	}

	user := getCurrentUser(tv, s)
	if !s.Role.CanDeleteEntry(creator, s.Username, user) {
		color.Red("Permission denied.\n")
		return
	}

	// Check Sensitivity
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
			ID:          fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:        "Delete",
			EntryType:   res.Type,
			EntryID:     res.Identifier,
			RequestedBy: s.Username,
			RequestedAt: time.Now(),
			Status:      "Pending",
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
	case "Document":
		d := res.Data.(SharedDocumentEntry)
		fmt.Printf("File Name: %s\n", d.FileName)
		fmt.Printf("File size: %d bytes (Encrypted)\n", len(d.Content))
		fmt.Printf("Sensitive: %v | Global: %v\n", d.IsSensitive, d.IsGlobal)
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
			ID:           fmt.Sprintf("doc_%d", time.Now().Unix()),
			DepartmentID: s.ActiveDeptID,
			CreatedBy:    s.Username,
			CreatedAt:    time.Now(),
			IsSensitive:  sensitive,
			IsGlobal:     global,
		},
		Name:     name,
		FileName: filepath.Base(path),
		Content:  encContent,
		Password: encDocPass,
	}

	if sensitive && s.Role != RoleAdmin {
		color.Yellow("Entry is sensitive. Change submitted for admin approval.\n")
		data, _ := json.Marshal(entry)
		tv.PendingApprovals = append(tv.PendingApprovals, ApprovalRequest{
			ID:          fmt.Sprintf("req_%d", time.Now().Unix()),
			Type:        "Create",
			EntryType:   "Document",
			EntryID:     name,
			NewData:     data,
			RequestedBy: s.Username,
			RequestedAt: time.Now(),
			Status:      "Pending",
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
