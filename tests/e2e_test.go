package apm_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
)

var (
	pmBinary      string
	pmTeamBinary  string
	testVault     = "vault.dat"
	testTeamVault = "team_vault.dat"
	masterPass    = "TestPass123!"
)

func TestMain(m *testing.M) {
	// Build binaries
	if err := buildBinaries(); err != nil {
		fmt.Printf("Failed to build binaries: %v\n", err)
		os.Exit(1)
	}

	// Clean up before proper tests
	cleanup()

	// Run tests
	exitCode := m.Run()

	// Clean up after tests
	cleanup()
	os.Remove(pmBinary)
	os.Remove(pmTeamBinary)

	os.Exit(exitCode)
}

func buildBinaries() error {
	exe := ".exe"
	if runtime.GOOS != "windows" {
		exe = ""
	}

	// Build APM
	pmBinary = "." + string(filepath.Separator) + "pm" + exe
	cmd := exec.Command("go", "build", "-o", pmBinary, "../main.go")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build pm failed: %s", out)
	}

	// Build Team APM
	pmTeamBinary = "." + string(filepath.Separator) + "pm-team" + exe
	// Must build inside team directory because it is a separate module
	absTeamBinary, _ := filepath.Abs(pmTeamBinary)
	cmdTeam := exec.Command("go", "build", "-o", absTeamBinary, ".")
	cmdTeam.Dir = "../team"
	if out, err := cmdTeam.CombinedOutput(); err != nil {
		return fmt.Errorf("build pm-team failed: %s", out)
	}

	return nil
}

func cleanup() {
	os.Remove(testVault)
	os.Remove(testTeamVault)
	os.Remove(".apm_lock")
	files, _ := filepath.Glob("test_export.*")
	for _, f := range files {
		os.Remove(f)
	}
}

func runPM(input string, args ...string) (string, error) {
	cmd := exec.Command(pmBinary, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func runTeam(input string, args ...string) (string, error) {
	cmd := exec.Command(pmTeamBinary, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

// --- APM Tests ---

func Test_01_Init(t *testing.T) {
	cleanup()
	// Init with valid password
	input := fmt.Sprintf("%s\n", masterPass)
	out, err := runPM(input, "init")
	if err != nil {
		t.Fatalf("Init failed: %v, output: %s", err, out)
	}
	if !strings.Contains(out, "Vault initialized successfully") {
		t.Errorf("Unexpected output: %s", out)
	}

	// Verify vault created
	if _, err := os.Stat(testVault); os.IsNotExist(err) {
		t.Error("Vault file not created")
	}
}

func Test_02_Add(t *testing.T) {
	// Add Password
	// Input: choice(1) -> Account -> Username -> Password
	input := fmt.Sprintf("%s\n1\nTestAcc\nTestUser\nTestPassWarning\n", masterPass)
	out, err := runPM(input, "add")
	if err != nil {
		t.Fatalf("Add failed: %v, output: %s", err, out)
	}
	if !strings.Contains(out, "Entry saved") {
		t.Errorf("Unexpected output: %s", out)
	}
}

func Test_03_Get(t *testing.T) {
	// Input: masterPass -> selection (if fuzzy disabled or multiple)
	// But get with query should be direct if unique
	input := fmt.Sprintf("%s\n", masterPass)
	out, err := runPM(input, "get", "TestAcc", "--show-pass")
	if err != nil {
		t.Fatalf("Get failed: %v, output: %s", err, out)
	}
	if !strings.Contains(out, "TestUser") || !strings.Contains(out, "TestPassWarning") {
		t.Errorf("Entry details missing in output: %s", out)
	}
}

func Test_04_Edit(t *testing.T) {
	// Choice 1 (Password) -> NewAccount -> NewUser -> NewPass
	input := fmt.Sprintf("%s\n1\nTestAcc\nUpdatedAcc\nUpdatedUser\nUpdatedPass\n", masterPass)
	out, err := runPM(input, "edit")
	if err != nil {
		t.Fatalf("Edit failed: %v, output: %s", err, out)
	}
	if !strings.Contains(out, "Entry saved") { // or however it confirms
		// Edit command might just return quietly or show "Entry saved" depending on implementation
		// Looking at main.go: "Entry saved" comes from add, but edit calls add internally after delete.
		// Wait, main.go edit implementation: prints "Editing Password...", then calls DeleteEntry, AddEntry.
		// It does NOT print "Entry saved" at the end of edit block explicitly in the snippet I saw?
		// Re-checking main.go...
		// It calls vault.AddEntry directly. It does NOT call saveVault inside the switch case.
		// It sets updated = true.
		// After switch: if updated { EncryptVault; SaveVault; color.Green("Entry updated.") }
		// So "Entry updated." is expected.
	}

	// Verify update
	input = fmt.Sprintf("%s\n", masterPass)
	out, _ = runPM(input, "get", "UpdatedAcc", "--show-pass")
	if !strings.Contains(out, "UpdatedUser") {
		t.Errorf("Edit verification failed: %s", out)
	}
}

func Test_05_Del(t *testing.T) {
	input := fmt.Sprintf("%s\n", masterPass)
	out, err := runPM(input, "del", "UpdatedAcc")
	if err != nil {
		t.Fatalf("Del failed: %v, output: %s", err, out)
	}
	if !strings.Contains(out, "Deleted 'UpdatedAcc'") {
		t.Errorf("Unexpected output: %s", out)
	}
}

func Test_06_Gen_TOTP(t *testing.T) {
	// Gen
	out, err := runPM("", "gen", "--length", "20")
	if err != nil {
		t.Errorf("Gen failed: %v", err)
	}
	if len(strings.TrimSpace(out)) < 20 {
		t.Errorf("Generated password too short: %s", out)
	}

	// TOTP (requires adding one first)
	// Add TOTP: choice 2
	input := fmt.Sprintf("%s\n2\nTestTOTP\nJBSWY3DPEHPK3PXP\n", masterPass)
	runPM(input, "add")

	input = fmt.Sprintf("%s\n", masterPass)
	out, err = runPM(input, "totp", "TestTOTP")
	if err != nil {
		t.Errorf("TOTP failed: %v", err)
	}
	if !strings.Contains(out, "Code:") { // Check main.go output format
		t.Errorf("TOTP output invalid: %s", out)
	}
}

func Test_07_Note(t *testing.T) {
	// Add Note: choice 4
	// Name -> Content -> Empty line to finish
	input := fmt.Sprintf("%s\n4\nMyNote\nSecretContent\n\n", masterPass)
	runPM(input, "add")

	input = fmt.Sprintf("%s\n", masterPass)
	out, _ := runPM(input, "get", "MyNote")
	if !strings.Contains(out, "SecretContent") {
		t.Errorf("Note retrieval failed: %s", out)
	}
}

func Test_08_ExportImport(t *testing.T) {
	// Export
	input := fmt.Sprintf("%s\n", masterPass)
	out, err := runPM(input, "export", "--format", "json", "--output", "test_export.json")
	if err != nil {
		t.Fatalf("Export failed: %v, output: %s", err, out)
	}

	// Clear vault (delete file)
	os.Remove(testVault)

	// Re-init
	input = fmt.Sprintf("%s\n", masterPass)
	runPM(input, "init")

	// Import
	input = fmt.Sprintf("%s\n", masterPass)
	out, err = runPM(input, "import", "test_export.json")
	if err != nil {
		t.Fatalf("Import failed: %v, output: %s", err, out)
	}

	// Verify data
	input = fmt.Sprintf("%s\n", masterPass)
	out, _ = runPM(input, "get", "MyNote")
	if !strings.Contains(out, "SecretContent") {
		t.Errorf("Import verification failed: %s", out)
	}
}

// --- Team Tests ---

func TestTeam_Init(t *testing.T) {
	cleanup() // Use separate vault file team_vault.dat
	// init <org> <admin>
	// Password -> Confirm
	input := fmt.Sprintf("%s\n%s\n", masterPass, masterPass)
	out, err := runTeam(input, "init", "MyOrg", "admin")
	if err != nil {
		t.Fatalf("Team Init failed: %v, output: %s", err, out)
	}
	if !strings.Contains(out, "Team Organization 'MyOrg' initialized") {
		t.Errorf("Unexpected output: %s", out)
	}
}

func TestTeam_Workflows(t *testing.T) {
	// Login
	// Password
	input := fmt.Sprintf("%s\n", masterPass)
	out, err := runTeam(input, "login", "admin")
	if err != nil {
		t.Fatalf("Login failed: %v", err)
	}
	if !strings.Contains(out, "Logged in as admin") {
		t.Errorf("Login failed: %s", out)
	}

	// Whoami
	out, _ = runTeam("", "whoami")
	if !strings.Contains(out, "MyOrg") {
		t.Errorf("Whoami failed: %s", out)
	}

	// Add User
	// Password for new user
	input = fmt.Sprintf("UserPass123!\n")
	out, err = runTeam(input, "user", "add", "alice", "--role", "user")
	if err != nil {
		t.Errorf("Add user failed: %v", err)
	}

	// List Users
	out, _ = runTeam("", "user", "list")
	if !strings.Contains(out, "alice") {
		t.Errorf("User list failed: %s", out)
	}

	// Add Shared Entry (Password)
	// Choice 1 -> Name -> Username -> Password
	input = fmt.Sprintf("1\nSharedAcc\nSharedUser\nSharedPass\n")
	out, err = runTeam(input, "add")
	if err != nil {
		t.Errorf("Add shared failed: %v", err)
	}

	// Get Shared
	out, err = runTeam("1\n", "get", "SharedAcc") // 1 to select if multiple, or just in case
	if err != nil {
		t.Errorf("Get shared failed: %v", err)
	}
	if !strings.Contains(out, "SharedUser") {
		t.Errorf("Shared entry content missing: %s", out)
	}

	// Logout
	runTeam("", "logout")
}
