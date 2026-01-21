package apm_test

import (
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

var (
	pmBinary     string
	pmTeamBinary string
	testVault    = "vault.dat"
	teamVault    = "team_vault.dat"
	masterPass   = "TestPass123!"
)

func TestMain(m *testing.M) {
	if err := buildBinaries(); err != nil {
		fmt.Printf("Failed to build binaries: %v\n", err)
		os.Exit(1)
	}

	cleanup()

	exitCode := m.Run()

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

	pmBinary = "." + string(filepath.Separator) + "pm" + exe
	cmd := exec.Command("go", "build", "-o", pmBinary, "../main.go")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build pm failed: %s", out)
	}

	pmTeamBinary = "." + string(filepath.Separator) + "pm-team" + exe
	cmdTeam := exec.Command("go", "build", "-o", pmTeamBinary, "../team")
	if out, err := cmdTeam.CombinedOutput(); err != nil {
		return fmt.Errorf("build pm-team failed: %s", out)
	}

	return nil
}

func cleanup() {
	os.Remove(testVault)
	os.Remove(teamVault)
	os.Remove(".apm_lock")
	os.Remove("session.json")
	files, _ := filepath.Glob("test_export.*")
	for _, f := range files {
		os.Remove(f)
	}
	os.Remove("exp.json")
	os.Remove("exp.csv")
	os.Remove("exp.txt")
	os.RemoveAll("policies")
}

func runPM(input string, args ...string) (string, error) {
	cmd := exec.Command(pmBinary, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func runPMTeam(input string, args ...string) (string, error) {
	cmd := exec.Command(pmTeamBinary, args...)
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func Test_01_Init(t *testing.T) {
	cleanup()
	input := fmt.Sprintf("%s\n", masterPass)
	out, err := runPM(input, "init")
	if err != nil {
		t.Fatalf("Init failed: %v, output: %s", err, out)
	}
	if !strings.Contains(out, "Vault initialized successfully") {
		t.Errorf("Unexpected output: %s", out)
	}

	if _, err := os.Stat(testVault); os.IsNotExist(err) {
		t.Error("Vault file not created")
	}
}

func Test_02_Add_AllTypes(t *testing.T) {
	input := fmt.Sprintf("%s\n1\nTestAcc\nTestUser\nTestPass123\n", masterPass)
	out, _ := runPM(input, "add")
	if !strings.Contains(out, "Entry saved") {
		t.Errorf("Password add failed: %s", out)
	}

	input = fmt.Sprintf("%s\n2\nTestTOTP\nJBSWY3DPEHPK3PXP\n", masterPass)
	out, _ = runPM(input, "add")
	if !strings.Contains(out, "Entry saved") {
		t.Errorf("TOTP add failed: %s", out)
	}
}

func Test_14_Profiles(t *testing.T) {
	input := fmt.Sprintf("%s\n", masterPass)
	out, _ := runPM(input, "profile", "create", "Work")
	if !strings.Contains(out, "created successfully") {
		t.Errorf("Profile create failed: %s", out)
	}

	out, _ = runPM(input, "profile", "list")
	if !strings.Contains(out, "Work") {
		t.Errorf("Profile list failed: %s", out)
	}

	out, _ = runPM(input, "profile", "switch", "Work")
	if !strings.Contains(out, "Switched to profile: Work") {
		t.Errorf("Profile switch failed: %s", out)
	}

	out, _ = runPM(input, "get", "TestAcc")
	if !strings.Contains(out, "No matching entries") && !strings.Contains(out, "matches found: 0") {
		if strings.Contains(out, "TestUser") {
			t.Errorf("Profile isolation failed. Found 'TestUser' in Work profile.")
		}
	}

	inputAdd := fmt.Sprintf("%s\n1\nWorkAcc\nWorkUser\nWorkPass\n", masterPass)
	runPM(inputAdd, "add")

	out, _ = runPM(input, "get", "WorkAcc")
	if !strings.Contains(out, "WorkUser") {
		t.Errorf("Entry not found in Work profile")
	}
}

func Test_15_Policy(t *testing.T) {

	os.Mkdir("policies", 0755)
	policyContent := `name: "TestPolicy"
password_policy:
  min_length: 20
  require_uppercase: true
`
	os.WriteFile("policies/test.yaml", []byte(policyContent), 0644)
	defer os.RemoveAll("policies")

	input := fmt.Sprintf("%s\n", masterPass)

	out, _ := runPM(input, "policy", "load", "test.yaml")
	if !strings.Contains(out, "Policy loaded: TestPolicy") {

		if strings.Contains(out, "Error") {
			t.Errorf("Policy load failed: %s", out)
		}
	}

	out, _ = runPM(input, "policy", "show")
	if !strings.Contains(out, "TestPolicy") {
		t.Errorf("Policy show failed: %s", out)
	}

	inputAdd := fmt.Sprintf("%s\n1\nWeakAcc\nUser\nShortPass\n", masterPass)
	out, _ = runPM(inputAdd, "add")
	if !strings.Contains(out, "password too short") && !strings.Contains(out, "Policy violation") {

	}

	out, _ = runPM(input, "policy", "clear")
	if !strings.Contains(out, "Policy cleared") {
		t.Errorf("Policy clear failed: %s", out)
	}
}

func Test_16_SecProfile(t *testing.T) {
	input := fmt.Sprintf("%s\n", masterPass)

	out, _ := runPM(input, "sec_profile", "set", "standard")
	if !strings.Contains(out, "Profile switched to standard") {
		t.Errorf("sec_profile set failed: %s", out)
	}

	inputCreate := fmt.Sprintf("%s\n64\n3\n2\n16\n32\n", masterPass)
	out, _ = runPM(inputCreate, "sec_profile", "create", "custom_test")
	if !strings.Contains(out, "Custom profile 'custom_test' created") {
		t.Errorf("sec_profile create failed: %s", out)
	}
}

func Test_17_Unlock_Flags(t *testing.T) {
	input := fmt.Sprintf("%s\n", masterPass)
	out, _ := runPM(input, "unlock", "--timeout", "1s")
	if !strings.Contains(out, "Vault unlocked") {
		t.Errorf("Unlock failed: %s", out)
	}
	time.Sleep(2 * time.Second)

}

func Test_20_Team_Init(t *testing.T) {

	os.Remove(teamVault)

	input := fmt.Sprintf("%s\n%s\n", masterPass, masterPass)
	out, err := runPMTeam(input, "init", "AcmeCorp", "admin")
	if err != nil {
		t.Fatalf("Team Init failed: %v, output: %s", err, out)
	}
	if !strings.Contains(out, "Organization 'AcmeCorp' initialized") {
		t.Errorf("Unexpected output: %s", out)
	}
}

func Test_21_Team_Login_Logout(t *testing.T) {
	input := fmt.Sprintf("%s\n", masterPass)
	out, _ := runPMTeam(input, "login", "admin")
	if !strings.Contains(out, "Logged in as admin") {
		t.Errorf("Team Login failed: %s", out)
	}

	out, _ = runPMTeam("", "whoami")
	if !strings.Contains(out, "AcmeCorp") || !strings.Contains(out, "admin") {
		t.Errorf("whoami failed: %s", out)
	}

}

func Test_22_Team_Dept(t *testing.T) {

	out, _ := runPMTeam("", "dept", "create", "Engineering")
	if !strings.Contains(out, "created") {

		t.Errorf("Dept create failed: %s", out)
	}

	out, _ = runPMTeam("", "dept", "list")
	if !strings.Contains(out, "Engineering") {
		t.Errorf("Dept list failed: %s", out)
	}
}

func Test_23_Team_User(t *testing.T) {

	input := fmt.Sprintf("AlicePass123\n")
	out, _ := runPMTeam(input, "user", "add", "alice", "--role", "MANAGER", "--dept", "engineering")
	if !strings.Contains(out, "added successfully") {
		t.Errorf("User add failed: %s", out)
	}

	out, _ = runPMTeam("", "user", "list")
	if !strings.Contains(out, "alice") {
		t.Errorf("User list failed: %s", out)
	}

	out, _ = runPMTeam("", "user", "promote", "alice", "ADMIN")
	if !strings.Contains(out, "promoted to ADMIN") {
		t.Errorf("User promote failed: %s", out)
	}

	out, _ = runPMTeam("", "user", "permission", "grant", "alice", "CanDeleteVault")
	if !strings.Contains(out, "granted") {
		t.Errorf("Permission grant failed: %s", out)
	}
}

func Test_24_Team_Entries(t *testing.T) {

	input := fmt.Sprintf("1\nSharedDB\ndbuser\ndbpass\ndb.local\nCritical DB\n")
	out, _ := runPMTeam(input, "add")
	if !strings.Contains(out, "Entry added") {
		t.Errorf("Team add entry failed: %s", out)
	}

	out, _ = runPMTeam("", "list")
	if !strings.Contains(out, "SharedDB") {
		t.Errorf("Team list failed: %s", out)
	}

	out, _ = runPMTeam("", "get", "SharedDB")
	if !strings.Contains(out, "dbpass") {
		t.Errorf("Team get failed: %s", out)
	}
}

func Test_25_Team_Approvals(t *testing.T) {
	out, _ := runPMTeam("", "approvals", "list")
	if strings.Contains(out, "Error") {
		t.Errorf("Approvals list failed: %s", out)
	}
}

func Test_26_Audit(t *testing.T) {
	out, _ := runPMTeam("", "audit")
	if !strings.Contains(out, "Audit Trail") {
		t.Errorf("Team audit failed: %s", out)
	}
}
