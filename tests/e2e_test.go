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
	pmBinary   string
	testVault  = "vault.dat"
	masterPass = "TestPass123!"
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

	return nil
}

func cleanup() {
	os.Remove(testVault)
	os.Remove(".apm_lock")
	files, _ := filepath.Glob("test_export.*")
	for _, f := range files {
		os.Remove(f)
	}
	os.Remove("exp.json")
	os.Remove("exp.csv")
	os.Remove("exp.txt")
}

func runPM(input string, args ...string) (string, error) {
	cmd := exec.Command(pmBinary, args...)
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
	// 1. Password
	input := fmt.Sprintf("%s\n1\nTestAcc\nTestUser\nTestPass123\n", masterPass)
	out, _ := runPM(input, "add")
	if !strings.Contains(out, "Entry saved") {
		t.Errorf("Password add failed: %s", out)
	}

	// 2. TOTP
	input = fmt.Sprintf("%s\n2\nTestTOTP\nJBSWY3DPEHPK3PXP\n", masterPass)
	out, _ = runPM(input, "add")
	if !strings.Contains(out, "Entry saved") {
		t.Errorf("TOTP add failed: %s", out)
	}

	// 3. Token
	input = fmt.Sprintf("%s\n3\nTestToken\nmy-secret-token\nGitHub\n", masterPass)
	runPM(input, "add")

	// 4. Secure Note
	input = fmt.Sprintf("%s\n4\nMyNote\nline1\nline2\n\n", masterPass)
	runPM(input, "add")

	// 5. API Key
	input = fmt.Sprintf("%s\n5\nMyAPIKey\nOpenAI\nsk-12345\n", masterPass)
	runPM(input, "add")

	// 6. SSH Key
	input = fmt.Sprintf("%s\n6\nMySSH\n-----BEGIN RSA PRIVATE KEY-----\nkey-content\n\n", masterPass)
	runPM(input, "add")

	// 7. Wi-Fi
	input = fmt.Sprintf("%s\n7\nMyWiFi\npass123\nWPA2\n", masterPass)
	runPM(input, "add")

	// 8. Recovery Codes
	input = fmt.Sprintf("%s\n8\nMyRecovery\ncode1\ncode2\n\n", masterPass)
	runPM(input, "add")

	// 9. Certificate
	input = fmt.Sprintf("%s\n9\nMyCert\nIssuerX\n2025-01-01\ncert-data\n\nkey-data\n\n", masterPass)
	runPM(input, "add")

	// 10. Banking
	input = fmt.Sprintf("%s\n10\nMyBank\nCard\n1234567812345678\n123\n12/26\n", masterPass)
	runPM(input, "add")

	// 11. Document (requires a real file)
	dummyPDF := "dummy.pdf"
	os.WriteFile(dummyPDF, []byte("fake pdf content"), 0644)
	defer os.Remove(dummyPDF)
	input = fmt.Sprintf("%s\n11\nMyDoc\n%s\ndocpass123\n", masterPass, dummyPDF)
	runPM(input, "add")
}

func Test_03_Get_Fuzzy_And_Flags(t *testing.T) {
	// Test category-based retrieval (Interactive)
	// Choice: 1 (Password) -> Choice: 1 (TestAcc)
	input := fmt.Sprintf("%s\n1\n1\n", masterPass)
	out, err := runPM(input, "get")
	if err != nil || !strings.Contains(out, "TestUser") {
		t.Errorf("Interactive get failed: %s", out)
	}

	// Test fuzzy search with flag
	input = fmt.Sprintf("%s\n", masterPass)
	out, _ = runPM(input, "get", "TestAc", "--show-pass")
	if !strings.Contains(out, "TestPass123") {
		t.Errorf("Fuzzy get with show-pass failed: %s", out)
	}
}

func Test_04_Edit_Entry(t *testing.T) {
	// Edit Password entry: Choice 1 (Password) -> identifier NewAcc (oops, it was TestAcc)
	// Let's use TestAcc
	input := fmt.Sprintf("%s\n1\nTestAcc\nUpdatedAcc\nUpdatedUser\nUpdatedPass\n", masterPass)
	out, _ := runPM(input, "edit")
	if !strings.Contains(out, "Entry updated successfully") {
		t.Errorf("Edit failed: %s", out)
	}
}

func Test_05_Del_Entry(t *testing.T) {
	input := fmt.Sprintf("%s\n", masterPass)
	out, _ := runPM(input, "del", "UpdatedAcc")
	if !strings.Contains(out, "Deleted 'UpdatedAcc'") {
		t.Errorf("Del failed: %s", out)
	}
}

func Test_06_Utility_Commands(t *testing.T) {
	// cinfo
	out, _ := runPM("", "cinfo")
	if !strings.Contains(out, "Argon2id") {
		t.Errorf("cinfo failed")
	}

	// gen
	out, _ = runPM("", "gen", "--length", "32")
	if len(strings.TrimSpace(out)) < 32 {
		t.Errorf("gen failed")
	}

	// scan
	input := fmt.Sprintf("%s\n", masterPass)
	out, _ = runPM(input, "scan")
	if !strings.Contains(out, "Scanning Vault Health") {
		t.Errorf("scan failed: %s", out)
	}

	// audit
	input = fmt.Sprintf("%s\n", masterPass)
	out, _ = runPM(input, "audit")
	if !strings.Contains(out, "Timestamp") {
		t.Errorf("audit failed: %s", out)
	}

	// info
	out, _ = runPM("", "info")
	if !strings.Contains(out, "@apm") {
		t.Errorf("info failed")
	}
}

func Test_07_Mode_Commands(t *testing.T) {
	// readonly
	input := fmt.Sprintf("%s\n", masterPass)
	out, _ := runPM(input, "mode", "readonly", "5")
	if !strings.Contains(out, "Vault unlocked for 5 minutes (READ-ONLY)") {
		t.Errorf("readonly mode failed: %s", out)
	}

	// lock
	out, _ = runPM("", "mode", "lock")
	if !strings.Contains(out, "Vault locked") {
		t.Errorf("lock mode failed")
	}
}

func Test_09_ExportImport_Formats(t *testing.T) {
	input := fmt.Sprintf("%s\n", masterPass)

	// JSON
	runPM(input, "export", "--output", "exp.json")
	if _, err := os.Stat("exp.json"); err != nil {
		t.Errorf("JSON export failed")
	}

	// CSV
	runPM(input, "export", "--output", "exp.csv")
	if _, err := os.Stat("exp.csv"); err != nil {
		t.Errorf("CSV export failed")
	}

	// TXT --without-password
	runPM(input, "export", "--output", "exp.txt", "--without-password")
	if _, err := os.Stat("exp.txt"); err != nil {
		t.Errorf("TXT export failed")
	}

	// Import check
	input = fmt.Sprintf("%s\n", masterPass)
	out, _ := runPM(input, "import", "exp.json")
	if !strings.Contains(out, "Successfully imported") {
		t.Errorf("Import failed: %s", out)
	}

	cleanup()
	// re-init for final tests
	runPM(fmt.Sprintf("%s\n", masterPass), "init")
}

func Test_10_Cloud_CLI_Flow(t *testing.T) {
	input := fmt.Sprintf("%s\n", masterPass)
	out, _ := runPM(input, "cloud", "reset")
	if !strings.Contains(out, "Cloud sync is not initialized") && !strings.Contains(out, "metadata reset") {
		t.Errorf("Cloud reset flow failed: %s", out)
	}
}

func Test_11_Compromise(t *testing.T) {
	input := "DESTROY\n"
	out, _ := runPM(input, "mode", "compromise")
	if !strings.Contains(out, "Vault nuked") {
		t.Errorf("Compromise failed: %s", out)
	}
	// Note: src.VaultExists checks global variable but we are in tests,
	// we should check if file exists
	if _, err := os.Stat(testVault); err == nil {
		t.Errorf("Vault still exists after compromise")
	}
}
