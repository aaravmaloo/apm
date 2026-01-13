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

func Test_02_Add(t *testing.T) {
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
	input := fmt.Sprintf("%s\n1\nTestAcc\nUpdatedAcc\nUpdatedUser\nUpdatedPass\n", masterPass)
	out, err := runPM(input, "edit")
	if err != nil {
		t.Fatalf("Edit failed: %v, output: %s", err, out)
	}
	if !strings.Contains(out, "Entry saved") {
	}

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
	out, err := runPM("", "gen", "--length", "20")
	if err != nil {
		t.Errorf("Gen failed: %v", err)
	}
	if len(strings.TrimSpace(out)) < 20 {
		t.Errorf("Generated password too short: %s", out)
	}

	input := fmt.Sprintf("%s\n2\nTestTOTP\nJBSWY3DPEHPK3PXP\n", masterPass)
	runPM(input, "add")

	input = fmt.Sprintf("%s\n", masterPass)
	out, err = runPM(input, "totp", "show", "TestTOTP")
	if err != nil {
		t.Errorf("TOTP failed: %v", err)
	}
	if !strings.Contains(out, "Code:") {
		t.Errorf("TOTP output invalid: %s", out)
	}
}

func Test_07_Note(t *testing.T) {
	input := fmt.Sprintf("%s\n4\nMyNote\nSecretContent\n\n", masterPass)
	runPM(input, "add")

	input = fmt.Sprintf("%s\n", masterPass)
	out, _ := runPM(input, "get", "MyNote")
	if !strings.Contains(out, "SecretContent") {
		t.Errorf("Note retrieval failed: %s", out)
	}
}

func Test_08_ExportImport(t *testing.T) {
	input := fmt.Sprintf("%s\n", masterPass)
	out, err := runPM(input, "export", "--format", "json", "--output", "test_export.json")
	if err != nil {
		t.Fatalf("Export failed: %v, output: %s", err, out)
	}

	os.Remove(testVault)

	input = fmt.Sprintf("%s\n", masterPass)
	runPM(input, "init")

	input = fmt.Sprintf("%s\n", masterPass)
	out, err = runPM(input, "import", "test_export.json")
	if err != nil {
		t.Fatalf("Import failed: %v, output: %s", err, out)
	}

	input = fmt.Sprintf("%s\n", masterPass)
	out, _ = runPM(input, "get", "MyNote")
	if !strings.Contains(out, "SecretContent") {
		t.Errorf("Import verification failed: %s", out)
	}
}
