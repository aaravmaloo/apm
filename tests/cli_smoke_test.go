package apm_test

import (
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
	"time"
)

func buildPMBinary(t *testing.T, outPath string) {
	t.Helper()

	cmd := exec.Command("go", "build", "-o", outPath, "../main.go")
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("failed to build pm binary: %v\n%s", err, string(output))
	}
}

func runCommand(t *testing.T, cmd *exec.Cmd) string {
	t.Helper()
	output, err := cmd.CombinedOutput()
	if err != nil {
		t.Fatalf("command failed: %v\n%s", err, string(output))
	}
	return string(output)
}

func TestCLISmoke_SetupAndProfileCurrent(t *testing.T) {
	tempDir := t.TempDir()

	exe := "pm"
	if runtime.GOOS == "windows" {
		exe += ".exe"
	}
	pmBinary := filepath.Join(tempDir, exe)
	buildPMBinary(t, pmBinary)

	helpOut := runCommand(t, exec.Command(pmBinary, "--help"))
	if !strings.Contains(helpOut, "setup") {
		t.Fatalf("expected help output to include setup command, output:\n%s", helpOut)
	}

	vaultPath := filepath.Join(tempDir, "vault.dat")
	sessionID := "cli_smoke_" + strconv.FormatInt(time.Now().UnixNano(), 10)
	env := append(os.Environ(), "APM_SESSION_ID="+sessionID)

	setupCmd := exec.Command(pmBinary, "--vault", vaultPath, "setup", "--non-interactive")
	setupCmd.Env = env
	setupCmd.Stdin = strings.NewReader("ValidPass123!\n")
	setupOut := runCommand(t, setupCmd)
	if !strings.Contains(setupOut, "Setup completed successfully.") {
		t.Fatalf("expected setup success output, got:\n%s", setupOut)
	}

	if _, err := os.Stat(vaultPath); err != nil {
		t.Fatalf("expected vault file at %s: %v", vaultPath, err)
	}

	profileCmd := exec.Command(pmBinary, "--vault", vaultPath, "profile", "current")
	profileCmd.Env = env
	profileCmd.Stdin = strings.NewReader("ValidPass123!\n")
	profileOut := runCommand(t, profileCmd)
	if !strings.Contains(profileOut, "Current profile") {
		t.Fatalf("expected profile output, got:\n%s", profileOut)
	}
}
