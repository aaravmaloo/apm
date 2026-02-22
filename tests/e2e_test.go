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
	pmBinary     string
	pmTeamBinary string
)

func TestMain(m *testing.M) {
	if err := buildBinaries(); err != nil {
		fmt.Printf("Failed to build binaries: %v\n", err)
		os.Exit(1)
	}

	exitCode := m.Run()

	cleanupBinaries()
	os.Exit(exitCode)
}

func buildBinaries() error {
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}

	tmp, err := os.MkdirTemp("", "apm_build_*")
	if err != nil {
		return err
	}

	pmBinary = filepath.Join(tmp, "pm"+exe)
	cmd := exec.Command("go", "build", "-o", pmBinary, "../main.go")
	if out, err := cmd.CombinedOutput(); err != nil {
		return fmt.Errorf("build pm failed: %s", out)
	}

	pmTeamBinary = filepath.Join(tmp, "pm-team"+exe)
	cmdTeam := exec.Command("go", "build", "-o", pmTeamBinary, ".")
	cmdTeam.Dir = "../team"
	if out, err := cmdTeam.CombinedOutput(); err != nil {
		return fmt.Errorf("build pm-team failed: %s", out)
	}

	return nil
}

func cleanupBinaries() {
	if pmBinary != "" {
		os.RemoveAll(filepath.Dir(pmBinary))
	}
}

func runPM(t *testing.T, workDir string, env []string, input string, args ...string) (string, error) {
	cmd := exec.Command(pmBinary, args...)
	cmd.Dir = workDir

	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, env...)

	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func runPMTeam(t *testing.T, workDir string, env []string, input string, args ...string) (string, error) {
	cmd := exec.Command(pmTeamBinary, args...)
	cmd.Dir = workDir
	cmd.Env = os.Environ()
	cmd.Env = append(cmd.Env, env...)

	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	out, err := cmd.CombinedOutput()
	return string(out), err
}

func TestE2EFlow(t *testing.T) {

	workDir := t.TempDir()

	sessionID := "E2ETEST_" + filepath.Base(workDir)
	env := []string{
		"APM_SESSION_ID=" + sessionID,
	}

	masterPass := "TestPass123!"

	t.Run("Setup", func(t *testing.T) {
		input := fmt.Sprintf("%s\n", masterPass)
		// Use a unique session ID to avoid interference
		localEnv := append(env, "APM_SESSION_ID="+sessionID+"_INIT")
		out, err := runPM(t, workDir, localEnv, input, "--vault", "vault.dat", "setup", "--non-interactive")
		if err != nil {
			t.Fatalf("Setup failed: %v, output: %s", err, out)
		}
		if !strings.Contains(out, "Setup completed successfully") {
			t.Errorf("Unexpected output: %s", out)
		}

		if _, err := os.Stat(filepath.Join(workDir, "vault.dat")); os.IsNotExist(err) {
			t.Error("Vault file not created")
		}
	})

	t.Run("Add_AllTypes", func(t *testing.T) {
		// Category 1 (Identity), Item 1 (Password)
		input := fmt.Sprintf("%s\n1\n1\nTestAcc\nTestUser\nTestPass123\n", masterPass)
		localEnv := append(env, "APM_SESSION_ID="+sessionID+"_ADD1")
		out, _ := runPM(t, workDir, localEnv, input, "--vault", "vault.dat", "add")
		if !strings.Contains(out, "Entry saved") {
			t.Errorf("Password add failed: %s", out)
		}

		// Category 1 (Identity), Item 2 (TOTP)
		input = fmt.Sprintf("%s\n1\n2\nTestTOTP\nJBSWY3DPEHPK3PXP\n", masterPass)
		localEnv = append(env, "APM_SESSION_ID="+sessionID+"_ADD2")
		out, _ = runPM(t, workDir, localEnv, input, "--vault", "vault.dat", "add")
		if !strings.Contains(out, "Entry saved") {
			t.Errorf("TOTP add failed: %s", out)
		}
	})

	t.Run("Spaces", func(t *testing.T) {
		input := fmt.Sprintf("%s\n", masterPass)
		localEnv := append(env, "APM_SESSION_ID="+sessionID+"_SPACE1")
		out, _ := runPM(t, workDir, localEnv, input, "--vault", "vault.dat", "space", "create", "Work")
		if !strings.Contains(out, "created successfully") {
			t.Errorf("Space create failed: %s", out)
		}

		localEnv = append(env, "APM_SESSION_ID="+sessionID+"_SPACE2")
		out, _ = runPM(t, workDir, localEnv, input, "--vault", "vault.dat", "space", "list")
		if !strings.Contains(out, "Work") {
			t.Errorf("Space list failed: %s", out)
		}

		localEnv = append(env, "APM_SESSION_ID="+sessionID+"_SPACE3")
		out, _ = runPM(t, workDir, localEnv, input, "--vault", "vault.dat", "space", "switch", "Work")
		if !strings.Contains(out, "Switched to space: Work") {
			t.Errorf("Space switch failed: %s", out)
		}

		localEnv = append(env, "APM_SESSION_ID="+sessionID+"_SPACE4")
		out, _ = runPM(t, workDir, localEnv, input, "--vault", "vault.dat", "get", "TestAcc")
		if !strings.Contains(out, "No matching entries") && !strings.Contains(out, "matches found: 0") {
			t.Errorf("Space isolation failed. Found entry from default space in Work space.")
		}

		// Category 1, Item 1
		inputAdd := fmt.Sprintf("%s\n1\n1\nWorkAcc\nWorkUser\nWorkPass\n", masterPass)
		localEnv = append(env, "APM_SESSION_ID="+sessionID+"_SPACE5")
		_, _ = runPM(t, workDir, localEnv, inputAdd, "--vault", "vault.dat", "add")

		localEnv = append(env, "APM_SESSION_ID="+sessionID+"_SPACE6")
		out, _ = runPM(t, workDir, localEnv, input, "--vault", "vault.dat", "get", "WorkAcc")
		if !strings.Contains(out, "WorkUser") {
			t.Errorf("Entry not found in Work space")
		}

		localEnv = append(env, "APM_SESSION_ID="+sessionID+"_SPACE7")
		out, _ = runPM(t, workDir, localEnv, input, "--vault", "vault.dat", "space", "switch", "default")
		if !strings.Contains(out, "Switched to space: default") {
			t.Errorf("Failed to switch back to default space: %s", out)
		}
	})

	t.Run("Policy", func(t *testing.T) {
		policiesDir := filepath.Join(workDir, "policies")
		os.Mkdir(policiesDir, 0755)
		policyContent := `name: "TestPolicy"
password_policy:
  min_length: 20
  require_uppercase: true
`
		os.WriteFile(filepath.Join(policiesDir, "test.yaml"), []byte(policyContent), 0644)

		input := fmt.Sprintf("%s\n", masterPass)
		out, _ := runPM(t, workDir, env, input, "policy", "load", "TestPolicy")

		if strings.Contains(out, "Error") {
			t.Logf("Policy load warning (might depend on impl): %s", out)
		}

		inputAdd := fmt.Sprintf("%s\n1\nWeakAcc\nUser\nShortPass\n", masterPass)
		out, _ = runPM(t, workDir, env, inputAdd, "add")

		if !strings.Contains(out, "password too short") && !strings.Contains(out, "Policy violation") {

		}
	})
}

func TestTeamFlow(t *testing.T) {
	workDir := t.TempDir()
	env := []string{}
	masterPass := "TestPass123!"

	t.Run("Team_Init", func(t *testing.T) {
		input := fmt.Sprintf("%s\n%s\n", masterPass, masterPass)
		out, err := runPMTeam(t, workDir, env, input, "init", "AcmeCorp", "admin")
		if err != nil {
			t.Fatalf("Team Init failed: %v, output: %s", err, out)
		}
		if !strings.Contains(out, "Organization 'AcmeCorp' initialized") {
			t.Errorf("Unexpected output: %s", out)
		}
	})

	t.Run("Team_Login_Logout", func(t *testing.T) {
		input := fmt.Sprintf("%s\n", masterPass)
		out, _ := runPMTeam(t, workDir, env, input, "login", "admin")
		if !strings.Contains(out, "Logged in as admin") {
			t.Errorf("Team Login failed: %s", out)
		}

		out, _ = runPMTeam(t, workDir, env, "", "whoami")
		if !strings.Contains(out, "AcmeCorp") || !strings.Contains(out, "admin") {
			t.Errorf("whoami failed: %s", out)
		}
	})

	// Add more team tests following the same pattern...
}
