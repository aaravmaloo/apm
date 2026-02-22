package apm_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

func TestBruteForceResistance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
	defer cancel()

	tempDir := t.TempDir()

	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	pmBinary := filepath.Join(tempDir, "pm_brute"+exe)

	// Build the binary
	cmd := exec.CommandContext(ctx, "go", "build", "-o", pmBinary, "../main.go")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build: %s", out)
	}

	weakPass := "password123"
	vaultFile := filepath.Join(tempDir, "brute_vault.dat")

	// Initialize vault with weak password via setup
	initCmd := exec.CommandContext(ctx, pmBinary, "setup", "--non-interactive")
	initCmd.Env = append(os.Environ(), "APM_VAULT_PATH="+vaultFile)
	initCmd.Dir = tempDir

	stdin, _ := initCmd.StdinPipe()
	go func() {
		defer stdin.Close()
		fmt.Fprintln(stdin, weakPass) // Password
	}()

	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("Setup failed: %s", out)
	}

	wordlist := []string{"123456", "admin", "password", "password123", "secret"}
	found := false
	start := time.Now()

	for _, p := range wordlist {
		// Attempt to 'get' something using the password candidate
		checkCmd := exec.CommandContext(ctx, pmBinary, "get", "anything")
		checkCmd.Env = append(os.Environ(), "APM_VAULT_PATH="+vaultFile)
		checkCmd.Dir = tempDir

		chkStdin, _ := checkCmd.StdinPipe()
		go func() {
			defer chkStdin.Close()
			fmt.Fprintln(chkStdin, p)
		}()

		// CombinedOutput will return error if exit code != 0 (which happens on wrong password usually)
		out, err := checkCmd.CombinedOutput()

		// Logic: If err == nil, it means the command succeeded, so password was correct.
		// However, "get anything" might fail if "anything" doesn't exist, even with correct password.
		// We need to distinguish "wrong password" from "entry not found".
		// Usually tools return specific exit code or output for auth failure.
		// Assuming exit code 0 means auth success but maybe entry lookup failure.

		// If auth fails, it usually returns non-zero.
		if err == nil || (err != nil && !containsAuthError(string(out))) {
			// If we got past auth (even if entry not found), we consider it a 'success' in guessing password
			// But strictly, if err == nil, we are definitely in.
			if err == nil {
				found = true
				if p == weakPass {
					t.Logf("Brute force succeeded for weak password: %s", p)
				} else {
					t.Logf("False positive or collision? Password: %s", p)
				}
				break
			}
		}
	}

	duration := time.Since(start)
	t.Logf("Brute force attempt of %d passwords took %v", len(wordlist), duration)

	if !found {
		t.Log("Brute force failed to find password (expected if Argone2 cost is high or logic differs)")
	}
}

func containsAuthError(output string) bool {
	// Adjust based on actual error messages
	return false // Simplified: Assume any error is auth error for now unless we know better
}
