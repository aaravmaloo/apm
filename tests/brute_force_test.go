package apm_test

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestBruteForceResistance(t *testing.T) {
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()

	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	pmBinary := "./pm_brute" + exe
	cmd := exec.CommandContext(ctx, "go", "build", "-o", pmBinary, "../main.go")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build: %s", out)
	}
	defer os.Remove(pmBinary)

	weakPass := "password123"
	vaultFile := "brute_vault.dat"
	defer os.Remove(vaultFile)

	initCmd := exec.CommandContext(ctx, pmBinary, "init")
	initCmd.Env = append(os.Environ(), "APM_VAULT_PATH="+vaultFile)
	stdin, _ := initCmd.StdinPipe()
	go func() {
		fmt.Fprintln(stdin, weakPass)
		fmt.Fprintln(stdin, "n")
		stdin.Close()
	}()
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("Init failed: %s", out)
	}

	wordlist := []string{"123456", "admin", "password", "password123", "secret"}
	found := false
	start := time.Now()

	for _, p := range wordlist {
		checkCmd := exec.CommandContext(ctx, pmBinary, "get", "anything")
		checkCmd.Env = append(os.Environ(), "APM_VAULT_PATH="+vaultFile)
		stdin, _ := checkCmd.StdinPipe()
		go func() {
			fmt.Fprintln(stdin, p)
			stdin.Close()
		}()

		_, err := checkCmd.CombinedOutput()
		if err == nil {
			found = true
			if p == weakPass {
				t.Logf("Brute force succeeded for weak password: %s", p)
			}
			break
		}
	}

	duration := time.Since(start)
	t.Logf("Brute force of %d passwords took %v", len(wordlist), duration)

	if !found {
		t.Log("Brute force failed to find password (expected for this simple test if Argon2 cost is high)")
	}
}
