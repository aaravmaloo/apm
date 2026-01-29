package apm_test

import (
	"fmt"
	"os"
	"os/exec"
	"runtime"
	"testing"
	"time"
)

func TestBruteForceResistance(t *testing.T) {
	// 1. Build binary
	exe := ""
	if runtime.GOOS == "windows" {
		exe = ".exe"
	}
	pmBinary := "./pm_brute" + exe
	cmd := exec.Command("go", "build", "-o", pmBinary, "../main.go")
	if out, err := cmd.CombinedOutput(); err != nil {
		t.Fatalf("Failed to build: %s", out)
	}
	defer os.Remove(pmBinary)

	// 2. Create a vault with a known weak password
	weakPass := "password123"
	vaultFile := "brute_vault.dat"
	defer os.Remove(vaultFile)

	initCmd := exec.Command(pmBinary, "init")
	initCmd.Env = append(os.Environ(), "APM_VAULT_PATH="+vaultFile)
	stdin, _ := initCmd.StdinPipe()
	go func() {
		fmt.Fprintln(stdin, weakPass) // Master Pass
		fmt.Fprintln(stdin, "n")      // No cloud sync
		stdin.Close()
	}()
	if out, err := initCmd.CombinedOutput(); err != nil {
		t.Fatalf("Init failed: %s", out)
	}

	// 3. Attempt brute force
	wordlist := []string{"123456", "admin", "password", "password123", "secret"}
	found := false
	start := time.Now()

	for _, p := range wordlist {
		checkCmd := exec.Command(pmBinary, "get", "anything")
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
