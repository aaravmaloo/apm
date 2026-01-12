package apm

import (
	"fmt"
	"os"
	"os/exec"
)

func main() {
	fmt.Println("Starting Team APM Verification...")

	// 1. Clean up existing vault
	os.Remove("team_vault.dat")
	os.Remove("session.json")

	// 2. Build the team binary
	fmt.Println("Building team binary...")
	buildCmd := exec.Command("go", "build", "-o", "pm-team-test.exe", "main.go", "team_vault.go", "session.go", "crypto.go")
	buildCmd.Dir = "./team"
	if out, err := buildCmd.CombinedOutput(); err != nil {
		fmt.Printf("Build failed: %v\n%s\n", err, out)
		return
	}

	fmt.Println("Build successful. Manual verification recommended for interactive features.")
}
