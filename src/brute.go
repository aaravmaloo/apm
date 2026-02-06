package apm

import (
	"context"
	"fmt"
	"runtime"
	"sync"
	"sync/atomic"
	"time"

	"github.com/fatih/color"
)

var commonPasswords = []string{
	"password", "123456", "12345678", "qwerty", "admin", "welcome", "login", "secret",
	"password123", "dragon", "letmein", "sunshine", "football", "monkey", "charlie",
}

func RunBruteTest(vaultPath string, timeoutMins int) {
	if !VaultExists(vaultPath) {
		color.Red("Vault file not found: %s", vaultPath)
		return
	}

	data, err := LoadVault(vaultPath)
	if err != nil {
		color.Red("Error loading vault: %v", err)
		return
	}

	profile, _, err := GetVaultParams(data)
	if err != nil {
		color.Red("Error reading vault parameters: %v", err)
		return
	}

	// Extract salt and stored validator
	offset := len(VaultHeader) + 1 // Version byte
	if offset+2 > len(data) {
		color.Red("Corrupted vault header")
		return
	}
	pLen := int(data[offset])<<8 | int(data[offset+1])
	offset += 2 + pLen

	if offset+16 > len(data) {
		color.Red("Corrupted vault header (salt)")
		return
	}
	salt := data[offset : offset+16]
	offset += 16

	if offset+32 > len(data) {
		color.Red("Corrupted vault header (validator)")
		return
	}
	storedValidator := data[offset : offset+32]

	color.HiCyan("\nAPM BRUTE FORCE SECURITY TEST")
	color.HiCyan("=============================")
	fmt.Printf("Vault:     %s\n", vaultPath)
	fmt.Printf("Profile:   %s (Time: %d, Mem: %d KB)\n", profile.Name, profile.Time, profile.Memory/1024)
	fmt.Printf("Timeout:   %d minutes\n", timeoutMins)
	fmt.Printf("CPUs:      %d (Parallelizing Argon2id)\n", runtime.NumCPU())
	color.Yellow("\nWarning: This will consume maximum CPU resources for the duration of the test.")
	fmt.Print("Starting in 3 seconds... (Ctrl+C to abort)")
	time.Sleep(3 * time.Second)
	fmt.Println("\n\n[TESTING...]")

	ctx, cancel := context.WithTimeout(context.Background(), time.Duration(timeoutMins)*time.Minute)
	defer cancel()

	var attempts uint64
	var foundPassword string
	var wg sync.WaitGroup

	passChan := make(chan string, 100)

	// Stats worker
	go func() {
		start := time.Now()
		for {
			select {
			case <-ctx.Done():
				return
			case <-time.After(5 * time.Second):
				curAttempts := atomic.LoadUint64(&attempts)
				elapsed := time.Since(start).Seconds()
				rate := float64(curAttempts) / elapsed
				color.HiBlack("  > Progress: %d attempts (%.2f/sec)", curAttempts, rate)
			}
		}
	}()

	// Workers
	for i := 0; i < runtime.NumCPU(); i++ {
		wg.Add(1)
		go func() {
			defer wg.Done()
			for {
				select {
				case <-ctx.Done():
					return
				case pass, ok := <-passChan:
					if !ok {
						return
					}

					keys := DeriveKeys(pass, salt, profile.Time, profile.Memory, profile.Parallelism)
					if VerifyPasswordValidator(keys.Validator, storedValidator) {
						foundPassword = pass
						cancel()
						return
					}
					atomic.AddUint64(&attempts, 1)
					Wipe(keys.EncryptionKey)
					Wipe(keys.AuthKey)
					Wipe(keys.Validator)
				}
			}
		}()
	}

	// Password Generator
	go func() {
		// 1. Dictionary Attack
		for _, p := range commonPasswords {
			select {
			case <-ctx.Done():
				close(passChan)
				return
			case passChan <- p:
			}
		}

		// 2. Simple Brute Force (Iterative)
		chars := "abcdefghijklmnopqrstuvwxyz0123456789"
		for length := 1; length <= 8; length++ {
			generatePasswords("", chars, length, passChan, ctx)
		}
		close(passChan)
	}()

	wg.Wait()

	fmt.Println("\n=============================")
	if foundPassword != "" {
		color.Red("CRITICAL FAILURE: Vault Cracked!")
		color.Red("Password Found: %s", foundPassword)
		color.Yellow("\nSECURITY RECOMMENDATIONS:")
		fmt.Println("1. Change your master password immediately to a long, complex passphrase.")
		fmt.Println("2. Use a 'Hardened' or 'Paranoid' encryption profile to increase brute-force cost.")
		fmt.Println("3. Use symbols, numbers, and casing to drastically increase the search space.")
	} else {
		color.Green("TEST PASSED: Vault is Secure!")
		color.Green("Your password resisted intensive brute-forcing for %d minutes.", timeoutMins)
		color.Cyan("\nTECHNICAL EXPLANATION:")
		fmt.Println("- Argon2id is highly resistant to GPU/FPGA attacks due to its memory-hard design.")
		fmt.Println("- Your current profile makes each password guess too slow for a practical attack.")
		fmt.Println("- Keep using a strong master password (12+ characters recommended).")
	}
	fmt.Printf("\nFinal Stats: %d total attempts.\n", atomic.LoadUint64(&attempts))
}

func generatePasswords(prefix string, chars string, length int, passChan chan string, ctx context.Context) {
	if length == 0 {
		select {
		case <-ctx.Done():
		case passChan <- prefix:
		}
		return
	}
	for _, c := range chars {
		select {
		case <-ctx.Done():
			return
		default:
			generatePasswords(prefix+string(c), chars, length-1, passChan, ctx)
		}
	}
}
