//go:build faceid

package faceid

import (
	"fmt"
	"path/filepath"

	src "github.com/aaravmaloo/apm/src"
	"github.com/fatih/color"
	"github.com/spf13/cobra"
)

func BuildFaceIDCmd(vaultPath string, readPasswordFunc func() (string, error), getModelsDir func() string) *cobra.Command {
	faceidCmd := &cobra.Command{
		Use:   "faceid",
		Short: "Manage Face ID authentication",
	}

	enrollCmd := &cobra.Command{
		Use:   "enroll",
		Short: "Enroll your face for unlocking",
		Run: func(cmd *cobra.Command, args []string) {
			vaultDir := filepath.Dir(vaultPath)
			modelsDir := getModelsDir()

			data, err := src.LoadVault(vaultPath)
			if err != nil {
				color.Red("Failed to load vault: %v", err)
				return
			}

			fmt.Print("Master Password: ")
			mp, err := readPasswordFunc()
			if err != nil {
				return
			}
			fmt.Println()

			vault, err := src.DecryptVault(data, mp, 1)
			if err != nil {
				color.Red("Invalid master password")
				return
			}

			enrollment, err := LoadEnrollment(vaultDir)
			if err != nil {
				color.Red("Failed to load enrollment: %v", err)
				return
			}
			if enrollment != nil {
				color.Yellow("A face is already enrolled. Enrolling again will overwrite it.")
			}

			_, err = EnrollFace(mp, vaultDir, modelsDir, vault.Profile)
			if err != nil {
				color.Red("Enrollment failed: %v", err)
				return
			}

			color.Green("Face ID enrolled successfully!")
		},
	}

	testCmd := &cobra.Command{
		Use:   "test",
		Short: "Test face recognition without unlocking",
		Run: func(cmd *cobra.Command, args []string) {
			vaultDir := filepath.Dir(vaultPath)
			modelsDir := getModelsDir()

			data, err := src.LoadVault(vaultPath)
			if err != nil {
				color.Red("Failed to load vault: %v", err)
				return
			}

			fmt.Print("Master Password: ")
			mp, err := readPasswordFunc()
			if err != nil {
				return
			}
			fmt.Println()

			vault, err := src.DecryptVault(data, mp, 1)
			if err != nil {
				color.Red("Invalid master password")
				return
			}

			enrollment, err := LoadEnrollment(vaultDir)
			if err != nil {
				color.Red("Failed to load enrollment: %v", err)
				return
			}
			if enrollment == nil {
				color.Red("No face enrolled. Run 'pm faceid enroll' first.")
				return
			}

			if err := EnsureModels(modelsDir); err != nil {
				color.Red("Face ID models download failed: %v", err)
				return
			}

			rec, err := NewRecognizer(modelsDir)
			if err != nil {
				color.Red("Failed to init recognizer: %v", err)
				return
			}
			defer rec.Close()

			fmt.Println("Capturing face...")
			matched, conf, err := rec.Verify(enrollment.Embedding, vault.Profile)
			if err != nil {
				color.Red("Verification failed: %v", err)
				return
			}

			if matched {
				color.Green("PASS - Match confirmed (score: %.3f)", conf)
			} else {
				color.Red("FAIL - No match (best score: %.3f)", conf)
			}
		},
	}

	removeCmd := &cobra.Command{
		Use:   "remove",
		Short: "Remove Face ID enrollment",
		Run: func(cmd *cobra.Command, args []string) {
			vaultDir := filepath.Dir(vaultPath)
			data, err := src.LoadVault(vaultPath)
			if err != nil {
				color.Red("Failed to load vault: %v", err)
				return
			}

			fmt.Print("Master Password: ")
			mp, err := readPasswordFunc()
			if err != nil {
				return
			}
			fmt.Println()

			_, err = src.DecryptVault(data, mp, 1)
			if err != nil {
				color.Red("Invalid master password")
				return
			}

			enrollment, err := LoadEnrollment(vaultDir)
			if err != nil {
				color.Red("Failed to load enrollment: %v", err)
				return
			}
			if enrollment == nil {
				color.Yellow("No face enrolled.")
				return
			}

			err = RemoveEnrollment(vaultDir)
			if err != nil {
				color.Red("Failed to remove enrollment: %v", err)
				return
			}

			color.Green("Face ID enrollment removed.")
		},
	}

	statusCmd := &cobra.Command{
		Use:   "status",
		Short: "Show Face ID enrollment status",
		Run: func(cmd *cobra.Command, args []string) {
			vaultDir := filepath.Dir(vaultPath)
			data, err := src.LoadVault(vaultPath)
			if err != nil {
				color.Red("Failed to load vault: %v", err)
				return
			}

			fmt.Print("Master Password: ")
			mp, err := readPasswordFunc()
			if err != nil {
				return
			}
			fmt.Println()

			_, err = src.DecryptVault(data, mp, 1)
			if err != nil {
				color.Red("Invalid master password")
				return
			}

			enrollment, err := LoadEnrollment(vaultDir)
			if err != nil {
				color.Red("Failed to load enrollment: %v", err)
				return
			}
			if enrollment == nil {
				fmt.Println("Face ID: Not Enrolled")
			} else {
				fmt.Println("Face ID: Enrolled")
				fmt.Printf("  Enrolled At:   %s\n", enrollment.EnrolledAt.Format("Jan 02, 2006 15:04:05"))
				fmt.Printf("  Device Name:   %s\n", enrollment.DeviceName)
				fmt.Printf("  Model Version: %s\n", enrollment.ModelVersion)
			}
		},
	}

	faceidCmd.AddCommand(enrollCmd, testCmd, removeCmd, statusCmd)
	return faceidCmd
}
