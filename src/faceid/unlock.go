//go:build faceid

package faceid

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"

	"golang.org/x/term"
)

var ErrModelsNotFound = fmt.Errorf("face recognition models not found")
var ErrEnrollmentCorrupt = fmt.Errorf("face enrollment data is corrupted")

func RaceUnlock(enrollment *FaceIDEnrollment, modelsDir string, securityProfile string) (string, string, error) {
	if enrollment == nil {
		return "", "", fmt.Errorf("no face enrollment provided")
	}

	if len(enrollment.Embedding) == 0 || len(enrollment.EncryptedMasterPass) == 0 {
		fmt.Printf("  %s⚠  Face enrollment data appears corrupted, using password only%s\n", colorYellow, colorReset)
		return passwordOnlyUnlock()
	}

	if _, err := os.Stat(filepath.Join(modelsDir, "shape_predictor_5_face_landmarks.dat")); os.IsNotExist(err) {
		if err := EnsureModels(modelsDir); err != nil {
			fmt.Printf("  %sℹ  Face ID models missing and auto-download failed: %v%s\n", colorDimGray, err, colorReset)
			fmt.Printf("  %sℹ  Run 'pm faceid enroll' to set up Face ID%s\n", colorDimGray, colorReset)
			return passwordOnlyUnlock()
		}
	}

	fmt.Println("Looking for face...")

	rec, err := NewRecognizer(modelsDir)
	if err != nil {
		return passwordOnlyUnlock()
	}
	defer rec.Close()

	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()

	matched, _, err := rec.VerifyWithContext(ctx, enrollment.verificationEmbeddings(), securityProfile, 24)
	if err != nil || !matched {
		return passwordOnlyUnlock()
	}

	password, err := DecryptMasterPassword(enrollment, enrollment.Embedding)
	if err != nil {
		return passwordOnlyUnlock()
	}

	return "face", password, nil
}

func passwordOnlyUnlock() (string, string, error) {
	fmt.Print("Master password: ")
	if term.IsTerminal(int(os.Stdin.Fd())) {
		bytePassword, err := term.ReadPassword(int(os.Stdin.Fd()))
		if err != nil {
			return "", "", err
		}
		fmt.Println()
		return "password", strings.TrimSpace(string(bytePassword)), nil
	}
	buf := make([]byte, 1024)
	n, err := os.Stdin.Read(buf)
	if err != nil {
		return "", "", err
	}
	return "password", strings.TrimSpace(string(buf[:n])), nil
}
