//go:build !faceid

package faceid

import (
	"errors"
	"time"

	"github.com/spf13/cobra"
)

var ErrNotCompiled = errors.New("apm was compiled without Face ID support")

type FaceIDEnrollment struct {
	Embedding           []float32 `json:"embedding"`
	EncryptedMasterPass []byte    `json:"encrypted_master"`
	EnrolledAt          time.Time `json:"enrolled_at"`
	DeviceName          string    `json:"device_name"`
	ModelVersion        string    `json:"model_version"`
}

func LoadEnrollment(vaultDir string) (*FaceIDEnrollment, error) {
	return nil, nil
}

func RemoveEnrollment(vaultDir string) error {
	return nil
}

func EnrollFace(masterPassword string, vaultDir string, modelsDir string, profile string) (*FaceIDEnrollment, error) {
	return nil, ErrNotCompiled
}

func EnsureModels(modelsDir string) error {
	return ErrNotCompiled
}

func RaceUnlock(enrollment *FaceIDEnrollment, modelsDir string, securityProfile string) (string, string, error) {
	return "", "", ErrNotCompiled
}

func BuildFaceIDCmd(vaultPath string, readPasswordFunc func() (string, error), getModelsDir func() string) *cobra.Command {
	cmd := &cobra.Command{
		Use:   "faceid",
		Short: "Manage Face ID authentication (Not compiled)",
		RunE: func(cmd *cobra.Command, args []string) error {
			return ErrNotCompiled
		},
	}
	return cmd
}
