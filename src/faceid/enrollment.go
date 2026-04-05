//go:build faceid

package faceid

import (
	"crypto/aes"
	"crypto/cipher"
	"crypto/rand"
	"crypto/sha256"
	"encoding/binary"
	"encoding/json"
	"fmt"
	"io"
	"math"
	"os"
	"path/filepath"
	"time"
)

type FaceIDEnrollment struct {
	Embedding           []float32   `json:"embedding"`
	VerificationSamples [][]float32 `json:"verification_samples,omitempty"`
	EncryptedMasterPass []byte      `json:"encrypted_master"`
	EnrolledAt          time.Time   `json:"enrolled_at"`
	DeviceName          string      `json:"device_name"`
	ModelVersion        string      `json:"model_version"`
}

func EnrollFace(masterPassword string, vaultDir string, modelsDir string, profile string) (*FaceIDEnrollment, error) {
	if modelsDir == "" {
		modelsDir = filepath.Join(vaultDir, "faceid", "models")
	}
	if err := EnsureModels(modelsDir); err != nil {
		return nil, err
	}

	rec, err := NewRecognizer(modelsDir)
	if err != nil {
		return nil, err
	}
	defer rec.Close()

	fmt.Println("  Capturing face frames...")
	embedding, verificationSamples, err := rec.Enroll(12)
	if err != nil {
		return nil, fmt.Errorf("enrollment failed: %w", err)
	}

	encryptedPass, err := encryptWithEmbedding(embedding, []byte(masterPassword))
	if err != nil {
		return nil, fmt.Errorf("failed to encrypt master password: %w", err)
	}

	hostname, _ := os.Hostname()

	enrollment := &FaceIDEnrollment{
		Embedding:           embedding,
		VerificationSamples: verificationSamples,
		EncryptedMasterPass: encryptedPass,
		EnrolledAt:          time.Now(),
		DeviceName:          hostname,
		ModelVersion:        "dlib_resnet_v1",
	}

	enrollmentPath := filepath.Join(vaultDir, "faceid", "enrollment.json")
	if err := os.MkdirAll(filepath.Dir(enrollmentPath), 0700); err != nil {
		return nil, fmt.Errorf("failed to create enrollment directory: %w", err)
	}
	data, err := json.MarshalIndent(enrollment, "", "  ")
	if err != nil {
		return nil, fmt.Errorf("failed to encode enrollment: %w", err)
	}

	if err := os.WriteFile(enrollmentPath, data, 0600); err != nil {
		return nil, fmt.Errorf("failed to write enrollment: %w", err)
	}

	return enrollment, nil
}

func LoadEnrollment(vaultDir string) (*FaceIDEnrollment, error) {
	enrollmentPath := filepath.Join(vaultDir, "faceid", "enrollment.json")
	data, err := os.ReadFile(enrollmentPath)
	if err != nil {
		if os.IsNotExist(err) {
			return nil, nil
		}
		return nil, err
	}

	var enrollment FaceIDEnrollment
	if err := json.Unmarshal(data, &enrollment); err != nil {
		return nil, fmt.Errorf("failed to parse enrollment: %w", err)
	}

	return &enrollment, nil
}

func RemoveEnrollment(vaultDir string) error {
	enrollmentPath := filepath.Join(vaultDir, "faceid", "enrollment.json")
	return os.Remove(enrollmentPath)
}

func DecryptMasterPassword(enrollment *FaceIDEnrollment, verifiedEmbedding []float32) (string, error) {
	key := embeddingToKey(enrollment.Embedding)
	defer wipeBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return "", err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return "", err
	}

	nonceSize := gcm.NonceSize()
	if len(enrollment.EncryptedMasterPass) < nonceSize {
		return "", fmt.Errorf("encrypted master password data is corrupted")
	}

	nonce := enrollment.EncryptedMasterPass[:nonceSize]
	ciphertext := enrollment.EncryptedMasterPass[nonceSize:]

	plaintext, err := gcm.Open(nil, nonce, ciphertext, nil)
	if err != nil {
		return "", fmt.Errorf("failed to decrypt master password from face enrollment: %w", err)
	}

	return string(plaintext), nil
}

func encryptWithEmbedding(embedding []float32, plaintext []byte) ([]byte, error) {
	key := embeddingToKey(embedding)
	defer wipeBytes(key)

	block, err := aes.NewCipher(key)
	if err != nil {
		return nil, err
	}

	gcm, err := cipher.NewGCM(block)
	if err != nil {
		return nil, err
	}

	nonce := make([]byte, gcm.NonceSize())
	if _, err := io.ReadFull(rand.Reader, nonce); err != nil {
		return nil, err
	}

	ciphertext := gcm.Seal(nil, nonce, plaintext, nil)
	result := append(nonce, ciphertext...)
	return result, nil
}

func embeddingToKey(embedding []float32) []byte {
	buf := make([]byte, len(embedding)*4)
	for i, v := range embedding {
		bits := math.Float32bits(v)
		binary.LittleEndian.PutUint32(buf[i*4:], bits)
	}
	hash := sha256.Sum256(buf)
	key := make([]byte, 32)
	copy(key, hash[:])
	return key
}

func wipeBytes(b []byte) {
	for i := range b {
		b[i] = 0
	}
}

func (e *FaceIDEnrollment) verificationEmbeddings() [][]float32 {
	if e == nil {
		return nil
	}
	if len(e.VerificationSamples) > 0 {
		return e.VerificationSamples
	}
	if len(e.Embedding) == 0 {
		return nil
	}
	return [][]float32{e.Embedding}
}
