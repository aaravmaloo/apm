package apm

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"time"

	"strings" // Added import

	"github.com/mr-tron/base58/base58"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

const DriveFolderID = "100G-gs-wQnjmGipXdKFBBNd-Qbu6PpYJ"

func GenerateRetrievalKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base58.Encode(b), nil
}

type CloudManager struct {
	Service *drive.Service
}

func NewCloudManager(ctx context.Context, credsJSON []byte, tokenJSON []byte) (*CloudManager, error) {
	if len(credsJSON) == 0 {
		return nil, fmt.Errorf("cloud credentials missing")
	}

	config, err := google.ConfigFromJSON(credsJSON, drive.DriveFileScope)
	if err != nil {
		return nil, fmt.Errorf("unable to parse config: %v", err)
	}

	var client *http.Client
	if len(tokenJSON) > 0 {
		tok := &oauth2.Token{}
		if err := json.Unmarshal(tokenJSON, tok); err != nil {
			return nil, fmt.Errorf("unable to parse token: %v", err)
		}
		client = config.Client(ctx, tok)
	} else {
		return nil, fmt.Errorf("cloud token missing")
	}

	srv, err := drive.NewService(ctx, option.WithHTTPClient(client))
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve Drive client: %v", err)
	}

	return &CloudManager{Service: srv}, nil
}

func (cm *CloudManager) UploadVault(vaultPath string) (string, error) {
	f, err := os.Open(vaultPath)
	if err != nil {
		return "", fmt.Errorf("unable to open vault file: %v", err)
	}
	defer f.Close()

	driveFile := &drive.File{
		Name:    fmt.Sprintf("vault_pending_%d.bin", time.Now().Unix()),
		Parents: []string{DriveFolderID},
	}

	res, err := cm.Service.Files.Create(driveFile).Media(f).Do()
	if err != nil {
		return "", fmt.Errorf("unable to upload vault: %v", err)
	}

	fileID := res.Id

	permission := &drive.Permission{
		Type: "anyone",
		Role: "reader",
	}
	_, err = cm.Service.Permissions.Create(fileID, permission).Do()
	if err != nil {
		return "", fmt.Errorf("unable to make file public: %v", err)
	}

	newName := fmt.Sprintf("vault_%s.bin", fileID)
	_, err = cm.Service.Files.Update(fileID, &drive.File{Name: newName}).Do()
	if err != nil {
		return "", fmt.Errorf("unable to rename file: %v", err)
	}

	return fileID, nil
}

func (cm *CloudManager) DownloadVault(fileID string) ([]byte, error) {
	return DownloadPublicVault(fileID)
}

func extractFileID(input string) string {
	// Handle full URLs
	if strings.Contains(input, "drive.google.com") {
		// Case 1: /file/d/<ID>/view
		if strings.Contains(input, "/file/d/") {
			parts := strings.Split(input, "/file/d/")
			if len(parts) > 1 {
				idPart := parts[1]
				if idx := strings.Index(idPart, "/"); idx != -1 {
					return idPart[:idx]
				}
				if idx := strings.Index(idPart, "?"); idx != -1 {
					return idPart[:idx]
				}
				return idPart
			}
		}
		// Case 2: id=<ID> parameter
		if strings.Contains(input, "id=") {
			parts := strings.Split(input, "id=")
			if len(parts) > 1 {
				idPart := parts[1]
				if idx := strings.Index(idPart, "&"); idx != -1 {
					return idPart[:idx]
				}
				return idPart
			}
		}
	}
	// Assume raw ID if no URL structure found
	return input
}

func DownloadPublicVault(input string) ([]byte, error) {
	fileID := extractFileID(input)
	url := fmt.Sprintf("https://drive.google.com/uc?export=download&id=%s", fileID)
	resp, err := http.Get(url)
	if err != nil {
		return nil, fmt.Errorf("http error: %v", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("bad status code: %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func (cm *CloudManager) SyncVault(vaultPath, fileID string) error {
	f, err := os.Open(vaultPath)
	if err != nil {
		return fmt.Errorf("unable to open vault file: %v", err)
	}
	defer f.Close()

	_, err = cm.Service.Files.Update(fileID, &drive.File{}).Media(f).Do()
	if err != nil {
		return fmt.Errorf("unable to sync vault: %v", err)
	}

	return nil
}

func (cm *CloudManager) DeleteVault(fileID string) error {
	err := cm.Service.Files.Delete(fileID).Do()
	if err != nil {
		return fmt.Errorf("unable to delete file %s: %v", fileID, err)
	}
	return nil
}

func (cm *CloudManager) ListVaults() ([]string, error) {
	query := fmt.Sprintf("'%s' in parents and trashed = false", DriveFolderID)
	list, err := cm.Service.Files.List().Q(query).Do()
	if err != nil {
		return nil, fmt.Errorf("unable to list vaults: %v", err)
	}

	var vaults []string
	for _, f := range list.Files {
		vaults = append(vaults, fmt.Sprintf("%-30s ID: %s", f.Name, f.Id))
	}
	return vaults, nil
}

func GetDefaultCreds() []byte {
	obf := []byte{209, 136, 195, 196, 217, 222, 203, 198, 198, 207, 206, 136, 144, 209, 136, 201, 198, 195, 207, 196, 222, 245, 195, 206, 136, 144, 136, 159, 146, 158, 158, 153, 147, 146, 155, 152, 152, 155, 156, 135, 216, 159, 156, 199, 222, 205, 193, 218, 220, 198, 217, 206, 194, 154, 152, 197, 201, 195, 222, 146, 153, 220, 207, 157, 156, 199, 206, 206, 204, 220, 223, 158, 132, 203, 218, 218, 217, 132, 205, 197, 197, 205, 198, 207, 223, 217, 207, 216, 201, 197, 196, 222, 207, 196, 222, 132, 201, 197, 199, 136, 134, 136, 218, 216, 197, 192, 207, 201, 222, 245, 195, 206, 136, 144, 136, 203, 206, 220, 203, 196, 201, 207, 206, 218, 203, 217, 217, 221, 197, 216, 206, 199, 203, 196, 203, 205, 207, 216, 135, 152, 136, 134, 136, 203, 223, 222, 194, 245, 223, 216, 195, 136, 144, 136, 194, 222, 222, 218, 217, 144, 133, 133, 203, 201, 201, 197, 223, 196, 222, 217, 132, 205, 197, 197, 205, 198, 207, 132, 201, 197, 199, 133, 197, 133, 197, 203, 223, 222, 194, 152, 133, 203, 223, 222, 194, 136, 134, 136, 222, 197, 193, 207, 196, 245, 223, 216, 195, 136, 144, 136, 194, 222, 222, 218, 217, 144, 133, 133, 197, 203, 223, 222, 194, 152, 132, 205, 197, 197, 205, 198, 207, 203, 218, 195, 217, 132, 201, 197, 199, 133, 222, 197, 193, 207, 196, 136, 134, 136, 203, 223, 222, 194, 245, 218, 216, 197, 220, 195, 206, 207, 216, 245, 210, 159, 154, 147, 245, 201, 207, 216, 222, 245, 223, 216, 198, 136, 144, 136, 194, 222, 222, 218, 217, 144, 133, 133, 221, 221, 221, 132, 205, 197, 197, 205, 198, 207, 203, 218, 195, 217, 132, 201, 197, 199, 133, 197, 203, 223, 222, 194, 152, 133, 220, 155, 133, 201, 207, 216, 222, 217, 136, 134, 136, 201, 198, 195, 207, 196, 222, 245, 217, 207, 201, 216, 207, 222, 136, 144, 136, 237, 229, 233, 249, 250, 242, 135, 197, 228, 193, 135, 236, 228, 243, 216, 239, 157, 154, 135, 223, 216, 224, 192, 157, 236, 206, 238, 197, 199, 251, 249, 219, 210, 230, 225, 136, 134, 136, 216, 207, 206, 195, 216, 207, 201, 222, 245, 223, 216, 195, 217, 136, 144, 241, 136, 194, 222, 222, 218, 144, 133, 133, 198, 197, 201, 203, 198, 194, 197, 217, 222, 136, 247, 215, 215}
	for i := range obf {
		obf[i] ^= 0xAA
	}
	return obf
}
func GetDefaultToken() []byte {
	obf := []byte{209, 136, 203, 201, 201, 207, 217, 217, 245, 222, 197, 193, 207, 196, 136, 144, 136, 211, 203, 152, 147, 132, 203, 154, 235, 255, 231, 253, 205, 245, 224, 221, 199, 197, 230, 232, 239, 200, 205, 245, 205, 229, 239, 222, 237, 242, 243, 251, 222, 208, 218, 216, 156, 239, 147, 195, 233, 249, 207, 239, 225, 208, 255, 232, 250, 200, 223, 193, 158, 199, 158, 205, 197, 154, 199, 219, 222, 210, 250, 157, 245, 248, 229, 198, 197, 254, 192, 220, 197, 204, 159, 226, 229, 251, 192, 226, 232, 251, 238, 252, 197, 231, 193, 248, 236, 255, 235, 224, 252, 159, 157, 249, 220, 221, 232, 207, 196, 229, 155, 232, 243, 205, 238, 197, 205, 252, 221, 219, 253, 135, 232, 158, 240, 255, 243, 155, 216, 224, 210, 230, 251, 146, 254, 222, 223, 229, 156, 230, 223, 219, 242, 159, 192, 224, 228, 222, 218, 239, 249, 233, 242, 216, 235, 252, 236, 221, 200, 193, 220, 156, 249, 199, 254, 253, 218, 217, 208, 193, 193, 254, 232, 198, 210, 255, 238, 147, 224, 206, 249, 229, 207, 238, 146, 194, 228, 225, 201, 205, 240, 196, 232, 230, 228, 206, 198, 235, 230, 253, 157, 211, 221, 243, 236, 219, 157, 223, 195, 192, 239, 239, 135, 193, 227, 203, 233, 205, 243, 225, 235, 253, 193, 249, 235, 248, 231, 249, 236, 251, 226, 237, 242, 152, 231, 195, 230, 242, 201, 210, 223, 207, 255, 223, 245, 203, 200, 221, 222, 207, 216, 201, 249, 199, 250, 222, 229, 205, 154, 152, 154, 156, 136, 134, 136, 222, 197, 193, 207, 196, 245, 222, 211, 218, 207, 136, 144, 136, 232, 207, 203, 216, 207, 216, 136, 134, 136, 216, 207, 204, 216, 207, 217, 194, 245, 222, 197, 193, 207, 196, 136, 144, 136, 155, 133, 133, 154, 205, 240, 147, 147, 242, 252, 237, 198, 237, 155, 221, 154, 233, 205, 243, 227, 235, 248, 235, 235, 237, 232, 235, 249, 228, 221, 236, 135, 230, 147, 227, 216, 146, 211, 152, 254, 203, 206, 153, 252, 224, 220, 159, 207, 220, 218, 240, 226, 207, 248, 157, 245, 255, 252, 135, 252, 135, 203, 154, 230, 223, 250, 192, 250, 232, 198, 158, 152, 220, 242, 204, 245, 245, 155, 200, 216, 192, 201, 210, 248, 218, 158, 135, 220, 219, 154, 156, 197, 204, 146, 250, 222, 240, 219, 222, 205, 254, 206, 158, 136, 134, 136, 207, 210, 218, 195, 216, 211, 136, 144, 136, 152, 154, 152, 156, 135, 154, 155, 135, 155, 155, 254, 155, 146, 144, 154, 152, 144, 154, 152, 132, 157, 157, 155, 156, 155, 146, 153, 129, 154, 159, 144, 153, 154, 136, 134, 136, 207, 210, 218, 195, 216, 207, 217, 245, 195, 196, 136, 144, 153, 159, 147, 147, 215, 160}
	for i := range obf {
		obf[i] ^= 0xAA
	}
	return obf
}
