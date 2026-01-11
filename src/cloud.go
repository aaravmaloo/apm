package apm

import (
	"context"
	"crypto/rand"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"github.com/mr-tron/base58/base58"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

const DriveFolderID = "100G-gs-wQnjmGipXdKFBBNd-Qbu6PpYJ"

// GenerateRetrievalKey creates a unique Base58 retrieval key for a vault.
func GenerateRetrievalKey() (string, error) {
	b := make([]byte, 16)
	if _, err := rand.Read(b); err != nil {
		return "", err
	}
	return base58.Encode(b), nil
}

// CloudManager handles Google Drive operations.
type CloudManager struct {
	Service *drive.Service
}

// NewCloudManager initializes a new CloudManager.
func NewCloudManager(ctx context.Context, credentialsPath string) (*CloudManager, error) {
	// Look for token.json in the same directory as credentials.json
	baseDir := filepath.Dir(credentialsPath)
	tokenPath := filepath.Join(baseDir, "token.json")

	if _, err := os.Stat(credentialsPath); os.IsNotExist(err) {
		return nil, fmt.Errorf("credentials file not found at %s", credentialsPath)
	}

	b, err := os.ReadFile(credentialsPath)
	if err != nil {
		return nil, fmt.Errorf("unable to read credentials: %v", err)
	}

	config, err := google.ConfigFromJSON(b, drive.DriveFileScope)
	if err != nil {
		return nil, fmt.Errorf("unable to parse config: %v", err)
	}

	var srv *drive.Service
	if _, err := os.Stat(tokenPath); err == nil {
		// Use existing token.json
		f, _ := os.Open(tokenPath)
		defer f.Close()
		tok := &oauth2.Token{}
		json.NewDecoder(f).Decode(tok)
		client := config.Client(ctx, tok)
		srv, err = drive.NewService(ctx, option.WithHTTPClient(client))
	} else {
		// Fallback to local file (might trigger standard flow if supported by library or fail)
		srv, err = drive.NewService(ctx, option.WithCredentialsFile(credentialsPath))
	}

	if err != nil {
		return nil, fmt.Errorf("unable to retrieve Drive client: %v", err)
	}

	return &CloudManager{Service: srv}, nil
}

// UploadVault uploads the vault to Google Drive and makes it public.
func (cm *CloudManager) UploadVault(vaultPath string) (string, error) {
	f, err := os.Open(vaultPath)
	if err != nil {
		return "", fmt.Errorf("unable to open vault file: %v", err)
	}
	defer f.Close()

	// Initial naming to something random
	driveFile := &drive.File{
		Name:    fmt.Sprintf("vault_pending_%d.bin", time.Now().Unix()),
		Parents: []string{DriveFolderID},
	}

	res, err := cm.Service.Files.Create(driveFile).Media(f).Do()
	if err != nil {
		return "", fmt.Errorf("unable to upload vault: %v", err)
	}

	fileID := res.Id

	// Make it public
	permission := &drive.Permission{
		Type: "anyone",
		Role: "reader",
	}
	_, err = cm.Service.Permissions.Create(fileID, permission).Do()
	if err != nil {
		return "", fmt.Errorf("unable to make file public: %v", err)
	}

	// Rename it to deterministic name: vault_<fileID>.bin
	newName := fmt.Sprintf("vault_%s.bin", fileID)
	_, err = cm.Service.Files.Update(fileID, &drive.File{Name: newName}).Do()
	if err != nil {
		return "", fmt.Errorf("unable to rename file: %v", err)
	}

	return fileID, nil
}

// DownloadVault downloads the vault using OAuth (for verified uploader).
func (cm *CloudManager) DownloadVault(fileID string) ([]byte, error) {
	resp, err := cm.Service.Files.Get(fileID).Download()
	if err != nil {
		return nil, fmt.Errorf("unable to download file: %v", err)
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}

// DownloadPublicVault downloads a publicly available vault without OAuth directly from Drive.
func DownloadPublicVault(fileID string) ([]byte, error) {
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

// SyncVault updates the existing cloud file.
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

// DeleteVault deletes the vault from Google Drive.
func (cm *CloudManager) DeleteVault(fileID string) error {
	err := cm.Service.Files.Delete(fileID).Do()
	if err != nil {
		return fmt.Errorf("unable to delete file %s: %v", fileID, err)
	}
	return nil
}

// ListVaults lists all vaults in the Drive folder.
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
