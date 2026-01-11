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
	resp, err := cm.Service.Files.Get(fileID).Download()
	if err != nil {
		return nil, fmt.Errorf("unable to download file: %v", err)
	}
	defer resp.Body.Close()

	return io.ReadAll(resp.Body)
}


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