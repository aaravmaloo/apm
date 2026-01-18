package apm

import (
	"bytes"
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"path/filepath"
	"time"

	"strings"

	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

const DriveFolderID = "100G-gs-wQnjmGipXdKFBBNd-Qbu6PpYJ"
const DropboxAppKey = ""

type CloudProvider interface {
	UploadVault(vaultPath string, customKey string) (string, error)
	DownloadVault(fileID string) ([]byte, error)
	SyncVault(vaultPath, fileID string) error
	DeleteVault(fileID string) error
	ResolveKeyToID(key string) (string, error)
	ListMarketplacePlugins() ([]string, error)
	DownloadPlugin(name string, destDir string) error
	UploadPlugin(name string, pluginPath string) error
}

func GenerateRetrievalKey() (string, error) {
	return GenerateRandomWords()
}

type GoogleDriveManager struct {
	Service *drive.Service
}

func NewGoogleDriveManager(ctx context.Context, credsJSON []byte, tokenJSON []byte) (*GoogleDriveManager, error) {
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

	return &GoogleDriveManager{Service: srv}, nil
}

func (cm *GoogleDriveManager) UploadVault(vaultPath string, customKey string) (string, error) {
	f, err := os.Open(vaultPath)
	if err != nil {
		return "", fmt.Errorf("unable to open vault file: %v", err)
	}
	defer f.Close()

	randomName, err := GenerateRandomHex(6)
	if err != nil {
		randomName = fmt.Sprintf("vault_%d", time.Now().Unix())
	} else {
		randomName = fmt.Sprintf("v_%s.bin", randomName)
	}

	driveFile := &drive.File{
		Name:        randomName,
		Description: HashKey(customKey),
		Parents:     []string{DriveFolderID},
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

	return fileID, nil
}

func (cm *GoogleDriveManager) DownloadVault(fileID string) ([]byte, error) {
	return DownloadPublicVault(fileID)
}

func extractFileID(input string) string {
	if strings.Contains(input, "drive.google.com") {
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
	return input
}

func (cm *GoogleDriveManager) ResolveKeyToID(key string) (string, error) {
	query := fmt.Sprintf("'%s' in parents and description = '%s' and trashed = false", DriveFolderID, HashKey(key))
	list, err := cm.Service.Files.List().Q(query).Fields("files(id, name)").Do()
	if err != nil {
		return "", err
	}

	if len(list.Files) == 0 {
		queryLegacy := fmt.Sprintf("name = 'vault_%s.bin' and '%s' in parents and trashed = false", key, DriveFolderID)
		listLegacy, err := cm.Service.Files.List().Q(queryLegacy).Fields("files(id, name)").Do()
		if err == nil && len(listLegacy.Files) > 0 {
			return listLegacy.Files[0].Id, nil
		}
		return "", fmt.Errorf("no vault found with key '%s'", key)
	}

	return list.Files[0].Id, nil
}

func DownloadPublicVault(input string) ([]byte, error) {
	fileID := extractFileID(input)

	if len(fileID) > 20 || strings.Contains(input, "drive.google.com") {
		url := fmt.Sprintf("https://drive.google.com/uc?export=download&id=%s", fileID)
		resp, err := http.Get(url)
		if err != nil {
			return nil, err
		}
		defer resp.Body.Close()
		if resp.StatusCode == http.StatusOK {
			return io.ReadAll(resp.Body)
		}
	}

	return nil, fmt.Errorf("direct download failed for '%s'. please use provider-specific retrieval.", input)
}

func (cm *GoogleDriveManager) SyncVault(vaultPath, fileID string) error {
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

func (cm *GoogleDriveManager) DeleteVault(fileID string) error {
	err := cm.Service.Files.Delete(fileID).Do()
	if err != nil {
		return fmt.Errorf("unable to delete file %s: %v", fileID, err)
	}
	return nil
}

func HashKey(key string) string {
	h := sha256.New()
	h.Write([]byte(key))
	return hex.EncodeToString(h.Sum(nil))
}

func (cm *GoogleDriveManager) ListVaults() ([]string, error) {
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

type DropboxManager struct {
	Token string
}

func NewDropboxManager(token []byte) *DropboxManager {
	return &DropboxManager{Token: strings.TrimSpace(string(token))}
}

func (dm *DropboxManager) UploadVault(vaultPath string, customKey string) (string, error) {
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		return "", err
	}

	randomName, _ := GenerateRandomHex(6)
	if randomName == "" {
		randomName = fmt.Sprintf("v_%d", time.Now().Unix())
	} else {
		randomName = "v_" + randomName + ".bin"
	}

	url := "https://content.dropboxapi.com/2/files/upload"
	req, _ := http.NewRequest("POST", url, strings.NewReader(string(data)))
	req.Header.Set("Authorization", "Bearer "+dm.Token)
	req.Header.Set("Content-Type", "application/octet-stream")

	arg := fmt.Sprintf(`{"path":"/%s","mode":"overwrite","autorename":true,"mute":false,"strict_conflict":false}`, randomName)
	req.Header.Set("Dropbox-API-Arg", arg)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return "", fmt.Errorf("dropbox upload failed: %s", body)
	}

	urlShare := "https://api.dropboxapi.com/2/sharing/create_shared_link_with_settings"
	argShare := fmt.Sprintf(`{"path":"/%s","settings":{"requested_visibility":"public"}}`, randomName)
	reqShare, _ := http.NewRequest("POST", urlShare, strings.NewReader(argShare))
	reqShare.Header.Set("Authorization", "Bearer "+dm.Token)
	reqShare.Header.Set("Content-Type", "application/json")

	respShare, err := http.DefaultClient.Do(reqShare)
	if err != nil {
		return randomName, nil
	}
	defer respShare.Body.Close()

	var resMap map[string]interface{}
	json.NewDecoder(respShare.Body).Decode(&resMap)

	newPath := fmt.Sprintf("/v_%s_%s.bin", randomName[2:8], HashKey(customKey)[:12])
	urlMove := "https://api.dropboxapi.com/2/files/move_v2"
	argMove := fmt.Sprintf(`{"from_path":"/%s","to_path":"%s"}`, randomName, newPath)
	reqMove, _ := http.NewRequest("POST", urlMove, strings.NewReader(argMove))
	reqMove.Header.Set("Authorization", "Bearer "+dm.Token)
	reqMove.Header.Set("Content-Type", "application/json")
	http.DefaultClient.Do(reqMove)

	return newPath, nil
}

func (dm *DropboxManager) DownloadVault(path string) ([]byte, error) {
	url := "https://content.dropboxapi.com/2/files/download"
	req, _ := http.NewRequest("POST", url, nil)
	req.Header.Set("Authorization", "Bearer "+dm.Token)
	req.Header.Set("Dropbox-API-Arg", fmt.Sprintf(`{"path":"%s"}`, path))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dropbox download failed: status %d", resp.StatusCode)
	}

	return io.ReadAll(resp.Body)
}

func (dm *DropboxManager) SyncVault(vaultPath, path string) error {
	data, err := os.ReadFile(vaultPath)
	if err != nil {
		return err
	}

	url := "https://content.dropboxapi.com/2/files/upload"
	req, _ := http.NewRequest("POST", url, strings.NewReader(string(data)))
	req.Header.Set("Authorization", "Bearer "+dm.Token)
	req.Header.Set("Content-Type", "application/octet-stream")

	arg := fmt.Sprintf(`{"path":"%s","mode":"overwrite"}`, path)
	req.Header.Set("Dropbox-API-Arg", arg)

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("dropbox sync failed: %s", body)
	}

	return nil
}

func (dm *DropboxManager) DeleteVault(path string) error {
	url := "https://api.dropboxapi.com/2/files/delete_v2"
	arg := fmt.Sprintf(`{"path":"%s"}`, path)
	req, _ := http.NewRequest("POST", url, strings.NewReader(arg))
	req.Header.Set("Authorization", "Bearer "+dm.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("dropbox delete failed: %s", body)
	}
	return nil
}

func (dm *DropboxManager) EnsurePluginsFolder() error {
	url := "https://api.dropboxapi.com/2/files/create_folder_v2"
	arg := `{"path":"/plugins","autorename":false}`
	req, _ := http.NewRequest("POST", url, strings.NewReader(arg))
	req.Header.Set("Authorization", "Bearer "+dm.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	return nil
}

func (dm *DropboxManager) ListMarketplacePlugins() ([]string, error) {
	url := "https://api.dropboxapi.com/2/files/list_folder"
	arg := `{"path":"/plugins","recursive":false}`
	req, _ := http.NewRequest("POST", url, strings.NewReader(arg))
	req.Header.Set("Authorization", "Bearer "+dm.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("dropbox list plugins failed: code %d", resp.StatusCode)
	}

	var res struct {
		Entries []struct {
			Name string `json:"name"`
		} `json:"entries"`
	}
	json.NewDecoder(resp.Body).Decode(&res)

	var names []string
	for _, e := range res.Entries {
		if strings.HasSuffix(e.Name, ".zip") {
			names = append(names, strings.TrimSuffix(e.Name, ".zip"))
		}
	}
	return names, nil
}

func (dm *DropboxManager) DownloadPlugin(name string, destDir string) error {
	url := "https://content.dropboxapi.com/2/files/download"
	req, _ := http.NewRequest("POST", url, nil)
	req.Header.Set("Authorization", "Bearer "+dm.Token)
	req.Header.Set("Dropbox-API-Arg", fmt.Sprintf(`{"path":"/plugins/%s.zip"}`, name))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("dropbox download plugin failed: code %d", resp.StatusCode)
	}

	tmpZip := filepath.Join(os.TempDir(), name+"_download_dbx.zip")
	out, err := os.Create(tmpZip)
	if err != nil {
		return err
	}
	defer func() {
		out.Close()
		os.Remove(tmpZip)
	}()

	if _, err := io.Copy(out, resp.Body); err != nil {
		return err
	}
	out.Close()

	return unzip(tmpZip, destDir)
}

func (dm *DropboxManager) UploadPlugin(name string, pluginPath string) error {
	dm.EnsurePluginsFolder()

	zipPath := filepath.Join(os.TempDir(), name+"_dbx.zip")
	if err := zipFolder(pluginPath, zipPath); err != nil {
		return err
	}
	defer os.Remove(zipPath)

	data, err := os.ReadFile(zipPath)
	if err != nil {
		return err
	}

	url := "https://content.dropboxapi.com/2/files/upload"
	req, _ := http.NewRequest("POST", url, bytes.NewReader(data))
	req.Header.Set("Authorization", "Bearer "+dm.Token)
	req.Header.Set("Content-Type", "application/octet-stream")
	req.Header.Set("Dropbox-API-Arg", fmt.Sprintf(`{"path":"/plugins/%s.zip","mode":"overwrite"}`, name))

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		body, _ := io.ReadAll(resp.Body)
		return fmt.Errorf("dropbox upload plugin failed: %s", body)
	}
	return nil
}

func (dm *DropboxManager) ResolveKeyToID(key string) (string, error) {
	url := "https://api.dropboxapi.com/2/files/list_folder"
	arg := `{"path":"","recursive":false}`
	req, _ := http.NewRequest("POST", url, strings.NewReader(arg))
	req.Header.Set("Authorization", "Bearer "+dm.Token)
	req.Header.Set("Content-Type", "application/json")

	resp, err := http.DefaultClient.Do(req)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()

	var res struct {
		Entries []struct {
			Name string `json:"name"`
			Path string `json:"path_lower"`
		} `json:"entries"`
	}
	json.NewDecoder(resp.Body).Decode(&res)

	hashPart := HashKey(key)[:12]
	for _, e := range res.Entries {
		if strings.Contains(e.Name, hashPart) {
			return e.Path, nil
		}
		if e.Name == "vault_"+key+".bin" {
			return e.Path, nil
		}
	}

	return "", fmt.Errorf("no vault found for key %s", key)
}

func GetDefaultDropboxToken() []byte {
	obf := []byte{217, 198, 132, 223, 132, 235, 237, 228, 231, 253, 154, 250, 198, 239, 201, 251, 253, 206, 232, 225, 221, 226, 201, 217, 254, 225, 250, 193, 253, 153, 154, 154, 251, 196, 225, 199, 207, 233, 196, 195, 253, 248, 251, 231, 216, 236, 217, 250, 204, 225, 230, 228, 192, 155, 205, 218, 194, 239, 255, 152, 243, 201, 239, 237, 231, 237, 221, 155, 238, 251, 204, 157, 245, 155, 199, 254, 201, 156, 222, 251, 232, 193, 242, 204, 195, 237, 224, 252, 249, 253, 217, 146, 243, 153, 245, 198, 249, 245, 204, 217, 231, 205, 242, 211, 152, 226, 194, 195, 206, 237, 233, 238, 252, 230, 211, 229, 225, 225, 230, 245, 197, 198, 158, 207, 157, 239, 203, 232, 207, 239, 218, 249, 206, 239, 240, 199, 217, 255, 216, 203, 230, 206, 195, 198, 156, 239, 201, 226, 228, 194, 219, 223, 228, 223, 250, 239, 159, 231, 243, 196, 242, 228, 229, 220, 232, 193, 156, 219, 211, 245, 217, 231, 211, 242, 223, 158, 207, 199, 221, 155, 207, 205, 152, 207, 243, 218, 201, 227, 236, 193, 216, 245, 230, 206, 230, 201, 157, 218, 255, 159, 226, 216, 222, 229, 135, 235, 208, 255, 153, 232, 224, 201, 248, 158, 218, 239, 155, 216, 206, 218, 232, 135, 205, 251, 237, 236, 203, 211, 230, 201, 243, 201, 248, 232, 201, 245, 216, 224, 229, 216, 157, 245, 251, 229, 252, 158, 239, 135, 227, 158, 159, 253, 242, 154, 231, 251, 146, 255, 227, 207, 135, 248, 199, 238, 220, 233, 253, 255, 251, 203, 224, 218, 210, 208, 216, 201, 192, 222, 220, 153, 147, 207, 249, 230, 221, 206, 249, 250, 237, 238, 207, 255, 245, 204, 201, 236, 200, 159, 204, 239, 193, 206, 210, 147, 245, 236, 217, 204, 193, 230, 211, 198, 193, 224, 220, 156, 230, 223, 223, 156, 248, 217, 233, 221, 199, 230, 222, 224, 201, 245, 198, 232, 152, 196, 255, 195, 226, 154, 199, 245, 240, 239, 251, 229, 250, 219, 230, 206, 226, 237, 152, 216, 254, 157, 154, 206, 231, 237, 217, 153, 199, 155, 221, 217, 157, 154, 245, 155, 201, 135, 220, 201, 219, 157, 199, 154, 238, 250, 199, 232, 242, 195, 217, 204, 152, 194, 193, 153, 211, 201, 192, 253, 216, 251, 238, 156, 195, 135, 229, 206, 253, 235, 236, 157, 228, 239, 221, 147, 232, 206, 205, 155, 193, 255, 146, 201, 203, 203, 248, 155, 154, 205, 252, 228, 229, 242, 245, 158, 254, 220, 236, 237, 206, 218, 250, 229, 158, 156, 157, 217, 245, 195, 228, 242, 135, 250, 158, 216, 203, 146, 158, 207, 197, 242, 245, 251, 156, 231, 203, 200, 221, 237, 229, 250, 226, 192, 228, 252, 197, 154, 219, 220, 230, 228, 235, 208, 218, 159, 207, 237, 208, 236, 238, 159, 206, 228, 152, 146, 237, 225, 147, 210, 201, 245, 197, 217, 228, 196, 228, 238, 233, 208, 195, 196, 207, 248, 249, 146, 229, 203, 222, 155, 220, 238, 210, 159, 248, 205, 220, 249, 155, 222, 220, 228, 223, 205, 207, 216, 218, 242, 254, 192, 223, 210, 217, 156, 158, 206, 225, 240, 206, 222, 217, 193, 242, 216, 211, 255, 233, 231, 237, 236, 135, 159, 250, 225, 222, 228, 193, 228, 239, 240, 196, 135, 238, 152, 216, 250, 223, 207, 253, 233, 196, 243, 231, 248, 203, 235, 252, 194, 203, 225, 240, 153, 153, 230, 156, 252, 158, 224, 224, 236, 252, 198, 225, 253, 207, 239, 147, 245, 227, 249, 153, 250, 153, 218, 147, 224, 243, 224, 135, 227, 200, 228, 229, 231, 198, 226, 231, 196, 200, 227, 225, 159, 219, 155, 221, 249, 158, 155, 225, 248, 242, 219, 207, 156, 210, 221, 228, 217, 240, 199, 216, 227, 152, 230, 232, 200, 158, 236, 199, 239, 249, 208, 230, 152, 135, 233, 252, 217, 159, 235, 251, 153, 210, 249, 217, 207, 192, 152, 253, 218, 200, 243, 197, 240, 245, 255, 159, 229, 152, 156, 250, 242, 159, 154, 252, 224, 229, 221, 198, 204, 152, 252, 223, 228, 197, 238, 230, 159, 153, 229, 200, 240, 147, 255, 155, 157, 228, 236, 197, 155, 228, 197, 153, 242, 253, 159, 154, 248, 249, 198, 152, 192, 154, 249, 195, 225, 193, 218, 155, 208, 255, 147, 253, 242, 195, 228, 153, 197, 146, 231, 236, 253, 223, 224, 154, 158, 232, 237, 231, 193, 252, 208, 208, 192, 229, 229, 236, 210, 245, 222, 201, 239, 226, 242, 158, 232, 253, 203, 201, 200, 198, 232, 195, 221, 155, 242, 238, 196, 219, 221, 197, 237, 196, 243, 154, 240, 195, 240, 135, 240, 224, 235, 153, 245, 147, 226, 192, 226, 154, 207, 154, 235, 228, 193, 210, 242, 207, 222, 199, 232, 194, 210, 243, 251, 245, 235, 230, 218, 193, 223, 228, 227, 228, 216, 243, 227, 193, 236, 158, 245, 250, 250, 229, 154, 237, 195, 203, 235, 222, 221, 198, 211, 210, 206, 254, 204, 251, 237, 243, 146, 229, 157, 147, 227, 238, 230, 233, 255, 223, 218, 232, 200, 230, 196, 237, 240, 248, 208, 243, 193, 158, 204, 243, 217, 193, 146, 238, 152, 239, 210, 248, 158, 236, 237, 153, 205, 252, 232, 222, 254, 228, 239, 224, 254, 156, 203, 204, 229, 194, 195, 230, 242, 211, 251, 157, 157, 232, 146, 252, 229, 223, 203, 229, 236, 243, 135, 210, 240, 154, 197, 221, 243, 193, 251, 252, 251, 203, 197, 203, 155, 232, 195, 231, 210, 207, 239, 193, 210, 200, 204, 155, 155, 233, 218, 239, 193, 158, 194, 217, 248, 217, 208, 211, 196, 204, 251, 230, 206, 253, 135, 252, 155, 155, 203, 146, 224, 146, 192, 249, 230, 211, 231, 236, 192, 195, 195, 192, 217, 204, 158, 208, 238, 153, 158, 255, 220, 222, 251, 193, 235, 205, 156, 236, 250, 253, 193, 146, 199, 158, 199, 193, 219, 159, 231, 224, 221, 158, 192, 228, 205, 193, 201, 224, 253, 233, 219, 250, 252, 237, 211, 225, 251, 251, 192, 238, 158, 255, 243, 203, 219, 220, 242, 205, 249, 207, 211, 231, 194, 146, 197, 242, 228, 155, 152, 204, 231, 135, 223, 249, 219, 210, 245, 135, 206, 147, 203, 195, 250, 155, 236, 229, 243, 236, 206, 193, 204, 253, 156, 230, 159, 152, 200, 219, 240, 199, 249, 158, 255, 229, 238, 243, 232, 238, 252, 217, 223, 251, 227, 206, 233, 231, 232, 250, 245, 235, 195, 250, 227, 238, 252, 135, 252, 195, 153, 233, 248, 230, 220, 156, 236, 204, 192, 236, 201, 135, 245, 159, 135, 199, 157, 200, 233, 208, 228, 252, 135, 159, 198, 204, 220, 252, 249, 232, 250, 223, 250, 231, 208, 203, 197, 146, 210, 250, 252, 198, 229, 193, 239, 203, 153, 236, 255, 206, 250, 211, 206, 230, 249, 203, 222, 195, 155, 210, 157, 198, 224, 159, 232, 238, 225, 205, 203, 230, 253, 249, 201, 228, 236, 220, 226, 230, 253, 201, 207, 228, 221, 252, 158, 240, 233, 135, 217, 227, 193, 198, 243, 203, 223, 135, 216, 135, 154, 147, 207, 248, 236, 224, 198, 222, 206, 238, 193, 232, 238, 210, 199, 198, 226, 198, 231, 242, 147, 198, 206, 208, 147, 229, 193, 228, 146, 222, 239, 210, 242, 152, 218, 154, 251, 223, 227, 223, 203, 155, 156, 242, 217, 206, 228, 253, 228, 135, 224, 218, 232, 157, 237, 156, 239, 219, 231, 224, 135, 224, 226, 205, 152, 147, 135, 223, 208, 252, 225, 156, 217, 240, 201, 199, 207, 206, 221, 155, 196, 250, 242, 205, 254, 197, 250, 197, 157, 224, 245, 242, 239, 227, 227, 239, 203, 228, 158, 235, 238, 207, 216, 194, 237, 229, 200, 204, 211, 218, 229, 223, 208, 158, 198, 204, 238, 211, 224, 203, 253, 239, 155, 224, 224, 255, 233, 252, 226, 220, 221, 193, 227, 211, 237, 204, 255, 195, 218, 192, 237, 206, 219, 248, 251, 206, 228, 235, 204, 221, 255, 155, 216, 195, 255, 252, 203, 230, 236, 227, 200, 159, 206, 157, 195, 238, 210, 239, 253, 208, 195, 217, 221, 243, 199, 220, 253, 205, 205, 226, 205, 255, 200, 193, 203, 236, 255, 205, 254, 235, 251, 192, 248, 219, 227, 216, 224, 235, 152, 211, 203, 198, 242, 159, 199, 200, 222, 238, 235, 239, 252, 216, 250, 135, 231, 194, 228, 240, 196, 217, 158, 205, 201, 231, 239, 207, 219, 232, 205, 229, 193, 146, 155, 240}
	for i := range obf {
		obf[i] ^= 0xAA
	}
	return obf
}

func GetCloudProvider(providerName string, ctx context.Context, credsJSON []byte, tokenJSON []byte) (CloudProvider, error) {
	switch strings.ToLower(providerName) {
	case "dropbox":
		if len(tokenJSON) == 0 {
			tokenJSON = GetDefaultDropboxToken()
		}
		return NewDropboxManager(tokenJSON), nil
	case "gdrive", "google":
		if len(credsJSON) == 0 {
			credsJSON = GetDefaultCreds()
		}
		if len(tokenJSON) == 0 {
			tokenJSON = GetDefaultToken()
		}
		return NewGoogleDriveManager(ctx, credsJSON, tokenJSON)
	default:
		return nil, fmt.Errorf("unsupported cloud provider: %s", providerName)
	}
}
