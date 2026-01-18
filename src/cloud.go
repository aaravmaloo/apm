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
	return &DropboxManager{Token: string(token)}
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
	obf := []byte{217, 198, 132, 223, 132, 235, 237, 228, 250, 230, 153, 231, 135, 135, 153, 226, 233, 192, 230, 152, 194, 254, 228, 193, 242, 146, 251, 147, 235, 156, 223, 146, 222, 220, 217, 203, 253, 226, 192, 249, 228, 251, 194, 211, 235, 236, 238, 243, 156, 197, 233, 204, 225, 248, 207, 230, 198, 206, 156, 226, 147, 158, 147, 224, 194, 254, 240, 251, 206, 235, 251, 236, 156, 240, 218, 228, 224, 235, 221, 231, 236, 230, 236, 204, 159, 229, 225, 204, 240, 153, 252, 206, 236, 210, 157, 229, 135, 227, 146, 231, 146, 239, 250, 220, 242, 154, 231, 203, 147, 159, 249, 245, 223, 210, 157, 255, 217, 240, 206, 205, 223, 146, 198, 216, 152, 196, 192, 204, 159, 222, 221, 242, 199, 155, 243, 194, 199, 221, 228, 252, 198, 235, 146, 235, 224, 221, 216, 203, 222, 195, 153, 255, 217, 211, 135, 232, 203, 226, 196, 252, 251, 242, 219, 230, 220, 223, 238, 156, 253, 192, 250, 242, 233, 199, 203, 227, 204, 248, 245, 222, 248, 251, 157, 252, 255, 206, 211, 135, 245, 208, 200, 251, 158, 253, 237, 155, 221, 224, 154, 135, 230, 252, 233, 222, 159, 245, 135, 157, 155, 240, 198, 236, 211, 197, 242, 195, 251, 201, 193, 222, 194, 249, 208, 233, 224, 239, 239, 154, 155, 221, 152, 227, 240, 157, 245, 220, 194, 236, 250, 224, 192, 147, 152, 222, 146, 255, 201, 210, 207, 239, 225, 158, 236, 224, 203, 232, 239, 240, 227, 250, 196, 204, 249, 201, 196, 210, 226, 135, 230, 210, 157, 230, 233, 223, 208, 220, 155, 195, 207, 251, 251, 255, 253, 210, 228, 157, 222, 248, 226, 239, 208, 239, 196, 205, 135, 224, 255, 200, 193, 238, 157, 226, 229, 231, 224, 235, 231, 218, 205, 216, 220, 250, 250, 252, 243, 217, 211, 222, 218, 199, 230, 155, 211, 221, 249, 231, 195, 200, 232, 239, 199, 226, 224, 157, 217, 230, 235, 252, 239, 228, 196, 203, 221, 211, 208, 249, 153, 152, 225, 224, 203, 207, 199, 157, 198, 242, 235, 159, 201, 196, 217, 243, 232, 199, 206, 243, 194, 245, 227, 199, 146, 219, 211, 205, 220, 236, 198, 222, 227, 249, 249, 147, 205, 250, 240, 248, 230, 201, 228, 206, 206, 223, 219, 231, 249, 203, 230, 253, 253, 248, 237, 204, 157, 243, 155, 207, 237, 230, 198, 221, 250, 198, 237, 204, 216, 239, 231, 232, 220, 157, 159, 158, 229, 226, 222, 146, 200, 254, 218, 240, 221, 248, 253, 240, 220, 250, 158, 243, 228, 224, 225, 198, 225, 245, 155, 226, 229, 195, 153, 147, 228, 152, 135, 197, 146, 254, 135, 228, 238, 226, 204, 223, 228, 225, 206, 251, 216, 194, 216, 238, 135, 159, 211, 219, 222, 222, 251, 200, 222, 218, 195, 229, 225, 200, 228, 240, 217, 226, 201, 196, 250, 193, 157, 204, 252, 254, 229, 223, 227, 135, 206, 220, 221, 207, 157, 222, 206, 159, 211, 194, 208, 159, 217, 228, 203, 248, 204, 216, 193, 195, 217, 156, 250, 235, 232, 196, 153, 207, 219, 216, 207, 198, 203, 243, 199, 220, 243, 153, 253, 154, 147, 233, 207, 252, 211, 218, 242, 225, 210, 154, 238, 233, 221, 251, 217, 224, 210, 197, 207, 229, 239, 158, 222, 235, 147, 229, 199, 203, 153, 251, 230, 224, 156, 252, 206, 152, 253, 221, 156, 226, 192, 228, 245, 238, 224, 154, 158, 203, 154, 135, 222, 154, 146, 195, 237, 205, 221, 239, 239, 198, 237, 153, 135, 155, 219, 210, 201, 198, 206, 152, 238, 192, 219, 198, 203, 224, 229, 211, 207, 200, 251, 207, 255, 217, 224, 146, 207, 248, 146, 196, 235, 229, 228, 240, 204, 253, 225, 252, 226, 158, 230, 196, 210, 216, 221, 159, 218, 159, 157, 201, 204, 197, 249, 192, 218, 155, 155, 156, 249, 210, 146, 200, 217, 219, 157, 194, 232, 210, 216, 156, 203, 208, 157, 230, 221, 205, 135, 196, 159, 199, 153, 220, 255, 254, 233, 158, 194, 135, 235, 251, 158, 232, 253, 243, 232, 250, 237, 254, 230, 147, 239, 210, 250, 253, 201, 207, 231, 198, 222, 230, 240, 238, 230, 230, 245, 157, 196, 224, 155, 218, 206, 197, 135, 159, 195, 235, 193, 196, 225, 249, 198, 219, 231, 203, 251, 199, 224, 252, 197, 205, 152, 217, 159, 159, 251, 251, 227, 230, 194, 225, 156, 237, 238, 147, 204, 146, 228, 198, 226, 224, 147, 225, 249, 248, 156, 229, 229, 238, 158, 243, 248, 228, 159, 204, 255, 211, 222, 236, 251, 251, 208, 207, 206, 236, 226, 237, 211, 157, 158, 237, 224, 233, 232, 251, 221, 193, 206, 218, 218, 228, 146, 227, 193, 249, 226, 236, 195, 196, 219, 253, 223, 205, 192, 216, 232, 219, 211, 193, 157, 204, 224, 206, 220, 249, 197, 200, 242, 156, 226, 233, 221, 232, 219, 192, 242, 219, 219, 222, 220, 197, 194, 230, 218, 252, 254, 243, 147, 156, 158, 217, 229, 156, 199, 211, 216, 253, 231, 200, 253, 195, 158, 217, 154, 224, 200, 194, 153, 237, 236, 208, 230, 208, 239, 198, 193, 154, 235, 192, 147, 208, 237, 157, 240, 224, 250, 254, 200, 135, 237, 255, 159, 157, 255, 195, 224, 251, 203, 232, 199, 155, 207, 255, 196, 222, 206, 218, 195, 156, 197, 239, 219, 153, 206, 210, 199, 158, 236, 157, 248, 229, 194, 231, 154, 253, 211, 245, 159, 201, 242, 158, 198, 235, 217, 192, 221, 242, 206, 245, 221, 198, 255, 224, 208, 196, 158, 239, 255, 238, 157, 205, 231, 197, 236, 255, 226, 253, 223, 249, 154, 157, 159, 254, 203, 229, 248, 205, 135, 193, 219, 245, 153, 227, 227, 192, 210, 250, 220, 207, 200, 221, 229, 243, 152, 210, 243, 225, 235, 235, 239, 237, 243, 237, 224, 225, 226, 217, 229, 236, 225, 227, 159, 146, 208, 238, 223, 197, 220, 252, 218, 253, 250, 238, 210, 254, 239, 232, 196, 238, 201, 219, 252, 135, 245, 231, 227, 245, 157, 236, 204, 228, 220, 157, 240, 157, 254, 196, 230, 206, 253, 238, 196, 219, 240, 248, 232, 228, 238, 227, 242, 194, 196, 236, 243, 228, 223, 192, 206, 236, 207, 248, 250, 249, 205, 203, 251, 224, 203, 135, 135, 199, 207, 225, 230, 240, 194, 207, 252, 249, 248, 225, 146, 195, 216, 249, 240, 199, 198, 227, 220, 229, 204, 224, 200, 203, 251, 232, 230, 211, 155, 207, 198, 206, 251, 239, 238, 197, 204, 205, 198, 243, 197, 251, 251, 193, 242, 204, 211, 250, 252, 208, 225, 220, 254, 156, 242, 218, 152, 223, 219, 245, 243, 157, 195, 255, 210, 237, 199, 200, 203, 135, 242, 243, 254, 198, 229, 227, 196, 228, 248, 200, 201, 245, 153, 250, 248, 135, 226, 135, 221, 197, 193, 152, 152, 217, 230, 250, 226, 208, 195, 203, 152, 251, 235, 229, 206, 236, 153, 204, 158, 231, 196, 253, 240, 199, 228, 192, 227, 220, 157, 135, 196, 208, 248, 251, 216, 159, 226, 155, 222, 221, 216, 159, 154, 235, 240, 206, 242, 245, 243, 204, 154, 221, 195, 198, 253, 239, 159, 223, 158, 230, 197, 248, 193, 200, 211, 218, 235, 251, 230, 155, 197, 211, 153, 157, 229, 135, 243, 210, 250, 238, 208, 228, 200, 153, 250, 197, 251, 220, 249, 233, 249, 224, 248, 226, 236, 252, 235, 147, 159, 204, 232, 193, 196, 250, 155, 208, 195, 239, 205, 147, 249, 207, 252, 196, 229, 196, 203, 226, 239, 245, 217, 240, 196, 193, 154, 228, 207, 195, 159, 230, 158, 135, 218, 199, 239, 238, 254, 207, 222, 157, 225, 248, 235, 223, 238, 195, 253, 199, 255, 243, 224, 249, 236, 201, 135, 207, 154, 224, 210, 245, 226, 221, 159, 201, 236, 210, 219, 243, 253, 252, 158, 235, 226, 239, 239, 155, 207, 250, 217, 155, 221, 210, 146, 233, 227, 156, 192, 146, 157, 135, 197, 192, 204, 229, 231, 217, 243, 243, 158, 252, 220, 222, 223, 252, 253, 238, 205, 216, 205, 254, 240, 253, 155, 193, 237, 250, 242, 232, 235, 240, 159, 208, 204, 201, 245, 210, 237, 211, 217, 207, 223, 208, 228, 135, 195, 201, 229, 204, 146, 198, 197, 155, 206, 195, 239, 192, 152, 251, 218, 196, 245, 223, 147, 237, 232, 153, 254, 192, 204, 235, 201, 192, 218, 194, 255, 220, 157, 216, 135, 222, 219, 230, 253, 158, 153, 231, 221, 245, 203, 254, 200, 252, 198, 253, 239, 229, 228, 195, 210, 199, 199, 203, 233, 237, 135, 237, 220, 204, 221}
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
