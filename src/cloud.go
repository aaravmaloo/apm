package apm

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"os"
	"os/exec"
	"runtime"
	"time"

	"strings"

	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox"
	"github.com/dropbox/dropbox-sdk-go-unofficial/v6/dropbox/files"
	"github.com/google/go-github/v60/github"
	"golang.org/x/oauth2"
	"golang.org/x/oauth2/google"
	"google.golang.org/api/drive/v3"
	"google.golang.org/api/option"
)

const DriveFolderID = "100G-gs-wQnjmGipXdKFBBNd-Qbu6PpYJ"

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
	Mode    string // "apm_public" or "self_hosted"
}

func NewGoogleDriveManager(ctx context.Context, credsJSON []byte, tokenJSON []byte, mode string) (*GoogleDriveManager, error) {
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

	return &GoogleDriveManager{Service: srv, Mode: mode}, nil
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

	parent := DriveFolderID
	if cm.Mode == "self_hosted" {
		parent = "root"
	}

	driveFile := &drive.File{
		Name:        randomName,
		Description: HashKey(customKey),
		Parents:     []string{parent},
	}

	res, err := cm.Service.Files.Create(driveFile).Media(f).Do()
	if err != nil {
		return "", fmt.Errorf("unable to upload vault: %v", err)
	}

	fileID := res.Id

	if cm.Mode == "apm_public" {
		permission := &drive.Permission{
			Type: "anyone",
			Role: "reader",
		}
		_, err = cm.Service.Permissions.Create(fileID, permission).Do()
		if err != nil {
			return "", fmt.Errorf("unable to make file public: %v", err)
		}
	}

	return fileID, nil
}

func (cm *GoogleDriveManager) DownloadVault(fileID string) ([]byte, error) {
	return DownloadPublicVault(fileID)
}

func ExtractFileID(input string) string {
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
	parent := DriveFolderID
	if cm.Mode == "self_hosted" {
		parent = "root"
	}

	query := fmt.Sprintf("'%s' in parents and trashed = false", parent)
	list, err := cm.Service.Files.List().Q(query).Fields("files(id, name, description)").Do()
	if err != nil {
		return "", err
	}

	hashedKey := HashKey(key)
	for _, f := range list.Files {
		if f.Description == hashedKey {
			return f.Id, nil
		}
	}

	queryLegacy := fmt.Sprintf("name = 'vault_%s.bin' and '%s' in parents and trashed = false", key, parent)
	listLegacy, err := cm.Service.Files.List().Q(queryLegacy).Fields("files(id, name)").Do()
	if err == nil && len(listLegacy.Files) > 0 {
		return listLegacy.Files[0].Id, nil
	}

	return "", fmt.Errorf("no vault found with key '%s'", key)
}

func DownloadPublicVault(input string) ([]byte, error) {
	fileID := ExtractFileID(input)

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

func PerformDriveAuth(credsJSON []byte) ([]byte, error) {
	config, err := google.ConfigFromJSON(credsJSON, drive.DriveFileScope)
	if err != nil {
		return nil, fmt.Errorf("unable to parse client secret: %v", err)
	}

	config.RedirectURL = "http://localhost:8080"

	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("\nWaiting for authentication in browser...\n")
	fmt.Printf("If the browser does not open, visit: %v\n", authURL)

	codeChan := make(chan string)
	errChan := make(chan error)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code != "" {
			fmt.Fprintf(w, "Authentication successful! You can close this window and return to the terminal.")
			codeChan <- code
		} else {
			fmt.Fprintf(w, "Authentication failed. No code found.")
			errChan <- fmt.Errorf("no code in redirect")
		}
	})

	server := &http.Server{Addr: ":8080", Handler: mux}

	go func() {
		if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
			errChan <- err
		}
	}()

	// Attempt to open browser
	var errOpen error
	switch runtime.GOOS {
	case "linux":
		errOpen = exec.Command("xdg-open", authURL).Start()
	case "windows":
		errOpen = exec.Command("rundll32", "url.dll,FileProtocolHandler", authURL).Start()
	case "darwin":
		errOpen = exec.Command("open", authURL).Start()
	}
	if errOpen != nil {
		fmt.Println("Could not open browser automatically. Please open the link manually.")
	}

	var authCode string
	select {
	case authCode = <-codeChan:

	case err := <-errChan:
		return nil, err
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("authentication timed out")
	}

	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	server.Shutdown(ctx)

	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		return nil, fmt.Errorf("unable to retrieve token from web: %v", err)
	}

	return json.Marshal(tok)
}

func GetDefaultCreds() []byte {
	obf := []byte{209, 136, 195, 196, 217, 222, 203, 198, 198, 207, 206, 136, 144, 209, 136, 201, 198, 195, 207, 196, 222, 245, 195, 206, 136, 144, 136, 159, 146, 158, 158, 153, 147, 146, 155, 152, 152, 155, 156, 135, 216, 159, 156, 199, 222, 205, 193, 218, 220, 198, 217, 206, 194, 154, 152, 197, 201, 195, 222, 146, 153, 220, 207, 157, 156, 199, 206, 206, 204, 220, 223, 158, 132, 203, 218, 218, 217, 132, 205, 197, 197, 205, 198, 207, 223, 217, 207, 216, 201, 197, 196, 222, 207, 196, 222, 132, 201, 197, 199, 136, 134, 136, 201, 198, 195, 207, 196, 222, 245, 217, 207, 201, 216, 207, 222, 136, 144, 136, 237, 229, 233, 249, 250, 242, 135, 252, 154, 196, 158, 230, 227, 253, 147, 239, 196, 147, 153, 240, 205, 230, 154, 227, 218, 254, 195, 250, 201, 242, 211, 195, 159, 236, 217, 136, 134, 136, 216, 207, 206, 195, 216, 207, 201, 222, 245, 223, 216, 195, 217, 136, 144, 241, 136, 194, 222, 222, 218, 144, 133, 133, 198, 197, 201, 203, 198, 194, 197, 217, 222, 136, 247, 134, 136, 203, 223, 222, 194, 245, 223, 216, 195, 136, 144, 136, 194, 222, 222, 218, 217, 144, 133, 133, 203, 201, 201, 197, 223, 196, 222, 217, 132, 205, 197, 197, 205, 198, 207, 132, 201, 197, 199, 133, 197, 133, 197, 203, 223, 222, 194, 152, 133, 203, 223, 222, 194, 136, 134, 136, 222, 197, 193, 207, 196, 245, 223, 216, 195, 136, 144, 136, 194, 222, 222, 218, 217, 144, 133, 133, 197, 203, 223, 222, 194, 152, 132, 205, 197, 197, 205, 198, 207, 203, 218, 195, 217, 132, 201, 197, 199, 133, 222, 197, 193, 207, 196, 136, 215, 215}
	for i := range obf {
		obf[i] ^= 0xAA
	}
	return obf
}

func GetDefaultToken() []byte {
	obf := []byte{209, 136, 216, 207, 204, 216, 207, 217, 194, 245, 222, 197, 193, 207, 196, 136, 144, 136, 155, 133, 133, 154, 205, 197, 231, 227, 236, 135, 200, 218, 158, 227, 226, 203, 233, 205, 243, 227, 235, 248, 235, 235, 237, 232, 235, 249, 228, 221, 236, 135, 230, 147, 227, 216, 239, 155, 230, 198, 242, 226, 220, 218, 228, 158, 200, 193, 235, 146, 203, 155, 157, 254, 135, 228, 193, 230, 221, 252, 210, 152, 233, 155, 156, 153, 219, 231, 153, 203, 154, 250, 229, 223, 228, 254, 225, 224, 222, 197, 211, 226, 228, 194, 248, 252, 193, 240, 154, 233, 230, 251, 155, 253, 227, 226, 135, 254, 210, 224, 201, 208, 217, 136, 134, 136, 222, 197, 193, 207, 196, 245, 222, 211, 218, 207, 136, 144, 136, 232, 207, 203, 216, 207, 216, 136, 215}
	for i := range obf {
		obf[i] ^= 0xAA
	}
	return obf
}

func GetCloudProvider(providerName string, ctx context.Context, credsJSON []byte, tokenJSON []byte, mode string) (CloudProvider, error) {
	fmt.Printf("DEBUG: GetCloudProvider called with providerName='%s' mode='%s'\n", providerName, mode)
	switch strings.ToLower(providerName) {
	case "gdrive", "google":
		if len(credsJSON) == 0 {
			credsJSON = GetDefaultCreds()
		}
		if len(tokenJSON) == 0 {
			tokenJSON = GetDefaultToken()
		}
		if mode == "" {
			mode = "apm_public"
		}
		return NewGoogleDriveManager(ctx, credsJSON, tokenJSON, mode)
	case "github":
		if len(tokenJSON) == 0 {
			return nil, fmt.Errorf("github personal access token missing")
		}
		return NewGitHubManager(ctx, string(tokenJSON))
	case "dropbox":
		if len(tokenJSON) == 0 {
			tokenJSON = GetDefaultDropboxToken()
		}
		return NewDropboxManager(ctx, string(tokenJSON))
	default:
		return nil, fmt.Errorf("unsupported cloud provider: %s", providerName)
	}
}

type DropboxManager struct {
	Client files.Client
	Token  string
}

func NewDropboxManager(ctx context.Context, token string) (*DropboxManager, error) {
	config := dropbox.Config{
		Token: token,
	}
	return &DropboxManager{
		Client: files.New(config),
		Token:  token,
	}, nil
}

func (cm *DropboxManager) UploadVault(vaultPath string, customKey string) (string, error) {
	f, err := os.Open(vaultPath)
	if err != nil {
		return "", err
	}
	defer f.Close()

	fileName := fmt.Sprintf("/v_%s.bin", HashKey(customKey))

	arg := files.NewUploadArg(fileName)
	arg.Mode = &files.WriteMode{Tagged: dropbox.Tagged{Tag: "overwrite"}}

	_, err = cm.Client.Upload(arg, f)
	if err != nil {
		return "", fmt.Errorf("dropbox upload failed: %v", err)
	}
	return fileName, nil
}

func (cm *DropboxManager) DownloadVault(fileID string) ([]byte, error) {
	if !strings.HasPrefix(fileID, "/") {
		fileID = "/" + fileID
	}
	_, content, err := cm.Client.Download(files.NewDownloadArg(fileID))
	if err != nil {
		return nil, fmt.Errorf("dropbox download failed: %v", err)
	}
	defer content.Close()
	return io.ReadAll(content)
}

func (cm *DropboxManager) SyncVault(vaultPath, fileID string) error {
	f, err := os.Open(vaultPath)
	if err != nil {
		return err
	}
	defer f.Close()

	if !strings.HasPrefix(fileID, "/") {
		fileID = "/" + fileID
	}

	arg := files.NewUploadArg(fileID)
	arg.Mode = &files.WriteMode{Tagged: dropbox.Tagged{Tag: "overwrite"}}
	_, err = cm.Client.Upload(arg, f)
	if err != nil {
		return fmt.Errorf("dropbox sync failed: %v", err)
	}
	return nil
}

func (cm *DropboxManager) DeleteVault(fileID string) error {
	if !strings.HasPrefix(fileID, "/") {
		fileID = "/" + fileID
	}
	_, err := cm.Client.DeleteV2(files.NewDeleteArg(fileID))
	if err != nil {
		return fmt.Errorf("dropbox delete failed: %v", err)
	}
	return nil
}

func (cm *DropboxManager) ResolveKeyToID(key string) (string, error) {
	target := fmt.Sprintf("/v_%s.bin", HashKey(key))
	_, err := cm.Client.GetMetadata(files.NewGetMetadataArg(target))
	if err == nil {
		return target, nil
	}
	return "", fmt.Errorf("no vault found for key '%s'", key)
}

func (cm *DropboxManager) ListMarketplacePlugins() ([]string, error) {
	return nil, fmt.Errorf("plugins are only supported on Google Drive")
}

func (cm *DropboxManager) DownloadPlugin(name string, destDir string) error {
	return fmt.Errorf("plugins are only supported on Google Drive")
}

func (cm *DropboxManager) UploadPlugin(name string, pluginPath string) error {
	return fmt.Errorf("plugins are only supported on Google Drive")
}

func GetDefaultDropboxToken() []byte {
	obf := []byte{217, 198, 132, 223, 132, 235, 237, 248, 195, 207, 210, 233, 204, 197, 250, 197, 196, 220, 232, 206, 218, 222, 159, 220, 211, 236, 194, 251, 157, 156, 228, 239, 147, 255, 226, 228, 217, 195, 205, 211, 135, 222, 208, 152, 199, 198, 245, 201, 232, 204, 253, 221, 208, 152, 199, 226, 200, 221, 240, 192, 250, 219, 243, 220, 152, 135, 228, 223, 135, 229, 250, 238, 200, 250, 205, 198, 233, 222, 254, 250, 237, 206, 156, 243, 235, 199, 249, 252, 221, 217, 254, 205, 224, 194, 231, 159, 240, 253, 157, 199, 192, 232, 194, 211, 155, 201, 158, 223, 198, 242, 220, 250, 238, 217, 250, 193, 254, 157, 217, 153, 192, 197, 237, 154, 157, 239, 242, 238, 198, 198, 198, 229, 207, 216, 237, 154, 210, 208, 206, 248, 232, 155, 235, 250, 196, 249, 204, 242, 201, 200, 159, 195, 201, 245, 251, 206, 242, 248, 159, 249, 248, 208, 217, 228, 154, 195, 230, 243, 248, 239, 225, 192, 245, 239, 205, 251, 223, 217, 216, 147, 232, 153, 252, 135, 210, 250, 225, 235, 232, 147, 253, 251, 208, 252, 211, 223, 208, 245, 147, 253, 245, 238, 232, 206, 204, 200, 249, 226, 233, 195, 206, 199, 199, 226, 238, 221, 135, 146, 154, 200, 225, 193, 195, 204, 197, 219, 218, 222, 159, 211, 199, 155, 152, 227, 222, 193, 197, 217, 235, 219, 220, 233, 233, 155, 243, 158, 197, 146, 227, 226, 207, 210, 227, 230, 153, 198, 156, 220, 219, 225, 229, 199, 218, 217, 157, 201, 195, 222, 154, 211, 228, 223, 208, 240, 232, 242, 192, 198, 229, 242, 245, 220, 227, 233, 152, 156, 232, 205, 216, 251, 252, 154, 218, 195, 152, 152, 197, 250, 249, 220, 217, 231, 231, 253, 230, 192, 227, 225, 222, 204, 154, 205, 153, 254, 243, 193, 207, 253, 225, 205, 253, 231, 225, 201, 218, 255, 210, 226, 238, 201, 204, 196, 200, 222, 254, 198, 218, 251, 226, 147, 238, 232, 203, 211, 222, 192, 203, 222, 236, 230, 204, 216, 236, 231, 225, 250, 248, 219, 211, 232, 237, 220, 210, 238, 199, 231, 193, 225, 203, 250, 230, 158, 203, 203, 255, 196, 152, 156, 219, 225, 203, 217, 220, 211, 159, 200, 237, 193, 226, 242, 207, 233, 204, 204, 249, 198, 198, 252, 243, 201, 196, 147, 135, 229, 228, 239, 207, 193, 146, 195, 152, 152, 218, 216, 203, 199, 238, 235, 252, 251, 207, 227, 135, 196, 157, 135, 239, 159, 235, 251, 205, 229, 224, 196, 204, 228, 156, 155, 232, 135, 152, 236, 205, 205, 255, 232, 197, 225, 235, 230, 198, 156, 219, 219, 252, 229, 223, 135, 222, 208, 238, 249, 255, 236, 207, 158, 208, 228, 146, 147, 210, 249, 157, 237, 193, 204, 231, 208, 204, 237, 229, 240, 231, 245, 221, 146, 211, 227, 152, 225, 197, 255, 216, 232, 220, 210, 245, 206, 237, 255, 242, 226, 155, 255, 211, 228, 242, 195, 250, 231, 242, 193, 159, 152, 207, 211, 210, 254, 203, 220, 207, 217, 197, 218, 221, 238, 154, 157, 229, 158, 219, 248, 155, 153, 252, 248, 250, 255, 194, 193, 252, 252, 153, 206, 198, 222, 206, 205, 153, 240, 251, 210, 152, 206, 196, 206, 229, 210, 135, 210, 255, 205, 198, 243, 207, 200, 251, 235, 198, 158, 197, 224, 192, 238, 254, 200, 200, 216, 203, 224, 243, 235, 226, 243, 146, 229, 240, 236, 225, 154, 219, 193, 147, 237, 224, 228, 218, 223, 249, 245, 197, 218, 235, 255, 216, 147, 219, 203, 238, 245, 255, 225, 200, 199, 251, 147, 223, 147, 235, 157, 243, 225, 251, 221, 255, 200, 254, 220, 250, 158, 156, 233, 159, 154, 220, 224, 251, 255, 253, 230, 238, 157, 195, 194, 253, 135, 239, 251, 196, 152, 255, 232, 228, 220, 152, 239, 254, 152, 207, 240, 254, 135, 206, 255, 147, 251, 248, 205, 199, 193, 157, 211, 147, 225, 218, 146, 251, 194, 249, 220, 232, 243, 251, 205, 233, 230, 222, 157, 227, 243, 240, 218, 254, 235, 226, 235, 211, 147, 226, 196, 157, 249, 206, 159, 235, 245, 219, 192, 197, 232, 216, 226, 216, 207, 255, 152, 194, 207, 152, 199, 229, 199, 157, 233, 231, 197, 204, 159, 255, 197, 233, 222, 210, 135, 232, 221, 235, 156, 210, 158, 254, 222, 228, 197, 225, 135, 154, 232, 255, 159, 147, 228, 192, 229, 196, 199, 200, 250, 252, 235, 232, 227, 211, 218, 135, 210, 216, 203, 203, 216, 147, 200, 248, 220, 230, 207, 245, 221, 159, 199, 135, 152, 248, 233, 159, 221, 231, 230, 253, 236, 255, 228, 237, 201, 242, 194, 227, 250, 255, 154, 206, 236, 147, 196, 240, 242, 238, 210, 219, 231, 203, 219, 208, 233, 253, 204, 216, 203, 228, 251, 236, 253, 203, 196, 232, 243, 203, 250, 229, 232, 235, 230, 230, 198, 240, 194, 193, 219, 240, 147, 205, 159, 158, 203, 153, 245, 147, 219, 192, 248, 237, 232, 135, 152, 192, 135, 249, 222, 236, 153, 211, 238, 203, 216, 200, 200, 154, 204, 152, 216, 154, 157, 224, 197, 195, 243, 239, 220, 224, 229, 194, 254, 219, 208, 210, 218, 206, 221, 237, 238, 223, 194, 238, 228, 253, 158, 152, 239, 248, 228, 159, 242, 239, 251, 198, 231, 199, 158, 203, 153, 245, 245, 239, 206, 156, 203, 153, 199, 159, 206, 201, 243, 211, 217, 156, 198, 146, 240, 153, 221, 147, 154, 222, 206, 146, 155, 232, 194, 227, 240, 220, 252, 250, 207, 238, 248, 240, 211, 239, 218, 230, 222, 232, 252, 227, 243, 200, 224, 218, 229, 203, 245, 253, 195, 207, 226, 220, 218, 240, 254, 225, 232, 255, 195, 207, 152, 195, 253, 232, 135, 251, 206, 135, 147, 211, 201, 207, 198, 195, 231, 242, 156, 192, 227, 228, 238, 226, 238, 220, 159, 135, 233, 193, 197, 228, 221, 224, 155, 243, 255, 210, 158, 230, 207, 254, 235, 205, 227, 225, 218, 249, 255, 211, 197, 233, 225, 135, 205, 226, 221, 206, 210, 226, 220, 225, 237, 147, 249, 219, 240, 230, 255, 147, 237, 240, 155, 147, 207, 253, 154, 235, 158, 210, 218, 235, 242, 147, 211, 198, 207, 248, 240, 203, 158, 227, 217, 152, 248, 146, 238, 146, 233, 193, 233, 203, 219, 196, 135, 216, 243, 237, 201, 201, 154, 192, 217, 250, 228, 233, 208, 159, 223, 158, 192, 254, 157, 233, 192, 233, 227, 208, 229, 197, 231, 251, 248, 231, 207, 236, 245, 228, 199, 231, 221, 254, 222, 217, 196, 232, 228, 198, 242, 156, 250, 199, 225, 245, 211, 230, 229, 155, 248, 221, 228, 219, 198, 205, 158, 152, 201, 198, 224, 199, 239, 253, 147, 216, 199, 233, 153, 196, 233, 147, 253, 239, 147, 233, 225, 205, 210, 251, 232, 196, 157, 205, 146, 232, 240, 210, 157, 248, 245, 237, 227, 198, 238, 233, 242, 248, 217, 227, 223, 153, 226, 199, 147, 255, 156, 230, 135, 225, 222, 152, 240, 216, 216, 155, 157, 153, 204, 203, 152, 248, 155, 199, 203, 147, 228, 227, 154, 207, 159, 154, 235, 197, 248, 237, 220, 250, 253, 147, 210, 198, 153, 224, 206, 216, 232, 233, 146, 229, 152, 193, 242, 154, 155, 243, 249, 194, 229, 201, 205, 222, 211, 203, 253, 239, 254, 218, 197, 235, 154, 135, 240, 224, 226, 224, 229, 147, 154, 230, 243, 239, 220, 200, 233, 220, 157, 223, 200, 157, 237, 157, 232, 232, 231, 243, 227, 207, 249, 210, 227, 237, 217, 218, 245, 200, 199, 232, 248, 146, 155, 222, 195, 242, 197, 221, 249, 233, 194, 228, 204, 229, 248, 206, 197, 236, 248, 253, 227, 251, 192, 230, 216, 249, 204, 218, 216, 219, 227, 208, 135, 222, 245, 219, 217, 227, 232, 248, 206, 252, 253, 226, 152, 242, 208, 229, 242, 205, 192, 208, 250, 240, 240, 194, 253, 135, 231, 233, 228, 135, 237, 204, 248, 158, 158, 225, 195, 197, 240, 204, 237, 224, 237, 147, 230, 197, 231, 205, 154, 211, 250, 233, 207, 248, 211, 235, 203, 159, 240, 203, 192, 236, 194, 248, 159, 222, 201, 207, 204, 157, 155, 204, 146, 135, 158, 223, 254, 239, 216, 211, 224, 249, 226, 218, 233, 222, 225, 236, 207, 206, 223, 231, 238, 251, 227, 221, 156, 135, 230, 251, 152, 220, 229, 226, 155, 152, 220, 252, 216, 197, 251, 205, 154, 230, 153, 147, 193, 203, 230, 251, 217, 210, 152, 216, 152, 240, 153, 210, 147, 235, 222, 155, 243, 201, 207, 224, 210, 254, 198, 198, 221, 239, 159, 193, 158, 227, 230, 194, 197, 156, 248, 243, 238, 200, 198, 199, 153, 224, 205}
	for i := range obf {
		obf[i] ^= 0xAA
	}
	return obf
}

func PerformDropboxAuth(config oauth2.Config) ([]byte, error) {
	authURL := config.AuthCodeURL("state-token", oauth2.AccessTypeOffline)
	fmt.Printf("\nWaiting for Dropbox authentication...\n")
	fmt.Printf("Visit: %v\n", authURL)

	codeChan := make(chan string)
	errChan := make(chan error)

	mux := http.NewServeMux()
	mux.HandleFunc("/", func(w http.ResponseWriter, r *http.Request) {
		code := r.URL.Query().Get("code")
		if code != "" {
			fmt.Fprintf(w, "Authentication successful!")
			codeChan <- code
		} else {
			errChan <- fmt.Errorf("no code found")
		}
	})

	server := &http.Server{Addr: ":8080", Handler: mux}
	go server.ListenAndServe()

	// Attempt to open browser
	switch os.Getenv("OS") {
	case "Windows_NT":
		exec.Command("rundll32", "url.dll,FileProtocolHandler", authURL).Start()
	}

	var authCode string
	select {
	case authCode = <-codeChan:
	case err := <-errChan:
		return nil, err
	case <-time.After(5 * time.Minute):
		return nil, fmt.Errorf("timed out")
	}

	server.Shutdown(context.Background())
	tok, err := config.Exchange(context.TODO(), authCode)
	if err != nil {
		return nil, err
	}
	return json.Marshal(tok)
}

type GitHubManager struct {
	Client *github.Client
	Token  string
	Repo   string
	Ctx    context.Context
}

func NewGitHubManager(ctx context.Context, token string) (*GitHubManager, error) {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	return &GitHubManager{
		Client: client,
		Token:  token,
		Ctx:    ctx,
	}, nil
}

func (gm *GitHubManager) SetRepo(repo string) {
	gm.Repo = repo
}

func (gm *GitHubManager) UploadVault(vaultPath string, customKey string) (string, error) {
	content, err := os.ReadFile(vaultPath)
	if err != nil {
		return "", err
	}

	repoParts := strings.Split(gm.Repo, "/")
	if len(repoParts) != 2 {
		return "", fmt.Errorf("invalid repo format, expected owner/repo")
	}
	owner, repo := repoParts[0], repoParts[1]

	_, _, err = gm.Client.Repositories.Get(gm.Ctx, owner, repo)
	if err != nil {
		newRepo := &github.Repository{
			Name:        github.String(repo),
			Private:     github.Bool(true),
			Description: github.String("APM Secure Vault Storage"),
		}
		_, _, err = gm.Client.Repositories.Create(gm.Ctx, "", newRepo)
		if err != nil {
			return "", fmt.Errorf("failed to create private repo: %v", err)
		}
	}

	fileContent, _, _, err := gm.Client.Repositories.GetContents(gm.Ctx, owner, repo, "vault.dat", nil)
	var sha *string
	if err == nil && fileContent != nil {
		sha = fileContent.SHA
	}

	opts := &github.RepositoryContentFileOptions{
		Message: github.String("update vault"),
		Content: content,
		SHA:     sha,
	}

	_, _, err = gm.Client.Repositories.UpdateFile(gm.Ctx, owner, repo, "vault.dat", opts)
	if err != nil {
		_, _, err = gm.Client.Repositories.CreateFile(gm.Ctx, owner, repo, "vault.dat", opts)
		if err != nil {
			return "", fmt.Errorf("failed to upload vault to github: %v", err)
		}
	}

	return gm.Repo, nil
}

func (gm *GitHubManager) DownloadVault(fileID string) ([]byte, error) {
	repoParts := strings.Split(fileID, "/")
	if len(repoParts) != 2 {
		return nil, fmt.Errorf("invalid repo format in fileID")
	}
	owner, repo := repoParts[0], repoParts[1]

	fileContent, _, _, err := gm.Client.Repositories.GetContents(gm.Ctx, owner, repo, "vault.dat", nil)
	if err != nil {
		return nil, fmt.Errorf("failed to get vault from github: %v", err)
	}

	content, err := fileContent.GetContent()
	if err != nil {
		return nil, err
	}

	return []byte(content), nil
}

func (gm *GitHubManager) SyncVault(vaultPath, fileID string) error {
	_, err := gm.UploadVault(vaultPath, "")
	return err
}

func (gm *GitHubManager) DeleteVault(fileID string) error {
	repoParts := strings.Split(fileID, "/")
	if len(repoParts) != 2 {
		return fmt.Errorf("invalid repo format")
	}
	owner, repo := repoParts[0], repoParts[1]

	_, err := gm.Client.Repositories.Delete(gm.Ctx, owner, repo)
	return err
}

func (gm *GitHubManager) ResolveKeyToID(key string) (string, error) {

	return key, nil
}

func (gm *GitHubManager) ListMarketplacePlugins() ([]string, error) {
	return nil, fmt.Errorf("plugins are only supported on Google Drive")
}

func (gm *GitHubManager) DownloadPlugin(name string, destDir string) error {
	return fmt.Errorf("plugins are only supported on Google Drive")
}

func (gm *GitHubManager) UploadPlugin(name string, pluginPath string) error {
	return fmt.Errorf("plugins are only supported on Google Drive")
}
