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
	Service	*drive.Service
	Mode	string	// "apm_public" or "self_hosted"
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
		Name:	randomName,
		Description:	HashKey(customKey),
		Parents:	[]string{parent},
	}

	res, err := cm.Service.Files.Create(driveFile).Media(f).Do()
	if err != nil {
		return "", fmt.Errorf("unable to upload vault: %v", err)
	}

	fileID := res.Id

	if cm.Mode == "apm_public" {
		permission := &drive.Permission{
			Type:	"anyone",
			Role:	"reader",
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
	default:
		return nil, fmt.Errorf("unsupported cloud provider: %s", providerName)
	}
}

type GitHubManager struct {
	Client	*github.Client
	Token	string
	Repo	string
	Ctx	context.Context
}

func NewGitHubManager(ctx context.Context, token string) (*GitHubManager, error) {
	ts := oauth2.StaticTokenSource(
		&oauth2.Token{AccessToken: token},
	)
	tc := oauth2.NewClient(ctx, ts)
	client := github.NewClient(tc)

	return &GitHubManager{
		Client:	client,
		Token:	token,
		Ctx:	ctx,
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
			Name:	github.String(repo),
			Private:	github.Bool(true),
			Description:	github.String("APM Secure Vault Storage"),
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
		Message:	github.String("update vault"),
		Content:	content,
		SHA:	sha,
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
