package tui

import (
	"context"
	"fmt"
	"strings"

	oauth "golang.org/x/oauth2"

	src "github.com/aaravmaloo/apm/src"
)

func setupCloudProvider(vault *src.Vault, masterPassword, vaultPath, provider, mode, retrievalKey, githubToken, githubRepo, dropboxToken, appKey, appSecret string, keyConsent bool) error {
	provider = strings.ToLower(strings.TrimSpace(provider))
	mode = strings.ToLower(strings.TrimSpace(mode))
	if mode == "" {
		mode = "apm_public"
	}

	switch provider {
	case "gdrive":
		var token []byte
		var err error
		if mode == "self_hosted" {
			token, err = src.PerformDriveAuth(src.GetDefaultCreds())
			if err != nil {
				return err
			}
			vault.CloudToken = token
			vault.CloudCredentials = src.GetDefaultCreds()
		} else {
			vault.CloudToken = src.GetDefaultToken()
			vault.CloudCredentials = src.GetDefaultCreds()
		}
		vault.DriveSyncMode = mode
		vault.DriveKeyMetadataConsent = keyConsent

		key := strings.TrimSpace(retrievalKey)
		if keyConsent && key == "" {
			key, err = src.GenerateRetrievalKey()
			if err != nil {
				return err
			}
		}

		cp, err := src.GetCloudProvider("gdrive", context.Background(), vault.CloudCredentials, vault.CloudToken, vault.DriveSyncMode)
		if err != nil {
			return err
		}
		uploadPath, cleanupUpload, err := src.PrepareCloudUploadVaultPath(vault, masterPassword, vaultPath, "gdrive")
		if err != nil {
			return err
		}
		defer cleanupUpload()

		fileID, err := cp.UploadVault(uploadPath, key)
		if err != nil {
			return err
		}
		vault.CloudFileID = fileID
		vault.RetrievalKey = key
		vault.LastCloudProvider = "gdrive"
		return saveVault(vault, masterPassword, vaultPath)

	case "github":
		token := strings.TrimSpace(githubToken)
		repo := strings.TrimSpace(githubRepo)
		if token == "" || repo == "" {
			return fmt.Errorf("github token and repo are required")
		}
		gm, err := src.NewGitHubManager(context.Background(), token)
		if err != nil {
			return err
		}
		gm.SetRepo(repo)
		uploadPath, cleanupUpload, err := src.PrepareCloudUploadVaultPath(vault, masterPassword, vaultPath, "github")
		if err != nil {
			return err
		}
		defer cleanupUpload()

		if _, err := gm.UploadVault(uploadPath, ""); err != nil {
			return err
		}
		vault.GitHubToken = token
		vault.GitHubRepo = repo
		vault.LastCloudProvider = "github"
		return saveVault(vault, masterPassword, vaultPath)

	case "dropbox":
		var token []byte
		var err error
		if mode == "self_hosted" {
			t := strings.TrimSpace(dropboxToken)
			if t != "" {
				token = []byte(t)
			} else {
				if strings.TrimSpace(appKey) == "" || strings.TrimSpace(appSecret) == "" {
					return fmt.Errorf("dropbox app key and app secret are required for self-hosted auth")
				}
				cfg := oauth.Config{
					ClientID:     strings.TrimSpace(appKey),
					ClientSecret: strings.TrimSpace(appSecret),
					Endpoint: oauth.Endpoint{
						AuthURL:  "https://www.dropbox.com/oauth2/authorize",
						TokenURL: "https://api.dropboxapi.com/oauth2/token",
					},
					RedirectURL: "http://localhost:8080",
				}
				token, err = src.PerformDropboxAuth(cfg)
				if err != nil {
					return err
				}
			}
		} else {
			token = src.GetDefaultDropboxToken()
		}

		vault.DropboxToken = token
		vault.DropboxSyncMode = mode
		vault.DropboxKeyMetadataConsent = keyConsent
		key := strings.TrimSpace(retrievalKey)
		if keyConsent && key == "" {
			key, err = src.GenerateRetrievalKey()
			if err != nil {
				return err
			}
		}

		cp, err := src.GetCloudProvider("dropbox", context.Background(), nil, vault.DropboxToken, vault.DropboxSyncMode)
		if err != nil {
			return err
		}
		uploadPath, cleanupUpload, err := src.PrepareCloudUploadVaultPath(vault, masterPassword, vaultPath, "dropbox")
		if err != nil {
			return err
		}
		defer cleanupUpload()

		fileID, err := cp.UploadVault(uploadPath, key)
		if err != nil {
			return err
		}
		vault.DropboxFileID = fileID
		vault.RetrievalKey = key
		vault.LastCloudProvider = "dropbox"
		return saveVault(vault, masterPassword, vaultPath)
	}

	return fmt.Errorf("unsupported provider: %s", provider)
}

func syncCloudProvider(vault *src.Vault, masterPassword, vaultPath, provider string) error {
	provider = strings.ToLower(strings.TrimSpace(provider))
	if provider == "" {
		return fmt.Errorf("provider is required")
	}

	var cp src.CloudProvider
	var err error
	var targetID string

	switch provider {
	case "gdrive":
		if vault.CloudFileID == "" {
			return fmt.Errorf("google drive not initialized")
		}
		cp, err = src.GetCloudProvider("gdrive", context.Background(), vault.CloudCredentials, vault.CloudToken, vault.DriveSyncMode)
		targetID = vault.CloudFileID
	case "github":
		if vault.GitHubToken == "" || vault.GitHubRepo == "" {
			return fmt.Errorf("github not initialized")
		}
		var gm *src.GitHubManager
		gm, err = src.NewGitHubManager(context.Background(), vault.GitHubToken)
		if err == nil {
			gm.SetRepo(vault.GitHubRepo)
			cp = gm
			targetID = vault.GitHubRepo
		}
	case "dropbox":
		if vault.DropboxToken == nil || vault.DropboxFileID == "" {
			return fmt.Errorf("dropbox not initialized")
		}
		cp, err = src.GetCloudProvider("dropbox", context.Background(), nil, vault.DropboxToken, vault.DropboxSyncMode)
		targetID = vault.DropboxFileID
	default:
		return fmt.Errorf("unsupported provider: %s", provider)
	}
	if err != nil {
		return err
	}
	uploadPath, cleanupUpload, err := src.PrepareCloudUploadVaultPath(vault, masterPassword, vaultPath, provider)
	if err != nil {
		return err
	}
	defer cleanupUpload()

	return cp.SyncVault(uploadPath, targetID)
}

func resetCloudMetadata(vault *src.Vault, masterPassword, vaultPath string) error {
	vault.RetrievalKey = ""
	vault.CloudFileID = ""
	vault.LastCloudProvider = ""
	vault.DriveSyncMode = ""
	vault.DriveKeyMetadataConsent = false
	vault.CloudCredentials = nil
	vault.CloudToken = nil
	vault.GitHubToken = ""
	vault.GitHubRepo = ""
	vault.DropboxToken = nil
	vault.DropboxSyncMode = ""
	vault.DropboxKeyMetadataConsent = false
	vault.DropboxFileID = ""
	return saveVault(vault, masterPassword, vaultPath)
}
