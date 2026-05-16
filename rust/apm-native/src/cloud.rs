use std::fs;
use std::path::PathBuf;
use serde::{Deserialize, Serialize};
use reqwest::blocking::Client;
use reqwest::header::{HeaderMap, HeaderValue, AUTHORIZATION, USER_AGENT, ACCEPT};

pub trait CloudProvider {
    fn upload_vault(&self, vault_path: &str, custom_key: &str) -> Result<String, String>;
    fn download_vault(&self, file_id: &str) -> Result<Vec<u8>, String>;
    fn sync_vault(&self, vault_path: &str, file_id: &str) -> Result<(), String>;
    fn delete_vault(&self, file_id: &str) -> Result<(), String>;
    fn resolve_key_to_id(&self, key: &str) -> Result<String, String>;
    fn list_marketplace_plugins(&self) -> Result<Vec<String>, String>;
    fn download_plugin(&self, name: &str, dest_dir: &str) -> Result<(), String>;
    fn upload_plugin(&self, name: &str, plugin_path: &str) -> Result<(), String>;
}

pub struct GitHubManager {
    client: Client,
    token: String,
    repo: String,
}

impl GitHubManager {
    pub fn new(token: &str) -> Result<Self, String> {
        let mut headers = HeaderMap::new();
        headers.insert(
            AUTHORIZATION,
            HeaderValue::from_str(&format!("Bearer {}", token)).map_err(|e| e.to_string())?,
        );
        headers.insert(
            USER_AGENT,
            HeaderValue::from_static("apm-rust-client"),
        );
        headers.insert(
            ACCEPT,
            HeaderValue::from_static("application/vnd.github.v3+json"),
        );

        let client = Client::builder()
            .default_headers(headers)
            .build()
            .map_err(|e| e.to_string())?;

        Ok(Self {
            client,
            token: token.to_string(),
            repo: String::new(),
        })
    }

    pub fn set_repo(&mut self, repo: &str) {
        self.repo = repo.to_string();
    }
}

#[derive(Serialize, Deserialize, Debug)]
struct GithubFile {
    sha: String,
    content: Option<String>,
}

#[derive(Serialize, Deserialize)]
struct GithubCreateRepoReq {
    name: String,
    private: bool,
    description: String,
}

#[derive(Serialize, Deserialize)]
struct GithubUpdateFileReq {
    message: String,
    content: String, // base64
    #[serde(skip_serializing_if = "Option::is_none")]
    sha: Option<String>,
}

impl CloudProvider for GitHubManager {
    fn upload_vault(&self, vault_path: &str, _custom_key: &str) -> Result<String, String> {
        let content = fs::read(vault_path).map_err(|e| e.to_string())?;
        let base64_content = base64::encode(&content);

        let parts: Vec<&str> = self.repo.split('/').collect();
        if parts.len() != 2 {
            return Err("invalid repo format, expected owner/repo".to_string());
        }
        let owner = parts[0];
        let repo_name = parts[1];

        // Ensure repo exists
        let repo_url = format!("https://api.github.com/repos/{}/{}", owner, repo_name);
        let resp = self.client.get(&repo_url).send().map_err(|e| e.to_string())?;

        if !resp.status().is_success() {
            let req = GithubCreateRepoReq {
                name: repo_name.to_string(),
                private: true,
                description: "APM Secure Vault Storage".to_string(),
            };
            self.client.post("https://api.github.com/user/repos")
                .json(&req)
                .send()
                .map_err(|e| e.to_string())?;
        }

        let file_url = format!("https://api.github.com/repos/{}/{}/contents/vault.dat", owner, repo_name);
        
        let mut sha = None;
        if let Ok(file_resp) = self.client.get(&file_url).send() {
            if file_resp.status().is_success() {
                if let Ok(file_info) = file_resp.json::<GithubFile>() {
                    sha = Some(file_info.sha);
                }
            }
        }

        let req = GithubUpdateFileReq {
            message: "update vault".to_string(),
            content: base64_content,
            sha,
        };

        let update_resp = self.client.put(&file_url)
            .json(&req)
            .send()
            .map_err(|e| e.to_string())?;

        if !update_resp.status().is_success() {
            return Err(format!("failed to upload vault to github: {}", update_resp.status()));
        }

        Ok(self.repo.clone())
    }

    fn download_vault(&self, file_id: &str) -> Result<Vec<u8>, String> {
        let parts: Vec<&str> = file_id.split('/').collect();
        if parts.len() != 2 {
            return Err("invalid repo format in fileID".to_string());
        }
        let owner = parts[0];
        let repo_name = parts[1];

        let file_url = format!("https://api.github.com/repos/{}/{}/contents/vault.dat", owner, repo_name);
        let resp = self.client.get(&file_url).send().map_err(|e| e.to_string())?;

        if !resp.status().is_success() {
            return Err(format!("failed to get vault from github: {}", resp.status()));
        }

        let file_info: GithubFile = resp.json().map_err(|e| e.to_string())?;
        let content_str = file_info.content.ok_or_else(|| "no content found".to_string())?;
        // Github API returns base64 string with newlines
        let cleaned = content_str.replace("\n", "").replace("\r", "");
        let decoded = base64::decode(cleaned).map_err(|e| e.to_string())?;

        Ok(decoded)
    }

    fn sync_vault(&self, vault_path: &str, _file_id: &str) -> Result<(), String> {
        self.upload_vault(vault_path, "")?;
        Ok(())
    }

    fn delete_vault(&self, file_id: &str) -> Result<(), String> {
        let parts: Vec<&str> = file_id.split('/').collect();
        if parts.len() != 2 {
            return Err("invalid repo format in fileID".to_string());
        }
        let owner = parts[0];
        let repo_name = parts[1];

        let repo_url = format!("https://api.github.com/repos/{}/{}", owner, repo_name);
        self.client.delete(&repo_url).send().map_err(|e| e.to_string())?;
        Ok(())
    }

    fn resolve_key_to_id(&self, key: &str) -> Result<String, String> {
        Ok(key.to_string())
    }

    fn list_marketplace_plugins(&self) -> Result<Vec<String>, String> {
        Err("plugins are only supported on Google Drive".to_string())
    }

    fn download_plugin(&self, _name: &str, _dest_dir: &str) -> Result<(), String> {
        Err("plugins are only supported on Google Drive".to_string())
    }

    fn upload_plugin(&self, _name: &str, _plugin_path: &str) -> Result<(), String> {
        Err("plugins are only supported on Google Drive".to_string())
    }
}
