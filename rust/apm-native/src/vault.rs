use crate::crypto::CryptoProfile;
use serde::{Serialize, Deserialize};
use std::collections::HashMap;

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct Vault {
    pub salt: Vec<u8>,
    pub security_level: i32,
    pub entries: Vec<Entry>,
    pub totp_entries: Vec<TOTPEntry>,
    pub totp_order: Option<Vec<String>>,
    pub totp_domain_links: Option<HashMap<String, String>>,
    pub tokens: Vec<TokenEntry>,
    pub secure_notes: Vec<SecureNoteEntry>,
    pub api_keys: Vec<APIKeyEntry>,
    pub ssh_keys: Vec<SSHKeyEntry>,
    pub wifi_credentials: Vec<WiFiEntry>,
    pub recovery_codes: Vec<RecoveryCodeEntry>,
    pub certificates: Vec<CertificateEntry>,
    pub banking_items: Vec<BankingEntry>,
    pub documents: Vec<DocumentEntry>,
    pub audio_files: Vec<AudioEntry>,
    pub video_files: Vec<VideoEntry>,
    pub photo_files: Vec<PhotoEntry>,
    pub gov_ids: Vec<GovIDEntry>,
    pub medical_records: Vec<MedicalRecordEntry>,
    pub travel_docs: Vec<TravelEntry>,
    pub contacts: Vec<ContactEntry>,
    pub cloud_credentials_items: Vec<CloudCredentialEntry>,
    pub k8s_secrets: Vec<K8sSecretEntry>,
    
    #[serde(skip_serializing_if = "Option::is_none")]
    pub retrieval_key: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_file_id: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_credentials: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub cloud_token: Option<Vec<u8>>,
    #[serde(default)]
    pub failed_attempts: u8,
    #[serde(default)]
    pub emergency_mode: bool,
    #[serde(default)]
    pub decoy_mode: bool,
    #[serde(default)]
    pub decoy_session_count: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub profile: Option<String>,
    #[serde(default)]
    pub autocomplete_enabled: bool,
    #[serde(default)]
    pub autocomplete_window_disabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub vocab_compressed: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_email: Option<String>,
    #[serde(default)]
    pub alerts_enabled: bool,
    #[serde(default)]
    pub anomaly_detection_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub last_cloud_provider: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub drive_sync_mode: Option<String>,
    #[serde(default)]
    pub drive_key_metadata_consent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_token: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub github_repo: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dropbox_token: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dropbox_sync_mode: Option<String>,
    #[serde(default)]
    pub dropbox_key_metadata_consent: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dropbox_file_id: Option<String>,
    
    pub current_space: Option<String>,
    pub spaces: Vec<String>,
    
    pub dek: Option<Vec<u8>>,
    #[serde(skip)]
    pub needs_repair: bool,
    #[serde(skip)]
    pub current_profile_params: Option<CryptoProfile>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_email: Option<String>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_hash: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_slot: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_salt: Option<Vec<u8>>,
    #[serde(skip)]
    pub raw_recovery_key: Option<String>,
    #[serde(skip)]
    pub obfuscated_key: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_token_hash: Option<Vec<u8>>,
    #[serde(default)]
    pub recovery_share_threshold: i32,
    #[serde(default)]
    pub recovery_share_count: i32,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_share_hashes: Option<HashMap<String, Vec<u8>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_code_hashes: Option<Vec<Vec<u8>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_code_used: Option<Vec<bool>>,
    #[serde(default)]
    pub recovery_passkey_enabled: bool,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_passkey_user_id: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_passkey_cred: Option<Vec<u8>>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct Entry {
    pub account: String,
    pub username: String,
    pub password: String,
    pub space: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TOTPEntry {
    pub account: String,
    pub secret: String,
    pub space: Option<String>,
}

#[derive(Serialize, Deserialize, Clone)]
pub struct TokenEntry { pub name: String, pub token: String, pub space: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct SecureNoteEntry { pub name: String, pub content: String, pub space: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct APIKeyEntry { pub name: String, pub key: String, pub space: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct SSHKeyEntry { pub name: String, pub private_key: String, pub space: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct WiFiEntry { pub ssid: String, pub password: String, pub security: String, pub space: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct RecoveryCodeEntry { pub service: String, pub codes: Vec<String>, pub space: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct CertificateEntry { pub label: String, pub cert: String, pub key: String, pub space: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct BankingEntry { pub label: String, pub account_number: String, pub routing_number: String, pub space: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct DocumentEntry { pub name: String, pub path: String, pub space: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct AudioEntry { pub name: String, pub path: String, pub space: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct VideoEntry { pub name: String, pub path: String, pub space: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct PhotoEntry { pub name: String, pub path: String, pub space: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct GovIDEntry { pub name: String, pub id_number: String, pub type_: String, pub space: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct MedicalRecordEntry { pub label: String, pub description: String, pub space: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct TravelEntry { pub label: String, pub details: String, pub space: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct ContactEntry { pub name: String, pub phone: String, pub email: String, pub space: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct CloudCredentialEntry { pub label: String, pub key: String, pub space: Option<String> }
#[derive(Serialize, Deserialize, Clone)]
pub struct K8sSecretEntry { pub name: String, pub value: String, pub space: Option<String> }

// Crypto logic will be added here
