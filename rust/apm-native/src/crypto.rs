use aes_gcm::{
    aead::{Aead, KeyInit},
    Aes256Gcm, Nonce,
};
use chacha20poly1305::XChaCha20Poly1305;
use argon2::Argon2;
use rand::{rngs::OsRng, RngCore};
use serde::{Deserialize, Serialize};
use sha2::{Sha256, Digest};
use hmac::Mac;
use std::collections::HashMap;

use crate::vault::Vault;

const VAULT_HEADER: &[u8] = b"APMVAULT";
const CURRENT_VERSION: u8 = 4;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct CryptoProfile {
    #[serde(rename = "Name")]
    pub name: String,
    #[serde(rename = "KDF")]
    pub kdf: String,
    #[serde(rename = "Cipher")]
    pub cipher: String,
    #[serde(rename = "Time")]
    pub time: u32,
    #[serde(rename = "Memory")]
    pub memory: u32,
    #[serde(rename = "Parallelism")]
    pub parallelism: u8,
    #[serde(rename = "SaltLen")]
    pub salt_len: usize,
    #[serde(rename = "NonceLen")]
    pub nonce_len: usize,
}

pub const CIPHER_AES_GCM: &str = "aes-gcm";
pub const CIPHER_XCHACHA20_POLY1305: &str = "xchacha20-poly1305";

pub fn get_standard_profile() -> CryptoProfile {
    CryptoProfile {
        name: "standard".to_string(),
        kdf: "argon2id".to_string(),
        cipher: CIPHER_AES_GCM.to_string(),
        time: 3,
        memory: 64 * 1024,
        parallelism: 2,
        salt_len: 16,
        nonce_len: 12,
    }
}

pub fn get_profile(name: &str) -> CryptoProfile {
    match name {
        "standard" => get_standard_profile(),
        "hardened" => CryptoProfile {
            name: "hardened".to_string(),
            kdf: "argon2id".to_string(),
            cipher: CIPHER_AES_GCM.to_string(),
            time: 5,
            memory: 256 * 1024,
            parallelism: 4,
            salt_len: 32,
            nonce_len: 12,
        },
        "paranoid" => CryptoProfile {
            name: "paranoid".to_string(),
            kdf: "argon2id".to_string(),
            cipher: CIPHER_AES_GCM.to_string(),
            time: 6,
            memory: 512 * 1024,
            parallelism: 4,
            salt_len: 32,
            nonce_len: 24,
        },
        "legacy" => CryptoProfile {
            name: "legacy".to_string(),
            kdf: "pbkdf2".to_string(),
            cipher: CIPHER_AES_GCM.to_string(),
            time: 600000,
            memory: 0,
            parallelism: 1,
            salt_len: 16,
            nonce_len: 12,
        },
        _ => get_standard_profile(),
    }
}

pub fn normalize_crypto_profile(mut p: CryptoProfile) -> CryptoProfile {
    if p.kdf.is_empty() { p.kdf = "argon2id".to_string(); }
    if p.cipher.is_empty() { p.cipher = CIPHER_AES_GCM.to_string(); }
    if p.nonce_len == 0 {
        if p.cipher == CIPHER_XCHACHA20_POLY1305 {
            p.nonce_len = 24;
        } else {
            p.nonce_len = 12;
        }
    }
    p
}

pub struct Keys {
    pub encryption_key: [u8; 32],
    pub auth_key: [u8; 32],
    pub validator: [u8; 32],
}

pub fn derive_keys(password: &str, salt: &[u8], time: u32, memory: u32, parallelism: u32) -> Keys {
    let mut output = [0u8; 96];
    let argon2 = Argon2::new(
        argon2::Algorithm::Argon2id,
        argon2::Version::V0x13,
        argon2::Params::new(memory, time, parallelism, Some(96)).unwrap(),
    );
    argon2.hash_password_into(password.as_bytes(), salt, &mut output).expect("Argon2 failed");

    let mut keys = Keys {
        encryption_key: [0; 32],
        auth_key: [0; 32],
        validator: [0; 32],
    };
    keys.encryption_key.copy_from_slice(&output[0..32]);
    keys.auth_key.copy_from_slice(&output[32..64]);
    keys.validator.copy_from_slice(&output[64..96]);
    
    output.fill(0); // Wipe key material
    keys
}

pub fn wipe(b: &mut [u8]) {
    b.fill(0);
}

pub fn calculate_hmac(data: &[u8], key: &[u8]) -> Vec<u8> {
    let mut mac = <hmac::Hmac<Sha256> as Mac>::new_from_slice(key).expect("HMAC can take key of any size");
    mac.update(data);
    mac.finalize().into_bytes().to_vec()
}

pub fn verify_hmac(data: &[u8], expected_mac: &[u8], key: &[u8]) -> bool {
    let calculated = calculate_hmac(data, key);
    if calculated.len() != expected_mac.len() {
        return false;
    }
    let mut res = 0;
    for (a, b) in calculated.iter().zip(expected_mac.iter()) {
        res |= a ^ b;
    }
    res == 0
}

#[derive(Serialize, Deserialize, Default, Clone)]
pub struct RecoveryData {
    #[serde(skip_serializing_if = "Option::is_none")]
    pub email_hash: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub key_hash: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub dek_slot: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub salt: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub obfuscated_key: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_token_hash: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_share_threshold: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_share_count: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_share_hashes: Option<HashMap<String, Vec<u8>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_code_hashes: Option<Vec<Vec<u8>>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_code_used: Option<Vec<bool>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_passkey_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_passkey_user_id: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub recovery_passkey_cred: Option<Vec<u8>>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alerts_enabled: Option<bool>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub security_level: Option<i32>,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub alert_email: Option<String>,
}

fn aead_seal(key: &[u8], profile: &CryptoProfile, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    match profile.cipher.as_str() {
        CIPHER_AES_GCM => {
            if nonce.len() != 12 {
                return Err("aes-gcm requires a 12-byte nonce in the Rust backend".to_string());
            }
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
            let nonce_obj = Nonce::from_slice(nonce);
            cipher.encrypt(nonce_obj, data).map_err(|_| "encryption failed".to_string())
        }
        CIPHER_XCHACHA20_POLY1305 => {
            if nonce.len() != 24 {
                return Err("xchacha20-poly1305 requires a 24-byte nonce".to_string());
            }
            let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
            let nonce_obj = chacha20poly1305::XNonce::from_slice(nonce);
            cipher.encrypt(nonce_obj, data).map_err(|_| "encryption failed".to_string())
        }
        _ => Err(format!("Unsupported cipher: {}", profile.cipher)),
    }
}

fn aead_open(key: &[u8], profile: &CryptoProfile, nonce: &[u8], data: &[u8]) -> Result<Vec<u8>, String> {
    match profile.cipher.as_str() {
        CIPHER_AES_GCM => {
            if nonce.len() != 12 {
                return Err("aes-gcm requires a 12-byte nonce in the Rust backend".to_string());
            }
            let cipher = Aes256Gcm::new_from_slice(key).map_err(|e| e.to_string())?;
            let nonce_obj = Nonce::from_slice(nonce);
            cipher.decrypt(nonce_obj, data).map_err(|_| "decryption failed".to_string())
        }
        CIPHER_XCHACHA20_POLY1305 => {
            if nonce.len() != 24 {
                return Err("xchacha20-poly1305 requires a 24-byte nonce".to_string());
            }
            let cipher = XChaCha20Poly1305::new_from_slice(key).map_err(|e| e.to_string())?;
            let nonce_obj = chacha20poly1305::XNonce::from_slice(nonce);
            cipher.decrypt(nonce_obj, data).map_err(|_| "decryption failed".to_string())
        }
        _ => Err(format!("Unsupported cipher: {}", profile.cipher)),
    }
}

pub fn encrypt_vault(vault: &mut Vault, password: &str) -> Result<Vec<u8>, String> {
    let mut profile = if let Some(ref p) = vault.current_profile_params {
        let mut prof = p.clone();
        if prof.name.is_empty() {
            prof.name = "custom".to_string();
        }
        prof
    } else {
        let name = if let Some(ref n) = vault.profile { n.clone() } else { "standard".to_string() };
        vault.profile = Some(name.clone());
        get_profile(&name)
    };
    
    profile = normalize_crypto_profile(profile);
    vault.current_profile_params = Some(profile.clone());

    let mut salt = vec![0u8; profile.salt_len];
    OsRng.fill_bytes(&mut salt);

    let mut keys = derive_keys(password, &salt, profile.time, profile.memory, profile.parallelism as u32);
    
    let dek = vault.dek.clone().unwrap_or_else(|| {
        let mut d = vec![0u8; 32];
        OsRng.fill_bytes(&mut d);
        d
    });
    vault.dek = Some(dek.clone());

    let json_data = serde_json::to_vec(vault).map_err(|e| e.to_string())?;

    let mut nonce = vec![0u8; profile.nonce_len];
    OsRng.fill_bytes(&mut nonce);
    let ciphertext = aead_seal(&dek, &profile, &nonce, &json_data)?;

    let mut payload = Vec::new();
    payload.extend_from_slice(VAULT_HEADER);
    payload.push(CURRENT_VERSION);

    let enc_profile = serde_json::to_vec(&profile).map_err(|e| e.to_string())?;
    payload.push((enc_profile.len() >> 8) as u8);
    payload.push(enc_profile.len() as u8);
    payload.extend_from_slice(&enc_profile);

    let mut rec = RecoveryData::default();
    if let Some(ref email) = vault.recovery_email {
        rec.email_hash = Some(Sha256::digest(email.to_lowercase().as_bytes()).to_vec());
    }
    if let Some(ref slot) = vault.recovery_slot {
        if !slot.is_empty() {
            rec.dek_slot = Some(slot.clone());
            rec.key_hash = vault.recovery_hash.clone();
            rec.salt = vault.recovery_salt.clone();
        }
    }
    if let Some(ref raw_key) = vault.raw_recovery_key {
        // XORRecoveryKey not implemented here yet, just fallback to obfuscated_key
        let _ = raw_key;
        rec.obfuscated_key = vault.obfuscated_key.clone();
    } else if let Some(ref obf_key) = vault.obfuscated_key {
        rec.obfuscated_key = Some(obf_key.clone());
    }
    // Set other recovery fields...
    rec.alerts_enabled = Some(vault.alerts_enabled);
    rec.security_level = Some(vault.security_level);
    rec.alert_email = vault.alert_email.clone();

    let enc_rec = serde_json::to_vec(&rec).map_err(|e| e.to_string())?;
    payload.push((enc_rec.len() >> 8) as u8);
    payload.push(enc_rec.len() as u8);
    payload.extend_from_slice(&enc_rec);

    payload.extend_from_slice(&salt);
    payload.extend_from_slice(&keys.validator);
    payload.extend_from_slice(&nonce);

    let m_nonce = vec![0u8; profile.nonce_len];
    let master_slot = aead_seal(&keys.encryption_key, &profile, &m_nonce, &dek)?;
    payload.extend_from_slice(&master_slot);
    
    payload.extend_from_slice(&ciphertext);

    let signature = calculate_hmac(&payload, &keys.auth_key);
    payload.extend_from_slice(&signature);

    wipe(&mut keys.encryption_key);
    wipe(&mut keys.auth_key);
    wipe(&mut keys.validator);

    Ok(payload)
}

pub fn decrypt_vault(data: &[u8], password: &str) -> Result<Vault, String> {
    // Basic implementation of V4 decryption
    let header_len = VAULT_HEADER.len();
    if data.len() < header_len || &data[..header_len] != VAULT_HEADER {
        return Err("invalid vault header".to_string());
    }
    
    let mut offset = header_len;
    let version = data[offset];
    offset += 1;
    
    if version != 4 && version != 3 {
        return Err(format!("unsupported vault version: {}", version));
    }
    
    let p_len = ((data[offset] as usize) << 8) | (data[offset+1] as usize);
    offset += 2;
    let p_bytes = &data[offset..offset+p_len];
    let profile: CryptoProfile = serde_json::from_slice(p_bytes).map_err(|e| e.to_string())?;
    let profile = normalize_crypto_profile(profile);
    offset += p_len;
    
    if version == 4 {
        let r_len = ((data[offset] as usize) << 8) | (data[offset+1] as usize);
        offset += 2;
        offset += r_len; // Skip recovery data for now
    }
    
    let salt = &data[offset..offset+profile.salt_len];
    offset += profile.salt_len;
    
    let stored_validator = &data[offset..offset+32];
    offset += 32;
    
    let nonce = &data[offset..offset+profile.nonce_len];
    offset += profile.nonce_len;
    
    let mut keys = derive_keys(password, salt, profile.time, profile.memory, profile.parallelism as u32);
    
    let payload_for_hmac = &data[..data.len()-32];
    let stored_hmac = &data[data.len()-32..];
    
    if !verify_hmac(payload_for_hmac, stored_hmac, &keys.auth_key) {
        wipe(&mut keys.encryption_key);
        wipe(&mut keys.auth_key);
        wipe(&mut keys.validator);
        return Err("vault file has been tampered with or corrupted".to_string());
    }
    
    let mut dek = keys.encryption_key.to_vec();
    
    if version == 4 {
        // Assume master slot size is 32 + 16 (overhead)
        let master_slot_len = 32 + 16; 
        if offset + master_slot_len <= data.len() - 32 {
            let master_slot = &data[offset..offset+master_slot_len];
            let m_nonce = vec![0u8; profile.nonce_len]; // Go code in V4 created new empty mNonce?
            // Actually Go code: dek, err = slotAEAD.Open(nil, mNonce, masterSlot, nil)
            // where mNonce = make([]byte, slotAEAD.NonceSize()) which is 0s
            if let Ok(unwrapped_dek) = aead_open(&keys.encryption_key, &profile, &m_nonce, master_slot) {
                dek = unwrapped_dek;
                offset += master_slot_len;
            } else {
                // Heuristic scan not fully ported yet
                println!("Warning: master slot decryption failed, falling back to heuristic...");
                // Just fallback to key
            }
        }
    }
    
    let ciphertext = &data[offset..data.len()-32];
    let plaintext = aead_open(&dek, &profile, nonce, ciphertext)?;
    
    let vault: Vault = serde_json::from_slice(&plaintext).map_err(|e| e.to_string())?;
    
    wipe(&mut keys.encryption_key);
    wipe(&mut keys.auth_key);
    wipe(&mut keys.validator);
    
    Ok(vault)
}
