use serde::{Serialize, Deserialize};
use std::fs::{self, OpenOptions};
use std::io::{BufRead, BufReader, Write};
use std::path::PathBuf;
use std::time::SystemTime;
use sha2::{Sha256, Digest};
use hmac::{Hmac, Mac};
use rand::RngCore;

type HmacSha256 = Hmac<Sha256>;

#[derive(Serialize, Deserialize, Clone, Debug)]
pub struct LGitCommit {
    pub id: String,
    pub timestamp_ns: u128,
    pub action: String,
    pub vault_path: String,
    pub data_hash: String,
    #[serde(skip_serializing_if = "Option::is_none")]
    pub prev_hash: Option<String>,
    pub hash: String,
    pub signature: String,
    pub snapshot_file: String,
}

pub fn get_apm_config_dir() -> Result<PathBuf, String> {
    if let Some(mut path) = dirs::config_dir() {
        path.push("apm");
        if !path.exists() {
            fs::create_dir_all(&path).map_err(|e| e.to_string())?;
        }
        return Ok(path);
    }
    
    // Fallback to home dir for OSes without standard config dir
    if let Some(mut path) = dirs::home_dir() {
        path.push(".apm");
        if !path.exists() {
            fs::create_dir_all(&path).map_err(|e| e.to_string())?;
        }
        return Ok(path);
    }
    
    Err("Could not determine config directory".to_string())
}

pub fn get_lgit_file() -> Result<PathBuf, String> {
    let dir = get_apm_config_dir()?;
    Ok(dir.join("lgit.jsonl"))
}

pub fn get_lgit_snapshot_dir() -> Result<PathBuf, String> {
    let dir = get_apm_config_dir()?;
    Ok(dir.join("lgit_snapshots"))
}

pub fn load_or_create_signing_key(file_path: &PathBuf) -> Result<Vec<u8>, String> {
    if let Ok(b) = fs::read(file_path) {
        if b.len() >= 32 {
            return Ok(b);
        }
    }

    let mut key = vec![0u8; 32];
    rand::rngs::OsRng.fill_bytes(&mut key);
    fs::write(file_path, &key).map_err(|e| e.to_string())?;
    Ok(key)
}

pub fn get_lgit_signing_key() -> Result<Vec<u8>, String> {
    let dir = get_apm_config_dir()?;
    load_or_create_signing_key(&dir.join("lgit_signing.key"))
}

pub fn get_lgit_commits(limit: usize) -> Result<Vec<LGitCommit>, String> {
    let path = get_lgit_file()?;
    if !path.exists() {
        return Ok(Vec::new());
    }

    let file = fs::File::open(&path).map_err(|e| e.to_string())?;
    let reader = BufReader::new(file);
    let mut commits = Vec::new();

    for line in reader.lines() {
        let line = line.map_err(|e| e.to_string())?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }
        if let Ok(c) = serde_json::from_str::<LGitCommit>(trimmed) {
            commits.push(c);
        }
    }

    if limit > 0 && commits.len() > limit {
        let start = commits.len() - limit;
        commits.drain(0..start);
    }
    Ok(commits)
}

pub fn get_lgit_head() -> Result<Option<LGitCommit>, String> {
    let mut commits = get_lgit_commits(1)?;
    if commits.is_empty() {
        Ok(None)
    } else {
        Ok(Some(commits.pop().unwrap()))
    }
}

pub fn find_lgit_commit_by_prefix(prefix: &str) -> Result<Option<(LGitCommit, usize)>, String> {
    let commits = get_lgit_commits(0)?;
    if commits.is_empty() {
        return Ok(None);
    }

    let prefix = prefix.trim();
    if prefix.is_empty() || prefix.eq_ignore_ascii_case("head") {
        let idx = commits.len() - 1;
        return Ok(Some((commits[idx].clone(), idx)));
    }

    let mut match_idx: Option<usize> = None;
    for (i, c) in commits.iter().enumerate() {
        if c.id.starts_with(prefix) {
            if match_idx.is_some() {
                return Err(format!("ambiguous commit prefix '{}'", prefix));
            }
            match_idx = Some(i);
        }
    }

    match match_idx {
        Some(idx) => Ok(Some((commits[idx].clone(), idx))),
        None => Ok(None),
    }
}

pub fn verify_lgit_commits(commits: &[LGitCommit]) -> Vec<bool> {
    let mut out = vec![false; commits.len()];
    let key = match get_lgit_signing_key() {
        Ok(k) => k,
        Err(_) => return out,
    };

    let mut prev_hash = "".to_string();
    for (i, c) in commits.iter().enumerate() {
        let mut ok = !c.hash.is_empty() && !c.signature.is_empty();
        
        if ok {
            let prev = c.prev_hash.as_deref().unwrap_or("");
            let content = format!("{}:{}:{}:{}:{}:{}:{}", c.id, c.timestamp_ns, c.action, c.vault_path, c.data_hash, prev, c.snapshot_file);
            let expected_hash = hex::encode(Sha256::digest(content.as_bytes()));
            if expected_hash != c.hash {
                ok = false;
            }
        }
        
        if ok {
            if let Ok(mut mac) = <HmacSha256 as Mac>::new_from_slice(&key) {
                mac.update(c.hash.as_bytes());
                let expected_sig = hex::encode(mac.finalize().into_bytes());
                if expected_sig != c.signature {
                    ok = false;
                }
            } else {
                ok = false;
            }
        }
        
        if ok {
            if let Some(ref ph) = c.prev_hash {
                if !ph.is_empty() && *ph != prev_hash {
                    ok = false;
                }
            }
        }
        
        out[i] = ok;
        prev_hash = c.hash.clone();
    }
    out
}

pub fn verify_lgit_history() -> Result<(usize, usize), String> {
    let commits = get_lgit_commits(0)?;
    let flags = verify_lgit_commits(&commits);
    let ok_count = flags.iter().filter(|&&v| v).count();
    Ok((ok_count, commits.len()))
}

pub fn record_lgit_commit(vault_path: &str, data: &[u8], mut action: &str) -> Result<(), String> {
    if data.is_empty() {
        return Ok(());
    }
    if action.is_empty() {
        action = "SAVE";
    }

    let all = get_lgit_commits(0)?;
    let data_hash = hex::encode(Sha256::digest(data));

    let mut prev_hash = "".to_string();
    if let Some(prev) = all.last() {
        prev_hash = prev.hash.clone();
        if prev.data_hash == data_hash && prev.vault_path == vault_path && action == "SAVE" {
            return Ok(());
        }
    }

    let snapshot_dir = get_lgit_snapshot_dir()?;
    if !snapshot_dir.exists() {
        fs::create_dir_all(&snapshot_dir).map_err(|e| e.to_string())?;
    }

    let now = SystemTime::now().duration_since(SystemTime::UNIX_EPOCH).unwrap().as_nanos();
    let id = format!("{}-{}", now, &data_hash[..12]);
    let snapshot_file = snapshot_dir.join(format!("{}.vault", id));
    fs::write(&snapshot_file, data).map_err(|e| e.to_string())?;

    let mut commit = LGitCommit {
        id: id.clone(),
        timestamp_ns: now,
        action: action.to_string(),
        vault_path: vault_path.to_string(),
        data_hash: data_hash.clone(),
        prev_hash: if prev_hash.is_empty() { None } else { Some(prev_hash.clone()) },
        hash: String::new(),
        signature: String::new(),
        snapshot_file: snapshot_file.to_string_lossy().to_string(),
    };

    let ph = commit.prev_hash.as_deref().unwrap_or("");
    let content = format!("{}:{}:{}:{}:{}:{}:{}", commit.id, commit.timestamp_ns, commit.action, commit.vault_path, commit.data_hash, ph, commit.snapshot_file);
    commit.hash = hex::encode(Sha256::digest(content.as_bytes()));

    let key = get_lgit_signing_key()?;
    let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).map_err(|e| e.to_string())?;
    mac.update(commit.hash.as_bytes());
    commit.signature = hex::encode(mac.finalize().into_bytes());

    let line = serde_json::to_string(&commit).map_err(|e| e.to_string())?;
    let mut file = OpenOptions::new()
        .create(true)
        .append(true)
        .open(get_lgit_file()?)
        .map_err(|e| e.to_string())?;
    
    writeln!(file, "{}", line).map_err(|e| e.to_string())?;
    Ok(())
}

pub fn checkout_lgit(vault_path: &str, commit_prefix: &str) -> Result<(), String> {
    let commit_opt = find_lgit_commit_by_prefix(commit_prefix)?;
    if let Some((commit, _)) = commit_opt {
        let data = fs::read(&commit.snapshot_file).map_err(|e| e.to_string())?;
        fs::write(vault_path, &data).map_err(|e| e.to_string())?;
        record_lgit_commit(vault_path, &data, "CHECKOUT")
    } else {
        Err(format!("commit '{}' not found", commit_prefix))
    }
}

pub fn squash_lgit_history(vault_path: &str, mut keep: usize) -> Result<(), String> {
    if keep < 1 {
        keep = 1;
    }
    let commits = get_lgit_commits(0)?;
    if commits.len() <= keep {
        return Ok(());
    }

    let keep_from = commits.len() - keep;
    for c in &commits[..keep_from] {
        if !c.snapshot_file.is_empty() {
            let _ = fs::remove_file(&c.snapshot_file);
        }
    }

    let mut kept = commits[keep_from..].to_vec();
    rewrite_lgit_chain(&mut kept)?;

    if let Some(last) = kept.last() {
        let data = fs::read(&last.snapshot_file).map_err(|e| e.to_string())?;
        record_lgit_commit(vault_path, &data, "SQUASH")?;
    }
    Ok(())
}

pub fn undo_lgit(vault_path: &str) -> Result<(), String> {
    let commits = get_lgit_commits(0)?;
    if commits.len() < 2 {
        return Err("not enough lgit history to undo".to_string());
    }

    let target = &commits[commits.len() - 2];
    let data = fs::read(&target.snapshot_file).map_err(|e| e.to_string())?;
    fs::write(vault_path, &data).map_err(|e| e.to_string())?;
    record_lgit_commit(vault_path, &data, "UNDO")
}

pub fn lgit_status(vault_path: &str) -> Result<(bool, String, String, bool), String> {
    let head_opt = get_lgit_head()?;
    if let Some(head) = head_opt {
        match fs::read(vault_path) {
            Ok(data) => {
                let current_hash = hex::encode(Sha256::digest(data));
                Ok((true, head.id, head.data_hash.clone(), current_hash == head.data_hash))
            }
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
                Ok((true, head.id, head.data_hash.clone(), false))
            }
            Err(e) => Err(e.to_string()),
        }
    } else {
        Ok((false, String::new(), String::new(), false))
    }
}

pub fn prune_lgit_snapshots() -> Result<(usize, usize), String> {
    let commits = get_lgit_commits(0)?;
    use std::collections::HashSet;
    let mut keep = HashSet::new();
    for c in commits {
        if !c.snapshot_file.is_empty() {
            keep.insert(PathBuf::from(c.snapshot_file));
        }
    }

    let snapshot_dir = get_lgit_snapshot_dir()?;
    if !snapshot_dir.exists() {
        return Ok((0, 0));
    }

    let mut removed = 0;
    let mut total = 0;
    
    if let Ok(entries) = fs::read_dir(snapshot_dir) {
        for entry in entries.flatten() {
            if entry.file_type().map(|ft| ft.is_file()).unwrap_or(false) {
                total += 1;
                let path = entry.path();
                if !keep.contains(&path) {
                    if fs::remove_file(path).is_ok() {
                        removed += 1;
                    }
                }
            }
        }
    }

    Ok((removed, total - removed))
}

fn rewrite_lgit_chain(commits: &mut [LGitCommit]) -> Result<(), String> {
    let file_path = get_lgit_file()?;
    if commits.is_empty() {
        fs::write(file_path, "").map_err(|e| e.to_string())?;
        return Ok(());
    }

    let key = get_lgit_signing_key()?;
    let mut prev_hash = "".to_string();

    for c in commits.iter_mut() {
        c.prev_hash = if prev_hash.is_empty() { None } else { Some(prev_hash.clone()) };
        let ph = c.prev_hash.as_deref().unwrap_or("");
        let content = format!("{}:{}:{}:{}:{}:{}:{}", c.id, c.timestamp_ns, c.action, c.vault_path, c.data_hash, ph, c.snapshot_file);
        c.hash = hex::encode(Sha256::digest(content.as_bytes()));

        let mut mac = <HmacSha256 as Mac>::new_from_slice(&key).map_err(|e| e.to_string())?;
        mac.update(c.hash.as_bytes());
        c.signature = hex::encode(mac.finalize().into_bytes());
        prev_hash = c.hash.clone();
    }

    let mut b = String::new();
    for c in commits {
        let line = serde_json::to_string(c).map_err(|e| e.to_string())?;
        b.push_str(&line);
        b.push('\n');
    }
    
    fs::write(file_path, b).map_err(|e| e.to_string())?;
    Ok(())
}
