use std::ffi::CStr;
use std::os::raw::c_char;
use libc::{size_t, int32_t};
use std::sync::Mutex;
use std::sync::OnceLock;
use serde::Deserialize;
use rayon::prelude::*;

#[derive(Deserialize)]
struct VaultJson {
    entries: Option<Vec<Entry>>,
    totp_entries: Option<Vec<Entry>>,
    tokens: Option<Vec<NameEntry>>,
    secure_notes: Option<Vec<NameEntry>>,
    api_keys: Option<Vec<NameEntry>>,
    ssh_keys: Option<Vec<NameEntry>>,
    wifi_credentials: Option<Vec<WifiEntry>>,
    recovery_codes: Option<Vec<RecoveryEntry>>,
    certificates: Option<Vec<LabelEntry>>,
    banking_items: Option<Vec<LabelEntry>>,
    documents: Option<Vec<NameEntry>>,
    audio_files: Option<Vec<NameEntry>>,
    video_files: Option<Vec<NameEntry>>,
    photo_files: Option<Vec<NameEntry>>,
    gov_ids: Option<Vec<GovIDEntry>>,
    medical_records: Option<Vec<LabelEntry>>,
    travel_docs: Option<Vec<LabelEntry>>,
    contacts: Option<Vec<NameEntry>>,
    cloud_credentials_items: Option<Vec<LabelEntry>>,
    k8s_secrets: Option<Vec<NameEntry>>,
}

#[derive(Deserialize)]
struct Entry {
    account: Option<String>,
}

#[derive(Deserialize)]
struct NameEntry {
    name: Option<String>,
}

#[derive(Deserialize)]
struct LabelEntry {
    label: Option<String>,
}

#[derive(Deserialize)]
struct WifiEntry {
    ssid: Option<String>,
}

#[derive(Deserialize)]
struct RecoveryEntry {
    service: Option<String>,
}

#[derive(Deserialize)]
struct GovIDEntry {
    id_number: Option<String>,
    name: Option<String>,
}

struct Target {
    identifier: String,
    lower: String,
}

static CACHED_TARGETS: OnceLock<Mutex<Vec<Target>>> = OnceLock::new();

#[no_mangle]
pub unsafe extern "C" fn apm_get_load_vault_json(json_ptr: *const c_char) -> int32_t {
    if json_ptr.is_null() {
        return -1;
    }

    let json_str = match CStr::from_ptr(json_ptr).to_str() {
        Ok(s) => s,
        Err(_) => return -2,
    };

    let vault: VaultJson = match serde_json::from_str(json_str) {
        Ok(v) => v,
        Err(_) => return -3,
    };

    let mut identifiers = Vec::new();

    let mut add = |s: Option<String>| {
        if let Some(val) = s {
            let lower = val.to_lowercase();
            identifiers.push(Target {
                identifier: val,
                lower,
            });
        }
    };

    if let Some(v) = vault.entries { for e in v { add(e.account); } }
    if let Some(v) = vault.totp_entries { for e in v { add(e.account); } }
    if let Some(v) = vault.tokens { for e in v { add(e.name); } }
    if let Some(v) = vault.secure_notes { for e in v { add(e.name); } }
    if let Some(v) = vault.api_keys { for e in v { add(e.name); } }
    if let Some(v) = vault.ssh_keys { for e in v { add(e.name); } }
    if let Some(v) = vault.wifi_credentials { for e in v { add(e.ssid); } }
    if let Some(v) = vault.recovery_codes { for e in v { add(e.service); } }
    if let Some(v) = vault.certificates { for e in v { add(e.label); } }
    if let Some(v) = vault.banking_items { for e in v { add(e.label); } }
    if let Some(v) = vault.documents { for e in v { add(e.name); } }
    if let Some(v) = vault.audio_files { for e in v { add(e.name); } }
    if let Some(v) = vault.video_files { for e in v { add(e.name); } }
    if let Some(v) = vault.photo_files { for e in v { add(e.name); } }
    if let Some(v) = vault.gov_ids { for e in v { add(e.id_number); add(e.name); } }
    if let Some(v) = vault.medical_records { for e in v { add(e.label); } }
    if let Some(v) = vault.travel_docs { for e in v { add(e.label); } }
    if let Some(v) = vault.contacts { for e in v { add(e.name); } }
    if let Some(v) = vault.cloud_credentials_items { for e in v { add(e.label); } }
    if let Some(v) = vault.k8s_secrets { for e in v { add(e.name); } }

    let mutex = CACHED_TARGETS.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut guard) = mutex.lock() {
        *guard = identifiers;
    }

    0
}

#[no_mangle]
pub unsafe extern "C" fn apm_get_search_sorted(
    query: *const c_char,
    top_n: size_t,
    out_indices: *mut int32_t,
    out_count: *mut size_t,
) {
    if query.is_null() || out_indices.is_null() || out_count.is_null() {
        return;
    }

    let q_str = match CStr::from_ptr(query).to_str() {
        Ok(s) => s,
        Err(_) => return,
    };

    if q_str.is_empty() {
        *out_count = 0;
        return;
    }

    let q_lower = q_str.to_lowercase();
    let q_terms: Vec<&str> = q_lower.split_whitespace().collect();
    let q_term_chars: Vec<Vec<char>> = q_terms.iter().map(|t| t.chars().collect()).collect();

    let mutex = match CACHED_TARGETS.get() {
        Some(m) => m,
        None => return,
    };

    if let Ok(guard) = mutex.lock() {
        let mut scored: Vec<(usize, i32)> = guard
            .par_iter()
            .enumerate()
            .filter_map(|(i, target)| {
                let score = rank_match_fast(&q_lower, &q_terms, &q_term_chars, &target.lower);
                if score > 0 {
                    Some((i, score))
                } else {
                    None
                }
            })
            .collect();

        scored.par_sort_unstable_by(|a, b| {
            if a.1 == b.1 {
                guard[a.0].lower.cmp(&guard[b.0].lower)
            } else {
                b.1.cmp(&a.1)
            }
        });

        let result_count = scored.len().min(top_n as usize);
        let out_indices_slice = std::slice::from_raw_parts_mut(out_indices, result_count);

        for i in 0..result_count {
            out_indices_slice[i] = scored[i].0 as int32_t;
        }

        *out_count = result_count as size_t;
    }
}

fn rank_match_fast(q_lower: &str, q_terms: &[&str], q_term_chars: &[Vec<char>], t: &str) -> i32 {
    if q_lower.is_empty() {
        return 1;
    }

    if q_lower == t {
        return 1000;
    }

    let mut total_score = 0;
    let mut found_all = true;

    for i in 0..q_terms.len() {
        let term = q_terms[i];
        let term_score;
        if term == t {
            term_score = 500;
        } else if t.starts_with(term) {
            term_score = 200;
        } else if t.contains(term) {
            term_score = 100;
        } else {
            let mut qi = 0;
            let term_chars = &q_term_chars[i];

            for tc in t.chars() {
                if qi < term_chars.len() && term_chars[qi] == tc {
                    qi += 1;
                }
            }

            if qi == term_chars.len() {
                term_score = 50;
            } else {
                found_all = false;
                break;
            }
        }
        total_score += term_score;
    }

    if !found_all {
        return 0;
    }

    total_score
}

#[no_mangle]
pub unsafe extern "C" fn apm_get_load_targets(targets: *const *const c_char, count: size_t) {
    if targets.is_null() {
        return;
    }

    let mut t_vec = Vec::with_capacity(count as usize);
    let targets_slice = std::slice::from_raw_parts(targets, count as usize);

    for i in 0..count {
        let t_ptr = targets_slice[i];
        if !t_ptr.is_null() {
            if let Ok(s) = CStr::from_ptr(t_ptr).to_str() {
                t_vec.push(Target {
                    identifier: s.to_string(),
                    lower: s.to_lowercase(),
                });
            }
        }
    }

    let mutex = CACHED_TARGETS.get_or_init(|| Mutex::new(Vec::new()));
    if let Ok(mut guard) = mutex.lock() {
        *guard = t_vec;
    }
}

#[no_mangle]
pub unsafe extern "C" fn apm_get_rank_match(query: *const c_char, target: *const c_char) -> int32_t {
    if query.is_null() || target.is_null() {
        return 0;
    }
    let q_str = match CStr::from_ptr(query).to_str() { Ok(s) => s, Err(_) => return 0 };
    let t_str = match CStr::from_ptr(target).to_str() { Ok(s) => s, Err(_) => return 0 };
    let q_lower = q_str.to_lowercase();
    let q_terms: Vec<&str> = q_lower.split_whitespace().collect();
    let q_term_chars: Vec<Vec<char>> = q_terms.iter().map(|t| t.chars().collect()).collect();
    rank_match_fast(&q_lower, &q_terms, &q_term_chars, &t_str.to_lowercase()) as int32_t
}
