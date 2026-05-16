use std::ffi::{CStr, CString};
use std::os::raw::c_char;
use libc::{size_t, int32_t};

#[no_mangle]
pub unsafe extern "C" fn apm_get_rank_match(query: *const c_char, target: *const c_char) -> int32_t {
    if query.is_null() || target.is_null() {
        return 0;
    }

    let q_str = match CStr::from_ptr(query).to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    let t_str = match CStr::from_ptr(target).to_str() {
        Ok(s) => s,
        Err(_) => return 0,
    };

    rank_match(q_str, t_str) as int32_t
}

fn rank_match(query: &str, target: &str) -> i32 {
    if query.is_empty() {
        return 1;
    }

    let q = query.to_lowercase();
    let t = target.to_lowercase();

    if q == t {
        return 1000;
    }

    let terms: Vec<&str> = q.split_whitespace().collect();
    let mut total_score = 0;
    let mut found_all = true;

    for term in terms {
        let term_score;
        if term == t {
            term_score = 500;
        } else if t.starts_with(term) {
            term_score = 200;
        } else if t.contains(term) {
            term_score = 100;
        } else {
            let mut qi = 0;
            let mut ti = 0;
            let mut match_count = 0;
            let term_chars: Vec<char> = term.chars().collect();
            let target_chars: Vec<char> = t.chars().collect();

            while qi < term_chars.len() && ti < target_chars.len() {
                if term_chars[qi] == target_chars[ti] {
                    match_count += 1;
                    qi += 1;
                }
                ti += 1;
            }

            if match_count == term_chars.len() {
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

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_rank_match() {
        assert_eq!(rank_match("google", "Google"), 1000);
        assert_eq!(rank_match("goo", "Google"), 200);
        assert_eq!(rank_match("ogl", "Google"), 100);
        assert_eq!(rank_match("abc", "Google"), 0);
        assert_eq!(rank_match("g l", "Google"), 300);
    }
}
