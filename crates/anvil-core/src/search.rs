//! Client-side fuzzy search (`nucleo-matcher`) and strict domain matching (`eTLD+1`).

use std::collections::HashMap;
use std::net::IpAddr;

use nucleo_matcher::pattern::{CaseMatching, Normalization, Pattern};
use nucleo_matcher::{Config, Matcher, Utf32Str};
use regex::RegexBuilder;
use serde::{Deserialize, Serialize};
use url::Url;
use uuid::Uuid;

use crate::models::{ItemUri, UriMatchMode, VaultFolder, VaultItem};

const MAX_REGEX_PATTERN_LEN: usize = 256;
const MAX_REGEX_SIZE_LIMIT: usize = 1 << 16;
const MAX_SEARCH_HAYSTACK_CHARS: usize = 2048;

/// Ranked search result emitted by `search_items`.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct SearchHit {
    pub item_id: Uuid,
    pub score: u32,
}

/// Parses a URL (or bare domain/host) and extracts its normalized lowercase host.
pub fn extract_host(input: &str) -> Option<String> {
    let trimmed = input.trim();
    if trimmed.is_empty() {
        return None;
    }

    let parsed = if trimmed.contains("://") {
        Url::parse(trimmed).ok()?
    } else {
        Url::parse(&format!("https://{trimmed}")).ok()?
    };

    let host = parsed.host_str()?;
    let normalized = host
        .trim_start_matches('[')
        .trim_end_matches(']')
        .trim_end_matches('.')
        .to_ascii_lowercase();

    if normalized.is_empty() {
        None
    } else {
        Some(normalized)
    }
}

/// Extracts the registrable `eTLD+1` base domain via the Public Suffix List (handling `.co.uk`, `.github.io`, etc.).
pub fn extract_base_domain(input: &str) -> Option<String> {
    let host = extract_host(input)?;
    if host == "localhost" || host.parse::<IpAddr>().is_ok() || !host.contains('.') {
        return Some(host);
    }
    psl::domain_str(&host).map(str::to_owned).or(Some(host))
}

/// Evaluates whether a stored `ItemUri` matches the active target URL under its matching rule.
pub fn uri_matches(item_uri: &ItemUri, target_url: &str) -> bool {
    uri_match_rank(item_uri, target_url).is_some()
}

fn uri_match_rank(item_uri: &ItemUri, target_url: &str) -> Option<u32> {
    let stored = item_uri.uri.trim();
    let target = target_url.trim();
    if stored.is_empty() || target.is_empty() {
        return None;
    }

    match item_uri.match_mode {
        UriMatchMode::Never => None,
        UriMatchMode::Exact => stored.eq_ignore_ascii_case(target).then_some(40),
        UriMatchMode::StartsWith => {
            let stored_lower = stored.to_ascii_lowercase();
            let target_lower = target.to_ascii_lowercase();
            target_lower.starts_with(&stored_lower).then_some(30)
        }
        UriMatchMode::Host => {
            let h1 = extract_host(stored)?;
            let h2 = extract_host(target)?;
            (h1 == h2).then_some(20)
        }
        UriMatchMode::BaseDomain => {
            let d1 = extract_base_domain(stored)?;
            let d2 = extract_base_domain(target)?;
            (d1 == d2).then_some(10)
        }
        UriMatchMode::Regex => {
            if stored.len() > MAX_REGEX_PATTERN_LEN {
                return None;
            }
            let re = RegexBuilder::new(stored)
                .size_limit(MAX_REGEX_SIZE_LIMIT)
                .build()
                .ok()?;
            re.is_match(target).then_some(5)
        }
    }
}

/// Returns active (non-trashed) item IDs matching `target_url`, ordered by rule specificity and favorites.
pub fn find_matching_items(items: &[VaultItem], target_url: &str) -> Vec<Uuid> {
    let mut ranked: Vec<(u32, bool, &str, Uuid)> = items
        .iter()
        .filter(|item| item.trashed_at.is_none())
        .filter_map(|item| {
            let login = item.login.as_ref()?;
            let best_rank = login
                .uris
                .iter()
                .filter_map(|uri| uri_match_rank(uri, target_url))
                .max()?;
            Some((best_rank, item.favorite, item.title.as_str(), item.id))
        })
        .collect();

    ranked.sort_by(|a, b| {
        b.0.cmp(&a.0)
            .then_with(|| b.1.cmp(&a.1))
            .then_with(|| a.2.cmp(b.2))
    });

    ranked.into_iter().map(|entry| entry.3).collect()
}

/// Performs weighted client-side fuzzy search over non-trashed vault entries.
pub fn search_items(items: &[VaultItem], folders: &[VaultFolder], query: &str) -> Vec<SearchHit> {
    let trimmed = query.trim();
    if trimmed.is_empty() {
        let mut all: Vec<SearchHit> = items
            .iter()
            .filter(|i| i.trashed_at.is_none())
            .map(|i| SearchHit {
                item_id: i.id,
                score: u32::from(i.favorite),
            })
            .collect();
        all.sort_by_key(|a| std::cmp::Reverse(a.score));
        return all;
    }

    let folder_map: HashMap<Uuid, &str> = folders.iter().map(|f| (f.id, f.name.as_str())).collect();

    let pattern = Pattern::parse(trimmed, CaseMatching::Ignore, Normalization::Smart);
    let mut matcher = Matcher::new(Config::DEFAULT);
    let mut buf = Vec::new();
    let mut hits = Vec::new();

    for item in items.iter().filter(|i| i.trashed_at.is_none()) {
        let mut best_score: Option<u32> = None;
        let mut record_score = |candidate: Option<u32>, weight: u32| {
            if let Some(raw) = candidate {
                let weighted = raw.saturating_mul(weight);
                best_score = Some(best_score.map_or(weighted, |cur| cur.max(weighted)));
            }
        };

        record_score(score_text(&pattern, &item.title, &mut matcher, &mut buf), 4);

        if let Some(login) = &item.login {
            for uri in &login.uris {
                record_score(score_text(&pattern, &uri.uri, &mut matcher, &mut buf), 3);
            }
            record_score(
                score_text(&pattern, &login.username, &mut matcher, &mut buf),
                3,
            );
            record_score(
                score_text(&pattern, &login.email, &mut matcher, &mut buf),
                3,
            );
        }

        if let Some(fid) = item.folder_id
            && let Some(folder_name) = folder_map.get(&fid)
        {
            record_score(score_text(&pattern, folder_name, &mut matcher, &mut buf), 2);
        }

        if !item.notes.is_empty() {
            let truncated: String = item.notes.chars().take(MAX_SEARCH_HAYSTACK_CHARS).collect();
            record_score(score_text(&pattern, &truncated, &mut matcher, &mut buf), 1);
        }

        if let Some(score) = best_score {
            hits.push(SearchHit {
                item_id: item.id,
                score: score.saturating_add(if item.favorite { 25 } else { 0 }),
            });
        }
    }

    hits.sort_by_key(|a| std::cmp::Reverse(a.score));
    hits
}

fn score_text(
    pattern: &Pattern,
    text: &str,
    matcher: &mut Matcher,
    buf: &mut Vec<char>,
) -> Option<u32> {
    if text.is_empty() {
        return None;
    }
    pattern.score(Utf32Str::new(text, buf), matcher)
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::models::LoginData;

    #[test]
    fn public_suffix_anti_phishing_domain_matching() {
        assert_eq!(
            extract_base_domain("https://login.sub.example.co.uk:8443/auth").as_deref(),
            Some("example.co.uk")
        );
        assert_eq!(
            extract_base_domain("https://app.github.io/login").as_deref(),
            Some("app.github.io")
        );
        assert_eq!(
            extract_base_domain("https://evil.github.io/login").as_deref(),
            Some("evil.github.io")
        );
        assert_eq!(
            extract_base_domain("http://192.168.1.50:8006").as_deref(),
            Some("192.168.1.50")
        );

        let gh_uri = ItemUri {
            uri: "https://github.com/login".to_owned(),
            match_mode: UriMatchMode::BaseDomain,
        };
        assert!(uri_matches(&gh_uri, "https://gist.github.com/settings"));
        assert!(!uri_matches(&gh_uri, "https://evil-github.com/login"));

        let shared_host = ItemUri {
            uri: "https://app.github.io".to_owned(),
            match_mode: UriMatchMode::BaseDomain,
        };
        assert!(!uri_matches(&shared_host, "https://attacker.github.io"));

        let never_uri = ItemUri {
            uri: "https://github.com".to_owned(),
            match_mode: UriMatchMode::Never,
        };
        assert!(!uri_matches(&never_uri, "https://github.com"));
    }

    #[test]
    fn find_matching_items_orders_by_specificity() {
        let base_item = VaultItem::new_login(
            "GitHub Org",
            LoginData {
                username: String::new(),
                email: String::new(),
                password: String::new(),
                password_history: Vec::new(),
                uris: vec![ItemUri {
                    uri: "https://github.com".to_owned(),
                    match_mode: UriMatchMode::BaseDomain,
                }],
                totp: None,
            },
        );
        let exact_item = VaultItem::new_login(
            "GitHub Login Exact",
            LoginData {
                username: String::new(),
                email: String::new(),
                password: String::new(),
                password_history: Vec::new(),
                uris: vec![ItemUri {
                    uri: "https://gist.github.com/login".to_owned(),
                    match_mode: UriMatchMode::Exact,
                }],
                totp: None,
            },
        );

        let matches = find_matching_items(
            &[base_item.clone(), exact_item.clone()],
            "https://gist.github.com/login",
        );
        assert_eq!(matches, vec![exact_item.id, base_item.id]);
    }

    #[test]
    fn fuzzy_search_ranks_title_above_notes() {
        let folder = VaultFolder::new("Cloud");
        let mut aws = VaultItem::new_login(
            "AWS Console Prod",
            LoginData {
                username: "ops-admin".to_owned(),
                email: "ops@corp.io".to_owned(),
                password: String::new(),
                password_history: Vec::new(),
                uris: vec![ItemUri {
                    uri: "https://console.aws.amazon.com".to_owned(),
                    match_mode: UriMatchMode::BaseDomain,
                }],
                totp: None,
            },
        );
        aws.folder_id = Some(folder.id);

        let note = VaultItem::new_secure_note("Recovery", "Backup code for aws console");
        let hits = search_items(&[note.clone(), aws.clone()], &[folder], "aws");
        assert_eq!(hits.len(), 2);
        assert_eq!(hits[0].item_id, aws.id);
    }
}
