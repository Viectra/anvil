//! CSPRNG password/passphrase generators and zxcvbn-backed strength estimation.

use std::sync::LazyLock;

use serde::{Deserialize, Serialize};
use zeroize::Zeroizing;
use zxcvbn::Score;

use crate::crypto::fill_random_bytes;
use crate::error::AnvilError;

const UPPERCASE_CHARS: &[u8] = b"ABCDEFGHIJKLMNOPQRSTUVWXYZ";
const LOWERCASE_CHARS: &[u8] = b"abcdefghijklmnopqrstuvwxyz";
const DIGIT_CHARS: &[u8] = b"0123456789";
const SYMBOL_CHARS: &[u8] = b"!@#$%^&*()-_=+[]{}|;:,.<>?";

static EFF_SHORT_WORDS: LazyLock<Vec<&'static str>> = LazyLock::new(|| {
    include_str!("wordlist_eff_short.txt")
        .lines()
        .map(str::trim)
        .filter(|line| !line.is_empty())
        .collect()
});

/// Configuration for CSPRNG character-based password generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PasswordGeneratorConfig {
    pub length: usize,
    pub uppercase: bool,
    pub lowercase: bool,
    pub digits: bool,
    pub symbols: bool,
    pub exclude_ambiguous: bool,
    pub min_digits: usize,
    pub min_symbols: usize,
}

impl Default for PasswordGeneratorConfig {
    fn default() -> Self {
        Self {
            length: 20,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: false,
            min_digits: 1,
            min_symbols: 1,
        }
    }
}

/// Configuration for EFF-short-wordlist passphrase generation.
#[derive(Debug, Clone, PartialEq, Eq, Serialize, Deserialize)]
pub struct PassphraseConfig {
    pub word_count: usize,
    pub separator: String,
    pub capitalize: bool,
    pub include_number: bool,
}

impl Default for PassphraseConfig {
    fn default() -> Self {
        Self {
            word_count: 5,
            separator: "-".to_owned(),
            capitalize: false,
            include_number: false,
        }
    }
}

/// Password strength analysis combining zxcvbn and combinatorial entropy.
#[derive(Debug, Clone, PartialEq, Serialize, Deserialize)]
pub struct PasswordStrength {
    pub score: u8,
    pub entropy_bits: f64,
    pub crack_time_display: String,
    pub feedback_warning: Option<String>,
    pub feedback_suggestions: Vec<String>,
}

/// Generates a uniform random index in `0..bound` using rejection sampling.
fn random_index(bound: usize) -> Result<usize, AnvilError> {
    if bound == 0 {
        return Err(AnvilError::InvalidPasswordConfig(
            "empty character pool".to_owned(),
        ));
    }
    if bound == 1 {
        return Ok(0);
    }

    let bound_u64 = u64::try_from(bound).map_err(|_| {
        AnvilError::InvalidPasswordConfig("character pool bound out of range".to_owned())
    })?;
    let total_space = u64::from(u32::MAX) + 1;
    let limit = total_space - (total_space % bound_u64);

    loop {
        let mut buf = [0u8; 4];
        fill_random_bytes(&mut buf)?;
        let candidate = u64::from(u32::from_le_bytes(buf));
        if candidate < limit {
            return usize::try_from(candidate % bound_u64).map_err(|_| {
                AnvilError::InvalidPasswordConfig("random index conversion overflow".to_owned())
            });
        }
    }
}

fn filter_ambiguous(chars: &[u8], exclude_ambiguous: bool) -> Vec<u8> {
    if !exclude_ambiguous {
        return chars.to_vec();
    }
    chars
        .iter()
        .copied()
        .filter(|b| !matches!(b, b'0' | b'O' | b'1' | b'l' | b'I'))
        .collect()
}

/// Generates a random password matching `config` without modulo bias.
pub fn generate_password(
    config: &PasswordGeneratorConfig,
) -> Result<Zeroizing<String>, AnvilError> {
    if !(8..=128).contains(&config.length) {
        return Err(AnvilError::InvalidPasswordConfig(
            "password length must be between 8 and 128".to_owned(),
        ));
    }

    let upper = if config.uppercase {
        filter_ambiguous(UPPERCASE_CHARS, config.exclude_ambiguous)
    } else {
        Vec::new()
    };
    let lower = if config.lowercase {
        filter_ambiguous(LOWERCASE_CHARS, config.exclude_ambiguous)
    } else {
        Vec::new()
    };
    let digits = if config.digits {
        filter_ambiguous(DIGIT_CHARS, config.exclude_ambiguous)
    } else {
        Vec::new()
    };
    let symbols = if config.symbols {
        SYMBOL_CHARS.to_vec()
    } else {
        Vec::new()
    };

    let mut pool = Vec::with_capacity(upper.len() + lower.len() + digits.len() + symbols.len());
    pool.extend_from_slice(&upper);
    pool.extend_from_slice(&lower);
    pool.extend_from_slice(&digits);
    pool.extend_from_slice(&symbols);

    if pool.is_empty() {
        return Err(AnvilError::InvalidPasswordConfig(
            "at least one character class must be enabled".to_owned(),
        ));
    }

    let req_digits = if config.digits {
        config.min_digits.max(1)
    } else {
        0
    };
    let req_symbols = if config.symbols {
        config.min_symbols.max(1)
    } else {
        0
    };
    let req_upper = usize::from(config.uppercase);
    let req_lower = usize::from(config.lowercase);

    let min_required = req_upper + req_lower + req_digits + req_symbols;
    if min_required > config.length {
        return Err(AnvilError::InvalidPasswordConfig(format!(
            "password length {} is smaller than required class minimums ({min_required})",
            config.length
        )));
    }

    let mut out = Zeroizing::new(Vec::with_capacity(config.length));
    for _ in 0..req_upper {
        out.push(upper[random_index(upper.len())?]);
    }
    for _ in 0..req_lower {
        out.push(lower[random_index(lower.len())?]);
    }
    for _ in 0..req_digits {
        out.push(digits[random_index(digits.len())?]);
    }
    for _ in 0..req_symbols {
        out.push(symbols[random_index(symbols.len())?]);
    }
    while out.len() < config.length {
        out.push(pool[random_index(pool.len())?]);
    }

    // Fisher-Yates CSPRNG shuffle so guaranteed quotas appear at uniform positions.
    for i in (1..out.len()).rev() {
        let j = random_index(i + 1)?;
        out.swap(i, j);
    }

    let s = String::from_utf8(std::mem::take(&mut *out)).map_err(|_| {
        AnvilError::InvalidPasswordConfig("generated password was not valid UTF-8".to_owned())
    })?;
    Ok(Zeroizing::new(s))
}

/// Generates a diceware-style passphrase from the bundled 1,296-word EFF short list.
pub fn generate_passphrase(config: &PassphraseConfig) -> Result<Zeroizing<String>, AnvilError> {
    if !(3..=12).contains(&config.word_count) {
        return Err(AnvilError::InvalidPasswordConfig(
            "passphrase word_count must be between 3 and 12".to_owned(),
        ));
    }
    if EFF_SHORT_WORDS.is_empty() {
        return Err(AnvilError::InvalidPasswordConfig(
            "EFF wordlist is empty".to_owned(),
        ));
    }

    let num_target_idx = if config.include_number {
        Some(random_index(config.word_count)?)
    } else {
        None
    };

    let mut chosen = Vec::with_capacity(config.word_count);
    for idx in 0..config.word_count {
        let word_idx = random_index(EFF_SHORT_WORDS.len())?;
        let base_word = EFF_SHORT_WORDS[word_idx];
        let mut word = if config.capitalize {
            capitalize_ascii(base_word)
        } else {
            base_word.to_owned()
        };
        if num_target_idx == Some(idx) {
            let digit = random_index(10)?;
            word.push_str(&digit.to_string());
        }
        chosen.push(word);
    }

    Ok(Zeroizing::new(chosen.join(&config.separator)))
}

fn capitalize_ascii(word: &str) -> String {
    let mut chars = word.chars();
    match chars.next() {
        Some(first) => {
            let mut out = String::with_capacity(word.len());
            out.extend(first.to_uppercase());
            out.push_str(chars.as_str());
            out
        }
        None => String::new(),
    }
}

/// Evaluates password strength using `zxcvbn` and returns bits of estimated guess entropy.
pub fn evaluate_password_strength(password: &str, user_inputs: &[&str]) -> PasswordStrength {
    let analysis = zxcvbn::zxcvbn(password, user_inputs);
    let score = match analysis.score() {
        Score::Zero => 0,
        Score::One => 1,
        Score::Two => 2,
        Score::Three => 3,
        Score::Four | _ => 4,
    };

    let guesses_log10 = analysis.guesses_log10();
    let entropy_bits = if guesses_log10.is_finite() && guesses_log10 > 0.0 {
        guesses_log10 * std::f64::consts::LOG2_10
    } else {
        0.0
    };

    let crack_time_display = analysis
        .crack_times()
        .offline_slow_hashing_1e4_per_second()
        .to_string();

    let (feedback_warning, feedback_suggestions) = match analysis.feedback() {
        Some(fb) => (
            fb.warning().map(|w| w.to_string()),
            fb.suggestions().iter().map(ToString::to_string).collect(),
        ),
        None => (None, Vec::new()),
    };

    PasswordStrength {
        score,
        entropy_bits,
        crack_time_display,
        feedback_warning,
        feedback_suggestions,
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn generates_password_honoring_constraints_and_ambiguous_exclusion() {
        let cfg = PasswordGeneratorConfig {
            length: 24,
            uppercase: true,
            lowercase: true,
            digits: true,
            symbols: true,
            exclude_ambiguous: true,
            min_digits: 3,
            min_symbols: 3,
        };
        let pw = generate_password(&cfg).expect("password generation succeeds");
        assert_eq!(pw.len(), 24);
        assert!(pw.chars().any(|c| c.is_ascii_uppercase()));
        assert!(pw.chars().any(|c| c.is_ascii_lowercase()));
        assert!(pw.chars().filter(|c| c.is_ascii_digit()).count() >= 3);
        assert!(
            pw.chars()
                .filter(|c| SYMBOL_CHARS.contains(&(*c as u8)))
                .count()
                >= 3
        );
        for ambiguous in ['0', 'O', '1', 'l', 'I'] {
            assert!(!pw.contains(ambiguous));
        }

        let bad_len = PasswordGeneratorConfig {
            length: 6,
            ..Default::default()
        };
        assert!(generate_password(&bad_len).is_err());

        let no_classes = PasswordGeneratorConfig {
            uppercase: false,
            lowercase: false,
            digits: false,
            symbols: false,
            ..Default::default()
        };
        assert!(generate_password(&no_classes).is_err());
    }

    #[test]
    fn eff_wordlist_has_1296_words_and_generates_passphrase() {
        assert_eq!(EFF_SHORT_WORDS.len(), 1296);

        let cfg = PassphraseConfig {
            word_count: 6,
            separator: ".".to_owned(),
            capitalize: true,
            include_number: true,
        };
        let phrase = generate_passphrase(&cfg).expect("passphrase generation succeeds");
        let parts: Vec<&str> = phrase.split('.').collect();
        assert_eq!(parts.len(), 6);
        assert!(
            parts
                .iter()
                .all(|w| w.chars().next().is_some_and(|c| c.is_uppercase()))
        );
        assert!(phrase.chars().any(|c| c.is_ascii_digit()));
    }

    #[test]
    fn strength_evaluator_distinguishes_weak_and_strong_passwords() {
        let weak = evaluate_password_strength("password123", &[]);
        assert!(weak.score <= 1);
        assert!(weak.feedback_warning.is_some());

        let strong = evaluate_password_strength("K9#vP2!mQ7@xR4$zN8^wL5", &[]);
        assert_eq!(strong.score, 4);
        assert!(strong.entropy_bits > 60.0);
    }
}
