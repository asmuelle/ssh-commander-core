//! Multi-perspective DNS resolution.
//!
//! For a given hostname, query each connected SSH host's resolver plus
//! the local Mac's resolver in parallel. Useful for spotting DNS
//! drift — e.g. internal vs public split-horizon, or stale caches on a
//! specific host.
//!
//! Implementation: `dig +short <name> <type>` on the remote (cheap and
//! universally available). Local perspective uses `tokio::net::lookup_host`
//! so we don't shell out for the most common path.

use crate::ssh::SshClient;
use crate::tools::ToolsError;

/// What to resolve and how.
#[derive(Debug, Clone)]
pub struct DnsQuery {
    pub name: String,
    pub record_type: DnsRecordType,
}

#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum DnsRecordType {
    A,
    AAAA,
    CNAME,
    MX,
    TXT,
    NS,
}

impl DnsRecordType {
    fn dig_arg(self) -> &'static str {
        match self {
            DnsRecordType::A => "A",
            DnsRecordType::AAAA => "AAAA",
            DnsRecordType::CNAME => "CNAME",
            DnsRecordType::MX => "MX",
            DnsRecordType::TXT => "TXT",
            DnsRecordType::NS => "NS",
        }
    }
}

/// One perspective's answer.
#[derive(Debug, Clone)]
pub struct DnsAnswer {
    pub perspective: String,
    pub query: String,
    pub record_type: DnsRecordType,
    pub answers: Vec<String>,
    pub error: Option<String>,
    pub elapsed_ms: u64,
}

/// Resolve from the local Mac. `tokio::net::lookup_host` only handles A/AAAA;
/// non-address record types fall back to spawning `dig` locally.
pub async fn dns_resolve_local(query: &DnsQuery) -> DnsAnswer {
    let started = std::time::Instant::now();
    let perspective = "local".to_string();
    match query.record_type {
        DnsRecordType::A | DnsRecordType::AAAA => {
            // lookup_host wants host:port — use a dummy port; we throw it away.
            let target = format!("{}:0", query.name);
            match tokio::net::lookup_host(target).await {
                Ok(iter) => {
                    let want_v6 = query.record_type == DnsRecordType::AAAA;
                    let answers: Vec<String> = iter
                        .filter(|sa| sa.is_ipv6() == want_v6)
                        .map(|sa| sa.ip().to_string())
                        .collect();
                    DnsAnswer {
                        perspective,
                        query: query.name.clone(),
                        record_type: query.record_type,
                        answers,
                        error: None,
                        elapsed_ms: started.elapsed().as_millis() as u64,
                    }
                }
                Err(e) => DnsAnswer {
                    perspective,
                    query: query.name.clone(),
                    record_type: query.record_type,
                    answers: vec![],
                    error: Some(e.to_string()),
                    elapsed_ms: started.elapsed().as_millis() as u64,
                },
            }
        }
        _ => {
            let dig_cmd = format!(
                "dig +short {} {}",
                shell_safe(&query.name),
                query.record_type.dig_arg()
            );
            match tokio::process::Command::new("sh")
                .arg("-c")
                .arg(&dig_cmd)
                .output()
                .await
            {
                Ok(out) if out.status.success() => DnsAnswer {
                    perspective,
                    query: query.name.clone(),
                    record_type: query.record_type,
                    answers: parse_dig_lines(&String::from_utf8_lossy(&out.stdout)),
                    error: None,
                    elapsed_ms: started.elapsed().as_millis() as u64,
                },
                Ok(out) => DnsAnswer {
                    perspective,
                    query: query.name.clone(),
                    record_type: query.record_type,
                    answers: vec![],
                    error: Some(String::from_utf8_lossy(&out.stderr).to_string()),
                    elapsed_ms: started.elapsed().as_millis() as u64,
                },
                Err(e) => DnsAnswer {
                    perspective,
                    query: query.name.clone(),
                    record_type: query.record_type,
                    answers: vec![],
                    error: Some(e.to_string()),
                    elapsed_ms: started.elapsed().as_millis() as u64,
                },
            }
        }
    }
}

/// Resolve from one remote SSH host using `dig +short`.
///
/// `perspective_label` is what the UI shows in the table — typically the
/// connection's display name or `<user>@<host>`.
pub async fn dns_resolve_remote(
    client: &SshClient,
    perspective_label: &str,
    query: &DnsQuery,
) -> DnsAnswer {
    let started = std::time::Instant::now();
    let cmd = format!(
        "dig +short {} {}",
        shell_safe(&query.name),
        query.record_type.dig_arg()
    );
    match client.execute_command_full(&cmd).await {
        Ok(out) if out.is_success() => DnsAnswer {
            perspective: perspective_label.to_string(),
            query: query.name.clone(),
            record_type: query.record_type,
            answers: parse_dig_lines(&out.stdout),
            error: None,
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
        Ok(out) => {
            // `dig` returns non-zero when it can't reach a resolver but
            // also when the answer set is empty on certain platforms.
            // Treat empty stdout + empty stderr as "no answer" rather
            // than an error so the UI shows a clean blank cell.
            let answers = parse_dig_lines(&out.stdout);
            let err = if answers.is_empty() && !out.stderr.trim().is_empty() {
                Some(out.stderr.trim().to_string())
            } else if answers.is_empty() && out.exit_code.unwrap_or(0) != 0 {
                Some(format!(
                    "dig exited {}",
                    out.exit_code
                        .map(|c| c.to_string())
                        .unwrap_or_else(|| "?".into())
                ))
            } else {
                None
            };
            DnsAnswer {
                perspective: perspective_label.to_string(),
                query: query.name.clone(),
                record_type: query.record_type,
                answers,
                error: err,
                elapsed_ms: started.elapsed().as_millis() as u64,
            }
        }
        Err(e) => DnsAnswer {
            perspective: perspective_label.to_string(),
            query: query.name.clone(),
            record_type: query.record_type,
            answers: vec![],
            error: Some(e.to_string()),
            elapsed_ms: started.elapsed().as_millis() as u64,
        },
    }
}

fn parse_dig_lines(out: &str) -> Vec<String> {
    out.lines()
        .map(|l| l.trim())
        .filter(|l| !l.is_empty() && !l.starts_with(';'))
        .map(|l| l.to_string())
        .collect()
}

/// Reject hostnames containing shell metacharacters. DNS names can never
/// validly contain these — anything else is an injection attempt.
fn shell_safe(name: &str) -> String {
    name.chars()
        .filter(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_'))
        .collect()
}

// Allow ToolsError to surface here for FFI parity even though the public
// resolvers above return `DnsAnswer` directly (errors live inside the
// answer struct so multi-host fan-out can collect partial results).
#[allow(dead_code)]
fn _ensure_error_unused(e: ToolsError) -> ToolsError {
    e
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn parses_dig_short_output() {
        let raw = "\
1.2.3.4
5.6.7.8
;; Truncated, retrying in TCP mode.
";
        let parsed = parse_dig_lines(raw);
        assert_eq!(parsed, vec!["1.2.3.4", "5.6.7.8"]);
    }

    #[test]
    fn shell_safe_strips_metachars() {
        assert_eq!(shell_safe("example.com"), "example.com");
        assert_eq!(shell_safe("ex; rm -rf /"), "exrm-rf");
        assert_eq!(shell_safe("foo$(bad)"), "foobad");
    }

    proptest! {
        #[test]
        fn shell_safe_only_emits_dns_safe_characters(input in ".*") {
            let sanitized = shell_safe(&input);
            prop_assert!(sanitized
                .chars()
                .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_')));
        }
    }
}
