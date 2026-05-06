//! Safe argument quoting for remote shell commands.
//!
//! Every path or user-supplied string that is about to be interpolated into a
//! POSIX shell command must go through `quote` to defeat argument splitting,
//! globbing, and command injection. A filename containing `'` or `;` or `$(` is
//! otherwise a direct RCE against the remote host.

/// Wrap `s` in single quotes, escaping any embedded single quotes using the
/// portable POSIX idiom `'\''`. Always returns a quoted string, even for the
/// empty string — callers should never concatenate unquoted.
pub fn quote(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('\'');
    for ch in s.chars() {
        if ch == '\'' {
            out.push_str("'\\''");
        } else {
            out.push(ch);
        }
    }
    out.push('\'');
    out
}

/// Validate that `s` is a plain decimal integer in `1..=u32::MAX`, suitable for
/// use as a PID. Returns the original string if valid.
pub fn validate_pid(s: &str) -> Result<&str, String> {
    let trimmed = s.trim();
    match trimmed.parse::<u32>() {
        Ok(n) if n >= 1 => Ok(trimmed),
        _ => Err(format!("Invalid PID: {:?}", s)),
    }
}

/// Validate a POSIX kill signal. Accepts a numeric signal in `1..=64` or one of
/// the common signal names. Returns the canonical form to interpolate directly.
pub fn validate_signal(s: &str) -> Result<String, String> {
    const NAMES: &[&str] = &[
        "HUP", "INT", "QUIT", "ILL", "TRAP", "ABRT", "BUS", "FPE", "KILL", "USR1", "SEGV", "USR2",
        "PIPE", "ALRM", "TERM", "STKFLT", "CHLD", "CONT", "STOP", "TSTP", "TTIN", "TTOU", "URG",
        "XCPU", "XFSZ", "VTALRM", "PROF", "WINCH", "IO", "PWR", "SYS",
    ];
    let trimmed = s.trim().to_ascii_uppercase();
    let trimmed = trimmed.trim_start_matches("SIG").to_string();
    if let Ok(n) = trimmed.parse::<u32>() {
        if (1..=64).contains(&n) {
            return Ok(n.to_string());
        }
        return Err(format!("Signal out of range: {}", n));
    }
    if NAMES.iter().any(|&n| n == trimmed) {
        return Ok(trimmed);
    }
    Err(format!("Unknown signal: {:?}", s))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_empty_string() {
        assert_eq!(quote(""), "''");
    }

    #[test]
    fn quote_plain_string() {
        assert_eq!(quote("foo"), "'foo'");
        assert_eq!(quote("/var/log/syslog"), "'/var/log/syslog'");
    }

    #[test]
    fn quote_defuses_single_quote_injection() {
        // Classic injection payload: 'foo' ; rm -rf / ; echo 'x
        let attack = "foo'; rm -rf /; echo 'x";
        let quoted = quote(attack);
        assert_eq!(quoted, r#"'foo'\''; rm -rf /; echo '\''x'"#);
        // The quoted form starts and ends with ' and contains no unescaped '.
        assert!(quoted.starts_with('\''));
        assert!(quoted.ends_with('\''));
    }

    #[test]
    fn quote_handles_glob_and_substitution_meta() {
        assert_eq!(quote("$(whoami)"), "'$(whoami)'");
        assert_eq!(quote("*.log"), "'*.log'");
        assert_eq!(quote("a b\tc\nd"), "'a b\tc\nd'");
    }

    #[test]
    fn validate_pid_accepts_normal_pids() {
        assert_eq!(validate_pid("1234").unwrap(), "1234");
        assert_eq!(validate_pid(" 42 ").unwrap(), "42");
    }

    #[test]
    fn validate_pid_rejects_non_numeric_and_zero() {
        assert!(validate_pid("0").is_err());
        assert!(validate_pid("-1").is_err());
        assert!(validate_pid("1; rm -rf /").is_err());
        assert!(validate_pid("").is_err());
        assert!(validate_pid("1 2").is_err());
    }

    #[test]
    fn validate_signal_accepts_numeric_and_names() {
        assert_eq!(validate_signal("15").unwrap(), "15");
        assert_eq!(validate_signal("9").unwrap(), "9");
        assert_eq!(validate_signal("TERM").unwrap(), "TERM");
        assert_eq!(validate_signal("sigkill").unwrap(), "KILL");
        assert_eq!(validate_signal("SIGHUP").unwrap(), "HUP");
    }

    #[test]
    fn validate_signal_rejects_garbage() {
        assert!(validate_signal("0").is_err());
        assert!(validate_signal("999").is_err());
        assert!(validate_signal("FOO").is_err());
        assert!(validate_signal("15; rm -rf /").is_err());
    }
}
