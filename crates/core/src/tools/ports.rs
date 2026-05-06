//! Listening-port inventory for one host.
//!
//! Strategy: prefer `ss -tunlpH` (Linux iproute2 — header-suppressed).
//! Fall back to `ss -tunlp` and skip the header line if `H` isn't
//! supported by an old version. Final fallback: `netstat -tunlp` for
//! BSDs / very old distros.

use crate::ssh::SshClient;
use crate::tools::ToolsError;

#[derive(Debug, Clone)]
pub struct ListeningPort {
    pub protocol: String,
    pub local_addr: String,
    pub port: u16,
    pub process: Option<String>,
    pub pid: Option<u32>,
}

pub async fn listening_ports(client: &SshClient) -> Result<Vec<ListeningPort>, ToolsError> {
    // Try ss first; if it's missing, fall back to netstat. We pipe stderr
    // into stdout so a user-friendly message survives the round-trip.
    let cmd = "if command -v ss >/dev/null 2>&1; then \
                  ss -tunlpH 2>/dev/null || ss -tunlp 2>/dev/null; \
               elif command -v netstat >/dev/null 2>&1; then \
                  netstat -tunlp 2>/dev/null; \
               else \
                  echo 'NEITHER_SS_NOR_NETSTAT' >&2; exit 127; \
               fi";

    let out = client
        .execute_command_full(cmd)
        .await
        .map_err(|e| ToolsError::SshExec(e.to_string()))?;

    if out.stderr.contains("NEITHER_SS_NOR_NETSTAT") {
        return Err(ToolsError::RemoteCommand {
            exit: out.exit_code.map(|c| c as i32),
            message: "host has neither `ss` nor `netstat` available".into(),
        });
    }

    Ok(parse(&out.stdout))
}

fn parse(stdout: &str) -> Vec<ListeningPort> {
    let mut ports = Vec::new();
    for raw_line in stdout.lines() {
        let line = raw_line.trim();
        // Skip headers from ss/netstat. ss header starts with "Netid";
        // netstat -tunlp starts with "Active" or "Proto".
        if line.is_empty()
            || line.starts_with("Netid")
            || line.starts_with("Active")
            || line.starts_with("Proto")
        {
            continue;
        }
        if let Some(parsed) = parse_line(line) {
            ports.push(parsed);
        }
    }
    ports
}

fn parse_line(line: &str) -> Option<ListeningPort> {
    let cols: Vec<&str> = line.split_whitespace().collect();
    if cols.is_empty() {
        return None;
    }

    // Heuristic: ss output has 6 columns
    //   Netid State Recv-Q Send-Q LocalAddr:Port PeerAddr:Port [users:...]
    // netstat output has 7 columns
    //   Proto Recv-Q Send-Q LocalAddr ForeignAddr State PID/Process
    let proto_token = cols[0].to_lowercase();
    if !(proto_token.starts_with("tcp") || proto_token.starts_with("udp")) {
        return None;
    }

    // Find the local-address token: must contain ':' and have a numeric
    // tail (i.e. looks like "addr:port" or "[::]:port"). The colon
    // requirement excludes Recv-Q/Send-Q numeric columns that would
    // otherwise parse as u16 on their own.
    let local = cols.iter().find(|t| {
        t.contains(':')
            && t.rsplit_once(':')
                .is_some_and(|(_, p)| p.parse::<u16>().is_ok())
    })?;

    let (local_addr, port_str) = local.rsplit_once(':')?;
    let port: u16 = port_str.parse().ok()?;

    // Process info: ss puts it in a "users:((\"sshd\",pid=1234,fd=3))" token,
    // netstat puts it in a final "1234/sshd" token.
    let mut process: Option<String> = None;
    let mut pid: Option<u32> = None;
    if let Some(users_tok) = cols.iter().find(|t| t.starts_with("users:((")) {
        // Trim leading `users:((` and trailing `))`.
        let inner = users_tok
            .trim_start_matches("users:((")
            .trim_end_matches("))");
        // Pieces separated by ),( — usually just one.
        if let Some(first) = inner.split("),(").next() {
            let mut parts = first.split(',');
            if let Some(name) = parts.next() {
                process = Some(name.trim_matches('"').to_string());
            }
            for part in parts {
                if let Some(rest) = part.trim().strip_prefix("pid=") {
                    pid = rest.parse().ok();
                }
            }
        }
    } else if let Some(last) = cols.last()
        && let Some((p, name)) = last.split_once('/')
    {
        pid = p.parse().ok();
        process = Some(name.to_string());
    }

    Some(ListeningPort {
        protocol: proto_token,
        local_addr: local_addr.trim_matches(['[', ']']).to_string(),
        port,
        process,
        pid,
    })
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parses_ss_output() {
        let sample = "\
Netid State  Recv-Q Send-Q Local Address:Port Peer Address:Port Process
udp   UNCONN 0      0      0.0.0.0:68         0.0.0.0:*         users:((\"dhclient\",pid=512,fd=6))
tcp   LISTEN 0      128    0.0.0.0:22         0.0.0.0:*         users:((\"sshd\",pid=1024,fd=3))
tcp   LISTEN 0      128    [::]:22            [::]:*            users:((\"sshd\",pid=1024,fd=4))
";
        let parsed = parse(sample);
        assert_eq!(parsed.len(), 3);
        assert_eq!(parsed[1].port, 22);
        assert_eq!(parsed[1].protocol, "tcp");
        assert_eq!(parsed[1].process.as_deref(), Some("sshd"));
        assert_eq!(parsed[1].pid, Some(1024));
        assert_eq!(parsed[2].local_addr, "::");
    }

    #[test]
    fn parses_netstat_output() {
        let sample = "\
Active Internet connections (only servers)
Proto Recv-Q Send-Q Local Address    Foreign Address State   PID/Program name
tcp   0      0      0.0.0.0:22       0.0.0.0:*       LISTEN  1024/sshd
tcp   0      0      127.0.0.1:631    0.0.0.0:*       LISTEN  900/cupsd
";
        let parsed = parse(sample);
        assert_eq!(parsed.len(), 2);
        assert_eq!(parsed[0].process.as_deref(), Some("sshd"));
        assert_eq!(parsed[1].port, 631);
        assert_eq!(parsed[1].pid, Some(900));
    }
}
