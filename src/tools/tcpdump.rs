//! Streaming packet capture via `tcpdump -lnn` over SSH.
//!
//! Each capture is registered with a `u64` handle. The capture task pulls
//! lines from `SshClient::execute_command_streaming` and republishes them
//! on the global event bus as `CoreEvent::TcpdumpLine` so the Swift layer
//! can append rows in real time without holding a per-capture FFI
//! callback.
//!
//! Stop is cooperative: `stop(id)` cancels the streaming token, which
//! tears down the SSH channel and ends the capture task.

use crate::event_bus::{CoreEvent, event_sender};
use crate::ssh::SshClient;
use crate::tools::ToolsError;
use std::collections::HashMap;
use std::sync::Arc;
use std::sync::Mutex;
use std::sync::OnceLock;
use std::sync::atomic::{AtomicU64, Ordering};
use tokio_util::sync::CancellationToken;

/// One line from a running tcpdump capture, as forwarded over the event bus.
#[derive(Debug, Clone)]
pub struct TcpdumpEvent {
    pub capture_id: u64,
    pub line: String,
    /// `true` if the line came from stderr (e.g. tcpdump startup banner
    /// or a libpcap warning) — UI can dim these.
    pub is_stderr: bool,
}

type CaptureMap = Arc<Mutex<HashMap<u64, CancellationToken>>>;

/// Tracks active captures so callers can stop them by id.
pub struct TcpdumpRegistry {
    next_id: AtomicU64,
    captures: CaptureMap,
}

impl Default for TcpdumpRegistry {
    fn default() -> Self {
        Self::new()
    }
}

impl TcpdumpRegistry {
    pub fn new() -> Self {
        Self {
            next_id: AtomicU64::new(1),
            captures: Arc::new(Mutex::new(HashMap::new())),
        }
    }

    /// Process-wide singleton — the FFI surface uses this so capture
    /// ids are unique across the app.
    pub fn global() -> &'static Self {
        static REGISTRY: OnceLock<TcpdumpRegistry> = OnceLock::new();
        REGISTRY.get_or_init(TcpdumpRegistry::new)
    }

    /// Start a new capture on `client`. Returns the capture id; lines
    /// arrive asynchronously via the event bus.
    ///
    /// `interface` is the tcpdump `-i` value (use `any` if the user
    /// hasn't picked one). `filter` is the bpf expression — the empty
    /// string means "capture everything". `snaplen` defaults to 96 if
    /// `None` (header-only, low bandwidth).
    pub async fn start(
        &self,
        client: &SshClient,
        interface: &str,
        filter: &str,
        snaplen: Option<u32>,
    ) -> Result<u64, ToolsError> {
        validate_interface(interface)?;
        validate_filter(filter)?;

        let snap = snaplen.unwrap_or(96);
        let cmd = if filter.trim().is_empty() {
            format!("sudo -n tcpdump -lnn -s {snap} -i {interface}")
        } else {
            format!("sudo -n tcpdump -lnn -s {snap} -i {interface} '{filter}'")
        };

        let (mut rx, cancel) = client
            .execute_command_streaming(&cmd)
            .await
            .map_err(|e| ToolsError::SshExec(e.to_string()))?;

        let id = self.next_id.fetch_add(1, Ordering::SeqCst);
        if let Ok(mut map) = self.captures.lock() {
            map.insert(id, cancel.clone());
        }

        let captures = self.captures.clone();
        tokio::spawn(async move {
            let tx = event_sender();
            while let Some(line) = rx.recv().await {
                let (is_stderr, payload) = if let Some(rest) = line.strip_prefix('!') {
                    (true, rest.to_string())
                } else {
                    (false, line)
                };
                if let Some(ref tx) = tx {
                    let _ = tx.send(CoreEvent::TcpdumpLine {
                        capture_id: id,
                        line: payload,
                        is_stderr,
                    });
                }
            }
            // Receiver closed — capture ended. Drop the cancel token from
            // the registry so a later `stop(id)` is a clean no-op.
            if let Ok(mut map) = captures.lock() {
                map.remove(&id);
            }
        });

        Ok(id)
    }

    pub fn stop(&self, id: u64) -> Result<(), ToolsError> {
        let token = {
            let mut map = self
                .captures
                .lock()
                .map_err(|e| ToolsError::Parse(format!("lock poisoned: {e}")))?;
            map.remove(&id)
        };
        match token {
            Some(t) => {
                t.cancel();
                Ok(())
            }
            None => Err(ToolsError::CaptureNotFound(id)),
        }
    }
}

fn validate_interface(iface: &str) -> Result<(), ToolsError> {
    if iface.is_empty()
        || iface.len() > 32
        || !iface
            .chars()
            .all(|c| c.is_ascii_alphanumeric() || matches!(c, '.' | '-' | '_' | ':'))
    {
        return Err(ToolsError::Parse(format!("invalid interface: {iface}")));
    }
    Ok(())
}

fn validate_filter(filter: &str) -> Result<(), ToolsError> {
    // tcpdump bpf filters are passed as a single quoted argument. Reject
    // single quotes so they can't break out of the quoting; everything else
    // is bpf's problem.
    if filter.contains('\'') {
        return Err(ToolsError::Parse(
            "filter may not contain single quotes".into(),
        ));
    }
    if filter.len() > 4096 {
        return Err(ToolsError::Parse("filter too long".into()));
    }
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn rejects_bad_interface() {
        assert!(validate_interface("eth0; rm -rf /").is_err());
        assert!(validate_interface("").is_err());
        assert!(validate_interface("eth0").is_ok());
        assert!(validate_interface("any").is_ok());
        assert!(validate_interface("en0:vlan100").is_ok());
    }

    #[test]
    fn rejects_filter_with_quotes() {
        assert!(validate_filter("port 80").is_ok());
        assert!(validate_filter("port 80 and 'evil'").is_err());
        assert!(validate_filter("").is_ok());
    }
}
