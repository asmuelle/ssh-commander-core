//! Network/dev tools surface — features that ride on top of an existing
//! SSH connection without requiring a separate protocol implementation.
//!
//! Submodules:
//! - `git`     — git deploy-state for a repo on a remote host
//! - `dns`     — multi-perspective DNS resolution across all connected hosts
//! - `ports`   — listening-port inventory via `ss` / `netstat`
//! - `tcpdump` — streaming packet capture via `tcpdump -lnn`, lines emitted
//!   to the event bus for real-time UI display
//!
//! All tools share `ToolsError` so the FFI surface can present a single error
//! type to callers regardless of which sub-feature failed.

pub mod dns;
pub mod git;
pub mod ports;
pub mod tcpdump;

use thiserror::Error;

#[derive(Debug, Error)]
pub enum ToolsError {
    #[error("connection not found: {0}")]
    ConnectionNotFound(String),

    #[error("connection is not SSH: {0}")]
    NotSshConnection(String),

    #[error("remote command failed (exit {exit:?}): {message}")]
    RemoteCommand { exit: Option<i32>, message: String },

    #[error("ssh exec failed: {0}")]
    SshExec(String),

    #[error("parse error: {0}")]
    Parse(String),

    #[error("capture not found: {0}")]
    CaptureNotFound(u64),

    #[error("io: {0}")]
    Io(#[from] std::io::Error),
}

pub use dns::{DnsAnswer, DnsQuery, dns_resolve_local, dns_resolve_remote};
pub use git::{GitStatus, git_status};
pub use ports::{ListeningPort, listening_ports};
pub use tcpdump::{TcpdumpEvent, TcpdumpRegistry};
