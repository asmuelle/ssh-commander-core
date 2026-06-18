//! ssh-commander-core: Rust domain layer for R-Shell.
//!
//! This crate owns all connection and protocol logic:
//! SSH, PTY lifecycle, host-key handling, connection manager,
//! SFTP, FTP, desktop protocol (RDP/VNC), and Keychain integration.
//!
//! # Thread Safety
//!
//! - `ConnectionManager`: `Send + Sync`. All public methods are `async`.
//!   Callers must be running inside a Tokio runtime. Internally uses
//!   `Arc<RwLock<HashMap>>` — fine to call from any task, but the task
//!   must live on the Tokio runtime.
//! - `SshClient`: `Send` (not `Sync`). Single-owner state; wrap in
//!   `Arc<RwLock<SshClient>>` to share across tasks (as `ConnectionManager` does).
//! - `StandaloneSftpClient`, `FtpClient`: Same pattern as `SshClient`.
//! - `HostKeyStore`: `Send + Sync`. Uses `tokio::sync::Mutex` internally.
//!   Safe to share via `Arc`.
//! - `keychain` module: Synchronous only. Do **not** call from a Tokio
//!   `spawn_blocking` is fine; do not hold an `.await` across a keychain call.
//! - `PtySession`: `Send`. The `output_rx` field is `Arc<Mutex<Receiver>>`
//!   for sharing. `input_tx` and `resize_tx` are cloneable `Sender`s.
//! - `DesktopProtocol` trait: Requires `Send + Sync`. Implementations
//!   (`RdpClient`, `VncClient`) are `Send` (not `Sync`) — wrap in
//!   `Arc<RwLock<Box<dyn DesktopProtocol>>>`.

// At least one protocol feature must be enabled — an empty build has no
// `ManagedConnection` variants and the manager would be inert.
#[cfg(not(any(
    feature = "ssh",
    feature = "sftp",
    feature = "ftp",
    feature = "desktop",
    feature = "tools",
    feature = "postgres"
)))]
compile_error!(
    "ssh-commander-core needs at least one protocol feature enabled: \
     ssh, sftp, ftp, desktop, tools, or postgres"
);

pub mod connection_manager;
#[cfg(feature = "desktop")]
pub mod desktop_protocol;
// Protocol-agnostic file listing types — always available so the `ftp`
// feature need not pull in the SSH stack just to share them.
pub mod file_entry;
#[cfg(feature = "ftp")]
pub mod ftp_client;
#[cfg(feature = "desktop")]
pub mod rdp_client;
#[cfg(feature = "sftp")]
pub mod sftp_client;
#[cfg(feature = "ssh")]
pub mod ssh;
#[cfg(feature = "tools")]
pub mod tools;
#[cfg(feature = "desktop")]
pub mod vnc_client;

pub mod event_bus;

pub use connection_manager::{ConnectionManager, ManagedConnection, ProtocolKind};
#[cfg(feature = "desktop")]
pub use desktop_protocol::{
    DesktopConnectRequest, DesktopConnectResponse, DesktopKind, DesktopProtocol, FrameUpdate,
    RdpConfig, VncConfig,
};
pub use event_bus::CoreEvent;
pub use file_entry::{FileEntry, FileEntryType, RemoteFileEntry};

// The Keychain credential store lives in a sibling leaf crate; the
// PostgreSQL layer (behind the `postgres` feature) in another. Re-export
// them as modules so consumers keep using
// `ssh_commander_core::keychain::*` / `::postgres::*`, alongside the flat
// re-exports below.
pub use ssh_commander_keychain as keychain;
#[cfg(feature = "postgres")]
pub use ssh_commander_pg as postgres;

pub use keychain::{
    CredentialKind, delete_password, is_supported, list_accounts, load_password, save_password,
};
#[cfg(feature = "postgres")]
pub use postgres::{
    ActiveCursor, BROWSER_SESSION_ID, ColumnDetail, ColumnMeta, DbSummary, ExecutionOutcome,
    InsertColumnInput, InsertedRow, ObjectType, ObjectTypeKind, PageResult, PgAuthMethod, PgConfig,
    PgError, PgPool, PgTlsMode, Relation, RelationKind, Routine, RoutineKind, SchemaContents,
    SchemaSummary, Sequence, UpdateOutcome,
};
#[cfg(feature = "sftp")]
pub use sftp_client::{SftpAuthMethod, SftpConfig, StandaloneSftpClient};
#[cfg(feature = "ssh")]
pub use ssh::{
    AuthMethod, CommandOutput, HostKeyMismatch, HostKeyStore, HostKeyStoreAccessError,
    HostKeyVerificationFailure, PtySession, SshClient, SshConfig, SshTunnel, SshTunnelRef,
};
#[cfg(feature = "tools")]
pub use tools::{
    DnsAnswer, DnsQuery, GitStatus, ListeningPort, TcpdumpEvent, TcpdumpRegistry, ToolsError,
    dns_resolve_local, dns_resolve_remote, git_status, listening_ports,
};

pub fn core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
