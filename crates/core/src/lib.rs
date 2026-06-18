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

pub mod connection_manager;
pub mod desktop_protocol;
pub mod ftp_client;
pub mod rdp_client;
pub mod sftp_client;
pub mod ssh;
pub mod tools;
pub mod vnc_client;

pub mod event_bus;

pub use connection_manager::{ConnectionManager, ManagedConnection, ProtocolKind};
pub use desktop_protocol::{
    DesktopConnectRequest, DesktopConnectResponse, DesktopKind, DesktopProtocol, FrameUpdate,
    RdpConfig, VncConfig,
};
pub use event_bus::CoreEvent;

// The PostgreSQL layer and Keychain credential store live in sibling
// crates. Re-export them as modules so existing consumers keep using
// `ssh_commander_core::postgres::*` / `ssh_commander_core::keychain::*`,
// alongside the flat re-exports below.
pub use ssh_commander_keychain as keychain;
pub use ssh_commander_pg as postgres;

pub use keychain::{
    CredentialKind, delete_password, is_supported, list_accounts, load_password, save_password,
};
pub use postgres::{
    ActiveCursor, BROWSER_SESSION_ID, ColumnDetail, ColumnMeta, DbSummary, ExecutionOutcome,
    InsertColumnInput, InsertedRow, ObjectType, ObjectTypeKind, PageResult, PgAuthMethod, PgConfig,
    PgError, PgPool, PgTlsMode, Relation, RelationKind, Routine, RoutineKind, SchemaContents,
    SchemaSummary, Sequence, UpdateOutcome,
};
pub use sftp_client::{
    FileEntry, FileEntryType, RemoteFileEntry, SftpAuthMethod, SftpConfig, StandaloneSftpClient,
};
pub use ssh::{
    AuthMethod, CommandOutput, HostKeyMismatch, HostKeyStore, HostKeyStoreAccessError,
    HostKeyVerificationFailure, PtySession, SshClient, SshConfig, SshTunnel, SshTunnelRef,
};
pub use tools::{
    DnsAnswer, DnsQuery, GitStatus, ListeningPort, TcpdumpEvent, TcpdumpRegistry, ToolsError,
    dns_resolve_local, dns_resolve_remote, git_status, listening_ports,
};

pub fn core_version() -> &'static str {
    env!("CARGO_PKG_VERSION")
}
