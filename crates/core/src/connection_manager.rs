#[cfg(feature = "desktop")]
use crate::desktop_protocol::{DesktopConnectRequest, DesktopProtocol, FrameUpdate};
#[cfg(feature = "ftp")]
use crate::ftp_client::FtpClient;
#[cfg(feature = "desktop")]
use crate::rdp_client::RdpClient;
#[cfg(feature = "sftp")]
use crate::sftp_client::StandaloneSftpClient;
#[cfg(feature = "ssh")]
use crate::ssh::{HostKeyStore, PtySession, SshClient, SshConfig};
#[cfg(all(feature = "postgres", feature = "ssh"))]
use crate::ssh::{SshTunnel, SshTunnelRef};
#[cfg(feature = "desktop")]
use crate::vnc_client::VncClient;
use anyhow::Result;
#[cfg(feature = "postgres")]
use ssh_commander_pg::{PgConfig, PgPool};
use std::collections::HashMap;
use std::sync::Arc;
use tokio::sync::RwLock;
#[cfg(feature = "desktop")]
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

/// Canonical protocol tag for a managed connection.
///
/// Using an enum instead of a free-form string means every branch that inspects
/// a connection is exhaustiveness-checked and callers can't typo a tag.
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum ProtocolKind {
    #[cfg(feature = "ssh")]
    Ssh,
    #[cfg(feature = "sftp")]
    Sftp,
    #[cfg(feature = "ftp")]
    Ftp,
    #[cfg(feature = "desktop")]
    Rdp,
    #[cfg(feature = "desktop")]
    Vnc,
    #[cfg(feature = "postgres")]
    Postgres,
}

impl ProtocolKind {
    pub fn as_str(self) -> &'static str {
        match self {
            #[cfg(feature = "ssh")]
            ProtocolKind::Ssh => "SSH",
            #[cfg(feature = "sftp")]
            ProtocolKind::Sftp => "SFTP",
            #[cfg(feature = "ftp")]
            ProtocolKind::Ftp => "FTP",
            #[cfg(feature = "desktop")]
            ProtocolKind::Rdp => "RDP",
            #[cfg(feature = "desktop")]
            ProtocolKind::Vnc => "VNC",
            #[cfg(feature = "postgres")]
            ProtocolKind::Postgres => "POSTGRES",
        }
    }
}

/// A single managed connection, tagged by protocol.
///
/// Each variant owns its own `Arc<RwLock<_>>` — giving per-connection locking
/// granularity, instead of a global map-level RwLock that would serialise
/// every operation across unrelated connections.
pub enum ManagedConnection {
    #[cfg(feature = "ssh")]
    Ssh(Arc<RwLock<SshClient>>),
    #[cfg(feature = "sftp")]
    Sftp(Arc<RwLock<StandaloneSftpClient>>),
    #[cfg(feature = "ftp")]
    Ftp(Arc<RwLock<FtpClient>>),
    #[cfg(feature = "desktop")]
    Desktop {
        kind: ProtocolKind, // Rdp or Vnc
        client: Arc<RwLock<Box<dyn DesktopProtocol>>>,
    },
    /// `PgPool` is internally `Sync` (manages its own locks), so no
    /// outer `RwLock` is needed here — multiple sessions / tabs can
    /// hit the pool concurrently from independent tasks. `tunnel` holds
    /// the SSH local-forward open for the pool's lifetime when the
    /// profile connects through one; the pool itself dials its local
    /// port and is unaware of SSH.
    #[cfg(feature = "postgres")]
    Postgres {
        pool: Arc<PgPool>,
        #[cfg(feature = "ssh")]
        tunnel: Option<Arc<SshTunnel>>,
    },
}

impl ManagedConnection {
    pub fn kind(&self) -> ProtocolKind {
        match self {
            #[cfg(feature = "ssh")]
            ManagedConnection::Ssh(_) => ProtocolKind::Ssh,
            #[cfg(feature = "sftp")]
            ManagedConnection::Sftp(_) => ProtocolKind::Sftp,
            #[cfg(feature = "ftp")]
            ManagedConnection::Ftp(_) => ProtocolKind::Ftp,
            #[cfg(feature = "desktop")]
            ManagedConnection::Desktop { kind, .. } => *kind,
            #[cfg(feature = "postgres")]
            ManagedConnection::Postgres { .. } => ProtocolKind::Postgres,
        }
    }
}

#[cfg(any(
    feature = "ssh",
    feature = "sftp",
    feature = "ftp",
    feature = "desktop",
    feature = "postgres"
))]
#[derive(Debug, Clone, Copy)]
#[allow(dead_code)] // some variants only exist under specific feature sets
enum ConnectionSlotKind {
    #[cfg(feature = "ssh")]
    Ssh,
    #[cfg(feature = "sftp")]
    Sftp,
    #[cfg(feature = "ftp")]
    Ftp,
    #[cfg(feature = "desktop")]
    Desktop,
    #[cfg(feature = "postgres")]
    Postgres,
}

#[cfg(any(
    feature = "ssh",
    feature = "sftp",
    feature = "ftp",
    feature = "desktop",
    feature = "postgres"
))]
impl ConnectionSlotKind {
    fn label(self) -> &'static str {
        match self {
            #[cfg(feature = "ssh")]
            ConnectionSlotKind::Ssh => "SSH",
            #[cfg(feature = "sftp")]
            ConnectionSlotKind::Sftp => "SFTP",
            #[cfg(feature = "ftp")]
            ConnectionSlotKind::Ftp => "FTP",
            #[cfg(feature = "desktop")]
            ConnectionSlotKind::Desktop => "desktop",
            #[cfg(feature = "postgres")]
            ConnectionSlotKind::Postgres => "postgres",
        }
    }

    fn matches(self, connection: &ManagedConnection) -> bool {
        match self {
            #[cfg(feature = "ssh")]
            ConnectionSlotKind::Ssh => matches!(connection, ManagedConnection::Ssh(_)),
            #[cfg(feature = "sftp")]
            ConnectionSlotKind::Sftp => matches!(connection, ManagedConnection::Sftp(_)),
            #[cfg(feature = "ftp")]
            ConnectionSlotKind::Ftp => matches!(connection, ManagedConnection::Ftp(_)),
            #[cfg(feature = "desktop")]
            ConnectionSlotKind::Desktop => {
                matches!(connection, ManagedConnection::Desktop { .. })
            }
            #[cfg(feature = "postgres")]
            ConnectionSlotKind::Postgres => {
                matches!(connection, ManagedConnection::Postgres { .. })
            }
        }
    }
}

/// The connection manager owns the mapping from connection_id → its backing
/// protocol state. Previously this was eight parallel hashmaps held together
/// by convention; invariants (e.g. "if connection_types says SFTP, the sftp
/// hashmap contains the id") are now enforced by the variant tag itself.
pub struct ConnectionManager {
    connections: Arc<RwLock<HashMap<String, ManagedConnection>>>,
    /// PTY session state — only present when the SSH feature is enabled,
    /// since interactive shells are an SSH-only capability.
    #[cfg(feature = "ssh")]
    pty_sessions: Arc<RwLock<HashMap<String, Arc<PtySession>>>>,
    /// Generation counter per connection_id — incremented on each StartPty.
    /// Used to prevent a stale Close from killing a newly created session.
    #[cfg(feature = "ssh")]
    pty_generations: Arc<RwLock<HashMap<String, u64>>>,
    pending_connections: Arc<RwLock<HashMap<String, CancellationToken>>>,
    /// Shared TOFU host-key store used by every SSH/SFTP connection.
    #[cfg(feature = "ssh")]
    host_keys: Arc<HostKeyStore>,
}

impl Default for ConnectionManager {
    fn default() -> Self {
        Self::new()
    }
}

impl ConnectionManager {
    #[cfg(feature = "ssh")]
    pub fn new() -> Self {
        Self::with_host_keys(Arc::new(HostKeyStore::new(HostKeyStore::default_path())))
    }

    /// Construct a manager for a build without the SSH feature. There is
    /// no host-key store or PTY state to initialise.
    #[cfg(not(feature = "ssh"))]
    pub fn new() -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            pending_connections: Arc::new(RwLock::new(HashMap::new())),
        }
    }

    #[cfg(feature = "ssh")]
    pub fn with_host_keys(host_keys: Arc<HostKeyStore>) -> Self {
        Self {
            connections: Arc::new(RwLock::new(HashMap::new())),
            pty_sessions: Arc::new(RwLock::new(HashMap::new())),
            pty_generations: Arc::new(RwLock::new(HashMap::new())),
            pending_connections: Arc::new(RwLock::new(HashMap::new())),
            host_keys,
        }
    }

    /// Access the shared host-key store. Used by the macOS bridge to
    /// expose `forget` over FFI for the "Trust new key" flow on a
    /// `HostKeyMismatch`.
    #[cfg(feature = "ssh")]
    pub fn host_keys(&self) -> Arc<HostKeyStore> {
        self.host_keys.clone()
    }

    // =========================================================================
    // Inspection
    // =========================================================================

    /// Protocol of an existing connection, or None if not registered.
    pub async fn connection_kind(&self, id: &str) -> Option<ProtocolKind> {
        let connections = self.connections.read().await;
        connections.get(id).map(|c| c.kind())
    }

    /// Backward-compatible string form of `connection_kind`. Returns "SSH",
    /// "SFTP", "FTP", "RDP", or "VNC". Prefer `connection_kind` in new code.
    pub async fn get_connection_type(&self, id: &str) -> Option<String> {
        self.connection_kind(id)
            .await
            .map(|k| k.as_str().to_string())
    }

    pub async fn list_connections(&self) -> Vec<String> {
        let connections = self.connections.read().await;
        connections.keys().cloned().collect()
    }

    /// Return the SSH client for a connection if it is an SSH connection.
    #[cfg(feature = "ssh")]
    pub async fn get_connection(&self, id: &str) -> Option<Arc<RwLock<SshClient>>> {
        let connections = self.connections.read().await;
        match connections.get(id) {
            Some(ManagedConnection::Ssh(c)) => Some(c.clone()),
            _ => None,
        }
    }

    #[cfg(feature = "sftp")]
    pub async fn get_sftp_client(&self, id: &str) -> Option<Arc<RwLock<StandaloneSftpClient>>> {
        let connections = self.connections.read().await;
        match connections.get(id) {
            Some(ManagedConnection::Sftp(c)) => Some(c.clone()),
            _ => None,
        }
    }

    #[cfg(feature = "ftp")]
    pub async fn get_ftp_client(&self, id: &str) -> Option<Arc<RwLock<FtpClient>>> {
        let connections = self.connections.read().await;
        match connections.get(id) {
            Some(ManagedConnection::Ftp(c)) => Some(c.clone()),
            _ => None,
        }
    }

    #[cfg(feature = "desktop")]
    pub async fn get_desktop_connection(
        &self,
        id: &str,
    ) -> Option<Arc<RwLock<Box<dyn DesktopProtocol>>>> {
        let connections = self.connections.read().await;
        match connections.get(id) {
            Some(ManagedConnection::Desktop { client, .. }) => Some(client.clone()),
            _ => None,
        }
    }

    #[cfg(feature = "postgres")]
    pub async fn get_postgres_pool(&self, id: &str) -> Option<Arc<PgPool>> {
        let connections = self.connections.read().await;
        match connections.get(id) {
            Some(ManagedConnection::Postgres { pool, .. }) => Some(pool.clone()),
            _ => None,
        }
    }

    // =========================================================================
    // SSH connection lifecycle (supports cancellation of a pending connect)
    // =========================================================================

    #[cfg(feature = "ssh")]
    pub async fn create_connection(&self, connection_id: String, config: SshConfig) -> Result<()> {
        let mut client = SshClient::new(self.host_keys.clone());
        let cancel_token = self.register_pending_connection(&connection_id).await;

        let connect_result = tokio::select! {
            res = client.connect(&config) => res,
            _ = cancel_token.cancelled() => Err(anyhow::anyhow!("Connection cancelled by user")),
        };

        self.clear_pending_connection(&connection_id).await;

        connect_result?;
        self.replace_managed_connection(
            connection_id,
            ManagedConnection::Ssh(Arc::new(RwLock::new(client))),
        )
        .await
    }

    // Cancellable-connect bookkeeping is only exercised by the SSH and
    // Postgres connect paths; a build without either does not need it.
    #[cfg(any(feature = "ssh", feature = "postgres"))]
    async fn register_pending_connection(&self, connection_id: &str) -> CancellationToken {
        let token = CancellationToken::new();
        let mut pending = self.pending_connections.write().await;
        pending.insert(connection_id.to_string(), token.clone());
        token
    }

    #[cfg(any(feature = "ssh", feature = "postgres"))]
    async fn clear_pending_connection(&self, connection_id: &str) {
        let mut pending = self.pending_connections.write().await;
        pending.remove(connection_id);
    }

    #[cfg(any(
        feature = "ssh",
        feature = "sftp",
        feature = "ftp",
        feature = "desktop",
        feature = "postgres"
    ))]
    async fn disconnect_managed_connection(
        &self,
        connection_id: &str,
        connection: ManagedConnection,
    ) -> Result<()> {
        match connection {
            #[cfg(feature = "ssh")]
            ManagedConnection::Ssh(client) => {
                {
                    let mut pty_sessions = self.pty_sessions.write().await;
                    if let Some(session) = pty_sessions.remove(connection_id) {
                        session.cancel.cancel();
                    }
                }
                {
                    let mut generations = self.pty_generations.write().await;
                    generations.remove(connection_id);
                }
                let mut client = client.write().await;
                client.disconnect().await?;
            }
            #[cfg(feature = "sftp")]
            ManagedConnection::Sftp(client) => {
                let mut client = client.write().await;
                client.disconnect().await?;
            }
            #[cfg(feature = "ftp")]
            ManagedConnection::Ftp(client) => {
                let mut client = client.write().await;
                client.disconnect().await?;
            }
            #[cfg(feature = "desktop")]
            ManagedConnection::Desktop { client, .. } => {
                let mut client = client.write().await;
                client.disconnect().await?;
            }
            #[cfg(feature = "postgres")]
            ManagedConnection::Postgres { pool, .. } => {
                pool.shutdown().await;
                // `tunnel` (if any) is dropped with the ManagedConnection,
                // cancelling the SSH local-forward accept loop.
            }
        }
        // `connection_id` is unused when no protocol arm consumes it (e.g.
        // a postgres-only build), so keep it referenced to avoid a warning.
        let _ = connection_id;
        Ok(())
    }

    #[cfg(any(
        feature = "ssh",
        feature = "sftp",
        feature = "ftp",
        feature = "desktop",
        feature = "postgres"
    ))]
    async fn replace_managed_connection(
        &self,
        connection_id: String,
        replacement: ManagedConnection,
    ) -> Result<()> {
        let previous = {
            let mut connections = self.connections.write().await;
            connections.remove(&connection_id)
        };

        if let Some(previous) = previous {
            self.disconnect_managed_connection(&connection_id, previous)
                .await?;
        }

        let mut connections = self.connections.write().await;
        connections.insert(connection_id, replacement);
        Ok(())
    }

    #[cfg(any(
        feature = "ssh",
        feature = "sftp",
        feature = "ftp",
        feature = "desktop",
        feature = "postgres"
    ))]
    async fn take_connection_if_kind(
        &self,
        connection_id: &str,
        expected: ConnectionSlotKind,
    ) -> Result<Option<ManagedConnection>> {
        let mut connections = self.connections.write().await;
        let Some(current) = connections.get(connection_id) else {
            return Ok(None);
        };

        if !expected.matches(current) {
            return Err(anyhow::anyhow!(
                "Connection '{}' is {}, not {}",
                connection_id,
                current.kind().as_str(),
                expected.label()
            ));
        }

        Ok(connections.remove(connection_id))
    }

    pub async fn cancel_pending_connection(&self, connection_id: &str) -> bool {
        let mut pending = self.pending_connections.write().await;
        if let Some(token) = pending.remove(connection_id) {
            token.cancel();
            true
        } else {
            false
        }
    }

    /// Close the SSH connection for `connection_id` (if it is SSH). Also tears
    /// down any associated PTY session and prunes the generation counter so it
    /// cannot leak across reconnects.
    #[cfg(feature = "ssh")]
    pub async fn close_connection(&self, connection_id: &str) -> Result<()> {
        if let Some(connection) = self
            .take_connection_if_kind(connection_id, ConnectionSlotKind::Ssh)
            .await?
        {
            self.disconnect_managed_connection(connection_id, connection)
                .await?;
        }
        Ok(())
    }

    // =========================================================================
    // PTY (interactive shell) management — only valid on SSH connections.
    // =========================================================================

    /// Start a PTY shell connection (like ttyd does).
    /// Enables interactive commands: vim, less, more, top, htop, etc.
    #[cfg(feature = "ssh")]
    pub async fn start_pty_connection(
        &self,
        connection_id: &str,
        cols: u32,
        rows: u32,
    ) -> Result<u64> {
        let client = self
            .get_connection(connection_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("Connection not found"))?;

        // Cancel and remove any existing PTY session for this connection first.
        // This ensures the old SSH channel and reader task are torn down before
        // we create a new one, preventing orphaned sessions.
        {
            let mut pty_sessions = self.pty_sessions.write().await;
            if let Some(old_session) = pty_sessions.remove(connection_id) {
                old_session.cancel.cancel();
                tracing::info!("Cancelled old PTY session for {}", connection_id);
            }
        }

        let pty = {
            let client = client.read().await;
            client.create_pty_session(cols, rows).await?
        };

        // Bump generation so any in-flight Close for the old session is ignored.
        let mut generations = self.pty_generations.write().await;
        let generation_entry = generations.entry(connection_id.to_string()).or_insert(0);
        *generation_entry += 1;
        let current_gen = *generation_entry;
        drop(generations);

        let mut pty_sessions = self.pty_sessions.write().await;
        pty_sessions.insert(connection_id.to_string(), Arc::new(pty));

        Ok(current_gen)
    }

    /// Send data to PTY (user input).
    ///
    /// Backpressure: if the input channel is full we await `send`, preserving
    /// keystroke order.
    #[cfg(feature = "ssh")]
    pub async fn write_to_pty(&self, connection_id: &str, data: Vec<u8>) -> Result<()> {
        let tx = {
            let pty_sessions = self.pty_sessions.read().await;
            let pty = pty_sessions
                .get(connection_id)
                .ok_or_else(|| anyhow::anyhow!("PTY connection not found"))?;
            pty.input_tx.clone()
        };

        tx.send(data)
            .await
            .map_err(|_| anyhow::anyhow!("PTY channel closed"))
    }

    /// Capture the active `PtySession` for a connection. Used by the macOS
    /// bridge to spawn an output-forwarder task that holds a stable handle
    /// to the session's `output_rx` for the lifetime of that PTY, even if
    /// `start_pty_connection` is later called again for the same connection
    /// (which would replace the entry in `pty_sessions`).
    #[cfg(feature = "ssh")]
    pub async fn get_pty_session(&self, connection_id: &str) -> Option<Arc<PtySession>> {
        self.pty_sessions.read().await.get(connection_id).cloned()
    }

    /// Read a burst of PTY output — blocks until data arrives, then drains any
    /// additional already-queued chunks up to `max_bytes`.
    #[cfg(feature = "ssh")]
    pub async fn read_pty_burst(&self, connection_id: &str, max_bytes: usize) -> Result<Vec<u8>> {
        let pty = {
            let pty_sessions = self.pty_sessions.read().await;
            pty_sessions
                .get(connection_id)
                .cloned()
                .ok_or_else(|| anyhow::anyhow!("PTY connection not found"))?
        };

        let mut rx = pty.output_rx.lock().await;

        let mut out = match rx.recv().await {
            Some(data) => data,
            None => return Err(anyhow::anyhow!("PTY connection closed")),
        };

        while out.len() < max_bytes {
            match rx.try_recv() {
                Ok(more) => out.extend_from_slice(&more),
                Err(tokio::sync::mpsc::error::TryRecvError::Empty) => break,
                Err(tokio::sync::mpsc::error::TryRecvError::Disconnected) => break,
            }
        }

        Ok(out)
    }

    /// Close PTY connection, but only if the generation matches.
    #[cfg(feature = "ssh")]
    pub async fn close_pty_connection(
        &self,
        connection_id: &str,
        expected_gen: Option<u64>,
    ) -> Result<()> {
        if let Some(expected_generation) = expected_gen {
            let generations = self.pty_generations.read().await;
            let current_gen = generations.get(connection_id).copied().unwrap_or(0);
            if current_gen != expected_generation {
                tracing::info!(
                    "Ignoring stale Close for {} (gen {} != current {})",
                    connection_id,
                    expected_generation,
                    current_gen
                );
                return Ok(());
            }
        }
        let mut pty_sessions = self.pty_sessions.write().await;
        if let Some(session) = pty_sessions.remove(connection_id) {
            session.cancel.cancel();
        }
        Ok(())
    }

    /// Get the cancellation token for a PTY session (used by WebSocket reader tasks).
    #[cfg(feature = "ssh")]
    pub async fn get_pty_cancel_token(&self, connection_id: &str) -> Option<CancellationToken> {
        let sessions = self.pty_sessions.read().await;
        sessions.get(connection_id).map(|s| s.cancel.clone())
    }

    /// Resize PTY terminal (send window-change to remote SSH channel)
    #[cfg(feature = "ssh")]
    pub async fn resize_pty(&self, connection_id: &str, cols: u32, rows: u32) -> Result<()> {
        let pty_sessions = self.pty_sessions.read().await;
        let pty = pty_sessions
            .get(connection_id)
            .ok_or_else(|| anyhow::anyhow!("PTY connection not found"))?;

        pty.resize_tx
            .send((cols, rows))
            .await
            .map_err(|_| anyhow::anyhow!("PTY resize channel closed"))
    }

    // =========================================================================
    // Standalone SFTP
    // =========================================================================

    #[cfg(feature = "sftp")]
    pub async fn create_sftp_connection(
        &self,
        connection_id: String,
        config: crate::sftp_client::SftpConfig,
    ) -> Result<()> {
        let client = StandaloneSftpClient::connect(&config, self.host_keys.clone()).await?;
        self.replace_managed_connection(
            connection_id,
            ManagedConnection::Sftp(Arc::new(RwLock::new(client))),
        )
        .await
    }

    #[cfg(feature = "sftp")]
    pub async fn close_sftp_connection(&self, connection_id: &str) -> Result<()> {
        if let Some(connection) = self
            .take_connection_if_kind(connection_id, ConnectionSlotKind::Sftp)
            .await?
        {
            self.disconnect_managed_connection(connection_id, connection)
                .await?;
        }
        Ok(())
    }

    // =========================================================================
    // FTP / FTPS
    // =========================================================================

    #[cfg(feature = "ftp")]
    pub async fn create_ftp_connection(
        &self,
        connection_id: String,
        config: crate::ftp_client::FtpConfig,
    ) -> Result<()> {
        let client = FtpClient::connect(&config).await?;
        self.replace_managed_connection(
            connection_id,
            ManagedConnection::Ftp(Arc::new(RwLock::new(client))),
        )
        .await
    }

    #[cfg(feature = "ftp")]
    pub async fn close_ftp_connection(&self, connection_id: &str) -> Result<()> {
        if let Some(connection) = self
            .take_connection_if_kind(connection_id, ConnectionSlotKind::Ftp)
            .await?
        {
            self.disconnect_managed_connection(connection_id, connection)
                .await?;
        }
        Ok(())
    }

    // =========================================================================
    // Remote desktop (RDP / VNC)
    // =========================================================================

    #[cfg(feature = "desktop")]
    pub async fn create_desktop_connection(
        &self,
        connection_id: String,
        request: &DesktopConnectRequest,
    ) -> Result<(u16, u16)> {
        use crate::desktop_protocol::DesktopKind;
        let (kind, client): (ProtocolKind, Box<dyn DesktopProtocol>) = match request.protocol {
            DesktopKind::Rdp => {
                let config = request.to_rdp_config();
                (
                    ProtocolKind::Rdp,
                    Box::new(RdpClient::connect(&config).await?),
                )
            }
            DesktopKind::Vnc => {
                let config = request.to_vnc_config();
                (
                    ProtocolKind::Vnc,
                    Box::new(VncClient::connect(&config).await?),
                )
            }
        };

        let (w, h) = client.desktop_size();

        self.replace_managed_connection(
            connection_id,
            ManagedConnection::Desktop {
                kind,
                client: Arc::new(RwLock::new(client)),
            },
        )
        .await?;

        Ok((w, h))
    }

    #[cfg(feature = "desktop")]
    pub async fn close_desktop_connection(&self, connection_id: &str) -> Result<()> {
        if let Some(connection) = self
            .take_connection_if_kind(connection_id, ConnectionSlotKind::Desktop)
            .await?
        {
            self.disconnect_managed_connection(connection_id, connection)
                .await?;
        }
        Ok(())
    }

    // =========================================================================
    // Postgres
    // =========================================================================

    /// Open a Postgres pool, optionally tunneled through an SSH connection
    /// this manager already owns. Available when both `postgres` and `ssh`
    /// features are enabled.
    #[cfg(all(feature = "postgres", feature = "ssh"))]
    pub async fn create_postgres_connection(
        &self,
        connection_id: String,
        mut config: PgConfig,
        tunnel: Option<SshTunnelRef>,
    ) -> Result<()> {
        // The tunnel seam lives here, not in the pool: if the profile
        // routes through SSH, this manager owns the already-open SSH
        // connection, so it stands up the `direct-tcpip` local forward
        // and points the pool's `PgConfig` at the loopback end. The
        // Postgres layer dials a plain host:port and has no knowledge of
        // SSH. Resolve the source up front so a missing one is a single
        // typed error rather than a partial connect.
        let tunnel_guard = if let Some(t) = tunnel {
            let ssh_client = match self.get_connection(&t.ssh_connection_id).await {
                Some(c) => c,
                None => {
                    return Err(anyhow::Error::from(
                        ssh_commander_pg::PgError::TunnelSourceMissing(format!(
                            "ssh connection '{}' is not registered or has been closed",
                            t.ssh_connection_id
                        )),
                    ));
                }
            };
            let opened = SshTunnel::open(ssh_client, t.remote_host.clone(), t.remote_port)
                .await
                .map_err(|e| {
                    anyhow::Error::from(ssh_commander_pg::PgError::Tunnel(e.to_string()))
                })?;
            // Redirect the pool at the local end of the forward.
            config.host = "127.0.0.1".to_string();
            config.port = opened.local_port();
            Some(Arc::new(opened))
        } else {
            None
        };

        let cancel_token = self.register_pending_connection(&connection_id).await;
        let connect_result = tokio::select! {
            res = PgPool::connect(config) => res.map_err(anyhow::Error::from),
            _ = cancel_token.cancelled() => Err(anyhow::anyhow!("Connection cancelled by user")),
        };
        self.clear_pending_connection(&connection_id).await;

        let pool = connect_result?;
        self.replace_managed_connection(
            connection_id,
            ManagedConnection::Postgres {
                pool,
                tunnel: tunnel_guard,
            },
        )
        .await
    }

    /// Open a Postgres pool. This build has no SSH feature, so there is no
    /// tunnel option — the pool connects directly to `config`'s host:port.
    #[cfg(all(feature = "postgres", not(feature = "ssh")))]
    pub async fn create_postgres_connection(
        &self,
        connection_id: String,
        config: PgConfig,
    ) -> Result<()> {
        let cancel_token = self.register_pending_connection(&connection_id).await;
        let connect_result = tokio::select! {
            res = PgPool::connect(config) => res.map_err(anyhow::Error::from),
            _ = cancel_token.cancelled() => Err(anyhow::anyhow!("Connection cancelled by user")),
        };
        self.clear_pending_connection(&connection_id).await;

        let pool = connect_result?;
        self.replace_managed_connection(connection_id, ManagedConnection::Postgres { pool })
            .await
    }

    #[cfg(feature = "postgres")]
    pub async fn close_postgres_connection(&self, connection_id: &str) -> Result<()> {
        if let Some(connection) = self
            .take_connection_if_kind(connection_id, ConnectionSlotKind::Postgres)
            .await?
        {
            self.disconnect_managed_connection(connection_id, connection)
                .await?;
        }
        Ok(())
    }

    /// Start the frame update loop for a desktop connection.
    ///
    /// Not yet wired up to the WebSocket server — kept here so the RDP/VNC
    /// stubs have a concrete dispatch point once the protocol clients gain
    /// real implementations. Remove the allow once a caller appears.
    #[cfg(feature = "desktop")]
    #[allow(dead_code)]
    pub async fn start_desktop_stream(
        &self,
        connection_id: &str,
        frame_tx: mpsc::UnboundedSender<FrameUpdate>,
        cancel: CancellationToken,
    ) -> Result<()> {
        let client = self
            .get_desktop_connection(connection_id)
            .await
            .ok_or_else(|| anyhow::anyhow!("Desktop connection not found: {}", connection_id))?;
        let client = client.read().await;
        client.start_frame_loop(frame_tx, cancel).await
    }
}

// =============================================================================
// Unit tests
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;
    #[cfg(all(feature = "desktop", feature = "ssh"))]
    use async_trait::async_trait;

    #[cfg(all(feature = "desktop", feature = "ssh"))]
    struct TestDesktopClient;

    #[cfg(all(feature = "desktop", feature = "ssh"))]
    #[async_trait]
    impl DesktopProtocol for TestDesktopClient {
        async fn start_frame_loop(
            &self,
            _frame_tx: mpsc::UnboundedSender<FrameUpdate>,
            _cancel: CancellationToken,
        ) -> Result<()> {
            Ok(())
        }

        async fn send_key(&self, _key_code: u32, _down: bool) -> Result<()> {
            Ok(())
        }

        async fn send_pointer(&self, _x: u16, _y: u16, _button_mask: u8) -> Result<()> {
            Ok(())
        }

        async fn request_full_frame(&self) -> Result<()> {
            Ok(())
        }

        async fn set_clipboard(&self, _text: String) -> Result<()> {
            Ok(())
        }

        fn desktop_size(&self) -> (u16, u16) {
            (1024, 768)
        }

        async fn resize(&mut self, _width: u16, _height: u16) -> Result<()> {
            Ok(())
        }

        async fn disconnect(&mut self) -> Result<()> {
            Ok(())
        }
    }

    #[cfg(all(feature = "ssh", feature = "desktop"))]
    fn disconnected_ssh_client() -> SshClient {
        SshClient::new(Arc::new(HostKeyStore::new(
            std::env::temp_dir().join("r-shell-test-known-hosts"),
        )))
    }

    #[tokio::test]
    async fn test_new_manager_has_no_connections() {
        let mgr = ConnectionManager::new();
        assert!(mgr.list_connections().await.is_empty());
    }

    #[tokio::test]
    async fn test_connection_kind_returns_none_for_unknown() {
        let mgr = ConnectionManager::new();
        assert!(mgr.connection_kind("unknown-id").await.is_none());
        assert!(mgr.get_connection_type("unknown-id").await.is_none());
    }

    #[tokio::test]
    async fn test_cancel_nonexistent_pending_connection() {
        let mgr = ConnectionManager::new();
        assert!(!mgr.cancel_pending_connection("ghost").await);
    }

    #[tokio::test]
    async fn test_protocol_kind_round_trip() {
        #[cfg(feature = "ssh")]
        assert_eq!(ProtocolKind::Ssh.as_str(), "SSH");
        #[cfg(feature = "sftp")]
        assert_eq!(ProtocolKind::Sftp.as_str(), "SFTP");
        #[cfg(feature = "ftp")]
        assert_eq!(ProtocolKind::Ftp.as_str(), "FTP");
        #[cfg(feature = "desktop")]
        assert_eq!(ProtocolKind::Rdp.as_str(), "RDP");
        #[cfg(feature = "desktop")]
        assert_eq!(ProtocolKind::Vnc.as_str(), "VNC");
        #[cfg(feature = "postgres")]
        assert_eq!(ProtocolKind::Postgres.as_str(), "POSTGRES");
    }

    #[cfg(feature = "postgres")]
    #[tokio::test]
    async fn test_close_postgres_of_unknown_id_is_noop() {
        let mgr = ConnectionManager::new();
        let result = mgr.close_postgres_connection("ghost").await;
        assert!(result.is_ok());
    }

    #[cfg(feature = "sftp")]
    #[tokio::test]
    async fn test_close_sftp_of_unknown_id_is_noop() {
        let mgr = ConnectionManager::new();
        let result = mgr.close_sftp_connection("ghost").await;
        assert!(result.is_ok());
    }

    #[cfg(feature = "ftp")]
    #[tokio::test]
    async fn test_close_ftp_of_unknown_id_is_noop() {
        let mgr = ConnectionManager::new();
        let result = mgr.close_ftp_connection("ghost").await;
        assert!(result.is_ok());
    }

    #[cfg(all(feature = "ssh", feature = "desktop"))]
    #[tokio::test]
    async fn test_close_connection_rejects_non_ssh_without_removing_it() {
        let mgr = ConnectionManager::new();
        {
            let mut connections = mgr.connections.write().await;
            connections.insert(
                "desktop".to_string(),
                ManagedConnection::Desktop {
                    kind: ProtocolKind::Rdp,
                    client: Arc::new(RwLock::new(Box::new(TestDesktopClient))),
                },
            );
        }

        let err = mgr
            .close_connection("desktop")
            .await
            .expect_err("closing an RDP connection through the SSH API must fail");
        assert!(err.to_string().contains("not SSH"));
        assert_eq!(
            mgr.connection_kind("desktop").await,
            Some(ProtocolKind::Rdp)
        );
    }

    #[cfg(all(feature = "ssh", feature = "desktop"))]
    #[tokio::test]
    async fn test_close_desktop_connection_rejects_ssh_without_removing_it() {
        let mgr = ConnectionManager::new();
        {
            let mut connections = mgr.connections.write().await;
            connections.insert(
                "ssh".to_string(),
                ManagedConnection::Ssh(Arc::new(RwLock::new(disconnected_ssh_client()))),
            );
        }

        let err = mgr
            .close_desktop_connection("ssh")
            .await
            .expect_err("closing an SSH connection through the desktop API must fail");
        assert!(err.to_string().contains("not desktop"));
        assert_eq!(mgr.connection_kind("ssh").await, Some(ProtocolKind::Ssh));
    }
}
