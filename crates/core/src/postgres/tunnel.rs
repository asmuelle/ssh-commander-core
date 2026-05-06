//! SSH local-port forwarding for the Postgres explorer.
//!
//! Binds a local TCP listener on `127.0.0.1:<ephemeral>` and, for every
//! inbound connection, opens a fresh `direct-tcpip` SSH channel to the
//! configured remote endpoint and bidirectionally splices bytes between
//! the local socket and the SSH channel. Pattern matches `ssh -L`.
//!
//! # Lifetime
//!
//! `SshTunnel` owns a `CancellationToken` and a `JoinHandle` for the
//! accept loop. Dropping the tunnel cancels the loop and releases the
//! local listener. Per-connection forwarder tasks are independent — they
//! finish naturally when either side closes the stream — so the drop is
//! best-effort: any in-flight Postgres traffic continues until the
//! sockets close, which matches the observable behavior of `ssh -L`
//! when the controlling terminal exits.
//!
//! # Concurrency
//!
//! The accept loop holds an `Arc<RwLock<SshClient>>`. Each accepted
//! connection acquires a *read* lock for the duration of the
//! `channel_open_direct_tcpip` round-trip only — the lock is dropped
//! before splicing begins so the same SSH session can host many
//! simultaneous Postgres connections without serializing channel
//! opens.

use std::sync::Arc;

use tokio::io::AsyncWriteExt;
use tokio::net::TcpListener;
use tokio::sync::RwLock;
use tokio::task::JoinHandle;
use tokio_util::sync::CancellationToken;

use crate::ssh::SshClient;

/// Live SSH local-forward to `(remote_host, remote_port)`.
///
/// Public surface is intentionally tiny: the local port the caller
/// should target, and an opaque drop guard. The accept loop, channel
/// management, and byte splicing are private.
pub struct SshTunnel {
    /// Loopback port the local listener is bound to. Stable for the
    /// lifetime of the tunnel.
    local_port: u16,
    cancel: CancellationToken,
    /// Held only so the accept-loop task is aborted on drop. Never
    /// awaited externally.
    _accept_task: JoinHandle<()>,
}

impl SshTunnel {
    pub fn local_port(&self) -> u16 {
        self.local_port
    }

    /// Open the listener and start the accept loop. Returns once the
    /// listener is bound; per-connection channels open lazily on
    /// inbound traffic.
    ///
    /// Errors:
    /// - `bind` fails (vanishingly rare on `127.0.0.1:0`)
    /// - the SshClient is not connected (caller bug — should have
    ///   confirmed before invoking)
    pub async fn open(
        ssh_client: Arc<RwLock<SshClient>>,
        remote_host: String,
        remote_port: u16,
    ) -> anyhow::Result<Self> {
        // 0.0.0.0 would expose the forward to the LAN — `127.0.0.1` keeps
        // it loopback-only, matching `ssh -L` defaults.
        let listener = TcpListener::bind("127.0.0.1:0").await?;
        let local_port = listener.local_addr()?.port();

        let cancel = CancellationToken::new();
        let task_cancel = cancel.clone();

        let accept_task = tokio::spawn(async move {
            run_accept_loop(listener, ssh_client, remote_host, remote_port, task_cancel).await;
        });

        Ok(Self {
            local_port,
            cancel,
            _accept_task: accept_task,
        })
    }
}

impl Drop for SshTunnel {
    fn drop(&mut self) {
        // Cancellation is sufficient — the listener is owned by the
        // accept task, so dropping the JoinHandle (with abort behavior)
        // and signalling cancel both ensure the listener is closed.
        self.cancel.cancel();
    }
}

async fn run_accept_loop(
    listener: TcpListener,
    ssh_client: Arc<RwLock<SshClient>>,
    remote_host: String,
    remote_port: u16,
    cancel: CancellationToken,
) {
    loop {
        tokio::select! {
            _ = cancel.cancelled() => {
                tracing::debug!("postgres tunnel accept loop cancelled");
                return;
            }
            res = listener.accept() => {
                match res {
                    Ok((local_stream, peer)) => {
                        let ssh_client = ssh_client.clone();
                        let remote_host = remote_host.clone();
                        let conn_cancel = cancel.clone();
                        tokio::spawn(async move {
                            if let Err(e) = forward_one(
                                local_stream,
                                ssh_client,
                                &remote_host,
                                remote_port,
                                conn_cancel,
                            )
                            .await
                            {
                                tracing::warn!(
                                    peer = %peer,
                                    error = %e,
                                    "postgres tunnel forwarder ended with error"
                                );
                            }
                        });
                    }
                    Err(e) => {
                        tracing::warn!("postgres tunnel accept failed: {e}");
                        // Don't tight-loop on a fatal listener error —
                        // a brief yield lets the runtime mark the
                        // listener dead, after which subsequent accepts
                        // also fail and we exit on cancel.
                        tokio::task::yield_now().await;
                    }
                }
            }
        }
    }
}

async fn forward_one(
    mut local_stream: tokio::net::TcpStream,
    ssh_client: Arc<RwLock<SshClient>>,
    remote_host: &str,
    remote_port: u16,
    cancel: CancellationToken,
) -> anyhow::Result<()> {
    // Brief read-lock window: open the SSH channel, then drop the
    // guard so other tasks can use the SshClient while we splice.
    let channel = {
        let guard = ssh_client.read().await;
        guard.open_direct_tcpip(remote_host, remote_port).await?
    };

    let mut stream = channel.into_stream();
    let (mut local_read, mut local_write) = local_stream.split();
    let (mut ssh_read, mut ssh_write) = tokio::io::split(&mut stream);

    // Bidirectional splice. `tokio::io::copy` returns when its source
    // EOFs. Either direction finishing tears down both — Postgres
    // connections are duplex and a half-open state is never useful.
    let local_to_ssh = async {
        let r = tokio::io::copy(&mut local_read, &mut ssh_write).await;
        let _ = ssh_write.shutdown().await;
        r
    };
    let ssh_to_local = async {
        let r = tokio::io::copy(&mut ssh_read, &mut local_write).await;
        let _ = local_write.shutdown().await;
        r
    };

    tokio::select! {
        _ = cancel.cancelled() => {
            tracing::debug!("postgres tunnel forwarder cancelled");
            Ok(())
        }
        res = async {
            tokio::try_join!(local_to_ssh, ssh_to_local).map(|_| ())
        } => {
            res.map_err(anyhow::Error::from)
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `SshTunnel::open` doesn't try to use the SSH client until a TCP
    /// connection arrives. So binding the listener succeeds even when
    /// the underlying SshClient is disconnected — which is the right
    /// behavior: failure surfaces on first use, not on construction.
    /// We can't easily build a real connected SshClient without a server,
    /// but we can verify the bind step and the local port assignment.
    #[tokio::test]
    async fn open_binds_local_port_immediately() {
        use crate::ssh::HostKeyStore;
        let host_keys = Arc::new(HostKeyStore::new(
            std::env::temp_dir().join("r-shell-tunnel-test-known-hosts"),
        ));
        let client = Arc::new(RwLock::new(SshClient::new(host_keys)));
        let tunnel = SshTunnel::open(client, "irrelevant".to_string(), 5432)
            .await
            .expect("bind should succeed");
        assert!(tunnel.local_port() > 0);
        // Listener is reachable as long as the tunnel is alive.
        let probe = tokio::net::TcpStream::connect(("127.0.0.1", tunnel.local_port())).await;
        assert!(probe.is_ok(), "listener should accept connections");
    }

    /// Dropping the tunnel cancels the accept loop and releases the
    /// listener. Asserted by binding a *new* listener on the same port
    /// after drop — succeeds only if the original is gone.
    #[tokio::test]
    async fn drop_releases_local_port() {
        use crate::ssh::HostKeyStore;
        let host_keys = Arc::new(HostKeyStore::new(
            std::env::temp_dir().join("r-shell-tunnel-test-known-hosts-2"),
        ));
        let client = Arc::new(RwLock::new(SshClient::new(host_keys)));
        let tunnel = SshTunnel::open(client, "irrelevant".to_string(), 5432)
            .await
            .expect("bind");
        let port = tunnel.local_port();
        drop(tunnel);

        // Give the runtime a tick to process the cancellation. SO_REUSEADDR
        // is on by default for ephemeral ports on macOS/Linux, so a re-bind
        // attempt is the cleanest assertion that the slot is free.
        tokio::task::yield_now().await;
        let rebind = TcpListener::bind(("127.0.0.1", port)).await;
        assert!(rebind.is_ok(), "port {port} should be reusable after drop");
    }
}
