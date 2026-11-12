use crate::file_entry::RemoteFileEntry;
use crate::transfer::TransferError;
use russh::keys::{HashAlg, PublicKeyBase64, PublicKeyOrCertificate};
use russh::*;
use russh_sftp::client::SftpSession;
use serde::{Deserialize, Serialize};
use std::path::Path;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::AsyncWriteExt;
use tokio::sync::mpsc;
use tokio_util::sync::CancellationToken;

pub mod error;
pub mod host_keys;
pub(crate) mod pty_registry;
pub(crate) mod sftp_ops;
pub mod shell;
pub mod tunnel;
pub use error::SshError;
pub use host_keys::{
    HostKeyMismatch, HostKeyStore, HostKeyStoreAccessError, HostKeyVerificationFailure, Verdict,
    VerificationFailureSlot,
};
pub use tunnel::{SshTunnel, SshTunnelRef};

/// Chunk size used for streaming SFTP transfers. 32 KiB balances throughput
/// against memory overhead for concurrent transfers. Larger sizes hit
/// diminishing returns because SFTP's window management caps effective
/// pipelining anyway.
pub const SFTP_CHUNK_SIZE: usize = crate::file_entry::FILE_TRANSFER_CHUNK_SIZE;

/// Host-key algorithms offered to the server by default, most preferred first.
///
/// Host-key algorithms are `ssh_key::Algorithm` values, re-exported as
/// `russh::keys::Algorithm`.
pub(crate) static MODERN_HOST_KEY_ALGOS: &[russh::keys::Algorithm] = &[
    russh::keys::Algorithm::Ed25519,
    russh::keys::Algorithm::Ecdsa {
        curve: russh::keys::EcdsaCurve::NistP256,
    },
    russh::keys::Algorithm::Ecdsa {
        curve: russh::keys::EcdsaCurve::NistP521,
    },
    russh::keys::Algorithm::Rsa {
        hash: Some(russh::keys::HashAlg::Sha256),
    },
    russh::keys::Algorithm::Rsa {
        hash: Some(russh::keys::HashAlg::Sha512),
    },
];

/// `ssh-rsa` host keys, i.e. RSA signatures over SHA-1. Offered only with
/// [`SshConfig::allow_legacy_algorithms`].
static LEGACY_HOST_KEY_ALGOS: &[russh::keys::Algorithm] =
    &[russh::keys::Algorithm::Rsa { hash: None }];

/// Key-exchange algorithms offered by default, most preferred first.
static MODERN_KEX_ALGOS: &[russh::kex::Name] = &[
    russh::kex::CURVE25519,
    russh::kex::CURVE25519_PRE_RFC_8731,
    russh::kex::DH_G16_SHA512,
    russh::kex::DH_G14_SHA256,
];

/// SHA-1 Diffie-Hellman key exchange (group14 and the 1024-bit group1).
/// Some older enterprise or managed SFTP endpoints still require these.
/// Offered only with [`SshConfig::allow_legacy_algorithms`].
static LEGACY_KEX_ALGOS: &[russh::kex::Name] = &[russh::kex::DH_G14_SHA1, russh::kex::DH_G1_SHA1];

/// Extension-negotiation markers. They must stay in the key-exchange offer
/// for ext-info and OpenSSH strict-KEX support.
static KEX_EXTENSION_MARKERS: &[russh::kex::Name] = &[
    russh::kex::EXTENSION_SUPPORT_AS_CLIENT,
    russh::kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
];

/// HMAC-SHA1. russh's default MAC list already leaves it out. Offered only
/// with [`SshConfig::allow_legacy_algorithms`], since servers old enough to
/// need SHA-1 key exchange often offer nothing newer.
static LEGACY_MAC_ALGOS: &[russh::mac::Name] = &[russh::mac::HMAC_SHA1_ETM, russh::mac::HMAC_SHA1];

/// Signature hashes tried for client RSA key authentication, in order.
/// SHA-1 (`None`, i.e. `ssh-rsa`) comes last and only with the opt-in.
fn rsa_signature_hashes(allow_legacy: bool) -> &'static [Option<HashAlg>] {
    if allow_legacy {
        &[Some(HashAlg::Sha512), Some(HashAlg::Sha256), None]
    } else {
        &[Some(HashAlg::Sha512), Some(HashAlg::Sha256)]
    }
}

/// The legacy algorithms in a server's offer that this client would accept
/// with [`SshConfig::allow_legacy_algorithms`]. Used to explain a failed
/// negotiation: an empty result means the opt-in would not help.
fn legacy_algorithms_offered_by_server(
    kind: &russh::AlgorithmKind,
    theirs: &[String],
) -> Vec<String> {
    let legacy: Vec<&str> = match kind {
        russh::AlgorithmKind::Kex => LEGACY_KEX_ALGOS.iter().map(|n| n.as_ref()).collect(),
        russh::AlgorithmKind::Key => LEGACY_HOST_KEY_ALGOS.iter().map(|a| a.as_str()).collect(),
        russh::AlgorithmKind::Mac => LEGACY_MAC_ALGOS.iter().map(|n| n.as_ref()).collect(),
        _ => Vec::new(),
    };
    theirs
        .iter()
        .filter(|name| legacy.contains(&name.as_str()))
        .cloned()
        .collect()
}

#[derive(Clone, Serialize, Deserialize)]
pub struct SshConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: AuthMethod,
    /// Also offer SHA-1 algorithms: `diffie-hellman-group14-sha1` and
    /// `diffie-hellman-group1-sha1` key exchange, `ssh-rsa` host keys,
    /// `hmac-sha1` MACs, and SHA-1 signatures for RSA key authentication.
    ///
    /// Off by default. Turn it on only for a server that can't negotiate
    /// anything newer; a connect to such a server fails with
    /// [`SshError::LegacyAlgorithmsRequired`] naming what it offered. The
    /// legacy algorithms are offered after every modern one, so a server that
    /// supports both still negotiates a modern algorithm.
    #[serde(default)]
    pub allow_legacy_algorithms: bool,
}

impl std::fmt::Debug for SshConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SshConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("auth_method", &self.auth_method)
            .field("allow_legacy_algorithms", &self.allow_legacy_algorithms)
            .finish()
    }
}

#[derive(Clone, Serialize, Deserialize)]
#[serde(tag = "type")]
pub enum AuthMethod {
    Password {
        password: String,
    },
    PublicKey {
        key_path: String,
        passphrase: Option<String>,
    },
    Agent {
        identity_hint: Option<String>,
    },
}

impl std::fmt::Debug for AuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            AuthMethod::Password { .. } => f
                .debug_struct("AuthMethod::Password")
                .field("password", &"<redacted>")
                .finish(),
            AuthMethod::PublicKey {
                key_path,
                passphrase,
            } => f
                .debug_struct("AuthMethod::PublicKey")
                .field("key_path", key_path)
                .field(
                    "passphrase",
                    &passphrase
                        .as_ref()
                        .map(|_| "<redacted>")
                        .unwrap_or("<none>"),
                )
                .finish(),
            AuthMethod::Agent { identity_hint } => f
                .debug_struct("AuthMethod::Agent")
                .field("identity_hint", identity_hint)
                .finish(),
        }
    }
}

pub struct SshClient {
    session: Option<Arc<client::Handle<Client>>>,
    host_keys: Arc<HostKeyStore>,
    /// Cached SFTP subsystem channel, opened lazily on first file op and
    /// reused thereafter. Avoids a channel-open round-trip per file op.
    /// Cleared by `disconnect`.
    sftp: tokio::sync::OnceCell<Arc<SftpSession>>,
}

/// Structured result of running a remote command. Callers that need to branch
/// on the exit code or separate the streams should consume this directly; the
/// convenience `execute_command` merges the streams for display.
#[derive(Debug, Clone, Default)]
pub struct CommandOutput {
    pub stdout: String,
    pub stderr: String,
    pub exit_code: Option<u32>,
}

impl CommandOutput {
    /// Did the command report a zero exit status?
    pub fn is_success(&self) -> bool {
        matches!(self.exit_code, Some(0))
    }

    /// stdout followed by stderr (separated by a newline only when both are
    /// non-empty). This is the legacy shape `execute_command` returned before
    /// the stderr fix, but now includes stderr instead of dropping it.
    pub fn combined(&self) -> String {
        if self.stderr.is_empty() {
            self.stdout.clone()
        } else if self.stdout.is_empty() {
            self.stderr.clone()
        } else {
            let mut out = String::with_capacity(self.stdout.len() + self.stderr.len() + 1);
            out.push_str(&self.stdout);
            if !self.stdout.ends_with('\n') {
                out.push('\n');
            }
            out.push_str(&self.stderr);
            out
        }
    }
}

/// Opaque handle to an open `direct-tcpip` SSH channel, as returned by
/// [`SshClient::open_direct_tcpip`]. Wraps the underlying russh channel so
/// this crate's public API doesn't expose russh types — consumers only need
/// the duplex byte stream.
pub struct TunnelChannel(russh::Channel<client::Msg>);

impl TunnelChannel {
    /// Consume the channel and expose it as a duplex byte stream suitable
    /// for splicing onto a local TCP socket.
    pub fn into_stream(
        self,
    ) -> impl tokio::io::AsyncRead + tokio::io::AsyncWrite + Send + Unpin + 'static {
        self.0.into_stream()
    }
}

// PTY session handle for interactive shell
pub struct PtySession {
    pub input_tx: mpsc::Sender<Vec<u8>>,
    pub output_rx: Arc<tokio::sync::Mutex<mpsc::Receiver<Vec<u8>>>>,
    /// Sender for resize requests (cols, rows) — forwarded to the SSH channel
    pub resize_tx: mpsc::Sender<(u32, u32)>,
    /// Cancellation token — cancelled when this session is torn down.
    /// The WebSocket reader task should select on this to stop promptly.
    pub cancel: CancellationToken,
}

/// russh Handler that verifies each server host key against a `HostKeyStore`.
///
/// On `Verdict::Known` the handshake proceeds. On `Verdict::Unknown` the key is
/// TOFU-trusted and persisted. On `Verdict::Mismatch` the handshake is rejected
/// and details are written to the shared verification-failure slot so the
/// caller can build a descriptive user-facing error.
pub(crate) struct Client {
    host: String,
    port: u16,
    store: Arc<HostKeyStore>,
    verification_failure_slot: VerificationFailureSlot,
}

impl Client {
    pub(crate) fn new(
        host: impl Into<String>,
        port: u16,
        store: Arc<HostKeyStore>,
    ) -> (Self, VerificationFailureSlot) {
        let slot: VerificationFailureSlot = Arc::new(std::sync::Mutex::new(None));
        let client = Self {
            host: host.into(),
            port,
            store,
            verification_failure_slot: slot.clone(),
        };
        (client, slot)
    }
}

/// The plain public key behind what the server presented, or `None` for a host
/// certificate.
///
/// russh >= 0.65 hands `check_server_key` either a bare key or an OpenSSH host
/// certificate. This client's host-key store only knows bare keys and has no
/// notion of trusted certificate authorities, so a certificate cannot be
/// verified and must be refused rather than trusted on first use.
fn plain_host_key(presented: &PublicKeyOrCertificate) -> Option<&russh::keys::PublicKey> {
    match presented {
        PublicKeyOrCertificate::PublicKey { key, .. } => Some(key),
        PublicKeyOrCertificate::Certificate(_) => None,
    }
}

/// Algorithm preferences offered to the server.
///
/// Without `allow_legacy` no SHA-1 algorithm is offered. With it, the legacy
/// algorithms are appended after every modern one.
///
/// `host_key_certificates` is deliberately left at russh's empty default: it
/// makes a server present a certificate instead of a bare key, which this
/// client cannot verify (see [`plain_host_key`]).
fn client_preferred(allow_legacy: bool) -> russh::Preferred {
    use std::borrow::Cow;

    let legacy_kex: &[russh::kex::Name] = if allow_legacy { LEGACY_KEX_ALGOS } else { &[] };
    let legacy_keys: &[russh::keys::Algorithm] = if allow_legacy {
        LEGACY_HOST_KEY_ALGOS
    } else {
        &[]
    };
    let legacy_macs: &[russh::mac::Name] = if allow_legacy { LEGACY_MAC_ALGOS } else { &[] };

    let defaults = russh::Preferred::DEFAULT;
    russh::Preferred {
        key: Cow::Owned(
            MODERN_HOST_KEY_ALGOS
                .iter()
                .chain(legacy_keys)
                .cloned()
                .collect(),
        ),
        kex: Cow::Owned(
            MODERN_KEX_ALGOS
                .iter()
                .chain(legacy_kex)
                .chain(KEX_EXTENSION_MARKERS)
                .copied()
                .collect(),
        ),
        mac: Cow::Owned(defaults.mac.iter().chain(legacy_macs).copied().collect()),
        ..defaults
    }
}

// russh uses RPITIT (no async_trait needed for the Handler trait itself).
impl client::Handler for Client {
    type Error = russh::Error;

    async fn check_server_key(
        &mut self,
        presented: &PublicKeyOrCertificate,
    ) -> Result<bool, Self::Error> {
        let Some(server_public_key) = plain_host_key(presented) else {
            // Not reachable while `client_preferred` advertises no certificate
            // algorithms; kept as a fail-closed guard in case that changes.
            tracing::error!(
                "refusing host certificate from {}:{}: certificate authorities are not supported",
                self.host,
                self.port
            );
            return Ok(false);
        };
        match self
            .store
            .verify(&self.host, self.port, server_public_key)
            .await
        {
            Ok(Verdict::Known) => {
                tracing::debug!(
                    "host key for {}:{} matches known_hosts",
                    self.host,
                    self.port
                );
                Ok(true)
            }
            Ok(Verdict::Unknown) => {
                tracing::warn!(
                    "TOFU: trusting new host key for {}:{} (fingerprint SHA256:{})",
                    self.host,
                    self.port,
                    // fingerprint() now requires a HashAlg argument in russh 0.61.
                    server_public_key.fingerprint(HashAlg::Sha256)
                );
                if let Err(e) = self
                    .store
                    .trust(&self.host, self.port, server_public_key)
                    .await
                {
                    tracing::error!("failed to persist host key: {}", e);
                    if let Ok(mut slot) = self.verification_failure_slot.lock() {
                        *slot = Some(HostKeyVerificationFailure::StoreAccess(
                            HostKeyStoreAccessError {
                                host: self.host.clone(),
                                port: self.port,
                                store_path: self.store.path().to_path_buf(),
                                operation: "write",
                                source: e.to_string(),
                            },
                        ));
                    }
                    return Err(
                        std::io::Error::other("failed to persist trusted SSH host key").into(),
                    );
                }
                Ok(true)
            }
            Ok(Verdict::Mismatch {
                expected_fingerprint,
                got_fingerprint,
            }) => {
                tracing::error!(
                    "host key mismatch for {}:{} — expected SHA256:{}, got SHA256:{}",
                    self.host,
                    self.port,
                    expected_fingerprint,
                    got_fingerprint
                );
                if let Ok(mut slot) = self.verification_failure_slot.lock() {
                    *slot = Some(HostKeyVerificationFailure::Mismatch(HostKeyMismatch {
                        host: self.host.clone(),
                        port: self.port,
                        expected_fingerprint,
                        got_fingerprint,
                        store_path: self.store.path().to_path_buf(),
                    }));
                }
                Ok(false)
            }
            Err(e) => {
                tracing::error!("failed to access host-key store: {}", e);
                if let Ok(mut slot) = self.verification_failure_slot.lock() {
                    *slot = Some(HostKeyVerificationFailure::StoreAccess(
                        HostKeyStoreAccessError {
                            host: self.host.clone(),
                            port: self.port,
                            store_path: self.store.path().to_path_buf(),
                            operation: "read",
                            source: e.to_string(),
                        },
                    ));
                }
                Err(std::io::Error::other("failed to access SSH host-key store").into())
            }
        }
    }
}

/// A resolved authentication payload, shared between SSH and standalone-SFTP
/// connection paths so they can use a single `connect_authenticated` helper
/// instead of duplicating the config-building / error-wrapping logic.
pub(crate) enum ResolvedAuth<'a> {
    Password {
        password: &'a str,
    },
    Key {
        /// In russh 0.61 the key type is `ssh_key::PrivateKey` (re-exported as
        /// `russh::keys::PrivateKey`), replacing the old `key::KeyPair`.
        key: Box<russh::keys::PrivateKey>,
        /// Optional hint for user-facing error messages (the key path the
        /// user asked us to load). Not used for the authentication itself.
        key_path_hint: Option<&'a str>,
    },
    Agent {
        identity_hint: Option<&'a str>,
    },
}

/// Perform the full SSH connect + authenticate sequence with host-key
/// verification and a timeout. Produces a descriptive error if the key
/// verification fails.
pub(crate) async fn connect_authenticated(
    host: &str,
    port: u16,
    username: &str,
    auth: ResolvedAuth<'_>,
    timeout: Duration,
    host_keys: Arc<HostKeyStore>,
    allow_legacy_algorithms: bool,
) -> Result<client::Handle<Client>, SshError> {
    let ssh_config = client::Config {
        preferred: client_preferred(allow_legacy_algorithms),
        keepalive_interval: Some(Duration::from_secs(60)),
        keepalive_max: 3,
        ..client::Config::default()
    };

    let (handler, verification_failure_slot) = Client::new(host, port, host_keys);

    let mut session = tokio::time::timeout(
        timeout,
        client::connect(Arc::new(ssh_config), (host, port), handler),
    )
    .await
    .map_err(|_| SshError::ConnectTimeout {
        seconds: timeout.as_secs(),
    })?
    .map_err(|e| {
        if let Ok(mut guard) = verification_failure_slot.lock()
            && let Some(failure) = guard.take()
        {
            return SshError::HostKeyVerification(failure);
        }

        // A server that only speaks legacy algorithms: name them and point
        // at the opt-in instead of surfacing russh's raw negotiation dump.
        if !allow_legacy_algorithms && let russh::Error::NoCommonAlgo { kind, theirs, .. } = &e {
            let algorithms = legacy_algorithms_offered_by_server(kind, theirs);
            if !algorithms.is_empty() {
                return SshError::LegacyAlgorithmsRequired {
                    host: host.to_string(),
                    port,
                    algorithms,
                };
            }
        }

        // "Connection reset by peer" during the initial handshake almost
        // always means either (a) the server's IP allowlist is excluding
        // us, or (b) an intermediate firewall / IDS is dropping the
        // connection based on source address or protocol. No amount of
        // KEX / cipher tuning on the client fixes either — the hint
        // points the user at the real remediation path.
        let msg = e.to_string();
        let looks_like_reset = msg.contains("reset by peer")
            || msg.contains("ConnectionReset")
            || msg.contains("kex_exchange_identification");
        let message = if looks_like_reset {
            format!(
                "The SSH server at {}:{} accepted the TCP connection but then \
                 reset it during the handshake ({}).\n\n\
                 This usually means the server is rejecting your source IP \
                 or SSH client via a firewall / access list. Try:\n\
                 - Confirm your public IP is on the server's allowlist (ask \
                   the service operator).\n\
                 - Connect over a VPN that terminates inside the allowed \
                   network.\n\
                 - Verify the host and port are correct for external access \
                   (some services publish a different SFTP endpoint).",
                host, port, e
            )
        } else {
            format!("Failed to connect to {}:{}: {}", host, port, e)
        };
        SshError::Connect {
            host: host.to_string(),
            port,
            message,
        }
    })?;

    // Capture what we need for the `!authenticated` error before moving `auth`
    // into the matching branch.
    let key_hint_for_error = match &auth {
        ResolvedAuth::Password { .. } => None,
        ResolvedAuth::Key { key_path_hint, .. } => key_path_hint.map(String::from),
        ResolvedAuth::Agent { identity_hint } => Some(
            identity_hint
                .filter(|hint| !hint.is_empty())
                .unwrap_or("SSH agent")
                .to_string(),
        ),
    };

    // russh 0.61: authenticate_* methods return AuthResult (Success / Failure enum)
    // rather than bool. Call .success() to map to the bool the guard below expects.
    let authenticated = match auth {
        ResolvedAuth::Password { password } => session
            .authenticate_password(username, password)
            .await
            .map_err(|e| SshError::Auth {
                message: format!("Password authentication failed: {}", e),
            })?
            .success(),
        ResolvedAuth::Key { key, .. } => {
            // authenticate_publickey takes a PrivateKeyWithHashAlg. For RSA
            // keys, hash_alg = None signs with SHA-1 (ssh-rsa), which OpenSSH
            // >= 8.8 rejects by default, so SHA-512 and SHA-256 are tried
            // first and SHA-1 only with the legacy opt-in. Non-RSA keys ignore
            // the hash alg, so a single None attempt uses their natural one.
            let key = Arc::new(*key);
            let hash_algs: &[Option<HashAlg>] =
                if matches!(key.algorithm(), russh::keys::Algorithm::Rsa { .. }) {
                    rsa_signature_hashes(allow_legacy_algorithms)
                } else {
                    &[None]
                };

            let mut authenticated = false;
            for hash_alg in hash_algs.iter().copied() {
                let key_with_alg =
                    russh::keys::key::PrivateKeyWithHashAlg::new(key.clone(), hash_alg);
                let auth = session
                    .authenticate_publickey(username, key_with_alg)
                    .await
                    .map_err(|e| SshError::Auth {
                        message: format!(
                            "Public key authentication failed: {}. The key may not be authorized on the server.",
                            e
                        ),
                    })?;
                if auth.success() {
                    authenticated = true;
                    break;
                }
            }
            authenticated
        }
        ResolvedAuth::Agent { identity_hint } => {
            // russh 0.61: authenticate_future is removed. Use authenticate_publickey_with,
            // which takes a public key + optional hash_alg + a &mut Signer. AgentClient
            // implements the Signer trait in russh 0.61 (russh::auth::Signer).
            let mut agent = russh::keys::agent::client::AgentClient::connect_env()
                .await
                .map_err(|e| SshError::Auth {
                    message: format!(
                        "SSH agent authentication is enabled, but r-shell could not connect to SSH_AUTH_SOCK: {}",
                        e
                    ),
                })?;
            let identities = agent
                .request_identities()
                .await
                .map_err(|e| SshError::Auth {
                    message: format!("SSH agent did not return identities: {}", e),
                })?;
            let identity = select_agent_identity(identities, identity_hint).ok_or_else(|| {
                let message = if let Some(hint) = identity_hint.filter(|hint| !hint.is_empty()) {
                    format!(
                        "SSH agent has no identity matching '{}'. Add the key to your agent or clear the identity hint.",
                        hint
                    )
                } else {
                    "SSH agent has no identities. Add a key to your agent and try again."
                        .to_string()
                };
                SshError::Auth { message }
            })?;
            // Extract the public key from the agent identity for authenticate_publickey_with.
            // As with key files, an RSA identity signs with SHA-2 first; a
            // `None` hash would ask the agent for an ssh-rsa (SHA-1) signature.
            let public_key = identity.public_key().into_owned();
            let hash_algs: &[Option<HashAlg>] =
                if matches!(public_key.algorithm(), russh::keys::Algorithm::Rsa { .. }) {
                    rsa_signature_hashes(allow_legacy_algorithms)
                } else {
                    &[None]
                };
            let mut authenticated = false;
            for hash_alg in hash_algs.iter().copied() {
                let auth = session
                    .authenticate_publickey_with(username, public_key.clone(), hash_alg, &mut agent)
                    .await
                    .map_err(|e| SshError::Auth {
                        message: format!("SSH agent authentication failed: {}", e),
                    })?;
                if auth.success() {
                    authenticated = true;
                    break;
                }
            }
            authenticated
        }
    };

    if !authenticated {
        let message = match key_hint_for_error {
            None => format!(
                "Authentication failed for {}@{} with password authentication.",
                username, host
            ),
            Some(path) => format!(
                "Authentication failed for {}@{} using public key {}.",
                username, host, path
            ),
        };
        return Err(SshError::Auth { message });
    }

    Ok(session)
}

/// Select an agent identity based on an optional hint string.
///
/// In russh 0.61, `request_identities` returns `Vec<AgentIdentity>` (which may be
/// a public key or a certificate) instead of `Vec<key::PublicKey>`. We compare
/// against the base64 of the underlying public key to preserve the existing hint
/// semantics.
fn select_agent_identity(
    identities: Vec<russh::keys::agent::AgentIdentity>,
    identity_hint: Option<&str>,
) -> Option<russh::keys::agent::AgentIdentity> {
    let hint = identity_hint.map(str::trim).filter(|hint| !hint.is_empty());

    match hint {
        None => identities.into_iter().next(),
        Some(hint) => identities.into_iter().find(|identity| {
            let encoded = identity.public_key().public_key_base64();
            encoded.contains(hint) || hint.contains(&encoded)
        }),
    }
}

/// Render a mismatch into a user-facing error message.
pub fn format_mismatch(m: &HostKeyMismatch) -> String {
    format!(
        "Host key verification failed for {}:{}.\n\
         Expected fingerprint (stored): SHA256:{}\n\
         Offered fingerprint (server):  SHA256:{}\n\
         If the remote host legitimately rotated its key, remove the entry from:\n  {}",
        m.host,
        m.port,
        m.expected_fingerprint,
        m.got_fingerprint,
        m.store_path.display()
    )
}

fn format_store_access_error(err: &HostKeyStoreAccessError) -> String {
    format!(
        "Host key verification could not complete for {}:{}.\n\
         r-shell could not {} the trusted host-key store at:\n  {}\n\
         Underlying error: {}\n\
         Connection refused to avoid trusting a host key without a durable trust store.",
        err.host,
        err.port,
        err.operation,
        err.store_path.display(),
        err.source
    )
}

pub fn format_verification_failure(failure: &HostKeyVerificationFailure) -> String {
    match failure {
        HostKeyVerificationFailure::Mismatch(mismatch) => format_mismatch(mismatch),
        HostKeyVerificationFailure::StoreAccess(err) => format_store_access_error(err),
    }
}

/// Expand a leading `~/` to the user's home directory via `dirs::home_dir()`.
/// Returns `None` if the path starts with `~/` but we cannot resolve home,
/// letting callers produce a specific error instead of silently returning the
/// literal tilde path.
pub(crate) fn expand_home_path(path: &str) -> Option<String> {
    if let Some(rest) = path.strip_prefix("~/") {
        let home = dirs::home_dir()?;
        Some(home.join(rest).to_string_lossy().into_owned())
    } else if path == "~" {
        dirs::home_dir().map(|h| h.to_string_lossy().into_owned())
    } else {
        Some(path.to_string())
    }
}

/// Load a private key from disk, returning the russh 0.61 `PrivateKey` type
/// (was `key::KeyPair` in older russh-keys).
pub(crate) fn load_private_key(
    key_path: &str,
    passphrase: Option<&str>,
) -> Result<russh::keys::PrivateKey, SshError> {
    let expanded = expand_home_path(key_path).ok_or_else(|| SshError::KeyLoad {
        message: format!(
            "Cannot resolve '~' in SSH key path '{}': home directory unknown.",
            key_path
        ),
    })?;
    let path = Path::new(&expanded);

    // Surface both forms when they differ so the user can see that expansion
    // happened and went where they expected.
    let location = if expanded != key_path {
        format!("{} (expanded from {})", expanded, key_path)
    } else {
        expanded.clone()
    };

    // Use `metadata()` (not `exists()`) so we can distinguish "not found" from
    // "found but unreadable". On macOS the latter is usually a TCC / Full Disk
    // Access denial, which the previous code silently reported as "not found".
    match path.metadata() {
        Ok(_) => {}
        Err(e) if e.kind() == std::io::ErrorKind::NotFound => {
            return Err(SshError::KeyLoad {
                message: format!(
                    "SSH key file not found: {}. Please check the file path and try again.",
                    location
                ),
            });
        }
        Err(e) if e.kind() == std::io::ErrorKind::PermissionDenied => {
            return Err(SshError::KeyLoad {
                message: format!(
                    "Permission denied reading SSH key at {}.\n\
                     On macOS this usually means r-shell hasn't been granted access to this file. \
                     Open System Settings → Privacy & Security → Full Disk Access (or App Management / Files and Folders), \
                     add r-shell to the list, then try again.",
                    location
                ),
            });
        }
        Err(e) => {
            return Err(SshError::KeyLoad {
                message: format!("Cannot access SSH key at {}: {}", location, e),
            });
        }
    }

    // load_secret_key lives in russh::keys in russh 0.61 (was from russh_keys:: wildcard).
    russh::keys::load_secret_key(path, passphrase).map_err(|e| {
        let msg = e.to_string();
        let message = if msg.contains("encrypted") || msg.contains("passphrase") {
            format!(
                "Failed to decrypt SSH key at {}. The key may be encrypted. Please provide the correct passphrase.",
                expanded
            )
        } else {
            format!(
                "Failed to load SSH key from {}: {}. Ensure the file is a valid SSH private key (RSA, Ed25519, or ECDSA).",
                expanded, e
            )
        };
        SshError::KeyLoad { message }
    })
}

impl SshClient {
    pub fn new(host_keys: Arc<HostKeyStore>) -> Self {
        Self {
            session: None,
            host_keys,
            sftp: tokio::sync::OnceCell::new(),
        }
    }

    /// Return a handle to a cached SFTP session, opening the subsystem on
    /// first call. Subsequent calls reuse the same session, saving the
    /// channel-open + subsystem-negotiation round-trip.
    async fn sftp_session(&self) -> Result<Arc<SftpSession>, TransferError> {
        let session = self
            .session
            .as_ref()
            .ok_or(TransferError::NotConnected("SSH"))?
            .clone();
        let sftp =
            self.sftp
                .get_or_try_init(|| async move {
                    let channel = session.channel_open_session().await.map_err(|e| {
                        TransferError::Session {
                            message: format!("Failed to open SFTP channel: {}", e),
                        }
                    })?;
                    channel.request_subsystem(true, "sftp").await.map_err(|e| {
                        TransferError::Session {
                            message: format!("Failed to start SFTP subsystem: {}", e),
                        }
                    })?;
                    let session = SftpSession::new(channel.into_stream()).await.map_err(|e| {
                        TransferError::Session {
                            message: format!("Failed to initialise SFTP session: {}", e),
                        }
                    })?;
                    Ok::<_, TransferError>(Arc::new(session))
                })
                .await?;
        Ok(sftp.clone())
    }

    pub async fn connect(&mut self, config: &SshConfig) -> Result<(), SshError> {
        let auth = match &config.auth_method {
            AuthMethod::Password { password } => ResolvedAuth::Password { password },
            AuthMethod::PublicKey {
                key_path,
                passphrase,
            } => ResolvedAuth::Key {
                key: Box::new(load_private_key(key_path, passphrase.as_deref())?),
                key_path_hint: Some(key_path.as_str()),
            },
            AuthMethod::Agent { identity_hint } => ResolvedAuth::Agent {
                identity_hint: identity_hint.as_deref(),
            },
        };

        let session = connect_authenticated(
            &config.host,
            config.port,
            &config.username,
            auth,
            Duration::from_secs(10),
            self.host_keys.clone(),
            config.allow_legacy_algorithms,
        )
        .await?;

        self.session = Some(Arc::new(session));
        Ok(())
    }

    /// Execute a remote command and return the combined stdout+stderr as a
    /// string, matching the shell-convention where both streams are interleaved
    /// in the user's view. Returns `Err` only for transport-level failures
    /// (session gone, channel couldn't open) — a nonzero exit code is a valid
    /// result, not an error, and its stdout/stderr is still returned.
    ///
    /// For callers that need to branch on the exit code or separate streams,
    /// use [`SshClient::execute_command_full`] instead.
    pub async fn execute_command(&self, command: &str) -> Result<String, SshError> {
        let out = self.execute_command_full(command).await?;
        Ok(out.combined())
    }

    /// Execute a remote command and return full stdout/stderr/exit-code.
    pub async fn execute_command_full(&self, command: &str) -> Result<CommandOutput, SshError> {
        let Some(session) = &self.session else {
            return Err(SshError::NotConnected);
        };

        let mut channel = session
            .channel_open_session()
            .await
            .map_err(SshError::transport)?;
        channel
            .exec(true, command)
            .await
            .map_err(SshError::transport)?;

        let mut stdout = String::new();
        let mut stderr = String::new();
        let mut exit_code: Option<u32> = None;
        let mut eof_received = false;

        loop {
            let msg = channel.wait().await;
            match msg {
                Some(ChannelMsg::Data { ref data }) => {
                    stdout.push_str(&String::from_utf8_lossy(data));
                }
                Some(ChannelMsg::ExtendedData { ref data, .. }) => {
                    // Extended data channel 1 = stderr (per RFC 4254 §5.2).
                    // Capture regardless of the `ext` code — servers occasionally
                    // send other codes and dropping them silently is worse than
                    // merging them into the stderr buffer.
                    stderr.push_str(&String::from_utf8_lossy(data));
                }
                Some(ChannelMsg::ExitStatus { exit_status }) => {
                    exit_code = Some(exit_status);
                    if eof_received {
                        break;
                    }
                }
                Some(ChannelMsg::Eof) => {
                    eof_received = true;
                    if exit_code.is_some() {
                        break;
                    }
                }
                Some(ChannelMsg::Close) | None => {
                    break;
                }
                _ => {}
            }
        }

        Ok(CommandOutput {
            stdout,
            stderr,
            exit_code,
        })
    }

    /// Execute a remote command and stream its stdout line-by-line over
    /// an mpsc channel. Returns the receiver and a cancellation token —
    /// dropping the receiver or cancelling the token tears down the
    /// channel.
    ///
    /// Used by long-running tools like `tcpdump` where the caller wants
    /// real-time line output instead of waiting for the command to exit.
    /// stderr lines are sent on the same channel prefixed with `"!"` so
    /// the consumer can distinguish them; the convention keeps the FFI
    /// surface a single string stream.
    pub async fn execute_command_streaming(
        &self,
        command: &str,
    ) -> Result<(mpsc::Receiver<String>, CancellationToken), SshError> {
        let Some(session) = &self.session else {
            return Err(SshError::NotConnected);
        };

        let mut channel = session
            .channel_open_session()
            .await
            .map_err(SshError::transport)?;
        channel
            .exec(true, command)
            .await
            .map_err(SshError::transport)?;

        let (tx, rx) = mpsc::channel::<String>(256);
        let cancel = CancellationToken::new();
        let cancel_task = cancel.clone();

        tokio::spawn(async move {
            // Buffers carry partial trailing lines across reads.
            let mut stdout_buf = String::new();
            let mut stderr_buf = String::new();
            loop {
                tokio::select! {
                    _ = cancel_task.cancelled() => {
                        let _ = channel.eof().await;
                        let _ = channel.close().await;
                        break;
                    }
                    msg = channel.wait() => {
                        match msg {
                            Some(ChannelMsg::Data { ref data }) => {
                                stdout_buf.push_str(&String::from_utf8_lossy(data));
                                while let Some(idx) = stdout_buf.find('\n') {
                                    let line: String = stdout_buf.drain(..=idx).collect();
                                    let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
                                    if tx.send(trimmed).await.is_err() {
                                        cancel_task.cancel();
                                        break;
                                    }
                                }
                            }
                            Some(ChannelMsg::ExtendedData { ref data, .. }) => {
                                stderr_buf.push_str(&String::from_utf8_lossy(data));
                                while let Some(idx) = stderr_buf.find('\n') {
                                    let line: String = stderr_buf.drain(..=idx).collect();
                                    let trimmed = line.trim_end_matches(['\r', '\n']).to_string();
                                    if tx.send(format!("!{}", trimmed)).await.is_err() {
                                        cancel_task.cancel();
                                        break;
                                    }
                                }
                            }
                            Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                                if !stdout_buf.is_empty() {
                                    let _ = tx.send(stdout_buf.trim_end_matches(['\r', '\n']).to_string()).await;
                                }
                                if !stderr_buf.is_empty() {
                                    let _ = tx.send(format!("!{}", stderr_buf.trim_end_matches(['\r', '\n']))).await;
                                }
                                break;
                            }
                            _ => {}
                        }
                    }
                }
            }
        });

        Ok((rx, cancel))
    }

    pub async fn disconnect(&mut self) -> Result<(), SshError> {
        // Drop the cached SFTP session first so its channel shuts cleanly
        // before we tear down the underlying SSH transport.
        self.sftp.take();

        if let Some(session) = self.session.take() {
            match Arc::try_unwrap(session) {
                Ok(session) => {
                    if let Err(e) = session.disconnect(Disconnect::ByApplication, "", "").await {
                        tracing::warn!("SSH disconnect failed cleanly: {}", e);
                    }
                }
                Err(arc_session) => {
                    // Other references (typically spawned PTY tasks) still
                    // exist. Drop ours — the session ends when the last
                    // reference dies.
                    tracing::debug!("SSH disconnect: other refs still alive, dropping handle");
                    drop(arc_session);
                }
            }
        }
        Ok(())
    }

    /// Open a `direct-tcpip` channel that the SSH server bridges to
    /// `(host, port)` as seen from the server's network. Used by the
    /// Postgres tunnel to forward a local TCP listener through this
    /// SSH session.
    ///
    /// `originator_address`/`originator_port` are reported to the server
    /// for logging/auditing and may be `127.0.0.1:0` when the caller
    /// doesn't have a meaningful client endpoint to advertise.
    pub async fn open_direct_tcpip(
        &self,
        host: &str,
        port: u16,
    ) -> Result<TunnelChannel, SshError> {
        let Some(session) = &self.session else {
            return Err(SshError::NotConnected);
        };
        let channel = session
            .channel_open_direct_tcpip(host.to_string(), port as u32, "127.0.0.1", 0)
            .await
            .map_err(SshError::transport)?;
        Ok(TunnelChannel(channel))
    }

    /// Create a persistent PTY shell session (like ttyd)
    /// This enables interactive commands like vim, less, more, top, etc.
    pub async fn create_pty_session(&self, cols: u32, rows: u32) -> Result<PtySession, SshError> {
        if let Some(session) = &self.session {
            // Open a new SSH channel
            let mut channel = session
                .channel_open_session()
                .await
                .map_err(SshError::transport)?;

            // Request PTY with terminal type and dimensions
            // Similar to ttyd's approach: xterm-256color terminal
            channel
                .request_pty(
                    true,             // want_reply
                    "xterm-256color", // terminal type (like ttyd)
                    cols,             // columns
                    rows,             // rows
                    0,                // pixel_width (not used)
                    0,                // pixel_height (not used)
                    &[],              // terminal modes
                )
                .await
                .map_err(SshError::transport)?;

            // Start interactive shell
            channel
                .request_shell(true)
                .await
                .map_err(SshError::transport)?;

            // Create channels for bidirectional communication (like ttyd's pty_buf)
            // Increased capacity for better buffering during fast input
            let (input_tx, mut input_rx) = mpsc::channel::<Vec<u8>>(1000); // Increased from 100
            let (output_tx, output_rx) = mpsc::channel::<Vec<u8>>(2000); // Increased from 1000

            // Clone channel for input task
            let input_channel = channel.make_writer();

            // Create a channel for resize requests
            let (resize_tx, mut resize_rx) = mpsc::channel::<(u32, u32)>(16);

            // The cancel token is created here and shared with both spawned
            // tasks *and* returned in `PtySession`. When `close_pty_connection`
            // cancels, every long-lived future on this session unblocks.
            let cancel = CancellationToken::new();

            // Spawn task to handle input (frontend → SSH)
            // This is similar to ttyd's pty_write and INPUT command handling
            // Key: immediate write + flush for responsiveness
            let input_cancel = cancel.clone();
            tokio::spawn(async move {
                let mut writer = input_channel;
                loop {
                    tokio::select! {
                        biased;
                        _ = input_cancel.cancelled() => {
                            tracing::debug!("[PTY] input task cancelled");
                            break;
                        }
                        maybe_data = input_rx.recv() => {
                            let Some(data) = maybe_data else {
                                // sender dropped — session torn down
                                break;
                            };
                            if let Err(e) = writer.write_all(&data).await {
                                tracing::error!("[PTY] failed to send data to SSH: {}", e);
                                break;
                            }
                            if let Err(e) = writer.flush().await {
                                tracing::error!("[PTY] failed to flush data to SSH: {}", e);
                                break;
                            }
                        }
                    }
                }
            });

            // Spawn task to handle output (SSH → frontend) AND resize requests.
            // The channel must stay in this task because `wait()` requires `&mut self`,
            // but we also need `window_change()` which only requires `&self`.
            // We use `tokio::select!` to multiplex between output reading, resize,
            // and cancellation. Without the cancel arm the task would outlive
            // `close_pty_connection` until the remote side eventually closes the
            // channel — see audit finding #7.
            let output_cancel = cancel.clone();
            tokio::spawn(async move {
                loop {
                    tokio::select! {
                        biased;
                        _ = output_cancel.cancelled() => {
                            tracing::debug!("[PTY] output task cancelled");
                            break;
                        }
                        msg = channel.wait() => {
                            match msg {
                                Some(ChannelMsg::Data { data })
                                    if output_tx.send(data.to_vec()).await.is_err() =>
                                {
                                    break;
                                }
                                Some(ChannelMsg::ExtendedData { data, .. })
                                    if output_tx.send(data.to_vec()).await.is_err() =>
                                {
                                    // stderr data (also send to output)
                                    break;
                                }
                                Some(ChannelMsg::Eof) | Some(ChannelMsg::Close) | None => {
                                    tracing::debug!("[PTY] channel closed");
                                    break;
                                }
                                Some(ChannelMsg::ExitStatus { exit_status }) => {
                                    tracing::info!("[PTY] process exited with status: {}", exit_status);
                                }
                                _ => {}
                            }
                        }
                        resize = resize_rx.recv() => {
                            match resize {
                                Some((cols, rows)) => {
                                    if let Err(e) = channel.window_change(cols, rows, 0, 0).await {
                                        tracing::error!("[PTY] failed to send window change: {}", e);
                                    } else {
                                        tracing::debug!("[PTY] window changed to {}x{}", cols, rows);
                                    }
                                }
                                None => {
                                    // resize channel closed, session is being torn down
                                    break;
                                }
                            }
                        }
                    }
                }
            });

            Ok(PtySession {
                input_tx,
                output_rx: Arc::new(tokio::sync::Mutex::new(output_rx)),
                resize_tx,
                cancel,
            })
        } else {
            Err(SshError::NotConnected)
        }
    }

    pub async fn list_dir(&self, path: &str) -> Result<Vec<RemoteFileEntry>, TransferError> {
        let sftp = self.sftp_session().await?;
        sftp_ops::list_dir(&sftp, path).await
    }

    pub async fn download_file(
        &self,
        remote_path: &str,
        local_path: &str,
    ) -> Result<u64, TransferError> {
        self.download_file_with_progress(remote_path, local_path, |_| {}, None)
            .await
    }

    /// Stream a remote file to disk, calling `progress` after every SFTP
    /// chunk with the running total of bytes transferred. Caller is
    /// responsible for knowing the file's total size — use `list_dir` /
    /// the entry's `size` field beforehand.
    ///
    /// The callback runs synchronously inside the read loop, so it must
    /// be cheap. The macOS bridge uses it to emit `TransferProgress`
    /// events on the event bus; the real work happens on the consumer
    /// thread that drains the bus, not here.
    ///
    /// `cancel`, when supplied, is checked between chunks. On
    /// cancellation the partial local file is left on disk (callers can
    /// delete it on receipt of the `TransferCancelled` error if they
    /// want clean removal — leaving it lets a future "resume" feature
    /// pick up where we left off).
    pub async fn download_file_with_progress(
        &self,
        remote_path: &str,
        local_path: &str,
        progress: impl FnMut(u64),
        cancel: Option<&CancellationToken>,
    ) -> Result<u64, TransferError> {
        let sftp = self.sftp_session().await?;
        sftp_ops::download_file(&sftp, remote_path, local_path, progress, cancel).await
    }

    pub async fn download_file_to_memory(
        &self,
        remote_path: &str,
    ) -> Result<Vec<u8>, TransferError> {
        let sftp = self.sftp_session().await?;
        sftp_ops::download_to_memory(&sftp, remote_path).await
    }

    pub async fn upload_file(
        &self,
        local_path: &str,
        remote_path: &str,
    ) -> Result<u64, TransferError> {
        self.upload_file_with_progress(local_path, remote_path, |_| {}, None)
            .await
    }

    /// Stream a local file to the remote, calling `progress` after every
    /// SFTP chunk. See `download_file_with_progress` for the threading
    /// constraints — the callback is on the same task as the SFTP I/O.
    ///
    /// `cancel` checks between chunks; on cancellation the partial
    /// remote file is left in place (call `delete_file` afterwards if
    /// clean removal is wanted).
    pub async fn upload_file_with_progress(
        &self,
        local_path: &str,
        remote_path: &str,
        progress: impl FnMut(u64),
        cancel: Option<&CancellationToken>,
    ) -> Result<u64, TransferError> {
        let sftp = self.sftp_session().await?;
        sftp_ops::upload_file(&sftp, local_path, remote_path, progress, cancel).await
    }

    pub async fn upload_file_from_bytes(
        &self,
        data: &[u8],
        remote_path: &str,
    ) -> Result<u64, TransferError> {
        let sftp = self.sftp_session().await?;
        sftp_ops::upload_from_bytes(&sftp, data, remote_path).await
    }

    /// Create a directory on the remote. Fails if the parent doesn't
    /// exist or the path is already taken.
    pub async fn create_dir(&self, path: &str) -> Result<(), TransferError> {
        let sftp = self.sftp_session().await?;
        sftp_ops::create_dir(&sftp, path).await
    }

    /// Rename a file or directory. SFTP RENAME is atomic when source
    /// and destination are on the same filesystem; cross-filesystem
    /// renames may copy-then-delete depending on the server.
    pub async fn rename(&self, old_path: &str, new_path: &str) -> Result<(), TransferError> {
        let sftp = self.sftp_session().await?;
        sftp_ops::rename(&sftp, old_path, new_path).await
    }

    /// Delete a regular file. For directories, use `delete_dir`.
    pub async fn delete_file(&self, path: &str) -> Result<(), TransferError> {
        let sftp = self.sftp_session().await?;
        sftp_ops::delete_file(&sftp, path).await
    }

    /// Delete an empty directory. SFTP requires the directory be empty;
    /// recursive removal would need a list-then-delete loop, which
    /// belongs at the caller layer (with progress reporting).
    pub async fn delete_dir(&self, path: &str) -> Result<(), TransferError> {
        let sftp = self.sftp_session().await?;
        sftp_ops::delete_dir(&sftp, path).await
    }
}

#[cfg(test)]
mod expand_home_tests {
    use super::expand_home_path;

    #[test]
    fn returns_non_tilde_paths_unchanged() {
        assert_eq!(
            expand_home_path("/absolute/path").as_deref(),
            Some("/absolute/path")
        );
        assert_eq!(
            expand_home_path("relative/dir").as_deref(),
            Some("relative/dir")
        );
        assert_eq!(expand_home_path("").as_deref(), Some(""));
    }

    #[test]
    fn expands_tilde_slash_prefix_when_home_is_known() {
        // We can't rely on a specific home_dir() value here, but we can assert
        // that the tilde is replaced and the suffix is preserved.
        let expanded = expand_home_path("~/.ssh/id_rsa");
        // When CI doesn't set HOME, dirs::home_dir may return None — tolerate both
        // outcomes and only assert the happy path.
        if let Some(result) = expanded {
            assert!(
                !result.starts_with("~/"),
                "tilde must be expanded: {}",
                result
            );
            assert!(
                result.ends_with("/.ssh/id_rsa"),
                "suffix preserved: {}",
                result
            );
        }
    }
}

#[cfg(test)]
mod command_output_tests {
    use super::CommandOutput;

    #[test]
    fn is_success_requires_zero_exit() {
        assert!(
            CommandOutput {
                stdout: "x".into(),
                stderr: "".into(),
                exit_code: Some(0),
            }
            .is_success()
        );
        assert!(
            !CommandOutput {
                stdout: "x".into(),
                stderr: "".into(),
                exit_code: Some(1),
            }
            .is_success()
        );
        assert!(
            !CommandOutput {
                stdout: "x".into(),
                stderr: "".into(),
                exit_code: None,
            }
            .is_success()
        );
    }

    #[test]
    fn combined_merges_streams_with_separator() {
        let c = CommandOutput {
            stdout: "out".into(),
            stderr: "err".into(),
            exit_code: Some(0),
        };
        assert_eq!(c.combined(), "out\nerr");
    }

    #[test]
    fn combined_preserves_trailing_newline() {
        let c = CommandOutput {
            stdout: "out\n".into(),
            stderr: "err".into(),
            exit_code: Some(0),
        };
        assert_eq!(c.combined(), "out\nerr");
    }

    #[test]
    fn combined_returns_single_stream_when_other_empty() {
        assert_eq!(
            CommandOutput {
                stdout: "only".into(),
                stderr: "".into(),
                exit_code: Some(0),
            }
            .combined(),
            "only"
        );
        assert_eq!(
            CommandOutput {
                stdout: "".into(),
                stderr: "only-err".into(),
                exit_code: Some(1),
            }
            .combined(),
            "only-err"
        );
    }
}

#[cfg(test)]
mod redaction_tests {
    use super::{AuthMethod, SshConfig};

    #[test]
    fn debug_redacts_password() {
        let cfg = SshConfig {
            host: "h".into(),
            port: 22,
            username: "u".into(),
            auth_method: AuthMethod::Password {
                password: "super-secret-123".into(),
            },
            allow_legacy_algorithms: false,
        };
        let rendered = format!("{:?}", cfg);
        assert!(
            !rendered.contains("super-secret-123"),
            "password must not appear in Debug output: {}",
            rendered
        );
        assert!(rendered.contains("<redacted>"), "expected redaction marker");
    }

    #[test]
    fn debug_redacts_passphrase() {
        let m = AuthMethod::PublicKey {
            key_path: "/tmp/id".into(),
            passphrase: Some("xyz-passphrase".into()),
        };
        let rendered = format!("{:?}", m);
        assert!(!rendered.contains("xyz-passphrase"));
        assert!(rendered.contains("<redacted>"));
        assert!(rendered.contains("/tmp/id"));
    }

    #[test]
    fn debug_shows_none_when_no_passphrase() {
        let m = AuthMethod::PublicKey {
            key_path: "/tmp/id".into(),
            passphrase: None,
        };
        let rendered = format!("{:?}", m);
        assert!(rendered.contains("<none>"));
    }
}

#[cfg(test)]
mod key_loading_tests {
    use super::load_private_key;
    use std::io::Write;
    use tempfile::NamedTempFile;

    const TEST_OPENSSH_PRIVATE_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM\n\
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg\n\
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf\n\
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==\n\
-----END OPENSSH PRIVATE KEY-----\n";

    #[test]
    fn load_private_key_reads_key_file_contents() {
        let mut key_file = NamedTempFile::new().expect("failed to create temp key file");
        key_file
            .write_all(TEST_OPENSSH_PRIVATE_KEY.as_bytes())
            .expect("failed to write temp key file");

        let key = load_private_key(
            key_file
                .path()
                .to_str()
                .expect("temp key path must be valid UTF-8"),
            None,
        )
        .expect("expected key file to load successfully");

        // russh 0.61: PrivateKey uses algorithm() → Algorithm instead of name() → &str.
        // Algorithm implements Display, producing the wire-format algorithm name.
        assert_eq!(key.algorithm().to_string(), "ssh-ed25519");
    }
}

#[cfg(test)]
mod host_key_policy_tests {
    use super::{MODERN_HOST_KEY_ALGOS, client_preferred, plain_host_key};
    use russh::keys::{Certificate, PrivateKey, PublicKeyOrCertificate, ssh_key};
    use ssh_key::certificate::{Builder, CertType};

    // Throwaway ed25519 key used only to sign a test certificate.
    const TEST_KEY: &str = "\
-----BEGIN OPENSSH PRIVATE KEY-----\n\
b3BlbnNzaC1rZXktdjEAAAAABG5vbmUAAAAEbm9uZQAAAAAAAAABAAAAMwAAAAtzc2gtZW\n\
QyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYgAAAJgAIAxdACAM\n\
XQAAAAtzc2gtZWQyNTUxOQAAACCzPq7zfqLffKoBDe/eo04kH2XxtSmk9D7RQyf1xUqrYg\n\
AAAEC2BsIi0QwW2uFscKTUUXNHLsYX4FxlaSDSblbAj7WR7bM+rvN+ot98qgEN796jTiQf\n\
ZfG1KaT0PtFDJ/XFSqtiAAAAEHVzZXJAZXhhbXBsZS5jb20BAgMEBQ==\n\
-----END OPENSSH PRIVATE KEY-----\n";

    fn test_key() -> PrivateKey {
        PrivateKey::from_openssh(TEST_KEY).expect("test key parses")
    }

    fn test_certificate(key: &PrivateKey) -> Certificate {
        let mut builder = Builder::new(vec![0u8; 32], key.public_key(), 0, u64::MAX)
            .expect("certificate builder");
        builder
            .cert_type(CertType::Host)
            .expect("host certificate type")
            .valid_principal("host.example.test")
            .expect("principal");
        builder.sign(key).expect("certificate signs")
    }

    #[test]
    fn plain_public_key_is_passed_through_to_the_host_key_store() {
        let key = test_key();
        let presented = PublicKeyOrCertificate::PublicKey {
            key: key.public_key().clone(),
            hash_alg: None,
        };
        assert_eq!(plain_host_key(&presented), Some(key.public_key()));
    }

    #[test]
    fn host_certificate_is_never_treated_as_a_trusted_key() {
        let key = test_key();
        let presented = PublicKeyOrCertificate::Certificate(test_certificate(&key));
        assert!(
            plain_host_key(&presented).is_none(),
            "a host certificate must not reach the TOFU host-key store"
        );
    }

    #[test]
    fn client_does_not_advertise_certificate_host_key_algorithms() {
        for allow_legacy in [false, true] {
            let preferred = client_preferred(allow_legacy);
            assert!(
                preferred.host_key_certificates.is_empty(),
                "advertising certificates makes servers present ones we cannot verify"
            );
        }
        assert_eq!(&*client_preferred(false).key, MODERN_HOST_KEY_ALGOS);
    }
}

#[cfg(test)]
mod algorithm_policy_tests {
    use super::{client_preferred, legacy_algorithms_offered_by_server, rsa_signature_hashes};
    use russh::keys::{Algorithm, HashAlg};
    use russh::{AlgorithmKind, kex, mac};

    const SHA1_KEX: [kex::Name; 2] = [kex::DH_G14_SHA1, kex::DH_G1_SHA1];
    const SHA1_MAC: [mac::Name; 2] = [mac::HMAC_SHA1_ETM, mac::HMAC_SHA1];
    const SSH_RSA: Algorithm = Algorithm::Rsa { hash: None };

    #[test]
    fn default_offer_has_no_sha1_algorithms() {
        let preferred = client_preferred(false);
        for name in SHA1_KEX {
            assert!(
                !preferred.kex.contains(&name),
                "{name:?} offered by default"
            );
        }
        for name in SHA1_MAC {
            assert!(
                !preferred.mac.contains(&name),
                "{name:?} offered by default"
            );
        }
        assert!(
            !preferred.key.contains(&SSH_RSA),
            "ssh-rsa offered by default"
        );
        assert!(preferred.kex.contains(&kex::CURVE25519));
        assert!(
            preferred
                .kex
                .contains(&kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT)
        );
    }

    #[test]
    fn legacy_opt_in_adds_sha1_algorithms_after_every_modern_one() {
        let modern = client_preferred(false);
        let legacy = client_preferred(true);

        for name in SHA1_KEX {
            assert!(legacy.kex.contains(&name), "{name:?} missing with opt-in");
        }
        for name in SHA1_MAC {
            assert!(legacy.mac.contains(&name), "{name:?} missing with opt-in");
        }
        assert!(legacy.key.contains(&SSH_RSA));

        // Modern algorithms keep their order and all come first, so a server
        // that supports both still negotiates a modern one.
        assert_eq!(&legacy.key[..modern.key.len()], &*modern.key);
        assert_eq!(&legacy.mac[..modern.mac.len()], &*modern.mac);
        let first_legacy_kex = legacy
            .kex
            .iter()
            .position(|n| SHA1_KEX.contains(n))
            .expect("legacy kex present");
        for name in modern.kex.iter() {
            let at = legacy
                .kex
                .iter()
                .position(|n| n == name)
                .expect("modern kex kept");
            // Extension markers aren't real algorithms; their position is free.
            let is_marker = [
                kex::EXTENSION_SUPPORT_AS_CLIENT,
                kex::EXTENSION_OPENSSH_STRICT_KEX_AS_CLIENT,
            ]
            .contains(name);
            if !is_marker {
                assert!(at < first_legacy_kex, "{name:?} must precede SHA-1 kex");
            }
        }
    }

    #[test]
    fn ssh_config_keeps_legacy_algorithms_off_unless_requested() {
        let json = r#"{"host":"h","port":22,"username":"u","auth_method":{"type":"Password","password":"p"}}"#;
        let config: super::SshConfig = serde_json::from_str(json).expect("deserialize");
        assert!(!config.allow_legacy_algorithms);
    }

    #[test]
    fn rsa_client_signatures_use_sha1_only_with_opt_in() {
        assert_eq!(
            rsa_signature_hashes(false),
            &[Some(HashAlg::Sha512), Some(HashAlg::Sha256)]
        );
        assert_eq!(
            rsa_signature_hashes(true),
            &[Some(HashAlg::Sha512), Some(HashAlg::Sha256), None]
        );
    }

    #[test]
    fn server_offering_only_legacy_kex_is_reported() {
        let theirs = vec![
            "diffie-hellman-group14-sha1".to_string(),
            "diffie-hellman-group1-sha1".to_string(),
        ];
        assert_eq!(
            legacy_algorithms_offered_by_server(&AlgorithmKind::Kex, &theirs),
            theirs
        );
    }

    #[test]
    fn server_offering_only_ssh_rsa_host_keys_is_reported() {
        let theirs = vec!["ssh-rsa".to_string(), "ssh-dss".to_string()];
        assert_eq!(
            legacy_algorithms_offered_by_server(&AlgorithmKind::Key, &theirs),
            vec!["ssh-rsa".to_string()]
        );
    }

    #[test]
    fn server_offering_only_hmac_sha1_is_reported() {
        let theirs = vec!["hmac-sha1".to_string(), "hmac-md5".to_string()];
        assert_eq!(
            legacy_algorithms_offered_by_server(&AlgorithmKind::Mac, &theirs),
            vec!["hmac-sha1".to_string()]
        );
    }

    #[test]
    fn mismatch_unrelated_to_the_opt_in_is_not_reported() {
        let ciphers = vec!["3des-cbc".to_string()];
        assert!(legacy_algorithms_offered_by_server(&AlgorithmKind::Cipher, &ciphers).is_empty());
        let dss_only = vec!["ssh-dss".to_string()];
        assert!(legacy_algorithms_offered_by_server(&AlgorithmKind::Key, &dss_only).is_empty());
    }
}

#[cfg(test)]
mod tests;
