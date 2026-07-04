//! Typed errors for the SSH client surface.
//!
//! Consumers can match on the failure class — host-key verification vs.
//! authentication vs. transport — instead of parsing strings. The `Display`
//! output of each variant preserves the user-facing messages the clients
//! have always produced, so error text shown in UIs is unchanged.

use super::format_verification_failure;
use super::host_keys::HostKeyVerificationFailure;

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum SshError {
    /// The server's host key failed verification — either a mismatch against
    /// the trusted store (possible MITM or legitimate key rotation) or the
    /// store itself could not be read/written. The structured details are
    /// preserved for callers that drive a "trust new key" flow.
    #[error("{}", format_verification_failure(.0))]
    HostKeyVerification(HostKeyVerificationFailure),

    #[error("Connection timed out after {seconds}s. Please check the host address and network.")]
    ConnectTimeout { seconds: u64 },

    /// TCP / handshake-level connect failure (includes the firewall-allowlist
    /// hint when the server resets the connection during KEX).
    #[error("{message}")]
    Connect {
        host: String,
        port: u16,
        message: String,
    },

    /// The server rejected authentication, or the auth exchange itself
    /// failed (agent unreachable, no matching identity, …).
    #[error("{message}")]
    Auth { message: String },

    /// A private key could not be located, read, or decrypted.
    #[error("{message}")]
    KeyLoad { message: String },

    #[error("Not connected")]
    NotConnected,

    /// Transport or channel failure on an established session.
    #[error("{message}")]
    Transport { message: String },
}

impl SshError {
    /// Wrap a transport-layer failure, type-erasing the underlying library
    /// error so it doesn't become part of this crate's public API.
    pub(crate) fn transport(e: impl std::fmt::Display) -> Self {
        Self::Transport {
            message: e.to_string(),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::ssh::host_keys::HostKeyMismatch;

    #[test]
    fn host_key_variant_displays_full_mismatch_message() {
        let err =
            SshError::HostKeyVerification(HostKeyVerificationFailure::Mismatch(HostKeyMismatch {
                host: "example.com".into(),
                port: 22,
                expected_fingerprint: "AAAA".into(),
                got_fingerprint: "BBBB".into(),
                store_path: "/tmp/known_hosts".into(),
            }));
        let rendered = err.to_string();
        assert!(rendered.contains("Host key verification failed for example.com:22"));
        assert!(rendered.contains("SHA256:AAAA"));
        assert!(rendered.contains("SHA256:BBBB"));
    }

    #[test]
    fn variants_are_matchable_by_class() {
        let err = SshError::Auth {
            message: "Authentication failed for user@host with password authentication.".into(),
        };
        assert!(matches!(err, SshError::Auth { .. }));
        assert!(!matches!(err, SshError::NotConnected));
    }
}
