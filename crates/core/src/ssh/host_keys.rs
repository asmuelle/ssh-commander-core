use anyhow::{Context, Result};
use russh_keys::PublicKeyBase64;
use std::collections::HashMap;
use std::path::{Path, PathBuf};
use std::sync::Arc;
use tokio::sync::Mutex;

/// Result of verifying a server-offered host key against the local store.
#[derive(Debug, Clone)]
pub enum Verdict {
    /// Host is known and the key matches.
    Known,
    /// Host has never been seen — safe to TOFU-trust.
    Unknown,
    /// Host is known but the key has changed — refuse the connection.
    Mismatch {
        expected_fingerprint: String,
        got_fingerprint: String,
    },
}

/// Details surfaced to the user when `Verdict::Mismatch` caused a rejection.
#[derive(Debug, Clone)]
pub struct HostKeyMismatch {
    pub host: String,
    pub port: u16,
    pub expected_fingerprint: String,
    pub got_fingerprint: String,
    pub store_path: PathBuf,
}

/// Details surfaced to the user when host-key verification could not complete
/// because the trust store was unavailable.
#[derive(Debug, Clone)]
pub struct HostKeyStoreAccessError {
    pub host: String,
    pub port: u16,
    pub store_path: PathBuf,
    pub operation: &'static str,
    pub source: String,
}

/// Any verification failure that should be surfaced verbosely to the caller.
#[derive(Debug, Clone)]
pub enum HostKeyVerificationFailure {
    Mismatch(HostKeyMismatch),
    StoreAccess(HostKeyStoreAccessError),
}

/// Slot that a `Client` instance writes a host-key verification failure into
/// during the SSH handshake. The caller of `connect` reads it after the error
/// to build a descriptive user-facing message.
pub type VerificationFailureSlot = Arc<std::sync::Mutex<Option<HostKeyVerificationFailure>>>;

/// Persistent store of trusted SSH host keys (analogous to `~/.ssh/known_hosts`).
///
/// Internally lazily loaded on first use. Safe to clone `Arc<HostKeyStore>`
/// across many connections — all access is serialised through an async Mutex.
pub struct HostKeyStore {
    path: PathBuf,
    state: Mutex<Option<HashMap<String, String>>>,
}

impl HostKeyStore {
    pub fn new(path: PathBuf) -> Self {
        Self {
            path,
            state: Mutex::new(None),
        }
    }

    /// Default location: `$XDG_CONFIG_HOME/r-shell/known_hosts` (or platform
    /// equivalent via `dirs::config_dir()`).
    pub fn default_path() -> PathBuf {
        dirs::config_dir()
            .unwrap_or_else(std::env::temp_dir)
            .join("r-shell")
            .join("known_hosts")
    }

    pub fn path(&self) -> &Path {
        &self.path
    }

    /// Check whether the server-offered key matches the stored fingerprint for
    /// `(host, port)`. Does not mutate the store.
    pub async fn verify(
        &self,
        host: &str,
        port: u16,
        key: &russh_keys::key::PublicKey,
    ) -> Result<Verdict> {
        let offered = key.public_key_base64();
        let offered_fp = key.fingerprint();
        let key_id = Self::make_key(host, port);

        let mut guard = self.state.lock().await;
        if guard.is_none() {
            *guard = Some(Self::load_from_disk(&self.path).await?);
        }
        let entries = guard.as_ref().expect("state initialised above");

        let verdict = match entries.get(&key_id) {
            Some(stored) if stored == &offered => Verdict::Known,
            Some(stored) => Verdict::Mismatch {
                expected_fingerprint: fingerprint_from_stored(stored),
                got_fingerprint: offered_fp,
            },
            None => Verdict::Unknown,
        };

        Ok(verdict)
    }

    /// Persist the server-offered key as trusted for `(host, port)`.
    /// Creates the parent directory if missing.
    pub async fn trust(
        &self,
        host: &str,
        port: u16,
        key: &russh_keys::key::PublicKey,
    ) -> Result<()> {
        let offered = key.public_key_base64();
        let key_id = Self::make_key(host, port);

        let mut guard = self.state.lock().await;
        if guard.is_none() {
            *guard = Some(Self::load_from_disk(&self.path).await?);
        }

        let mut snapshot = guard.as_ref().cloned().unwrap_or_default();
        snapshot.insert(key_id, offered);

        self.write_to_disk(&snapshot).await?;
        *guard = Some(snapshot);
        Ok(())
    }

    /// Forget a previously-trusted host. Returns `true` if an entry was
    /// removed, `false` if there was nothing to remove. Used by the UI's
    /// "Trust new key" flow on a `HostKeyMismatch`: forget the stale
    /// entry, retry the connect, the next `verify()` falls through to
    /// `Verdict::Unknown` and the new key is TOFU-trusted.
    pub async fn forget(&self, host: &str, port: u16) -> Result<bool> {
        let key_id = Self::make_key(host, port);

        let mut guard = self.state.lock().await;
        if guard.is_none() {
            *guard = Some(Self::load_from_disk(&self.path).await?);
        }

        let mut snapshot = guard.as_ref().cloned().unwrap_or_default();
        let removed = snapshot.remove(&key_id).is_some();
        if removed {
            self.write_to_disk(&snapshot).await?;
            *guard = Some(snapshot);
        }
        Ok(removed)
    }

    /// Normalize host:port into a known_hosts-style key.
    /// Non-default ports use the `[host]:port` form to match OpenSSH conventions.
    fn make_key(host: &str, port: u16) -> String {
        if port == 22 {
            host.to_string()
        } else {
            format!("[{}]:{}", host, port)
        }
    }

    async fn load_from_disk(path: &Path) -> Result<HashMap<String, String>> {
        let mut map = HashMap::new();
        let content = match tokio::fs::read_to_string(path).await {
            Ok(s) => s,
            Err(e) if e.kind() == std::io::ErrorKind::NotFound => return Ok(map),
            Err(e) => {
                return Err(e)
                    .with_context(|| format!("failed to read known_hosts at {}", path.display()));
            }
        };

        for line in content.lines() {
            let trimmed = line.trim();
            if trimmed.is_empty() || trimmed.starts_with('#') {
                continue;
            }
            let mut parts = trimmed.splitn(2, char::is_whitespace);
            if let (Some(host_id), Some(key_blob)) = (parts.next(), parts.next()) {
                map.insert(host_id.to_string(), key_blob.trim().to_string());
            }
        }
        Ok(map)
    }

    async fn write_to_disk(&self, entries: &HashMap<String, String>) -> Result<()> {
        if let Some(parent) = self.path.parent() {
            tokio::fs::create_dir_all(parent)
                .await
                .with_context(|| format!("failed to create {}", parent.display()))?;
        }

        let mut content =
            String::from("# r-shell known hosts — auto-managed, one entry per host\n");
        let mut keys: Vec<&String> = entries.keys().collect();
        keys.sort();
        for k in keys {
            if let Some(v) = entries.get(k) {
                content.push_str(k);
                content.push(' ');
                content.push_str(v);
                content.push('\n');
            }
        }
        tokio::fs::write(&self.path, content)
            .await
            .with_context(|| format!("failed to write {}", self.path.display()))?;
        Ok(())
    }
}

/// Compute an SHA-256 fingerprint from a stored base64 public-key blob,
/// matching the format returned by `key::PublicKey::fingerprint()` so both
/// sides of a mismatch display in the same form.
fn fingerprint_from_stored(blob_b64: &str) -> String {
    match russh_keys::parse_public_key_base64(blob_b64) {
        Ok(key) => key.fingerprint(),
        Err(_) => String::from("<unparseable stored key>"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use russh_keys::key::KeyPair;
    use tempfile::TempDir;

    fn temp_store() -> (TempDir, HostKeyStore) {
        let dir = TempDir::new().expect("tmpdir");
        let path = dir.path().join("known_hosts");
        (dir, HostKeyStore::new(path))
    }

    #[test]
    fn make_key_uses_bracket_form_for_non_default_port() {
        assert_eq!(HostKeyStore::make_key("host", 22), "host");
        assert_eq!(HostKeyStore::make_key("host", 2222), "[host]:2222");
    }

    #[tokio::test]
    async fn unknown_host_yields_unknown_verdict() {
        let (_dir, store) = temp_store();
        // Load without any file present — should be empty, not an error.
        let mut guard = store.state.lock().await;
        *guard = Some(HostKeyStore::load_from_disk(store.path()).await.unwrap());
        assert!(guard.as_ref().unwrap().is_empty());
    }

    fn test_public_key() -> russh_keys::key::PublicKey {
        KeyPair::generate_ed25519()
            .expect("generate keypair")
            .clone_public_key()
            .expect("clone public key")
    }

    #[tokio::test]
    async fn verify_propagates_store_read_errors() {
        let dir = TempDir::new().expect("tmpdir");
        let store = HostKeyStore::new(dir.path().to_path_buf());

        let err = store
            .verify("host", 22, &test_public_key())
            .await
            .expect_err("directory path must not be treated as an empty store");

        assert!(err.to_string().contains("failed to read known_hosts"));
    }

    #[tokio::test]
    async fn trust_does_not_cache_keys_when_write_fails() {
        let dir = TempDir::new().expect("tmpdir");
        let file_parent = dir.path().join("not-a-dir");
        std::fs::write(&file_parent, "regular file").expect("write blocker file");
        let store = HostKeyStore::new(file_parent.join("known_hosts"));
        let key = test_public_key();

        store
            .trust("host", 22, &key)
            .await
            .expect_err("write should fail when parent is not a directory");

        let guard = store.state.lock().await;
        assert!(
            guard.as_ref().is_none_or(HashMap::is_empty),
            "failed trust must not mark the key as known in memory",
        );
    }
}
