use russh::*;
use russh_sftp::client::SftpSession;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;

use crate::file_entry::RemoteFileEntry;
use crate::ssh::{Client, HostKeyStore, SshError, sftp_ops};
use crate::transfer::TransferError;

/// Configuration for a standalone SFTP connection (SSH transport, no PTY).
#[derive(Clone, Deserialize)]
pub struct SftpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub auth_method: SftpAuthMethod,
}

impl std::fmt::Debug for SftpConfig {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        f.debug_struct("SftpConfig")
            .field("host", &self.host)
            .field("port", &self.port)
            .field("username", &self.username)
            .field("auth_method", &self.auth_method)
            .finish()
    }
}

#[derive(Clone, Deserialize)]
#[serde(tag = "type")]
pub enum SftpAuthMethod {
    Password {
        password: String,
    },
    PublicKey {
        key_path: String,
        passphrase: Option<String>,
    },
}

impl std::fmt::Debug for SftpAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            SftpAuthMethod::Password { .. } => f
                .debug_struct("SftpAuthMethod::Password")
                .field("password", &"<redacted>")
                .finish(),
            SftpAuthMethod::PublicKey {
                key_path,
                passphrase,
            } => f
                .debug_struct("SftpAuthMethod::PublicKey")
                .field("key_path", key_path)
                .field(
                    "passphrase",
                    &passphrase
                        .as_ref()
                        .map(|_| "<redacted>")
                        .unwrap_or("<none>"),
                )
                .finish(),
        }
    }
}

/// Standalone SFTP client — opens an SSH connection and SFTP subsystem
/// channel without allocating a PTY.
pub struct StandaloneSftpClient {
    session: Option<Arc<client::Handle<Client>>>,
    sftp: Option<SftpSession>,
}

impl StandaloneSftpClient {
    /// Establish an SSH connection, authenticate, and open the SFTP subsystem.
    pub async fn connect(
        config: &SftpConfig,
        host_keys: Arc<HostKeyStore>,
    ) -> Result<Self, SshError> {
        let auth = match &config.auth_method {
            SftpAuthMethod::Password { password } => {
                crate::ssh::ResolvedAuth::Password { password }
            }
            SftpAuthMethod::PublicKey {
                key_path,
                passphrase,
            } => crate::ssh::ResolvedAuth::Key {
                key: Box::new(crate::ssh::load_private_key(
                    key_path,
                    passphrase.as_deref(),
                )?),
                key_path_hint: Some(key_path),
            },
        };

        let ssh_session = crate::ssh::connect_authenticated(
            &config.host,
            config.port,
            &config.username,
            auth,
            Duration::from_secs(10),
            host_keys,
        )
        .await?;
        let session = Arc::new(ssh_session);

        // Open an SFTP subsystem channel (no PTY)
        let channel = session
            .channel_open_session()
            .await
            .map_err(SshError::transport)?;
        channel
            .request_subsystem(true, "sftp")
            .await
            .map_err(SshError::transport)?;
        let sftp = SftpSession::new(channel.into_stream())
            .await
            .map_err(SshError::transport)?;

        Ok(Self {
            session: Some(session),
            sftp: Some(sftp),
        })
    }

    pub async fn disconnect(&mut self) -> Result<(), SshError> {
        // Drop SFTP session first
        self.sftp.take();
        // Disconnect SSH session
        if let Some(session) = self.session.take() {
            match Arc::try_unwrap(session) {
                Ok(session) => {
                    if let Err(e) = session.disconnect(Disconnect::ByApplication, "", "").await {
                        tracing::warn!("SFTP SSH disconnect failed cleanly: {}", e);
                    }
                }
                Err(arc_session) => {
                    // Other references (e.g. pending SFTP ops) still exist;
                    // drop ours. The session ends when the last reference dies.
                    drop(arc_session);
                }
            }
        }
        Ok(())
    }

    // ===== File Operations =====
    //
    // All file operations delegate to `crate::ssh::sftp_ops`, the single
    // implementation shared with `SshClient` — behavior and error messages
    // stay identical across both SFTP entry points.

    /// Borrow the live SFTP session or fail with a consistent
    /// "not connected" error.
    fn sftp(&self) -> Result<&SftpSession, TransferError> {
        self.sftp
            .as_ref()
            .ok_or(TransferError::NotConnected("SFTP"))
    }

    /// List directory contents at `path`.
    pub async fn list_dir(&self, path: &str) -> Result<Vec<RemoteFileEntry>, TransferError> {
        sftp_ops::list_dir(self.sftp()?, path).await
    }

    /// Download a remote file to a local path. Streams chunks — never buffers
    /// the whole file. Returns bytes downloaded.
    pub async fn download_file(
        &self,
        remote_path: &str,
        local_path: &str,
    ) -> Result<u64, TransferError> {
        sftp_ops::download_file(self.sftp()?, remote_path, local_path, |_| {}, None).await
    }

    /// Upload a local file to a remote path. Streams chunks — never buffers
    /// the whole file. Returns bytes uploaded.
    pub async fn upload_file(
        &self,
        local_path: &str,
        remote_path: &str,
    ) -> Result<u64, TransferError> {
        sftp_ops::upload_file(self.sftp()?, local_path, remote_path, |_| {}, None).await
    }

    /// Create a directory on the remote server.
    pub async fn create_dir(&self, path: &str) -> Result<(), TransferError> {
        sftp_ops::create_dir(self.sftp()?, path).await
    }

    /// Rename a file or directory.
    pub async fn rename(&self, old_path: &str, new_path: &str) -> Result<(), TransferError> {
        sftp_ops::rename(self.sftp()?, old_path, new_path).await
    }

    /// Delete a file on the remote server.
    pub async fn delete_file(&self, path: &str) -> Result<(), TransferError> {
        sftp_ops::delete_file(self.sftp()?, path).await
    }

    /// Delete a directory on the remote server.
    pub async fn delete_dir(&self, path: &str) -> Result<(), TransferError> {
        sftp_ops::delete_dir(self.sftp()?, path).await
    }
}

// =============================================================================
// Unit tests — Task 4.3
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_sftp_config_deserialization() {
        let json = r#"{"host":"10.0.0.1","port":22,"username":"admin","auth_method":{"type":"Password","password":"secret"}}"#;
        let config: SftpConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.host, "10.0.0.1");
        assert_eq!(config.port, 22);
        assert_eq!(config.username, "admin");
        match config.auth_method {
            SftpAuthMethod::Password { password } => assert_eq!(password, "secret"),
            _ => panic!("Expected Password auth method"),
        }
    }

    #[test]
    fn test_sftp_config_publickey() {
        let json = r#"{"host":"server","port":2222,"username":"deploy","auth_method":{"type":"PublicKey","key_path":"/home/user/.ssh/id_rsa","passphrase":null}}"#;
        let config: SftpConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.port, 2222);
        match config.auth_method {
            SftpAuthMethod::PublicKey {
                key_path,
                passphrase,
            } => {
                assert_eq!(key_path, "/home/user/.ssh/id_rsa");
                assert!(passphrase.is_none());
            }
            _ => panic!("Expected PublicKey auth method"),
        }
    }
}
