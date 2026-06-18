use anyhow::Result;
use russh::*;
use russh_sftp::client::SftpSession;
use serde::Deserialize;
use std::sync::Arc;
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::file_entry::{
    FileEntryType, RemoteFileEntry, format_permissions, format_unix_timestamp,
};
use crate::ssh::{Client, HostKeyStore};

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
    pub async fn connect(config: &SftpConfig, host_keys: Arc<HostKeyStore>) -> Result<Self> {
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
        let channel = session.channel_open_session().await?;
        channel.request_subsystem(true, "sftp").await?;
        let sftp = SftpSession::new(channel.into_stream()).await?;

        Ok(Self {
            session: Some(session),
            sftp: Some(sftp),
        })
    }

    pub async fn disconnect(&mut self) -> Result<()> {
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

    /// List directory contents at `path`.
    pub async fn list_dir(&self, path: &str) -> Result<Vec<RemoteFileEntry>> {
        let sftp = self
            .sftp
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SFTP session not connected"))?;

        let entries = sftp
            .read_dir(path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to list directory '{}': {}", path, e))?;

        let mut result = Vec::new();
        for entry in entries {
            let name = entry.file_name();
            // Skip . and .. entries
            if name == "." || name == ".." {
                continue;
            }

            let attrs = entry.metadata();
            let size = attrs.size.unwrap_or(0);
            let mtime_secs = attrs.mtime.map(|t| t as i64);
            let modified = mtime_secs.map(format_unix_timestamp);

            let permissions = attrs.permissions.map(format_permissions);
            let owner = attrs.uid.map(|u| u.to_string());
            let group = attrs.gid.map(|g| g.to_string());

            let file_type = if attrs.is_dir() {
                FileEntryType::Directory
            } else if attrs.is_symlink() {
                FileEntryType::Symlink
            } else {
                FileEntryType::File
            };

            result.push(RemoteFileEntry {
                name,
                size,
                modified,
                modified_unix: mtime_secs,
                permissions,
                owner,
                group,
                file_type,
            });
        }

        // Sort: directories first, then by name
        result.sort_by(|a, b| {
            let a_is_dir = matches!(a.file_type, FileEntryType::Directory);
            let b_is_dir = matches!(b.file_type, FileEntryType::Directory);
            b_is_dir
                .cmp(&a_is_dir)
                .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
        });

        Ok(result)
    }

    /// Download a remote file to a local path. Streams chunks — never buffers
    /// the whole file. Returns bytes downloaded.
    pub async fn download_file(&self, remote_path: &str, local_path: &str) -> Result<u64> {
        let sftp = self
            .sftp
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SFTP session not connected"))?;

        let mut remote_file = sftp
            .open(remote_path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to open remote file '{}': {}", remote_path, e))?;
        let mut local_file = tokio::fs::File::create(local_path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create local file '{}': {}", local_path, e))?;

        let mut buf = vec![0u8; crate::ssh::SFTP_CHUNK_SIZE];
        let mut total_bytes = 0u64;
        loop {
            let n = remote_file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            local_file.write_all(&buf[..n]).await?;
            total_bytes += n as u64;
        }
        local_file.flush().await?;
        Ok(total_bytes)
    }

    /// Upload a local file to a remote path. Streams chunks — never buffers
    /// the whole file. Returns bytes uploaded.
    pub async fn upload_file(&self, local_path: &str, remote_path: &str) -> Result<u64> {
        let sftp = self
            .sftp
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SFTP session not connected"))?;

        let mut local_file = tokio::fs::File::open(local_path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to open local file '{}': {}", local_path, e))?;
        let mut remote_file = sftp.create(remote_path).await.map_err(|e| {
            anyhow::anyhow!("Failed to create remote file '{}': {}", remote_path, e)
        })?;

        let mut buf = vec![0u8; crate::ssh::SFTP_CHUNK_SIZE];
        let mut total_bytes = 0u64;
        loop {
            let n = local_file.read(&mut buf).await?;
            if n == 0 {
                break;
            }
            remote_file.write_all(&buf[..n]).await?;
            total_bytes += n as u64;
        }
        remote_file.flush().await?;

        Ok(total_bytes)
    }

    /// Create a directory on the remote server.
    pub async fn create_dir(&self, path: &str) -> Result<()> {
        let sftp = self
            .sftp
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SFTP session not connected"))?;

        sftp.create_dir(path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to create directory '{}': {}", path, e))?;
        Ok(())
    }

    /// Rename a file or directory.
    pub async fn rename(&self, old_path: &str, new_path: &str) -> Result<()> {
        let sftp = self
            .sftp
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SFTP session not connected"))?;

        sftp.rename(old_path, new_path).await.map_err(|e| {
            anyhow::anyhow!("Failed to rename '{}' to '{}': {}", old_path, new_path, e)
        })?;
        Ok(())
    }

    /// Delete a file on the remote server.
    pub async fn delete_file(&self, path: &str) -> Result<()> {
        let sftp = self
            .sftp
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SFTP session not connected"))?;

        sftp.remove_file(path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to delete file '{}': {}", path, e))?;
        Ok(())
    }

    /// Delete a directory on the remote server.
    pub async fn delete_dir(&self, path: &str) -> Result<()> {
        let sftp = self
            .sftp
            .as_ref()
            .ok_or_else(|| anyhow::anyhow!("SFTP session not connected"))?;

        sftp.remove_dir(path)
            .await
            .map_err(|e| anyhow::anyhow!("Failed to delete directory '{}': {}", path, e))?;
        Ok(())
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
