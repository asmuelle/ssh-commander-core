use serde::Deserialize;
use std::io::{Read, Write};
use std::time::Duration;
use tokio::io::{AsyncReadExt, AsyncWriteExt};

use crate::file_entry::{FileEntry, FileEntryType};
use crate::transfer::TransferError;

/// Typed errors for the FTP/FTPS connect path. File operations return
/// [`TransferError`], shared with the SFTP clients.
#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum FtpError {
    /// TCP-level connect failure or timeout.
    #[error("{message}")]
    Connect { message: String },

    /// FTPS TLS handshake failure.
    #[error("{message}")]
    Tls { message: String },

    /// The server rejected the login.
    #[error("{message}")]
    Auth { message: String },

    /// Post-login protocol failure (e.g. switching to binary mode).
    #[error("{message}")]
    Protocol { message: String },
}

/// Configuration for an FTP/FTPS connection.
#[derive(Clone, Deserialize)]
pub struct FtpConfig {
    pub host: String,
    pub port: u16,
    pub username: String,
    pub password: String,
    pub ftps_enabled: bool,
    pub anonymous: bool,
    /// Extra trust anchors for FTPS: one or more PEM-encoded certificates,
    /// trusted **in addition to** the system roots.
    ///
    /// For a server with a self-signed certificate, pass that certificate;
    /// for a private CA, pass the CA. The host name is still checked against
    /// the certificate either way. Certificate validation can't be turned
    /// off. Malformed PEM, or PEM with no certificate in it, fails the
    /// connect with [`FtpError::Tls`] rather than silently falling back to
    /// the system roots. Ignored for plain FTP.
    ///
    /// Saved profiles from before 0.4 may still carry `allow_invalid_certs`;
    /// it is ignored.
    #[serde(default)]
    pub tls_root_certs_pem: Option<String>,
}

const PEM_CERTIFICATE_BEGIN: &str = "-----BEGIN CERTIFICATE-----";
const PEM_CERTIFICATE_END: &str = "-----END CERTIFICATE-----";

/// Parse every `CERTIFICATE` block in `pem`. Fails closed: a block without
/// an END line, a block that doesn't parse, or no block at all is an error.
/// Error messages never echo the PEM itself.
fn parse_pem_certificates(
    pem: &str,
) -> Result<Vec<suppaftp::async_native_tls::Certificate>, FtpError> {
    let invalid = |reason: String| FtpError::Tls {
        message: format!("custom root certificates: {reason}"),
    };
    let mut certs = Vec::new();
    let mut rest = pem;
    while let Some(start) = rest.find(PEM_CERTIFICATE_BEGIN) {
        let block_and_rest = &rest[start..];
        let end = block_and_rest
            .find(PEM_CERTIFICATE_END)
            .ok_or_else(|| invalid("a certificate block has no END line".to_string()))?
            + PEM_CERTIFICATE_END.len();
        let cert =
            suppaftp::async_native_tls::Certificate::from_pem(&block_and_rest.as_bytes()[..end])
                .map_err(|e| invalid(format!("certificate {} is invalid: {e}", certs.len() + 1)))?;
        certs.push(cert);
        rest = &block_and_rest[end..];
    }
    if certs.is_empty() {
        return Err(invalid("no certificate found in the PEM".to_string()));
    }
    Ok(certs)
}

/// The FTPS TLS connector: system roots plus `extra_roots_pem`, with
/// certificate and host-name validation always on.
fn build_tls_connector(
    extra_roots_pem: Option<&str>,
) -> Result<suppaftp::async_native_tls::TlsConnector, FtpError> {
    let mut connector = suppaftp::async_native_tls::TlsConnector::new();
    if let Some(pem) = extra_roots_pem {
        for cert in parse_pem_certificates(pem)? {
            connector = connector.add_root_certificate(cert);
        }
    }
    Ok(connector)
}

/// Wrapper enum to handle both plain and TLS FTP streams.
enum FtpStreamKind {
    Plain(suppaftp::tokio::AsyncFtpStream),
    Secure(suppaftp::tokio::AsyncNativeTlsFtpStream),
}

/// Dispatch a method call to whichever stream variant is active.
macro_rules! ftp_stream {
    ($self:expr, $s:ident => $body:expr) => {{
        let kind = $self
            .stream
            .as_mut()
            .ok_or(TransferError::NotConnected("FTP"))?;
        match kind {
            FtpStreamKind::Plain($s) => $body,
            FtpStreamKind::Secure($s) => $body,
        }
    }};
}

/// FTP/FTPS client using `suppaftp` with async support.
pub struct FtpClient {
    stream: Option<FtpStreamKind>,
}

impl FtpClient {
    /// Connect to an FTP server, authenticate, and switch to binary transfer mode.
    pub async fn connect(config: &FtpConfig) -> Result<Self, FtpError> {
        let addr = format!("{}:{}", config.host, config.port);

        tracing::info!(
            "FTP connecting to {} (ftps={}, anonymous={})",
            addr,
            config.ftps_enabled,
            config.anonymous
        );

        // suppaftp runs on tokio, so tokio's timeout bounds the TCP connect.
        let timeout_duration = Duration::from_secs(15);

        let mut stream_kind = if config.ftps_enabled {
            let ftp_stream = tokio::time::timeout(
                timeout_duration,
                suppaftp::tokio::AsyncNativeTlsFtpStream::connect(&addr),
            )
            .await
            .map_err(|_| FtpError::Connect {
                message: format!(
                    "FTPS connection timed out after 15s. Check host {} and port {}.",
                    config.host, config.port
                ),
            })?
            .map_err(|e| FtpError::Connect {
                message: format!("FTPS TCP connect to {} failed: {}", addr, e),
            })?;

            tracing::info!("FTPS TCP connected, starting TLS handshake...");

            let tls_connector = build_tls_connector(config.tls_root_certs_pem.as_deref())?;
            let secure_stream = ftp_stream
                .into_secure(
                    suppaftp::tokio::AsyncNativeTlsConnector::from(tls_connector),
                    &config.host,
                )
                .await
                .map_err(|e| FtpError::Tls {
                    message: format!(
                        "FTPS TLS handshake failed: {}. \
                         If the server uses a self-signed certificate or a private CA, \
                         add that certificate as a trusted root certificate.",
                        e
                    ),
                })?;

            tracing::info!("FTPS TLS handshake complete");
            FtpStreamKind::Secure(secure_stream)
        } else {
            let ftp_stream = tokio::time::timeout(
                timeout_duration,
                suppaftp::tokio::AsyncFtpStream::connect(&addr),
            )
            .await
            .map_err(|_| FtpError::Connect {
                message: format!(
                    "FTP connection timed out after 15s. Check host {} and port {}.",
                    config.host, config.port
                ),
            })?
            .map_err(|e| FtpError::Connect {
                message: format!("FTP TCP connect to {} failed: {}", addr, e),
            })?;

            tracing::info!("FTP TCP connected to {}", addr);
            FtpStreamKind::Plain(ftp_stream)
        };

        // Authenticate
        {
            let (user, pass) = if config.anonymous {
                ("anonymous", "anonymous@")
            } else {
                (config.username.as_str(), config.password.as_str())
            };
            tracing::info!("FTP authenticating as '{}'", user);
            match &mut stream_kind {
                FtpStreamKind::Plain(s) => s.login(user, pass).await,
                FtpStreamKind::Secure(s) => s.login(user, pass).await,
            }
            .map_err(|e| FtpError::Auth {
                message: format!("FTP authentication failed for user '{}': {}", user, e),
            })?;
        }

        tracing::info!("FTP authenticated successfully");

        // Set binary transfer type
        {
            match &mut stream_kind {
                FtpStreamKind::Plain(s) => s.transfer_type(suppaftp::types::FileType::Binary).await,
                FtpStreamKind::Secure(s) => {
                    s.transfer_type(suppaftp::types::FileType::Binary).await
                }
            }
            .map_err(|e| FtpError::Protocol {
                message: format!("Failed to set binary transfer type: {}", e),
            })?;
        }

        tracing::info!("FTP connection fully established to {}", addr);

        Ok(Self {
            stream: Some(stream_kind),
        })
    }

    pub async fn disconnect(&mut self) -> Result<(), FtpError> {
        if let Some(kind) = self.stream.take() {
            match kind {
                FtpStreamKind::Plain(mut s) => {
                    if let Err(e) = s.quit().await {
                        tracing::warn!("FTP quit failed cleanly: {}", e);
                    }
                }
                FtpStreamKind::Secure(mut s) => {
                    if let Err(e) = s.quit().await {
                        tracing::warn!("FTPS quit failed cleanly: {}", e);
                    }
                }
            }
        }
        Ok(())
    }

    /// Test-only hook used by integration tests to assert lifecycle state.
    /// Production code dispatches via `ConnectionManager`, not via a direct
    /// handle, so this is kept behind `#[cfg(test)]` to avoid dead-code noise.
    #[cfg(test)]
    pub fn is_connected(&self) -> bool {
        self.stream.is_some()
    }

    // ===== File Operations =====

    /// List directory contents at `path`.
    pub async fn list_dir(&mut self, path: &str) -> Result<Vec<FileEntry>, TransferError> {
        let entries: Vec<String> = ftp_stream!(self, s => {
            s.list(Some(path)).await.map_err(|e| {
                TransferError::operation(format!("Failed to list directory '{}': {}", path, e))
            })?
        });

        let mut result = Vec::new();
        for line in entries {
            if let Some(entry) = parse_ftp_list_line(&line) {
                if entry.name == "." || entry.name == ".." {
                    continue;
                }
                result.push(entry);
            }
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

    /// Download a remote file to a local path. Streams in 32 KiB chunks —
    /// never buffers the entire file in memory. Returns bytes downloaded.
    pub async fn download_file(
        &mut self,
        remote_path: &str,
        local_path: &str,
    ) -> Result<u64, TransferError> {
        let remote = remote_path.to_string();
        let local = local_path.to_string();

        Ok(ftp_stream!(self, s => {
            let mut data_stream = s.retr_as_stream(&remote).await.map_err(|e| {
                TransferError::operation(format!("Failed to download file '{}': {}", remote, e))
            })?;
            let mut local_file = std::fs::File::create(&local).map_err(|e| {
                TransferError::operation(format!("Failed to create local file '{}': {}", local, e))
            })?;
            let mut buf = vec![0u8; crate::file_entry::FILE_TRANSFER_CHUNK_SIZE];
            let mut total = 0u64;
            loop {
                let n = data_stream.read(&mut buf).await.map_err(|e| {
                    TransferError::operation(format!("Failed to read download stream: {}", e))
                })?;
                if n == 0 {
                    break;
                }
                local_file.write_all(&buf[..n]).map_err(|e| {
                    TransferError::operation(format!("Failed to write local file: {}", e))
                })?;
                total += n as u64;
            }
            local_file.flush().map_err(|e| {
                TransferError::operation(format!("Failed to flush local file: {}", e))
            })?;
            data_stream.finish().await.map_err(|e| {
                TransferError::operation(format!("Failed to finalize download: {}", e))
            })?;
            total
        }))
    }

    /// Upload a local file to a remote path. Streams in 32 KiB chunks —
    /// never buffers the entire file in memory. Returns bytes uploaded.
    pub async fn upload_file(
        &mut self,
        local_path: &str,
        remote_path: &str,
    ) -> Result<u64, TransferError> {
        let local = local_path.to_string();
        let remote = remote_path.to_string();

        Ok(ftp_stream!(self, s => {
            let mut data_stream = s.put_with_stream(&remote).await.map_err(|e| {
                TransferError::operation(format!("Failed to open upload stream: {}", e))
            })?;
            let mut local_file = std::fs::File::open(&local).map_err(|e| {
                TransferError::operation(format!("Failed to open local file '{}': {}", local, e))
            })?;
            let mut buf = vec![0u8; crate::file_entry::FILE_TRANSFER_CHUNK_SIZE];
            let mut total = 0u64;
            loop {
                let n = local_file.read(&mut buf).map_err(|e| {
                    TransferError::operation(format!("Failed to read local file: {}", e))
                })?;
                if n == 0 {
                    break;
                }
                data_stream.write_all(&buf[..n]).await.map_err(|e| {
                    TransferError::operation(format!("Failed to write upload stream: {}", e))
                })?;
                total += n as u64;
            }
            data_stream.finish().await.map_err(|e| {
                TransferError::operation(format!("Failed to finalize upload: {}", e))
            })?;
            total
        }))
    }

    /// Create a directory on the remote server.
    pub async fn create_dir(&mut self, path: &str) -> Result<(), TransferError> {
        ftp_stream!(self, s => {
            s.mkdir(path).await.map_err(|e| {
                TransferError::operation(format!("Failed to create directory '{}': {}", path, e))
            })?
        });
        Ok(())
    }

    /// Rename a file or directory.
    pub async fn rename(&mut self, old_path: &str, new_path: &str) -> Result<(), TransferError> {
        ftp_stream!(self, s => {
            s.rename(old_path, new_path).await.map_err(|e| {
                TransferError::operation(format!(
                    "Failed to rename '{}' to '{}': {}",
                    old_path, new_path, e
                ))
            })?
        });
        Ok(())
    }

    /// Delete a file on the remote server.
    pub async fn delete_file(&mut self, path: &str) -> Result<(), TransferError> {
        ftp_stream!(self, s => {
            s.rm(path).await.map_err(|e| {
                TransferError::operation(format!("Failed to delete file '{}': {}", path, e))
            })?
        });
        Ok(())
    }

    /// Delete a directory on the remote server.
    pub async fn delete_dir(&mut self, path: &str) -> Result<(), TransferError> {
        ftp_stream!(self, s => {
            s.rmdir(path).await.map_err(|e| {
                TransferError::operation(format!("Failed to delete directory '{}': {}", path, e))
            })?
        });
        Ok(())
    }
}

/// Parse a single line from the FTP LIST command (Unix format).
/// Example: `drwxr-xr-x   2 user group  4096 Jan 01 12:00 dirname`
fn parse_ftp_list_line(line: &str) -> Option<FileEntry> {
    let line = line.trim();
    if line.is_empty() {
        return None;
    }

    // Unix-style listing
    let parts: Vec<&str> = line.splitn(9, char::is_whitespace).collect();
    if parts.len() < 9 {
        // Try to at least get the name
        if let Some(last) = line.split_whitespace().last() {
            return Some(FileEntry {
                name: last.to_string(),
                size: 0,
                modified: None,
                modified_unix: None,
                permissions: None,
                owner: None,
                group: None,
                file_type: FileEntryType::File,
            });
        }
        return None;
    }

    let perms_str = parts[0];
    let file_type = if perms_str.starts_with('d') {
        FileEntryType::Directory
    } else if perms_str.starts_with('l') {
        FileEntryType::Symlink
    } else {
        FileEntryType::File
    };

    // Filter out empty parts from whitespace splitting
    let tokens: Vec<&str> = line.split_whitespace().collect();
    if tokens.len() < 9 {
        let name = tokens.last().unwrap_or(&"").to_string();
        return Some(FileEntry {
            name,
            size: 0,
            modified: None,
            modified_unix: None,
            permissions: Some(perms_str.to_string()),
            owner: None,
            group: None,
            file_type,
        });
    }

    let size = tokens[4].parse::<u64>().unwrap_or(0);
    let month = tokens[5];
    let day = tokens[6];
    let time_or_year = tokens[7];
    let modified = Some(format!("{} {} {}", month, day, time_or_year));
    // Name is everything after the 8th token (handles spaces in names)
    let name = tokens[8..].join(" ");
    // For symlinks, strip the " -> target" part from the name
    let name = if matches!(file_type, FileEntryType::Symlink) {
        name.split(" -> ").next().unwrap_or(&name).to_string()
    } else {
        name
    };

    Some(FileEntry {
        name,
        size,
        modified,
        modified_unix: None,
        permissions: Some(perms_str.to_string()),
        owner: None,
        group: None,
        file_type,
    })
}

// =============================================================================
// Integration tests — require a live FTP server
//
// The tests are gated behind the FTP_TEST_HOST env var so they are skipped
// in CI / normal `cargo test` runs.
// =============================================================================
#[cfg(test)]
mod tests {
    use super::*;

    /// Helper – read env vars or skip the test.
    fn test_config() -> Option<FtpConfig> {
        let host = std::env::var("FTP_TEST_HOST").ok()?;
        let user = std::env::var("FTP_TEST_USER").unwrap_or_else(|_| "xxxx".into());
        let pass = std::env::var("FTP_TEST_PASS").unwrap_or_else(|_| "xxxxxxx".into());
        let port: u16 = std::env::var("FTP_TEST_PORT")
            .ok()
            .and_then(|p| p.parse().ok())
            .unwrap_or(21);
        Some(FtpConfig {
            host,
            port,
            username: user,
            password: pass,
            ftps_enabled: false,
            anonymous: false,
            tls_root_certs_pem: None,
        })
    }

    // ---- FTPS trust anchors (no server needed) ----------------------------

    mod tls_trust {
        use super::super::*;
        use native_tls::Identity;
        use rcgen::{
            BasicConstraints, CertificateParams, DnType, ExtendedKeyUsagePurpose, IsCa, Issuer,
            KeyPair, KeyUsagePurpose,
        };
        use suppaftp::async_native_tls::TlsAcceptor;

        // Throwaway RSA-2048 key, used only to stand up the in-process test
        // server. macOS's native-tls imports RSA keys but not EC ones for a
        // server identity, and rcgen on ring can't generate RSA keys.
        // Certificates are still generated per run, so nothing here expires.
        const TEST_SERVER_RSA_KEY: &str = "\
-----BEGIN PRIVATE KEY-----\n\
MIIEvAIBADANBgkqhkiG9w0BAQEFAASCBKYwggSiAgEAAoIBAQC1hkTB9s65EMRp\n\
trhakYLii8Rb/I2o//fe8Pw+aRWBT1egp/54HdQDTDXxGFt2p263xplhNbLmllmt\n\
YpljewNonrIVfKkJ3IZk4TI5HzdQfxrZ+rmLXvKjCcZk6aE8AGl1qsdzpcakdIXe\n\
gPFC72vyqGGPCt+h6c1/EN9k940b5OE69c5Yc1WTC7tlPvPNOzURck1frNzlpM1F\n\
YWFJrQCrsBU4kkE0WI98uOuRz59vGAbr/uZM8Q7nBfUlODAJr2z/IV/wCmihqSq3\n\
cgSl91G570GCpxREhSyZN3OWIwVriLFeRslOXDmaFxIwWrPZoS+076FkRY96PACG\n\
7AnJO+oLAgMBAAECgf9YCvJOdubNMX9nxrf5NZpwnFnLmTMcRQp0QhjA1zcXAOSq\n\
MiZlHBKOMZNNh1gqtLV+wqn3UZRJQviRSsFwVA8ohHrbm8W2gr9XLo1YJ0vXlHlG\n\
6yoTRHoVmdLKyduUvp5n8+0eqnPY+qtIwEGZtYZ7Vi/7W8rGksqZAWtYuA44+Hkf\n\
6R6/7NwdOIhMOJv/OyFZrbGdBKL2kC1PtmqWAtVgfSSoC4m7xMSvgF5yuyvImohe\n\
kPkUvblVxlszG8J9AfaKV20/CUWpLu1/gxJ6VSIrBvmn/Dc/eabgogGVY9tdDMwc\n\
9TKbi2CTrjhvsU6Zw13CLBAvgrFIhaq2p1FojokCgYEA23cnA89xJVeeHxMAPWpX\n\
70p0XAdss9Efwl1gnBwiAFcFG8jqSuY7a7hHrhhLDGKPB8cMC3seQZTDsWpzxW5c\n\
LGapBNXW/DMg03zMfwuwWxBjYUUSM3oEjw7LLE21CNd/mJWzsROOW+rghb24NwUk\n\
nvCkeYWphW/heJYPsGYGAIMCgYEA0740r77dMd57vZ1RzaWJUwLVTd17x4eQx9CF\n\
SIOZQYG0je0Izo7FKxPzXIE3A2I377ygXcfCtcw/dvtw/+I/bCMCj371iIvVIT/s\n\
2c+8QOJBs4jqtFOO6Rkgk88AJlJAbrJmeE9EGplyEeBuGUL9JjLciGCw6HJfcc6G\n\
YNHFqdkCgYEA2Gvj+Ynz1hNVRueB8Q6RsNQHc0mPFLRBUXar8sZ7cUJfM0sqYLoy\n\
FsQfS7uBJrF6wvyzEA9Vgu6lHKwRhrySAOcr/iyyWPpCgMwtDYwFWYgLuLxYepL1\n\
M+4uxX3L7PA2T84w6YqTdGlnB/xTUU6tEl/UklIRHhl6i2PQDPBPMukCgYAcOZ6M\n\
TsTtgNq9y9q7rvU/O4Fzf7KgRlHmUMVzhRdIxCFtScuCvUVLGL239wF+Ufli26IE\n\
3jv2P+O12I6XjXEm2QPeXO4d5YXjiMHpxucxPvfDFt0ybHEAYXkWOuGqOgyctOsz\n\
3l0Vrp6mA2SpuWRFU0JSa5EpaxWN9hmzjkLrAQKBgQCJhqCElzrp7pDuHmK305rp\n\
A+kTfnm/695KyWr/NPwnfaQsIUmHZQwoSypnS7xy9ittrduUQqBdtjwK22u8wrWw\n\
9xyR5VDylZJ6yBfJQ0r5MU/zqeP1wWdeGLcn3bDoNpLaiDJRcRX9Td+ZqSLYamTW\n\
ea4hFZ1Agq/uAmbbCFmPBQ==\n\
-----END PRIVATE KEY-----\n\
";

        /// A throwaway CA. rcgen's default validity starts in 1975, which keeps
        /// these certificates clear of Apple's 825-day limit (it only applies
        /// to certificates issued from July 2019 on).
        fn new_ca(name: &str) -> (Issuer<'static, KeyPair>, String) {
            let key = KeyPair::generate().expect("ca key");
            let mut params = CertificateParams::new(Vec::<String>::new()).expect("ca params");
            params.distinguished_name.push(DnType::CommonName, name);
            params.is_ca = IsCa::Ca(BasicConstraints::Unconstrained);
            params.key_usages = vec![KeyUsagePurpose::KeyCertSign, KeyUsagePurpose::CrlSign];
            let pem = params.self_signed(&key).expect("ca cert").pem();
            (Issuer::new(params, key), pem)
        }

        /// A `localhost` server certificate and its PKCS#8 key, signed by
        /// `issuer` or self-signed.
        fn server_cert(issuer: Option<&Issuer<'static, KeyPair>>) -> (String, String) {
            let key = KeyPair::from_pem(TEST_SERVER_RSA_KEY).expect("server key");
            let mut params =
                CertificateParams::new(vec!["localhost".to_string()]).expect("server params");
            params
                .distinguished_name
                .push(DnType::CommonName, "localhost");
            params.key_usages = vec![KeyUsagePurpose::DigitalSignature];
            params.extended_key_usages = vec![ExtendedKeyUsagePurpose::ServerAuth];
            let cert = match issuer {
                Some(issuer) => params.signed_by(&key, issuer),
                None => params.self_signed(&key),
            }
            .expect("server cert");
            (cert.pem(), key.serialize_pem())
        }

        /// Accept one TLS connection with `cert_pem`/`key_pem`, then handshake
        /// from the client side with the FTPS connector built from `roots`,
        /// asking for `server_name`.
        async fn handshake(
            cert_pem: &str,
            key_pem: &str,
            roots: Option<&str>,
            server_name: &str,
        ) -> Result<(), String> {
            let identity =
                Identity::from_pkcs8(cert_pem.as_bytes(), key_pem.as_bytes()).expect("identity");
            let acceptor =
                TlsAcceptor::from(native_tls::TlsAcceptor::new(identity).expect("acceptor"));
            let listener = tokio::net::TcpListener::bind("127.0.0.1:0")
                .await
                .expect("bind");
            let addr = listener.local_addr().expect("addr");
            let server = tokio::spawn(async move {
                if let Ok((tcp, _)) = listener.accept().await {
                    let _ = acceptor.accept(tcp).await;
                }
            });

            let connector = build_tls_connector(roots).map_err(|e| e.to_string())?;
            let tcp = tokio::net::TcpStream::connect(addr).await.expect("connect");
            let result = connector
                .connect(server_name, tcp)
                .await
                .map(|_| ())
                .map_err(|e| e.to_string());
            server.abort();
            result
        }

        #[tokio::test]
        async fn ca_signed_server_is_trusted_through_its_ca() {
            let (ca, ca_pem) = new_ca("ftps test ca");
            let (cert, key) = server_cert(Some(&ca));
            handshake(&cert, &key, Some(&ca_pem), "localhost")
                .await
                .expect("the server's CA must be trusted");
        }

        #[tokio::test]
        async fn self_signed_server_is_trusted_through_its_own_certificate() {
            let (cert, key) = server_cert(None);
            handshake(&cert, &key, Some(&cert), "localhost")
                .await
                .expect("a self-signed server is trusted via its own certificate");
        }

        #[tokio::test]
        async fn untrusted_server_is_rejected_without_extra_roots() {
            let (ca, _) = new_ca("ftps test ca");
            let (cert, key) = server_cert(Some(&ca));
            assert!(handshake(&cert, &key, None, "localhost").await.is_err());
        }

        #[tokio::test]
        async fn unrelated_root_does_not_make_the_server_trusted() {
            let (ca, _) = new_ca("ftps test ca");
            let (_, other_pem) = new_ca("unrelated ca");
            let (cert, key) = server_cert(Some(&ca));
            assert!(
                handshake(&cert, &key, Some(&other_pem), "localhost")
                    .await
                    .is_err()
            );
        }

        #[tokio::test]
        async fn trusted_certificate_for_another_host_is_rejected() {
            let (ca, ca_pem) = new_ca("ftps test ca");
            let (cert, key) = server_cert(Some(&ca));
            assert!(
                handshake(&cert, &key, Some(&ca_pem), "other-host.example")
                    .await
                    .is_err(),
                "the host name must still be checked"
            );
        }

        #[test]
        fn malformed_root_pem_is_rejected() {
            let err = build_tls_connector(Some("not a certificate"))
                .expect_err("garbage must not be accepted");
            assert!(matches!(err, FtpError::Tls { .. }), "{err}");
        }

        #[test]
        fn pem_without_a_certificate_is_rejected() {
            let key_only = KeyPair::generate().expect("key").serialize_pem();
            assert!(matches!(
                build_tls_connector(Some(&key_only)),
                Err(FtpError::Tls { .. })
            ));
        }

        #[test]
        fn truncated_certificate_block_is_rejected() {
            let (_, ca_pem) = new_ca("ftps test ca");
            let truncated = &ca_pem[..ca_pem.len() / 2];
            assert!(matches!(
                build_tls_connector(Some(truncated)),
                Err(FtpError::Tls { .. })
            ));
        }

        #[test]
        fn bundle_with_several_certificates_is_parsed() {
            let (_, a) = new_ca("ca a");
            let (_, b) = new_ca("ca b");
            let bundle = format!("{a}\n{b}");
            assert_eq!(parse_pem_certificates(&bundle).expect("bundle").len(), 2);
        }

        #[test]
        fn legacy_allow_invalid_certs_field_is_ignored() {
            let json = r#"{
                "host": "ftp.example.com",
                "port": 21,
                "username": "u",
                "password": "p",
                "ftps_enabled": true,
                "anonymous": false,
                "allow_invalid_certs": true
            }"#;
            let cfg: FtpConfig = serde_json::from_str(json).expect("old profiles still load");
            assert_eq!(cfg.tls_root_certs_pem, None);
        }
    }

    // ---- 1. Connect & disconnect -----------------------------------------

    #[tokio::test]
    async fn test_ftp_connect_and_disconnect() {
        let Some(cfg) = test_config() else {
            eprintln!("SKIP: FTP_TEST_HOST not set");
            return;
        };

        let mut client = FtpClient::connect(&cfg)
            .await
            .expect("FTP connect should succeed");

        assert!(client.is_connected(), "client should be connected");

        client
            .disconnect()
            .await
            .expect("disconnect should succeed");
        assert!(!client.is_connected(), "client should be disconnected");
    }

    // ---- 2. Connect with wrong credentials --------------------------------

    #[tokio::test]
    async fn test_ftp_connect_bad_credentials() {
        let Some(mut cfg) = test_config() else {
            eprintln!("SKIP: FTP_TEST_HOST not set");
            return;
        };
        cfg.password = "wrong-password-definitely".into();

        let result = FtpClient::connect(&cfg).await;
        assert!(result.is_err(), "connect with bad password should fail");

        let err_msg = result.err().unwrap().to_string();
        eprintln!("Expected error: {}", err_msg);
        assert!(
            err_msg.to_lowercase().contains("auth")
                || err_msg.to_lowercase().contains("login")
                || err_msg.to_lowercase().contains("fail"),
            "error should mention authentication failure, got: {}",
            err_msg
        );
    }

    // ---- 3. List root directory -------------------------------------------

    #[tokio::test]
    async fn test_ftp_list_root() {
        let Some(cfg) = test_config() else {
            eprintln!("SKIP: FTP_TEST_HOST not set");
            return;
        };

        let mut client = FtpClient::connect(&cfg).await.expect("connect");

        let entries = client.list_dir("/").await.expect("list root directory");
        eprintln!("Root contains {} entries:", entries.len());
        for e in &entries {
            eprintln!("  {:?}  {:>10}  {}", e.file_type, e.size, e.name);
        }
        // Root should be listable (may be empty on fresh server)

        client.disconnect().await.ok();
    }

    // ---- 4. Full CRUD cycle: mkdir → upload → list → download → rename → delete

    #[tokio::test]
    async fn test_ftp_crud_cycle() {
        let Some(cfg) = test_config() else {
            eprintln!("SKIP: FTP_TEST_HOST not set");
            return;
        };

        let mut client = FtpClient::connect(&cfg).await.expect("connect");

        let test_dir = "/rshell_e2e_test";
        let test_file_remote = format!("{}/hello.txt", test_dir);
        let renamed_file_remote = format!("{}/hello_renamed.txt", test_dir);

        // --- Clean up from any previous failed run ---
        let _ = client.delete_file(&renamed_file_remote).await;
        let _ = client.delete_file(&test_file_remote).await;
        let _ = client.delete_dir(test_dir).await;

        // 4a. Create directory
        client
            .create_dir(test_dir)
            .await
            .expect("create_dir should succeed");
        eprintln!("Created directory: {}", test_dir);

        // 4b. Upload a file
        let tmp_upload = std::env::temp_dir().join("rshell_e2e_upload.txt");
        let upload_content = b"Hello from R-Shell E2E test!\nLine 2\n";
        tokio::fs::write(&tmp_upload, upload_content)
            .await
            .expect("write temp file");

        let uploaded_bytes = client
            .upload_file(tmp_upload.to_str().unwrap(), &test_file_remote)
            .await
            .expect("upload_file should succeed");
        assert_eq!(uploaded_bytes, upload_content.len() as u64);
        eprintln!("Uploaded {} bytes to {}", uploaded_bytes, test_file_remote);

        // 4c. List directory — should contain our file
        let entries = client.list_dir(test_dir).await.expect("list test dir");
        eprintln!("Directory {} contains {} entries", test_dir, entries.len());
        let found = entries.iter().any(|e| e.name == "hello.txt");
        assert!(
            found,
            "uploaded file should appear in listing: {:?}",
            entries.iter().map(|e| &e.name).collect::<Vec<_>>()
        );

        // 4d. Download the file and verify contents
        let tmp_download = std::env::temp_dir().join("rshell_e2e_download.txt");
        let downloaded_bytes = client
            .download_file(&test_file_remote, tmp_download.to_str().unwrap())
            .await
            .expect("download_file should succeed");
        assert_eq!(downloaded_bytes, upload_content.len() as u64);

        let downloaded_data = tokio::fs::read(&tmp_download)
            .await
            .expect("read downloaded");
        assert_eq!(
            downloaded_data, upload_content,
            "downloaded content should match uploaded content"
        );
        eprintln!("Download verified: {} bytes match", downloaded_bytes);

        // 4e. Rename the file
        client
            .rename(&test_file_remote, &renamed_file_remote)
            .await
            .expect("rename should succeed");
        eprintln!("Renamed {} → {}", test_file_remote, renamed_file_remote);

        // Verify rename: old name gone, new name present
        let entries_after = client.list_dir(test_dir).await.expect("list after rename");
        assert!(
            !entries_after.iter().any(|e| e.name == "hello.txt"),
            "old file name should be gone"
        );
        assert!(
            entries_after.iter().any(|e| e.name == "hello_renamed.txt"),
            "renamed file should exist"
        );

        // 4f. Delete the file
        client
            .delete_file(&renamed_file_remote)
            .await
            .expect("delete_file should succeed");
        eprintln!("Deleted {}", renamed_file_remote);

        // 4g. Delete the directory
        client
            .delete_dir(test_dir)
            .await
            .expect("delete_dir should succeed");
        eprintln!("Deleted directory {}", test_dir);

        // Verify cleanup
        let root_entries = client.list_dir("/").await.expect("list root");
        assert!(
            !root_entries.iter().any(|e| e.name == "rshell_e2e_test"),
            "test directory should be removed"
        );
        eprintln!("Cleanup verified: test directory removed from root listing");

        // Cleanup temp files
        let _ = tokio::fs::remove_file(&tmp_upload).await;
        let _ = tokio::fs::remove_file(&tmp_download).await;

        client.disconnect().await.ok();
        eprintln!("FTP CRUD E2E test PASSED ✓");
    }

    // ---- 5. Parse FTP LIST line -------------------------------------------

    #[test]
    fn test_parse_ftp_list_line_unix_dir() {
        let line = "drwxr-xr-x   2 user group  4096 Jan 15 12:00 mydir";
        let entry = parse_ftp_list_line(line).expect("should parse");
        assert_eq!(entry.name, "mydir");
        assert!(matches!(entry.file_type, FileEntryType::Directory));
        assert_eq!(entry.size, 4096);
        assert_eq!(entry.permissions.as_deref(), Some("drwxr-xr-x"));
    }

    #[test]
    fn test_parse_ftp_list_line_unix_file() {
        let line = "-rw-r--r--   1 user group  12345 Feb 28 09:30 report.pdf";
        let entry = parse_ftp_list_line(line).expect("should parse");
        assert_eq!(entry.name, "report.pdf");
        assert!(matches!(entry.file_type, FileEntryType::File));
        assert_eq!(entry.size, 12345);
    }

    #[test]
    fn test_parse_ftp_list_line_symlink() {
        let line = "lrwxrwxrwx   1 user group  10 Mar 01 00:00 link -> target";
        let entry = parse_ftp_list_line(line).expect("should parse");
        assert_eq!(entry.name, "link");
        assert!(matches!(entry.file_type, FileEntryType::Symlink));
    }

    #[test]
    fn test_parse_ftp_list_line_name_with_spaces() {
        let line = "-rw-r--r--   1 user group  100 Dec 25 23:59 my file name.txt";
        let entry = parse_ftp_list_line(line).expect("should parse");
        assert_eq!(entry.name, "my file name.txt");
    }

    #[test]
    fn test_parse_ftp_list_line_empty() {
        assert!(parse_ftp_list_line("").is_none());
        assert!(parse_ftp_list_line("   ").is_none());
    }

    #[test]
    fn test_parse_ftp_list_line_dot_entries() {
        // These are filtered out in list_dir, but the parser itself should parse them
        let line = "drwxr-xr-x   2 user group  4096 Jan 01 00:00 .";
        let entry = parse_ftp_list_line(line).expect("should parse");
        assert_eq!(entry.name, ".");
    }

    // ---- Task 5.4: Additional unit tests ----

    #[test]
    fn test_ftp_config_deserialization() {
        let json = r#"{"host":"192.168.1.1","port":21,"username":"user","password":"pass","ftps_enabled":false,"anonymous":false}"#;
        let config: FtpConfig = serde_json::from_str(json).unwrap();
        assert_eq!(config.host, "192.168.1.1");
        assert_eq!(config.port, 21);
        assert_eq!(config.username, "user");
        assert_eq!(config.password, "pass");
        assert!(!config.ftps_enabled);
        assert!(!config.anonymous);
    }

    #[test]
    fn test_ftp_config_anonymous() {
        let json = r#"{"host":"ftp.example.com","port":21,"username":"","password":"","ftps_enabled":false,"anonymous":true}"#;
        let config: FtpConfig = serde_json::from_str(json).unwrap();
        assert!(config.anonymous);
    }

    #[test]
    fn test_ftp_config_ftps_enabled() {
        let json = r#"{"host":"secure.example.com","port":990,"username":"admin","password":"secret","ftps_enabled":true,"anonymous":false}"#;
        let config: FtpConfig = serde_json::from_str(json).unwrap();
        assert!(config.ftps_enabled);
        assert_eq!(config.port, 990);
    }

    #[test]
    fn test_parse_ftp_list_large_file_size() {
        let line = "-rw-r--r--   1 user group  9999999999 Dec 31 23:59 huge.iso";
        let entry = parse_ftp_list_line(line).expect("should parse");
        assert_eq!(entry.name, "huge.iso");
        assert_eq!(entry.size, 9999999999);
    }

    #[test]
    fn test_parse_ftp_list_zero_size() {
        let line = "-rw-r--r--   1 user group  0 Apr 01 00:00 empty.txt";
        let entry = parse_ftp_list_line(line).expect("should parse");
        assert_eq!(entry.size, 0);
    }
}
