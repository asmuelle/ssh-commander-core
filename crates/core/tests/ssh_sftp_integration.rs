//! Exercises the SSH transport and standalone SFTP; only meaningful when
//! both features are compiled in.
#![cfg(all(feature = "ssh", feature = "sftp"))]

use std::env;
use std::sync::Arc;

use ssh_commander_core::sftp_client::{SftpAuthMethod, SftpConfig, StandaloneSftpClient};
use ssh_commander_core::ssh::{AuthMethod, HostKeyStore, SshClient, SshConfig};
use tempfile::tempdir;

fn ssh_config() -> Option<SshConfig> {
    let host = env::var("SSH_TEST_HOST").ok()?;
    let port = env::var("SSH_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(22);
    let username = env::var("SSH_TEST_USER").unwrap_or_else(|_| "testuser".to_string());
    let password = env::var("SSH_TEST_PASSWORD").unwrap_or_else(|_| "testpass".to_string());
    Some(SshConfig {
        host,
        port,
        username,
        auth_method: AuthMethod::Password { password },
    })
}

fn host_keys() -> Arc<HostKeyStore> {
    Arc::new(HostKeyStore::new(std::env::temp_dir().join(format!(
        "ssh-commander-core-test-known-hosts-{}",
        std::process::id()
    ))))
}

#[tokio::test]
async fn ssh_exec_smoke() {
    let Some(cfg) = ssh_config() else {
        eprintln!("SKIP: SSH_TEST_HOST not set");
        return;
    };

    let mut client = SshClient::new(host_keys());
    client.connect(&cfg).await.expect("connect ssh");
    let out = client
        .execute_command_full("printf 'ssh-ok'")
        .await
        .expect("exec command");
    assert!(out.is_success(), "{out:?}");
    assert_eq!(out.stdout, "ssh-ok");
    client.disconnect().await.expect("disconnect ssh");
}

#[tokio::test]
async fn sftp_crud_smoke() {
    let Some(ssh) = ssh_config() else {
        eprintln!("SKIP: SSH_TEST_HOST not set");
        return;
    };

    let cfg = SftpConfig {
        host: ssh.host,
        port: ssh.port,
        username: ssh.username,
        auth_method: match ssh.auth_method {
            AuthMethod::Password { password } => SftpAuthMethod::Password { password },
            _ => unreachable!("test helper only creates password auth"),
        },
    };
    let mut client = StandaloneSftpClient::connect(&cfg, host_keys())
        .await
        .expect("connect sftp");

    let remote_root = env::var("SSH_TEST_REMOTE_DIR")
        .unwrap_or_else(|_| format!("/tmp/ssh_commander_core_sftp_{}", std::process::id()));
    let remote_file = format!("{remote_root}/hello.txt");
    let renamed_file = format!("{remote_root}/renamed.txt");
    let local = tempdir().expect("tempdir");
    let upload_path = local.path().join("upload.txt");
    let download_path = local.path().join("download.txt");
    tokio::fs::write(&upload_path, b"hello over sftp\n")
        .await
        .expect("write upload file");

    let _ = client.delete_file(&renamed_file).await;
    let _ = client.delete_file(&remote_file).await;
    let _ = client.delete_dir(&remote_root).await;

    client
        .create_dir(&remote_root)
        .await
        .expect("create remote dir");
    let uploaded = client
        .upload_file(upload_path.to_str().expect("utf8 path"), &remote_file)
        .await
        .expect("upload");
    assert_eq!(uploaded, b"hello over sftp\n".len() as u64);

    let entries = client.list_dir(&remote_root).await.expect("list dir");
    assert!(entries.iter().any(|e| e.name == "hello.txt"));

    client
        .rename(&remote_file, &renamed_file)
        .await
        .expect("rename");
    client
        .download_file(&renamed_file, download_path.to_str().expect("utf8 path"))
        .await
        .expect("download");
    let downloaded = tokio::fs::read(&download_path)
        .await
        .expect("read download");
    assert_eq!(downloaded, b"hello over sftp\n");

    client
        .delete_file(&renamed_file)
        .await
        .expect("delete file");
    client.delete_dir(&remote_root).await.expect("delete dir");
    client.disconnect().await.expect("disconnect sftp");
}
