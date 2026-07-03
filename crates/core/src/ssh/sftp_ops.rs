//! Shared SFTP file operations over an established [`SftpSession`].
//!
//! Both `SshClient` (which opens the SFTP subsystem lazily on its existing
//! session) and `StandaloneSftpClient` (which owns a dedicated session)
//! delegate here, so listing, transfer, and directory-management behavior —
//! including error-message shape, chunked streaming, and sort order — stays
//! identical across the two entry points.

use anyhow::Result;
use russh_sftp::client::SftpSession;
use tokio::io::{AsyncReadExt, AsyncWriteExt};
use tokio_util::sync::CancellationToken;

use crate::file_entry::{
    FileEntryType, RemoteFileEntry, format_permissions, format_unix_timestamp,
};
use crate::ssh::SFTP_CHUNK_SIZE;

/// List directory contents at `path`, skipping `.`/`..`, directories first,
/// then case-insensitive by name.
pub(crate) async fn list_dir(sftp: &SftpSession, path: &str) -> Result<Vec<RemoteFileEntry>> {
    let entries = sftp
        .read_dir(path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to list directory '{}': {}", path, e))?;

    let mut result = Vec::new();
    for entry in entries {
        let name = entry.file_name();
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

    sort_entries(&mut result);
    Ok(result)
}

/// Sort order shared by every file listing: directories before files,
/// then case-insensitive name comparison.
fn sort_entries(entries: &mut [RemoteFileEntry]) {
    entries.sort_by(|a, b| {
        let a_is_dir = matches!(a.file_type, FileEntryType::Directory);
        let b_is_dir = matches!(b.file_type, FileEntryType::Directory);
        b_is_dir
            .cmp(&a_is_dir)
            .then_with(|| a.name.to_lowercase().cmp(&b.name.to_lowercase()))
    });
}

/// Stream a remote file to disk in [`SFTP_CHUNK_SIZE`] chunks, calling
/// `progress` with the running byte total after each chunk. `cancel`, when
/// supplied, is checked between chunks; on cancellation the partial local
/// file is left on disk (callers may delete it, or keep it for a future
/// resume feature). Returns bytes transferred.
pub(crate) async fn download_file(
    sftp: &SftpSession,
    remote_path: &str,
    local_path: &str,
    mut progress: impl FnMut(u64),
    cancel: Option<&CancellationToken>,
) -> Result<u64> {
    let mut remote_file = sftp
        .open(remote_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open remote file '{}': {}", remote_path, e))?;
    let mut local_file = tokio::fs::File::create(local_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create local file '{}': {}", local_path, e))?;

    let mut buf = vec![0u8; SFTP_CHUNK_SIZE];
    let mut total_bytes = 0u64;
    loop {
        if let Some(token) = cancel
            && token.is_cancelled()
        {
            return Err(anyhow::anyhow!("Transfer cancelled"));
        }
        let n = remote_file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        local_file.write_all(&buf[..n]).await?;
        total_bytes += n as u64;
        progress(total_bytes);
    }
    local_file.flush().await?;

    Ok(total_bytes)
}

/// Read a remote file fully into memory. Only for small files — no
/// progress or cancellation, the whole payload is buffered.
pub(crate) async fn download_to_memory(sftp: &SftpSession, remote_path: &str) -> Result<Vec<u8>> {
    let mut remote_file = sftp
        .open(remote_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open remote file '{}': {}", remote_path, e))?;

    let mut buffer = Vec::new();
    let mut temp_buf = vec![0u8; SFTP_CHUNK_SIZE];
    loop {
        let n = remote_file.read(&mut temp_buf).await?;
        if n == 0 {
            break;
        }
        buffer.extend_from_slice(&temp_buf[..n]);
    }
    Ok(buffer)
}

/// Stream a local file to the remote in [`SFTP_CHUNK_SIZE`] chunks. Same
/// progress/cancellation contract as [`download_file`]; on cancellation the
/// partial remote file is left in place.
pub(crate) async fn upload_file(
    sftp: &SftpSession,
    local_path: &str,
    remote_path: &str,
    mut progress: impl FnMut(u64),
    cancel: Option<&CancellationToken>,
) -> Result<u64> {
    let mut local_file = tokio::fs::File::open(local_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to open local file '{}': {}", local_path, e))?;
    let mut remote_file = sftp
        .create(remote_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create remote file '{}': {}", remote_path, e))?;

    let mut buf = vec![0u8; SFTP_CHUNK_SIZE];
    let mut total_bytes = 0u64;
    loop {
        if let Some(token) = cancel
            && token.is_cancelled()
        {
            return Err(anyhow::anyhow!("Transfer cancelled"));
        }
        let n = local_file.read(&mut buf).await?;
        if n == 0 {
            break;
        }
        remote_file.write_all(&buf[..n]).await?;
        total_bytes += n as u64;
        progress(total_bytes);
    }
    remote_file.flush().await?;

    Ok(total_bytes)
}

/// Write an in-memory buffer to a remote file.
pub(crate) async fn upload_from_bytes(
    sftp: &SftpSession,
    data: &[u8],
    remote_path: &str,
) -> Result<u64> {
    let mut remote_file = sftp
        .create(remote_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create remote file '{}': {}", remote_path, e))?;

    for chunk in data.chunks(SFTP_CHUNK_SIZE) {
        remote_file.write_all(chunk).await?;
    }
    remote_file.flush().await?;

    Ok(data.len() as u64)
}

/// Create a directory on the remote. Fails if the parent doesn't exist or
/// the path is already taken.
pub(crate) async fn create_dir(sftp: &SftpSession, path: &str) -> Result<()> {
    sftp.create_dir(path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to create directory '{}': {}", path, e))?;
    Ok(())
}

/// Rename a file or directory. SFTP RENAME is atomic when source and
/// destination are on the same filesystem; cross-filesystem renames may
/// copy-then-delete depending on the server.
pub(crate) async fn rename(sftp: &SftpSession, old_path: &str, new_path: &str) -> Result<()> {
    sftp.rename(old_path, new_path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to rename '{}' to '{}': {}", old_path, new_path, e))?;
    Ok(())
}

/// Delete a regular file. For directories, use [`delete_dir`].
pub(crate) async fn delete_file(sftp: &SftpSession, path: &str) -> Result<()> {
    sftp.remove_file(path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete file '{}': {}", path, e))?;
    Ok(())
}

/// Delete an empty directory. SFTP requires the directory be empty;
/// recursive removal belongs at the caller layer (with progress reporting).
pub(crate) async fn delete_dir(sftp: &SftpSession, path: &str) -> Result<()> {
    sftp.remove_dir(path)
        .await
        .map_err(|e| anyhow::anyhow!("Failed to delete directory '{}': {}", path, e))?;
    Ok(())
}

#[cfg(test)]
mod tests {
    use super::sort_entries;
    use crate::file_entry::{FileEntryType, RemoteFileEntry};

    fn entry(name: &str, file_type: FileEntryType) -> RemoteFileEntry {
        RemoteFileEntry {
            name: name.to_string(),
            size: 0,
            modified: None,
            modified_unix: None,
            permissions: None,
            owner: None,
            group: None,
            file_type,
        }
    }

    #[test]
    fn sorts_directories_first_then_case_insensitive_names() {
        let mut entries = vec![
            entry("zeta.txt", FileEntryType::File),
            entry("Alpha.txt", FileEntryType::File),
            entry("beta", FileEntryType::Directory),
            entry("ALSO-DIR", FileEntryType::Directory),
            entry("link", FileEntryType::Symlink),
        ];
        sort_entries(&mut entries);
        let names: Vec<&str> = entries.iter().map(|e| e.name.as_str()).collect();
        assert_eq!(names, ["ALSO-DIR", "beta", "Alpha.txt", "link", "zeta.txt"]);
    }
}
