//! Protocol-agnostic file listing types and transfer tuning shared by the
//! SFTP and FTP clients.
//!
//! These are deliberately free of any SSH/SFTP/FTP dependency so they
//! compile under any feature combination — a build with only the `ftp`
//! feature can list and transfer files without pulling in the russh stack.

use serde::Serialize;

/// Chunk size for streamed file transfers (uploads/downloads). 32 KiB is a
/// good balance between syscall overhead and memory for interactive use.
pub const FILE_TRANSFER_CHUNK_SIZE: usize = 32 * 1024;

/// A single file/directory entry returned from directory listings.
/// Used by both local and remote (SFTP/FTP) file operations.
#[derive(Debug, Clone, Serialize)]
pub struct FileEntry {
    pub name: String,
    pub size: u64,
    /// Pre-formatted timestamp string for human display.
    pub modified: Option<String>,
    /// Raw modification time as Unix epoch seconds. Surfaced
    /// alongside `modified` so consumers (the macOS file table)
    /// can sort numerically and reformat per-locale instead of
    /// relying on lexical comparison of the formatted string.
    pub modified_unix: Option<i64>,
    pub permissions: Option<String>,
    pub owner: Option<String>,
    pub group: Option<String>,
    pub file_type: FileEntryType,
}

/// Backward-compatible alias for code that still references RemoteFileEntry.
pub type RemoteFileEntry = FileEntry;

#[derive(Debug, Clone, Serialize, PartialEq)]
pub enum FileEntryType {
    File,
    Directory,
    Symlink,
}

/// Convert a Unix timestamp (seconds since epoch) to a readable UTC datetime
/// string ("YYYY-MM-DD HH:MM:SS"). Uses chrono for correct leap-year and
/// post-2106 handling.
pub fn format_unix_timestamp(secs: i64) -> String {
    chrono::DateTime::<chrono::Utc>::from_timestamp(secs, 0)
        .map(|dt| dt.format("%Y-%m-%d %H:%M:%S").to_string())
        .unwrap_or_else(|| "invalid-timestamp".to_string())
}

/// Format Unix file permissions (mode bits) as a string like `rwxr-xr-x`.
pub(crate) fn format_permissions(mode: u32) -> String {
    let mut s = String::with_capacity(9);
    let flags = [
        (0o400, 'r'),
        (0o200, 'w'),
        (0o100, 'x'),
        (0o040, 'r'),
        (0o020, 'w'),
        (0o010, 'x'),
        (0o004, 'r'),
        (0o002, 'w'),
        (0o001, 'x'),
    ];
    for (bit, ch) in flags.iter() {
        if mode & bit != 0 {
            s.push(*ch);
        } else {
            s.push('-');
        }
    }
    s
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn test_format_permissions_full() {
        assert_eq!(format_permissions(0o777), "rwxrwxrwx");
    }

    #[test]
    fn test_format_permissions_none() {
        assert_eq!(format_permissions(0o000), "---------");
    }

    #[test]
    fn test_format_permissions_typical_file() {
        assert_eq!(format_permissions(0o644), "rw-r--r--");
    }

    #[test]
    fn test_format_permissions_typical_dir() {
        assert_eq!(format_permissions(0o755), "rwxr-xr-x");
    }

    #[test]
    fn test_format_permissions_write_only() {
        assert_eq!(format_permissions(0o200), "-w-------");
    }

    #[test]
    fn format_unix_timestamp_epoch() {
        assert_eq!(format_unix_timestamp(0), "1970-01-01 00:00:00");
    }

    #[test]
    fn format_unix_timestamp_known_date() {
        // 2024-01-01 00:00:00 UTC
        assert_eq!(format_unix_timestamp(1704067200), "2024-01-01 00:00:00");
    }

    #[test]
    fn format_unix_timestamp_with_time() {
        // 2000-06-15 11:30:45 UTC
        assert_eq!(format_unix_timestamp(961068645), "2000-06-15 11:30:45");
    }

    #[test]
    fn format_unix_timestamp_post_2106() {
        // 2200-01-01 00:00:00 UTC — past the u32 epoch cutoff that the old
        // hand-rolled code would have silently truncated.
        assert_eq!(format_unix_timestamp(7258118400), "2200-01-01 00:00:00");
    }

    #[test]
    fn test_file_entry_type_serialization() {
        let entry = RemoteFileEntry {
            name: "test.txt".to_string(),
            size: 1024,
            modified: Some("2024-01-01 00:00:00".to_string()),
            modified_unix: Some(1_704_067_200),
            permissions: Some("rw-r--r--".to_string()),
            owner: Some("501".to_string()),
            group: Some("20".to_string()),
            file_type: FileEntryType::File,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("\"name\":\"test.txt\""));
        assert!(json.contains("\"size\":1024"));
        assert!(json.contains("File"));
    }

    #[test]
    fn test_directory_entry_serialization() {
        let entry = RemoteFileEntry {
            name: "mydir".to_string(),
            size: 4096,
            modified: None,
            modified_unix: None,
            permissions: Some("rwxr-xr-x".to_string()),
            owner: None,
            group: None,
            file_type: FileEntryType::Directory,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("Directory"));
        assert!(json.contains("\"modified\":null"));
    }

    #[test]
    fn test_symlink_entry_serialization() {
        let entry = RemoteFileEntry {
            name: "link".to_string(),
            size: 0,
            modified: None,
            modified_unix: None,
            permissions: None,
            owner: None,
            group: None,
            file_type: FileEntryType::Symlink,
        };
        let json = serde_json::to_string(&entry).unwrap();
        assert!(json.contains("Symlink"));
    }
}
