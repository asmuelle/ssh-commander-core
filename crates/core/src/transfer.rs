//! Protocol-agnostic file-transfer errors, shared by the SFTP (over SSH),
//! standalone-SFTP, and FTP file operations.
//!
//! `Display` output preserves the user-facing messages the clients have
//! always produced; the variants exist so callers can branch on the failure
//! class (not connected vs. cancelled vs. operation failure) without string
//! matching.

#[derive(Debug, thiserror::Error)]
#[non_exhaustive]
pub enum TransferError {
    /// No live session for this protocol — connect first. The payload is the
    /// protocol label ("SSH", "SFTP", "FTP") used in the rendered message.
    #[error("{0} session not connected")]
    NotConnected(&'static str),

    /// The caller's `CancellationToken` fired between chunks. Partial files
    /// are left in place (see the transfer methods' docs).
    #[error("Transfer cancelled")]
    Cancelled,

    /// Failure opening or driving the underlying protocol session (e.g. the
    /// SFTP subsystem channel could not be opened).
    #[error("{message}")]
    Session { message: String },

    /// A remote file operation failed (open/list/rename/delete/…), with the
    /// path context baked into the message.
    #[error("{message}")]
    Operation { message: String },

    /// Raw I/O failure while streaming chunks (local disk or remote stream).
    #[error("{0}")]
    Io(#[from] std::io::Error),
}

impl TransferError {
    /// Wrap an operation failure, type-erasing the underlying library error
    /// so it doesn't become part of this crate's public API.
    pub(crate) fn operation(message: impl Into<String>) -> Self {
        Self::Operation {
            message: message.into(),
        }
    }
}
