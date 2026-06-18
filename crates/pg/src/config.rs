//! PostgreSQL connection configuration.
//!
//! Mirrors the shape of `SshConfig` / `SftpConfig` so the macOS bridge can
//! map a `ConnectionProfile` onto a `PgConfig` with the same conventions
//! used for every other protocol.

use serde::{Deserialize, Serialize};

/// How to authenticate to the Postgres server.
///
/// `Keychain` defers credential lookup to the macOS keychain at connect time;
/// this matches the SSH/SFTP pattern and keeps secrets out of memory until
/// they are actually required.
#[derive(Clone, Serialize, Deserialize)]
pub enum PgAuthMethod {
    /// Plaintext password supplied directly. Use only for ephemeral test
    /// connections; production callers should prefer `Keychain`.
    Password { password: String },
    /// Resolve the password from the macOS keychain at connect time, using
    /// the supplied `account` identifier (e.g. `"postgres:profile-id"`).
    Keychain { account: String },
}

impl std::fmt::Debug for PgAuthMethod {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        match self {
            PgAuthMethod::Password { .. } => f
                .debug_struct("PgAuthMethod::Password")
                .field("password", &"<redacted>")
                .finish(),
            PgAuthMethod::Keychain { account } => f
                .debug_struct("PgAuthMethod::Keychain")
                .field("account", account)
                .finish(),
        }
    }
}

/// TLS posture for the connection.
///
/// Modeled after libpq's `sslmode`. The MVP supports the four most useful
/// values; `allow` is omitted because it negotiates plaintext on failure
/// and silently weakens security in a way no UI affordance can clarify.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq, Default)]
pub enum PgTlsMode {
    /// Never use TLS.
    Disable,
    /// Try TLS, fall back to plaintext on negotiation failure.
    #[default]
    Prefer,
    /// Require TLS, but do not verify the server certificate.
    Require,
    /// Require TLS and validate the server certificate against system roots.
    VerifyFull,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PgConfig {
    pub host: String,
    pub port: u16,
    pub database: String,
    pub user: String,
    pub auth: PgAuthMethod,
    #[serde(default)]
    pub tls: PgTlsMode,
    /// Optional application_name reported to the server. Surfaces nicely in
    /// `pg_stat_activity` so DBAs can identify connections from r-shell.
    #[serde(default)]
    pub application_name: Option<String>,
    /// Connection timeout, seconds. `None` falls back to the driver default.
    #[serde(default)]
    pub connect_timeout_secs: Option<u64>,
    /// Maximum number of connections this profile's pool may open.
    /// `None` keeps the built-in default. Tighten on managed-DB
    /// providers with strict `max_connections` quotas.
    #[serde(default)]
    pub max_pool_size: Option<u32>,
    /// How long an idle connection lingers before the eviction loop
    /// closes it, in seconds. `None` keeps the built-in default.
    /// Lower values are politer to providers that bill on connection
    /// hours (RDS, Neon).
    #[serde(default)]
    pub idle_timeout_secs: Option<u64>,
    /// Minimum idle connections to keep alive even past
    /// `idle_timeout_secs`. `Some(0)` lets a profile fully evacuate
    /// during inactivity at the cost of a reconnect on next use.
    #[serde(default)]
    pub min_idle_connections: Option<u32>,
}

impl PgConfig {
    /// Sensible local-development default — useful in tests and the bridge's
    /// "new connection" flow.
    pub fn local(database: impl Into<String>, user: impl Into<String>) -> Self {
        Self {
            host: "127.0.0.1".to_string(),
            port: 5432,
            database: database.into(),
            user: user.into(),
            auth: PgAuthMethod::Password {
                password: String::new(),
            },
            tls: PgTlsMode::Disable,
            application_name: Some("r-shell".to_string()),
            connect_timeout_secs: Some(10),
            max_pool_size: None,
            idle_timeout_secs: None,
            min_idle_connections: None,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn local_defaults_disable_tls_and_set_app_name() {
        let cfg = PgConfig::local("mydb", "alice");
        assert_eq!(cfg.host, "127.0.0.1");
        assert_eq!(cfg.port, 5432);
        assert_eq!(cfg.database, "mydb");
        assert_eq!(cfg.user, "alice");
        assert_eq!(cfg.tls, PgTlsMode::Disable);
        assert_eq!(cfg.application_name.as_deref(), Some("r-shell"));
    }

    #[test]
    fn tls_mode_default_is_prefer() {
        assert_eq!(PgTlsMode::default(), PgTlsMode::Prefer);
    }

    #[test]
    fn config_round_trips_through_serde() {
        let cfg = PgConfig {
            host: "db.example.com".to_string(),
            port: 5433,
            database: "app".to_string(),
            user: "svc".to_string(),
            auth: PgAuthMethod::Keychain {
                account: "postgres:profile-1".to_string(),
            },
            tls: PgTlsMode::VerifyFull,
            application_name: Some("r-shell".to_string()),
            connect_timeout_secs: Some(15),
            max_pool_size: Some(10),
            idle_timeout_secs: Some(120),
            min_idle_connections: Some(0),
        };
        let json = serde_json::to_string(&cfg).expect("serialize");
        let back: PgConfig = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.host, cfg.host);
        assert_eq!(back.tls, cfg.tls);
        assert_eq!(back.max_pool_size, Some(10));
        assert_eq!(back.idle_timeout_secs, Some(120));
        assert_eq!(back.min_idle_connections, Some(0));
    }

    #[test]
    fn local_defaults_pool_settings_to_none() {
        // None means "use built-in default". The pool reads these
        // and substitutes its constants when absent.
        let cfg = PgConfig::local("db", "u");
        assert_eq!(cfg.max_pool_size, None);
        assert_eq!(cfg.idle_timeout_secs, None);
        assert_eq!(cfg.min_idle_connections, None);
    }

    #[test]
    fn debug_redacts_direct_password() {
        let cfg = PgConfig {
            auth: PgAuthMethod::Password {
                password: "super-secret-pg-password".to_string(),
            },
            ..PgConfig::local("db", "u")
        };
        let rendered = format!("{cfg:?}");
        assert!(!rendered.contains("super-secret-pg-password"));
        assert!(rendered.contains("<redacted>"));
    }

    #[test]
    fn debug_preserves_keychain_account() {
        let auth = PgAuthMethod::Keychain {
            account: "postgres:profile-1".to_string(),
        };
        let rendered = format!("{auth:?}");
        assert!(rendered.contains("postgres:profile-1"));
    }
}
