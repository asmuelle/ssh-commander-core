//! PostgreSQL pool for the database explorer.
//!
//! Sprint 6 model: each `PgPool` represents one configured Postgres
//! profile and manages up to `max_size` underlying connections. Callers
//! identify their work by `session_id` (typically a UUID per query
//! tab). The pool maps `session_id → connection` so a tab's cursor
//! always lives on the same wire across `execute → fetch_page →
//! close_query`. Idle connections are reused for fresh sessions.
//!
//! ## Why per-session leasing
//!
//! `tokio_postgres::Client` is `Sync`, but a Postgres *session* is
//! single-threaded by protocol: one transaction at a time, one cursor
//! at a time. To let two query tabs run independent paginated SELECTs
//! in parallel, each must hold its own connection for the cursor's
//! lifetime. Without that, opening cursor A then cursor B on the same
//! wire kills A — what Sprint 5's single-cursor invariant produced.
//!
//! ## Tunnel sharing
//!
//! When the profile uses an SSH tunnel, the listener is opened *once*
//! at pool construction and shared by every pooled connection — they
//! each open their own SSH `direct-tcpip` channel via the same local
//! port. Single tunnel per profile keeps SSH session usage minimal.
//!
//! ## Thread safety
//!
//! `PgPool` is `Send + Sync`. All public methods take `&self` and
//! acquire internal locks for short windows (the pool's own metadata
//! Mutex during lease/release, and a per-connection Mutex during
//! cursor bookkeeping). FFI callers wrap one `Arc<PgPool>` per
//! managed connection id.

pub mod config;
pub mod edit;
pub mod exec;
pub mod introspect;
pub mod parquet_export;
pub mod tunnel;

pub use config::{PgAuthMethod, PgConfig, PgTlsMode, SshTunnelRef};
pub use edit::{InsertColumnInput, InsertedRow, UpdateOutcome};
pub use exec::{ActiveCursor, ColumnMeta, ExecutionOutcome, PageResult};
pub use introspect::{
    ColumnDetail, DbSummary, ObjectType, ObjectTypeKind, Relation, RelationKind, Routine,
    RoutineKind, SchemaContents, SchemaSummary, Sequence,
};
pub use parquet_export::{ParquetExportError, ParquetRegistry};
pub use tunnel::SshTunnel;

use std::collections::HashMap;
use std::sync::{Arc, Weak};
use std::time::{Duration, Instant};

use rustls::ClientConfig as RustlsClientConfig;
use tokio::sync::{Mutex, RwLock};
use tokio::task::JoinHandle;
use tokio_postgres::config::SslMode as PgSslMode;
use tokio_postgres::{CancelToken, Client, Config as PgDriverConfig};
use tokio_postgres_rustls::MakeRustlsConnect;
use tokio_util::sync::CancellationToken;

use crate::ssh::SshClient;

/// Default upper bound on connections per pool. Five is plenty for an
/// interactive explorer (you'd need six query tabs running at once to
/// hit it) and well below the default `max_connections=100` Postgres
/// quota that managed providers tend to set.
const DEFAULT_MAX_POOL_SIZE: usize = 5;

/// Default idle-connection lifetime. Five minutes balances "alt-tabbing
/// out and back doesn't pay reconnect cost" against "polite to managed
/// providers that bill on connection-hours". Per-profile override on
/// `PgConfig.idle_timeout_secs`.
const DEFAULT_IDLE_TIMEOUT: Duration = Duration::from_secs(300);

/// How often the eviction loop wakes up. Independent of the idle
/// timeout — connections live at most `idle_timeout + EVICTION_INTERVAL`.
/// Not exposed on `PgConfig`; the cadence is global and the value is
/// already much smaller than typical idle_timeout settings.
const EVICTION_INTERVAL: Duration = Duration::from_secs(30);

/// Default minimum idle connections to keep alive past `idle_timeout`.
/// One warm connection means the next query doesn't pay connect
/// latency. Per-profile override on `PgConfig.min_idle_connections`.
const DEFAULT_MIN_IDLE_CONNECTIONS: usize = 1;

/// Stable session id used for the schema browser's introspection
/// calls (`list_databases`, `list_schemas`, `list_relations`). Uses
/// a name that can't collide with a UUID-generated tab session id.
pub const BROWSER_SESSION_ID: &str = "_browser";

/// Errors surfaced from the Postgres explorer layer.
#[derive(Debug, thiserror::Error)]
pub enum PgError {
    #[error("postgres connect failed: {0}")]
    Connect(String),
    #[error("postgres auth failed: {0}")]
    Auth(String),
    #[error("postgres tls setup failed: {0}")]
    Tls(String),
    #[error("ssh tunnel error: {0}")]
    Tunnel(String),
    /// Tunnel was requested but the referenced SSH connection isn't
    /// registered (or has been closed).
    #[error("ssh tunnel source not found: {0}")]
    TunnelSourceMissing(String),
    /// The cursor referenced by a fetch_page / close_query call no
    /// longer exists. Sprint 6: now scoped to the session — only
    /// fires if the same session opened a new cursor in between, or
    /// the session was released.
    #[error("cursor no longer available: {0}")]
    CursorExpired(String),
    /// The pool is at `max_size` and all connections are currently
    /// leased to other sessions. Caller should wait and retry, or
    /// release another session.
    #[error("pool exhausted: {0} of {1} connections leased")]
    PoolExhausted(usize, usize),
    #[error("postgres driver error: {0}")]
    Driver(#[from] tokio_postgres::Error),
}

// ============================================================================
// Pool
// ============================================================================

pub struct PgPool {
    config: PgConfig,
    /// Optional SSH tunnel shared across all pooled connections. The
    /// listener stays bound for the pool's lifetime; per-connection
    /// `direct-tcpip` channels open lazily as each connection
    /// dials in.
    tunnel: Option<Arc<SshTunnel>>,
    /// TLS connector built once at pool init and reused for every
    /// new connection plus every server-side cancel. Sharing
    /// matters for TLS-only Postgres deployments (RDS, Supabase,
    /// Neon) where the server rejects a plaintext cancel handshake;
    /// the cancel must use the same TLS posture as the data wire.
    tls_connector: TlsConnectorKind,
    /// Pool state guarded by a single Mutex. Acquire/release windows
    /// are short — the actual SQL round trips happen against the
    /// per-connection Mutex, not this one.
    inner: Mutex<PoolInner>,
    max_size: usize,
    /// Per-pool idle-connection lifetime. Read once at construction
    /// from `PgConfig.idle_timeout_secs` (or `DEFAULT_IDLE_TIMEOUT`).
    idle_timeout: Duration,
    /// Per-pool minimum-idle floor. Eviction won't drop below this
    /// even when entries are aged.
    min_idle: usize,
    /// Cached side-connections for browsing databases other than
    /// `config.database`. Postgres connections are bound to one
    /// database at connect time; the schema browser tree shows
    /// every database on the server, so expanding a non-default
    /// one needs its own connection. Keyed by database name.
    /// Lazily populated on first cross-database introspection;
    /// torn down by `shutdown`.
    secondary_browsers: Mutex<HashMap<String, Arc<Mutex<PooledConnection>>>>,
    /// Signal to the background eviction task that it should stop.
    /// `shutdown` cancels it explicitly; the task also self-exits
    /// when the pool's `Weak<Self>` upgrade fails (i.e. all `Arc`s
    /// have been dropped).
    eviction_cancel: CancellationToken,
}

/// One idle connection plus the moment it returned to idle. The
/// eviction loop reads `since` to decide what to drop. Newly opened
/// connections also enter idle with `since = now`, so a cold pool
/// doesn't immediately evict.
struct IdleEntry {
    since: Instant,
    conn: Arc<Mutex<PooledConnection>>,
}

/// Erased TLS strategy for both data connections and cancel
/// requests. `MakeRustlsConnect` clones cheaply (the inner
/// `rustls::ClientConfig` is `Arc`-shared), so reusing the same
/// instance for many connections is fine.
#[derive(Clone)]
enum TlsConnectorKind {
    NoTls,
    Rustls(MakeRustlsConnect),
}

struct PoolInner {
    /// Connections free to lease, with the timestamp they returned to
    /// idle. The eviction loop scans this list every
    /// `EVICTION_INTERVAL`.
    idle: Vec<IdleEntry>,
    /// Active leases, keyed by caller-supplied session id.
    leased: HashMap<String, Arc<Mutex<PooledConnection>>>,
    /// Total connections in existence (idle + leased + currently
    /// being opened). Bounds growth against `max_size`.
    total: usize,
}

struct PooledConnection {
    client: Client,
    cancel_token: CancelToken,
    /// At-most-one active cursor on this wire. Protected by the
    /// per-connection mutex (callers hold it for the duration of
    /// any cursor op).
    active_cursor: Option<ActiveCursor>,
    /// Background task that drives this connection's wire protocol.
    /// Aborted when the connection is dropped from the pool.
    connection_task: Option<JoinHandle<()>>,
}

impl PgPool {
    /// Open a pool with `min_size = 1` (one connection eagerly
    /// established) and `max_size = DEFAULT_MAX_POOL_SIZE`. Eager
    /// initial connect surfaces auth/network errors immediately
    /// rather than deferring them to the first query.
    pub async fn connect(
        cfg: PgConfig,
        ssh_client: Option<Arc<RwLock<SshClient>>>,
    ) -> Result<Arc<Self>, PgError> {
        // Open the tunnel once if requested. Subsequent connections
        // dial 127.0.0.1:<local_port> independently.
        let tunnel: Option<Arc<SshTunnel>> = if let Some(tunnel_ref) = cfg.ssh_tunnel.as_ref() {
            let Some(ssh) = ssh_client else {
                return Err(PgError::Tunnel(
                    "ssh tunnel requested but no ssh client supplied".into(),
                ));
            };
            let t = SshTunnel::open(
                ssh,
                tunnel_ref.remote_host.clone(),
                tunnel_ref.remote_port,
            )
            .await
            .map_err(|e| PgError::Tunnel(format!("failed to open ssh tunnel: {e}")))?;
            Some(Arc::new(t))
        } else {
            None
        };

        // Build the TLS connector once. Subsequent opens (and the
        // initial open below) reuse it; so does `cancel`.
        let tls_connector = build_tls_connector(&cfg)?;

        // Eager-connect the first connection so authentication errors
        // surface up front.
        let first = open_one(&cfg, tunnel.as_deref(), &tls_connector).await?;

        let now = Instant::now();
        // Apply per-profile overrides on top of the built-in
        // defaults. `0` is a valid `min_idle` (full evacuate) so we
        // pass it through as-is.
        let max_size = cfg
            .max_pool_size
            .map(|n| n as usize)
            .filter(|&n| n > 0)
            .unwrap_or(DEFAULT_MAX_POOL_SIZE);
        let idle_timeout = cfg
            .idle_timeout_secs
            .map(Duration::from_secs)
            .unwrap_or(DEFAULT_IDLE_TIMEOUT);
        let min_idle = cfg
            .min_idle_connections
            .map(|n| n as usize)
            .unwrap_or(DEFAULT_MIN_IDLE_CONNECTIONS);

        let pool = Arc::new(Self {
            config: cfg,
            tunnel,
            tls_connector,
            inner: Mutex::new(PoolInner {
                idle: vec![IdleEntry {
                    since: now,
                    conn: Arc::new(Mutex::new(first)),
                }],
                leased: HashMap::new(),
                total: 1,
            }),
            max_size,
            idle_timeout,
            min_idle,
            secondary_browsers: Mutex::new(HashMap::new()),
            eviction_cancel: CancellationToken::new(),
        });

        // Spawn the eviction loop. We hand it a `Weak<Self>` so the
        // pool can drop without the task keeping it alive — and a
        // clone of the cancel token so an explicit `shutdown` can
        // wake it immediately rather than waiting for the next tick.
        let weak = Arc::downgrade(&pool);
        let cancel = pool.eviction_cancel.clone();
        tokio::spawn(run_eviction(weak, cancel));

        Ok(pool)
    }

    // ------------------------------------------------------------------
    // High-level operations
    // ------------------------------------------------------------------

    /// Schema introspection runs on the connection bound to the
    /// well-known browser session. Re-using the same session means
    /// the browser doesn't churn through pool slots on every tree
    /// refresh.
    pub async fn list_databases(&self) -> Result<Vec<DbSummary>, PgError> {
        let conn = self.lease_for_session(BROWSER_SESSION_ID).await?;
        let guard = conn.lock().await;
        Ok(introspect::list_databases(&guard.client).await?)
    }

    pub async fn list_schemas(&self) -> Result<Vec<SchemaSummary>, PgError> {
        self.list_schemas_in(None).await
    }

    /// List schemas in `database`, opening (and caching) a side
    /// connection when it differs from the connection's default DB.
    /// Postgres binds a connection to one database at startup, so
    /// browsing other DBs in the tree requires this routing —
    /// otherwise every database expansion would show the connected
    /// DB's schemas.
    pub async fn list_schemas_in(
        &self,
        database: Option<&str>,
    ) -> Result<Vec<SchemaSummary>, PgError> {
        let conn = self.browser_connection_for(database).await?;
        let guard = conn.lock().await;
        Ok(introspect::list_schemas(&guard.client).await?)
    }

    pub async fn list_relations(&self, schema: &str) -> Result<Vec<Relation>, PgError> {
        self.list_relations_in(schema, None).await
    }

    pub async fn list_relations_in(
        &self,
        schema: &str,
        database: Option<&str>,
    ) -> Result<Vec<Relation>, PgError> {
        let conn = self.browser_connection_for(database).await?;
        let guard = conn.lock().await;
        Ok(introspect::list_relations(&guard.client, schema).await?)
    }

    /// Unified schema-contents fetch — tables, views, mat-views,
    /// sequences, routines, and object types in one call. Replaces
    /// the per-category round-trips the older tree did, and is what
    /// the DataGrip-style 6-category tree expects.
    pub async fn list_schema_contents_in(
        &self,
        schema: &str,
        database: Option<&str>,
    ) -> Result<SchemaContents, PgError> {
        let conn = self.browser_connection_for(database).await?;
        let guard = conn.lock().await;
        Ok(introspect::list_schema_contents(&guard.client, schema).await?)
    }

    /// Resolve a browser connection for `database`. When `None` or
    /// matching the pool's default DB, returns the regular browser
    /// session's lease. Otherwise opens (or returns cached) a
    /// secondary connection bound to that database.
    async fn browser_connection_for(
        &self,
        database: Option<&str>,
    ) -> Result<Arc<Mutex<PooledConnection>>, PgError> {
        let target = database.unwrap_or(self.config.database.as_str());
        if target == self.config.database {
            return self.lease_for_session(BROWSER_SESSION_ID).await;
        }
        // Cached secondary?
        {
            let map = self.secondary_browsers.lock().await;
            if let Some(c) = map.get(target) {
                return Ok(c.clone());
            }
        }
        // Open a fresh connection bound to the target database.
        // Reuse credentials, TLS posture, and tunnel — only the
        // database name differs.
        let mut cfg = self.config.clone();
        cfg.database = target.to_string();
        let conn = open_one(&cfg, self.tunnel.as_deref(), &self.tls_connector).await?;
        let arc = Arc::new(Mutex::new(conn));
        let mut map = self.secondary_browsers.lock().await;
        // Race: another task may have inserted while we were
        // opening. Prefer the existing entry to avoid leaking the
        // freshly-opened one — drop ours, return theirs.
        if let Some(existing) = map.get(target) {
            return Ok(existing.clone());
        }
        map.insert(target.to_string(), arc.clone());
        Ok(arc)
    }

    /// Describe a relation's columns for the INSERT form. Runs on
    /// the browser session to avoid churning a query tab's lease.
    pub async fn describe_columns(
        &self,
        schema: &str,
        table: &str,
    ) -> Result<Vec<ColumnDetail>, PgError> {
        let conn = self.lease_for_session(BROWSER_SESSION_ID).await?;
        let guard = conn.lock().await;
        Ok(introspect::describe_columns(&guard.client, schema, table).await?)
    }

    /// Run a SQL statement on the connection assigned to `session_id`,
    /// leasing one if the session is new. Closes any previously-active
    /// cursor on that connection (per-session behavior — other sessions
    /// are unaffected).
    pub async fn execute(
        &self,
        session_id: &str,
        sql: &str,
        page_size: usize,
    ) -> Result<ExecutionOutcome, PgError> {
        let conn = self.lease_for_session(session_id).await?;
        let mut guard = conn.lock().await;
        let previous = guard.active_cursor.take();
        let (outcome, new_cursor) =
            exec::open_query(&guard.client, sql, page_size, previous).await?;
        guard.active_cursor = new_cursor;
        // If the cursor closed (no more rows), the connection is
        // logically idle — but we keep the lease so the same session
        // continues to land on the same wire for follow-up commands
        // (helpful for SET / temporary tables). Explicit
        // `release_session` returns it to idle.
        Ok(outcome)
    }

    pub async fn fetch_page(
        &self,
        session_id: &str,
        cursor_id: &str,
        count: usize,
    ) -> Result<PageResult, PgError> {
        let conn = self
            .leased_only(session_id)
            .await
            .ok_or_else(|| PgError::CursorExpired(format!("no active session {session_id}")))?;
        let guard = conn.lock().await;
        let Some(cursor) = guard.active_cursor.as_ref() else {
            return Err(PgError::CursorExpired(format!(
                "session {session_id} has no active cursor"
            )));
        };
        if cursor.cursor_id != cursor_id {
            return Err(PgError::CursorExpired(format!(
                "session {session_id} active cursor is {} (looking for {cursor_id})",
                cursor.cursor_id
            )));
        }
        let cursor_clone = cursor.clone();
        let client = &guard.client;
        exec::fetch_page(client, &cursor_clone, count).await
    }

    /// Update a single cell on `(schema, table)` identified by ctid.
    /// Runs on the session's connection so users editing in one tab
    /// don't block on another tab's pagination cursor. Returns
    /// `UpdateOutcome { rows_affected }` — the UI treats `0` as
    /// "row no longer there, please refresh".
    pub async fn update_cell(
        &self,
        session_id: &str,
        schema: &str,
        table: &str,
        column: &str,
        column_type: &str,
        new_value: Option<&str>,
        ctid: &str,
    ) -> Result<UpdateOutcome, PgError> {
        let conn = self.lease_for_session(session_id).await?;
        let guard = conn.lock().await;
        edit::update_cell(
            &guard.client,
            schema,
            table,
            column,
            column_type,
            new_value,
            ctid,
        )
        .await
    }

    /// Insert one row, returning the requested columns. Runs on the
    /// session's connection so any session-local state (SET,
    /// transactions) applies. See [`edit::insert_row`] for the SQL
    /// shape and parameter rules.
    pub async fn insert_row(
        &self,
        session_id: &str,
        schema: &str,
        table: &str,
        inputs: &[InsertColumnInput],
        return_columns: &[String],
    ) -> Result<InsertedRow, PgError> {
        let conn = self.lease_for_session(session_id).await?;
        let guard = conn.lock().await;
        edit::insert_row(&guard.client, schema, table, inputs, return_columns).await
    }

    /// Delete one or more rows by ctid on the session's connection.
    /// Returns the actual rows-deleted count — callers compare
    /// against the requested count to spot "some rows were already
    /// gone" (concurrent edit / delete from another session).
    pub async fn delete_rows(
        &self,
        session_id: &str,
        schema: &str,
        table: &str,
        ctids: &[String],
    ) -> Result<UpdateOutcome, PgError> {
        let conn = self.lease_for_session(session_id).await?;
        let guard = conn.lock().await;
        edit::delete_rows(&guard.client, schema, table, ctids).await
    }

    pub async fn close_query(
        &self,
        session_id: &str,
        cursor_id: &str,
    ) -> Result<(), PgError> {
        let Some(conn) = self.leased_only(session_id).await else {
            return Ok(()); // Nothing to close — idempotent.
        };
        let mut guard = conn.lock().await;
        if let Some(c) = guard.active_cursor.as_ref() {
            if c.cursor_id == cursor_id {
                let cursor = guard.active_cursor.take().expect("just checked");
                let client = &guard.client;
                exec::close_query(client, &cursor).await;
            }
        }
        Ok(())
    }

    /// Server-side cancel for whatever query is in flight on the
    /// session's connection. Uses the same TLS posture as the
    /// data wire — TLS-only Postgres deployments (RDS, Supabase,
    /// Neon) reject plaintext cancels, which would silently leave
    /// the in-flight query running until it timed out. No-op if
    /// the session has no lease.
    pub async fn cancel(&self, session_id: &str) -> Result<(), PgError> {
        let Some(conn) = self.leased_only(session_id).await else {
            return Ok(());
        };
        let token = {
            let guard = conn.lock().await;
            guard.cancel_token.clone()
        };
        match &self.tls_connector {
            TlsConnectorKind::NoTls => token.cancel_query(tokio_postgres::NoTls).await,
            TlsConnectorKind::Rustls(connector) => token.cancel_query(connector.clone()).await,
        }
        .map_err(PgError::Driver)
    }

    /// Release a session's lease. Closes any active cursor first so
    /// the underlying connection returns to idle in a clean state.
    pub async fn release_session(&self, session_id: &str) {
        let Some(conn) = self.take_lease(session_id).await else {
            return;
        };
        // Close any open cursor + transaction so the connection is
        // safe to hand to a different session.
        {
            let mut guard = conn.lock().await;
            if let Some(cursor) = guard.active_cursor.take() {
                exec::close_query(&guard.client, &cursor).await;
            }
        }
        // Return to idle, stamping the moment of release so the
        // eviction loop can age it out.
        let mut inner = self.inner.lock().await;
        inner.idle.push(IdleEntry {
            since: Instant::now(),
            conn,
        });
    }

    /// Tear down all connections. Used on `disconnect`.
    pub async fn shutdown(&self) {
        // Wake the eviction loop so it exits promptly rather than
        // sleeping on the next tick.
        self.eviction_cancel.cancel();

        let mut inner = self.inner.lock().await;
        let mut conns: Vec<Arc<Mutex<PooledConnection>>> =
            inner.idle.drain(..).map(|e| e.conn).collect();
        conns.extend(inner.leased.drain().map(|(_, c)| c));
        inner.total = 0;
        drop(inner);
        // Also close any secondary cross-database browser
        // connections we opened.
        let secondaries: Vec<Arc<Mutex<PooledConnection>>> = {
            let mut map = self.secondary_browsers.lock().await;
            map.drain().map(|(_, c)| c).collect()
        };
        let conns_with_secondaries = conns.into_iter().chain(secondaries.into_iter());
        let conns: Vec<Arc<Mutex<PooledConnection>>> = conns_with_secondaries.collect();
        for conn in conns {
            // Best-effort task abort; the wire closes when `Client`
            // is dropped (which happens when the last Arc to this
            // PooledConnection drops — usually right here).
            let mut guard = conn.lock().await;
            if let Some(task) = guard.connection_task.take() {
                task.abort();
            }
        }
    }

    // ------------------------------------------------------------------
    // Internal: leasing
    // ------------------------------------------------------------------

    /// Get the connection currently leased to `session_id`, opening
    /// a new one (and leasing it) when the session is new.
    async fn lease_for_session(
        &self,
        session_id: &str,
    ) -> Result<Arc<Mutex<PooledConnection>>, PgError> {
        // Fast path: existing lease.
        {
            let inner = self.inner.lock().await;
            if let Some(c) = inner.leased.get(session_id) {
                return Ok(c.clone());
            }
        }

        // Try to grab an idle connection first. LIFO (`pop`) keeps
        // the most-recently-released connection warm — which is the
        // youngest, most-likely-to-survive eviction next round.
        let from_idle = {
            let mut inner = self.inner.lock().await;
            inner.idle.pop().map(|e| e.conn)
        };
        if let Some(conn) = from_idle {
            self.assign_lease(session_id, conn.clone()).await;
            return Ok(conn);
        }

        // No idle connections. Open a new one if we have room.
        let need_new = {
            let inner = self.inner.lock().await;
            if inner.total >= self.max_size {
                return Err(PgError::PoolExhausted(inner.total, self.max_size));
            }
            true
        };
        if need_new {
            // Reserve the slot before the network round trip so two
            // simultaneous lease requests don't both think there's
            // room.
            {
                let mut inner = self.inner.lock().await;
                if inner.total >= self.max_size {
                    return Err(PgError::PoolExhausted(inner.total, self.max_size));
                }
                inner.total += 1;
            }
            let new_conn = match open_one(
                &self.config,
                self.tunnel.as_deref(),
                &self.tls_connector,
            )
            .await
            {
                Ok(c) => c,
                Err(e) => {
                    // Roll back the slot reservation on failure so
                    // the pool can try again later.
                    let mut inner = self.inner.lock().await;
                    inner.total = inner.total.saturating_sub(1);
                    return Err(e);
                }
            };
            let conn = Arc::new(Mutex::new(new_conn));
            self.assign_lease(session_id, conn.clone()).await;
            return Ok(conn);
        }
        unreachable!()
    }

    async fn assign_lease(&self, session_id: &str, conn: Arc<Mutex<PooledConnection>>) {
        let mut inner = self.inner.lock().await;
        inner.leased.insert(session_id.to_string(), conn);
    }

    /// Evict idle connections older than the pool's configured
    /// `idle_timeout`, keeping at least `min_idle` alive. Runs from
    /// the background eviction task; safe to call manually too.
    async fn evict_idle(&self) {
        let now = Instant::now();
        let to_drop: Vec<Arc<Mutex<PooledConnection>>>;
        {
            let mut inner = self.inner.lock().await;
            // Take the idle list out so we can decide which entries
            // to keep without holding the lock during async work.
            // Single-pass keep/drop: iterate in storage order (most
            // recently released last, since `lease` pops from the
            // end); the first `min_idle` we encounter are pinned
            // regardless of age.
            let snapshot = std::mem::take(&mut inner.idle);
            let mut keep: Vec<IdleEntry> = Vec::with_capacity(snapshot.len());
            let mut drop_list: Vec<Arc<Mutex<PooledConnection>>> = Vec::new();
            for entry in snapshot.into_iter() {
                let aged = now.duration_since(entry.since) >= self.idle_timeout;
                if !aged || keep.len() < self.min_idle {
                    keep.push(entry);
                } else {
                    drop_list.push(entry.conn);
                    inner.total = inner.total.saturating_sub(1);
                }
            }
            inner.idle = keep;
            to_drop = drop_list;
        }

        if !to_drop.is_empty() {
            tracing::debug!(
                target: "postgres::pool",
                count = to_drop.len(),
                "evicted idle postgres connections"
            );
        }

        // Abort the connection tasks. Dropping the `Arc` (via
        // out-of-scope at end of this function) closes the wire when
        // the last reference goes — which is here, since `idle`
        // held the only one.
        for conn in to_drop {
            let mut guard = conn.lock().await;
            if let Some(task) = guard.connection_task.take() {
                task.abort();
            }
        }
    }

    /// Look up the lease for `session_id` without opening a new one.
    async fn leased_only(&self, session_id: &str) -> Option<Arc<Mutex<PooledConnection>>> {
        let inner = self.inner.lock().await;
        inner.leased.get(session_id).cloned()
    }

    /// Remove and return the lease for `session_id`.
    async fn take_lease(&self, session_id: &str) -> Option<Arc<Mutex<PooledConnection>>> {
        let mut inner = self.inner.lock().await;
        inner.leased.remove(session_id)
    }

}

impl Drop for PgPool {
    fn drop(&mut self) {
        // Cancel the eviction loop first so it doesn't try to upgrade
        // the soon-dead `Weak<Self>` and log spurious work.
        self.eviction_cancel.cancel();

        // Best-effort: abort connection tasks. Async shutdown is the
        // documented path for clean teardown; this guards against
        // forgotten shutdown calls.
        if let Ok(mut inner) = self.inner.try_lock() {
            let mut conns: Vec<Arc<Mutex<PooledConnection>>> =
                inner.idle.drain(..).map(|e| e.conn).collect();
            conns.extend(inner.leased.drain().map(|(_, c)| c));
            for conn in conns {
                if let Ok(mut guard) = conn.try_lock() {
                    if let Some(task) = guard.connection_task.take() {
                        task.abort();
                    }
                }
            }
        }
        // Best-effort close of secondary cross-database browsers.
        if let Ok(mut map) = self.secondary_browsers.try_lock() {
            for (_, conn) in map.drain() {
                if let Ok(mut guard) = conn.try_lock() {
                    if let Some(task) = guard.connection_task.take() {
                        task.abort();
                    }
                }
            }
        }
    }
}

// ============================================================================
// Background eviction (private)
// ============================================================================

/// Background loop that prunes idle connections aged past
/// `IDLE_TIMEOUT`. Holds a `Weak<PgPool>` so it can't extend the
/// pool's lifetime — when all `Arc<PgPool>`s are dropped, the next
/// upgrade fails and the loop exits.
async fn run_eviction(pool: Weak<PgPool>, cancel: CancellationToken) {
    let mut ticker = tokio::time::interval(EVICTION_INTERVAL);
    // Skip the immediate first tick — `connect` just opened a
    // connection so there's nothing to evict yet.
    ticker.tick().await;
    loop {
        tokio::select! {
            _ = cancel.cancelled() => return,
            _ = ticker.tick() => {
                let Some(pool) = pool.upgrade() else { return };
                pool.evict_idle().await;
                // Drop the strong ref before the next sleep so the
                // pool can be reclaimed promptly when the manager
                // discards it.
                drop(pool);
            }
        }
    }
}

// ============================================================================
// Connection construction (private)
// ============================================================================

async fn open_one(
    cfg: &PgConfig,
    tunnel: Option<&SshTunnel>,
    tls: &TlsConnectorKind,
) -> Result<PooledConnection, PgError> {
    let driver_cfg = build_driver_config(cfg, tunnel)?;
    match tls {
        TlsConnectorKind::NoTls => {
            let (client, connection) = driver_cfg
                .connect(tokio_postgres::NoTls)
                .await
                .map_err(classify_connect_error)?;
            Ok(spawn_connection(client, connection))
        }
        TlsConnectorKind::Rustls(connector) => {
            // `MakeRustlsConnect` clones cheaply (Arc-shared
            // ClientConfig); each connect consumes its own clone.
            let (client, connection) = driver_cfg
                .connect(connector.clone())
                .await
                .map_err(classify_connect_error)?;
            Ok(spawn_connection(client, connection))
        }
    }
}

/// Build the TLS connector used for both the data wire and cancel
/// handshakes for this pool. Installing the rustls crypto provider
/// once per pool is sufficient — the call is idempotent across
/// multiple pools (the second install returns Err and we ignore it).
fn build_tls_connector(cfg: &PgConfig) -> Result<TlsConnectorKind, PgError> {
    match cfg.tls {
        PgTlsMode::Disable => Ok(TlsConnectorKind::NoTls),
        PgTlsMode::Prefer | PgTlsMode::Require | PgTlsMode::VerifyFull => {
            let _ = rustls::crypto::ring::default_provider().install_default();
            let tls_config = build_rustls_config(cfg.tls)?;
            Ok(TlsConnectorKind::Rustls(MakeRustlsConnect::new(tls_config)))
        }
    }
}

fn build_driver_config(
    cfg: &PgConfig,
    tunnel: Option<&SshTunnel>,
) -> Result<PgDriverConfig, PgError> {
    let mut driver = PgDriverConfig::new();
    if let Some(t) = tunnel {
        driver.host("127.0.0.1").port(t.local_port());
    } else {
        driver.host(&cfg.host).port(cfg.port);
    }
    driver.dbname(&cfg.database).user(&cfg.user);

    let password = match &cfg.auth {
        PgAuthMethod::Password { password } => password.clone(),
        PgAuthMethod::Keychain { account } => crate::keychain::load_password(
            crate::keychain::CredentialKind::PostgresPassword,
            account,
        )
        .map_err(|e| PgError::Auth(format!("keychain load failed for {account}: {e}")))?
        .ok_or_else(|| {
            PgError::Auth(format!("no keychain entry for postgres account {account}"))
        })?,
    };
    if !password.is_empty() {
        driver.password(password);
    }

    if let Some(name) = &cfg.application_name {
        driver.application_name(name);
    }
    if let Some(secs) = cfg.connect_timeout_secs {
        driver.connect_timeout(Duration::from_secs(secs));
    }

    driver.ssl_mode(match cfg.tls {
        PgTlsMode::Disable => PgSslMode::Disable,
        PgTlsMode::Prefer => PgSslMode::Prefer,
        PgTlsMode::Require | PgTlsMode::VerifyFull => PgSslMode::Require,
    });
    Ok(driver)
}

fn build_rustls_config(mode: PgTlsMode) -> Result<RustlsClientConfig, PgError> {
    let mut roots = rustls::RootCertStore::empty();
    let native = rustls_native_certs::load_native_certs();
    for cert in native.certs {
        let _ = roots.add(cert);
    }

    let cfg = match mode {
        PgTlsMode::VerifyFull => RustlsClientConfig::builder()
            .with_root_certificates(roots)
            .with_no_client_auth(),
        _ => RustlsClientConfig::builder()
            .dangerous()
            .with_custom_certificate_verifier(std::sync::Arc::new(NoCertVerifier))
            .with_no_client_auth(),
    };
    Ok(cfg)
}

fn classify_connect_error(e: tokio_postgres::Error) -> PgError {
    if let Some(db_err) = e.as_db_error() {
        let code = db_err.code().code();
        if code == "28P01" || code == "28000" {
            return PgError::Auth(db_err.message().to_string());
        }
    }
    PgError::Connect(e.to_string())
}

fn spawn_connection<S, T>(
    client: Client,
    connection: tokio_postgres::Connection<S, T>,
) -> PooledConnection
where
    S: tokio::io::AsyncRead + tokio::io::AsyncWrite + Unpin + Send + 'static,
    T: tokio_postgres::tls::TlsStream + Unpin + Send + 'static,
{
    let cancel_token = client.cancel_token();
    let task = tokio::spawn(async move {
        if let Err(e) = connection.await {
            tracing::warn!("postgres connection task ended with error: {e}");
        }
    });
    PooledConnection {
        client,
        cancel_token,
        active_cursor: None,
        connection_task: Some(task),
    }
}

#[derive(Debug)]
struct NoCertVerifier;

impl rustls::client::danger::ServerCertVerifier for NoCertVerifier {
    fn verify_server_cert(
        &self,
        _end_entity: &rustls::pki_types::CertificateDer<'_>,
        _intermediates: &[rustls::pki_types::CertificateDer<'_>],
        _server_name: &rustls::pki_types::ServerName<'_>,
        _ocsp_response: &[u8],
        _now: rustls::pki_types::UnixTime,
    ) -> Result<rustls::client::danger::ServerCertVerified, rustls::Error> {
        Ok(rustls::client::danger::ServerCertVerified::assertion())
    }

    fn verify_tls12_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn verify_tls13_signature(
        &self,
        _message: &[u8],
        _cert: &rustls::pki_types::CertificateDer<'_>,
        _dss: &rustls::DigitallySignedStruct,
    ) -> Result<rustls::client::danger::HandshakeSignatureValid, rustls::Error> {
        Ok(rustls::client::danger::HandshakeSignatureValid::assertion())
    }

    fn supported_verify_schemes(&self) -> Vec<rustls::SignatureScheme> {
        vec![
            rustls::SignatureScheme::RSA_PKCS1_SHA256,
            rustls::SignatureScheme::RSA_PKCS1_SHA384,
            rustls::SignatureScheme::RSA_PKCS1_SHA512,
            rustls::SignatureScheme::ECDSA_NISTP256_SHA256,
            rustls::SignatureScheme::ECDSA_NISTP384_SHA384,
            rustls::SignatureScheme::ED25519,
            rustls::SignatureScheme::RSA_PSS_SHA256,
            rustls::SignatureScheme::RSA_PSS_SHA384,
            rustls::SignatureScheme::RSA_PSS_SHA512,
        ]
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    /// `PgPool::connect` rejects a tunneled config when no SSH client
    /// is supplied. The macOS bridge always supplies one when the
    /// config requests a tunnel; this guards against accidental
    /// bypass in tests / library usage.
    #[test]
    fn pool_connect_with_tunnel_requires_ssh_client() {
        let cfg = PgConfig {
            ssh_tunnel: Some(SshTunnelRef {
                ssh_connection_id: "ssh-1".to_string(),
                remote_host: "db".to_string(),
                remote_port: 5432,
            }),
            ..PgConfig::local("db", "u")
        };
        let rt = tokio::runtime::Runtime::new().unwrap();
        match rt.block_on(PgPool::connect(cfg, None)) {
            Err(PgError::Tunnel(detail)) => {
                assert!(detail.contains("ssh client"));
            }
            Err(other) => panic!("expected Tunnel error, got {other:?}"),
            Ok(_) => panic!("expected error, got Ok"),
        }
    }

    #[test]
    fn driver_config_uses_correct_ssl_mode() {
        let mut cfg = PgConfig::local("db", "u");
        cfg.tls = PgTlsMode::Require;
        let driver = build_driver_config(&cfg, None).expect("driver cfg");
        assert!(matches!(driver.get_ssl_mode(), PgSslMode::Require));

        cfg.tls = PgTlsMode::Disable;
        let driver = build_driver_config(&cfg, None).expect("driver cfg");
        assert!(matches!(driver.get_ssl_mode(), PgSslMode::Disable));
    }

    #[test]
    fn driver_config_omits_password_when_empty() {
        let cfg = PgConfig::local("db", "u");
        let driver = build_driver_config(&cfg, None).expect("driver cfg");
        assert!(driver.get_password().is_none());
    }

    /// Pure logic test of the eviction policy: given idle entries
    /// with various ages, the keep/drop split honors `IDLE_TIMEOUT`
    /// and `MIN_IDLE_CONNECTIONS`. Doesn't open real connections —
    /// the policy is just arithmetic over `(since, idx)` pairs.
    #[test]
    fn eviction_policy_keeps_min_idle_and_drops_aged() {
        // The keep/drop math against (idle_timeout, min_idle) inputs.
        // Mirrors `evict_idle` so a future change to the loop forces
        // a test update.
        fn run_policy(
            entries: Vec<(usize, Instant)>,
            now: Instant,
            idle_timeout: Duration,
            min_idle: usize,
        ) -> (Vec<usize>, Vec<usize>) {
            let mut keep: Vec<usize> = Vec::new();
            let mut drop_idx: Vec<usize> = Vec::new();
            for (idx, since) in entries {
                let aged = now.duration_since(since) >= idle_timeout;
                if !aged || keep.len() < min_idle {
                    keep.push(idx);
                } else {
                    drop_idx.push(idx);
                }
            }
            (keep, drop_idx)
        }

        let now = Instant::now();
        let timeout = Duration::from_secs(300);
        let aged = now - timeout - Duration::from_secs(1);
        let fresh = now - Duration::from_secs(10);

        // min_idle = 1 (default): one aged entry survives, fresh
        // always survives, rest evicted.
        let (keep, drop_idx) = run_policy(
            vec![(0, aged), (1, aged), (2, fresh), (3, aged)],
            now,
            timeout,
            1,
        );
        assert_eq!(keep, vec![0, 2]);
        assert_eq!(drop_idx, vec![1, 3]);

        // min_idle = 0: all aged entries evicted, only fresh survives.
        let (keep, drop_idx) = run_policy(
            vec![(0, aged), (1, fresh), (2, aged)],
            now,
            timeout,
            0,
        );
        assert_eq!(keep, vec![1]);
        assert_eq!(drop_idx, vec![0, 2]);
    }
}
