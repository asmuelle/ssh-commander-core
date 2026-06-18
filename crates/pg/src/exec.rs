//! Query execution for the Postgres explorer.
//!
//! Sprint 5 strategy: server-side cursors driven by `simple_query`.
//! The cursor holds the result set on the server; the explorer streams
//! pages on demand. This replaces the Sprint 3 "fetch everything up to
//! `max_rows`" approach so users can browse genuinely large tables.
//!
//! ## Why simple_query (still)
//!
//! Even with cursors, we use `simple_query` for the FETCH itself —
//! it returns text representations of every value, which gives us
//! universal type support (bytea, JSON, arrays, ranges, custom enums,
//! geometry) without per-OID decoding.
//!
//! ## Cursor lifecycle
//!
//! - `BEGIN; DECLARE c_<uuid> NO SCROLL CURSOR FOR <user_sql>` opens.
//! - `FETCH FORWARD <n> FROM c_<uuid>` returns the next page; the
//!   server's `CommandComplete(actual)` tells us how many rows came
//!   back, so we know whether more remain (actual == n means there's
//!   probably more; actual < n means the cursor exhausted).
//! - `CLOSE c_<uuid>; COMMIT` releases the server resources.
//!
//! Single-cursor invariant is enforced by the pool's per-connection lease
//! (one transaction per connection on the wire). If a second `execute`
//! call comes in while a cursor is open, the old one is closed first
//! — the surfaced `CursorExpired` error tells the previous tab's UI
//! that "Load more" can no longer fetch.

use serde::{Deserialize, Serialize};
use tokio_postgres::{Client, SimpleQueryMessage};
use uuid::Uuid;

use crate::PgError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnMeta {
    pub name: String,
    /// Postgres type OID (oid 16 = bool, 23 = int4, 1184 = timestamptz,
    /// 3802 = jsonb, etc). Stable across server versions, so the UI
    /// can decide presentation (alignment, formatting) from this
    /// without a separate type-name lookup. `0` if the source
    /// statement didn't expose a typed column descriptor (rare —
    /// only certain dynamic catalog functions).
    pub type_oid: u32,
    /// Human-readable type name from `pg_type.typname` (`int4`,
    /// `timestamptz`, `jsonb`, …). Surfaces in tooltips and gives
    /// the UI a reasonable fallback label for OIDs the affinity
    /// decoder doesn't classify.
    pub type_name: String,
}

/// Server-side cursor metadata. Held by the client when a query has
/// remaining rows; consumed (closed) on `close_query` or when the next
/// `execute` call supersedes it.
#[derive(Debug, Clone)]
pub struct ActiveCursor {
    pub cursor_id: String,
    pub column_count: usize,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ExecutionOutcome {
    /// Column metadata. Empty for non-row-returning statements.
    pub columns: Vec<ColumnMeta>,
    /// First page of rows. Each inner `Vec` has `columns.len()`
    /// entries; `None` is SQL NULL.
    pub rows: Vec<Vec<Option<String>>>,
    /// `RowsAffected` from the last completed statement, when the
    /// server reports one.
    pub rows_affected: Option<u64>,
    /// `Some(_)` when the query returned a full page and more rows
    /// remain server-side. The id is opaque to callers and used as
    /// the handle for [`fetch_page`] / [`close_query`].
    pub cursor_id: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct PageResult {
    pub rows: Vec<Vec<Option<String>>>,
    /// `true` when this page filled to `count` (so more might be
    /// available). `false` when the cursor exhausted on this fetch.
    pub has_more: bool,
}

/// Detect whether `sql` contains more than one statement.
///
/// Walks the text with a tiny lexer that tracks string literals
/// (`'…''…'`), quoted identifiers (`"…""…"`), line comments (`-- …`),
/// and block comments (`/* … */`). A `;` outside any of those
/// contexts, with at least one non-whitespace character following,
/// makes the script "multi-statement".
///
/// False positives are possible only for SQL that looks like
/// `…';' …` inside a quote we mis-tracked — extremely rare and the
/// fallback (lose column types, no cursor pagination) is non-fatal.
pub(crate) fn is_multi_statement(sql: &str) -> bool {
    top_level_semicolons(sql)
        .into_iter()
        .any(|idx| !is_effectively_empty(&sql[idx + 1..]))
}

/// Split a multi-statement script into `(preamble, main)` where
/// `main` is the last top-level statement and `preamble` is
/// everything before it. Returns `None` when no clean split is
/// available (script is single-statement or the trailing piece is
/// blank/comment-only after the last delimiter).
///
/// The point of the split is to let the caller run `preamble` via
/// `batch_execute` (which preserves the SET/SHOW/etc effects) and
/// then run `main` through the cursor path so pagination works on
/// the SELECT that the user actually cares about.
pub(crate) fn split_at_last_statement(sql: &str) -> Option<(&str, &str)> {
    let split = top_level_semicolons(sql).into_iter().last()?;
    let main = &sql[split + 1..];
    if is_effectively_empty(main) {
        // Trailing semicolon with nothing real after — possibly just
        // whitespace, a line comment, or a block comment. Caller
        // falls back to the bulk multi-statement path.
        return None;
    }
    let main = main.trim();
    let preamble = &sql[..split + 1]; // include the delimiter
    // Refuse to split if the "main" itself contains an unguarded `;`
    // — defensive: the main piece must be a single statement so the
    // cursor path's `prepare` accepts it.
    if is_multi_statement(main) {
        return None;
    }
    Some((preamble, main))
}

fn top_level_semicolons(sql: &str) -> Vec<usize> {
    enum LexState<'a> {
        Normal,
        SingleQuote,
        DoubleQuote,
        LineComment,
        BlockComment,
        DollarQuote(&'a str),
    }

    let bytes = sql.as_bytes();
    let mut positions = Vec::new();
    let mut i = 0usize;
    let mut state = LexState::Normal;
    while i < bytes.len() {
        let c = bytes[i];
        match state {
            LexState::Normal => match c {
                b'\'' => state = LexState::SingleQuote,
                b'"' => state = LexState::DoubleQuote,
                b'-' if i + 1 < bytes.len() && bytes[i + 1] == b'-' => {
                    state = LexState::LineComment;
                    i += 1;
                }
                b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                    state = LexState::BlockComment;
                    i += 1;
                }
                b'$' => {
                    if let Some(delimiter) = dollar_quote_delimiter_at(sql, i) {
                        state = LexState::DollarQuote(delimiter);
                        i += delimiter.len() - 1;
                    }
                }
                b';' => positions.push(i),
                _ => {}
            },
            LexState::SingleQuote => {
                if c == b'\'' {
                    if i + 1 < bytes.len() && bytes[i + 1] == b'\'' {
                        i += 1;
                    } else {
                        state = LexState::Normal;
                    }
                }
            }
            LexState::DoubleQuote => {
                if c == b'"' {
                    if i + 1 < bytes.len() && bytes[i + 1] == b'"' {
                        i += 1;
                    } else {
                        state = LexState::Normal;
                    }
                }
            }
            LexState::LineComment => {
                if c == b'\n' {
                    state = LexState::Normal;
                }
            }
            LexState::BlockComment => {
                if c == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    state = LexState::Normal;
                    i += 1;
                }
            }
            LexState::DollarQuote(delimiter) => {
                if sql[i..].starts_with(delimiter) {
                    state = LexState::Normal;
                    i += delimiter.len() - 1;
                }
            }
        }
        i += 1;
    }
    positions
}

fn dollar_quote_delimiter_at(sql: &str, start: usize) -> Option<&str> {
    let bytes = sql.as_bytes();
    if bytes.get(start) != Some(&b'$') {
        return None;
    }
    let mut end = start + 1;
    match bytes.get(end) {
        Some(b'$') => return Some(&sql[start..=end]),
        Some(b) if b.is_ascii_alphabetic() || *b == b'_' => end += 1,
        _ => return None,
    }
    while let Some(b) = bytes.get(end)
        && (b.is_ascii_alphanumeric() || *b == b'_')
    {
        end += 1;
    }
    if bytes.get(end) == Some(&b'$') {
        Some(&sql[start..=end])
    } else {
        None
    }
}

/// Whether `sql` is whitespace + comments only — i.e. has no real
/// SQL token. Used by the smart splitter to detect "trailing noise"
/// (a comment after the final `;`) and treat it as no-main-statement.
fn is_effectively_empty(sql: &str) -> bool {
    enum LexState {
        Normal,
        LineComment,
        BlockComment,
    }
    let bytes = sql.as_bytes();
    let mut i = 0usize;
    let mut state = LexState::Normal;
    while i < bytes.len() {
        let c = bytes[i];
        match state {
            LexState::Normal => match c {
                b' ' | b'\t' | b'\n' | b'\r' => {}
                b'-' if i + 1 < bytes.len() && bytes[i + 1] == b'-' => {
                    state = LexState::LineComment;
                    i += 1;
                }
                b'/' if i + 1 < bytes.len() && bytes[i + 1] == b'*' => {
                    state = LexState::BlockComment;
                    i += 1;
                }
                _ => return false,
            },
            LexState::LineComment => {
                if c == b'\n' {
                    state = LexState::Normal;
                }
            }
            LexState::BlockComment => {
                if c == b'*' && i + 1 < bytes.len() && bytes[i + 1] == b'/' {
                    state = LexState::Normal;
                    i += 1;
                }
            }
        }
        i += 1;
    }
    true
}

/// Run a multi-statement script via `simple_query` and return the
/// last row-returning result. No cursor pagination here — Postgres
/// implicit transactions don't compose cleanly with cursor declarations
/// inside user-supplied script bodies, and `prepare` rejects
/// multi-statement input. Result is capped at `page_size` rows; the
/// UI shows "more rows discarded" naturally because `cursor_id` is
/// `None` (no "Load more" affordance offered).
async fn run_multi_statement(
    client: &Client,
    sql: &str,
    page_size: usize,
) -> Result<ExecutionOutcome, PgError> {
    let stream = client.simple_query(sql).await.map_err(PgError::Driver)?;

    let mut current_columns: Vec<ColumnMeta> = vec![];
    let mut current_rows: Vec<Vec<Option<String>>> = vec![];
    let mut last_command_complete: Option<u64> = None;

    for msg in stream {
        match msg {
            SimpleQueryMessage::RowDescription(desc) => {
                // A new result block starts here. Discard any
                // previously-collected rows so we end up keeping
                // the LAST row-returning statement's output —
                // matches DataGrip-style behavior where the user
                // sees the result of `SET …; SELECT …`.
                //
                // OIDs aren't exposed via simple_query; type names
                // are blank. The grid falls back to default
                // alignment / formatting.
                current_columns = desc
                    .iter()
                    .map(|c| ColumnMeta {
                        name: c.name().to_string(),
                        type_oid: 0,
                        type_name: String::new(),
                    })
                    .collect();
                current_rows.clear();
            }
            SimpleQueryMessage::Row(row) => {
                if current_rows.len() >= page_size {
                    // Continue draining the stream so the connection
                    // doesn't end up with buffered server messages,
                    // but ignore the surplus rows.
                    continue;
                }
                let width = current_columns.len();
                let mut cells = Vec::with_capacity(width);
                for idx in 0..width {
                    cells.push(row.get(idx).map(str::to_string));
                }
                current_rows.push(cells);
            }
            SimpleQueryMessage::CommandComplete(n) => {
                last_command_complete = Some(n);
            }
            _ => {}
        }
    }

    Ok(ExecutionOutcome {
        columns: current_columns,
        rows: current_rows,
        rows_affected: last_command_complete,
        cursor_id: None,
    })
}

/// Open a new query. Closes any previously-active cursor (and its
/// transaction) before starting. Returns the first page synchronously
/// along with a cursor id when more rows remain.
///
/// `page_size` is the soft window for the first page. Non-row-returning
/// statements (DDL, INSERT without RETURNING) skip the cursor path
/// entirely — they run via `batch_execute` and report rows_affected.
/// Multi-statement scripts (`SET …; SELECT …` etc) run via
/// `simple_query`; the last row-returning statement's result is
/// surfaced and cursor pagination isn't offered.
pub async fn open_query(
    client: &Client,
    sql: &str,
    page_size: usize,
    previous: Option<ActiveCursor>,
) -> Result<(ExecutionOutcome, Option<ActiveCursor>), PgError> {
    // Best-effort cleanup of any existing cursor. If the previous
    // transaction is already in a bad state (rollback pending), this
    // may fail — we log and continue. The new BEGIN below will reset
    // session state by aborting the abandoned transaction.
    if let Some(prev) = previous.as_ref() {
        let cleanup = format!("CLOSE {}; COMMIT", prev.cursor_id);
        if let Err(e) = client.batch_execute(&cleanup).await {
            tracing::debug!(
                cursor = %prev.cursor_id,
                error = %e,
                "previous cursor cleanup failed; continuing with ROLLBACK"
            );
            // Force the session out of any half-open transaction state.
            let _ = client.batch_execute("ROLLBACK").await;
        }
    }

    // Multi-statement scripts can't be `prepare`d (the extended
    // protocol's Parse message rejects multi-command input).
    //
    // Common pattern: `SET statement_timeout = …; SELECT …` — the
    // user wants pagination on the SELECT, and the SET configures
    // the session for that single execution. Smart-split runs the
    // preamble via `batch_execute` (state persists on the wire),
    // then routes the main statement through the cursor path
    // exactly as a single-statement query would. If the split
    // doesn't produce a clean main statement we fall back to the
    // bulk path.
    if is_multi_statement(sql) {
        if let Some((preamble, main)) = split_at_last_statement(sql) {
            // Preamble runs first. If it errors we surface the error
            // — the user's `SET` failing matters and shouldn't be
            // silently swallowed by then running the SELECT.
            client
                .batch_execute(preamble)
                .await
                .map_err(PgError::Driver)?;
            // Recurse with the single-statement main. `previous` was
            // already cleaned up at the top of this function, so
            // pass `None` to avoid a redundant cleanup attempt.
            return Box::pin(open_query(client, main, page_size, None)).await;
        }
        let outcome = run_multi_statement(client, sql, page_size).await?;
        return Ok((outcome, None));
    }

    // Sniff whether the user statement is row-returning by trying a
    // cursor declaration. If it isn't, Postgres returns SQLSTATE
    // 42601 ("syntax error at or near 'INSERT'") or similar — but
    // more reliably, we check the prepared statement's columns.
    //
    // Easier: optimistically run as a cursor. If `DECLARE` fails with
    // `34000` (cursor on a query that returns no result set), or the
    // server replies `0A000` ("DECLARE CURSOR can only be used in
    // transaction blocks" — won't happen since we BEGIN first), fall
    // back to plain `batch_execute`.
    //
    // Prepared-statement introspection is the cleanest detector:
    let stmt = client.prepare(sql).await.map_err(PgError::Driver)?;
    let columns: Vec<ColumnMeta> = stmt
        .columns()
        .iter()
        .map(|c| ColumnMeta {
            name: c.name().to_string(),
            type_oid: c.type_().oid(),
            type_name: c.type_().name().to_string(),
        })
        .collect();

    if columns.is_empty() {
        // Non-row-returning. Run directly; no cursor needed.
        let stream = client.simple_query(sql).await.map_err(PgError::Driver)?;
        let rows_affected = stream.into_iter().find_map(|m| match m {
            SimpleQueryMessage::CommandComplete(n) => Some(n),
            _ => None,
        });
        return Ok((
            ExecutionOutcome {
                columns: vec![],
                rows: vec![],
                rows_affected,
                cursor_id: None,
            },
            None,
        ));
    }

    let cursor_id = format!("c_{}", Uuid::new_v4().simple());

    // Open the transaction and cursor in one round trip. The user's
    // SQL is interpolated verbatim — sanitization isn't ours to do
    // (this is a power-user surface where users type any SQL).
    let begin = format!("BEGIN; DECLARE {} NO SCROLL CURSOR FOR {}", cursor_id, sql);
    if let Err(e) = client.batch_execute(&begin).await {
        // Make sure we don't leak a half-open transaction.
        let _ = client.batch_execute("ROLLBACK").await;
        // Some row-returning statements cannot be wrapped in a cursor —
        // notably `INSERT/UPDATE/DELETE ... RETURNING`, which `prepare`
        // reports as having columns yet `DECLARE CURSOR FOR` rejects with
        // SQLSTATE 42601. The DECLARE fails at parse time, so the statement
        // itself never ran: re-run it directly via `simple_query` and
        // return its rows as a single, non-paginated page.
        if e.code() == Some(&tokio_postgres::error::SqlState::SYNTAX_ERROR) {
            let outcome = run_multi_statement(client, sql, page_size).await?;
            return Ok((outcome, None));
        }
        return Err(PgError::Driver(e));
    }

    // Fetch the first page.
    let fetch_sql = format!("FETCH FORWARD {} FROM {}", page_size, cursor_id);
    let stream = match client.simple_query(&fetch_sql).await {
        Ok(s) => s,
        Err(e) => {
            let _ = client.batch_execute("ROLLBACK").await;
            return Err(PgError::Driver(e));
        }
    };

    let (rows, fetched) = collect_rows(stream, columns.len());

    // CommandComplete reports how many rows the FETCH returned. If
    // it's strictly less than the requested page_size, we know the
    // cursor has exhausted; close immediately.
    if fetched < page_size {
        let _ = client
            .batch_execute(&format!("CLOSE {}; COMMIT", cursor_id))
            .await;
        return Ok((
            ExecutionOutcome {
                columns,
                rows,
                rows_affected: Some(fetched as u64),
                cursor_id: None,
            },
            None,
        ));
    }

    // Cursor remains open server-side. Caller will fetch_page or
    // close_query.
    let active = ActiveCursor {
        cursor_id: cursor_id.clone(),
        column_count: columns.len(),
    };
    Ok((
        ExecutionOutcome {
            columns,
            rows,
            rows_affected: Some(fetched as u64),
            cursor_id: Some(cursor_id),
        },
        Some(active),
    ))
}

/// Fetch the next page from an active cursor.
pub async fn fetch_page(
    client: &Client,
    cursor: &ActiveCursor,
    count: usize,
) -> Result<PageResult, PgError> {
    let sql = format!("FETCH FORWARD {} FROM {}", count, cursor.cursor_id);
    let stream = client.simple_query(&sql).await.map_err(PgError::Driver)?;
    let (rows, fetched) = collect_rows(stream, cursor.column_count);
    Ok(PageResult {
        rows,
        has_more: fetched == count,
    })
}

/// Close an active cursor and end its transaction. Best effort — if
/// the connection is already broken we don't surface an error to
/// callers, since "the result is gone" is the expected interpretation.
pub async fn close_query(client: &Client, cursor: &ActiveCursor) {
    let sql = format!("CLOSE {}; COMMIT", cursor.cursor_id);
    if let Err(e) = client.batch_execute(&sql).await {
        tracing::debug!(
            cursor = %cursor.cursor_id,
            error = %e,
            "cursor close failed; session likely already broken"
        );
        // Try to leave the session usable for the next query.
        let _ = client.batch_execute("ROLLBACK").await;
    }
}

/// Drain a `simple_query` stream into row vectors. Returns the rows
/// plus the count reported by the server's `CommandComplete` (which
/// is the canonical "did we get a full page?" signal).
fn collect_rows(
    stream: Vec<SimpleQueryMessage>,
    width: usize,
) -> (Vec<Vec<Option<String>>>, usize) {
    let mut rows: Vec<Vec<Option<String>>> = Vec::new();
    let mut fetched = 0usize;
    for msg in stream {
        match msg {
            SimpleQueryMessage::Row(row) => {
                let mut values: Vec<Option<String>> = Vec::with_capacity(width);
                for idx in 0..width {
                    values.push(row.get(idx).map(str::to_string));
                }
                rows.push(values);
            }
            SimpleQueryMessage::CommandComplete(n) => {
                fetched = n as usize;
            }
            _ => {}
        }
    }
    (rows, fetched)
}

#[cfg(test)]
mod tests {
    use super::*;
    use proptest::prelude::*;

    #[test]
    fn execution_outcome_round_trips() {
        let out = ExecutionOutcome {
            columns: vec![ColumnMeta {
                name: "id".to_string(),
                type_oid: 23, // int4
                type_name: "int4".to_string(),
            }],
            rows: vec![vec![Some("1".to_string())], vec![None]],
            rows_affected: Some(2),
            cursor_id: Some("c_abc".to_string()),
        };
        let json = serde_json::to_string(&out).expect("serialize");
        let back: ExecutionOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.columns.len(), 1);
        assert_eq!(back.columns[0].type_oid, 23);
        assert_eq!(back.columns[0].type_name, "int4");
        assert_eq!(back.rows.len(), 2);
        assert_eq!(back.cursor_id.as_deref(), Some("c_abc"));
    }

    #[test]
    fn page_result_round_trips() {
        let p = PageResult {
            rows: vec![vec![Some("x".into())]],
            has_more: false,
        };
        let json = serde_json::to_string(&p).expect("serialize");
        let back: PageResult = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.rows.len(), 1);
        assert!(!back.has_more);
    }

    #[test]
    fn multi_statement_detector_handles_common_cases() {
        // Single statement, no semicolons.
        assert!(!is_multi_statement("SELECT 1"));
        // Single statement with trailing semicolon.
        assert!(!is_multi_statement("SELECT 1;"));
        assert!(!is_multi_statement("SELECT 1;\n"));
        assert!(!is_multi_statement("SELECT 1;\n  \n"));
        // Multi-statement.
        assert!(is_multi_statement("SET x = 1; SELECT 1"));
        assert!(is_multi_statement("BEGIN; UPDATE t SET v=1; COMMIT;"));
    }

    #[test]
    fn multi_statement_detector_ignores_semicolons_in_strings() {
        // Single quote literals.
        assert!(!is_multi_statement("SELECT 'hello; world'"));
        assert!(!is_multi_statement("INSERT INTO t VALUES ('a;b;c')"));
        // Escaped single quote inside literal.
        assert!(!is_multi_statement("SELECT 'it''s; fine'"));
        // Real split despite earlier in-string semicolon.
        assert!(is_multi_statement("SELECT 'a;b'; SELECT 1"));
    }

    #[test]
    fn multi_statement_detector_ignores_semicolons_in_identifiers() {
        // Quoted identifier containing a semicolon — unusual but valid.
        assert!(!is_multi_statement("SELECT \"weird;name\" FROM t"));
        assert!(is_multi_statement("SELECT \"col\"; SELECT 1"));
    }

    #[test]
    fn multi_statement_detector_ignores_semicolons_in_comments() {
        // Line comments.
        assert!(!is_multi_statement("SELECT 1 -- ; comment\n"));
        // Block comments.
        assert!(!is_multi_statement("SELECT 1 /* ; */ FROM t"));
        assert!(!is_multi_statement("/* ; */ SELECT 1"));
        assert!(!is_multi_statement("SELECT 1; -- trailing comment\n"));
        // Real split despite earlier in-comment semicolon.
        assert!(is_multi_statement("SELECT 1 -- ;\n; SELECT 2"));
    }

    #[test]
    fn multi_statement_detector_ignores_semicolons_in_dollar_quotes() {
        assert!(!is_multi_statement("SELECT $$hello; world$$"));
        assert!(!is_multi_statement("SELECT $tag$hello; world$tag$"));
        assert!(is_multi_statement("SELECT $$hello; world$$; SELECT 1"));
    }

    #[test]
    fn smart_split_returns_preamble_and_main() {
        let (pre, main) = split_at_last_statement("SET x = 1; SELECT * FROM t").expect("split");
        assert_eq!(pre, "SET x = 1;");
        assert_eq!(main, "SELECT * FROM t");
    }

    #[test]
    fn smart_split_handles_multiple_preamble_statements() {
        let (pre, main) = split_at_last_statement("SET x = 1; SET y = 2; SELECT 1").expect("split");
        assert_eq!(pre, "SET x = 1; SET y = 2;");
        assert_eq!(main, "SELECT 1");
    }

    #[test]
    fn smart_split_returns_none_when_no_main_statement_after_delimiter() {
        // Trailing semicolon with nothing real after — there's no
        // separable "main"; caller falls back to bulk multi-statement.
        assert!(split_at_last_statement("SET x = 1; SELECT 1;").is_none());
        assert!(split_at_last_statement("SET x = 1;").is_none());
        // Comment-only tail.
        assert!(split_at_last_statement("SET x = 1; -- trailing\n").is_none());
    }

    #[test]
    fn smart_split_ignores_in_string_semicolons() {
        let (pre, main) = split_at_last_statement("SET x = 'a;b'; SELECT 1").expect("split");
        assert_eq!(pre, "SET x = 'a;b';");
        assert_eq!(main, "SELECT 1");
    }

    #[test]
    fn smart_split_ignores_dollar_quoted_semicolons() {
        let (pre, main) =
            split_at_last_statement("SELECT $body$a;b$body$; SELECT 1").expect("split");
        assert_eq!(pre, "SELECT $body$a;b$body$;");
        assert_eq!(main, "SELECT 1");

        let function = "CREATE FUNCTION f() RETURNS int AS $$ BEGIN; RETURN 1; END; $$ LANGUAGE plpgsql; SELECT f()";
        let (pre, main) = split_at_last_statement(function).expect("split");
        assert_eq!(
            pre,
            "CREATE FUNCTION f() RETURNS int AS $$ BEGIN; RETURN 1; END; $$ LANGUAGE plpgsql;"
        );
        assert_eq!(main, "SELECT f()");
    }

    #[test]
    fn smart_split_returns_none_for_single_statement() {
        assert!(split_at_last_statement("SELECT 1").is_none());
        assert!(split_at_last_statement("SELECT 1;").is_none());
    }

    proptest! {
        #[test]
        fn dollar_quoted_semicolons_do_not_create_false_splits(body in "[A-Za-z0-9_ ;,()\\n]{0,128}") {
            let sql = format!("SELECT $$ {body} $$");
            prop_assert!(!is_multi_statement(&sql));
            prop_assert!(split_at_last_statement(&sql).is_none());
        }

        #[test]
        fn trailing_comment_after_semicolon_is_still_single_statement(comment in "[A-Za-z0-9_ ;,()]{0,128}") {
            let sql = format!("SELECT 1; -- {comment}");
            prop_assert!(!is_multi_statement(&sql));
            prop_assert!(split_at_last_statement(&sql).is_none());
        }
    }
}
