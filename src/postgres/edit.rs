//! Cell-level row editing for the explorer.
//!
//! Sprint 14 model: editing is enabled only on tabs opened from the
//! schema browser ("double-click a relation"), where the explorer
//! knows the (schema, table) and the auto-generated SELECT carries
//! `ctid AS __pg_rowid__`. The UI extracts that hidden column to use
//! as the row identifier for UPDATEs.
//!
//! ## Why ctid
//!
//! `ctid` is Postgres's internal per-row identifier on heap tables.
//! It is:
//!
//! - Always unique within a relation (so the WHERE matches at most
//!   one row).
//! - Always present (no PK assumption needed).
//! - Mutated on every UPDATE — which gives us *free* optimistic
//!   locking. If two clients race to edit the same row, the second
//!   UPDATE matches zero rows and we surface "row no longer there"
//!   instead of clobbering.
//!
//! Limitation: views, materialized views, and foreign tables don't
//! have a meaningful ctid. We don't try to edit them; the UI gates
//! editing on the relation kind already.
//!
//! ## Type binding
//!
//! Values cross the FFI as `String`. We bind `$1` as text and cast
//! it to the column's declared type server-side: `SET "col" = $1::int4`.
//! Postgres's text-input parser handles the heavy lifting (timestamps,
//! arrays, ranges, JSON). Setting NULL skips the parameter entirely
//! since `''::int4` would fail.
//!
//! Identifiers are quoted defensively (PG allows mixed-case and
//! reserved-word identifiers; an unquoted `Order` would target a
//! lowercase `order`). Type names from `pg_type.typname` are also
//! quoted to be safe — most don't need it but the cost is zero.

use serde::{Deserialize, Serialize};
use tokio_postgres::Client;

use crate::postgres::PgError;

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct UpdateOutcome {
    /// Number of rows the UPDATE matched. `1` for the happy path,
    /// `0` if the ctid is gone (row was deleted or modified by
    /// another session) — UI surfaces that as a refresh prompt.
    pub rows_affected: u64,
}

/// Issue a single-cell UPDATE. `new_value: None` means SET NULL.
/// `column_type` is the column's `pg_type.typname` (e.g. `int4`,
/// `timestamptz`); used for the server-side text→typed cast.
pub async fn update_cell(
    client: &Client,
    schema: &str,
    table: &str,
    column: &str,
    column_type: &str,
    new_value: Option<&str>,
    ctid: &str,
) -> Result<UpdateOutcome, PgError> {
    let qualified = format!("{}.{}", quote_ident(schema), quote_ident(table));
    let col = quote_ident(column);

    // ctid is bound as text and cast server-side. The standard text
    // form `(0,1)` is what Postgres returns from `SELECT ctid`, so
    // round-tripping through the UI as a String just works.
    let rows_affected = match new_value {
        Some(value) => {
            let sql = format!(
                "UPDATE {qualified} SET {col} = $1::{ty} WHERE ctid = $2::tid",
                qualified = qualified,
                col = col,
                ty = quote_ident(column_type),
            );
            client
                .execute(&sql, &[&value, &ctid])
                .await
                .map_err(PgError::Driver)?
        }
        None => {
            let sql = format!(
                "UPDATE {qualified} SET {col} = NULL WHERE ctid = $1::tid",
                qualified = qualified,
                col = col,
            );
            client
                .execute(&sql, &[&ctid])
                .await
                .map_err(PgError::Driver)?
        }
    };

    Ok(UpdateOutcome { rows_affected })
}

/// One column's worth of input for an INSERT. Caller emits a list
/// of these for the columns it wants to set explicitly; columns not
/// in the list are left to the server's `DEFAULT` (which honors
/// `pg_attrdef`-defined defaults, sequences, generated values, etc).
#[derive(Debug, Clone)]
pub struct InsertColumnInput {
    pub name: String,
    /// `pg_type.typname` for the server-side text→typed cast.
    pub type_name: String,
    /// `None` writes SQL NULL; `Some(text)` is bound and cast.
    pub value: Option<String>,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct InsertedRow {
    /// Cells in the order specified by the caller's `return_columns`.
    /// Mirrors the FFI execution-result row shape so the UI can
    /// append directly to its in-memory rows array.
    pub cells: Vec<Option<String>>,
}

/// Insert one row, returning the requested columns for the new row.
///
/// `return_columns` controls the `RETURNING` clause and the order
/// of cells in the result. The UI typically passes the same column
/// names + `__pg_rowid__` (which becomes `ctid` server-side) the
/// existing result already shows, so the new row slots straight
/// into the in-memory grid.
pub async fn insert_row(
    client: &Client,
    schema: &str,
    table: &str,
    inputs: &[InsertColumnInput],
    return_columns: &[String],
) -> Result<InsertedRow, PgError> {
    let qualified = format!("{}.{}", quote_ident(schema), quote_ident(table));

    // Empty inputs → INSERT … DEFAULT VALUES. Works iff every
    // column either has a default or accepts NULL; otherwise the
    // server complains and we surface that error.
    let column_clause: String;
    let values_clause: String;
    if inputs.is_empty() {
        column_clause = String::new();
        values_clause = "DEFAULT VALUES".to_string();
    } else {
        let cols = inputs
            .iter()
            .map(|i| quote_ident(&i.name))
            .collect::<Vec<_>>()
            .join(", ");
        column_clause = format!(" ({cols})");
        let placeholders = inputs
            .iter()
            .enumerate()
            .map(|(idx, i)| format!("${}::{}", idx + 1, quote_ident(&i.type_name)))
            .collect::<Vec<_>>()
            .join(", ");
        values_clause = format!("VALUES ({placeholders})");
    }

    // Cast every RETURNING column to text so we can read the row as
    // `Option<String>` regardless of underlying type. Postgres's
    // text output format covers every type the server can render,
    // mirroring the read path the rest of the explorer uses.
    let returning = if return_columns.is_empty() {
        // Caller didn't ask for anything back — return ctid alone
        // so the UI at least gets a row identity to work with.
        "ctid::text AS \"__pg_rowid__\"".to_string()
    } else {
        return_columns
            .iter()
            .map(|name| {
                let alias = quote_ident(name);
                if name == "__pg_rowid__" {
                    format!("ctid::text AS {alias}")
                } else {
                    format!("{}::text AS {alias}", quote_ident(name))
                }
            })
            .collect::<Vec<_>>()
            .join(", ")
    };

    let sql = format!(
        "INSERT INTO {qualified}{column_clause} {values_clause} RETURNING {returning}",
        qualified = qualified,
        column_clause = column_clause,
        values_clause = values_clause,
        returning = returning,
    );

    // Parameter list: each input contributes one `Option<&str>`.
    // tokio_postgres' `Option<&str>` impl serializes to NULL when
    // `None`, so we don't branch SQL for nulls.
    let params: Vec<&(dyn tokio_postgres::types::ToSql + Sync)> = inputs
        .iter()
        .map(|i| &i.value as &(dyn tokio_postgres::types::ToSql + Sync))
        .collect();

    // `simple_query` doesn't take params, so we use the extended
    // protocol via `query`. The RETURNING shape is fixed so we can
    // pull each value as a `&str` (text-coerced via `pg_get_typeof`
    // wouldn't be needed — `query` returns binary by default but
    // we get text for unknown types).
    //
    // Actually using `simple_query` would force a text protocol which
    // gives us uniform `Option<&str>` extraction. The downside is
    // we lose typed parameter binding. The compromise: use `query`
    // with the bound params, then for each column read a
    // `Option<String>` via the postgres-types Text feature. Since
    // we only RETURNING-cast one row, the cost is negligible.
    let rows = client
        .query(&sql, &params)
        .await
        .map_err(PgError::Driver)?;
    let row = rows.into_iter().next().ok_or_else(|| {
        // RETURNING on a successful single-row INSERT must produce
        // exactly one row. Anything else is a server-side surprise
        // we surface rather than panic on.
        PgError::Connect("INSERT returned no row".to_string())
    })?;

    // Every RETURNING column was cast to text in the SQL above, so
    // each column reads cleanly as `Option<String>`.
    let mut cells: Vec<Option<String>> = Vec::with_capacity(row.len());
    for idx in 0..row.len() {
        let v: Option<String> = row.try_get(idx).map_err(PgError::Driver)?;
        cells.push(v);
    }

    Ok(InsertedRow { cells })
}

/// Delete one or more rows identified by their ctids. Returns the
/// number of rows actually deleted (callers compare against the
/// requested count to surface "some rows were already gone" — the
/// same optimistic-locking semantic as cell UPDATEs).
///
/// One round trip via `DELETE … WHERE ctid = ANY($1)`. ctids are
/// passed as a `text[]` and cast to `tid[]` server-side, since
/// `tokio_postgres` doesn't have a native `tid[]` ToSql impl.
pub async fn delete_rows(
    client: &Client,
    schema: &str,
    table: &str,
    ctids: &[String],
) -> Result<UpdateOutcome, PgError> {
    if ctids.is_empty() {
        return Ok(UpdateOutcome { rows_affected: 0 });
    }
    let qualified = format!("{}.{}", quote_ident(schema), quote_ident(table));
    let sql = format!(
        "DELETE FROM {qualified} WHERE ctid = ANY($1::text[]::tid[])",
        qualified = qualified,
    );
    let rows_affected = client
        .execute(&sql, &[&ctids])
        .await
        .map_err(PgError::Driver)?;
    Ok(UpdateOutcome { rows_affected })
}

/// Postgres double-quote escaping. Embedded `"` becomes `""`; the
/// whole identifier is wrapped in double quotes. Defensive against
/// names with spaces, mixed case, or reserved words.
fn quote_ident(s: &str) -> String {
    format!("\"{}\"", s.replace('"', "\"\""))
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn quote_ident_handles_simple_and_quoted_names() {
        assert_eq!(quote_ident("users"), "\"users\"");
        assert_eq!(quote_ident("MyTable"), "\"MyTable\"");
        assert_eq!(quote_ident("with\"quote"), "\"with\"\"quote\"");
        // Reserved words quote without special handling — the wrap
        // makes them safe.
        assert_eq!(quote_ident("order"), "\"order\"");
        // Empty and whitespace get quoted as-is; the server will
        // reject empty identifiers but that's fine — we don't
        // pre-validate.
        assert_eq!(quote_ident(""), "\"\"");
    }

    #[test]
    fn update_outcome_round_trips() {
        let o = UpdateOutcome { rows_affected: 1 };
        let json = serde_json::to_string(&o).expect("serialize");
        let back: UpdateOutcome = serde_json::from_str(&json).expect("deserialize");
        assert_eq!(back.rows_affected, 1);
    }
}
