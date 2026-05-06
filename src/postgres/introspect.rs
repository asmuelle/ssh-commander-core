//! Schema introspection queries against `pg_catalog`.
//!
//! `information_schema` is portable but slow on large databases (the views
//! join across many tables and filter by privilege). `pg_catalog` is direct,
//! orders of magnitude faster, and exposes the metadata Postgres tooling
//! actually needs (relkind, oids, persistence). All queries are
//! parameter-less SELECTs to keep the surface boring and review-able.

use serde::{Deserialize, Serialize};
use tokio_postgres::{Client, Error as PgDriverError};

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct DbSummary {
    pub name: String,
    /// True for `template0` / `template1`. Filtered out by `list_databases`
    /// but the field is preserved so callers can show templates if desired.
    pub is_template: bool,
    pub owner: String,
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaSummary {
    pub name: String,
    pub owner: String,
    /// True for `pg_catalog`, `information_schema`, `pg_toast`, etc.
    pub is_system: bool,
}

/// Discriminator for tables / views / matviews / partitioned tables /
/// foreign tables. Matches `pg_class.relkind` values that an explorer cares
/// about. Sequences, indexes, composite types, and TOAST relations are
/// excluded from `list_relations` and so do not appear here.
#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RelationKind {
    Table,
    View,
    MaterializedView,
    PartitionedTable,
    ForeignTable,
}

impl RelationKind {
    fn from_relkind(c: i8) -> Option<Self> {
        match c as u8 as char {
            'r' => Some(Self::Table),
            'v' => Some(Self::View),
            'm' => Some(Self::MaterializedView),
            'p' => Some(Self::PartitionedTable),
            'f' => Some(Self::ForeignTable),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Relation {
    pub schema: String,
    pub name: String,
    pub kind: RelationKind,
    pub owner: String,
    /// Estimated row count from `pg_class.reltuples`. `-1` if statistics
    /// have never been gathered (fresh table).
    pub estimated_rows: f32,
}

pub async fn list_databases(client: &Client) -> Result<Vec<DbSummary>, PgDriverError> {
    // Excludes templates so the default tree is ergonomic. UI can issue a
    // separate "show system" query if needed.
    let rows = client
        .query(
            "SELECT d.datname,
                    d.datistemplate,
                    pg_catalog.pg_get_userbyid(d.datdba) AS owner
               FROM pg_catalog.pg_database d
              WHERE NOT d.datistemplate
              ORDER BY d.datname",
            &[],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| DbSummary {
            name: r.get(0),
            is_template: r.get(1),
            owner: r.get(2),
        })
        .collect())
}

pub async fn list_schemas(client: &Client) -> Result<Vec<SchemaSummary>, PgDriverError> {
    // We include system schemas but tag them so the UI can collapse them
    // under a "System" group instead of polluting the top level.
    let rows = client
        .query(
            "SELECT n.nspname,
                    pg_catalog.pg_get_userbyid(n.nspowner) AS owner,
                    (n.nspname IN ('pg_catalog', 'information_schema', 'pg_toast')
                     OR n.nspname LIKE 'pg_temp_%'
                     OR n.nspname LIKE 'pg_toast_temp_%') AS is_system
               FROM pg_catalog.pg_namespace n
              ORDER BY is_system, n.nspname",
            &[],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| SchemaSummary {
            name: r.get(0),
            owner: r.get(1),
            is_system: r.get(2),
        })
        .collect())
}

pub async fn list_relations(client: &Client, schema: &str) -> Result<Vec<Relation>, PgDriverError> {
    // Bind the schema name so we can't be tricked into cross-schema scans
    // by a malicious profile. The relkind filter list is fixed (matches
    // `RelationKind` variants) and inlined as a SQL literal — binding
    // a `Vec<i8>` and casting via `$2::char[]` doesn't round-trip
    // because unquoted `char` in SQL is `bpchar`, not the internal
    // single-byte `"char"` type that `pg_class.relkind` uses.
    let rows = client
        .query(
            "SELECT n.nspname,
                    c.relname,
                    c.relkind,
                    pg_catalog.pg_get_userbyid(c.relowner) AS owner,
                    c.reltuples
               FROM pg_catalog.pg_class c
               JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = $1
                AND c.relkind = ANY(ARRAY['r','v','m','p','f']::\"char\"[])
              ORDER BY c.relname",
            &[&schema],
        )
        .await?;

    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let relkind: i8 = r.get(2);
            RelationKind::from_relkind(relkind).map(|kind| Relation {
                schema: r.get(0),
                name: r.get(1),
                kind,
                owner: r.get(3),
                estimated_rows: r.get(4),
            })
        })
        .collect())
}

// =============================================================================
// Sequences / Routines / Object Types
//
// These mirror DataGrip's schema-tree categories. Each kind lives in
// its own pg_catalog table:
//   - Sequences        → pg_class WHERE relkind='S'
//   - Routines         → pg_proc (functions, procedures, aggregates,
//                                 window functions)
//   - Object types     → pg_type (composite, enum, domain, range)
//
// `list_schema_contents` runs all of these (plus the relation-kind
// queries) concurrently for the same schema and returns the unified
// SchemaContents — the schema browser's primary expand-a-schema call.
// =============================================================================

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Sequence {
    pub schema: String,
    pub name: String,
    pub owner: String,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum RoutineKind {
    /// Regular SQL/PL function — `pg_proc.prokind = 'f'`.
    Function,
    /// Stored procedure — `prokind = 'p'`. Distinct from functions
    /// in that they can manage transactions.
    Procedure,
    /// Aggregate function — `prokind = 'a'` (sum, avg, etc).
    Aggregate,
    /// Window function — `prokind = 'w'`.
    Window,
}

impl RoutineKind {
    fn from_prokind(c: i8) -> Option<Self> {
        match c as u8 as char {
            'f' => Some(Self::Function),
            'p' => Some(Self::Procedure),
            'a' => Some(Self::Aggregate),
            'w' => Some(Self::Window),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct Routine {
    pub schema: String,
    pub name: String,
    pub kind: RoutineKind,
    pub owner: String,
    /// Pretty-printed argument list `(integer, text)`. Built
    /// server-side via `pg_get_function_identity_arguments` so
    /// composite + array + qualified types render correctly.
    pub argument_signature: String,
    /// Return type name, when applicable. `None` for procedures
    /// (they don't return a single value) and aggregates that
    /// return record-shaped output.
    pub return_type: Option<String>,
}

#[derive(Debug, Clone, Copy, Serialize, Deserialize, PartialEq, Eq)]
pub enum ObjectTypeKind {
    /// Row-shaped composite type — `pg_type.typtype = 'c'`.
    Composite,
    /// Enum — `typtype = 'e'`.
    Enum,
    /// Domain (constrained alias of a base type) — `typtype = 'd'`.
    Domain,
    /// Range type — `typtype = 'r'` (or `'m'` for multirange in 14+).
    Range,
}

impl ObjectTypeKind {
    fn from_typtype(c: i8) -> Option<Self> {
        match c as u8 as char {
            'c' => Some(Self::Composite),
            'e' => Some(Self::Enum),
            'd' => Some(Self::Domain),
            'r' | 'm' => Some(Self::Range),
            _ => None,
        }
    }
}

#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ObjectType {
    pub schema: String,
    pub name: String,
    pub kind: ObjectTypeKind,
    pub owner: String,
}

/// Unified schema-contents view used by the tree's "expand a schema"
/// path. Six-way grouping mirrors DataGrip's tree. Tables include
/// regular, partitioned, and foreign tables (all "data-bearing
/// relations"); views and materialized views split out for clarity.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct SchemaContents {
    pub tables: Vec<Relation>,
    pub views: Vec<Relation>,
    pub materialized_views: Vec<Relation>,
    pub sequences: Vec<Sequence>,
    pub routines: Vec<Routine>,
    pub object_types: Vec<ObjectType>,
}

pub async fn list_sequences(
    client: &Client,
    schema: &str,
) -> Result<Vec<Sequence>, PgDriverError> {
    let rows = client
        .query(
            "SELECT n.nspname,
                    c.relname,
                    pg_catalog.pg_get_userbyid(c.relowner) AS owner
               FROM pg_catalog.pg_class c
               JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
              WHERE n.nspname = $1
                AND c.relkind = 'S'
              ORDER BY c.relname",
            &[&schema],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| Sequence {
            schema: r.get(0),
            name: r.get(1),
            owner: r.get(2),
        })
        .collect())
}

pub async fn list_routines(
    client: &Client,
    schema: &str,
) -> Result<Vec<Routine>, PgDriverError> {
    // pg_get_function_identity_arguments gives the parameter list
    // suitable for unique identification (no DEFAULTs / OUT params
    // confused with IN). pg_get_function_result is the return type;
    // it's NULL for procedures.
    let rows = client
        .query(
            "SELECT n.nspname,
                    p.proname,
                    p.prokind,
                    pg_catalog.pg_get_userbyid(p.proowner) AS owner,
                    pg_catalog.pg_get_function_identity_arguments(p.oid) AS arg_sig,
                    pg_catalog.pg_get_function_result(p.oid) AS ret_type
               FROM pg_catalog.pg_proc p
               JOIN pg_catalog.pg_namespace n ON n.oid = p.pronamespace
              WHERE n.nspname = $1
              ORDER BY p.proname, arg_sig",
            &[&schema],
        )
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let prokind: i8 = r.get(2);
            RoutineKind::from_prokind(prokind).map(|kind| Routine {
                schema: r.get(0),
                name: r.get(1),
                kind,
                owner: r.get(3),
                argument_signature: r.get::<_, Option<String>>(4).unwrap_or_default(),
                return_type: r.get::<_, Option<String>>(5),
            })
        })
        .collect())
}

pub async fn list_object_types(
    client: &Client,
    schema: &str,
) -> Result<Vec<ObjectType>, PgDriverError> {
    // Excludes system-generated row types (typtype='c' but typrelid
    // pointing at an existing relation — those are auto-created for
    // every table and would clutter the tree). The
    // `typrelid = 0 OR relkind = 'c'` filter keeps standalone
    // composite types and excludes table row types.
    let rows = client
        .query(
            "SELECT n.nspname,
                    t.typname,
                    t.typtype,
                    pg_catalog.pg_get_userbyid(t.typowner) AS owner
               FROM pg_catalog.pg_type t
               JOIN pg_catalog.pg_namespace n ON n.oid = t.typnamespace
          LEFT JOIN pg_catalog.pg_class c ON c.oid = t.typrelid
              WHERE n.nspname = $1
                AND t.typtype IN ('c', 'e', 'd', 'r', 'm')
                AND (t.typrelid = 0 OR c.relkind = 'c')
                AND NOT EXISTS (
                    -- Exclude array element type variants — pg
                    -- generates `_int4`, `_text`, etc. for every
                    -- type. They show up as composite-of-the-base
                    -- which is not user-meaningful in this view.
                    SELECT 1 FROM pg_catalog.pg_type elem
                     WHERE elem.typarray = t.oid
                )
              ORDER BY t.typname",
            &[&schema],
        )
        .await?;
    Ok(rows
        .into_iter()
        .filter_map(|r| {
            let typtype: i8 = r.get(2);
            ObjectTypeKind::from_typtype(typtype).map(|kind| ObjectType {
                schema: r.get(0),
                name: r.get(1),
                kind,
                owner: r.get(3),
            })
        })
        .collect())
}

/// Concurrent fetch of all schema contents in one logical call.
/// `tokio_postgres::Client` pipelines so the four queries overlap on
/// the wire — total latency is roughly max(query_latency) rather
/// than 4× a single query.
pub async fn list_schema_contents(
    client: &Client,
    schema: &str,
) -> Result<SchemaContents, PgDriverError> {
    let (relations, sequences, routines, object_types) = tokio::try_join!(
        list_relations(client, schema),
        list_sequences(client, schema),
        list_routines(client, schema),
        list_object_types(client, schema),
    )?;

    // Categorize relations. Tables, partitioned tables, and foreign
    // tables all live under the "Tables" header — they're all
    // data-bearing relations the user can SELECT from.
    let mut tables = Vec::new();
    let mut views = Vec::new();
    let mut materialized_views = Vec::new();
    for r in relations {
        match r.kind {
            RelationKind::Table | RelationKind::PartitionedTable | RelationKind::ForeignTable => {
                tables.push(r);
            }
            RelationKind::View => views.push(r),
            RelationKind::MaterializedView => materialized_views.push(r),
        }
    }
    Ok(SchemaContents {
        tables,
        views,
        materialized_views,
        sequences,
        routines,
        object_types,
    })
}

/// Per-column metadata used by the INSERT form to pre-set Use
/// DEFAULT and NULL toggles. Read from `pg_attribute` joined
/// with `pg_attrdef` for the default-presence flag.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct ColumnDetail {
    pub name: String,
    /// `pg_type.typname` — feeds the INSERT form's per-column
    /// `::type` cast.
    pub type_name: String,
    /// `attnotnull`. When true, the INSERT form refuses NULL.
    pub not_null: bool,
    /// `pg_attrdef` row exists for this column. When true, the
    /// form defaults to "Use DEFAULT" so the user only fills in
    /// what they want to override.
    pub has_default: bool,
    /// `attgenerated <> ''` — generated columns can't be set on
    /// INSERT. The form omits these entirely.
    pub is_generated: bool,
}

pub async fn describe_columns(
    client: &Client,
    schema: &str,
    table: &str,
) -> Result<Vec<ColumnDetail>, PgDriverError> {
    // attnum > 0 filters out the system columns (oid, ctid, etc).
    // attisdropped filters out logically-deleted columns whose
    // entries linger for tuple-format compatibility.
    let rows = client
        .query(
            "SELECT a.attname,
                    pg_catalog.format_type(a.atttypid, NULL) AS type_name,
                    a.attnotnull,
                    (d.adbin IS NOT NULL) AS has_default,
                    (a.attgenerated <> '') AS is_generated
               FROM pg_catalog.pg_attribute a
               JOIN pg_catalog.pg_class c ON c.oid = a.attrelid
               JOIN pg_catalog.pg_namespace n ON n.oid = c.relnamespace
          LEFT JOIN pg_catalog.pg_attrdef d
                 ON d.adrelid = a.attrelid AND d.adnum = a.attnum
              WHERE n.nspname = $1
                AND c.relname = $2
                AND a.attnum > 0
                AND NOT a.attisdropped
              ORDER BY a.attnum",
            &[&schema, &table],
        )
        .await?;
    Ok(rows
        .into_iter()
        .map(|r| ColumnDetail {
            name: r.get(0),
            type_name: r.get(1),
            not_null: r.get(2),
            has_default: r.get(3),
            is_generated: r.get(4),
        })
        .collect())
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn relation_kind_decodes_known_relkinds() {
        assert_eq!(
            RelationKind::from_relkind(b'r' as i8),
            Some(RelationKind::Table)
        );
        assert_eq!(
            RelationKind::from_relkind(b'v' as i8),
            Some(RelationKind::View)
        );
        assert_eq!(
            RelationKind::from_relkind(b'm' as i8),
            Some(RelationKind::MaterializedView)
        );
        assert_eq!(
            RelationKind::from_relkind(b'p' as i8),
            Some(RelationKind::PartitionedTable)
        );
        assert_eq!(
            RelationKind::from_relkind(b'f' as i8),
            Some(RelationKind::ForeignTable)
        );
    }

    #[test]
    fn relation_kind_rejects_unknown() {
        // 'i' = index, 'S' = sequence, 't' = TOAST, 'c' = composite type
        assert_eq!(RelationKind::from_relkind(b'i' as i8), None);
        assert_eq!(RelationKind::from_relkind(b'S' as i8), None);
        assert_eq!(RelationKind::from_relkind(b't' as i8), None);
        assert_eq!(RelationKind::from_relkind(b'c' as i8), None);
    }

    #[test]
    fn routine_kind_decodes_known_prokinds() {
        assert_eq!(RoutineKind::from_prokind(b'f' as i8), Some(RoutineKind::Function));
        assert_eq!(RoutineKind::from_prokind(b'p' as i8), Some(RoutineKind::Procedure));
        assert_eq!(RoutineKind::from_prokind(b'a' as i8), Some(RoutineKind::Aggregate));
        assert_eq!(RoutineKind::from_prokind(b'w' as i8), Some(RoutineKind::Window));
        assert_eq!(RoutineKind::from_prokind(b'?' as i8), None);
    }

    #[test]
    fn object_type_kind_decodes_known_typtypes() {
        assert_eq!(ObjectTypeKind::from_typtype(b'c' as i8), Some(ObjectTypeKind::Composite));
        assert_eq!(ObjectTypeKind::from_typtype(b'e' as i8), Some(ObjectTypeKind::Enum));
        assert_eq!(ObjectTypeKind::from_typtype(b'd' as i8), Some(ObjectTypeKind::Domain));
        assert_eq!(ObjectTypeKind::from_typtype(b'r' as i8), Some(ObjectTypeKind::Range));
        // multirange (PG 14+) groups with Range for tree purposes
        assert_eq!(ObjectTypeKind::from_typtype(b'm' as i8), Some(ObjectTypeKind::Range));
        // 'b' = base type (skip — not user-defined in the
        // tree-browsing sense).
        assert_eq!(ObjectTypeKind::from_typtype(b'b' as i8), None);
    }
}
