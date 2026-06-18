use std::env;
use std::time::Duration;

use ssh_commander_pg::{InsertColumnInput, PgAuthMethod, PgConfig, PgPool, PgTlsMode};
use uuid::Uuid;

fn pg_config() -> Option<PgConfig> {
    let host = env::var("PG_TEST_HOST").ok()?;
    let port = env::var("PG_TEST_PORT")
        .ok()
        .and_then(|p| p.parse().ok())
        .unwrap_or(5432);
    let database = env::var("PG_TEST_DB").unwrap_or_else(|_| "postgres".to_string());
    let user = env::var("PG_TEST_USER").unwrap_or_else(|_| "postgres".to_string());
    let password = env::var("PG_TEST_PASSWORD").unwrap_or_else(|_| "postgres".to_string());
    Some(PgConfig {
        host,
        port,
        database,
        user,
        auth: PgAuthMethod::Password { password },
        tls: PgTlsMode::Disable,
        application_name: Some("ssh-commander-core-tests".to_string()),
        connect_timeout_secs: Some(5),
        max_pool_size: Some(3),
        idle_timeout_secs: Some(1),
        min_idle_connections: Some(0),
    })
}

async fn pool() -> Option<std::sync::Arc<PgPool>> {
    let Some(cfg) = pg_config() else {
        eprintln!("SKIP: PG_TEST_HOST not set");
        return None;
    };
    Some(PgPool::connect(cfg).await.expect("connect postgres"))
}

#[tokio::test]
async fn pg_sleep_can_be_cancelled_promptly() {
    let Some(pool) = pool().await else {
        return;
    };

    let worker_pool = pool.clone();
    let started = std::time::Instant::now();
    let task = tokio::spawn(async move {
        worker_pool
            .execute("cancel-session", "SELECT pg_sleep(10)", 10)
            .await
    });

    tokio::time::sleep(Duration::from_millis(200)).await;
    pool.cancel("cancel-session").await.expect("send cancel");
    let result = tokio::time::timeout(Duration::from_secs(5), task)
        .await
        .expect("query should return after cancel")
        .expect("task join");

    assert!(result.is_err(), "cancelled query should fail");
    assert!(
        started.elapsed() < Duration::from_secs(5),
        "cancel waited for the original pg_sleep duration"
    );
    pool.shutdown().await;
}

#[tokio::test]
async fn cursor_pagination_is_isolated_by_session() {
    let Some(pool) = pool().await else {
        return;
    };

    let first = pool
        .execute("tab-a", "SELECT generate_series(1, 5) AS n", 2)
        .await
        .expect("execute tab a");
    let second = pool
        .execute("tab-b", "SELECT generate_series(10, 14) AS n", 2)
        .await
        .expect("execute tab b");

    let first_cursor = first.cursor_id.expect("tab a cursor");
    let second_cursor = second.cursor_id.expect("tab b cursor");
    assert_eq!(first.rows.len(), 2);
    assert_eq!(second.rows.len(), 2);

    let first_page = pool
        .fetch_page("tab-a", &first_cursor, 2)
        .await
        .expect("fetch tab a");
    let second_page = pool
        .fetch_page("tab-b", &second_cursor, 2)
        .await
        .expect("fetch tab b");

    assert_eq!(first_page.rows[0][0].as_deref(), Some("3"));
    assert_eq!(second_page.rows[0][0].as_deref(), Some("12"));
    pool.shutdown().await;
}

#[tokio::test]
async fn typed_insert_update_and_delete_round_trip() {
    let Some(pool) = pool().await else {
        return;
    };

    let table = format!("qa_edit_{}", Uuid::new_v4().simple());
    let setup_sql = format!(
        "CREATE TABLE public.{table} (
            id integer PRIMARY KEY,
            name character varying(12),
            amount numeric(10,2),
            seen_at timestamp with time zone,
            payload jsonb,
            tags text[]
        )"
    );
    pool.execute("edit-setup", &setup_sql, 10)
        .await
        .expect("create test table");
    pool.release_session("edit-setup").await;

    let columns = pool
        .describe_columns("public", &table)
        .await
        .expect("describe columns");
    let type_of = |name: &str| {
        columns
            .iter()
            .find(|c| c.name == name)
            .unwrap_or_else(|| panic!("missing column {name}"))
            .type_name
            .clone()
    };
    let inserted = pool
        .insert_row(
            "edit",
            "public",
            &table,
            &[
                InsertColumnInput {
                    name: "id".to_string(),
                    type_name: type_of("id"),
                    value: Some("1".to_string()),
                },
                InsertColumnInput {
                    name: "name".to_string(),
                    type_name: type_of("name"),
                    value: Some("alice".to_string()),
                },
                InsertColumnInput {
                    name: "amount".to_string(),
                    type_name: type_of("amount"),
                    value: Some("12.34".to_string()),
                },
                InsertColumnInput {
                    name: "seen_at".to_string(),
                    type_name: type_of("seen_at"),
                    value: Some("2024-01-02 03:04:05+00".to_string()),
                },
                InsertColumnInput {
                    name: "payload".to_string(),
                    type_name: type_of("payload"),
                    value: Some(r#"{"ok": true}"#.to_string()),
                },
                InsertColumnInput {
                    name: "tags".to_string(),
                    type_name: type_of("tags"),
                    value: Some("{red,blue}".to_string()),
                },
            ],
            &[
                "id".to_string(),
                "name".to_string(),
                "amount".to_string(),
                "payload".to_string(),
                "__pg_rowid__".to_string(),
            ],
        )
        .await
        .expect("insert row");

    assert_eq!(inserted.cells[0].as_deref(), Some("1"));
    assert_eq!(inserted.cells[1].as_deref(), Some("alice"));
    assert_eq!(inserted.cells[2].as_deref(), Some("12.34"));
    let ctid = inserted.cells[4].as_deref().expect("ctid").to_string();

    let updated = pool
        .update_cell(
            "edit",
            "public",
            &table,
            "amount",
            &type_of("amount"),
            Some("99.50"),
            &ctid,
        )
        .await
        .expect("update numeric cell");
    assert_eq!(updated.rows_affected, 1);

    // An UPDATE moves the row to a new heap tuple, so its ctid changes
    // (Postgres MVCC). The pre-update ctid no longer matches any live row,
    // so re-read the current ctid before deleting.
    let refetched = pool
        .execute(
            "edit",
            &format!("SELECT ctid::text FROM public.{table} WHERE id = 1"),
            10,
        )
        .await
        .expect("re-read ctid after update");
    let current_ctid = refetched.rows[0][0]
        .as_deref()
        .expect("row still present with a ctid")
        .to_string();

    let deleted = pool
        .delete_rows("edit", "public", &table, &[current_ctid])
        .await
        .expect("delete row");
    assert_eq!(deleted.rows_affected, 1);
    pool.release_session("edit").await;

    let cleanup_sql = format!("DROP TABLE IF EXISTS public.{table}");
    pool.execute("edit-cleanup", &cleanup_sql, 10)
        .await
        .expect("drop test table");
    pool.shutdown().await;
}
