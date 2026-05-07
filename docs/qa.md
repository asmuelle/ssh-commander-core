# QA Playbook

This workspace has three QA tiers. Keep the fast tier green before opening a
PR; use the integration tiers when touching protocol, pool, SQL, or transfer
code.

## Fast Local Gate

```sh
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace --all-targets --no-fail-fast
RUSTDOCFLAGS="-D warnings" cargo doc --workspace --no-deps
```

## Postgres Integration

These tests are skipped unless `PG_TEST_HOST` is set. They cover cancellation,
cursor isolation, and typed edit operations against a real server.

```sh
PG_TEST_HOST=127.0.0.1 \
PG_TEST_PORT=5432 \
PG_TEST_DB=postgres \
PG_TEST_USER=postgres \
PG_TEST_PASSWORD=postgres \
cargo test -p ssh-commander-core --test postgres_integration -- --nocapture
```

## Protocol Smoke Tests

SSH/SFTP tests are skipped unless `SSH_TEST_HOST` is set.

```sh
SSH_TEST_HOST=127.0.0.1 \
SSH_TEST_PORT=2222 \
SSH_TEST_USER=testuser \
SSH_TEST_PASSWORD=testpass \
cargo test -p ssh-commander-core --test ssh_sftp_integration -- --nocapture
```

FTP tests already live in `ftp_client.rs` and are skipped unless
`FTP_TEST_HOST` is set.

```sh
FTP_TEST_HOST=127.0.0.1 \
FTP_TEST_PORT=2121 \
FTP_TEST_USER=testuser \
FTP_TEST_PASS=testpass \
cargo test -p ssh-commander-core ftp_client::tests:: -- --nocapture
```

## Slower QA

CI runs `cargo audit`, `cargo deny`, rustdoc, and coverage summaries. The
scheduled Nightly QA workflow runs protocol smoke tests plus non-blocking
`cargo-semver-checks` and `cargo mutants` jobs.
