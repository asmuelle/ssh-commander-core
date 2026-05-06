# ssh-commander

[![CI](https://github.com/asmuelle/ssh-commander-core/actions/workflows/ci.yml/badge.svg)](https://github.com/asmuelle/ssh-commander-core/actions/workflows/ci.yml)
[![License: MIT OR Apache-2.0](https://img.shields.io/badge/license-MIT%20OR%20Apache--2.0-blue.svg)](#license)

Async Rust domain layer for SSH, SFTP, FTP/FTPS, PostgreSQL, and connection management. 

## Crates

| Crate | Purpose |
|-------|---------|
| [`ssh-commander-core`](crates/core) [![crates.io](https://img.shields.io/crates/v/ssh-commander-core.svg)](https://crates.io/crates/ssh-commander-core) [![docs.rs](https://docs.rs/ssh-commander-core/badge.svg)](https://docs.rs/ssh-commander-core) | SSH, SFTP, FTP/FTPS, Postgres explorer, connection manager, event bus, macOS keychain. |
| [`ssh-commander-pg-parquet`](crates/pg-parquet) [![crates.io](https://img.shields.io/crates/v/ssh-commander-pg-parquet.svg)](https://crates.io/crates/ssh-commander-pg-parquet) [![docs.rs](https://docs.rs/ssh-commander-pg-parquet/badge.svg)](https://docs.rs/ssh-commander-pg-parquet) | Parquet export pipeline for the Postgres explorer (pulls in arrow + parquet — opt-in). |

Pull in only what you need: the core crate has zero arrow/parquet weight unless you also depend on `ssh-commander-pg-parquet`.

## Features

- **SSH** (via [`russh`](https://crates.io/crates/russh)) — password and public-key auth, PTY shell sessions, known-hosts (TOFU), `exec` with capture, port forwarding, agent auth.
- **SFTP** — full file ops, recursive transfer, attribute introspection.
- **FTP / FTPS** (via [`suppaftp`](https://crates.io/crates/suppaftp)).
- **PostgreSQL explorer** — schema introspection, paginated cursor reads, edits, exec, parquet export, optional SSH tunneling.
- **Connection manager** — `Arc<RwLock<HashMap>>`-backed lifecycle for sessions across protocols.
- **Typed event bus** — single broadcast channel for async PTY output, transfer progress, and status updates.
- **macOS Keychain** integration (gated on `cfg(target_os = "macos")`).

## Install

```toml
[dependencies]
ssh-commander-core = "0.1"
# Optional: Parquet export for the Postgres explorer
ssh-commander-pg-parquet = "0.1"
```

Requires Rust **1.95+** (edition 2024).

## Usage

```rust
use ssh_commander_core::ssh::{SshConfig, AuthMethod};
use ssh_commander_core::connection_manager::ConnectionManager;

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    let mgr = ConnectionManager::new();

    let config = SshConfig {
        host: "example.com".into(),
        port: 22,
        user: "alice".into(),
        auth: AuthMethod::Password { password: "secret".into() },
        ..Default::default()
    };

    let connection_id = mgr.create_connection(config).await?;
    // … use the connection for shell sessions, command execution, file transfer
    Ok(())
}
```

See [`docs.rs/ssh-commander-core`](https://docs.rs/ssh-commander-core) for the full API.

## Status

`0.1.x` — pre-1.0, expect API changes. Originally extracted from a multi-crate workspace; the published surface is opinionated and follows the consumer's needs. Issues and PRs that improve generality are welcome.

## License

Dual-licensed under either of:

- [Apache License, Version 2.0](LICENSE-APACHE) (`Apache-2.0`)
- [MIT license](LICENSE-MIT) (`MIT`)

at your option.

This crate is derived from work originally licensed MIT by GOODBOY008 (the upstream `r-shell` project); their copyright notice is preserved in `LICENSE-MIT`.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual-licensed as above, without any additional terms or conditions.
