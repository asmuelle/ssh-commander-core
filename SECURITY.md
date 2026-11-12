# Security Policy

## Supported versions

Security fixes land on `main` and ship in the next release of the latest
minor line. The four crates in this workspace (`ssh-commander-core`,
`ssh-commander-keychain`, `ssh-commander-pg`, `ssh-commander-pg-parquet`)
are released together under one version number.

| Version | Supported          |
| ------- | ------------------ |
| 0.3.x   | :white_check_mark: |
| < 0.3   | :x:                |

While the crates are pre-1.0, a fix may arrive in a new minor version when
the fix itself has to change behavior or API (for example, a safer default).

## Reporting a vulnerability

**Please do not open a public issue, pull request or discussion for a
security problem.**

Report it privately through GitHub:
[**Report a vulnerability**](https://github.com/asmuelle/ssh-commander-core/security/advisories/new)
(Security tab → Advisories → Report a vulnerability).

Helpful details:

- the affected crate(s) and version, or commit
- what an attacker controls (a malicious SSH/FTP/Postgres server, a network
  position, input passed in by the calling app, a local user) and what they gain
- steps or a proof of concept to reproduce it
- any fix or mitigation you have in mind

### What to expect

This is a small, maintainer-run project, so these are goals rather than
guarantees:

- an acknowledgement within a week
- an initial assessment, confirmed or declined with the reasoning, within
  two weeks
- for confirmed issues, a fix and a coordinated release, published with a
  GitHub security advisory that credits you unless you prefer otherwise

Please keep the report private until a fixed release is out, or until we
agree on a disclosure date.

## Scope

In scope: code in this repository. That includes SSH host-key verification,
authentication and credential handling (including the macOS Keychain
integration), TLS configuration for FTPS and PostgreSQL, SSH tunnels, the
commands the network tools run over SSH, and SQL built by the PostgreSQL
explorer.

Out of scope:

- A vulnerability in a dependency that this project doesn't make worse.
  Report it to that dependency upstream. Known advisories are tracked in CI
  with `cargo audit` and `cargo deny`, and are fixed by upgrading.
- Behavior a caller explicitly opts into, such as plain FTP, accepting
  invalid FTPS certificates, or PostgreSQL TLS modes weaker than
  `VerifyFull`. Each of these is documented as unverified.
- The applications built on these crates. Report those to their own
  maintainers.

## Security-relevant defaults

- SSH host keys are trusted on first use and pinned. A changed key refuses
  the connection, and host certificates are refused.
- PostgreSQL connections default to `VerifyFull`: TLS is required and the
  server certificate is checked against the system roots, plus any extra CA
  the profile supplies.
- Passwords, passphrases and similar secrets are redacted from `Debug`
  output and kept out of log messages.
