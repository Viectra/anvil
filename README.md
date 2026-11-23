<p align="center">
  <img src="assets/logo.svg" alt="Anvil Logo" width="80" height="80" />
</p>

<h1 align="center">Anvil</h1>

<p align="center">
  Self-hosted, multi-user, zero-knowledge password manager and TOTP authenticator built around Rust.
</p>

---

## Overview

Anvil centralizes all security-critical logic—key derivation, authenticated encryption, TOTP generation, password analysis, client-side fuzzy search, and multi-manager import/export—inside a single shared Rust core (`anvil-core`) compiled natively and to WebAssembly.

### Architecture Highlights

- **Zero-Knowledge Cryptography**: `Argon2id` (`64 MiB`, `t = 3`, `p = 1`) + `HKDF-SHA256` domain separation derives an isolated `MasterEncryptionKey` (never leaves the client) and `MasterAuthHash` (re-hashed server-side). Vault items, folders, and encrypted logos use `XChaCha20-Poly1305` with 192-bit CSPRNG nonces and strict AAD context binding (`user_id`, entity type, entity ID).
- **Memory Hygiene**: Sensitive buffers implement `Zeroize` / `ZeroizeOnDrop` with automatic wiping on lock.
- **RFC 6238 TOTP**: Built-in 2FA generator supporting `SHA1`, `SHA256`, `SHA512`, `otpauth://` URIs, and real-time countdowns.
- **Multi-Manager Migration**: Dry-run import preview and duplicate detection for Bitwarden (unencrypted & password-encrypted JSON, CSV), Chrome/Edge/Brave/Firefox CSV, KeePass/KeePassXC (CSV & XML), 1Password (`.1pux` & CSV), and Proton Pass / Dashlane CSV, plus encrypted `.anvil`, Bitwarden JSON, and standard CSV exports.

## Workspace Layout

```text
apps/
  desktop/             Anvil Desktop shell (Svelte 5 + TypeScript) and Win32/Tauri backend (`anvil-desktop`)
crates/
  anvil-core/          Pure Rust crypto, vault models, TOTP, search, and importers/exporters
  anvil-client-core/   Offline encrypted SQLite cache, differential sync engine, and volatile RAM lock
  anvil-server/        Self-hosted Axum + SQLx API server (PostgreSQL & SQLite) and admin CLI
packages/
  anvil-ui/            Shared Svelte 5 + Tailwind v4 « Forge Moderne / Acier Sombre » UI library
deploy/
  Dockerfile           Multi-stage non-root container build
  docker-compose.yml   Hardened PostgreSQL 16 and SQLite compose stacks
docs/
  ARCHITECTURE.md      System, cryptographic, SQL, and REST API specification
  ROADMAP.md           Incremental 6-phase delivery plan
```

## Self-Hosted Server

Generate cryptographic instance keys and configure `deploy/.env`:

```bash
cp deploy/.env.example deploy/.env
cargo run -p anvil-server -- keygen
```

Manage database migrations, invitations, and accounts through the built-in CLI:

```bash
cargo run -p anvil-server -- migrate
cargo run -p anvil-server -- invite create --email alice@example.com --max-uses 1
cargo run -p anvil-server -- user promote alice@example.com
```

Run the containerized PostgreSQL stack (or `--profile sqlite` for single-file storage):

```bash
docker compose -f deploy/docker-compose.yml up -d --build
```

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check -p anvil-core --target wasm32-unknown-unknown --no-default-features
pnpm --filter @anvil/ui check
pnpm --filter @anvil/desktop check
```

## Documentation

- [Architecture & Cryptographic Design](docs/ARCHITECTURE.md)
- [Development Roadmap](docs/ROADMAP.md)

## License

Licensed under the [MIT License](LICENSE).
