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
crates/
  anvil-core/          Pure Rust crypto, vault models, TOTP, search, and importers/exporters
docs/
  ARCHITECTURE.md      System, cryptographic, SQL, and REST API specification
  ROADMAP.md           Incremental 6-phase delivery plan
```

## Development

```bash
cargo fmt --all -- --check
cargo clippy --workspace --all-targets -- -D warnings
cargo test --workspace
cargo check -p anvil-core --target wasm32-unknown-unknown --no-default-features
```

## Documentation

- [Architecture & Cryptographic Design](docs/ARCHITECTURE.md)
- [Development Roadmap](docs/ROADMAP.md)

## License

Licensed under the [MIT License](LICENSE).
