CREATE TABLE users (
    id                  TEXT PRIMARY KEY,
    email               TEXT NOT NULL UNIQUE,
    role                TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    is_active           INTEGER NOT NULL DEFAULT 1 CHECK (is_active IN (0, 1)),

    kdf_algorithm       TEXT NOT NULL DEFAULT 'argon2id' CHECK (kdf_algorithm IN ('argon2id')),
    kdf_memory_kib      INTEGER NOT NULL CHECK (kdf_memory_kib BETWEEN 19456 AND 524288),
    kdf_iterations      INTEGER NOT NULL CHECK (kdf_iterations BETWEEN 2 AND 20),
    kdf_parallelism     INTEGER NOT NULL CHECK (kdf_parallelism BETWEEN 1 AND 8),
    kdf_salt            BLOB NOT NULL CHECK (length(kdf_salt) = 32),

    server_auth_salt    BLOB NOT NULL CHECK (length(server_auth_salt) = 16),
    server_auth_hash    TEXT NOT NULL,

    key_version         INTEGER NOT NULL DEFAULT 1 CHECK (key_version >= 1),
    encrypted_vault_key BLOB NOT NULL,

    sync_revision       INTEGER NOT NULL DEFAULT 0 CHECK (sync_revision >= 0),

    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE invitations (
    id                  TEXT PRIMARY KEY,
    token_hash          BLOB NOT NULL UNIQUE CHECK (length(token_hash) = 32),
    invited_email       TEXT NULL,
    created_by_user_id  TEXT NULL REFERENCES users(id) ON DELETE SET NULL,
    max_uses            INTEGER NOT NULL DEFAULT 1 CHECK (max_uses >= 1),
    used_count          INTEGER NOT NULL DEFAULT 0 CHECK (used_count >= 0 AND used_count <= max_uses),
    expires_at          TEXT NOT NULL,
    revoked_at          TEXT NULL,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE sessions (
    id                  TEXT PRIMARY KEY,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_family_id     TEXT NOT NULL,
    refresh_token_hash  BLOB NOT NULL UNIQUE CHECK (length(refresh_token_hash) = 32),
    previous_token_hash BLOB NULL,
    device_name         TEXT NOT NULL,
    device_platform     TEXT NOT NULL CHECK (device_platform IN ('windows', 'macos', 'linux', 'android', 'ios', 'browser', 'cli', 'unknown')),
    user_agent          TEXT NULL,
    last_ip             TEXT NULL,
    expires_at          TEXT NOT NULL,
    last_used_at        TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    revoked_at          TEXT NULL,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE used_refresh_tokens (
    token_hash          BLOB PRIMARY KEY CHECK (length(token_hash) = 32),
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_family_id     TEXT NOT NULL,
    expires_at          TEXT NOT NULL,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE TABLE vault_folders (
    id                  TEXT NOT NULL,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_data      BLOB NOT NULL,
    revision            INTEGER NOT NULL CHECK (revision >= 1),
    deleted             INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1)),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (user_id, id)
);

CREATE TABLE vault_items (
    id                  TEXT NOT NULL,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_data      BLOB NOT NULL,
    revision            INTEGER NOT NULL CHECK (revision >= 1),
    deleted             INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1)),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (user_id, id)
);

CREATE TABLE vault_blobs (
    id                  TEXT NOT NULL,
    user_id             TEXT NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item_id             TEXT NOT NULL,
    encrypted_blob      BLOB NOT NULL,
    byte_size           INTEGER NOT NULL CHECK (byte_size > 0 AND byte_size <= 262144),
    sha256_ciphertext   BLOB NOT NULL CHECK (length(sha256_ciphertext) = 32),
    revision            INTEGER NOT NULL CHECK (revision >= 1),
    deleted             INTEGER NOT NULL DEFAULT 0 CHECK (deleted IN (0, 1)),
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    updated_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now')),
    PRIMARY KEY (user_id, id),
    FOREIGN KEY (user_id, item_id) REFERENCES vault_items(user_id, id) ON DELETE CASCADE
);

CREATE TABLE audit_logs (
    id                  INTEGER PRIMARY KEY AUTOINCREMENT,
    user_id             TEXT NULL REFERENCES users(id) ON DELETE SET NULL,
    event_type          TEXT NOT NULL,
    actor_ip            TEXT NULL,
    session_id          TEXT NULL,
    metadata_json       TEXT NULL,
    created_at          TEXT NOT NULL DEFAULT (strftime('%Y-%m-%dT%H:%M:%fZ', 'now'))
);

CREATE INDEX idx_sessions_user_active ON sessions(user_id, revoked_at, expires_at);
CREATE INDEX idx_sessions_family ON sessions(token_family_id);
CREATE INDEX idx_sessions_prev_hash ON sessions(previous_token_hash);
CREATE INDEX idx_used_refresh_family ON used_refresh_tokens(token_family_id);
CREATE INDEX idx_folders_user_rev ON vault_folders(user_id, revision);
CREATE INDEX idx_items_user_rev ON vault_items(user_id, revision);
CREATE INDEX idx_blobs_user_rev ON vault_blobs(user_id, revision);
CREATE INDEX idx_blobs_item ON vault_blobs(user_id, item_id);
CREATE INDEX idx_audit_user_time ON audit_logs(user_id, created_at DESC);
