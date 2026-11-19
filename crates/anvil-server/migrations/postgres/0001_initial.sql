CREATE TABLE users (
    id                  UUID PRIMARY KEY,
    email               TEXT NOT NULL UNIQUE,
    role                TEXT NOT NULL DEFAULT 'user' CHECK (role IN ('user', 'admin')),
    is_active           BOOLEAN NOT NULL DEFAULT TRUE,

    kdf_algorithm       TEXT NOT NULL DEFAULT 'argon2id' CHECK (kdf_algorithm IN ('argon2id')),
    kdf_memory_kib      INTEGER NOT NULL CHECK (kdf_memory_kib BETWEEN 19456 AND 524288),
    kdf_iterations      INTEGER NOT NULL CHECK (kdf_iterations BETWEEN 2 AND 20),
    kdf_parallelism     INTEGER NOT NULL CHECK (kdf_parallelism BETWEEN 1 AND 8),
    kdf_salt            BYTEA NOT NULL CHECK (octet_length(kdf_salt) = 32),

    server_auth_salt    BYTEA NOT NULL CHECK (octet_length(server_auth_salt) = 16),
    server_auth_hash    TEXT NOT NULL,

    key_version         INTEGER NOT NULL DEFAULT 1 CHECK (key_version >= 1),
    encrypted_vault_key BYTEA NOT NULL,

    sync_revision       BIGINT NOT NULL DEFAULT 0 CHECK (sync_revision >= 0),

    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE invitations (
    id                  UUID PRIMARY KEY,
    token_hash          BYTEA NOT NULL UNIQUE CHECK (octet_length(token_hash) = 32),
    invited_email       TEXT NULL,
    created_by_user_id  UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    max_uses            INTEGER NOT NULL DEFAULT 1 CHECK (max_uses >= 1),
    used_count          INTEGER NOT NULL DEFAULT 0 CHECK (used_count >= 0 AND used_count <= max_uses),
    expires_at          TIMESTAMPTZ NOT NULL,
    revoked_at          TIMESTAMPTZ NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE sessions (
    id                  UUID PRIMARY KEY,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_family_id     UUID NOT NULL,
    refresh_token_hash  BYTEA NOT NULL UNIQUE CHECK (octet_length(refresh_token_hash) = 32),
    previous_token_hash BYTEA NULL,
    device_name         TEXT NOT NULL,
    device_platform     TEXT NOT NULL CHECK (device_platform IN ('windows', 'macos', 'linux', 'android', 'ios', 'browser', 'cli', 'unknown')),
    user_agent          TEXT NULL,
    last_ip             TEXT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    last_used_at        TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    revoked_at          TIMESTAMPTZ NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE used_refresh_tokens (
    token_hash          BYTEA PRIMARY KEY CHECK (octet_length(token_hash) = 32),
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    token_family_id     UUID NOT NULL,
    expires_at          TIMESTAMPTZ NOT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
);

CREATE TABLE vault_folders (
    id                  UUID NOT NULL,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_data      BYTEA NOT NULL,
    revision            BIGINT NOT NULL CHECK (revision >= 1),
    deleted             BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, id)
);

CREATE TABLE vault_items (
    id                  UUID NOT NULL,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    encrypted_data      BYTEA NOT NULL,
    revision            BIGINT NOT NULL CHECK (revision >= 1),
    deleted             BOOLEAN NOT NULL DEFAULT FALSE,
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, id)
);

CREATE TABLE vault_blobs (
    id                  UUID NOT NULL,
    user_id             UUID NOT NULL REFERENCES users(id) ON DELETE CASCADE,
    item_id             UUID NOT NULL,
    encrypted_blob      BYTEA NOT NULL,
    byte_size           INTEGER NOT NULL CHECK (byte_size > 0 AND byte_size <= 262144),
    sha256_ciphertext   BYTEA NOT NULL CHECK (octet_length(sha256_ciphertext) = 32),
    revision            BIGINT NOT NULL CHECK (revision >= 1),
    deleted             BOOLEAN NOT NULL DEFAULT FALSE,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    updated_at          TIMESTAMPTZ NOT NULL DEFAULT NOW(),
    PRIMARY KEY (user_id, id),
    FOREIGN KEY (user_id, item_id) REFERENCES vault_items(user_id, id) ON DELETE CASCADE
);

CREATE TABLE audit_logs (
    id                  BIGSERIAL PRIMARY KEY,
    user_id             UUID NULL REFERENCES users(id) ON DELETE SET NULL,
    event_type          TEXT NOT NULL,
    actor_ip            TEXT NULL,
    session_id          UUID NULL,
    metadata_json       TEXT NULL,
    created_at          TIMESTAMPTZ NOT NULL DEFAULT NOW()
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
