PRAGMA foreign_keys = ON;

CREATE TABLE tenants (
    id TEXT PRIMARY KEY,
    name TEXT NOT NULL,
    quota_bytes INTEGER NOT NULL CHECK (quota_bytes >= 0),
    used_bytes INTEGER NOT NULL DEFAULT 0 CHECK (used_bytes >= 0),
    metadata_quota_units INTEGER NOT NULL DEFAULT 100000 CHECK (metadata_quota_units >= 0),
    used_metadata_units INTEGER NOT NULL DEFAULT 0 CHECK (used_metadata_units >= 0),
    created_at INTEGER NOT NULL
) STRICT;

CREATE TABLE repositories (
    tenant_id TEXT NOT NULL,
    id TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    deleted_at INTEGER,
    PRIMARY KEY (tenant_id, id),
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) STRICT;

CREATE TRIGGER repositories_metadata_quota_before_insert
BEFORE INSERT ON repositories
BEGIN
    SELECT CASE WHEN (
        SELECT used_metadata_units + 1 > metadata_quota_units
          FROM tenants WHERE id = NEW.tenant_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;
CREATE TRIGGER repositories_metadata_after_insert AFTER INSERT ON repositories
BEGIN
    UPDATE tenants SET used_metadata_units = used_metadata_units + 1 WHERE id = NEW.tenant_id;
END;
CREATE TRIGGER repositories_metadata_after_delete AFTER DELETE ON repositories
BEGIN
    UPDATE tenants SET used_metadata_units = max(0, used_metadata_units - 1) WHERE id = OLD.tenant_id;
END;

CREATE TABLE auth_tokens (
    id TEXT PRIMARY KEY,
    tenant_id TEXT NOT NULL,
    subject TEXT NOT NULL,
    secret_sha256 TEXT NOT NULL CHECK (length(secret_sha256) = 64),
    repository_scope TEXT,
    permissions TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    revoked_at INTEGER,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) STRICT;

CREATE TRIGGER auth_tokens_metadata_quota_before_insert
BEFORE INSERT ON auth_tokens
BEGIN
    SELECT CASE WHEN (
        SELECT used_metadata_units + 1 > metadata_quota_units
          FROM tenants WHERE id = NEW.tenant_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;
CREATE TRIGGER auth_tokens_metadata_after_insert AFTER INSERT ON auth_tokens
BEGIN
    UPDATE tenants SET used_metadata_units = used_metadata_units + 1 WHERE id = NEW.tenant_id;
END;
CREATE TRIGGER auth_tokens_metadata_after_delete AFTER DELETE ON auth_tokens
BEGIN
    UPDATE tenants SET used_metadata_units = max(0, used_metadata_units - 1) WHERE id = OLD.tenant_id;
END;

CREATE TABLE rate_windows (
    token_id TEXT NOT NULL,
    window_start INTEGER NOT NULL,
    request_count INTEGER NOT NULL CHECK (request_count > 0),
    PRIMARY KEY (token_id, window_start),
    FOREIGN KEY (token_id) REFERENCES auth_tokens(id) ON DELETE CASCADE
) STRICT;

CREATE INDEX rate_windows_expiry ON rate_windows(window_start);

CREATE TABLE producer_keys (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    producer_id TEXT NOT NULL,
    public_key_hex TEXT NOT NULL CHECK (length(public_key_hex) = 64),
    created_at INTEGER NOT NULL,
    revoked_at INTEGER,
    PRIMARY KEY (tenant_id, repository_id, key_id),
    FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE TRIGGER producer_keys_metadata_quota_before_insert
BEFORE INSERT ON producer_keys
BEGIN
    SELECT CASE WHEN (
        SELECT used_metadata_units + 1 > metadata_quota_units
          FROM tenants WHERE id = NEW.tenant_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;
CREATE TRIGGER producer_keys_metadata_after_insert AFTER INSERT ON producer_keys
BEGIN
    UPDATE tenants SET used_metadata_units = used_metadata_units + 1 WHERE id = NEW.tenant_id;
END;
CREATE TRIGGER producer_keys_metadata_after_delete AFTER DELETE ON producer_keys
BEGIN
    UPDATE tenants SET used_metadata_units = max(0, used_metadata_units - 1) WHERE id = OLD.tenant_id;
END;

CREATE TABLE blobs (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    digest TEXT NOT NULL CHECK (length(digest) = 64),
    size_bytes INTEGER NOT NULL CHECK (size_bytes >= 0 AND size_bytes <= 16777216),
    state TEXT NOT NULL CHECK (state IN ('pending', 'ready', 'quarantined', 'deleting')),
    created_at INTEGER NOT NULL,
    updated_at INTEGER NOT NULL,
    reconcile_attempts INTEGER NOT NULL DEFAULT 0 CHECK (reconcile_attempts >= 0),
    next_reconcile_at INTEGER NOT NULL DEFAULT 0,
    delete_not_before INTEGER,
    PRIMARY KEY (tenant_id, repository_id, digest),
    FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE INDEX blobs_reconcile_due ON blobs(state, next_reconcile_at, created_at);

CREATE TRIGGER blobs_metadata_quota_before_insert
BEFORE INSERT ON blobs
BEGIN
    SELECT CASE WHEN (
        SELECT used_metadata_units + 1 > metadata_quota_units
          FROM tenants WHERE id = NEW.tenant_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;
CREATE TRIGGER blobs_metadata_after_insert AFTER INSERT ON blobs
BEGIN
    UPDATE tenants SET used_metadata_units = used_metadata_units + 1 WHERE id = NEW.tenant_id;
END;
CREATE TRIGGER blobs_metadata_after_delete AFTER DELETE ON blobs
BEGIN
    UPDATE tenants SET used_metadata_units = max(0, used_metadata_units - 1) WHERE id = OLD.tenant_id;
END;

CREATE TRIGGER blobs_quota_before_insert
BEFORE INSERT ON blobs
BEGIN
    SELECT CASE
        WHEN (SELECT used_bytes + NEW.size_bytes FROM tenants WHERE id = NEW.tenant_id)
             > (SELECT quota_bytes FROM tenants WHERE id = NEW.tenant_id)
        THEN RAISE(ABORT, 'quota_exceeded')
    END;
END;
CREATE TRIGGER blobs_usage_after_insert AFTER INSERT ON blobs
BEGIN
    UPDATE tenants SET used_bytes = used_bytes + NEW.size_bytes WHERE id = NEW.tenant_id;
END;
CREATE TRIGGER blobs_usage_after_delete AFTER DELETE ON blobs
BEGIN
    UPDATE tenants
       SET used_bytes = max(0, used_bytes - OLD.size_bytes)
     WHERE id = OLD.tenant_id;
END;

CREATE TABLE manifests (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    request_key TEXT NOT NULL CHECK (length(request_key) = 64),
    record_id TEXT NOT NULL,
    body_sha256 TEXT NOT NULL CHECK (length(body_sha256) = 64),
    body_json TEXT NOT NULL,
    state TEXT NOT NULL CHECK (state IN ('ready', 'quarantined', 'deleted')),
    producer_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    stdout_digest TEXT NOT NULL,
    stdout_size_bytes INTEGER NOT NULL CHECK (stdout_size_bytes >= 0 AND stdout_size_bytes <= 16777216),
    stderr_digest TEXT NOT NULL,
    stderr_size_bytes INTEGER NOT NULL CHECK (stderr_size_bytes >= 0 AND stderr_size_bytes <= 16777216),
    created_at INTEGER NOT NULL,
    expires_at INTEGER NOT NULL,
    deleted_at INTEGER,
    PRIMARY KEY (tenant_id, repository_id, request_key),
    UNIQUE (tenant_id, repository_id, record_id),
    FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, repository_id, key_id)
        REFERENCES producer_keys(tenant_id, repository_id, key_id)
) STRICT;

CREATE TRIGGER manifests_metadata_quota_before_insert
BEFORE INSERT ON manifests
BEGIN
    SELECT CASE WHEN (
        SELECT used_metadata_units
               + 1 + ((length(CAST(NEW.body_json AS BLOB)) + 1023) / 1024)
               > metadata_quota_units
          FROM tenants WHERE id = NEW.tenant_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;
CREATE TRIGGER manifests_metadata_after_insert AFTER INSERT ON manifests
BEGIN
    UPDATE tenants
       SET used_metadata_units = used_metadata_units
           + 1 + ((length(CAST(NEW.body_json AS BLOB)) + 1023) / 1024)
     WHERE id = NEW.tenant_id;
END;
CREATE TRIGGER manifests_metadata_after_delete AFTER DELETE ON manifests
BEGIN
    UPDATE tenants
       SET used_metadata_units = max(
           0,
           used_metadata_units - 1 - ((length(CAST(OLD.body_json AS BLOB)) + 1023) / 1024)
       )
     WHERE id = OLD.tenant_id;
END;

CREATE TRIGGER manifests_ready_blobs_before_insert
BEFORE INSERT ON manifests
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM blobs
         WHERE tenant_id = NEW.tenant_id
           AND repository_id = NEW.repository_id
           AND digest = NEW.stdout_digest
           AND size_bytes = NEW.stdout_size_bytes
           AND state = 'ready'
    ) THEN RAISE(ABORT, 'blob_unavailable') END;
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM blobs
         WHERE tenant_id = NEW.tenant_id
           AND repository_id = NEW.repository_id
           AND digest = NEW.stderr_digest
           AND size_bytes = NEW.stderr_size_bytes
           AND state = 'ready'
    ) THEN RAISE(ABORT, 'blob_unavailable') END;
END;

CREATE INDEX manifests_lifecycle
    ON manifests(tenant_id, repository_id, state, expires_at);

CREATE TABLE manifest_conflicts (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    request_key TEXT NOT NULL,
    existing_body_sha256 TEXT NOT NULL,
    submitted_body_sha256 TEXT NOT NULL,
    detected_at INTEGER NOT NULL,
    FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE INDEX manifest_conflicts_tenant ON manifest_conflicts(tenant_id, id);

CREATE TRIGGER manifest_conflicts_metadata_quota_before_insert
BEFORE INSERT ON manifest_conflicts
BEGIN
    SELECT CASE WHEN (
        SELECT used_metadata_units + 1 > metadata_quota_units
          FROM tenants WHERE id = NEW.tenant_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;
CREATE TRIGGER manifest_conflicts_metadata_after_insert AFTER INSERT ON manifest_conflicts
BEGIN
    UPDATE tenants SET used_metadata_units = used_metadata_units + 1 WHERE id = NEW.tenant_id;
END;
CREATE TRIGGER manifest_conflicts_metadata_after_delete AFTER DELETE ON manifest_conflicts
BEGIN
    UPDATE tenants SET used_metadata_units = max(0, used_metadata_units - 1) WHERE id = OLD.tenant_id;
END;

CREATE TABLE audit_events (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    tenant_id TEXT NOT NULL,
    repository_id TEXT,
    actor TEXT NOT NULL,
    action TEXT NOT NULL,
    target_type TEXT NOT NULL,
    target_id_sha256 TEXT NOT NULL CHECK (length(target_id_sha256) = 64),
    outcome TEXT NOT NULL,
    details_json TEXT NOT NULL,
    created_at INTEGER NOT NULL,
    FOREIGN KEY (tenant_id) REFERENCES tenants(id) ON DELETE CASCADE
) STRICT;

CREATE INDEX audit_tenant_cursor ON audit_events(tenant_id, id DESC);

CREATE TRIGGER audit_events_metadata_quota_before_insert
BEFORE INSERT ON audit_events
BEGIN
    SELECT CASE WHEN (
        SELECT used_metadata_units
               + 1 + ((length(CAST(NEW.details_json AS BLOB)) + 1023) / 1024)
               > metadata_quota_units
          FROM tenants WHERE id = NEW.tenant_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;
CREATE TRIGGER audit_events_metadata_after_insert AFTER INSERT ON audit_events
BEGIN
    UPDATE tenants
       SET used_metadata_units = used_metadata_units
           + 1 + ((length(CAST(NEW.details_json AS BLOB)) + 1023) / 1024)
     WHERE id = NEW.tenant_id;
END;
CREATE TRIGGER audit_events_metadata_after_delete AFTER DELETE ON audit_events
BEGIN
    UPDATE tenants
       SET used_metadata_units = max(
           0,
           used_metadata_units - 1 - ((length(CAST(OLD.details_json AS BLOB)) + 1023) / 1024)
       )
     WHERE id = OLD.tenant_id;
END;
