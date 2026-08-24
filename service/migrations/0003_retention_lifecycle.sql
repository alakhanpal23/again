PRAGMA foreign_keys = ON;

-- Again's service has not been deployed. This migration deliberately supports
-- only the fresh-install path where 0001/0002 and this migration are applied
-- before customer repositories exist. Refuse a populated legacy database
-- rather than running an unbounded backfill or silently accepting rows that do
-- not satisfy the stronger generation/lifecycle invariants below.
CREATE TABLE migration_0003_fresh_install_guard (
    must_be_zero INTEGER NOT NULL CHECK (must_be_zero = 0)
) STRICT;
INSERT INTO migration_0003_fresh_install_guard(must_be_zero)
SELECT CASE WHEN EXISTS (SELECT 1 FROM repositories LIMIT 1) THEN 1 ELSE 0 END;
DROP TABLE migration_0003_fresh_install_guard;

-- Completed receipts are intentionally independent of the repository foreign
-- key. They make DELETE idempotent across finalization and prevent an old retry
-- from targeting a later incarnation that reuses the same human-readable id.
CREATE TABLE repository_deletion_receipts (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    generation_id TEXT NOT NULL CHECK (
        length(generation_id) = 32
        AND generation_id NOT GLOB '*[^0-9a-f]*'
    ),
    requested_at INTEGER NOT NULL CHECK (
        requested_at >= 0 AND requested_at <= 9007199254740991
    ),
    completed_at INTEGER CHECK (
        completed_at IS NULL
        OR (completed_at >= requested_at AND completed_at <= 9007199254740991)
    ),
    PRIMARY KEY (tenant_id, repository_id, generation_id)
) STRICT;

-- Repository deletion is a durable, crash-resumable state machine. The
-- repository row is tombstoned immediately, while this row retains the R2
-- cursor and retry state until the entire tenant/repository prefix has been
-- observed empty twice. Operational lifecycle rows are deliberately not
-- charged to customer metadata quota: quota exhaustion must never prevent a
-- customer from deleting data.
CREATE TABLE repository_deletions (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    generation_id TEXT NOT NULL CHECK (
        length(generation_id) = 32
        AND generation_id NOT GLOB '*[^0-9a-f]*'
    ),
    requested_at INTEGER NOT NULL CHECK (
        requested_at >= 0 AND requested_at <= 9007199254740991
    ),
    r2_cursor TEXT CHECK (r2_cursor IS NULL OR length(CAST(r2_cursor AS BLOB)) <= 4096),
    empty_confirmations INTEGER NOT NULL DEFAULT 0 CHECK (
        empty_confirmations >= 0 AND empty_confirmations <= 2
    ),
    last_empty_at INTEGER CHECK (
        last_empty_at IS NULL
        OR (last_empty_at >= requested_at AND last_empty_at <= 9007199254740991)
    ),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    next_attempt_at INTEGER NOT NULL CHECK (
        next_attempt_at >= 0 AND next_attempt_at <= 9007199254740991
    ),
    lease_id TEXT CHECK (
        lease_id IS NULL
        OR (length(lease_id) >= 1 AND length(CAST(lease_id AS BLOB)) <= 128)
    ),
    lease_until INTEGER CHECK (
        lease_until IS NULL OR (lease_until >= 0 AND lease_until <= 9007199254740991)
    ),
    phase TEXT NOT NULL DEFAULT 'r2' CHECK (phase IN (
        'r2',
        'manifest_conflicts',
        'manifests',
        'blobs',
        'trust_heads',
        'trust_key_history',
        'trust_revoked_keys',
        'trust_revoked_records',
        'trust_root_keys',
        'producer_keys',
        'auth_tokens',
        'audit_events',
        'finalize'
    )),
    updated_at INTEGER NOT NULL CHECK (
        updated_at >= requested_at AND updated_at <= 9007199254740991
    ),
    PRIMARY KEY (tenant_id, repository_id),
    FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE INDEX repository_deletions_due
    ON repository_deletions(next_attempt_at, requested_at, tenant_id, repository_id);

-- Every R2 object-creating upload holds a generation-scoped lease. Tombstoning
-- prevents new leases; deletion waits for all admitted leases to drain (or
-- expire) before accepting an empty R2 listing as final.
CREATE TABLE repository_write_leases (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    generation_id TEXT NOT NULL CHECK (
        length(generation_id) = 32
        AND generation_id NOT GLOB '*[^0-9a-f]*'
    ),
    lease_id TEXT NOT NULL CHECK (
        length(lease_id) >= 1 AND length(CAST(lease_id AS BLOB)) <= 128
    ),
    created_at INTEGER NOT NULL CHECK (
        created_at >= 0 AND created_at <= 9007199254740991
    ),
    expires_at INTEGER NOT NULL CHECK (
        expires_at > created_at AND expires_at <= 9007199254740991
    ),
    PRIMARY KEY (tenant_id, repository_id, generation_id, lease_id),
    FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE INDEX repository_write_leases_expiry
    ON repository_write_leases(tenant_id, repository_id, generation_id, expires_at);

-- The original append/read indexes are tenant-oriented. Repository erasure
-- needs selective access when a tenant owns many repositories; these indexes
-- keep each bounded chunk from scanning unrelated tenant metadata.
CREATE INDEX manifest_conflicts_repository_cleanup
    ON manifest_conflicts(tenant_id, repository_id, id);
CREATE INDEX auth_tokens_repository_cleanup
    ON auth_tokens(tenant_id, repository_scope, id);
CREATE INDEX audit_events_repository_cleanup
    ON audit_events(tenant_id, repository_id, id);

CREATE TRIGGER repository_deletions_require_tombstone_before_insert
BEFORE INSERT ON repository_deletions
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_id
           AND repository.generation_id = NEW.generation_id
           AND repository.deleted_at IS NOT NULL
    ) THEN RAISE(ABORT, 'repository_not_deleting') END;
END;

-- A tombstone is one-way. Reusing an identifier is only possible after the
-- lifecycle has confirmed R2 empty and deleted the old repository row.
CREATE TRIGGER repositories_deletion_timestamp_before_update
BEFORE UPDATE OF deleted_at ON repositories
BEGIN
    SELECT CASE WHEN NEW.deleted_at IS NOT NULL
                      AND (NEW.deleted_at < NEW.created_at
                           OR NEW.deleted_at > 9007199254740991)
        THEN RAISE(ABORT, 'invalid_repository_deletion_time') END;
    SELECT CASE WHEN OLD.deleted_at IS NOT NULL
                      AND (NEW.deleted_at IS NULL OR NEW.deleted_at != OLD.deleted_at)
        THEN RAISE(ABORT, 'repository_deletion_is_final') END;
END;

CREATE TRIGGER repositories_generation_immutable_before_update
BEFORE UPDATE OF generation_id ON repositories
BEGIN
    SELECT CASE WHEN NEW.generation_id != OLD.generation_id
        THEN RAISE(ABORT, 'repository_generation_is_immutable') END;
END;

-- This O(1) trigger is the authoritative tombstone -> lifecycle transition.
-- It also repairs the direct/operator mutation path; API code does not need a
-- second non-atomic statement to create the deletion job.
CREATE TRIGGER repositories_lifecycle_after_tombstone
AFTER UPDATE OF deleted_at ON repositories
WHEN OLD.deleted_at IS NULL AND NEW.deleted_at IS NOT NULL
BEGIN
    INSERT INTO repository_deletions(
        tenant_id, repository_id, generation_id, requested_at, r2_cursor,
        empty_confirmations, last_empty_at, attempts, next_attempt_at,
        lease_id, lease_until, phase, updated_at
    ) VALUES (
        NEW.tenant_id, NEW.id, NEW.generation_id, NEW.deleted_at, NULL,
        0, NULL, 0, NEW.deleted_at, NULL, NULL, 'r2', NEW.deleted_at
    );
    INSERT INTO repository_deletion_receipts(
        tenant_id, repository_id, generation_id, requested_at, completed_at
    ) VALUES (
        NEW.tenant_id, NEW.id, NEW.generation_id, NEW.deleted_at, NULL
    );
END;

CREATE TRIGGER repository_write_leases_active_repository_before_insert
BEFORE INSERT ON repository_write_leases
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_id
           AND repository.generation_id = NEW.generation_id
           AND repository.deleted_at IS NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;

-- Route-level checks hide a tombstoned repository. These write-boundary
-- triggers additionally close the check/write race for requests that were
-- authenticated immediately before deletion was requested.
CREATE TRIGGER producer_keys_active_repository_before_insert
BEFORE INSERT ON producer_keys
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_id
           AND repository.deleted_at IS NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;
CREATE TRIGGER producer_keys_active_repository_before_update
BEFORE UPDATE ON producer_keys
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_id
           AND repository.deleted_at IS NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;

CREATE TRIGGER blobs_active_repository_before_insert
BEFORE INSERT ON blobs
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_id
           AND repository.deleted_at IS NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;
CREATE TRIGGER blobs_active_repository_before_update
BEFORE UPDATE ON blobs
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_id
           AND repository.deleted_at IS NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;

CREATE TRIGGER manifests_active_repository_before_insert
BEFORE INSERT ON manifests
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_id
           AND repository.deleted_at IS NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;
CREATE TRIGGER manifests_active_repository_before_update
BEFORE UPDATE ON manifests
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_id
           AND repository.deleted_at IS NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;

CREATE TRIGGER manifest_conflicts_active_repository_before_insert
BEFORE INSERT ON manifest_conflicts
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_id
           AND repository.deleted_at IS NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;

CREATE TRIGGER trust_root_keys_active_repository_before_insert
BEFORE INSERT ON trust_root_keys
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_id
           AND repository.deleted_at IS NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;
CREATE TRIGGER trust_root_keys_active_repository_before_update
BEFORE UPDATE ON trust_root_keys
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_id
           AND repository.deleted_at IS NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;

CREATE TRIGGER trust_heads_active_repository_before_insert
BEFORE INSERT ON trust_heads
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_id
           AND repository.deleted_at IS NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;
CREATE TRIGGER trust_heads_active_repository_before_update
BEFORE UPDATE ON trust_heads
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_id
           AND repository.deleted_at IS NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;

CREATE TRIGGER trust_key_history_active_repository_before_insert
BEFORE INSERT ON trust_key_history
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_id
           AND repository.deleted_at IS NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;
CREATE TRIGGER trust_revoked_keys_active_repository_before_insert
BEFORE INSERT ON trust_revoked_keys
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_id
           AND repository.deleted_at IS NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;
CREATE TRIGGER trust_revoked_records_active_repository_before_insert
BEFORE INSERT ON trust_revoked_records
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_id
           AND repository.deleted_at IS NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;

-- Repository-scoped tokens are provisioned out of band, but they must not be
-- added or rebound to a repository once deletion has begun.
CREATE TRIGGER auth_tokens_active_repository_before_insert
BEFORE INSERT ON auth_tokens
WHEN NEW.repository_scope IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_scope
           AND repository.deleted_at IS NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;
CREATE TRIGGER auth_tokens_active_repository_before_update
BEFORE UPDATE OF tenant_id, repository_scope ON auth_tokens
WHEN NEW.repository_scope IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_scope
           AND repository.deleted_at IS NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;
CREATE TRIGGER auth_tokens_cannot_escape_deleting_repository_before_update
BEFORE UPDATE OF tenant_id, repository_scope ON auth_tokens
WHEN OLD.repository_scope IS NOT NULL
BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = OLD.tenant_id
           AND repository.id = OLD.repository_scope
           AND repository.deleted_at IS NOT NULL
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;

-- Audit rows are intentionally not foreign-keyed to repositories because the
-- original schema supports tenant-level events. Prevent repository-scoped
-- events from appearing after finalization. A deletion-request event is
-- allowed only while its lifecycle can still return to the audit cleanup
-- phase. The atomic audit-phase advance closes insertion before `finalize`.
CREATE TRIGGER audit_events_repository_lifecycle_before_insert
BEFORE INSERT ON audit_events
WHEN NEW.repository_id IS NOT NULL
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = NEW.tenant_id
           AND repository.id = NEW.repository_id
           AND (
             repository.deleted_at IS NULL
             OR (
               NEW.action = 'repository.delete'
               AND repository.deleted_at IS NOT NULL
               AND EXISTS (
                 SELECT 1 FROM repository_deletions deletion
                  WHERE deletion.tenant_id = repository.tenant_id
                    AND deletion.repository_id = repository.id
                    AND deletion.generation_id = repository.generation_id
                    AND deletion.phase != 'finalize'
               )
             )
           )
    ) THEN RAISE(ABORT, 'repository_deleting') END;
END;

-- A durable, indexed queue avoids re-scanning every blob on every cron. New
-- blobs get a one-hour adoption window. Publishing a manifest removes its
-- referenced blobs from the queue; deleting or expiring that manifest
-- enqueues only the two affected digests again.
CREATE TABLE blob_gc_candidates (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    digest TEXT NOT NULL CHECK (
        length(digest) = 64 AND digest NOT GLOB '*[^0-9a-f]*'
    ),
    next_check_at INTEGER NOT NULL CHECK (
        next_check_at >= 0 AND next_check_at <= 9007199254740991
    ),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    created_at INTEGER NOT NULL CHECK (
        created_at >= 0 AND created_at <= 9007199254740991
    ),
    updated_at INTEGER NOT NULL CHECK (
        updated_at >= 0 AND updated_at <= 9007199254740991
    ),
    PRIMARY KEY (tenant_id, repository_id, digest),
    FOREIGN KEY (tenant_id, repository_id, digest)
        REFERENCES blobs(tenant_id, repository_id, digest) ON DELETE CASCADE
) STRICT;

CREATE INDEX blob_gc_candidates_due
    ON blob_gc_candidates(next_check_at, created_at, tenant_id, repository_id, digest);

CREATE TABLE manifest_gc_candidates (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    request_key TEXT NOT NULL CHECK (
        length(request_key) = 64 AND request_key NOT GLOB '*[^0-9a-f]*'
    ),
    due_at INTEGER NOT NULL CHECK (due_at >= 0 AND due_at <= 9007199254740991),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0 AND updated_at <= 9007199254740991),
    PRIMARY KEY (tenant_id, repository_id, request_key),
    FOREIGN KEY (tenant_id, repository_id, request_key)
        REFERENCES manifests(tenant_id, repository_id, request_key) ON DELETE CASCADE
) STRICT;

CREATE INDEX manifest_gc_candidates_due
    ON manifest_gc_candidates(due_at, tenant_id, repository_id, request_key);

CREATE INDEX manifests_stdout_reference
    ON manifests(tenant_id, repository_id, stdout_digest, state, expires_at);
CREATE INDEX manifests_stderr_reference
    ON manifests(tenant_id, repository_id, stderr_digest, state, expires_at);

CREATE TRIGGER blobs_gc_after_insert
AFTER INSERT ON blobs
BEGIN
    INSERT INTO blob_gc_candidates(
        tenant_id, repository_id, digest, next_check_at, attempts, created_at, updated_at
    ) VALUES (
        NEW.tenant_id, NEW.repository_id, NEW.digest, NEW.created_at + 3600, 0,
        NEW.created_at, NEW.created_at
    );
END;

CREATE TRIGGER manifests_gc_after_insert
AFTER INSERT ON manifests
BEGIN
    DELETE FROM blob_gc_candidates
     WHERE tenant_id = NEW.tenant_id
       AND repository_id = NEW.repository_id
       AND digest IN (NEW.stdout_digest, NEW.stderr_digest);
    INSERT INTO manifest_gc_candidates(
        tenant_id, repository_id, request_key, due_at, updated_at
    ) VALUES (
        NEW.tenant_id, NEW.repository_id, NEW.request_key,
        CASE WHEN NEW.state = 'deleted' THEN coalesce(NEW.deleted_at, unixepoch())
             ELSE NEW.expires_at END,
        unixepoch()
    );
END;

CREATE TRIGGER manifests_retention_after_update
AFTER UPDATE OF state, expires_at, deleted_at ON manifests
BEGIN
    INSERT INTO manifest_gc_candidates(
        tenant_id, repository_id, request_key, due_at, updated_at
    ) VALUES (
        NEW.tenant_id, NEW.repository_id, NEW.request_key,
        CASE WHEN NEW.state = 'deleted' THEN coalesce(NEW.deleted_at, unixepoch())
             ELSE NEW.expires_at END,
        unixepoch()
    )
    ON CONFLICT(tenant_id, repository_id, request_key) DO UPDATE SET
        due_at = excluded.due_at,
        updated_at = excluded.updated_at;
END;

CREATE TRIGGER manifests_gc_after_logical_delete
AFTER UPDATE OF state ON manifests
WHEN OLD.state != 'deleted' AND NEW.state = 'deleted'
BEGIN
    INSERT INTO blob_gc_candidates(
        tenant_id, repository_id, digest, next_check_at, attempts, created_at, updated_at
    )
    SELECT NEW.tenant_id, NEW.repository_id, NEW.stdout_digest, unixepoch(), 0,
           unixepoch(), unixepoch()
     WHERE EXISTS (
         SELECT 1 FROM repositories repository
          WHERE repository.tenant_id = NEW.tenant_id
            AND repository.id = NEW.repository_id
            AND repository.deleted_at IS NULL
     )
       AND EXISTS (
         SELECT 1 FROM blobs blob
          WHERE blob.tenant_id = NEW.tenant_id
            AND blob.repository_id = NEW.repository_id
            AND blob.digest = NEW.stdout_digest
     )
    ON CONFLICT(tenant_id, repository_id, digest) DO UPDATE SET
        next_check_at = min(blob_gc_candidates.next_check_at, excluded.next_check_at),
        attempts = 0,
        updated_at = excluded.updated_at;
    INSERT INTO blob_gc_candidates(
        tenant_id, repository_id, digest, next_check_at, attempts, created_at, updated_at
    )
    SELECT NEW.tenant_id, NEW.repository_id, NEW.stderr_digest, unixepoch(), 0,
           unixepoch(), unixepoch()
     WHERE EXISTS (
         SELECT 1 FROM repositories repository
          WHERE repository.tenant_id = NEW.tenant_id
            AND repository.id = NEW.repository_id
            AND repository.deleted_at IS NULL
     )
       AND EXISTS (
         SELECT 1 FROM blobs blob
          WHERE blob.tenant_id = NEW.tenant_id
            AND blob.repository_id = NEW.repository_id
            AND blob.digest = NEW.stderr_digest
     )
    ON CONFLICT(tenant_id, repository_id, digest) DO UPDATE SET
        next_check_at = min(blob_gc_candidates.next_check_at, excluded.next_check_at),
        attempts = 0,
        updated_at = excluded.updated_at;
END;

CREATE TRIGGER manifests_gc_after_physical_delete
AFTER DELETE ON manifests
BEGIN
    INSERT INTO blob_gc_candidates(
        tenant_id, repository_id, digest, next_check_at, attempts, created_at, updated_at
    )
    SELECT OLD.tenant_id, OLD.repository_id, OLD.stdout_digest, unixepoch(), 0,
           unixepoch(), unixepoch()
     WHERE EXISTS (
         SELECT 1 FROM repositories repository
          WHERE repository.tenant_id = OLD.tenant_id
            AND repository.id = OLD.repository_id
            AND repository.deleted_at IS NULL
     )
       AND EXISTS (
         SELECT 1 FROM blobs blob
          WHERE blob.tenant_id = OLD.tenant_id
            AND blob.repository_id = OLD.repository_id
            AND blob.digest = OLD.stdout_digest
     )
    ON CONFLICT(tenant_id, repository_id, digest) DO UPDATE SET
        next_check_at = min(blob_gc_candidates.next_check_at, excluded.next_check_at),
        attempts = 0,
        updated_at = excluded.updated_at;
    INSERT INTO blob_gc_candidates(
        tenant_id, repository_id, digest, next_check_at, attempts, created_at, updated_at
    )
    SELECT OLD.tenant_id, OLD.repository_id, OLD.stderr_digest, unixepoch(), 0,
           unixepoch(), unixepoch()
     WHERE EXISTS (
         SELECT 1 FROM repositories repository
          WHERE repository.tenant_id = OLD.tenant_id
            AND repository.id = OLD.repository_id
            AND repository.deleted_at IS NULL
     )
       AND EXISTS (
         SELECT 1 FROM blobs blob
          WHERE blob.tenant_id = OLD.tenant_id
            AND blob.repository_id = OLD.repository_id
            AND blob.digest = OLD.stderr_digest
     )
    ON CONFLICT(tenant_id, repository_id, digest) DO UPDATE SET
        next_check_at = min(blob_gc_candidates.next_check_at, excluded.next_check_at),
        attempts = 0,
        updated_at = excluded.updated_at;
END;
