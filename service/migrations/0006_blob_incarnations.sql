PRAGMA foreign_keys = ON;

-- Cross-store tombstones cannot be reclaimed on a finite timer because an R2
-- write awaited by a terminated Worker has no documented finite completion
-- bound. Keep default capacity bounded while letting an operator raise a
-- tenant's isolated ceiling after reviewing its lifecycle backlog. The hard
-- maxima prevent an accidental control-plane update from making D1 work
-- unbounded.
ALTER TABLE tenants ADD COLUMN repository_generation_history_limit INTEGER NOT NULL
    DEFAULT 1024 CHECK (
        repository_generation_history_limit >= 1
        AND repository_generation_history_limit <= 16384
    );

ALTER TABLE tenants ADD COLUMN blob_orphan_candidate_limit INTEGER NOT NULL
    DEFAULT 4096 CHECK (
        blob_orphan_candidate_limit >= 1
        AND blob_orphan_candidate_limit <= 65536
    );

ALTER TABLE tenants ADD COLUMN blob_orphan_repository_limit INTEGER NOT NULL
    DEFAULT 1024 CHECK (
        blob_orphan_repository_limit >= 1
        AND blob_orphan_repository_limit <= 16384
        AND blob_orphan_repository_limit <= blob_orphan_candidate_limit
    );

ALTER TABLE tenants ADD COLUMN trust_security_reserve_limit INTEGER NOT NULL
    DEFAULT 131072 CHECK (
        trust_security_reserve_limit >= 1
        AND trust_security_reserve_limit <= 1048576
    );

ALTER TABLE tenants ADD COLUMN trust_security_repository_limit INTEGER NOT NULL
    DEFAULT 32768 CHECK (
        trust_security_repository_limit >= 1
        AND trust_security_repository_limit <= 262144
        AND trust_security_repository_limit <= trust_security_reserve_limit
    );

ALTER TABLE tenants ADD COLUMN audit_event_limit INTEGER NOT NULL
    DEFAULT 65536 CHECK (
        audit_event_limit >= 1 AND audit_event_limit <= 1048576
    );

ALTER TABLE tenants ADD COLUMN audit_partition_limit INTEGER NOT NULL
    DEFAULT 4096 CHECK (
        audit_partition_limit >= 1 AND audit_partition_limit <= 65536
    );

-- D1 blob rows and R2 objects do not share a transaction. A stale deleter can
-- therefore outlive a row deletion and a same-digest re-upload. Bind every R2
-- operation to an immutable row incarnation so the stale operation only ever
-- addresses the object belonging to the row it observed.
--
-- The all-zero value identifies objects written by the pre-incarnation
-- protocol and preserves their existing R2 key. New API-created rows always
-- provide a random non-zero value. Once a legacy row is removed, its
-- replacement receives a fresh key, so an old in-flight delete cannot target
-- it.
ALTER TABLE blobs ADD COLUMN incarnation_id TEXT NOT NULL
    DEFAULT '00000000000000000000000000000000'
    CHECK (
        length(incarnation_id) = 32
        AND incarnation_id NOT GLOB '*[^0-9a-f]*'
    );

CREATE TRIGGER blobs_incarnation_immutable_before_update
BEFORE UPDATE OF incarnation_id ON blobs
BEGIN
    SELECT CASE WHEN NEW.incarnation_id != OLD.incarnation_id
        THEN RAISE(ABORT, 'blob_incarnation_is_immutable') END;
END;

-- Completed generation tombstones are also a permanent R2 graveyard. Rotate
-- bounded sweeps across them so an object created by a very late suspended
-- request is eventually removed without starving newer receipts.
ALTER TABLE repository_deletion_receipts ADD COLUMN orphan_sweep_due_at INTEGER NOT NULL
    DEFAULT 0 CHECK (
        orphan_sweep_due_at >= 0 AND orphan_sweep_due_at <= 9007199254740991
    );

CREATE INDEX repository_deletion_receipts_orphan_sweep_due
    ON repository_deletion_receipts(orphan_sweep_due_at, completed_at, tenant_id, repository_id);

-- Register an R2 PUT before crossing the D1/R2 boundary. This table has no
-- repository/blob foreign key on purpose: if either row is later deleted, the
-- durable tombstone must survive and keep sweeping the exact incarnation key.
-- A completed handler removes its own candidate only after a ready-row fence;
-- abandoned candidates remain as bounded, rotating graveyard entries.
CREATE TABLE blob_object_orphan_candidates (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    generation_id TEXT NOT NULL CHECK (
        length(generation_id) = 32
        AND generation_id NOT GLOB '*[^0-9a-f]*'
    ),
    digest TEXT NOT NULL CHECK (
        length(digest) = 64 AND digest NOT GLOB '*[^0-9a-f]*'
    ),
    incarnation_id TEXT NOT NULL CHECK (
        length(incarnation_id) = 32
        AND incarnation_id NOT GLOB '*[^0-9a-f]*'
    ),
    operation_id TEXT NOT NULL CHECK (
        length(operation_id) = 32
        AND operation_id NOT GLOB '*[^0-9a-f]*'
    ),
    created_at INTEGER NOT NULL CHECK (
        created_at >= 0 AND created_at <= 9007199254740991
    ),
    next_sweep_at INTEGER NOT NULL CHECK (
        next_sweep_at >= 0 AND next_sweep_at <= 9007199254740991
    ),
    attempts INTEGER NOT NULL DEFAULT 0 CHECK (attempts >= 0),
    PRIMARY KEY (
        tenant_id, repository_id, generation_id, digest, incarnation_id, operation_id
    )
) STRICT;

CREATE INDEX blob_object_orphan_candidates_due
    ON blob_object_orphan_candidates(
        next_sweep_at, created_at, tenant_id, repository_id, generation_id, digest
    );

CREATE INDEX repository_write_leases_global_expiry
    ON repository_write_leases(expires_at, tenant_id, repository_id, generation_id, lease_id);

-- Producer authorization is part of manifest commit, not merely preflight.
-- Signature verification crosses asynchronous crypto and D1 reads; a
-- concurrent revocation must abort the whole D1 batch (including its audit)
-- instead of leaving a ready manifest signed by a revoked key.
CREATE TRIGGER manifests_active_producer_before_insert
BEFORE INSERT ON manifests
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM producer_keys key
         WHERE key.tenant_id = NEW.tenant_id
           AND key.repository_id = NEW.repository_id
           AND key.key_id = NEW.key_id
           AND key.producer_id = NEW.producer_id
           AND key.revoked_at IS NULL
    ) THEN RAISE(ABORT, 'manifest_producer_unavailable') END;
END;

-- The service treats a producer key identifier as an immutable identity.
-- Enforce that invariant in D1 as well as the HTTP handler so direct/operator
-- writes cannot rebind already-verified manifests to different key bytes.
CREATE TRIGGER producer_keys_identity_immutable_before_update
BEFORE UPDATE OF tenant_id, repository_id, key_id, producer_id, public_key_hex, revoked_at
ON producer_keys
BEGIN
    SELECT CASE WHEN
        NEW.tenant_id != OLD.tenant_id
        OR NEW.repository_id != OLD.repository_id
        OR NEW.key_id != OLD.key_id
        OR NEW.producer_id != OLD.producer_id
        OR NEW.public_key_hex != OLD.public_key_hex
    THEN RAISE(ABORT, 'producer_key_rebinding') END;
    SELECT CASE WHEN
        OLD.revoked_at IS NOT NULL AND NEW.revoked_at IS NOT OLD.revoked_at
    THEN RAISE(ABORT, 'producer_key_revocation_is_immutable') END;
END;

-- Generation is a signed replay boundary. Schema v1 does not contain a
-- generation_id, so new legacy rows (including direct/operator writes) are
-- forbidden. Pre-upgrade rows remain readable only to lifecycle cleanup; the
-- HTTP path rejects them and they cannot be rewritten back into service.
CREATE TRIGGER manifests_v2_only_before_insert
BEFORE INSERT ON manifests
BEGIN
    SELECT CASE WHEN json_type(NEW.body_json, '$.schema_version') IS NOT 'integer'
                      OR json_extract(NEW.body_json, '$.schema_version') IS NOT 2
        THEN RAISE(ABORT, 'manifest_schema_v2_required') END;
END;

CREATE TRIGGER manifests_v2_only_before_update
BEFORE UPDATE OF body_json ON manifests
BEGIN
    SELECT CASE WHEN json_type(NEW.body_json, '$.schema_version') IS NOT 'integer'
                      OR json_extract(NEW.body_json, '$.schema_version') IS NOT 2
        THEN RAISE(ABORT, 'manifest_schema_v2_required') END;
END;

-- Audit evidence is part of an authoritative mutation, so a tenant that has
-- consumed its ordinary metadata quota must still be able to revoke a key,
-- delete a manifest/blob, or complete reconciliation. Give audit events a
-- separate bounded reserve instead of letting the general metadata quota
-- deadlock those remediation paths. Retention is partitioned by repository
-- and by protected-remediation versus ordinary activity: a compromised token
-- for one repository cannot evict another repository's evidence, and cheap
-- invalid writes cannot evict revocation/deletion evidence. At the tenant cap
-- an established partition rotates only itself; a new partition requires an
-- operator limit raise.
DROP TRIGGER audit_events_metadata_quota_before_insert;

CREATE TRIGGER audit_events_bounded_reserve_before_insert
BEFORE INSERT ON audit_events
BEGIN
    DELETE FROM audit_events
     WHERE id = (
         SELECT candidate.id FROM audit_events candidate
          WHERE candidate.tenant_id = NEW.tenant_id
            AND candidate.repository_id IS NEW.repository_id
            AND (
                  candidate.action IN (
                    'repository.delete', 'producer.revoke', 'manifest.delete',
                    'manifest.quarantine', 'blob.delete', 'blob.cancel',
                    'blob.quarantine', 'blob.reconcile'
                  )
                  OR (candidate.action = 'trust_bundle.put'
                      AND candidate.outcome IN ('created', 'advanced'))
                ) = (
                  NEW.action IN (
                    'repository.delete', 'producer.revoke', 'manifest.delete',
                    'manifest.quarantine', 'blob.delete', 'blob.cancel',
                    'blob.quarantine', 'blob.reconcile'
                  )
                  OR (NEW.action = 'trust_bundle.put'
                      AND NEW.outcome IN ('created', 'advanced'))
                )
          ORDER BY candidate.id
          LIMIT 1
     )
       AND (
         (SELECT count(*) FROM audit_events candidate
           WHERE candidate.tenant_id = NEW.tenant_id
             AND candidate.repository_id IS NEW.repository_id
             AND (
                   candidate.action IN (
                     'repository.delete', 'producer.revoke', 'manifest.delete',
                     'manifest.quarantine', 'blob.delete', 'blob.cancel',
                     'blob.quarantine', 'blob.reconcile'
                   )
                   OR (candidate.action = 'trust_bundle.put'
                       AND candidate.outcome IN ('created', 'advanced'))
                 ) = (
                   NEW.action IN (
                     'repository.delete', 'producer.revoke', 'manifest.delete',
                     'manifest.quarantine', 'blob.delete', 'blob.cancel',
                     'blob.quarantine', 'blob.reconcile'
                   )
                   OR (NEW.action = 'trust_bundle.put'
                       AND NEW.outcome IN ('created', 'advanced'))
                 )) >= (
           SELECT tenant.audit_partition_limit FROM tenants tenant
            WHERE tenant.id = NEW.tenant_id
         )
         OR (SELECT count(*) FROM audit_events candidate
              WHERE candidate.tenant_id = NEW.tenant_id) >= (
           SELECT tenant.audit_event_limit FROM tenants tenant
            WHERE tenant.id = NEW.tenant_id
         )
       );
    SELECT CASE WHEN (
        SELECT (SELECT count(*) FROM audit_events candidate
                 WHERE candidate.tenant_id = NEW.tenant_id)
               >= tenant.audit_event_limit
          FROM tenants tenant WHERE tenant.id = NEW.tenant_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;

-- Signed trust revocation is also a remediation path: ordinary metadata
-- exhaustion must not prevent a higher epoch from revoking a producer or
-- record. Keep trust heads/history/revocations accounted in
-- used_metadata_units, but admit them from a separate operator-controlled
-- hard-bounded reserve. Root-key provisioning remains on ordinary quota.
CREATE VIEW tenant_trust_security_reserve_usage AS
SELECT tenant.id AS tenant_id,
       (SELECT count(*) FROM trust_key_history history
         WHERE history.tenant_id = tenant.id)
       + (SELECT count(*) FROM trust_revoked_keys revoked
           WHERE revoked.tenant_id = tenant.id)
       + (SELECT count(*) FROM trust_revoked_records revoked
           WHERE revoked.tenant_id = tenant.id)
       + (SELECT coalesce(sum(
             1 + ((length(CAST(head.body_json AS BLOB)) + 1023) / 1024)
           ), 0)
            FROM trust_heads head WHERE head.tenant_id = tenant.id)
       AS used_units
  FROM tenants tenant;

CREATE VIEW repository_trust_security_reserve_usage AS
SELECT repository.tenant_id, repository.id AS repository_id,
       (SELECT count(*) FROM trust_key_history history
         WHERE history.tenant_id = repository.tenant_id
           AND history.repository_id = repository.id)
       + (SELECT count(*) FROM trust_revoked_keys revoked
           WHERE revoked.tenant_id = repository.tenant_id
             AND revoked.repository_id = repository.id)
       + (SELECT count(*) FROM trust_revoked_records revoked
           WHERE revoked.tenant_id = repository.tenant_id
             AND revoked.repository_id = repository.id)
       + (SELECT coalesce(sum(
             1 + ((length(CAST(head.body_json AS BLOB)) + 1023) / 1024)
           ), 0)
            FROM trust_heads head
           WHERE head.tenant_id = repository.tenant_id
             AND head.repository_id = repository.id)
       AS used_units
  FROM repositories repository;

DROP TRIGGER trust_key_history_metadata_quota_before_insert;
DROP TRIGGER trust_revoked_keys_metadata_quota_before_insert;
DROP TRIGGER trust_revoked_records_metadata_quota_before_insert;
DROP TRIGGER trust_heads_metadata_quota_before_insert;
DROP TRIGGER trust_heads_metadata_quota_before_update;

CREATE TRIGGER trust_key_history_security_reserve_before_insert
BEFORE INSERT ON trust_key_history
WHEN NOT EXISTS (
    SELECT 1 FROM trust_key_history existing
     WHERE existing.tenant_id = NEW.tenant_id
       AND existing.repository_id = NEW.repository_id
       AND existing.key_id = NEW.key_id
)
BEGIN
    SELECT CASE WHEN (
        SELECT usage.used_units + 1 > tenant.trust_security_reserve_limit
          FROM tenant_trust_security_reserve_usage usage
          JOIN tenants tenant ON tenant.id = usage.tenant_id
         WHERE usage.tenant_id = NEW.tenant_id
    ) OR (
        SELECT usage.used_units + 1 > tenant.trust_security_repository_limit
          FROM repository_trust_security_reserve_usage usage
          JOIN tenants tenant ON tenant.id = usage.tenant_id
         WHERE usage.tenant_id = NEW.tenant_id
           AND usage.repository_id = NEW.repository_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;

CREATE TRIGGER trust_revoked_keys_security_reserve_before_insert
BEFORE INSERT ON trust_revoked_keys
WHEN NOT EXISTS (
    SELECT 1 FROM trust_revoked_keys existing
     WHERE existing.tenant_id = NEW.tenant_id
       AND existing.repository_id = NEW.repository_id
       AND existing.key_id = NEW.key_id
)
BEGIN
    SELECT CASE WHEN (
        SELECT usage.used_units + 1 > tenant.trust_security_reserve_limit
          FROM tenant_trust_security_reserve_usage usage
          JOIN tenants tenant ON tenant.id = usage.tenant_id
         WHERE usage.tenant_id = NEW.tenant_id
    ) OR (
        SELECT usage.used_units + 1 > tenant.trust_security_repository_limit
          FROM repository_trust_security_reserve_usage usage
          JOIN tenants tenant ON tenant.id = usage.tenant_id
         WHERE usage.tenant_id = NEW.tenant_id
           AND usage.repository_id = NEW.repository_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;

CREATE TRIGGER trust_revoked_records_security_reserve_before_insert
BEFORE INSERT ON trust_revoked_records
WHEN NOT EXISTS (
    SELECT 1 FROM trust_revoked_records existing
     WHERE existing.tenant_id = NEW.tenant_id
       AND existing.repository_id = NEW.repository_id
       AND existing.record_id = NEW.record_id
)
BEGIN
    SELECT CASE WHEN (
        SELECT usage.used_units + 1 > tenant.trust_security_reserve_limit
          FROM tenant_trust_security_reserve_usage usage
          JOIN tenants tenant ON tenant.id = usage.tenant_id
         WHERE usage.tenant_id = NEW.tenant_id
    ) OR (
        SELECT usage.used_units + 1 > tenant.trust_security_repository_limit
          FROM repository_trust_security_reserve_usage usage
          JOIN tenants tenant ON tenant.id = usage.tenant_id
         WHERE usage.tenant_id = NEW.tenant_id
           AND usage.repository_id = NEW.repository_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;

CREATE TRIGGER trust_heads_security_reserve_before_insert
BEFORE INSERT ON trust_heads
WHEN NOT EXISTS (
    SELECT 1 FROM trust_heads existing
     WHERE existing.tenant_id = NEW.tenant_id
       AND existing.repository_id = NEW.repository_id
)
BEGIN
    SELECT CASE WHEN (
        SELECT usage.used_units
               + 1 + ((length(CAST(NEW.body_json AS BLOB)) + 1023) / 1024)
               > tenant.trust_security_reserve_limit
          FROM tenant_trust_security_reserve_usage usage
          JOIN tenants tenant ON tenant.id = usage.tenant_id
         WHERE usage.tenant_id = NEW.tenant_id
    ) OR (
        SELECT usage.used_units
               + 1 + ((length(CAST(NEW.body_json AS BLOB)) + 1023) / 1024)
               > tenant.trust_security_repository_limit
          FROM repository_trust_security_reserve_usage usage
          JOIN tenants tenant ON tenant.id = usage.tenant_id
         WHERE usage.tenant_id = NEW.tenant_id
           AND usage.repository_id = NEW.repository_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;

CREATE TRIGGER trust_heads_security_reserve_before_update
BEFORE UPDATE ON trust_heads
BEGIN
    SELECT CASE WHEN (
        SELECT usage.used_units
               - 1 - ((length(CAST(OLD.body_json AS BLOB)) + 1023) / 1024)
               + 1 + ((length(CAST(NEW.body_json AS BLOB)) + 1023) / 1024)
               > tenant.trust_security_reserve_limit
          FROM tenant_trust_security_reserve_usage usage
          JOIN tenants tenant ON tenant.id = usage.tenant_id
         WHERE usage.tenant_id = NEW.tenant_id
    ) OR (
        SELECT usage.used_units
               - 1 - ((length(CAST(OLD.body_json AS BLOB)) + 1023) / 1024)
               + 1 + ((length(CAST(NEW.body_json AS BLOB)) + 1023) / 1024)
               > tenant.trust_security_repository_limit
          FROM repository_trust_security_reserve_usage usage
          JOIN tenants tenant ON tenant.id = usage.tenant_id
         WHERE usage.tenant_id = NEW.tenant_id
           AND usage.repository_id = NEW.repository_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;
