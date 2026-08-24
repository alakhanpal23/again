PRAGMA foreign_keys = ON;

-- Trust roots are provisioned out of band. No HTTP route can create, rotate,
-- or re-enable one, so compromise of a bearer token cannot replace a root
-- already pinned by clients.
CREATE TABLE trust_root_keys (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    root_key_id TEXT NOT NULL,
    public_key_hex TEXT NOT NULL CHECK (
        length(public_key_hex) = 64
        AND public_key_hex NOT GLOB '*[^0-9a-f]*'
    ),
    created_at INTEGER NOT NULL CHECK (created_at >= 0 AND created_at <= 9007199254740991),
    disabled_at INTEGER CHECK (
        disabled_at IS NULL
        OR (disabled_at >= created_at AND disabled_at <= 9007199254740991)
    ),
    PRIMARY KEY (tenant_id, repository_id, root_key_id),
    FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE CASCADE
) STRICT;

-- Root identities and key material are immutable. Disabling is one-way; root
-- provisioning and destructive repository lifecycle remain out-of-band.
CREATE TRIGGER trust_root_keys_immutable_before_update
BEFORE UPDATE ON trust_root_keys
BEGIN
    SELECT CASE WHEN NEW.tenant_id != OLD.tenant_id
                      OR NEW.repository_id != OLD.repository_id
                      OR NEW.root_key_id != OLD.root_key_id
                      OR NEW.public_key_hex != OLD.public_key_hex
        THEN RAISE(ABORT, 'trust_root_rebinding') END;
    SELECT CASE WHEN OLD.disabled_at IS NOT NULL
                      AND (NEW.disabled_at IS NULL OR NEW.disabled_at != OLD.disabled_at)
        THEN RAISE(ABORT, 'trust_root_reenable') END;
END;

CREATE TABLE trust_key_history (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    producer_id TEXT NOT NULL,
    public_key_json TEXT NOT NULL,
    first_epoch INTEGER NOT NULL CHECK (first_epoch > 0),
    PRIMARY KEY (tenant_id, repository_id, key_id),
    FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE TABLE trust_revoked_keys (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    key_id TEXT NOT NULL,
    first_epoch INTEGER NOT NULL CHECK (first_epoch > 0),
    PRIMARY KEY (tenant_id, repository_id, key_id),
    FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE TABLE trust_revoked_records (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    record_id TEXT NOT NULL,
    first_epoch INTEGER NOT NULL CHECK (first_epoch > 0),
    PRIMARY KEY (tenant_id, repository_id, record_id),
    FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE CASCADE
) STRICT;

CREATE TABLE trust_heads (
    tenant_id TEXT NOT NULL,
    repository_id TEXT NOT NULL,
    epoch INTEGER NOT NULL CHECK (epoch > 0 AND epoch <= 9007199254740991),
    root_key_id TEXT NOT NULL,
    body_sha256 TEXT NOT NULL CHECK (
        length(body_sha256) = 64
        AND body_sha256 NOT GLOB '*[^0-9a-f]*'
    ),
    body_json TEXT NOT NULL CHECK (length(CAST(body_json AS BLOB)) <= 1500000),
    issued_at INTEGER NOT NULL CHECK (issued_at >= 0 AND issued_at <= 9007199254740991),
    expires_at INTEGER NOT NULL CHECK (
        expires_at > issued_at
        AND expires_at - issued_at <= 300
        AND expires_at <= 9007199254740991
    ),
    updated_at INTEGER NOT NULL CHECK (updated_at >= 0 AND updated_at <= 9007199254740991),
    PRIMARY KEY (tenant_id, repository_id),
    FOREIGN KEY (tenant_id, repository_id)
        REFERENCES repositories(tenant_id, id) ON DELETE CASCADE,
    FOREIGN KEY (tenant_id, repository_id, root_key_id)
        REFERENCES trust_root_keys(tenant_id, repository_id, root_key_id) ON DELETE CASCADE
) STRICT;

-- A root can be disabled between the Worker's initial read and the atomic
-- trust-head write. Re-check its state inside that write so a concurrently
-- disabled root cannot advance the stored head.
CREATE TRIGGER trust_heads_active_root_before_insert
BEFORE INSERT ON trust_heads
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
          FROM trust_root_keys root
         WHERE root.tenant_id = NEW.tenant_id
           AND root.repository_id = NEW.repository_id
           AND root.root_key_id = NEW.root_key_id
           AND root.disabled_at IS NULL
    ) THEN RAISE(ABORT, 'trust_root_disabled') END;
END;

CREATE TRIGGER trust_heads_active_root_before_update
BEFORE UPDATE ON trust_heads
BEGIN
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1
          FROM trust_root_keys root
         WHERE root.tenant_id = NEW.tenant_id
           AND root.repository_id = NEW.repository_id
           AND root.root_key_id = NEW.root_key_id
           AND root.disabled_at IS NULL
    ) THEN RAISE(ABORT, 'trust_root_disabled') END;
END;

-- Encrypted manifests retain the exact signed trust snapshot admitted during
-- their write. The insert trigger below closes the read/verify/write race by
-- comparing that snapshot with the current head inside the manifest insert.
ALTER TABLE manifests ADD COLUMN trust_epoch INTEGER
    CHECK (trust_epoch IS NULL OR (trust_epoch > 0 AND trust_epoch <= 9007199254740991));
ALTER TABLE manifests ADD COLUMN trust_body_sha256 TEXT
    CHECK (
        trust_body_sha256 IS NULL
        OR (length(trust_body_sha256) = 64
            AND trust_body_sha256 NOT GLOB '*[^0-9a-f]*')
    );

CREATE TRIGGER encrypted_manifests_trust_before_insert
BEFORE INSERT ON manifests
BEGIN
    SELECT CASE WHEN json_type(NEW.body_json, '$.schema_version') IS NOT 'integer'
                      OR json_extract(NEW.body_json, '$.schema_version') NOT IN (1, 2)
        THEN RAISE(ABORT, 'invalid_manifest_schema') END;
    SELECT CASE WHEN json_extract(NEW.body_json, '$.schema_version') = 2
                      AND (NEW.trust_epoch IS NULL OR NEW.trust_body_sha256 IS NULL)
        THEN RAISE(ABORT, 'encrypted_manifest_trust_required') END;
    SELECT CASE WHEN json_extract(NEW.body_json, '$.schema_version') IS NOT 2
                      AND (NEW.trust_epoch IS NOT NULL OR NEW.trust_body_sha256 IS NOT NULL)
        THEN RAISE(ABORT, 'unexpected_manifest_trust') END;
    SELECT CASE WHEN json_extract(NEW.body_json, '$.schema_version') = 2
                      AND NOT EXISTS (
                          SELECT 1
                            FROM trust_heads head
                            JOIN trust_root_keys root
                              ON root.tenant_id = head.tenant_id
                             AND root.repository_id = head.repository_id
                             AND root.root_key_id = head.root_key_id
                           WHERE head.tenant_id = NEW.tenant_id
                             AND head.repository_id = NEW.repository_id
                             AND head.epoch = NEW.trust_epoch
                             AND head.body_sha256 = NEW.trust_body_sha256
                             AND head.expires_at > unixepoch()
                             AND root.disabled_at IS NULL
                      )
        THEN RAISE(ABORT, 'encrypted_manifest_trust_changed') END;
END;

CREATE TRIGGER trust_heads_monotonic_before_update
BEFORE UPDATE ON trust_heads
BEGIN
    SELECT CASE WHEN NEW.root_key_id != OLD.root_key_id
        THEN RAISE(ABORT, 'trust_root_rebinding') END;
    SELECT CASE WHEN NEW.epoch < OLD.epoch
        THEN RAISE(ABORT, 'trust_epoch_rollback') END;
    SELECT CASE WHEN NEW.epoch = OLD.epoch AND NEW.body_sha256 != OLD.body_sha256
        THEN RAISE(ABORT, 'trust_epoch_conflict') END;
END;

CREATE TRIGGER trust_heads_state_before_insert
BEFORE INSERT ON trust_heads
BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1
          FROM trust_revoked_keys revoked
         WHERE revoked.tenant_id = NEW.tenant_id
           AND revoked.repository_id = NEW.repository_id
           AND NOT EXISTS (
               SELECT 1 FROM json_each(NEW.body_json, '$.revoked_key_ids') item
                WHERE item.value = revoked.key_id
           )
    ) THEN RAISE(ABORT, 'trust_key_revocation_rollback') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1
          FROM trust_revoked_records revoked
         WHERE revoked.tenant_id = NEW.tenant_id
           AND revoked.repository_id = NEW.repository_id
           AND NOT EXISTS (
               SELECT 1 FROM json_each(NEW.body_json, '$.revoked_record_ids') item
                WHERE item.value = revoked.record_id
           )
    ) THEN RAISE(ABORT, 'trust_record_revocation_rollback') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1
          FROM json_each(NEW.body_json, '$.active_producer_keys') active
          JOIN trust_revoked_keys revoked
            ON revoked.tenant_id = NEW.tenant_id
           AND revoked.repository_id = NEW.repository_id
           AND revoked.key_id = json_extract(active.value, '$.key_id')
    ) THEN RAISE(ABORT, 'trust_key_revocation_rollback') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1
          FROM json_each(NEW.body_json, '$.active_producer_keys') active
          JOIN trust_key_history historical
            ON historical.tenant_id = NEW.tenant_id
           AND historical.repository_id = NEW.repository_id
           AND historical.key_id = json_extract(active.value, '$.key_id')
         WHERE historical.producer_id != json_extract(active.value, '$.producer_id')
            OR historical.public_key_json != json(json_extract(active.value, '$.public_key'))
    ) THEN RAISE(ABORT, 'trust_key_rebinding') END;
END;

CREATE TRIGGER trust_heads_state_before_update
BEFORE UPDATE ON trust_heads
WHEN NEW.epoch > OLD.epoch
BEGIN
    SELECT CASE WHEN EXISTS (
        SELECT 1
          FROM trust_revoked_keys revoked
         WHERE revoked.tenant_id = NEW.tenant_id
           AND revoked.repository_id = NEW.repository_id
           AND NOT EXISTS (
               SELECT 1 FROM json_each(NEW.body_json, '$.revoked_key_ids') item
                WHERE item.value = revoked.key_id
           )
    ) THEN RAISE(ABORT, 'trust_key_revocation_rollback') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1
          FROM trust_revoked_records revoked
         WHERE revoked.tenant_id = NEW.tenant_id
           AND revoked.repository_id = NEW.repository_id
           AND NOT EXISTS (
               SELECT 1 FROM json_each(NEW.body_json, '$.revoked_record_ids') item
                WHERE item.value = revoked.record_id
           )
    ) THEN RAISE(ABORT, 'trust_record_revocation_rollback') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1
          FROM json_each(NEW.body_json, '$.active_producer_keys') active
          JOIN trust_revoked_keys revoked
            ON revoked.tenant_id = NEW.tenant_id
           AND revoked.repository_id = NEW.repository_id
           AND revoked.key_id = json_extract(active.value, '$.key_id')
    ) THEN RAISE(ABORT, 'trust_key_revocation_rollback') END;
    SELECT CASE WHEN EXISTS (
        SELECT 1
          FROM json_each(NEW.body_json, '$.active_producer_keys') active
          JOIN trust_key_history historical
            ON historical.tenant_id = NEW.tenant_id
           AND historical.repository_id = NEW.repository_id
           AND historical.key_id = json_extract(active.value, '$.key_id')
         WHERE historical.producer_id != json_extract(active.value, '$.producer_id')
            OR historical.public_key_json != json(json_extract(active.value, '$.public_key'))
    ) THEN RAISE(ABORT, 'trust_key_rebinding') END;
END;

CREATE TRIGGER trust_heads_history_after_insert
AFTER INSERT ON trust_heads
BEGIN
    INSERT OR IGNORE INTO trust_key_history(
        tenant_id, repository_id, key_id, producer_id, public_key_json, first_epoch
    )
    SELECT NEW.tenant_id, NEW.repository_id,
           json_extract(active.value, '$.key_id'),
           json_extract(active.value, '$.producer_id'),
           json(json_extract(active.value, '$.public_key')),
           NEW.epoch
      FROM json_each(NEW.body_json, '$.active_producer_keys') active
     WHERE NOT EXISTS (
         SELECT 1 FROM trust_key_history historical
          WHERE historical.tenant_id = NEW.tenant_id
            AND historical.repository_id = NEW.repository_id
            AND historical.key_id = json_extract(active.value, '$.key_id')
     );
    INSERT OR IGNORE INTO trust_revoked_keys(tenant_id, repository_id, key_id, first_epoch)
    SELECT NEW.tenant_id, NEW.repository_id, item.value, NEW.epoch
      FROM json_each(NEW.body_json, '$.revoked_key_ids') item
     WHERE NOT EXISTS (
         SELECT 1 FROM trust_revoked_keys revoked
          WHERE revoked.tenant_id = NEW.tenant_id
            AND revoked.repository_id = NEW.repository_id
            AND revoked.key_id = item.value
     );
    INSERT OR IGNORE INTO trust_revoked_records(tenant_id, repository_id, record_id, first_epoch)
    SELECT NEW.tenant_id, NEW.repository_id, item.value, NEW.epoch
      FROM json_each(NEW.body_json, '$.revoked_record_ids') item
     WHERE NOT EXISTS (
         SELECT 1 FROM trust_revoked_records revoked
          WHERE revoked.tenant_id = NEW.tenant_id
            AND revoked.repository_id = NEW.repository_id
            AND revoked.record_id = item.value
     );
END;

CREATE TRIGGER trust_heads_history_after_update
AFTER UPDATE ON trust_heads
WHEN NEW.epoch > OLD.epoch
BEGIN
    INSERT OR IGNORE INTO trust_key_history(
        tenant_id, repository_id, key_id, producer_id, public_key_json, first_epoch
    )
    SELECT NEW.tenant_id, NEW.repository_id,
           json_extract(active.value, '$.key_id'),
           json_extract(active.value, '$.producer_id'),
           json(json_extract(active.value, '$.public_key')),
           NEW.epoch
      FROM json_each(NEW.body_json, '$.active_producer_keys') active
     WHERE NOT EXISTS (
         SELECT 1 FROM trust_key_history historical
          WHERE historical.tenant_id = NEW.tenant_id
            AND historical.repository_id = NEW.repository_id
            AND historical.key_id = json_extract(active.value, '$.key_id')
     );
    INSERT OR IGNORE INTO trust_revoked_keys(tenant_id, repository_id, key_id, first_epoch)
    SELECT NEW.tenant_id, NEW.repository_id, item.value, NEW.epoch
      FROM json_each(NEW.body_json, '$.revoked_key_ids') item
     WHERE NOT EXISTS (
         SELECT 1 FROM trust_revoked_keys revoked
          WHERE revoked.tenant_id = NEW.tenant_id
            AND revoked.repository_id = NEW.repository_id
            AND revoked.key_id = item.value
     );
    INSERT OR IGNORE INTO trust_revoked_records(tenant_id, repository_id, record_id, first_epoch)
    SELECT NEW.tenant_id, NEW.repository_id, item.value, NEW.epoch
      FROM json_each(NEW.body_json, '$.revoked_record_ids') item
     WHERE NOT EXISTS (
         SELECT 1 FROM trust_revoked_records revoked
          WHERE revoked.tenant_id = NEW.tenant_id
            AND revoked.repository_id = NEW.repository_id
            AND revoked.record_id = item.value
     );
END;

-- Every durable trust row consumes one metadata unit. The current signed head
-- additionally consumes one unit per KiB of canonical JSON, like manifests.
CREATE TRIGGER trust_root_keys_metadata_quota_before_insert BEFORE INSERT ON trust_root_keys
BEGIN
    SELECT CASE WHEN (
        SELECT used_metadata_units + 1 > metadata_quota_units FROM tenants WHERE id = NEW.tenant_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;
CREATE TRIGGER trust_root_keys_metadata_after_insert AFTER INSERT ON trust_root_keys
BEGIN
    UPDATE tenants SET used_metadata_units = used_metadata_units + 1 WHERE id = NEW.tenant_id;
END;
CREATE TRIGGER trust_root_keys_metadata_after_delete AFTER DELETE ON trust_root_keys
BEGIN
    UPDATE tenants SET used_metadata_units = max(0, used_metadata_units - 1) WHERE id = OLD.tenant_id;
END;

CREATE TRIGGER trust_key_history_metadata_quota_before_insert BEFORE INSERT ON trust_key_history
BEGIN
    SELECT CASE WHEN (
        SELECT used_metadata_units + 1 > metadata_quota_units FROM tenants WHERE id = NEW.tenant_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;
CREATE TRIGGER trust_key_history_metadata_after_insert AFTER INSERT ON trust_key_history
BEGIN
    UPDATE tenants SET used_metadata_units = used_metadata_units + 1 WHERE id = NEW.tenant_id;
END;
CREATE TRIGGER trust_key_history_metadata_after_delete AFTER DELETE ON trust_key_history
BEGIN
    UPDATE tenants SET used_metadata_units = max(0, used_metadata_units - 1) WHERE id = OLD.tenant_id;
END;

CREATE TRIGGER trust_revoked_keys_metadata_quota_before_insert BEFORE INSERT ON trust_revoked_keys
BEGIN
    SELECT CASE WHEN (
        SELECT used_metadata_units + 1 > metadata_quota_units FROM tenants WHERE id = NEW.tenant_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;
CREATE TRIGGER trust_revoked_keys_metadata_after_insert AFTER INSERT ON trust_revoked_keys
BEGIN
    UPDATE tenants SET used_metadata_units = used_metadata_units + 1 WHERE id = NEW.tenant_id;
END;
CREATE TRIGGER trust_revoked_keys_metadata_after_delete AFTER DELETE ON trust_revoked_keys
BEGIN
    UPDATE tenants SET used_metadata_units = max(0, used_metadata_units - 1) WHERE id = OLD.tenant_id;
END;

CREATE TRIGGER trust_revoked_records_metadata_quota_before_insert BEFORE INSERT ON trust_revoked_records
BEGIN
    SELECT CASE WHEN (
        SELECT used_metadata_units + 1 > metadata_quota_units FROM tenants WHERE id = NEW.tenant_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;
CREATE TRIGGER trust_revoked_records_metadata_after_insert AFTER INSERT ON trust_revoked_records
BEGIN
    UPDATE tenants SET used_metadata_units = used_metadata_units + 1 WHERE id = NEW.tenant_id;
END;
CREATE TRIGGER trust_revoked_records_metadata_after_delete AFTER DELETE ON trust_revoked_records
BEGIN
    UPDATE tenants SET used_metadata_units = max(0, used_metadata_units - 1) WHERE id = OLD.tenant_id;
END;

CREATE TRIGGER trust_heads_metadata_quota_before_insert BEFORE INSERT ON trust_heads
BEGIN
    -- INSERT ... ON CONFLICT DO UPDATE runs BEFORE INSERT triggers even when
    -- the row becomes an update. Leave that case to the update quota trigger,
    -- which subtracts the old head before charging the replacement.
    SELECT CASE WHEN NOT EXISTS (
        SELECT 1 FROM trust_heads existing
         WHERE existing.tenant_id = NEW.tenant_id
           AND existing.repository_id = NEW.repository_id
    ) AND (
        SELECT used_metadata_units + 1 + ((length(CAST(NEW.body_json AS BLOB)) + 1023) / 1024)
               > metadata_quota_units FROM tenants WHERE id = NEW.tenant_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;
CREATE TRIGGER trust_heads_metadata_after_insert AFTER INSERT ON trust_heads
BEGIN
    UPDATE tenants
       SET used_metadata_units = used_metadata_units
           + 1 + ((length(CAST(NEW.body_json AS BLOB)) + 1023) / 1024)
     WHERE id = NEW.tenant_id;
END;
CREATE TRIGGER trust_heads_metadata_quota_before_update BEFORE UPDATE ON trust_heads
BEGIN
    SELECT CASE WHEN (
        SELECT used_metadata_units
               - 1 - ((length(CAST(OLD.body_json AS BLOB)) + 1023) / 1024)
               + 1 + ((length(CAST(NEW.body_json AS BLOB)) + 1023) / 1024)
               > metadata_quota_units FROM tenants WHERE id = NEW.tenant_id
    ) THEN RAISE(ABORT, 'metadata_quota_exceeded') END;
END;
CREATE TRIGGER trust_heads_metadata_after_update AFTER UPDATE ON trust_heads
BEGIN
    UPDATE tenants
       SET used_metadata_units = max(
           0,
           used_metadata_units
           - 1 - ((length(CAST(OLD.body_json AS BLOB)) + 1023) / 1024)
           + 1 + ((length(CAST(NEW.body_json AS BLOB)) + 1023) / 1024)
       )
     WHERE id = NEW.tenant_id;
END;
CREATE TRIGGER trust_heads_metadata_after_delete AFTER DELETE ON trust_heads
BEGIN
    UPDATE tenants
       SET used_metadata_units = max(
           0,
           used_metadata_units - 1 - ((length(CAST(OLD.body_json AS BLOB)) + 1023) / 1024)
       )
     WHERE id = OLD.tenant_id;
END;
