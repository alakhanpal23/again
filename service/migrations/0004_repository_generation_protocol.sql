PRAGMA foreign_keys = ON;

-- Generation binding was added after the lifecycle schema. Existing pre-alpha
-- databases may upgrade only when every stored trust head and encrypted
-- manifest already carries the live repository generation. Re-signing either
-- body in a migration would destroy its cryptographic provenance, so an
-- incompatible database must be cleaned or recreated deliberately.
CREATE TABLE migration_0004_generation_guard (
    must_be_zero INTEGER NOT NULL CHECK (must_be_zero = 0)
) STRICT;
INSERT INTO migration_0004_generation_guard(must_be_zero)
SELECT CASE WHEN EXISTS (
    SELECT 1
      FROM trust_heads head
      JOIN repositories repository
        ON repository.tenant_id = head.tenant_id
       AND repository.id = head.repository_id
     WHERE json_type(head.body_json, '$.generation_id') IS NOT 'text'
        OR json_extract(head.body_json, '$.generation_id') != repository.generation_id
) OR EXISTS (
    SELECT 1
      FROM manifests manifest
      JOIN repositories repository
        ON repository.tenant_id = manifest.tenant_id
       AND repository.id = manifest.repository_id
     WHERE json_extract(manifest.body_json, '$.schema_version') = 2
       AND (
         json_type(manifest.body_json, '$.generation_id') IS NOT 'text'
         OR json_extract(manifest.body_json, '$.generation_id') != repository.generation_id
       )
) THEN 1 ELSE 0 END;
DROP TABLE migration_0004_generation_guard;

-- These triggers close the read/verify/write ABA window inside the exact D1
-- statement that stores signed protocol state. The application-level request
-- header and generation-scoped write lease provide earlier rejection and
-- fence non-protocol mutations; these guards remain authoritative even if a
-- lease expires or another writer bypasses the Worker.
CREATE TRIGGER trust_heads_generation_before_insert
BEFORE INSERT ON trust_heads
BEGIN
    SELECT CASE WHEN json_type(NEW.body_json, '$.generation_id') IS NOT 'text'
                      OR NOT EXISTS (
                          SELECT 1 FROM repositories repository
                           WHERE repository.tenant_id = NEW.tenant_id
                             AND repository.id = NEW.repository_id
                             AND repository.generation_id =
                                 json_extract(NEW.body_json, '$.generation_id')
                             AND repository.deleted_at IS NULL
                      )
        THEN RAISE(ABORT, 'repository_generation_mismatch') END;
END;

CREATE TRIGGER trust_heads_generation_before_update
BEFORE UPDATE ON trust_heads
BEGIN
    SELECT CASE WHEN json_type(NEW.body_json, '$.generation_id') IS NOT 'text'
                      OR NOT EXISTS (
                          SELECT 1 FROM repositories repository
                           WHERE repository.tenant_id = NEW.tenant_id
                             AND repository.id = NEW.repository_id
                             AND repository.generation_id =
                                 json_extract(NEW.body_json, '$.generation_id')
                             AND repository.deleted_at IS NULL
                      )
        THEN RAISE(ABORT, 'repository_generation_mismatch') END;
END;

CREATE TRIGGER encrypted_manifests_generation_before_insert
BEFORE INSERT ON manifests
WHEN json_extract(NEW.body_json, '$.schema_version') = 2
BEGIN
    SELECT CASE WHEN json_type(NEW.body_json, '$.generation_id') IS NOT 'text'
                      OR NOT EXISTS (
                          SELECT 1 FROM repositories repository
                           WHERE repository.tenant_id = NEW.tenant_id
                             AND repository.id = NEW.repository_id
                             AND repository.generation_id =
                                 json_extract(NEW.body_json, '$.generation_id')
                             AND repository.deleted_at IS NULL
                      )
        THEN RAISE(ABORT, 'repository_generation_mismatch') END;
END;

CREATE TRIGGER encrypted_manifests_generation_before_update
BEFORE UPDATE ON manifests
WHEN json_extract(NEW.body_json, '$.schema_version') = 2
BEGIN
    SELECT CASE WHEN json_type(NEW.body_json, '$.generation_id') IS NOT 'text'
                      OR NOT EXISTS (
                          SELECT 1 FROM repositories repository
                           WHERE repository.tenant_id = NEW.tenant_id
                             AND repository.id = NEW.repository_id
                             AND repository.generation_id =
                                 json_extract(NEW.body_json, '$.generation_id')
                             AND repository.deleted_at IS NULL
                      )
        THEN RAISE(ABORT, 'repository_generation_mismatch') END;
END;
