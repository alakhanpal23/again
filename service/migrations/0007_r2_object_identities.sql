PRAGMA foreign_keys = ON;

-- Bundle reads must bind the unconsumed R2 body stream to the exact upload
-- that was validated before the final D1 fence.  These fields intentionally
-- remain nullable for ready rows created before this migration: those legacy
-- rows can still be reconciled or deleted, but they are not bundle-eligible.
-- Every new ready row and every transition into ready must carry the complete
-- tuple recorded from the successful R2 PUT/readback.
ALTER TABLE blobs ADD COLUMN r2_key TEXT CHECK (
    r2_key IS NULL OR (
        length(CAST(r2_key AS BLOB)) BETWEEN 1 AND 1024
        AND instr(r2_key, char(0)) = 0
    )
);

ALTER TABLE blobs ADD COLUMN r2_version TEXT CHECK (
    r2_version IS NULL OR (
        length(CAST(r2_version AS BLOB)) BETWEEN 1 AND 1024
        AND instr(r2_version, char(0)) = 0
    )
);

ALTER TABLE blobs ADD COLUMN r2_etag TEXT CHECK (
    r2_etag IS NULL OR (
        length(CAST(r2_etag AS BLOB)) BETWEEN 1 AND 1024
        AND instr(r2_etag, char(0)) = 0
    )
);

ALTER TABLE blobs ADD COLUMN r2_sha256 TEXT CHECK (
    r2_sha256 IS NULL OR (
        length(r2_sha256) = 64
        AND r2_sha256 NOT GLOB '*[^0-9a-f]*'
    )
);

-- A partial identity must never be observable.  An all-NULL tuple represents
-- either a pending upload or a pre-v7 legacy row; otherwise every component
-- is present.
CREATE TRIGGER blobs_r2_identity_tuple_before_insert
BEFORE INSERT ON blobs
BEGIN
    SELECT CASE WHEN
        (NEW.r2_key IS NULL)
        + (NEW.r2_version IS NULL)
        + (NEW.r2_etag IS NULL)
        + (NEW.r2_sha256 IS NULL)
        NOT IN (0, 4)
    THEN RAISE(ABORT, 'blob_r2_identity_is_partial') END;
END;

CREATE TRIGGER blobs_r2_identity_tuple_before_update
BEFORE UPDATE OF r2_key, r2_version, r2_etag, r2_sha256 ON blobs
BEGIN
    SELECT CASE WHEN
        (NEW.r2_key IS NULL)
        + (NEW.r2_version IS NULL)
        + (NEW.r2_etag IS NULL)
        + (NEW.r2_sha256 IS NULL)
        NOT IN (0, 4)
    THEN RAISE(ABORT, 'blob_r2_identity_is_partial') END;
END;

-- Fresh ready rows cannot use the legacy all-NULL exception.
CREATE TRIGGER blobs_r2_identity_ready_before_insert
BEFORE INSERT ON blobs
WHEN NEW.state = 'ready'
BEGIN
    SELECT CASE WHEN NEW.r2_key IS NULL
        THEN RAISE(ABORT, 'blob_r2_identity_required') END;
END;

-- Preserve existing ready/all-NULL rows without allowing a new row to enter
-- ready without an upload identity.  Updating unrelated lifecycle metadata on
-- a legacy ready row remains possible.
CREATE TRIGGER blobs_r2_identity_ready_before_update
BEFORE UPDATE OF state ON blobs
WHEN NEW.state = 'ready' AND OLD.state != 'ready'
BEGIN
    SELECT CASE WHEN NEW.r2_key IS NULL
        THEN RAISE(ABORT, 'blob_r2_identity_required') END;
END;

-- An upload identity may only be established or replaced while the row is
-- pending.  Once ready, its tuple is immutable until a separate state change
-- fences all readers; a repair can then replace the tuple while pending and
-- promote the row atomically with the new identity.
CREATE TRIGGER blobs_r2_identity_immutable_before_update
BEFORE UPDATE OF r2_key, r2_version, r2_etag, r2_sha256 ON blobs
WHEN (
    NEW.r2_key IS NOT OLD.r2_key
    OR NEW.r2_version IS NOT OLD.r2_version
    OR NEW.r2_etag IS NOT OLD.r2_etag
    OR NEW.r2_sha256 IS NOT OLD.r2_sha256
)
BEGIN
    SELECT CASE WHEN OLD.state != 'pending' AND NEW.state != 'pending'
        THEN RAISE(ABORT, 'blob_r2_identity_is_immutable') END;
END;
