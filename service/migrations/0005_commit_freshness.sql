PRAGMA foreign_keys = ON;

-- Parsing and signature verification intentionally happen before the D1
-- transaction and may be delayed by the client, WebCrypto, or the platform.
-- These guards make D1's commit-time clock authoritative so already-expired
-- signed state can never be admitted even if the Worker's earlier sample was
-- fresh.
CREATE TRIGGER trust_heads_fresh_before_insert
BEFORE INSERT ON trust_heads
BEGIN
    SELECT CASE WHEN NEW.expires_at <= unixepoch()
        THEN RAISE(ABORT, 'expired_trust_bundle') END;
END;

CREATE TRIGGER trust_heads_fresh_before_update
BEFORE UPDATE ON trust_heads
BEGIN
    SELECT CASE WHEN NEW.expires_at <= unixepoch()
        THEN RAISE(ABORT, 'expired_trust_bundle') END;
END;

CREATE TRIGGER manifests_fresh_before_insert
BEFORE INSERT ON manifests
BEGIN
    SELECT CASE WHEN NEW.expires_at <= unixepoch()
        THEN RAISE(ABORT, 'expired_manifest') END;
END;
