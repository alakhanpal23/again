import { env } from "cloudflare:workers";
import { applyD1Migrations } from "cloudflare:test";
import { describe, expect, it } from "vitest";

const GENERATION_A = "1".repeat(32);
const GENERATION_B = "2".repeat(32);

describe("generation protocol migrations", () => {
  it("installs generation guards on the supported fresh path", async () => {
    const migrations = await env.DB.prepare(
      "SELECT name FROM d1_migrations ORDER BY id",
    ).all<{ name: string }>();
    expect(migrations.results.map((row) => row.name)).toEqual([
      "0001_initial.sql",
      "0002_trust_bundles.sql",
      "0003_retention_lifecycle.sql",
      "0004_repository_generation_protocol.sql",
      "0005_commit_freshness.sql",
      "0006_blob_incarnations.sql",
      "0007_r2_object_identities.sql",
    ]);
    await expectGenerationTriggers(env.DB);
  });

  it("upgrades a populated compatible v3 database and enforces generation atomically", async () => {
    const v3 = env.TEST_MIGRATIONS.filter((migration) =>
      ["0001_initial.sql", "0002_trust_bundles.sql", "0003_retention_lifecycle.sql"].includes(
        migration.name,
      ),
    );
    const v4 = env.TEST_MIGRATIONS.filter(
      (migration) => migration.name === "0004_repository_generation_protocol.sql",
    );
    expect(v3).toHaveLength(3);
    expect(v4).toHaveLength(1);
    await applyD1Migrations(env.MIGRATION_DB, v3);

    await env.MIGRATION_DB.batch([
      env.MIGRATION_DB.prepare(
        `INSERT INTO tenants(id, name, quota_bytes, created_at)
         VALUES ('tenant-upgrade', 'upgrade', 1048576, 1700000000)`,
      ),
      env.MIGRATION_DB.prepare(
        `INSERT INTO repositories(tenant_id, id, generation_id, created_at)
         VALUES ('tenant-upgrade', 'repo-a', ?, 1700000000)`,
      ).bind(GENERATION_A),
      env.MIGRATION_DB.prepare(
        `INSERT INTO repositories(tenant_id, id, generation_id, created_at)
         VALUES ('tenant-upgrade', 'repo-b', ?, 1700000000)`,
      ).bind(GENERATION_B),
    ]);

    await applyD1Migrations(env.MIGRATION_DB, v4);
    await expectGenerationTriggers(env.MIGRATION_DB);

    await env.MIGRATION_DB.prepare(
      `INSERT INTO trust_root_keys(
         tenant_id, repository_id, root_key_id, public_key_hex, created_at
       ) VALUES ('tenant-upgrade', 'repo-b', 'root-1', ?, 1700000000)`,
    )
      .bind("a".repeat(64))
      .run();
    const staleBody = JSON.stringify({
      schema_version: 1,
      generation_id: GENERATION_A,
      active_producer_keys: [],
      revoked_key_ids: [],
      revoked_record_ids: [],
    });
    await expect(
      env.MIGRATION_DB.prepare(
        `INSERT INTO trust_heads(
           tenant_id, repository_id, epoch, root_key_id, body_sha256, body_json,
           issued_at, expires_at, updated_at
         ) VALUES ('tenant-upgrade', 'repo-b', 1, 'root-1', ?, ?,
                   1700000000, 1700000300, 1700000000)`,
      )
        .bind("b".repeat(64), staleBody)
        .run(),
    ).rejects.toThrow(/repository_generation_mismatch/);
  });

  it("upgrades populated v5 blobs with a legacy incarnation and fences replacements", async () => {
    const throughV5 = env.TEST_MIGRATIONS.filter((migration) =>
      [
        "0001_initial.sql",
        "0002_trust_bundles.sql",
        "0003_retention_lifecycle.sql",
        "0004_repository_generation_protocol.sql",
        "0005_commit_freshness.sql",
      ].includes(migration.name),
    );
    const v6 = env.TEST_MIGRATIONS.filter(
      (migration) => migration.name === "0006_blob_incarnations.sql",
    );
    expect(throughV5).toHaveLength(5);
    expect(v6).toHaveLength(1);
    await applyD1Migrations(env.MIGRATION_DB, throughV5);

    const digest = "d".repeat(64);
    await env.MIGRATION_DB.batch([
      env.MIGRATION_DB.prepare(
        `INSERT INTO tenants(id, name, quota_bytes, created_at)
         VALUES ('tenant-upgrade-v6', 'upgrade-v6', 1048576, 1700000000)`,
      ),
      env.MIGRATION_DB.prepare(
        `INSERT INTO repositories(tenant_id, id, generation_id, created_at)
         VALUES ('tenant-upgrade-v6', 'repo-a', ?, 1700000000)`,
      ).bind(GENERATION_A),
      env.MIGRATION_DB.prepare(
        `INSERT INTO producer_keys(
           tenant_id, repository_id, key_id, producer_id, public_key_hex, created_at
         ) VALUES ('tenant-upgrade-v6', 'repo-a', 'key-1', 'producer-1', ?, 1700000000)`,
      ).bind("a".repeat(64)),
      env.MIGRATION_DB.prepare(
        `INSERT INTO blobs(
           tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
           reconcile_attempts, next_reconcile_at
         ) VALUES ('tenant-upgrade-v6', 'repo-a', ?, 0, 'ready',
                   1700000000, 1700000000, 0, 1700000000)`,
      ).bind(digest),
    ]);

    await applyD1Migrations(env.MIGRATION_DB, v6);
    expect(
      await env.MIGRATION_DB.prepare(
        `SELECT repository_generation_history_limit, blob_orphan_candidate_limit,
                blob_orphan_repository_limit,
                trust_security_reserve_limit, trust_security_repository_limit,
                audit_event_limit, audit_partition_limit
           FROM tenants WHERE id = 'tenant-upgrade-v6'`,
      ).first<{
        repository_generation_history_limit: number;
        blob_orphan_candidate_limit: number;
        blob_orphan_repository_limit: number;
        trust_security_reserve_limit: number;
        trust_security_repository_limit: number;
        audit_event_limit: number;
        audit_partition_limit: number;
      }>(),
    ).toEqual({
      repository_generation_history_limit: 1024,
      blob_orphan_candidate_limit: 4096,
      blob_orphan_repository_limit: 1024,
      trust_security_reserve_limit: 131072,
      trust_security_repository_limit: 32768,
      audit_event_limit: 65536,
      audit_partition_limit: 4096,
    });
    await expect(
      env.MIGRATION_DB.prepare(
        `UPDATE tenants SET blob_orphan_candidate_limit = 65537
          WHERE id = 'tenant-upgrade-v6'`,
      ).run(),
    ).rejects.toThrow(/CHECK constraint failed/);
    expect(
      await env.MIGRATION_DB.prepare(
        `SELECT incarnation_id FROM blobs
          WHERE tenant_id = 'tenant-upgrade-v6' AND repository_id = 'repo-a' AND digest = ?`,
      )
        .bind(digest)
        .first<{ incarnation_id: string }>(),
    ).toEqual({ incarnation_id: "0".repeat(32) });

    await expect(
      env.MIGRATION_DB.prepare(
        `UPDATE blobs SET incarnation_id = ?
          WHERE tenant_id = 'tenant-upgrade-v6' AND repository_id = 'repo-a' AND digest = ?`,
      )
        .bind("1".repeat(32), digest)
        .run(),
    ).rejects.toThrow(/blob_incarnation_is_immutable/);

    await env.MIGRATION_DB.prepare(
      `DELETE FROM blobs
        WHERE tenant_id = 'tenant-upgrade-v6' AND repository_id = 'repo-a' AND digest = ?`,
    )
      .bind(digest)
      .run();
    await env.MIGRATION_DB.prepare(
      `INSERT INTO blobs(
         tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
         reconcile_attempts, next_reconcile_at, incarnation_id
       ) VALUES ('tenant-upgrade-v6', 'repo-a', ?, 0, 'ready',
                 1700000001, 1700000001, 0, 1700000001, ?)`,
    )
      .bind(digest, "2".repeat(32))
      .run();
    expect(
      await env.MIGRATION_DB.prepare(
        `SELECT incarnation_id FROM blobs
          WHERE tenant_id = 'tenant-upgrade-v6' AND repository_id = 'repo-a' AND digest = ?`,
      )
        .bind(digest)
        .first<{ incarnation_id: string }>(),
    ).toEqual({ incarnation_id: "2".repeat(32) });

    await expect(
      env.MIGRATION_DB.prepare(
        `INSERT INTO manifests(
           tenant_id, repository_id, request_key, record_id, body_sha256, body_json,
           state, producer_id, key_id, stdout_digest, stdout_size_bytes,
           stderr_digest, stderr_size_bytes, created_at, expires_at
         ) VALUES ('tenant-upgrade-v6', 'repo-a', ?, 'legacy-record', ?,
                   '{"schema_version":1}', 'ready', 'producer-1', 'key-1',
                   ?, 0, ?, 0, 1700000000, 1700000300)`,
      )
        .bind("b".repeat(64), "c".repeat(64), digest, digest)
        .run(),
    ).rejects.toThrow(/manifest_schema_v2_required/);

    await expect(
      env.MIGRATION_DB.prepare(
        `UPDATE producer_keys SET public_key_hex = ?
          WHERE tenant_id = 'tenant-upgrade-v6' AND repository_id = 'repo-a' AND key_id = 'key-1'`,
      )
        .bind("f".repeat(64))
        .run(),
    ).rejects.toThrow(/producer_key_rebinding/);
  });

  it("upgrades v6 rows compatibly and strictly fences complete R2 upload identities", async () => {
    const throughV6 = env.TEST_MIGRATIONS.filter(
      (migration) => migration.name !== "0007_r2_object_identities.sql",
    );
    const v7 = env.TEST_MIGRATIONS.filter(
      (migration) => migration.name === "0007_r2_object_identities.sql",
    );
    expect(throughV6).toHaveLength(6);
    expect(v7).toHaveLength(1);
    await applyD1Migrations(env.MIGRATION_DB, throughV6);

    const legacyDigest = "d".repeat(64);
    const pendingDigest = "e".repeat(64);
    const readyDigest = "f".repeat(64);
    await env.MIGRATION_DB.batch([
      env.MIGRATION_DB.prepare(
        `INSERT INTO tenants(id, name, quota_bytes, created_at)
         VALUES ('tenant-upgrade-v7', 'upgrade-v7', 1048576, 1700000000)`,
      ),
      env.MIGRATION_DB.prepare(
        `INSERT INTO repositories(tenant_id, id, generation_id, created_at)
         VALUES ('tenant-upgrade-v7', 'repo-a', ?, 1700000000)`,
      ).bind(GENERATION_A),
      env.MIGRATION_DB.prepare(
        `INSERT INTO blobs(
           tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
           reconcile_attempts, next_reconcile_at, incarnation_id
         ) VALUES ('tenant-upgrade-v7', 'repo-a', ?, 0, 'ready',
                   1700000000, 1700000000, 0, 1700000000, ?)`,
      ).bind(legacyDigest, "1".repeat(32)),
      env.MIGRATION_DB.prepare(
        `INSERT INTO blobs(
           tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
           reconcile_attempts, next_reconcile_at, incarnation_id
         ) VALUES ('tenant-upgrade-v7', 'repo-a', ?, 0, 'pending',
                   1700000000, 1700000000, 0, 1700000000, ?)`,
      ).bind(pendingDigest, "2".repeat(32)),
    ]);

    await applyD1Migrations(env.MIGRATION_DB, v7);
    expect(
      await env.MIGRATION_DB.prepare(
        `SELECT r2_key, r2_version, r2_etag, r2_sha256 FROM blobs
          WHERE tenant_id = 'tenant-upgrade-v7' AND repository_id = 'repo-a'
            AND digest = ?`,
      )
        .bind(legacyDigest)
        .first<{
          r2_key: string | null;
          r2_version: string | null;
          r2_etag: string | null;
          r2_sha256: string | null;
        }>(),
    ).toEqual({ r2_key: null, r2_version: null, r2_etag: null, r2_sha256: null });

    const identityTriggers = await env.MIGRATION_DB.prepare(
      `SELECT name FROM sqlite_master
        WHERE type = 'trigger' AND name LIKE 'blobs_r2_identity_%'
        ORDER BY name`,
    ).all<{ name: string }>();
    expect(identityTriggers.results.map((row) => row.name)).toEqual([
      "blobs_r2_identity_immutable_before_update",
      "blobs_r2_identity_ready_before_insert",
      "blobs_r2_identity_ready_before_update",
      "blobs_r2_identity_tuple_before_insert",
      "blobs_r2_identity_tuple_before_update",
    ]);

    // The migration preserves legacy ready/all-NULL rows for lifecycle work,
    // but does not allow them to be silently backfilled while still ready.
    await env.MIGRATION_DB.prepare(
      `UPDATE blobs SET updated_at = 1700000001
        WHERE tenant_id = 'tenant-upgrade-v7' AND repository_id = 'repo-a' AND digest = ?`,
    )
      .bind(legacyDigest)
      .run();
    await expect(
      env.MIGRATION_DB.prepare(
        `UPDATE blobs
            SET r2_key = ?, r2_version = ?, r2_etag = ?, r2_sha256 = ?
          WHERE tenant_id = 'tenant-upgrade-v7' AND repository_id = 'repo-a' AND digest = ?`,
      )
        .bind("v1/key", "version-1", "etag-1", "a".repeat(64), legacyDigest)
        .run(),
    ).rejects.toThrow(/blob_r2_identity_is_immutable/);

    await expect(
      env.MIGRATION_DB.prepare(
        `INSERT INTO blobs(
           tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
           reconcile_attempts, next_reconcile_at, incarnation_id
         ) VALUES ('tenant-upgrade-v7', 'repo-a', ?, 0, 'ready',
                   1700000000, 1700000000, 0, 1700000000, ?)`,
      )
        .bind(readyDigest, "3".repeat(32))
        .run(),
    ).rejects.toThrow(/blob_r2_identity_required/);

    await env.MIGRATION_DB.prepare(
      `INSERT INTO blobs(
         tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
         reconcile_attempts, next_reconcile_at, incarnation_id,
         r2_key, r2_version, r2_etag, r2_sha256
       ) VALUES ('tenant-upgrade-v7', 'repo-a', ?, 0, 'ready',
                 1700000000, 1700000000, 0, 1700000000, ?, ?, ?, ?, ?)`,
    )
      .bind(
        readyDigest,
        "3".repeat(32),
        `v1/tenant-upgrade-v7/repo-a/${GENERATION_A}/blake3/${readyDigest}/${"3".repeat(32)}`,
        "version-ready",
        "etag-ready",
        "c".repeat(64),
      )
      .run();

    await expect(
      env.MIGRATION_DB.prepare(
        `INSERT INTO blobs(
           tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
           reconcile_attempts, next_reconcile_at, incarnation_id, r2_key
         ) VALUES ('tenant-upgrade-v7', 'repo-a', ?, 0, 'pending',
                   1700000000, 1700000000, 0, 1700000000, ?, 'v1/partial')`,
      )
        .bind("8".repeat(64), "8".repeat(32))
        .run(),
    ).rejects.toThrow(/blob_r2_identity_is_partial/);

    await expect(
      env.MIGRATION_DB.prepare(
        `UPDATE blobs SET r2_key = ?
          WHERE tenant_id = 'tenant-upgrade-v7' AND repository_id = 'repo-a' AND digest = ?`,
      )
        .bind("v1/partial", pendingDigest)
        .run(),
    ).rejects.toThrow(/blob_r2_identity_is_partial/);

    const firstIdentity = {
      key: `v1/tenant-upgrade-v7/repo-a/${GENERATION_A}/blake3/${pendingDigest}/${"2".repeat(32)}`,
      version: "version-1",
      etag: "etag-1",
      sha256: "a".repeat(64),
    };
    await env.MIGRATION_DB.prepare(
      `UPDATE blobs
          SET state = 'ready', r2_key = ?, r2_version = ?, r2_etag = ?, r2_sha256 = ?
        WHERE tenant_id = 'tenant-upgrade-v7' AND repository_id = 'repo-a' AND digest = ?
          AND state = 'pending'`,
    )
      .bind(
        firstIdentity.key,
        firstIdentity.version,
        firstIdentity.etag,
        firstIdentity.sha256,
        pendingDigest,
      )
      .run();
    expect(
      await env.MIGRATION_DB.prepare(
        `SELECT state, r2_key, r2_version, r2_etag, r2_sha256 FROM blobs
          WHERE tenant_id = 'tenant-upgrade-v7' AND repository_id = 'repo-a' AND digest = ?`,
      )
        .bind(pendingDigest)
        .first(),
    ).toEqual({
      state: "ready",
      r2_key: firstIdentity.key,
      r2_version: firstIdentity.version,
      r2_etag: firstIdentity.etag,
      r2_sha256: firstIdentity.sha256,
    });

    await expect(
      env.MIGRATION_DB.prepare(
        `UPDATE blobs SET r2_etag = 'etag-rebound'
          WHERE tenant_id = 'tenant-upgrade-v7' AND repository_id = 'repo-a' AND digest = ?`,
      )
        .bind(pendingDigest)
        .run(),
    ).rejects.toThrow(/blob_r2_identity_is_immutable/);

    // Repair atomically leaves ready and clears the old tuple.  A subsequent
    // promotion must establish a new complete tuple in the pending->ready
    // transition.
    await env.MIGRATION_DB.prepare(
      `UPDATE blobs
          SET state = 'pending', r2_key = NULL, r2_version = NULL,
              r2_etag = NULL, r2_sha256 = NULL
        WHERE tenant_id = 'tenant-upgrade-v7' AND repository_id = 'repo-a' AND digest = ?`,
    )
      .bind(pendingDigest)
      .run();
    await expect(
      env.MIGRATION_DB.prepare(
        `UPDATE blobs SET state = 'ready'
          WHERE tenant_id = 'tenant-upgrade-v7' AND repository_id = 'repo-a' AND digest = ?`,
      )
        .bind(pendingDigest)
        .run(),
    ).rejects.toThrow(/blob_r2_identity_required/);
    await env.MIGRATION_DB.prepare(
      `UPDATE blobs
          SET state = 'ready', r2_key = ?, r2_version = ?, r2_etag = ?, r2_sha256 = ?
        WHERE tenant_id = 'tenant-upgrade-v7' AND repository_id = 'repo-a' AND digest = ?`,
    )
      .bind(firstIdentity.key, "version-2", "etag-2", "b".repeat(64), pendingDigest)
      .run();

    await expect(
      env.MIGRATION_DB.prepare(
        `INSERT INTO blobs(
           tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
           reconcile_attempts, next_reconcile_at, incarnation_id,
           r2_key, r2_version, r2_etag, r2_sha256
         ) VALUES ('tenant-upgrade-v7', 'repo-a', ?, 0, 'pending',
                   1700000000, 1700000000, 0, 1700000000, ?, '', 'v', 'e', ?)`,
      )
        .bind("9".repeat(64), "9".repeat(32), "A".repeat(64))
        .run(),
    ).rejects.toThrow(/CHECK constraint failed/);
  });
});

async function expectGenerationTriggers(database: D1Database): Promise<void> {
  const triggers = await database
    .prepare(
      `SELECT name FROM sqlite_master
        WHERE type = 'trigger' AND name IN (
          'trust_heads_generation_before_insert',
          'trust_heads_generation_before_update',
          'encrypted_manifests_generation_before_insert',
          'encrypted_manifests_generation_before_update'
        ) ORDER BY name`,
    )
    .all<{ name: string }>();
  expect(triggers.results.map((row) => row.name)).toEqual([
    "encrypted_manifests_generation_before_insert",
    "encrypted_manifests_generation_before_update",
    "trust_heads_generation_before_insert",
    "trust_heads_generation_before_update",
  ]);
}
