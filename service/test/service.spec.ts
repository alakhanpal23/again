import { blake3 } from "@noble/hashes/blake3.js";
import { env } from "cloudflare:workers";
import { createExecutionContext, waitOnExecutionContext } from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import worker from "../src/index";
import { canonicalManifestBytes, parseManifest, type RemoteCacheManifest } from "../src/manifest";
import { bytesToHex, sha256Hex } from "../src/util";
import canonicalWireFixture from "./fixtures/manifest-v1-canonical.json";
import manifestWireFixture from "./fixtures/manifest-v1.json";

const ORIGIN = "https://cache.again.invalid";
const REPOSITORY = "repo-a";
const TENANT = "tenant-a";
const TOKEN_ID = "token-admin";
const TOKEN_SECRET = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const BEARER = `ag1.${TOKEN_ID}.${TOKEN_SECRET}`;
const textEncoder = new TextEncoder();

beforeEach(async () => {
  const objects = await env.BLOBS.list();
  if (objects.objects.length > 0) await env.BLOBS.delete(objects.objects.map((object) => object.key));
  await env.DB.batch([
    env.DB.prepare("DELETE FROM manifest_conflicts"),
    env.DB.prepare("DELETE FROM audit_events"),
    env.DB.prepare("DELETE FROM manifests"),
    env.DB.prepare("DELETE FROM blobs"),
    env.DB.prepare("DELETE FROM producer_keys"),
    env.DB.prepare("DELETE FROM rate_windows"),
    env.DB.prepare("DELETE FROM repositories"),
    env.DB.prepare("DELETE FROM auth_tokens"),
    env.DB.prepare("DELETE FROM tenants"),
  ]);
  await seedTenant(TENANT, TOKEN_ID, TOKEN_SECRET, REPOSITORY);
});

describe("service boundary", () => {
  it("matches the published BLAKE3 empty-input vector", () => {
    expect(bytesToHex(blake3(new Uint8Array()))).toBe(
      "af1349b9f5f9a1a6a0404dea36dcc9499bcb25c9adc112b7cc9a93cae41f3262",
    );
  });

  it("matches the Rust manifest-v1 canonical signing vector", () => {
    expect(bytesToHex(canonicalManifestBytes(manifestWireFixture as RemoteCacheManifest))).toBe(
      canonicalWireFixture.hex_chunks.join(""),
    );
  });

  it("matches the Rust manifest-v1 rejection boundary", () => {
    const parse = (manifest: unknown) =>
      parseManifest(manifest as Record<string, unknown>, 150);

    const unknownTopLevel = copyManifest(manifestWireFixture as RemoteCacheManifest);
    (unknownTopLevel as unknown as Record<string, unknown>).requires_attestation = true;
    expect(() => parse(unknownTopLevel)).toThrow();

    const unknownNested = copyManifest(manifestWireFixture as RemoteCacheManifest);
    (unknownNested.stdout as unknown as Record<string, unknown>).compression = "zstd";
    expect(() => parse(unknownNested)).toThrow();

    const unicodeDigest = copyManifest(manifestWireFixture as RemoteCacheManifest);
    unicodeDigest.request_key = `€${"0".repeat(61)}`;
    expect(() => parse(unicodeDigest)).toThrow();

    const longLived = copyManifest(manifestWireFixture as RemoteCacheManifest);
    longLived.expires_at_unix_seconds = longLived.created_at_unix_seconds + 30 * 24 * 60 * 60 + 1;
    expect(() => parse(longLived)).toThrow();

    const unsafeTimestamp = copyManifest(manifestWireFixture as RemoteCacheManifest);
    unsafeTimestamp.created_at_unix_seconds = Number.MAX_SAFE_INTEGER + 1;
    unsafeTimestamp.expires_at_unix_seconds = Number.MAX_SAFE_INTEGER + 2;
    expect(() => parse(unsafeTimestamp)).toThrow();

    const shortSignature = copyManifest(manifestWireFixture as RemoteCacheManifest);
    shortSignature.signature.signature = shortSignature.signature.signature.slice(1);
    expect(() => parse(shortSignature)).toThrow();

    const c1Control = copyManifest(manifestWireFixture as RemoteCacheManifest);
    c1Control.record_id = "record\u0080";
    expect(() => parse(c1Control)).toThrow();

    const byteOrderMark = copyManifest(manifestWireFixture as RemoteCacheManifest);
    byteOrderMark.record_id = "record\ufeff";
    expect(parse(byteOrderMark).record_id).toBe("record\ufeff");
  });

  it("serves health without auth and fails authentication generically", async () => {
    const health = await call("/v1/health");
    expect(health.status).toBe(200);
    await expect(health.json()).resolves.toMatchObject({ status: "ok", schema_version: 1 });

    const missing = await call(`/v1/repositories/${REPOSITORY}/stats`);
    const malformed = await call(`/v1/repositories/${REPOSITORY}/stats`, {
      headers: { authorization: "Bearer definitely-not-a-token" },
    });
    expect(missing.status).toBe(401);
    expect(malformed.status).toBe(401);
    await expect(missing.json()).resolves.toMatchObject({ error: { code: "unauthorized" } });
    await expect(malformed.json()).resolves.toMatchObject({ error: { code: "unauthorized" } });
  });

  it("creates a repository idempotently without allowing a scoped token to escape", async () => {
    const first = await call("/v1/repositories", jsonRequest({ repository_id: "repo-b" }));
    const second = await call("/v1/repositories", jsonRequest({ repository_id: "repo-b" }));
    expect(first.status).toBe(201);
    expect(second.status).toBe(200);

    await seedToken(TENANT, "token-scoped", "B".repeat(43), REPOSITORY, "admin");
    const denied = await call(
      "/v1/repositories",
      jsonRequest(
        { repository_id: "repo-c" },
        `ag1.token-scoped.${"B".repeat(43)}`,
      ),
    );
    expect(denied.status).toBe(404);
  });

  it("charges valid credentials before permission rejection", async () => {
    const secret = "D".repeat(43);
    await seedToken(TENANT, "token-read-only", secret, null, "read");
    const denied = await call(
      "/v1/repositories",
      jsonRequest({ repository_id: "repo-denied" }, `ag1.token-read-only.${secret}`),
    );
    expect(denied.status).toBe(403);
    const row = await env.DB.prepare(
      "SELECT request_count FROM rate_windows WHERE token_id = ?",
    )
      .bind("token-read-only")
      .first<{ request_count: number }>();
    expect(row?.request_count).toBe(1);
  });

  it("stores immutable verified blobs and isolates identical paths across tenants", async () => {
    const bytes = textEncoder.encode("hello from tenant a");
    const digest = bytesToHex(blake3(bytes));
    const missingLength = await call(
      `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
      {
        method: "PUT",
        headers: {
          authorization: `Bearer ${BEARER}`,
          "content-type": "application/octet-stream",
        },
        body: bytes,
      },
      true,
    );
    expect(missingLength.status).toBe(411);

    const badDigest = "0".repeat(64);
    const mismatch = await putBlob(bytes, badDigest);
    expect(mismatch.status).toBe(422);

    const created = await putBlob(bytes, digest);
    expect(created.status).toBe(201);
    expect(created.headers.get("etag")).toBe(`"${digest}"`);
    expect((await putBlob(bytes, digest)).status).toBe(204);

    const fetched = await call(`/v1/repositories/${REPOSITORY}/blobs/${digest}`, authRequest());
    expect(fetched.status).toBe(200);
    expect(new Uint8Array(await fetched.arrayBuffer())).toEqual(bytes);
    const head = await call(
      `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
      authRequest(undefined, "HEAD"),
    );
    expect(head.status).toBe(200);
    expect(head.headers.get("content-length")).toBe(String(bytes.length));

    const otherSecret = "C".repeat(43);
    await seedTenant("tenant-b", "token-b", otherSecret, REPOSITORY);
    const hidden = await call(`/v1/repositories/${REPOSITORY}/blobs/${digest}`, {
      headers: { authorization: `Bearer ag1.token-b.${otherSecret}` },
    });
    expect(hidden.status).toBe(404);
  });

  it("enforces quota atomically and releases it after unreferenced deletion", async () => {
    await env.DB.prepare("UPDATE tenants SET quota_bytes = 4 WHERE id = ?").bind(TENANT).run();
    const bytes = textEncoder.encode("12345");
    const digest = bytesToHex(blake3(bytes));
    const rejected = await putBlob(bytes, digest);
    expect(rejected.status).toBe(413);
    const tenant = await env.DB.prepare("SELECT used_bytes FROM tenants WHERE id = ?")
      .bind(TENANT)
      .first<{ used_bytes: number }>();
    expect(tenant?.used_bytes).toBe(0);

    await env.DB.prepare("UPDATE tenants SET quota_bytes = 10 WHERE id = ?").bind(TENANT).run();
    expect((await putBlob(bytes, digest)).status).toBe(201);
    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
          authRequest(undefined, "DELETE"),
        )
      ).status,
    ).toBe(204);
    const after = await env.DB.prepare("SELECT used_bytes FROM tenants WHERE id = ?")
      .bind(TENANT)
      .first<{ used_bytes: number }>();
    expect(after?.used_bytes).toBe(0);
  });

  it("rejects excess manifest metadata and releases its accounted units on removal", async () => {
    const fixture = await prepareManifestFixture();
    const bodyJson = JSON.stringify(fixture.manifest);
    const manifestUnits = 1 + Math.ceil(textEncoder.encode(bodyJson).byteLength / 1024);
    const before = await metadataUsage();

    await env.DB.prepare("UPDATE tenants SET metadata_quota_units = ? WHERE id = ?")
      .bind(before + manifestUnits - 1, TENANT)
      .run();
    await expect(manifestInsert(fixture.manifest, bodyJson).run()).rejects.toThrow(
      /metadata_quota_exceeded/,
    );
    expect(await metadataUsage()).toBe(before);

    await env.DB.prepare("UPDATE tenants SET metadata_quota_units = ? WHERE id = ?")
      .bind(before + manifestUnits, TENANT)
      .run();
    await manifestInsert(fixture.manifest, bodyJson).run();
    expect(await metadataUsage()).toBe(before + manifestUnits);

    await env.DB.prepare(
      "DELETE FROM manifests WHERE tenant_id = ? AND repository_id = ? AND request_key = ?",
    )
      .bind(TENANT, REPOSITORY, fixture.manifest.request_key)
      .run();
    expect(await metadataUsage()).toBe(before);
  });

  it("maps metadata quota exhaustion to a bounded API error", async () => {
    const used = await metadataUsage();
    await env.DB.prepare("UPDATE tenants SET metadata_quota_units = ? WHERE id = ?")
      .bind(used, TENANT)
      .run();
    const rejected = await call(
      "/v1/repositories",
      jsonRequest({ repository_id: "repo-over-metadata-quota" }),
    );
    expect(rejected.status).toBe(413);
    await expect(rejected.json()).resolves.toMatchObject({
      error: { code: "metadata_quota_exceeded" },
    });
    expect(await metadataUsage()).toBe(used);
  });

  it("lets compatible concurrent same-digest uploads converge at the exact byte quota", async () => {
    const bytes = textEncoder.encode("exact quota convergence");
    const digest = bytesToHex(blake3(bytes));
    await env.DB.prepare("UPDATE tenants SET quota_bytes = ? WHERE id = ?")
      .bind(bytes.byteLength, TENANT)
      .run();

    const gatedEnv: Env = {
      BLOBS: env.BLOBS,
      DB: databaseWithConcurrentInitialBlobReads(env.DB, 2),
    };
    const responses = await Promise.all([
      putBlobUsingEnv(gatedEnv, bytes, digest),
      putBlobUsingEnv(gatedEnv, bytes, digest),
    ]);
    const statuses = responses.map((response) => response.status);
    expect(statuses.every((status) => status === 201 || status === 204)).toBe(true);
    expect(statuses).toContain(201);

    const row = await env.DB.prepare(
      `SELECT count(*) AS count, max(state) AS state
         FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(TENANT, REPOSITORY, digest)
      .first<{ count: number; state: string }>();
    expect(row).toMatchObject({ count: 1, state: "ready" });
    const tenant = await env.DB.prepare("SELECT used_bytes FROM tenants WHERE id = ?")
      .bind(TENANT)
      .first<{ used_bytes: number }>();
    expect(tenant?.used_bytes).toBe(bytes.byteLength);
  });

  it("repairs both sides of an interrupted R2/D1 upload without releasing quota", async () => {
    const bytes = textEncoder.encode("interrupted upload");
    const digest = bytesToHex(blake3(bytes));
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      `INSERT INTO blobs(
         tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at
       ) VALUES (?, ?, ?, ?, 'pending', ?, ?)`,
    )
      .bind(TENANT, REPOSITORY, digest, bytes.byteLength, now, now)
      .run();
    await env.BLOBS.put(`v1/${TENANT}/${REPOSITORY}/blake3/${digest}`, bytes, {
      httpMetadata: { contentType: "application/octet-stream" },
      customMetadata: { blake3: digest, size_bytes: String(bytes.byteLength) },
    });

    expect((await putBlob(bytes, digest)).status).toBe(201);
    const recovered = await env.DB.prepare(
      "SELECT state FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = ?",
    )
      .bind(TENANT, REPOSITORY, digest)
      .first<{ state: string }>();
    expect(recovered?.state).toBe("ready");
    const accounted = await env.DB.prepare("SELECT used_bytes FROM tenants WHERE id = ?")
      .bind(TENANT)
      .first<{ used_bytes: number }>();
    expect(accounted?.used_bytes).toBe(bytes.byteLength);

    await env.BLOBS.delete(`v1/${TENANT}/${REPOSITORY}/blake3/${digest}`);
    expect((await putBlob(bytes, digest)).status).toBe(201);
    const repaired = await env.BLOBS.head(`v1/${TENANT}/${REPOSITORY}/blake3/${digest}`);
    expect(repaired?.customMetadata?.blake3).toBe(digest);
  });

  it("hashes stored R2 bytes even when forged metadata and size match", async () => {
    const bytes = textEncoder.encode("integrity-good");
    const digest = bytesToHex(blake3(bytes));
    expect((await putBlob(bytes, digest)).status).toBe(201);

    const forged = textEncoder.encode("integrity-evil");
    expect(forged.byteLength).toBe(bytes.byteLength);
    await env.BLOBS.put(`v1/${TENANT}/${REPOSITORY}/blake3/${digest}`, forged, {
      customMetadata: { blake3: digest, size_bytes: String(forged.byteLength) },
    });
    const response = await call(
      `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
      authRequest(),
    );
    expect(response.status).toBe(409);
    const row = await env.DB.prepare(
      "SELECT state FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = ?",
    )
      .bind(TENANT, REPOSITORY, digest)
      .first<{ state: string }>();
    expect(row?.state).toBe("quarantined");
  });

  it("refuses promotion when R2 retains different bytes after a successful put", async () => {
    const bytes = textEncoder.encode("promotion-good");
    const forged = textEncoder.encode("promotion-evil");
    expect(forged.byteLength).toBe(bytes.byteLength);
    const digest = bytesToHex(blake3(bytes));
    const corruptingEnv: Env = {
      DB: env.DB,
      BLOBS: bucketThatCorruptsPut(env.BLOBS, forged),
    };

    const response = await putBlobUsingEnv(corruptingEnv, bytes, digest);
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "blob_integrity_failure" },
    });
    const row = await env.DB.prepare(
      "SELECT state FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = ?",
    )
      .bind(TENANT, REPOSITORY, digest)
      .first<{ state: string }>();
    expect(row?.state).toBe("quarantined");
  });

  it("resumes an interrupted deletion and refuses to delete an active pending reservation", async () => {
    const bytes = textEncoder.encode("delete recovery");
    const digest = bytesToHex(blake3(bytes));
    expect((await putBlob(bytes, digest)).status).toBe(201);
    await env.DB.prepare(
      `UPDATE blobs SET state = 'deleting', updated_at = ?
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(Math.floor(Date.now() / 1000), TENANT, REPOSITORY, digest)
      .run();
    const resumed = await call(
      `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
      authRequest(undefined, "DELETE"),
    );
    expect(resumed.status).toBe(204);
    expect(await env.BLOBS.head(`v1/${TENANT}/${REPOSITORY}/blake3/${digest}`)).toBeNull();

    const pendingBytes = textEncoder.encode("reserved but not uploaded");
    const pendingDigest = bytesToHex(blake3(pendingBytes));
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      `INSERT INTO blobs(
         tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at
       ) VALUES (?, ?, ?, ?, 'pending', ?, ?)`,
    )
      .bind(TENANT, REPOSITORY, pendingDigest, pendingBytes.byteLength, now, now)
      .run();
    const refused = await call(
      `/v1/repositories/${REPOSITORY}/blobs/${pendingDigest}`,
      authRequest(undefined, "DELETE"),
    );
    expect(refused.status).toBe(409);
    const reservation = await env.DB.prepare(
      "SELECT state FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = ?",
    )
      .bind(TENANT, REPOSITORY, pendingDigest)
      .first<{ state: string }>();
    expect(reservation?.state).toBe("pending");
  });

  it("delays abandoned-pending cancellation, then lets the scheduled handler finish it", async () => {
    const bytes = textEncoder.encode("abandoned reservation");
    const digest = bytesToHex(blake3(bytes));
    const stale = Math.floor(Date.now() / 1000) - 3601;
    await env.DB.prepare(
      `INSERT INTO blobs(
         tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
         reconcile_attempts, next_reconcile_at
       ) VALUES (?, ?, ?, ?, 'pending', ?, ?, 0, ?)`,
    )
      .bind(TENANT, REPOSITORY, digest, bytes.byteLength, stale, stale, stale)
      .run();
    const accepted = await call(
      `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
      authRequest(undefined, "DELETE"),
    );
    expect(accepted.status).toBe(202);
    const tombstone = await env.DB.prepare(
      "SELECT state, delete_not_before FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = ?",
    )
      .bind(TENANT, REPOSITORY, digest)
      .first<{ state: string; delete_not_before: number }>();
    expect(tombstone?.state).toBe("deleting");
    expect(tombstone?.delete_not_before).toBeGreaterThan(Math.floor(Date.now() / 1000));

    await env.DB.prepare(
      `UPDATE blobs SET delete_not_before = 0, next_reconcile_at = 0
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(TENANT, REPOSITORY, digest)
      .run();
    await runScheduled();
    const removed = await env.DB.prepare(
      "SELECT state FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = ?",
    )
      .bind(TENANT, REPOSITORY, digest)
      .first<{ state: string }>();
    expect(removed).toBeNull();
  });

  it("advances missing pending rows so they cannot starve later recoverable work", async () => {
    const due = Math.floor(Date.now() / 1000) - 1;
    const statements: D1PreparedStatement[] = [];
    for (let index = 1; index <= 64; index += 1) {
      const digest = index.toString(16).padStart(64, "0");
      statements.push(
        env.DB.prepare(
          `INSERT INTO blobs(
             tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
             reconcile_attempts, next_reconcile_at
           ) VALUES (?, ?, ?, 0, 'pending', ?, ?, 0, ?)`,
        ).bind(TENANT, REPOSITORY, digest, index, due, due),
      );
    }
    await env.DB.batch(statements);
    const bytes = textEncoder.encode("recover after the first page");
    const digest = bytesToHex(blake3(bytes));
    await env.DB.prepare(
      `INSERT INTO blobs(
         tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
         reconcile_attempts, next_reconcile_at
       ) VALUES (?, ?, ?, ?, 'pending', 1000, ?, 0, ?)`,
    )
      .bind(TENANT, REPOSITORY, digest, bytes.byteLength, due, due)
      .run();
    await env.BLOBS.put(`v1/${TENANT}/${REPOSITORY}/blake3/${digest}`, bytes, {
      customMetadata: { blake3: digest, size_bytes: String(bytes.byteLength) },
    });

    await runScheduled();
    const afterFirstPage = await env.DB.prepare(
      "SELECT state FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = ?",
    )
      .bind(TENANT, REPOSITORY, digest)
      .first<{ state: string }>();
    expect(afterFirstPage?.state).toBe("pending");
    await runScheduled();
    const recovered = await env.DB.prepare(
      "SELECT state FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = ?",
    )
      .bind(TENANT, REPOSITORY, digest)
      .first<{ state: string }>();
    expect(recovered?.state).toBe("ready");
  });

  it("backs off a due row after an R2 exception", async () => {
    const bytes = textEncoder.encode("faulted reconciliation");
    const digest = bytesToHex(blake3(bytes));
    const due = Math.floor(Date.now() / 1000) - 1;
    await env.DB.prepare(
      `INSERT INTO blobs(
         tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
         reconcile_attempts, next_reconcile_at
       ) VALUES (?, ?, ?, ?, 'pending', ?, ?, 0, ?)`,
    )
      .bind(TENANT, REPOSITORY, digest, bytes.byteLength, due, due, due)
      .run();
    const failingBucket = new Proxy(env.BLOBS, {
      get(target, property) {
        if (property === "get") {
          return async (): Promise<never> => {
            throw new Error("injected R2 failure");
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    await runScheduledUsingEnv({ DB: env.DB, BLOBS: failingBucket });
    const row = await env.DB.prepare(
      `SELECT reconcile_attempts, next_reconcile_at FROM blobs
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(TENANT, REPOSITORY, digest)
      .first<{ reconcile_attempts: number; next_reconcile_at: number }>();
    expect(row?.reconcile_attempts).toBe(1);
    expect(row?.next_reconcile_at).toBeGreaterThan(Math.floor(Date.now() / 1000));
  });

  it("emits one transition audit when scheduled reconciliations overlap", async () => {
    const bytes = textEncoder.encode("overlap");
    const digest = bytesToHex(blake3(bytes));
    const due = Math.floor(Date.now() / 1000) - 1;
    await env.DB.prepare(
      `INSERT INTO blobs(
         tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
         reconcile_attempts, next_reconcile_at
       ) VALUES (?, ?, ?, ?, 'pending', ?, ?, 0, ?)`,
    )
      .bind(TENANT, REPOSITORY, digest, bytes.byteLength, due, due, due)
      .run();
    await env.BLOBS.put(`v1/${TENANT}/${REPOSITORY}/blake3/${digest}`, bytes, {
      customMetadata: { blake3: digest, size_bytes: String(bytes.byteLength) },
    });
    await Promise.all([runScheduled(), runScheduled()]);
    const audits = await env.DB.prepare(
      `SELECT count(*) AS count FROM audit_events
        WHERE tenant_id = ? AND repository_id = ?
          AND action = 'blob.reconcile' AND outcome = 'promoted'`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{ count: number }>();
    expect(audits?.count).toBe(1);
  });

  it("immutably binds producer keys and revokes them", async () => {
    const keys = await generateSigningKeys();
    expect((await registerProducer(keys.publicKeyHex)).status).toBe(201);
    expect((await registerProducer(keys.publicKeyHex)).status).toBe(204);
    const otherKeys = await generateSigningKeys();
    expect((await registerProducer(otherKeys.publicKeyHex)).status).toBe(409);
    const revoked = await call(
      `/v1/repositories/${REPOSITORY}/producers/key-1`,
      authRequest(undefined, "DELETE"),
    );
    expect(revoked.status).toBe(204);
    expect((await registerProducer(keys.publicKeyHex)).status).toBe(409);
  });

  it("accepts only bound, signed, shareable manifests with ready blobs", async () => {
    const fixture = await prepareManifestFixture();
    const created = await putManifest(fixture.manifest);
    expect(created.status).toBe(201);
    expect((await putManifest(fixture.manifest)).status).toBe(204);

    const fetched = await call(
      `/v1/repositories/${REPOSITORY}/manifests/${fixture.manifest.request_key}`,
      authRequest(),
    );
    expect(fetched.status).toBe(200);
    await expect(fetched.json()).resolves.toEqual(fixture.manifest);

    const invalidSignature = copyManifest(fixture.manifest);
    invalidSignature.request_key = "8".repeat(64);
    invalidSignature.signature.signature[0] = (invalidSignature.signature.signature[0] ?? 0) ^ 1;
    expect((await putManifest(invalidSignature)).status).toBe(422);

    const wrongTenant = copyManifest(fixture.manifest);
    wrongTenant.tenant_id = "tenant-other";
    wrongTenant.request_key = "7".repeat(64);
    await signManifest(wrongTenant, fixture.privateKey);
    expect((await putManifest(wrongTenant)).status).toBe(422);

    const secret = copyManifest(fixture.manifest);
    secret.request_key = "6".repeat(64);
    secret.privacy.secret_tainted = true;
    await signManifest(secret, fixture.privateKey);
    expect((await putManifest(secret)).status).toBe(422);
  });

  it("matches Rust's UTF-8, control, whitespace, and Unicode-scalar identifier rules", async () => {
    const fixture = await prepareManifestFixture();

    const tooLong = copyManifest(fixture.manifest);
    tooLong.request_key = "8".repeat(64);
    tooLong.record_id = "😀".repeat(65);
    await signManifest(tooLong, fixture.privateKey);
    const tooLongResponse = await putManifest(tooLong);
    expect(tooLongResponse.status).toBe(400);
    await expect(tooLongResponse.json()).resolves.toMatchObject({
      error: { code: "invalid_identifier" },
    });

    const loneSurrogate = copyManifest(fixture.manifest);
    loneSurrogate.request_key = "9".repeat(64);
    loneSurrogate.record_id = "\ud800";
    await signManifest(loneSurrogate, fixture.privateKey);
    const surrogateResponse = await putManifest(loneSurrogate);
    expect(surrogateResponse.status).toBe(400);
    await expect(surrogateResponse.json()).resolves.toMatchObject({
      error: { code: "invalid_identifier" },
    });

    const c1Control = copyManifest(fixture.manifest);
    c1Control.request_key = "b".repeat(64);
    c1Control.record_id = "record\u0080";
    await signManifest(c1Control, fixture.privateKey);
    const c1Response = await putManifest(c1Control);
    expect(c1Response.status).toBe(400);
    await expect(c1Response.json()).resolves.toMatchObject({
      error: { code: "invalid_identifier" },
    });

    const byteOrderMark = copyManifest(fixture.manifest);
    byteOrderMark.request_key = "c".repeat(64);
    byteOrderMark.record_id = "record\ufeff";
    await signManifest(byteOrderMark, fixture.privateKey);
    expect((await putManifest(byteOrderMark)).status).toBe(201);

    const boundary = copyManifest(fixture.manifest);
    boundary.request_key = "a".repeat(64);
    boundary.record_id = "😀".repeat(64);
    await signManifest(boundary, fixture.privateKey);
    expect((await putManifest(boundary)).status).toBe(201);
  });

  it("enforces ready-blob preconditions inside the manifest insert transaction", async () => {
    const fixture = await prepareManifestFixture();
    await env.DB.prepare(
      `UPDATE blobs SET state = 'deleting'
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(TENANT, REPOSITORY, fixture.manifest.stdout.digest)
      .run();
    await expect(
      env.DB.prepare(
        `INSERT INTO manifests(
           tenant_id, repository_id, request_key, record_id, body_sha256, body_json,
           state, producer_id, key_id, stdout_digest, stdout_size_bytes,
           stderr_digest, stderr_size_bytes, created_at, expires_at
         ) VALUES (?, ?, ?, ?, ?, ?, 'ready', ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          TENANT,
          REPOSITORY,
          fixture.manifest.request_key,
          fixture.manifest.record_id,
          "a".repeat(64),
          JSON.stringify(fixture.manifest),
          fixture.manifest.producer_id,
          fixture.manifest.signature.key_id,
          fixture.manifest.stdout.digest,
          fixture.manifest.stdout.size_bytes,
          fixture.manifest.stderr.digest,
          fixture.manifest.stderr.size_bytes,
          fixture.manifest.created_at_unix_seconds,
          fixture.manifest.expires_at_unix_seconds,
        )
        .run(),
    ).rejects.toThrow(/blob_unavailable/);
    const count = await env.DB.prepare("SELECT count(*) AS count FROM manifests")
      .first<{ count: number }>();
    expect(count?.count).toBe(0);
  });

  it("quarantines divergent same-key manifests instead of choosing a winner", async () => {
    const fixture = await prepareManifestFixture();
    expect((await putManifest(fixture.manifest)).status).toBe(201);

    const divergent = copyManifest(fixture.manifest);
    divergent.record_id = "record-divergent";
    divergent.policy_digest = "9".repeat(64);
    await signManifest(divergent, fixture.privateKey);
    const conflict = await putManifest(divergent);
    expect(conflict.status).toBe(409);
    const hidden = await call(
      `/v1/repositories/${REPOSITORY}/manifests/${fixture.manifest.request_key}`,
      authRequest(),
    );
    expect(hidden.status).toBe(404);

    const row = await env.DB.prepare(
      "SELECT state FROM manifests WHERE tenant_id = ? AND repository_id = ? AND request_key = ?",
    )
      .bind(TENANT, REPOSITORY, fixture.manifest.request_key)
      .first<{ state: string }>();
    expect(row?.state).toBe("quarantined");
    const conflictCount = await env.DB.prepare("SELECT count(*) AS count FROM manifest_conflicts")
      .first<{ count: number }>();
    expect(conflictCount?.count).toBe(1);
  });

  it("quarantines the existing manifest when a record id is rebound to another request key", async () => {
    const fixture = await prepareManifestFixture();
    expect((await putManifest(fixture.manifest)).status).toBe(201);

    const rebound = copyManifest(fixture.manifest);
    rebound.request_key = "b".repeat(64);
    await signManifest(rebound, fixture.privateKey);
    const conflict = await putManifest(rebound);
    expect(conflict.status).toBe(409);
    await expect(conflict.json()).resolves.toMatchObject({
      error: { code: "manifest_conflict" },
    });

    const rows = await env.DB.prepare(
      `SELECT request_key, state FROM manifests
        WHERE tenant_id = ? AND repository_id = ? ORDER BY request_key`,
    )
      .bind(TENANT, REPOSITORY)
      .all<{ request_key: string; state: string }>();
    expect(rows.results).toEqual([
      { request_key: fixture.manifest.request_key, state: "quarantined" },
    ]);
    const conflictRow = await env.DB.prepare(
      `SELECT request_key FROM manifest_conflicts
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{ request_key: string }>();
    expect(conflictRow?.request_key).toBe(fixture.manifest.request_key);
  });

  it("hides manifests immediately after key revocation", async () => {
    const fixture = await prepareManifestFixture();
    expect((await putManifest(fixture.manifest)).status).toBe(201);
    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}/producers/key-1`,
          authRequest(undefined, "DELETE"),
        )
      ).status,
    ).toBe(204);
    const fetched = await call(
      `/v1/repositories/${REPOSITORY}/manifests/${fixture.manifest.request_key}`,
      authRequest(),
    );
    expect(fetched.status).toBe(404);
  });

  it("requires manifest deletion before blob deletion and exposes privacy-safe audit/stats", async () => {
    const fixture = await prepareManifestFixture();
    expect((await putManifest(fixture.manifest)).status).toBe(201);
    const referenced = await call(
      `/v1/repositories/${REPOSITORY}/blobs/${fixture.manifest.stdout.digest}`,
      authRequest(undefined, "DELETE"),
    );
    expect(referenced.status).toBe(409);

    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}/manifests/${fixture.manifest.request_key}`,
          authRequest(undefined, "DELETE"),
        )
      ).status,
    ).toBe(204);
    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}/blobs/${fixture.manifest.stdout.digest}`,
          authRequest(undefined, "DELETE"),
        )
      ).status,
    ).toBe(204);

    const audit = await call(
      `/v1/repositories/${REPOSITORY}/audit?limit=100`,
      authRequest(),
    );
    expect(audit.status).toBe(200);
    const auditText = await audit.text();
    expect(auditText).not.toContain("hello stdout");
    expect(auditText).not.toContain(fixture.manifest.request_key);
    expect(JSON.parse(auditText)).toMatchObject({ events: expect.any(Array) });

    const stats = await call(`/v1/repositories/${REPOSITORY}/stats`, authRequest());
    expect(stats.status).toBe(200);
    await expect(stats.json()).resolves.toMatchObject({
      ready_manifests: 0,
      pending_blobs: 0,
      deleting_blobs: 0,
      quarantined_manifests: 0,
      used_metadata_units: expect.any(Number),
      metadata_quota_units: expect.any(Number),
    });
  });

  it("enforces the persisted per-token rate window", async () => {
    const now = Math.floor(Date.now() / 1000);
    const windowStart = now - (now % 60);
    await env.DB.prepare(
      "INSERT INTO rate_windows(token_id, window_start, request_count) VALUES (?, ?, ?)",
    )
      .bind(TOKEN_ID, windowStart, 600)
      .run();
    const limited = await call(`/v1/repositories/${REPOSITORY}/stats`, authRequest());
    expect(limited.status).toBe(429);
  });
});

async function seedTenant(
  tenantId: string,
  tokenId: string,
  secret: string,
  repositoryId: string,
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await env.DB.batch([
    env.DB.prepare(
      "INSERT INTO tenants(id, name, quota_bytes, created_at) VALUES (?, ?, ?, ?)",
    ).bind(tenantId, tenantId, 64 * 1024 * 1024, now),
    env.DB.prepare(
      "INSERT INTO repositories(tenant_id, id, created_at) VALUES (?, ?, ?)",
    ).bind(tenantId, repositoryId, now),
  ]);
  await seedToken(tenantId, tokenId, secret, null, "admin,read,write,delete,audit");
}

async function seedToken(
  tenantId: string,
  tokenId: string,
  secret: string,
  repositoryScope: string | null,
  permissions: string,
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    `INSERT INTO auth_tokens(
       id, tenant_id, subject, secret_sha256, repository_scope,
       permissions, created_at, expires_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?)`,
  )
    .bind(
      tokenId,
      tenantId,
      `${tokenId}-subject`,
      await sha256Hex(secret),
      repositoryScope,
      permissions,
      now,
      now + 3600,
    )
    .run();
}

async function call(path: string, init?: RequestInit, stripAutoLength = false): Promise<Response> {
  return callUsingEnv(env, path, init, stripAutoLength);
}

async function callUsingEnv(
  runtimeEnv: Env,
  path: string,
  init?: RequestInit,
  stripAutoLength = false,
): Promise<Response> {
  const request = new Request(`${ORIGIN}${path}`, init);
  if (stripAutoLength) request.headers.delete("content-length");
  const ctx = createExecutionContext();
  const response = await worker.fetch(request, runtimeEnv, ctx);
  await waitOnExecutionContext(ctx);
  return response;
}

function authRequest(body?: BodyInit, method = "GET"): RequestInit {
  const init: RequestInit = { method, headers: { authorization: `Bearer ${BEARER}` } };
  if (body !== undefined) init.body = body;
  return init;
}

function jsonRequest(value: unknown, bearer = BEARER, method = "POST"): RequestInit {
  return {
    method,
    headers: {
      authorization: `Bearer ${bearer}`,
      "content-type": "application/json",
    },
    body: JSON.stringify(value),
  };
}

async function putBlob(bytes: Uint8Array, digest: string): Promise<Response> {
  return putBlobUsingEnv(env, bytes, digest);
}

async function putBlobUsingEnv(
  runtimeEnv: Env,
  bytes: Uint8Array,
  digest: string,
): Promise<Response> {
  return callUsingEnv(runtimeEnv, `/v1/repositories/${REPOSITORY}/blobs/${digest}`, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${BEARER}`,
      "content-type": "application/octet-stream",
      "content-length": String(bytes.byteLength),
    },
    body: bytes,
  });
}

function databaseWithConcurrentInitialBlobReads(
  database: D1Database,
  participants: number,
): D1Database {
  let arrivals = 0;
  let release = (): void => {};
  const gate = new Promise<void>((resolve) => {
    release = resolve;
  });

  const wrapStatement = (
    statement: D1PreparedStatement,
    interceptInitialBlobRead: boolean,
  ): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...values: unknown[]) =>
            wrapStatement(target.bind(...values), interceptInitialBlobRead);
        }
        if (property === "first") {
          return async (columnName?: string) => {
            const result =
              columnName === undefined ? await target.first() : await target.first(columnName);
            if (interceptInitialBlobRead && arrivals < participants && result === null) {
              arrivals += 1;
              if (arrivals === participants) release();
              await gate;
            }
            return result;
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });

  return new Proxy(database, {
    get(target, property) {
      if (property === "prepare") {
        return (query: string) =>
          wrapStatement(
            target.prepare(query),
            query.includes("SELECT size_bytes, state, updated_at") && query.includes("FROM blobs"),
          );
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function bucketThatCorruptsPut(bucket: R2Bucket, forged: Uint8Array): R2Bucket {
  return new Proxy(bucket, {
    get(target, property) {
      if (property === "put") {
        return (
          key: string,
          _value: ReadableStream | ArrayBuffer | ArrayBufferView | string | null | Blob,
          options?: R2PutOptions,
        ) => target.put(key, forged, options);
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

async function metadataUsage(): Promise<number> {
  const row = await env.DB.prepare("SELECT used_metadata_units FROM tenants WHERE id = ?")
    .bind(TENANT)
    .first<{ used_metadata_units: number }>();
  if (row === null) throw new Error("seed tenant is missing");
  return row.used_metadata_units;
}

function manifestInsert(
  manifest: RemoteCacheManifest,
  bodyJson: string,
): D1PreparedStatement {
  return env.DB.prepare(
    `INSERT INTO manifests(
       tenant_id, repository_id, request_key, record_id, body_sha256, body_json,
       state, producer_id, key_id, stdout_digest, stdout_size_bytes,
       stderr_digest, stderr_size_bytes, created_at, expires_at
     ) VALUES (?, ?, ?, ?, ?, ?, 'ready', ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    TENANT,
    REPOSITORY,
    manifest.request_key,
    manifest.record_id,
    "a".repeat(64),
    bodyJson,
    manifest.producer_id,
    manifest.signature.key_id,
    manifest.stdout.digest,
    manifest.stdout.size_bytes,
    manifest.stderr.digest,
    manifest.stderr.size_bytes,
    manifest.created_at_unix_seconds,
    manifest.expires_at_unix_seconds,
  );
}

async function registerProducer(publicKeyHex: string): Promise<Response> {
  return call(
    `/v1/repositories/${REPOSITORY}/producers/key-1`,
    jsonRequest({ producer_id: "producer-1", public_key_hex: publicKeyHex }, BEARER, "PUT"),
  );
}

async function generateSigningKeys(): Promise<{
  privateKey: CryptoKey;
  publicKeyHex: string;
}> {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, ["sign", "verify"]);
  if (!("privateKey" in pair)) throw new Error("Ed25519 key generation did not return a key pair");
  const rawPublicKey = await crypto.subtle.exportKey("raw", pair.publicKey);
  if (!(rawPublicKey instanceof ArrayBuffer)) throw new Error("Ed25519 public key was not raw bytes");
  return {
    privateKey: pair.privateKey,
    publicKeyHex: bytesToHex(new Uint8Array(rawPublicKey)),
  };
}

async function prepareManifestFixture(): Promise<{
  manifest: RemoteCacheManifest;
  privateKey: CryptoKey;
}> {
  const keys = await generateSigningKeys();
  expect((await registerProducer(keys.publicKeyHex)).status).toBe(201);
  const stdout = textEncoder.encode("hello stdout");
  const stderr = new Uint8Array();
  const stdoutDigest = bytesToHex(blake3(stdout));
  const stderrDigest = bytesToHex(blake3(stderr));
  expect((await putBlob(stdout, stdoutDigest)).status).toBe(201);
  expect((await putBlob(stderr, stderrDigest)).status).toBe(201);
  const now = Math.floor(Date.now() / 1000);
  const manifest: RemoteCacheManifest = {
    schema_version: 1,
    record_id: "record-1",
    tenant_id: TENANT,
    repository_id: REPOSITORY,
    request_key: "1".repeat(64),
    policy_digest: "2".repeat(64),
    execution_profile_digest: "3".repeat(64),
    platform_digest: "4".repeat(64),
    image_digest: "5".repeat(64),
    stdout: { digest: stdoutDigest, size_bytes: stdout.byteLength },
    stderr: { digest: stderrDigest, size_bytes: stderr.byteLength },
    producer_id: "producer-1",
    created_at_unix_seconds: now - 1,
    expires_at_unix_seconds: now + 3600,
    privacy: {
      classification: "internal",
      shareability: "repository",
      secret_tainted: false,
    },
    signature: {
      schema_version: 1,
      algorithm: "ed25519",
      key_id: "key-1",
      signature: Array.from({ length: 64 }, () => 0),
    },
  };
  await signManifest(manifest, keys.privateKey);
  return { manifest, privateKey: keys.privateKey };
}

async function signManifest(manifest: RemoteCacheManifest, privateKey: CryptoKey): Promise<void> {
  manifest.signature.signature = Array.from(
    new Uint8Array(
      await crypto.subtle.sign("Ed25519", privateKey, canonicalManifestBytes(manifest)),
    ),
  );
}

async function putManifest(manifest: RemoteCacheManifest): Promise<Response> {
  return call(
    `/v1/repositories/${REPOSITORY}/manifests/${manifest.request_key}`,
    jsonRequest(manifest, BEARER, "PUT"),
  );
}

function copyManifest(manifest: RemoteCacheManifest): RemoteCacheManifest {
  return structuredClone(manifest);
}

async function runScheduled(): Promise<void> {
  return runScheduledUsingEnv(env);
}

async function runScheduledUsingEnv(runtimeEnv: Env): Promise<void> {
  const ctx = createExecutionContext();
  worker.scheduled(
    {
      scheduledTime: Date.now(),
      cron: "*/15 * * * *",
      noRetry(): void {},
    },
    runtimeEnv,
    ctx,
  );
  await waitOnExecutionContext(ctx);
}
