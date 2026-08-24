import { ed25519, ED25519_TORSION_SUBGROUP } from "@noble/curves/ed25519.js";
import { blake3 } from "@noble/hashes/blake3.js";
import { sha512 } from "@noble/hashes/sha2.js";
import { env } from "cloudflare:workers";
import {
  createExecutionContext,
  waitOnExecutionContext,
} from "cloudflare:test";
import { beforeEach, describe, expect, it } from "vitest";

import worker from "../src/index";
import { verifyEd25519Strict } from "../src/ed25519-strict";
import {
  canonicalManifestBytes,
  parseManifest,
  type RemoteCacheManifest,
} from "../src/manifest";
import {
  canonicalEncryptedManifestV2Bytes,
  parseEncryptedManifestV2,
  type EncryptedRemoteCacheManifestV2,
} from "../src/manifest-v2";
import {
  canonicalTrustBundleJson,
  canonicalTrustBundleBytes,
  MAX_TRUST_BUNDLE_JSON_SIZE,
  parseTrustBundle,
  type TrustBundleV1,
} from "../src/trust";
import {
  bytesToHex,
  hexToBytes,
  readBytesBounded,
  sha256Hex,
} from "../src/util";
import canonicalWireFixture from "./fixtures/manifest-v1-canonical.json";
import manifestWireFixture from "./fixtures/manifest-v1.json";
import manifestV2CanonicalRustFixture from "./fixtures/manifest-v2-canonical-rust.json";
import trustV1CanonicalRustFixture from "./fixtures/trust-v1-canonical-rust.json";

const ORIGIN = "https://cache.again.invalid";
const REPOSITORY = "repo-a";
const TENANT = "tenant-a";
const GENERATION = "1".repeat(32);
const TOKEN_ID = "token-admin";
const TOKEN_SECRET = "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA";
const BEARER = `ag1.${TOKEN_ID}.${TOKEN_SECRET}`;
const textEncoder = new TextEncoder();

type BundleReferenceMatrixState =
  | "valid"
  | "absent_manifest"
  | "deleted_manifest"
  | "expired_manifest"
  | "future_manifest"
  | "revoked_producer"
  | "revoked_record"
  | "disallowed_binding"
  | "quarantined_manifest"
  | "non_ready_blob"
  | "inconsistent_metadata"
  | "missing_blob"
  | "corrupt_blob"
  | "missing_trust"
  | "expired_trust"
  | "malformed_trust"
  | "disabled_root"
  | "wrong_generation";

type ServiceRouteDisposition = "hit" | "miss" | "hard_fail";

interface ServiceRouteObservation {
  disposition: ServiceRouteDisposition;
  stage: string;
  status: number;
  code: string | null;
  initialTrust?: Uint8Array;
  manifest?: Uint8Array;
  stdout?: Uint8Array;
  stderr?: Uint8Array;
  finalTrust?: Uint8Array;
}

const REPOSITORY_D1_CLEANUP_CASES = [
  ["manifest_conflicts", "manifest_conflicts"],
  ["manifests", "manifests"],
  ["blobs", "blobs"],
  ["trust_heads", "trust_heads"],
  ["trust_key_history", "trust_key_history"],
  ["trust_revoked_keys", "trust_revoked_keys"],
  ["trust_revoked_records", "trust_revoked_records"],
  ["trust_root_keys", "trust_root_keys"],
  ["producer_keys", "producer_keys"],
  ["auth_tokens", "auth_tokens"],
  ["audit_events", "audit_events"],
] as const;

beforeEach(async () => {
  const objects = await env.BLOBS.list();
  if (objects.objects.length > 0)
    await env.BLOBS.delete(objects.objects.map((object) => object.key));
  await env.DB.batch([
    env.DB.prepare("DELETE FROM blob_object_orphan_candidates"),
    env.DB.prepare("DELETE FROM repository_deletion_receipts"),
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

  it("enforces the request-body wall-clock deadline", async () => {
    const body = controlledRequestBody(textEncoder.encode("{}"));
    const request = new Request(`${ORIGIN}/deadline-proof`, {
      method: "POST",
      body: body.stream,
      duplex: "half",
    } as RequestInit & { duplex: "half" });
    const read = readBytesBounded(request, 1024, false, 5);
    await body.entered;
    setTimeout(body.release, 25);
    await expect(read).rejects.toMatchObject({
      status: 408,
      code: "request_timeout",
    });
  });

  it("bounds empty request-body chunks without retaining them", async () => {
    let pulls = 0;
    const request = new Request(`${ORIGIN}/fragmentation-proof`, {
      method: "POST",
      body: new ReadableStream<Uint8Array>({
        pull(controller) {
          pulls += 1;
          if (pulls <= 4097) controller.enqueue(new Uint8Array());
          else controller.close();
        },
      }),
      duplex: "half",
    } as RequestInit & { duplex: "half" });
    await expect(
      readBytesBounded(request, 1024, false, 1_000),
    ).rejects.toMatchObject({
      status: 413,
      code: "body_too_large",
    });
    expect(pulls).toBeLessThanOrEqual(4097);
  });

  it("matches the Rust manifest-v1 canonical signing vector", () => {
    expect(
      bytesToHex(
        canonicalManifestBytes(manifestWireFixture as RemoteCacheManifest),
      ),
    ).toBe(canonicalWireFixture.hex_chunks.join(""));
  });

  it("matches Rust canonical signing vectors for trust v1 and encrypted manifest v2", () => {
    const trust = parseTrustBundle(
      rustTrustCanonicalVector() as unknown as Record<string, unknown>,
      1_700_000_000,
    );
    expect(bytesToHex(canonicalTrustBundleBytes(trust))).toBe(
      trustV1CanonicalRustFixture.canonical_hex,
    );

    const manifest = parseEncryptedManifestV2(
      rustManifestV2CanonicalVector() as unknown as Record<string, unknown>,
      1_700_000_000,
    );
    expect(bytesToHex(canonicalEncryptedManifestV2Bytes(manifest))).toBe(
      manifestV2CanonicalRustFixture.canonical_hex,
    );
  });

  it("matches Rust strict trust-key and encrypted-manifest creation-time boundaries", () => {
    const invalidKey = rustTrustCanonicalVector();
    const binding = invalidKey.active_producer_keys[0];
    if (binding === undefined)
      throw new Error("canonical fixture producer key is missing");
    binding.public_key = Array.from({ length: 32 }, () => 0xff);
    expect(() =>
      parseTrustBundle(
        invalidKey as unknown as Record<string, unknown>,
        1_700_000_000,
      ),
    ).toThrow();

    for (const origin of [
      "http://cache.vector.invalid",
      "https://cache.vector.invalid/",
      "https://cache.vector.invalid/path",
      "https://user@cache.vector.invalid",
      "https://CACHE.vector.invalid",
      "https://cache.vector.invalid:443",
    ]) {
      const invalidOrigin = rustTrustCanonicalVector();
      invalidOrigin.endpoint_origin = origin;
      expect(() =>
        parseTrustBundle(
          invalidOrigin as unknown as Record<string, unknown>,
          1_700_000_000,
        ),
      ).toThrow();
    }

    const unknownBinding = rustTrustCanonicalVector();
    (
      unknownBinding.active_producer_keys[0] as unknown as Record<
        string,
        unknown
      >
    ).purpose = "cache";
    expect(() =>
      parseTrustBundle(
        unknownBinding as unknown as Record<string, unknown>,
        1_700_000_000,
      ),
    ).toThrow();

    const future = rustManifestV2CanonicalVector();
    future.created_at_unix_seconds = 1_700_000_001;
    future.expires_at_unix_seconds = 1_700_003_601;
    expect(() =>
      parseEncryptedManifestV2(
        future as unknown as Record<string, unknown>,
        1_700_000_000,
      ),
    ).toThrow();

    const unknownNested = rustManifestV2CanonicalVector();
    (
      unknownNested.stdout as unknown as Record<string, unknown>
    ).plaintext_size_bytes = 32;
    expect(() =>
      parseEncryptedManifestV2(
        unknownNested as unknown as Record<string, unknown>,
        1_700_000_000,
      ),
    ).toThrow();
  });

  it("rejects cofactored Ed25519 signatures that Rust strict verification rejects", () => {
    const seed = Uint8Array.from({ length: 32 }, () => 7);
    const { scalar, pointBytes: publicKey } =
      ed25519.utils.getExtendedPublicKey(seed);
    const message = textEncoder.encode("strict Ed25519 regression vector");
    const scalarOrder = ed25519.Point.CURVE().n;
    const nonceScalar = 123_456_789n;
    const torsion = ed25519.Point.fromHex(
      ED25519_TORSION_SUBGROUP[1] as string,
      true,
    );
    const rBytes = ed25519.Point.BASE.multiplyUnsafe(nonceScalar)
      .add(torsion)
      .toBytes();
    const challenge =
      littleEndianInteger(
        sha512(concatenateBytes(rBytes, publicKey, message)),
      ) % scalarOrder;
    const signature = concatenateBytes(
      rBytes,
      littleEndianBytes((nonceScalar + challenge * scalar) % scalarOrder, 32),
    );

    expect(
      ed25519.verify(signature, message, publicKey, { zip215: false }),
    ).toBe(true);
    expect(verifyEd25519Strict(message, signature, publicKey)).toBe(false);
  });

  it("matches the Rust manifest-v1 rejection boundary", () => {
    const parse = (manifest: unknown) =>
      parseManifest(manifest as Record<string, unknown>, 150);

    const unknownTopLevel = copyManifest(
      manifestWireFixture as RemoteCacheManifest,
    );
    (
      unknownTopLevel as unknown as Record<string, unknown>
    ).requires_attestation = true;
    expect(() => parse(unknownTopLevel)).toThrow();

    const unknownNested = copyManifest(
      manifestWireFixture as RemoteCacheManifest,
    );
    (unknownNested.stdout as unknown as Record<string, unknown>).compression =
      "zstd";
    expect(() => parse(unknownNested)).toThrow();

    const unicodeDigest = copyManifest(
      manifestWireFixture as RemoteCacheManifest,
    );
    unicodeDigest.request_key = `€${"0".repeat(61)}`;
    expect(() => parse(unicodeDigest)).toThrow();

    const longLived = copyManifest(manifestWireFixture as RemoteCacheManifest);
    longLived.expires_at_unix_seconds =
      longLived.created_at_unix_seconds + 30 * 24 * 60 * 60 + 1;
    expect(() => parse(longLived)).toThrow();

    const unsafeTimestamp = copyManifest(
      manifestWireFixture as RemoteCacheManifest,
    );
    unsafeTimestamp.created_at_unix_seconds = Number.MAX_SAFE_INTEGER + 1;
    unsafeTimestamp.expires_at_unix_seconds = Number.MAX_SAFE_INTEGER + 2;
    expect(() => parse(unsafeTimestamp)).toThrow();

    const shortSignature = copyManifest(
      manifestWireFixture as RemoteCacheManifest,
    );
    shortSignature.signature.signature =
      shortSignature.signature.signature.slice(1);
    expect(() => parse(shortSignature)).toThrow();

    const c1Control = copyManifest(manifestWireFixture as RemoteCacheManifest);
    c1Control.record_id = "record\u0080";
    expect(() => parse(c1Control)).toThrow();

    const byteOrderMark = copyManifest(
      manifestWireFixture as RemoteCacheManifest,
    );
    byteOrderMark.record_id = "record\ufeff";
    expect(parse(byteOrderMark).record_id).toBe("record\ufeff");
  });

  it("serves health without auth and fails authentication generically", async () => {
    const health = await call("/v1/health");
    expect(health.status).toBe(200);
    await expect(health.json()).resolves.toMatchObject({
      status: "ok",
      schema_version: 1,
    });

    const missing = await call(`/v1/repositories/${REPOSITORY}/stats`);
    const malformed = await call(`/v1/repositories/${REPOSITORY}/stats`, {
      headers: { authorization: "Bearer definitely-not-a-token" },
    });
    expect(missing.status).toBe(401);
    expect(malformed.status).toBe(401);
    await expect(missing.json()).resolves.toMatchObject({
      error: { code: "unauthorized" },
    });
    await expect(malformed.json()).resolves.toMatchObject({
      error: { code: "unauthorized" },
    });
  });

  it("creates a repository idempotently without allowing a scoped token to escape", async () => {
    const first = await call(
      "/v1/repositories",
      jsonRequest({ repository_id: "repo-b" }),
    );
    const second = await call(
      "/v1/repositories",
      jsonRequest({ repository_id: "repo-b" }),
    );
    expect(first.status).toBe(201);
    expect(second.status).toBe(200);

    await seedToken(
      TENANT,
      "token-scoped",
      "B".repeat(43),
      REPOSITORY,
      "admin",
    );
    const denied = await call(
      "/v1/repositories",
      jsonRequest(
        { repository_id: "repo-c" },
        `ag1.token-scoped.${"B".repeat(43)}`,
      ),
    );
    expect(denied.status).toBe(404);
  });

  it("does not create a repository after the authenticated tenant-admin token is deleted", async () => {
    const gate = databaseThatPausesAuthenticatedRequests(env.DB, 1);
    const creation = callUsingEnv(
      { DB: gate.database, BLOBS: env.BLOBS },
      "/v1/repositories",
      jsonRequest({ repository_id: "repo-stale-admin" }),
    );
    await gate.authenticated;
    await env.DB.prepare("DELETE FROM auth_tokens WHERE id = ?")
      .bind(TOKEN_ID)
      .run();
    gate.release();

    const response = await creation;
    expect(response.status).toBe(401);
    expect(response.headers.get("x-again-error-code")).toBe("unauthorized");
    expect(
      await env.DB.prepare(
        `SELECT
           (SELECT count(*) FROM repositories
             WHERE tenant_id = ? AND id = 'repo-stale-admin') AS repositories,
           (SELECT count(*) FROM audit_events
             WHERE tenant_id = ? AND repository_id = 'repo-stale-admin') AS audits`,
      )
        .bind(TENANT, TENANT)
        .first<{ repositories: number; audits: number }>(),
    ).toEqual({ repositories: 0, audits: 0 });
  });

  it("charges valid credentials before permission rejection", async () => {
    const secret = "D".repeat(43);
    await seedToken(TENANT, "token-read-only", secret, null, "read");
    const denied = await call(
      "/v1/repositories",
      jsonRequest(
        { repository_id: "repo-denied" },
        `ag1.token-read-only.${secret}`,
      ),
    );
    expect(denied.status).toBe(403);
    const row = await env.DB.prepare(
      "SELECT request_count FROM rate_windows WHERE token_id = ?",
    )
      .bind("token-read-only")
      .first<{ request_count: number }>();
    expect(row?.request_count).toBe(1);
  });

  it("exposes bounded generation-history capacity and permits operator recovery", async () => {
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      `UPDATE tenants SET repository_generation_history_limit = 1 WHERE id = ?`,
    )
      .bind(TENANT)
      .run();
    await env.DB.prepare(
      `INSERT INTO repository_deletion_receipts(
         tenant_id, repository_id, generation_id, requested_at, completed_at
       ) VALUES (?, 'retired-repo', ?, ?, ?)`,
    )
      .bind(TENANT, "a".repeat(32), now, now)
      .run();

    const blocked = await call(
      "/v1/repositories",
      jsonRequest({ repository_id: "repo-after-history-cap" }),
    );
    expect(blocked.status).toBe(413);
    expect(blocked.headers.get("x-again-error-code")).toBe(
      "metadata_quota_exceeded",
    );
    const stats = await call(
      `/v1/repositories/${REPOSITORY}/stats`,
      authRequest(),
    );
    await expect(stats.json()).resolves.toMatchObject({
      repository_generation_history_count: 1,
      repository_generation_history_limit: 1,
      repository_generation_history_near_limit: true,
    });

    // These limits are deliberately operator-only: raising an isolated
    // tenant ceiling is the safe recovery when no finite late-write bound
    // exists. Tenant HTTP credentials cannot alter the control-plane field.
    await env.DB.prepare(
      `UPDATE tenants SET repository_generation_history_limit = 2 WHERE id = ?`,
    )
      .bind(TENANT)
      .run();
    expect(
      (
        await call(
          "/v1/repositories",
          jsonRequest({ repository_id: "repo-after-history-cap" }),
        )
      ).status,
    ).toBe(201);
  });

  it("keeps another repository's protected audit evidence isolated from a write flood", async () => {
    await env.DB.prepare(
      `UPDATE tenants SET audit_partition_limit = 2, audit_event_limit = 20 WHERE id = ?`,
    )
      .bind(TENANT)
      .run();
    const createdB = await call(
      "/v1/repositories",
      jsonRequest({ repository_id: "repo-b" }),
    );
    expect(createdB.status).toBe(201);
    const generationB = (await createdB.json<{ generation_id: string }>())
      .generation_id;
    const producerB = await generateSigningKeys();
    expect(
      (
        await call(
          "/v1/repositories/repo-b/producers/key-b",
          jsonRequest(
            {
              producer_id: "producer-b",
              public_key_hex: producerB.publicKeyHex,
            },
            BEARER,
            "PUT",
            generationB,
          ),
        )
      ).status,
    ).toBe(201);
    expect(
      (
        await call("/v1/repositories/repo-b/producers/key-b", {
          method: "DELETE",
          headers: {
            authorization: `Bearer ${BEARER}`,
            "x-again-repository-generation": generationB,
          },
        })
      ).status,
    ).toBe(204);

    const trust = await prepareTrustBundleFixture();
    expect((await putTrustBundle(trust.bundle)).status).toBe(201);
    const invalidTrust = copyTrustBundle(trust.bundle);
    invalidTrust.signature[0] = (invalidTrust.signature[0] ?? 0) ^ 1;
    for (let index = 0; index < 4; index += 1) {
      expect((await putTrustBundle(invalidTrust)).status).toBe(422);
    }

    const bytes = textEncoder.encode("ordinary audit flood");
    for (let index = 0; index < 5; index += 1) {
      const wrongDigest = index.toString(16).padStart(64, "0");
      expect((await putBlob(bytes, wrongDigest)).status).toBe(422);
    }
    expect(
      await env.DB.prepare(
        `SELECT
           (SELECT count(*) FROM audit_events
             WHERE tenant_id = ? AND repository_id = 'repo-b'
               AND action = 'producer.revoke') AS protected_b,
           (SELECT count(*) FROM audit_events
             WHERE tenant_id = ? AND repository_id = ?
               AND action = 'trust_bundle.put' AND outcome = 'created') AS protected_a,
           (SELECT count(*) FROM audit_events
             WHERE tenant_id = ? AND repository_id = ? AND action = 'blob.put') AS ordinary_a`,
      )
        .bind(TENANT, TENANT, REPOSITORY, TENANT, REPOSITORY)
        .first<{
          protected_b: number;
          protected_a: number;
          ordinary_a: number;
        }>(),
    ).toEqual({ protected_b: 1, protected_a: 1, ordinary_a: 2 });
  });

  it("stores immutable verified blobs and isolates identical paths across tenants", async () => {
    const bytes = textEncoder.encode("hello from tenant a");
    const digest = bytesToHex(blake3(bytes));
    const missingGeneration = await call(
      `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
      {
        method: "PUT",
        headers: {
          authorization: `Bearer ${BEARER}`,
          "content-type": "application/octet-stream",
          "content-length": String(bytes.byteLength),
        },
        body: bytes,
      },
    );
    expect(missingGeneration.status).toBe(428);
    const wrongGeneration = await call(
      `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
      {
        method: "PUT",
        headers: {
          authorization: `Bearer ${BEARER}`,
          "content-type": "application/octet-stream",
          "content-length": String(bytes.byteLength),
          "x-again-repository-generation": "2".repeat(32),
        },
        body: bytes,
      },
    );
    expect(wrongGeneration.status).toBe(412);
    const missingLength = await call(
      `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
      {
        method: "PUT",
        headers: {
          authorization: `Bearer ${BEARER}`,
          "content-type": "application/octet-stream",
          "x-again-repository-generation": GENERATION,
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
    expect(created.headers.get("x-again-repository-generation")).toBe(
      GENERATION,
    );
    expect((await putBlob(bytes, digest)).status).toBe(204);
    const incarnation = await blobIncarnation(digest);
    expect(incarnation).toMatch(/^[0-9a-f]{32}$/);
    expect(incarnation).not.toBe("0".repeat(32));
    expect(await env.BLOBS.head(await blobObjectKey(digest))).not.toBeNull();
    const identity = await env.DB.prepare(
      `SELECT r2_key, r2_version, r2_etag, r2_sha256 FROM blobs
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(TENANT, REPOSITORY, digest)
      .first<{
        r2_key: string;
        r2_version: string;
        r2_etag: string;
        r2_sha256: string;
      }>();
    const stored = await env.BLOBS.head(await blobObjectKey(digest));
    expect(identity).toEqual({
      r2_key: stored?.key,
      r2_version: stored?.version,
      r2_etag: stored?.etag,
      r2_sha256:
        stored?.checksums.sha256 === undefined
          ? undefined
          : bytesToHex(new Uint8Array(stored.checksums.sha256)),
    });

    const fetched = await call(
      `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
      authRequest(),
    );
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
    const hidden = await call(
      `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
      {
        headers: {
          authorization: `Bearer ag1.token-b.${otherSecret}`,
          "x-again-repository-generation": GENERATION,
        },
      },
    );
    expect(hidden.status).toBe(404);
  });

  it("enforces quota atomically and releases it after unreferenced deletion", async () => {
    await env.DB.prepare("UPDATE tenants SET quota_bytes = 4 WHERE id = ?")
      .bind(TENANT)
      .run();
    const bytes = textEncoder.encode("12345");
    const digest = bytesToHex(blake3(bytes));
    const rejected = await putBlob(bytes, digest);
    expect(rejected.status).toBe(413);
    const tenant = await env.DB.prepare(
      "SELECT used_bytes FROM tenants WHERE id = ?",
    )
      .bind(TENANT)
      .first<{ used_bytes: number }>();
    expect(tenant?.used_bytes).toBe(0);

    await env.DB.prepare("UPDATE tenants SET quota_bytes = 10 WHERE id = ?")
      .bind(TENANT)
      .run();
    expect((await putBlob(bytes, digest)).status).toBe(201);
    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
          authRequest(undefined, "DELETE"),
        )
      ).status,
    ).toBe(204);
    const after = await env.DB.prepare(
      "SELECT used_bytes FROM tenants WHERE id = ?",
    )
      .bind(TENANT)
      .first<{ used_bytes: number }>();
    expect(after?.used_bytes).toBe(0);
  });

  it("rejects excess manifest metadata and releases its accounted units on removal", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    const bodyJson = JSON.stringify(fixture.manifest);
    const trustBodySha = await sha256Hex(
      canonicalTrustBundleJson(fixture.trustBundle),
    );
    const manifestUnits =
      1 + Math.ceil(textEncoder.encode(bodyJson).byteLength / 1024);
    const before = await metadataUsage();

    await env.DB.prepare(
      "UPDATE tenants SET metadata_quota_units = ? WHERE id = ?",
    )
      .bind(before + manifestUnits - 1, TENANT)
      .run();
    await expect(
      manifestInsert(
        fixture.manifest,
        bodyJson,
        fixture.trustBundle.epoch,
        trustBodySha,
      ).run(),
    ).rejects.toThrow(/metadata_quota_exceeded/);
    expect(await metadataUsage()).toBe(before);

    await env.DB.prepare(
      "UPDATE tenants SET metadata_quota_units = ? WHERE id = ?",
    )
      .bind(before + manifestUnits, TENANT)
      .run();
    await manifestInsert(
      fixture.manifest,
      bodyJson,
      fixture.trustBundle.epoch,
      trustBodySha,
    ).run();
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
    await env.DB.prepare(
      "UPDATE tenants SET metadata_quota_units = ? WHERE id = ?",
    )
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

  it("keeps revocation and deletion available at exact ordinary metadata quota", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
    const used = await metadataUsage();
    await env.DB.prepare(
      `UPDATE tenants SET metadata_quota_units = used_metadata_units WHERE id = ?`,
    )
      .bind(TENANT)
      .run();

    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}/producers/key-1`,
          authRequest(undefined, "DELETE"),
        )
      ).status,
    ).toBe(204);
    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}/manifests/${fixture.manifest.request_key}`,
          authRequest(undefined, "DELETE"),
        )
      ).status,
    ).toBe(204);
    for (const digest of [
      fixture.manifest.stdout.ciphertext_digest,
      fixture.manifest.stderr.ciphertext_digest,
    ]) {
      expect(
        (
          await call(
            `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
            authRequest(undefined, "DELETE"),
          )
        ).status,
      ).toBe(204);
    }
    expect(await metadataUsage()).toBeGreaterThan(used);
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
    expect(statuses.every((status) => status === 201 || status === 204)).toBe(
      true,
    );
    expect(statuses).toContain(201);

    const row = await env.DB.prepare(
      `SELECT count(*) AS count, max(state) AS state
         FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(TENANT, REPOSITORY, digest)
      .first<{ count: number; state: string }>();
    expect(row).toMatchObject({ count: 1, state: "ready" });
    const tenant = await env.DB.prepare(
      "SELECT used_bytes FROM tenants WHERE id = ?",
    )
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
    await env.BLOBS.put(
      `v1/${TENANT}/${REPOSITORY}/${GENERATION}/blake3/${digest}`,
      bytes,
      {
        httpMetadata: { contentType: "application/octet-stream" },
        customMetadata: {
          blake3: digest,
          size_bytes: String(bytes.byteLength),
          incarnation_id: "0".repeat(32),
        },
        sha256: await crypto.subtle.digest("SHA-256", bytes),
      },
    );

    expect((await putBlob(bytes, digest)).status).toBe(201);
    const recovered = await env.DB.prepare(
      "SELECT state FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = ?",
    )
      .bind(TENANT, REPOSITORY, digest)
      .first<{ state: string }>();
    expect(recovered?.state).toBe("ready");
    const accounted = await env.DB.prepare(
      "SELECT used_bytes FROM tenants WHERE id = ?",
    )
      .bind(TENANT)
      .first<{ used_bytes: number }>();
    expect(accounted?.used_bytes).toBe(bytes.byteLength);

    await env.BLOBS.delete(
      `v1/${TENANT}/${REPOSITORY}/${GENERATION}/blake3/${digest}`,
    );
    expect((await putBlob(bytes, digest)).status).toBe(201);
    const repaired = await env.BLOBS.head(
      `v1/${TENANT}/${REPOSITORY}/${GENERATION}/blake3/${digest}`,
    );
    expect(repaired?.customMetadata?.blake3).toBe(digest);
  });

  it("hashes stored R2 bytes even when forged metadata and size match", async () => {
    const bytes = textEncoder.encode("integrity-good");
    const digest = bytesToHex(blake3(bytes));
    expect((await putBlob(bytes, digest)).status).toBe(201);

    const forged = textEncoder.encode("integrity-evil");
    expect(forged.byteLength).toBe(bytes.byteLength);
    const key = await blobObjectKey(digest);
    const incarnationId = await blobIncarnation(digest);
    await env.BLOBS.put(key, forged, {
      customMetadata: {
        blake3: digest,
        size_bytes: String(forged.byteLength),
        incarnation_id: incarnationId,
      },
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

  it("does not let a paused generation-A blob read quarantine recreated generation B", async () => {
    const bytes = textEncoder.encode("generation-fenced-read");
    const digest = bytesToHex(blake3(bytes));
    expect((await putBlob(bytes, digest)).status).toBe(201);
    const keyA = await blobObjectKey(digest);
    const incarnationA = await blobIncarnation(digest);
    const forged = Uint8Array.from(bytes, (value, index) =>
      index === 0 ? value ^ 1 : value,
    );
    await env.BLOBS.put(keyA, forged, {
      httpMetadata: { contentType: "application/octet-stream" },
      customMetadata: {
        blake3: digest,
        size_bytes: String(bytes.byteLength),
        incarnation_id: incarnationA,
      },
    });

    const gate = bucketThatPausesFirstGetAfterRead(env.BLOBS);
    const staleRead = callUsingEnv(
      { DB: env.DB, BLOBS: gate.bucket },
      `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
      authRequest(),
    );
    await gate.entered;

    expect(
      (await call(`/v1/repositories/${REPOSITORY}`, repositoryDeleteRequest()))
        .status,
    ).toBe(202);
    await finishRepositoryDeletion();
    const recreated = await call(
      "/v1/repositories",
      jsonRequest({ repository_id: REPOSITORY }),
    );
    expect(recreated.status).toBe(201);
    const generationB = (await recreated.json<{ generation_id: string }>())
      .generation_id;
    expect(
      (await putBlobUsingEnv(env, bytes, digest, generationB)).status,
    ).toBe(201);
    const auditsBefore = await env.DB.prepare(
      `SELECT count(*) AS count FROM audit_events
        WHERE tenant_id = ? AND repository_id = ? AND action = 'blob.quarantine'`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{ count: number }>();

    gate.release();
    const response = await staleRead;
    expect(response.status).toBe(412);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "repository_generation_mismatch" },
    });
    expect(
      await env.DB.prepare(
        `SELECT state FROM blobs
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(TENANT, REPOSITORY, digest)
        .first<{ state: string }>(),
    ).toEqual({ state: "ready" });
    expect(
      await env.DB.prepare(
        `SELECT count(*) AS count FROM audit_events
          WHERE tenant_id = ? AND repository_id = ? AND action = 'blob.quarantine'`,
      )
        .bind(TENANT, REPOSITORY)
        .first<{ count: number }>(),
    ).toEqual(auditsBefore);
  });

  it("does not release verified bytes after the same blob incarnation leaves ready state", async () => {
    const bytes = textEncoder.encode("ready-state-release-fence");
    const digest = bytesToHex(blake3(bytes));
    expect((await putBlob(bytes, digest)).status).toBe(201);
    const gate = bucketThatPausesFirstGetAfterRead(env.BLOBS);
    const read = callUsingEnv(
      { DB: env.DB, BLOBS: gate.bucket },
      `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
      authRequest(),
    );
    await gate.entered;
    await env.DB.prepare(
      `UPDATE blobs SET state = 'quarantined', updated_at = ?
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(Math.floor(Date.now() / 1000), TENANT, REPOSITORY, digest)
      .run();
    gate.release();

    const response = await read;
    expect(response.status).toBe(409);
    expect(response.headers.get("x-again-error-code")).toBe(
      "blob_state_changed",
    );
  });

  it("uses immutable blob incarnations so a stale delete cannot erase a same-digest re-upload", async () => {
    const bytes = textEncoder.encode("same-generation-delete-aba");
    const digest = bytesToHex(blake3(bytes));
    expect((await putBlob(bytes, digest)).status).toBe(201);
    const incarnationA = await blobIncarnation(digest);
    const keyA = await blobObjectKey(digest);
    const gate = bucketThatPausesFirstDeleteBeforeMutation(env.BLOBS);
    const staleDelete = callUsingEnv(
      { DB: env.DB, BLOBS: gate.bucket },
      `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
      authRequest(undefined, "DELETE"),
    );
    await gate.entered;

    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
          authRequest(undefined, "DELETE"),
        )
      ).status,
    ).toBe(204);
    expect((await putBlob(bytes, digest)).status).toBe(201);
    const incarnationB = await blobIncarnation(digest);
    const keyB = await blobObjectKey(digest);
    expect(incarnationB).not.toBe(incarnationA);
    expect(keyB).not.toBe(keyA);

    gate.release();
    const staleResponse = await staleDelete;
    expect(staleResponse.status).toBe(409);
    expect(staleResponse.headers.get("x-again-error-code")).toBe(
      "blob_state_changed",
    );
    expect(await env.BLOBS.head(keyA)).toBeNull();
    expect(await env.BLOBS.head(keyB)).not.toBeNull();
    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
          authRequest(),
        )
      ).status,
    ).toBe(200);
  });

  it("uses the captured incarnation when a stale reconciler resumes deletion", async () => {
    const bytes = textEncoder.encode("same-generation-reconcile-aba");
    const digest = bytesToHex(blake3(bytes));
    expect((await putBlob(bytes, digest)).status).toBe(201);
    const incarnationA = await blobIncarnation(digest);
    const keyA = await blobObjectKey(digest);
    await env.DB.prepare(
      `UPDATE blobs
          SET state = 'deleting', updated_at = 0, next_reconcile_at = 0,
              delete_not_before = 0
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(TENANT, REPOSITORY, digest)
      .run();
    const gate = bucketThatPausesFirstDeleteBeforeMutation(env.BLOBS);
    const staleRun = runReconciliationUsingEnv({
      DB: env.DB,
      BLOBS: gate.bucket,
    });
    await gate.entered;

    await runReconciliation();
    expect((await putBlob(bytes, digest)).status).toBe(201);
    const incarnationB = await blobIncarnation(digest);
    const keyB = await blobObjectKey(digest);
    expect(incarnationB).not.toBe(incarnationA);

    gate.release();
    await staleRun;
    expect(await env.BLOBS.head(keyA)).toBeNull();
    expect(await env.BLOBS.head(keyB)).not.toBeNull();
    expect(
      await env.DB.prepare(
        `SELECT state, incarnation_id FROM blobs
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(TENANT, REPOSITORY, digest)
        .first<{ state: string; incarnation_id: string }>(),
    ).toEqual({ state: "ready", incarnation_id: incarnationB });
  });

  it("finishes a bounded blob body before acquiring a generation mutation lease", async () => {
    const bytes = textEncoder.encode("body-before-lease");
    const digest = bytesToHex(blake3(bytes));
    const body = controlledRequestBody(bytes);
    const upload = call(`/v1/repositories/${REPOSITORY}/blobs/${digest}`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${BEARER}`,
        "content-type": "application/octet-stream",
        "content-length": String(bytes.byteLength),
        "x-again-repository-generation": GENERATION,
      },
      body: body.stream,
      duplex: "half",
    } as RequestInit & { duplex: "half" });
    await body.entered;

    expect(
      (await call(`/v1/repositories/${REPOSITORY}`, repositoryDeleteRequest()))
        .status,
    ).toBe(202);
    await finishRepositoryDeletion();
    expect(
      (
        await call(
          "/v1/repositories",
          jsonRequest({ repository_id: REPOSITORY }),
        )
      ).status,
    ).toBe(201);
    body.release();

    const response = await upload;
    expect(response.status).toBe(412);
    const oldObjects = await env.BLOBS.list({
      prefix: `v1/${TENANT}/${REPOSITORY}/${GENERATION}/`,
    });
    expect(oldObjects.objects).toHaveLength(0);
  });

  it("reads producer JSON completely before acquiring a mutation lease", async () => {
    const keys = await generateSigningKeys();
    const bytes = textEncoder.encode(
      JSON.stringify({
        producer_id: "producer-2",
        public_key_hex: keys.publicKeyHex,
      }),
    );
    const body = controlledRequestBody(bytes);
    const request = call(`/v1/repositories/${REPOSITORY}/producers/key-2`, {
      method: "PUT",
      headers: {
        authorization: `Bearer ${BEARER}`,
        "content-type": "application/json",
        "content-length": String(bytes.byteLength),
        "x-again-repository-generation": GENERATION,
      },
      body: body.stream,
      duplex: "half",
    } as RequestInit & { duplex: "half" });
    await body.entered;
    expect(await activeWriteLeaseCount()).toBe(0);
    body.release();
    expect((await request).status).toBe(201);
  });

  it("reads trust JSON completely before acquiring a mutation lease", async () => {
    const fixture = await prepareTrustBundleFixture();
    const bytes = textEncoder.encode(JSON.stringify(fixture.bundle));
    const body = controlledRequestBody(bytes);
    const request = call(
      `/v1/repositories/${REPOSITORY}/trust-bundles/latest`,
      {
        method: "PUT",
        headers: {
          authorization: `Bearer ${BEARER}`,
          "content-type": "application/json",
          "content-length": String(bytes.byteLength),
          "x-again-repository-generation": GENERATION,
        },
        body: body.stream,
        duplex: "half",
      } as RequestInit & { duplex: "half" },
    );
    await body.entered;
    expect(await activeWriteLeaseCount()).toBe(0);
    body.release();
    expect((await request).status).toBe(201);
  });

  it("reads manifest JSON completely before acquiring a mutation lease", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    const bytes = textEncoder.encode(JSON.stringify(fixture.manifest));
    const body = controlledRequestBody(bytes);
    const request = call(
      `/v1/repositories/${REPOSITORY}/manifests/${fixture.manifest.request_key}`,
      {
        method: "PUT",
        headers: {
          authorization: `Bearer ${BEARER}`,
          "content-type": "application/json",
          "content-length": String(bytes.byteLength),
          "x-again-repository-generation": GENERATION,
        },
        body: body.stream,
        duplex: "half",
      } as RequestInit & { duplex: "half" },
    );
    await body.entered;
    expect(await activeWriteLeaseCount()).toBe(0);
    body.release();
    expect((await request).status).toBe(201);
  });

  it("durably sweeps a late R2 put orphan while the repository remains active", async () => {
    const bytes = textEncoder.encode("late active-repository put");
    const digest = bytesToHex(blake3(bytes));
    const gate = bucketThatGatesPutsAndFailsFirstDelete(env.BLOBS, 1);
    const upload = putBlobUsingEnv(
      { DB: env.DB, BLOBS: gate.bucket },
      bytes,
      digest,
    );
    await gate.entered[0];

    const pending = await env.DB.prepare(
      `SELECT incarnation_id FROM blobs
        WHERE tenant_id = ? AND repository_id = ? AND digest = ? AND state = 'pending'`,
    )
      .bind(TENANT, REPOSITORY, digest)
      .first<{ incarnation_id: string }>();
    expect(pending).not.toBeNull();
    expect(
      await env.DB.prepare(
        `SELECT count(*) AS count FROM blob_object_orphan_candidates
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(TENANT, REPOSITORY, digest)
        .first<{ count: number }>(),
    ).toEqual({ count: 1 });

    await env.DB.prepare(
      `DELETE FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(TENANT, REPOSITORY, digest)
      .run();
    gate.release[0]?.();
    const response = await upload;
    expect(response.status).toBe(409);
    expect(response.headers.get("x-again-error-code")).toBe(
      "blob_state_changed",
    );

    const key = `v1/${TENANT}/${REPOSITORY}/${GENERATION}/blake3/${digest}/${pending?.incarnation_id}`;
    expect(await env.BLOBS.head(key)).not.toBeNull();
    await runScheduled();
    expect(await env.BLOBS.head(key)).toBeNull();
    expect(
      await env.DB.prepare(
        `SELECT count(*) AS count FROM blob_object_orphan_candidates
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(TENANT, REPOSITORY, digest)
        .first<{ count: number }>(),
    ).toEqual({ count: 1 });
  });

  it("keeps one durable orphan record for each concurrent R2 put attempt", async () => {
    const bytes = textEncoder.encode("two independent put operations");
    const digest = bytesToHex(blake3(bytes));
    const gate = bucketThatGatesPutsAndFailsFirstDelete(env.BLOBS, 2);
    const runtimeEnv: Env = { DB: env.DB, BLOBS: gate.bucket };
    const uploadA = putBlobUsingEnv(runtimeEnv, bytes, digest);
    await gate.entered[0];
    const uploadB = putBlobUsingEnv(runtimeEnv, bytes, digest);
    await gate.entered[1];

    const candidates = await env.DB.prepare(
      `SELECT operation_id, incarnation_id FROM blob_object_orphan_candidates
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?
        ORDER BY operation_id`,
    )
      .bind(TENANT, REPOSITORY, digest)
      .all<{ operation_id: string; incarnation_id: string }>();
    expect(candidates.results).toHaveLength(2);
    expect(
      new Set(candidates.results.map((row) => row.operation_id)).size,
    ).toBe(2);
    expect(
      new Set(candidates.results.map((row) => row.incarnation_id)).size,
    ).toBe(1);
    const incarnationId = candidates.results[0]?.incarnation_id;
    expect(incarnationId).toMatch(/^[0-9a-f]{32}$/);

    gate.release[0]?.();
    const responseA = await uploadA;
    expect(responseA.status).toBe(201);
    expect(
      await env.DB.prepare(
        `SELECT count(*) AS count FROM blob_object_orphan_candidates
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(TENANT, REPOSITORY, digest)
        .first<{ count: number }>(),
    ).toEqual({ count: 1 });

    const key = `v1/${TENANT}/${REPOSITORY}/${GENERATION}/blake3/${digest}/${incarnationId}`;
    await runScheduled();
    expect(await env.BLOBS.head(key)).not.toBeNull();
    await env.DB.prepare(
      `DELETE FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(TENANT, REPOSITORY, digest)
      .run();
    await env.BLOBS.delete(key);

    gate.release[1]?.();
    const stale = await uploadB;
    expect(stale.status).toBe(409);
    expect(stale.headers.get("x-again-error-code")).toBe("blob_state_changed");
    expect(await env.BLOBS.head(key)).not.toBeNull();
    await env.DB.prepare(
      `UPDATE blob_object_orphan_candidates SET next_sweep_at = 0
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(TENANT, REPOSITORY, digest)
      .run();
    await runScheduled();
    expect(await env.BLOBS.head(key)).toBeNull();
  });

  it("retires a fulfilled put operation after transient readback failure", async () => {
    const bytes = textEncoder.encode("fulfilled put with failed readback");
    const digest = bytesToHex(blake3(bytes));
    const first = await putBlobUsingEnv(
      { DB: env.DB, BLOBS: bucketThatFailsFirstGet(env.BLOBS) },
      bytes,
      digest,
    );
    expect(first.status).toBe(503);
    expect(
      await env.DB.prepare(
        `SELECT
           (SELECT state FROM blobs
             WHERE tenant_id = ? AND repository_id = ? AND digest = ?) AS state,
           (SELECT count(*) FROM blob_object_orphan_candidates
             WHERE tenant_id = ? AND repository_id = ? AND digest = ?) AS candidates`,
      )
        .bind(TENANT, REPOSITORY, digest, TENANT, REPOSITORY, digest)
        .first<{ state: string; candidates: number }>(),
    ).toEqual({ state: "pending", candidates: 0 });

    expect((await putBlob(bytes, digest)).status).toBe(201);
    expect(
      await env.DB.prepare(
        `SELECT count(*) AS count FROM blob_object_orphan_candidates
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(TENANT, REPOSITORY, digest)
        .first<{ count: number }>(),
    ).toEqual({ count: 0 });
  });

  it("bounds ambiguous orphan operations and recovers through an operator-only limit raise", async () => {
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      `UPDATE tenants
          SET blob_orphan_candidate_limit = 4, blob_orphan_repository_limit = 2
        WHERE id = ?`,
    )
      .bind(TENANT)
      .run();
    const seededDigest = "e".repeat(64);
    const seededIncarnation = "f".repeat(32);
    await env.DB.batch(
      [1, 2].map((index) =>
        env.DB.prepare(
          `INSERT INTO blob_object_orphan_candidates(
             tenant_id, repository_id, generation_id, digest, incarnation_id,
             operation_id, created_at, next_sweep_at, attempts
           ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, 0)`,
        ).bind(
          TENANT,
          REPOSITORY,
          GENERATION,
          seededDigest,
          seededIncarnation,
          index.toString(16).padStart(32, "0"),
          now,
          now,
        ),
      ),
    );
    const bytes = textEncoder.encode("capacity-controlled orphan operation");
    const digest = bytesToHex(blake3(bytes));
    const blocked = await putBlob(bytes, digest);
    expect(blocked.status).toBe(413);
    expect(blocked.headers.get("x-again-error-code")).toBe(
      "metadata_quota_exceeded",
    );

    const createdB = await call(
      "/v1/repositories",
      jsonRequest({ repository_id: "repo-b" }),
    );
    expect(createdB.status).toBe(201);
    const generationB = (await createdB.json<{ generation_id: string }>())
      .generation_id;
    const bytesB = textEncoder.encode("repository-b remains available");
    expect(
      (
        await putBlobAtRepository(
          "repo-b",
          bytesB,
          bytesToHex(blake3(bytesB)),
          generationB,
        )
      ).status,
    ).toBe(201);

    const stats = await call(
      `/v1/repositories/${REPOSITORY}/stats`,
      authRequest(),
    );
    await expect(stats.json()).resolves.toMatchObject({
      blob_orphan_candidate_count: 2,
      blob_orphan_candidate_limit: 4,
      blob_orphan_candidate_near_limit: false,
      blob_orphan_repository_count: 2,
      blob_orphan_repository_limit: 2,
      blob_orphan_repository_near_limit: true,
    });

    await env.DB.prepare(
      `UPDATE tenants SET blob_orphan_repository_limit = 3 WHERE id = ?`,
    )
      .bind(TENANT)
      .run();
    expect((await putBlob(bytes, digest)).status).toBe(201);
    expect(
      await env.DB.prepare(
        `SELECT count(*) AS count FROM blob_object_orphan_candidates
          WHERE tenant_id = ?`,
      )
        .bind(TENANT)
        .first<{ count: number }>(),
    ).toEqual({ count: 2 });
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

  it("adopts the exact winning R2 identity when conditional PUT returns null", async () => {
    const bytes = textEncoder.encode("conditional put winner");
    const digest = bytesToHex(blake3(bytes));
    const response = await putBlobUsingEnv(
      { DB: env.DB, BLOBS: bucketThatReturnsNullAfterSuccessfulPut(env.BLOBS) },
      bytes,
      digest,
    );
    expect(response.status).toBe(201);
    const key = await blobObjectKey(digest);
    const [row, object] = await Promise.all([
      env.DB.prepare(
        `SELECT state, r2_key, r2_version, r2_etag, r2_sha256 FROM blobs
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(TENANT, REPOSITORY, digest)
        .first<{
          state: string;
          r2_key: string;
          r2_version: string;
          r2_etag: string;
          r2_sha256: string;
        }>(),
      env.BLOBS.head(key),
    ]);
    expect(row).toEqual({
      state: "ready",
      r2_key: object?.key,
      r2_version: object?.version,
      r2_etag: object?.etag,
      r2_sha256:
        object?.checksums.sha256 === undefined
          ? undefined
          : bytesToHex(new Uint8Array(object.checksums.sha256)),
    });
  });

  it("resumes an interrupted deletion and refuses to delete an active pending reservation", async () => {
    const bytes = textEncoder.encode("delete recovery");
    const digest = bytesToHex(blake3(bytes));
    expect((await putBlob(bytes, digest)).status).toBe(201);
    const storedKey = await blobObjectKey(digest);
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
    expect(await env.BLOBS.head(storedKey)).toBeNull();

    const pendingBytes = textEncoder.encode("reserved but not uploaded");
    const pendingDigest = bytesToHex(blake3(pendingBytes));
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      `INSERT INTO blobs(
         tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at
       ) VALUES (?, ?, ?, ?, 'pending', ?, ?)`,
    )
      .bind(
        TENANT,
        REPOSITORY,
        pendingDigest,
        pendingBytes.byteLength,
        now,
        now,
      )
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
    expect(tombstone?.delete_not_before).toBeGreaterThan(
      Math.floor(Date.now() / 1000),
    );

    await env.DB.prepare(
      `UPDATE blobs SET delete_not_before = 0, next_reconcile_at = 0
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(TENANT, REPOSITORY, digest)
      .run();
    await runReconciliation();
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
    for (let index = 1; index <= 16; index += 1) {
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
    await env.BLOBS.put(
      `v1/${TENANT}/${REPOSITORY}/${GENERATION}/blake3/${digest}`,
      bytes,
      {
        customMetadata: {
          blake3: digest,
          size_bytes: String(bytes.byteLength),
          incarnation_id: "0".repeat(32),
        },
        sha256: await crypto.subtle.digest("SHA-256", bytes),
      },
    );

    await runReconciliation();
    const afterFirstPage = await env.DB.prepare(
      "SELECT state FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = ?",
    )
      .bind(TENANT, REPOSITORY, digest)
      .first<{ state: string }>();
    expect(afterFirstPage?.state).toBe("pending");
    await runReconciliation();
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
    await runReconciliationUsingEnv({ DB: env.DB, BLOBS: failingBucket });
    const row = await env.DB.prepare(
      `SELECT reconcile_attempts, next_reconcile_at FROM blobs
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(TENANT, REPOSITORY, digest)
      .first<{ reconcile_attempts: number; next_reconcile_at: number }>();
    expect(row?.reconcile_attempts).toBe(1);
    expect(row?.next_reconcile_at).toBeGreaterThan(
      Math.floor(Date.now() / 1000),
    );
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
    await env.BLOBS.put(
      `v1/${TENANT}/${REPOSITORY}/${GENERATION}/blake3/${digest}`,
      bytes,
      {
        customMetadata: {
          blake3: digest,
          size_bytes: String(bytes.byteLength),
          incarnation_id: "0".repeat(32),
        },
        sha256: await crypto.subtle.digest("SHA-256", bytes),
      },
    );
    await Promise.all([runReconciliation(), runReconciliation()]);
    const audits = await env.DB.prepare(
      `SELECT count(*) AS count FROM audit_events
        WHERE tenant_id = ? AND repository_id = ?
          AND action = 'blob.reconcile' AND outcome = 'promoted'`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{ count: number }>();
    expect(audits?.count).toBe(1);
  });

  it.each([
    ["promote", "pending", "SET state = 'ready'", "valid"],
    ["quarantine", "pending", "SET state = 'quarantined'", "invalid"],
    [
      "defer",
      "pending",
      "SET reconcile_attempts = reconcile_attempts + 1",
      "missing",
    ],
    ["delete", "deleting", "DELETE FROM blobs", "missing"],
  ] as const)(
    "does not let a paused generation-A reconcile %s mutate recreated generation B",
    async (_outcome, state, mutationMarker, objectState) => {
      const bytes = textEncoder.encode("reconcile-generation-fence");
      const digest = bytesToHex(blake3(bytes));
      const selectedTime = Math.floor(Date.now() / 1000) - 1;
      await env.DB.prepare(
        `INSERT INTO blobs(
           tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
           reconcile_attempts, next_reconcile_at, delete_not_before,
           r2_key, r2_version, r2_etag, r2_sha256
         ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, 'test-version', 'test-etag', ?)`,
      )
        .bind(
          TENANT,
          REPOSITORY,
          digest,
          bytes.byteLength,
          state,
          selectedTime,
          selectedTime,
          state === "deleting" ? 0 : null,
          `v1/${TENANT}/${REPOSITORY}/${GENERATION}/blake3/${digest}`,
          "0".repeat(64),
        )
        .run();
      const keyA = `v1/${TENANT}/${REPOSITORY}/${GENERATION}/blake3/${digest}`;
      if (objectState !== "missing") {
        const stored =
          objectState === "valid"
            ? bytes
            : Uint8Array.from(bytes, (value, index) =>
                index === 0 ? value ^ 1 : value,
              );
        await env.BLOBS.put(keyA, stored, {
          customMetadata: {
            blake3: digest,
            size_bytes: String(bytes.byteLength),
            incarnation_id: "0".repeat(32),
          },
          sha256: await crypto.subtle.digest("SHA-256", stored),
        });
      }

      const gate = databaseThatPausesMutation(env.DB, mutationMarker);
      const staleRun = runReconciliationUsingEnv({
        DB: gate.database,
        BLOBS: env.BLOBS,
      });
      await gate.entered;

      expect(
        (
          await call(
            `/v1/repositories/${REPOSITORY}`,
            repositoryDeleteRequest(),
          )
        ).status,
      ).toBe(202);
      await finishRepositoryDeletion();
      const recreated = await call(
        "/v1/repositories",
        jsonRequest({ repository_id: REPOSITORY }),
      );
      expect(recreated.status).toBe(201);
      const generationB = (await recreated.json<{ generation_id: string }>())
        .generation_id;
      await env.DB.prepare(
        `INSERT INTO blobs(
           tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
           reconcile_attempts, next_reconcile_at, delete_not_before,
           r2_key, r2_version, r2_etag, r2_sha256
         ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0, ?, ?, 'test-version', 'test-etag', ?)`,
      )
        .bind(
          TENANT,
          REPOSITORY,
          digest,
          bytes.byteLength,
          state,
          selectedTime,
          selectedTime,
          state === "deleting" ? 0 : null,
          `v1/${TENANT}/${REPOSITORY}/${generationB}/blake3/${digest}`,
          "0".repeat(64),
        )
        .run();
      const keyB = `v1/${TENANT}/${REPOSITORY}/${generationB}/blake3/${digest}`;
      await env.BLOBS.put(keyB, bytes, {
        customMetadata: {
          blake3: digest,
          size_bytes: String(bytes.byteLength),
          incarnation_id: "0".repeat(32),
        },
        sha256: await crypto.subtle.digest("SHA-256", bytes),
      });

      gate.release();
      await staleRun;

      expect(
        await env.DB.prepare(
          `SELECT state, updated_at, reconcile_attempts, next_reconcile_at,
                  delete_not_before
             FROM blobs
            WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
        )
          .bind(TENANT, REPOSITORY, digest)
          .first<{
            state: string;
            updated_at: number;
            reconcile_attempts: number;
            next_reconcile_at: number;
            delete_not_before: number | null;
          }>(),
      ).toEqual({
        state,
        updated_at: selectedTime,
        reconcile_attempts: 0,
        next_reconcile_at: 0,
        delete_not_before: state === "deleting" ? 0 : null,
      });
      expect(await env.BLOBS.head(keyB)).not.toBeNull();
      expect(
        await env.DB.prepare(
          `SELECT count(*) AS count FROM audit_events
            WHERE tenant_id = ? AND repository_id = ? AND actor = 'system:reconciler'`,
        )
          .bind(TENANT, REPOSITORY)
          .first<{ count: number }>(),
      ).toEqual({ count: 0 });
    },
  );

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

  it("accepts only generation-bound, signed, shareable v2 manifests with ready blobs", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
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
    invalidSignature.signature.signature[0] =
      (invalidSignature.signature.signature[0] ?? 0) ^ 1;
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

    const legacy = copyManifest(manifestWireFixture as RemoteCacheManifest);
    const legacyResponse = await putManifest(legacy);
    expect(legacyResponse.status).toBe(422);
    await expect(legacyResponse.json()).resolves.toMatchObject({
      error: { code: "unsupported_schema" },
    });
  });

  it("acknowledges an exact manifest retry after a benign cumulative trust advance", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);

    const advanced = copyTrustBundle(fixture.trustBundle);
    advanced.epoch = 2;
    advanced.issued_at_unix_seconds += 1;
    advanced.expires_at_unix_seconds += 1;
    await signTrustBundle(advanced, fixture.trustPrivateKey);
    expect((await putTrustBundle(advanced)).status).toBe(204);

    const retry = await putEncryptedManifestV2(fixture.manifest);
    expect(retry.status).toBe(204);
    expect(retry.headers.get("x-again-body-sha256")).toBe(
      await sha256Hex(JSON.stringify(fixture.manifest)),
    );
    expect(
      await env.DB.prepare(
        `SELECT manifest.state,
                (SELECT count(*) FROM audit_events audit
                  WHERE audit.tenant_id = manifest.tenant_id
                    AND audit.repository_id = manifest.repository_id
                    AND audit.action = 'manifest.put') AS put_audits,
                (SELECT count(*) FROM manifest_conflicts conflict
                  WHERE conflict.tenant_id = manifest.tenant_id
                    AND conflict.repository_id = manifest.repository_id
                    AND conflict.request_key = manifest.request_key) AS conflicts
           FROM manifests manifest
          WHERE manifest.tenant_id = ? AND manifest.repository_id = ?
            AND manifest.request_key = ?`,
      )
        .bind(TENANT, REPOSITORY, fixture.manifest.request_key)
        .first<{ state: string; put_audits: number; conflicts: number }>(),
    ).toEqual({ state: "ready", put_audits: 1, conflicts: 0 });
  });

  it.each([
    ["record revocation", "record_revoked"],
    ["policy removal", "policy_not_allowed"],
  ] as const)(
    "rejects an exact manifest retry after current trust %s",
    async (mode, code) => {
      const fixture = await prepareEncryptedManifestV2Fixture();
      expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);

      const advanced = copyTrustBundle(fixture.trustBundle);
      advanced.epoch = 2;
      advanced.issued_at_unix_seconds += 1;
      advanced.expires_at_unix_seconds += 1;
      if (mode === "record revocation") {
        advanced.revoked_record_ids = [fixture.manifest.record_id];
      } else {
        advanced.allowed_policy_digests = [];
      }
      await signTrustBundle(advanced, fixture.trustPrivateKey);
      expect((await putTrustBundle(advanced)).status).toBe(204);

      const retry = await putEncryptedManifestV2(fixture.manifest);
      expect(retry.status).toBe(422);
      expect(retry.headers.get("x-again-error-code")).toBe(code);
      expect(
        await env.DB.prepare(
          `SELECT state FROM manifests
          WHERE tenant_id = ? AND repository_id = ? AND request_key = ?`,
        )
          .bind(TENANT, REPOSITORY, fixture.manifest.request_key)
          .first<{ state: string }>(),
      ).toEqual({ state: "ready" });
    },
  );

  it("returns manifest_not_found only for genuine legacy-route unavailability", async () => {
    const missing = await call(
      `/v1/repositories/${REPOSITORY}/manifests/${"f".repeat(64)}`,
      authRequest(),
    );
    expect(missing.status).toBe(404);
    expect(missing.headers.get("x-again-error-code")).toBe(
      "manifest_not_found",
    );

    const available = await prepareEncryptedManifestV2Fixture();
    expect((await putManifest(available.manifest)).status).toBe(201);
    const fetched = await call(
      `/v1/repositories/${REPOSITORY}/manifests/${available.manifest.request_key}`,
      authRequest(),
    );
    expect(fetched.status).toBe(200);

    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}/manifests/${available.manifest.request_key}`,
          authRequest(undefined, "DELETE"),
        )
      ).status,
    ).toBe(204);
    const deleted = await call(
      `/v1/repositories/${REPOSITORY}/manifests/${available.manifest.request_key}`,
      authRequest(),
    );
    expect(deleted.status).toBe(404);
    expect(deleted.headers.get("x-again-error-code")).toBe(
      "manifest_not_found",
    );
  });

  it("treats denormalized manifest time corruption as hard state corruption before availability", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putManifest(fixture.manifest)).status).toBe(201);
    await env.DB.prepare(
      `UPDATE manifests SET expires_at = ?
        WHERE tenant_id = ? AND repository_id = ? AND request_key = ?`,
    )
      .bind(
        Math.floor(Date.now() / 1000) - 1,
        TENANT,
        REPOSITORY,
        fixture.manifest.request_key,
      )
      .run();

    const response = await call(
      `/v1/repositories/${REPOSITORY}/manifests/${fixture.manifest.request_key}`,
      authRequest(),
    );
    expect(response.status).toBe(409);
    expect(response.headers.get("x-again-error-code")).toBe(
      "manifest_state_corrupt",
    );
  });

  it("treats an impossible missing manifest producer relationship as hard corruption", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putManifest(fixture.manifest)).status).toBe(201);
    const response = await callUsingEnv(
      { DB: databaseThatDropsManifestProducer(env.DB), BLOBS: env.BLOBS },
      `/v1/repositories/${REPOSITORY}/manifests/${fixture.manifest.request_key}`,
      authRequest(),
    );
    expect(response.status).toBe(409);
    expect(response.headers.get("x-again-error-code")).toBe(
      "manifest_state_corrupt",
    );
  });

  it("rejects a manifest that expires while publication is paused before commit", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    const expiresAt = Math.floor(Date.now() / 1000) + 2;
    fixture.manifest.created_at_unix_seconds = expiresAt - 2;
    fixture.manifest.expires_at_unix_seconds = expiresAt;
    await signManifest(fixture.manifest, fixture.privateKey);
    const gate = databaseThatPausesMutation(env.DB, "INSERT INTO manifests");
    const publication = putManifestUsingEnv(
      { DB: gate.database, BLOBS: env.BLOBS },
      fixture.manifest,
    );
    await gate.entered;
    await waitUntilUnixSecondAfter(expiresAt);
    gate.release();

    const response = await publication;
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "expired_manifest" },
    });
    expect(
      await env.DB.prepare(
        `SELECT
           (SELECT count(*) FROM manifests
             WHERE tenant_id = ? AND repository_id = ?) AS manifests,
           (SELECT count(*) FROM audit_events
             WHERE tenant_id = ? AND repository_id = ?
               AND action = 'manifest.put') AS audits`,
      )
        .bind(TENANT, REPOSITORY, TENANT, REPOSITORY)
        .first<{ manifests: number; audits: number }>(),
    ).toEqual({ manifests: 0, audits: 0 });
  });

  it("stores only signed encrypted v2 manifests for confidential team results", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    const created = await putEncryptedManifestV2(fixture.manifest);
    expect(created.status).toBe(201);
    expect(created.headers.get("x-again-repository-generation")).toBe(
      GENERATION,
    );
    expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(204);

    const fetched = await call(
      `/v1/repositories/${REPOSITORY}/manifests/${fixture.manifest.request_key}`,
      authRequest(),
    );
    expect(fetched.status).toBe(200);
    await expect(fetched.json()).resolves.toEqual(fixture.manifest);

    const invalidSignature = copyEncryptedManifestV2(fixture.manifest);
    invalidSignature.request_key = "8".repeat(64);
    invalidSignature.signature.signature[0] =
      (invalidSignature.signature.signature[0] ?? 0) ^ 1;
    expect((await putEncryptedManifestV2(invalidSignature)).status).toBe(422);

    const reusedNonce = copyEncryptedManifestV2(fixture.manifest);
    reusedNonce.request_key = "7".repeat(64);
    reusedNonce.stderr.nonce = [...reusedNonce.stdout.nonce];
    await signEncryptedManifestV2(reusedNonce, fixture.privateKey);
    expect((await putEncryptedManifestV2(reusedNonce)).status).toBe(422);

    const secret = copyEncryptedManifestV2(fixture.manifest);
    secret.request_key = "6".repeat(64);
    secret.privacy.secret_tainted = true;
    await signEncryptedManifestV2(secret, fixture.privateKey);
    expect((await putEncryptedManifestV2(secret)).status).toBe(422);

    const plaintextShape = structuredClone(
      fixture.manifest,
    ) as unknown as Record<string, unknown>;
    plaintextShape.stdout = { digest: "0".repeat(64), size_bytes: 0 };
    expect(() =>
      parseEncryptedManifestV2(plaintextShape, Math.floor(Date.now() / 1000)),
    ).toThrow();
  });

  it("streams an exact two-ciphertext lookup bundle without buffering R2 bodies", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
    const response = await callUsingEnv(
      { DB: env.DB, BLOBS: bucketThatForbidsBodyBuffering(env.BLOBS) },
      `/v1/repositories/${REPOSITORY}/lookup-bundles/${fixture.manifest.request_key}`,
      authRequest(),
    );
    expect(response.status).toBe(200);
    expect(response.headers.get("content-type")).toBe(
      "application/vnd.again.lookup-bundle-v1",
    );
    expect(response.headers.get("cache-control")).toContain("no-store");
    expect(response.headers.get("x-again-repository-generation")).toBe(
      GENERATION,
    );
    const wire = new Uint8Array(await response.arrayBuffer());
    expect(new TextDecoder().decode(wire.subarray(0, 8))).toBe("AGNBNDL1");
    const view = new DataView(wire.buffer, wire.byteOffset, wire.byteLength);
    expect(view.getUint16(8)).toBe(1);
    expect(view.getUint16(10)).toBe(0);
    const trustLength = view.getUint32(12);
    const manifestLength = view.getUint32(16);
    const stdoutLength = view.getUint32(20);
    const stderrLength = view.getUint32(24);
    expect(view.getUint32(28)).toBe(0);
    expect(stdoutLength).toBe(fixture.manifest.stdout.ciphertext_size_bytes);
    expect(stderrLength).toBe(fixture.manifest.stderr.ciphertext_size_bytes);
    expect(wire.byteLength).toBe(
      32 + trustLength + manifestLength + stdoutLength + stderrLength,
    );
    let offset = 32;
    expect(
      JSON.parse(
        new TextDecoder().decode(wire.subarray(offset, offset + trustLength)),
      ),
    ).toEqual(fixture.trustBundle);
    offset += trustLength;
    expect(
      JSON.parse(
        new TextDecoder().decode(
          wire.subarray(offset, offset + manifestLength),
        ),
      ),
    ).toEqual(fixture.manifest);
    offset += manifestLength;
    expect(wire.subarray(offset, offset + stdoutLength)).toEqual(
      Uint8Array.from({ length: 48 }, (_, index) => (index * 17) & 0xff),
    );
    offset += stdoutLength;
    expect(wire.subarray(offset, offset + stderrLength)).toEqual(
      Uint8Array.from({ length: 16 }, (_, index) => (index * 29) & 0xff),
    );
  });

  it("does not pull either exact R2 response body before the final D1 bundle fence completes", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
    const stdoutKey = await blobObjectKey(
      fixture.manifest.stdout.ciphertext_digest,
    );
    const stderrKey = await blobObjectKey(
      fixture.manifest.stderr.ciphertext_digest,
    );
    const tracked = bucketThatTracksResponseBodyPulls(env.BLOBS);
    const fence = databaseThatPausesExactBundleFinalFence(env.DB);
    const lookup = callUsingEnv(
      { DB: fence.database, BLOBS: tracked.bucket },
      `/v1/repositories/${REPOSITORY}/lookup-bundles/${fixture.manifest.request_key}`,
      authRequest(),
    );

    await fence.entered;
    try {
      expect(fence.matchCount()).toBe(1);
      expect(tracked.getCount(stdoutKey)).toBe(1);
      expect(tracked.getCount(stderrKey)).toBe(1);
      expect(tracked.pullCount(stdoutKey)).toBe(0);
      expect(tracked.pullCount(stderrKey)).toBe(0);
    } finally {
      fence.release();
    }

    const response = await lookup;
    expect(response.status).toBe(200);
    expect(response.headers.get("x-again-repository-generation")).toBe(
      GENERATION,
    );
    const wire = new Uint8Array(await response.arrayBuffer());
    expect(wire.byteLength).toBe(Number(response.headers.get("content-length")));
    const decoded = decodeServiceLookupBundleWire(wire);
    expect(JSON.parse(new TextDecoder().decode(decoded.initialTrust))).toEqual(
      fixture.trustBundle,
    );
    expect(JSON.parse(new TextDecoder().decode(decoded.manifest))).toEqual(
      fixture.manifest,
    );
    expect(decoded.stdout).toEqual(
      Uint8Array.from({ length: 48 }, (_, index) => (index * 17) & 0xff),
    );
    expect(decoded.stderr).toEqual(
      Uint8Array.from({ length: 16 }, (_, index) => (index * 29) & 0xff),
    );
    expect(tracked.pullCount(stdoutKey)).toBeGreaterThan(0);
    expect(tracked.pullCount(stderrKey)).toBeGreaterThan(0);
  });

  it("enforces auth, exact generation, tenant, and repository isolation on bundles", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
    const path = `/v1/repositories/${REPOSITORY}/lookup-bundles/${fixture.manifest.request_key}`;
    expect(
      (
        await call(path, {
          headers: { "x-again-repository-generation": GENERATION },
        })
      ).status,
    ).toBe(401);
    expect(
      (
        await call(path, {
          headers: { authorization: `Bearer ${BEARER}` },
        })
      ).status,
    ).toBe(428);
    expect(
      (await call(path, authRequest(undefined, "GET", "2".repeat(32)))).status,
    ).toBe(412);

    const secretB = "Z".repeat(43);
    await seedTenant("tenant-isolated", "token-isolated", secretB, REPOSITORY);
    const isolated = await call(path, {
      headers: {
        authorization: `Bearer ag1.token-isolated.${secretB}`,
        "x-again-repository-generation": GENERATION,
      },
    });
    expect(isolated.status).toBe(404);
    expect(isolated.headers.get("x-again-error-code")).toBe(
      "manifest_not_found",
    );

    const createdRepository = await call(
      "/v1/repositories",
      jsonRequest({ repository_id: "repo-isolated" }),
    );
    expect(createdRepository.status).toBe(201);
    const isolatedGeneration = (
      await createdRepository.json<{ generation_id: string }>()
    ).generation_id;
    const repositoryIsolated = await call(
      `/v1/repositories/repo-isolated/lookup-bundles/${fixture.manifest.request_key}`,
      authRequest(undefined, "GET", isolatedGeneration),
    );
    expect(repositoryIsolated.status).toBe(404);
    expect(repositoryIsolated.headers.get("x-again-error-code")).toBe(
      "manifest_not_found",
    );
  });

  it.each([
    {
      label: "valid hit",
      state: "valid",
      disposition: "hit",
      bundle: [200, null],
      reference: [200, null, "complete"],
    },
    {
      label: "absent manifest",
      state: "absent_manifest",
      disposition: "miss",
      bundle: [404, "manifest_not_found"],
      reference: [404, "manifest_not_found", "manifest"],
    },
    {
      label: "deleted manifest",
      state: "deleted_manifest",
      disposition: "miss",
      bundle: [404, "manifest_not_found"],
      reference: [404, "manifest_not_found", "manifest"],
    },
    {
      label: "ordinary manifest expiry",
      state: "expired_manifest",
      disposition: "miss",
      bundle: [404, "manifest_not_found"],
      reference: [404, "manifest_not_found", "manifest"],
    },
    {
      label: "not-yet-valid manifest",
      state: "future_manifest",
      disposition: "miss",
      bundle: [404, "manifest_not_found"],
      reference: [404, "manifest_not_found", "manifest"],
    },
    {
      label: "trust-revoked producer",
      state: "revoked_producer",
      disposition: "miss",
      bundle: [404, "manifest_not_found"],
      reference: [404, "manifest_not_found", "manifest"],
    },
    {
      label: "trust-revoked record",
      state: "revoked_record",
      disposition: "miss",
      bundle: [404, "manifest_not_found"],
      reference: [404, "manifest_not_found", "manifest"],
    },
    {
      label: "disallowed signed binding",
      state: "disallowed_binding",
      disposition: "miss",
      bundle: [404, "manifest_not_found"],
      reference: [404, "manifest_not_found", "manifest"],
    },
    {
      label: "quarantined manifest",
      state: "quarantined_manifest",
      disposition: "hard_fail",
      bundle: [409, "manifest_state_corrupt"],
      reference: [409, "manifest_state_corrupt", "manifest"],
    },
    {
      label: "non-ready blob row",
      state: "non_ready_blob",
      disposition: "hard_fail",
      bundle: [409, "manifest_state_corrupt"],
      reference: [409, "manifest_state_corrupt", "manifest"],
    },
    {
      label: "inconsistent manifest metadata",
      state: "inconsistent_metadata",
      disposition: "hard_fail",
      bundle: [409, "manifest_state_corrupt"],
      reference: [409, "manifest_state_corrupt", "manifest"],
    },
    {
      label: "missing stdout R2 object",
      state: "missing_blob",
      disposition: "hard_fail",
      bundle: [409, "blob_integrity_failure"],
      reference: [409, "blob_integrity_failure", "stdout_blob"],
    },
    {
      label: "corrupt stderr R2 object",
      state: "corrupt_blob",
      disposition: "hard_fail",
      bundle: [409, "blob_integrity_failure"],
      reference: [409, "blob_integrity_failure", "stderr_blob"],
    },
    {
      label: "missing trust",
      state: "missing_trust",
      disposition: "hard_fail",
      bundle: [422, "fresh_trust_required"],
      reference: [404, "not_found", "initial_trust"],
    },
    {
      label: "expired trust",
      state: "expired_trust",
      disposition: "hard_fail",
      bundle: [422, "fresh_trust_required"],
      reference: [404, "not_found", "initial_trust"],
    },
    {
      label: "malformed trust",
      state: "malformed_trust",
      disposition: "hard_fail",
      bundle: [409, "trust_state_corrupt"],
      reference: [409, "trust_state_corrupt", "initial_trust"],
    },
    {
      label: "disabled trust root",
      state: "disabled_root",
      disposition: "hard_fail",
      bundle: [422, "fresh_trust_required"],
      reference: [404, "not_found", "initial_trust"],
    },
    {
      label: "wrong repository generation",
      state: "wrong_generation",
      disposition: "hard_fail",
      bundle: [412, "repository_generation_mismatch"],
      reference: [412, "repository_generation_mismatch", "initial_trust"],
    },
  ] as const)(
    "matches the actual five-request service route for $label",
    async ({ state, disposition, bundle: expectedBundle, reference: expectedReference }) => {
      const fixture = await prepareEncryptedManifestV2Fixture();
      expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
      const configured = await configureBundleReferenceMatrixState(
        state,
        fixture,
      );
      // Observe the bundle first. A reference blob GET is allowed to quarantine
      // corrupt storage, which would otherwise change the state being compared.
      const bundled = await observeBundleRoute(
        configured.runtimeEnv,
        configured.manifest,
        configured.generationId,
      );
      const reference = await observeFiveRequestReferenceRoute(
        configured.runtimeEnv,
        configured.manifest,
        configured.generationId,
      );

      expect(bundled).toMatchObject({
        disposition,
        stage: "bundle",
        status: expectedBundle[0],
        code: expectedBundle[1],
      });
      expect(reference).toMatchObject({
        disposition,
        stage: expectedReference[2],
        status: expectedReference[0],
        code: expectedReference[1],
      });
      if (disposition === "hit") {
        expect(bundled.initialTrust).toEqual(reference.initialTrust);
        expect(bundled.manifest).toEqual(reference.manifest);
        expect(bundled.stdout).toEqual(reference.stdout);
        expect(bundled.stderr).toEqual(reference.stderr);
        expect(reference.finalTrust).toEqual(reference.initialTrust);
      } else if (disposition === "miss") {
        expect(bundled.code).toBe("manifest_not_found");
        expect(reference.code).toBe("manifest_not_found");
      } else {
        expect(bundled.code).not.toBe("manifest_not_found");
        expect(reference.code).not.toBe("manifest_not_found");
      }
    },
  );

  it.each(["stdout", "stderr"] as const)(
    "rechecks trust after the exact %s R2 GET and cancels both retained bodies on raced revocation",
    async (field) => {
      const fixture = await prepareEncryptedManifestV2Fixture();
      expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
      const targetKey = await blobObjectKey(
        fixture.manifest[field].ciphertext_digest,
      );
      const tracked = bucketThatTracksStreamCancellation(env.BLOBS, 2);
      const gate = bucketThatPausesGetAfterReadForKey(
        tracked.bucket,
        targetKey,
      );
      const lookup = callUsingEnv(
        { DB: env.DB, BLOBS: gate.bucket },
        `/v1/repositories/${REPOSITORY}/lookup-bundles/${fixture.manifest.request_key}`,
        authRequest(),
      );
      await gate.entered;
      expect(gate.matchCount()).toBe(1);
      const revoked = copyTrustBundle(fixture.trustBundle);
      revoked.epoch += 1;
      revoked.issued_at_unix_seconds += 1;
      revoked.expires_at_unix_seconds += 1;
      revoked.revoked_record_ids = [fixture.manifest.record_id];
      await signTrustBundle(revoked, fixture.trustPrivateKey);
      expect((await putTrustBundle(revoked)).status).toBe(204);
      gate.release();
      const response = await lookup;
      // The post-R2 authorization/final fence must classify the now-revoked
      // candidate as a miss before any bundle body is handed off.
      expect(response.status).toBe(404);
      expect(response.headers.get("x-again-error-code")).toBe(
        "manifest_not_found",
      );
      expect(response.headers.get("content-type")).not.toBe(
        "application/vnd.again.lookup-bundle-v1",
      );
      expect(tracked.cancelCount()).toBe(2);
    },
  );

  it.each(["stdout", "stderr"] as const)(
    "carries the latest still-authorizing trust after the exact %s R2 GET without cancelling successful bodies",
    async (field) => {
      const fixture = await prepareEncryptedManifestV2Fixture();
      expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
      const targetKey = await blobObjectKey(
        fixture.manifest[field].ciphertext_digest,
      );
      const tracked = bucketThatTracksStreamCancellation(env.BLOBS, 1);
      const gate = bucketThatPausesGetAfterReadForKey(
        tracked.bucket,
        targetKey,
      );
      const lookup = callUsingEnv(
        { DB: env.DB, BLOBS: gate.bucket },
        `/v1/repositories/${REPOSITORY}/lookup-bundles/${fixture.manifest.request_key}`,
        authRequest(),
      );
      await gate.entered;
      expect(gate.matchCount()).toBe(1);
      const rotated = copyTrustBundle(fixture.trustBundle);
      rotated.epoch += 1;
      rotated.issued_at_unix_seconds += 1;
      rotated.expires_at_unix_seconds += 1;
      await signTrustBundle(rotated, fixture.trustPrivateKey);
      expect((await putTrustBundle(rotated)).status).toBe(204);
      gate.release();
      const response = await lookup;
      expect(response.status).toBe(200);
      expect(response.headers.get("x-again-repository-generation")).toBe(
        GENERATION,
      );
      const wire = new Uint8Array(await response.arrayBuffer());
      expect(wire.byteLength).toBe(Number(response.headers.get("content-length")));
      const trustLength = new DataView(
        wire.buffer,
        wire.byteOffset,
        wire.byteLength,
      ).getUint32(12);
      expect(
        JSON.parse(
          new TextDecoder().decode(wire.subarray(32, 32 + trustLength)),
        ),
      ).toEqual(rotated);
      // Full successful consumption closes both bodies; it must not invoke
      // their cancellation algorithms.
      expect(tracked.cancelCount()).toBe(0);
    },
  );

  it("rejects a manifest transition after R2 reads at the final atomic fence", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
    const gate = bucketThatPausesFirstGetAfterRead(env.BLOBS);
    const lookup = callUsingEnv(
      { DB: env.DB, BLOBS: gate.bucket },
      `/v1/repositories/${REPOSITORY}/lookup-bundles/${fixture.manifest.request_key}`,
      authRequest(),
    );
    await gate.entered;
    await env.DB.prepare(
      `UPDATE manifests SET state = 'quarantined'
        WHERE tenant_id = ? AND repository_id = ? AND request_key = ?`,
    )
      .bind(TENANT, REPOSITORY, fixture.manifest.request_key)
      .run();
    gate.release();
    const response = await lookup;
    expect(response.status).toBe(409);
    expect(response.headers.get("x-again-error-code")).toBe(
      "manifest_state_corrupt",
    );
  });

  it.each([
    ["missing candidate", "missing", 404, "manifest_not_found"],
    ["deleted candidate", "deleted", 404, "manifest_not_found"],
    ["quarantined candidate", "quarantined", 409, "manifest_state_corrupt"],
    ["missing trust", "missing_trust", 422, "fresh_trust_required"],
    ["missing R2 ciphertext", "missing_blob", 409, "blob_integrity_failure"],
  ] as const)(
    "classifies bundle %s without converting corruption to a miss",
    async (_label, state, expectedStatus, expectedCode) => {
      if (state === "missing") {
        const response = await call(
          `/v1/repositories/${REPOSITORY}/lookup-bundles/${"f".repeat(64)}`,
          authRequest(),
        );
        expect(response.status).toBe(expectedStatus);
        expect(response.headers.get("x-again-error-code")).toBe(expectedCode);
        return;
      }
      const fixture = await prepareEncryptedManifestV2Fixture();
      expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
      if (state === "deleted" || state === "quarantined") {
        await env.DB.prepare(
          `UPDATE manifests SET state = ?
            WHERE tenant_id = ? AND repository_id = ? AND request_key = ?`,
        )
          .bind(state, TENANT, REPOSITORY, fixture.manifest.request_key)
          .run();
      } else if (state === "missing_trust") {
        await env.DB.prepare(
          "DELETE FROM trust_heads WHERE tenant_id = ? AND repository_id = ?",
        )
          .bind(TENANT, REPOSITORY)
          .run();
      } else {
        await env.BLOBS.delete(
          await blobObjectKey(fixture.manifest.stdout.ciphertext_digest),
        );
      }
      const response = await call(
        `/v1/repositories/${REPOSITORY}/lookup-bundles/${fixture.manifest.request_key}`,
        authRequest(),
      );
      expect(response.status).toBe(expectedStatus);
      expect(response.headers.get("x-again-error-code")).toBe(expectedCode);
    },
  );

  it("fails closed when an R2 upload identity changes after publication", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
    const digest = fixture.manifest.stdout.ciphertext_digest;
    const key = await blobObjectKey(digest);
    const bytes = Uint8Array.from(
      { length: 48 },
      (_, index) => (index * 17) & 0xff,
    );
    const incarnationId = await blobIncarnation(digest);
    await env.BLOBS.put(key, bytes, {
      customMetadata: {
        blake3: digest,
        size_bytes: String(bytes.byteLength),
        incarnation_id: incarnationId,
      },
      sha256: await crypto.subtle.digest("SHA-256", bytes),
    });
    const response = await call(
      `/v1/repositories/${REPOSITORY}/lookup-bundles/${fixture.manifest.request_key}`,
      authRequest(),
    );
    expect(response.status).toBe(409);
    expect(response.headers.get("x-again-error-code")).toBe(
      "blob_integrity_failure",
    );
  });

  it.each([
    ["key", "r2_key", "wrong-key", "blob_integrity_failure"],
    ["version", "r2_version", "wrong-version", "blob_integrity_failure"],
    ["ETag", "r2_etag", "wrong-etag", "blob_integrity_failure"],
    ["SHA-256", "r2_sha256", "f".repeat(64), "blob_integrity_failure"],
  ] as const)(
    "rejects a mismatched persisted R2 %s tuple component",
    async (_label, column, value, expectedCode) => {
      const fixture = await prepareEncryptedManifestV2Fixture();
      expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
      const digest = fixture.manifest.stdout.ciphertext_digest;
      await env.DB.prepare(
        `UPDATE blobs SET state = 'pending'
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(TENANT, REPOSITORY, digest)
        .run();
      await env.DB.prepare(
        `UPDATE blobs SET ${column} = ?
          WHERE tenant_id = ? AND repository_id = ? AND digest = ? AND state = 'pending'`,
      )
        .bind(value, TENANT, REPOSITORY, digest)
        .run();
      await env.DB.prepare(
        `UPDATE blobs SET state = 'ready'
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(TENANT, REPOSITORY, digest)
        .run();
      const response = await call(
        `/v1/repositories/${REPOSITORY}/lookup-bundles/${fixture.manifest.request_key}`,
        authRequest(),
      );
      expect(response.status).toBe(409);
      expect(response.headers.get("x-again-error-code")).toBe(expectedCode);
    },
  );

  it("rejects mismatched R2 custom metadata even when the persisted upload tuple is exact", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
    const digest = fixture.manifest.stdout.ciphertext_digest;
    const bytes = Uint8Array.from(
      { length: 48 },
      (_, index) => (index * 17) & 0xff,
    );
    const key = await blobObjectKey(digest);
    const incarnationId = await blobIncarnation(digest);
    const object = await env.BLOBS.put(key, bytes, {
      customMetadata: {
        blake3: "f".repeat(64),
        size_bytes: String(bytes.byteLength),
        incarnation_id: incarnationId,
      },
      sha256: await crypto.subtle.digest("SHA-256", bytes),
    });
    const sha = object.checksums.sha256;
    if (sha === undefined) throw new Error("test R2 object lacks SHA-256");
    await env.DB.prepare(
      `UPDATE blobs SET state = 'pending'
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(TENANT, REPOSITORY, digest)
      .run();
    await env.DB.prepare(
      `UPDATE blobs
          SET r2_key = ?, r2_version = ?, r2_etag = ?, r2_sha256 = ?, state = 'ready'
        WHERE tenant_id = ? AND repository_id = ? AND digest = ? AND state = 'pending'`,
    )
      .bind(
        object.key,
        object.version,
        object.etag,
        bytesToHex(new Uint8Array(sha)),
        TENANT,
        REPOSITORY,
        digest,
      )
      .run();
    const response = await call(
      `/v1/repositories/${REPOSITORY}/lookup-bundles/${fixture.manifest.request_key}`,
      authRequest(),
    );
    expect(response.status).toBe(409);
    expect(response.headers.get("x-again-error-code")).toBe(
      "blob_integrity_failure",
    );
  });

  it("rejects a D1 blob-size mismatch before opening a bundle stream", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
    await env.DB.prepare(
      `UPDATE blobs SET size_bytes = size_bytes + 1
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(TENANT, REPOSITORY, fixture.manifest.stdout.ciphertext_digest)
      .run();
    const response = await call(
      `/v1/repositories/${REPOSITORY}/lookup-bundles/${fixture.manifest.request_key}`,
      authRequest(),
    );
    expect(response.status).toBe(409);
    expect(response.headers.get("x-again-error-code")).toBe(
      "manifest_state_corrupt",
    );
  });

  it.each(["legacy-null", "partial"] as const)(
    "never treats a %s R2 identity tuple as bundle-eligible",
    async (mode) => {
      const fixture = await prepareEncryptedManifestV2Fixture();
      expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
      const response = await callUsingEnv(
        {
          DB: databaseThatOverridesBlobIdentity(env.DB, mode),
          BLOBS: env.BLOBS,
        },
        `/v1/repositories/${REPOSITORY}/lookup-bundles/${fixture.manifest.request_key}`,
        authRequest(),
      );
      expect(response.status).toBe(409);
      expect(response.headers.get("x-again-error-code")).toBe(
        "blob_integrity_failure",
      );
    },
  );

  it("cancels both retained R2 streams when the bundle client disconnects", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
    const tracked = bucketThatTracksStreamCancellation(env.BLOBS, 2);
    const response = await callUsingEnv(
      { DB: env.DB, BLOBS: tracked.bucket },
      `/v1/repositories/${REPOSITORY}/lookup-bundles/${fixture.manifest.request_key}`,
      authRequest(),
    );
    expect(response.status).toBe(200);
    if (response.body === null)
      throw new Error("bundle response body is missing");
    await response.body.cancel("test client disconnected");
    await tracked.cancelled;
    expect(tracked.cancelCount()).toBe(2);
  });

  it.each(["stdout", "stderr"] as const)(
    "aborts a generation-A bundle paused after the exact %s R2 read before recreated B can cross the final fence",
    async (field) => {
      const fixture = await prepareEncryptedManifestV2Fixture();
      expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
      const generationA = fixture.manifest.generation_id;
      expect(generationA).toBe(GENERATION);
      const stdoutCiphertext = Uint8Array.from(
        { length: 48 },
        (_, index) => (index * 17) & 0xff,
      );
      const stderrCiphertext = Uint8Array.from(
        { length: 16 },
        (_, index) => (index * 29) & 0xff,
      );
      const ciphertext =
        field === "stdout" ? stdoutCiphertext : stderrCiphertext;
      const digest = fixture.manifest[field].ciphertext_digest;
      expect(bytesToHex(blake3(ciphertext))).toBe(digest);
      const incarnationA = await blobIncarnation(digest);
      const objectKeyA = await blobObjectKey(digest, generationA);
      expect(objectKeyA).toContain(`/${generationA}/`);
      expect(objectKeyA).toContain(`/${incarnationA}`);

      const tracked = bucketThatTracksStreamCancellation(env.BLOBS, 2);
      const gate = bucketThatPausesGetAfterReadForKey(
        tracked.bucket,
        objectKeyA,
      );
      const staleLookup = callUsingEnv(
        { DB: env.DB, BLOBS: gate.bucket },
        `/v1/repositories/${REPOSITORY}/lookup-bundles/${fixture.manifest.request_key}`,
        authRequest(undefined, "GET", generationA),
      );
      await gate.entered;
      expect(gate.matchCount()).toBe(1);

      expect(
        (
          await call(
            `/v1/repositories/${REPOSITORY}`,
            repositoryDeleteRequest(generationA),
          )
        ).status,
      ).toBe(202);
      await finishRepositoryDeletion();
      expect(await env.BLOBS.head(objectKeyA)).toBeNull();

      const recreated = await call(
        "/v1/repositories",
        jsonRequest({ repository_id: REPOSITORY }),
      );
      expect(recreated.status).toBe(201);
      const generationB = (await recreated.json<{ generation_id: string }>())
        .generation_id;
      expect(generationB).not.toBe(generationA);
      const fixtureB = await prepareEncryptedManifestV2Fixture(generationB);
      expect(fixtureB.manifest.request_key).toBe(fixture.manifest.request_key);
      expect(fixtureB.manifest.stdout.ciphertext_digest).toBe(
        fixture.manifest.stdout.ciphertext_digest,
      );
      expect(fixtureB.manifest.stderr.ciphertext_digest).toBe(
        fixture.manifest.stderr.ciphertext_digest,
      );
      expect(
        (await putEncryptedManifestV2(fixtureB.manifest, generationB)).status,
      ).toBe(201);
      const incarnationB = await blobIncarnation(digest);
      const objectKeyB = await blobObjectKey(digest, generationB);
      expect(incarnationB).not.toBe(incarnationA);
      expect(objectKeyB).not.toBe(objectKeyA);
      expect(objectKeyB).toContain(`/${generationB}/`);
      expect(objectKeyB).toContain(`/${incarnationB}`);

      const expectFreshBExactSuccess = async (): Promise<void> => {
        const observed = await observeBundleRoute(
          env,
          fixtureB.manifest,
          generationB,
        );
        expect(observed).toMatchObject({
          disposition: "hit",
          stage: "bundle",
          status: 200,
          code: null,
        });
        if (
          observed.initialTrust === undefined ||
          observed.manifest === undefined ||
          observed.stdout === undefined ||
          observed.stderr === undefined
        ) {
          throw new Error("generation-B exact bundle omitted a required field");
        }
        expect(
          JSON.parse(new TextDecoder().decode(observed.initialTrust)),
        ).toEqual(fixtureB.trustBundle);
        expect(JSON.parse(new TextDecoder().decode(observed.manifest))).toEqual(
          fixtureB.manifest,
        );
        expect(observed.stdout).toEqual(stdoutCiphertext);
        expect(observed.stderr).toEqual(stderrCiphertext);
      };
      // B is already a complete, exactly readable candidate while A remains
      // paused with generation-A R2 response bodies retained.
      await expectFreshBExactSuccess();

      gate.release();
      const response = await staleLookup;
      // This is the post-R2 generation/final-fence result. A bundle response,
      // even one carrying bytes from A, must never be constructed for B.
      expect(response.status).toBe(412);
      expect(response.headers.get("x-again-error-code")).toBe(
        "repository_generation_mismatch",
      );
      expect(response.headers.get("content-type")).not.toBe(
        "application/vnd.again.lookup-bundle-v1",
      );
      expect(tracked.cancelCount()).toBe(2);

      const liveRepository = await env.DB.prepare(
        `SELECT generation_id FROM repositories
          WHERE tenant_id = ? AND id = ? AND deleted_at IS NULL`,
      )
        .bind(TENANT, REPOSITORY)
        .first<{ generation_id: string }>();
      expect(liveRepository?.generation_id).toBe(generationB);
      const liveBlob = await env.DB.prepare(
        `SELECT state, incarnation_id, r2_key FROM blobs
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(TENANT, REPOSITORY, digest)
        .first<{
          state: string;
          incarnation_id: string;
          r2_key: string | null;
        }>();
      expect(liveBlob).toEqual({
        state: "ready",
        incarnation_id: incarnationB,
        r2_key: objectKeyB,
      });
      const liveObject = await env.BLOBS.head(objectKeyB);
      expect(liveObject?.customMetadata?.incarnation_id).toBe(incarnationB);
      // Letting A finish and cancel its retained streams cannot mutate B's
      // same-key/same-digest candidate or prevent an exact bundle success.
      await expectFreshBExactSuccess();
    },
  );

  it.each(["stdout", "stderr"] as const)(
    "aborts an otherwise authorized bundle when the %s R2 body fails mid-stream",
    async (field) => {
      const fixture = await prepareEncryptedManifestV2Fixture();
      expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
      const stdoutKey = await blobObjectKey(
        fixture.manifest.stdout.ciphertext_digest,
      );
      const stderrKey = await blobObjectKey(
        fixture.manifest.stderr.ciphertext_digest,
      );
      const failingKey = field === "stdout" ? stdoutKey : stderrKey;
      const injected = bucketThatFailsBodyMidStream(env.BLOBS, failingKey);
      const response = await callUsingEnv(
        { DB: env.DB, BLOBS: injected.bucket },
        `/v1/repositories/${REPOSITORY}/lookup-bundles/${fixture.manifest.request_key}`,
        authRequest(),
      );
      expect(response.status).toBe(200);
      expect(response.headers.get("x-again-repository-generation")).toBe(
        GENERATION,
      );
      const declaredLength = Number(response.headers.get("content-length"));
      expect(Number.isSafeInteger(declaredLength)).toBe(true);
      const failed = await readResponseUntilStreamFailure(response);
      // A 200 header is not a successful bundle: exact framing requires the
      // declared body length. The injected source failure must abort early.
      expect(failed.receivedBytes).toBeLessThan(declaredLength);
      expect(failed.error).toBeInstanceOf(Error);
      expect(injected.failureCount()).toBe(1);
      expect(injected.cancelCount(failingKey)).toBe(1);
      if (field === "stdout") {
        // stderr has not entered its wire position and must be cancelled.
        expect(injected.cancelCount(stderrKey)).toBe(1);
      } else {
        // stdout was already emitted; only stderr's unused tail remains.
        expect(injected.cancelCount(stdoutKey)).toBe(0);
      }
    },
  );

  it("rejects generation-A trust and encrypted manifests after repository recreation as B", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);

    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}`,
          repositoryDeleteRequest(GENERATION),
        )
      ).status,
    ).toBe(202);
    await finishRepositoryDeletion();
    const recreated = await call(
      "/v1/repositories",
      jsonRequest({ repository_id: REPOSITORY }),
    );
    expect(recreated.status).toBe(201);
    const generationB = (await recreated.json<{ generation_id: string }>())
      .generation_id;
    expect(generationB).not.toBe(GENERATION);

    expect((await putTrustBundle(fixture.trustBundle, GENERATION)).status).toBe(
      412,
    );
    const replayedTrust = await putTrustBundle(
      fixture.trustBundle,
      generationB,
    );
    expect(replayedTrust.status).toBe(422);
    await expect(replayedTrust.json()).resolves.toMatchObject({
      error: { code: "repository_generation_mismatch" },
    });

    expect(
      (await putEncryptedManifestV2(fixture.manifest, GENERATION)).status,
    ).toBe(412);
    const replayedManifest = await putEncryptedManifestV2(
      fixture.manifest,
      generationB,
    );
    expect(replayedManifest.status).toBe(422);
    await expect(replayedManifest.json()).resolves.toMatchObject({
      error: { code: "repository_generation_mismatch" },
    });
    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}/manifests/${fixture.manifest.request_key}`,
          authRequest(undefined, "GET", generationB),
        )
      ).status,
    ).toBe(404);
  });

  it("requires fresh signed trust and immediately hides encrypted records after revocation", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);

    const revoked = copyTrustBundle(fixture.trustBundle);
    revoked.epoch = 2;
    revoked.issued_at_unix_seconds += 1;
    revoked.expires_at_unix_seconds += 1;
    revoked.revoked_record_ids = [fixture.manifest.record_id];
    await signTrustBundle(revoked, fixture.trustPrivateKey);
    expect((await putTrustBundle(revoked)).status).toBe(204);

    const hidden = await call(
      `/v1/repositories/${REPOSITORY}/manifests/${fixture.manifest.request_key}`,
      authRequest(),
    );
    expect(hidden.status).toBe(404);
    expect(hidden.headers.get("x-again-error-code")).toBe("manifest_not_found");
    await expect(hidden.json()).resolves.toMatchObject({
      error: { code: "manifest_not_found" },
    });
    const republish = await putEncryptedManifestV2(fixture.manifest);
    expect(republish.status).toBe(422);
    await expect(republish.json()).resolves.toMatchObject({
      error: { code: "record_revoked" },
    });

    const disallowed = copyTrustBundle(revoked);
    disallowed.epoch = 3;
    disallowed.issued_at_unix_seconds += 1;
    disallowed.expires_at_unix_seconds += 1;
    disallowed.allowed_policy_digests = [];
    await signTrustBundle(disallowed, fixture.trustPrivateKey);
    expect((await putTrustBundle(disallowed)).status).toBe(204);

    const newRecord = copyEncryptedManifestV2(fixture.manifest);
    newRecord.record_id = "encrypted-record-2";
    newRecord.request_key = "d".repeat(64);
    await signEncryptedManifestV2(newRecord, fixture.privateKey);
    const denied = await putEncryptedManifestV2(newRecord);
    expect(denied.status).toBe(422);
    await expect(denied.json()).resolves.toMatchObject({
      error: { code: "policy_not_allowed" },
    });
  });

  it("rejects encrypted publication without a fresh trust head", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    await env.DB.prepare(
      "DELETE FROM trust_heads WHERE tenant_id = ? AND repository_id = ?",
    )
      .bind(TENANT, REPOSITORY)
      .run();
    const response = await putEncryptedManifestV2(fixture.manifest);
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "fresh_trust_required" },
    });
  });

  it("does not downgrade missing current trust on an existing encrypted manifest to a cache miss", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
    await env.DB.prepare(
      "DELETE FROM trust_heads WHERE tenant_id = ? AND repository_id = ?",
    )
      .bind(TENANT, REPOSITORY)
      .run();

    const response = await call(
      `/v1/repositories/${REPOSITORY}/manifests/${fixture.manifest.request_key}`,
      authRequest(),
    );
    expect(response.status).toBe(422);
    expect(response.headers.get("x-again-error-code")).toBe(
      "fresh_trust_required",
    );
  });

  it.each([
    ["valid", 404, "manifest_not_found"],
    ["missing", 422, "fresh_trust_required"],
    ["expired", 422, "fresh_trust_required"],
    ["root_disabled", 422, "fresh_trust_required"],
    ["malformed", 409, "trust_state_corrupt"],
  ] as const)(
    "preserves trust-state precedence over a revoked producer with %s trust",
    async (trustState, expectedStatus, expectedCode) => {
      const fixture = await prepareEncryptedManifestV2Fixture();
      expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
      expect(
        (
          await call(
            `/v1/repositories/${REPOSITORY}/producers/key-1`,
            authRequest(undefined, "DELETE"),
          )
        ).status,
      ).toBe(204);

      let runtimeDb = env.DB;
      if (trustState === "missing") {
        await env.DB.prepare(
          "DELETE FROM trust_heads WHERE tenant_id = ? AND repository_id = ?",
        )
          .bind(TENANT, REPOSITORY)
          .run();
      } else if (trustState === "expired") {
        runtimeDb = databaseThatOverridesTrustHead(env.DB, "expired");
      } else if (trustState === "root_disabled") {
        await env.DB.prepare(
          `UPDATE trust_root_keys SET disabled_at = ?
            WHERE tenant_id = ? AND repository_id = ? AND root_key_id = 'root-key-1'`,
        )
          .bind(Math.floor(Date.now() / 1000), TENANT, REPOSITORY)
          .run();
      } else if (trustState === "malformed") {
        runtimeDb = databaseThatOverridesTrustHead(env.DB, "malformed");
      }

      const response = await callUsingEnv(
        { DB: runtimeDb, BLOBS: env.BLOBS },
        `/v1/repositories/${REPOSITORY}/manifests/${fixture.manifest.request_key}`,
        authRequest(),
      );
      expect(response.status).toBe(expectedStatus);
      expect(response.headers.get("x-again-error-code")).toBe(expectedCode);
    },
  );

  it("maps a currently disallowed encrypted candidate to manifest_not_found", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putEncryptedManifestV2(fixture.manifest)).status).toBe(201);
    const disallowed = copyTrustBundle(fixture.trustBundle);
    disallowed.epoch = 2;
    disallowed.issued_at_unix_seconds += 1;
    disallowed.expires_at_unix_seconds += 1;
    disallowed.allowed_policy_digests = [];
    await signTrustBundle(disallowed, fixture.trustPrivateKey);
    expect((await putTrustBundle(disallowed)).status).toBe(204);

    const response = await call(
      `/v1/repositories/${REPOSITORY}/manifests/${fixture.manifest.request_key}`,
      authRequest(),
    );
    expect(response.status).toBe(404);
    expect(response.headers.get("x-again-error-code")).toBe(
      "manifest_not_found",
    );
  });

  it("rejects a stale verified trust snapshot at the atomic manifest-insert boundary", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    const oldHead = await env.DB.prepare(
      "SELECT epoch, body_sha256 FROM trust_heads WHERE tenant_id = ? AND repository_id = ?",
    )
      .bind(TENANT, REPOSITORY)
      .first<{ epoch: number; body_sha256: string }>();
    if (oldHead === null) throw new Error("fixture trust head is missing");

    const advanced = copyTrustBundle(fixture.trustBundle);
    advanced.epoch = 2;
    advanced.issued_at_unix_seconds += 1;
    advanced.expires_at_unix_seconds += 1;
    await signTrustBundle(advanced, fixture.trustPrivateKey);
    expect((await putTrustBundle(advanced)).status).toBe(204);

    const manifest = fixture.manifest;
    const stdout = manifest.stdout;
    const stderr = manifest.stderr;
    const bodyJson = JSON.stringify(manifest);
    await expect(
      env.DB.prepare(
        `INSERT INTO manifests(
           tenant_id, repository_id, request_key, record_id, body_sha256, body_json,
           state, producer_id, key_id, stdout_digest, stdout_size_bytes,
           stderr_digest, stderr_size_bytes, created_at, expires_at,
           trust_epoch, trust_body_sha256
         ) VALUES (?, ?, ?, ?, ?, ?, 'ready', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          TENANT,
          REPOSITORY,
          manifest.request_key,
          manifest.record_id,
          await sha256Hex(bodyJson),
          bodyJson,
          manifest.producer_id,
          manifest.signature.key_id,
          stdout.ciphertext_digest,
          stdout.ciphertext_size_bytes,
          stderr.ciphertext_digest,
          stderr.ciphertext_size_bytes,
          manifest.created_at_unix_seconds,
          manifest.expires_at_unix_seconds,
          oldHead.epoch,
          oldHead.body_sha256,
        )
        .run(),
    ).rejects.toThrow(/encrypted_manifest_trust_changed/);
    const stored = await env.DB.prepare(
      "SELECT count(*) AS count FROM manifests WHERE tenant_id = ? AND repository_id = ?",
    )
      .bind(TENANT, REPOSITORY)
      .first<{ count: number }>();
    expect(stored).toEqual({ count: 0 });
  });

  it("does not commit a manifest when its verified producer is revoked before the D1 batch", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    const gate = databaseThatPausesMutation(env.DB, "INSERT INTO manifests");
    const publication = putManifestUsingEnv(
      { DB: gate.database, BLOBS: env.BLOBS },
      fixture.manifest,
    );
    await gate.entered;
    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}/producers/key-1`,
          authRequest(undefined, "DELETE"),
        )
      ).status,
    ).toBe(204);
    gate.release();

    const response = await publication;
    expect(response.status).toBe(409);
    expect(response.headers.get("x-again-error-code")).toBe("trust_changed");
    expect(
      await env.DB.prepare(
        `SELECT
           (SELECT count(*) FROM manifests
             WHERE tenant_id = ? AND repository_id = ?) AS manifests,
           (SELECT count(*) FROM audit_events
             WHERE tenant_id = ? AND repository_id = ? AND action = 'manifest.put') AS audits`,
      )
        .bind(TENANT, REPOSITORY, TENANT, REPOSITORY)
        .first<{ manifests: number; audits: number }>(),
    ).toEqual({ manifests: 0, audits: 0 });
  });

  it("matches Rust's UTF-8, control, whitespace, and Unicode-scalar identifier rules", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();

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
    const fixture = await prepareEncryptedManifestV2Fixture();
    const trustBodySha = await sha256Hex(
      canonicalTrustBundleJson(fixture.trustBundle),
    );
    await env.DB.prepare(
      `UPDATE blobs SET state = 'deleting'
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(TENANT, REPOSITORY, fixture.manifest.stdout.ciphertext_digest)
      .run();
    await expect(
      env.DB.prepare(
        `INSERT INTO manifests(
           tenant_id, repository_id, request_key, record_id, body_sha256, body_json,
           state, producer_id, key_id, stdout_digest, stdout_size_bytes,
           stderr_digest, stderr_size_bytes, created_at, expires_at,
           trust_epoch, trust_body_sha256
         ) VALUES (?, ?, ?, ?, ?, ?, 'ready', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
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
          fixture.manifest.stdout.ciphertext_digest,
          fixture.manifest.stdout.ciphertext_size_bytes,
          fixture.manifest.stderr.ciphertext_digest,
          fixture.manifest.stderr.ciphertext_size_bytes,
          fixture.manifest.created_at_unix_seconds,
          fixture.manifest.expires_at_unix_seconds,
          fixture.trustBundle.epoch,
          trustBodySha,
        )
        .run(),
    ).rejects.toThrow(/blob_unavailable/);
    const count = await env.DB.prepare(
      "SELECT count(*) AS count FROM manifests",
    ).first<{ count: number }>();
    expect(count?.count).toBe(0);
  });

  it("quarantines divergent same-key manifests instead of choosing a winner", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putManifest(fixture.manifest)).status).toBe(201);

    const divergent = copyManifest(fixture.manifest);
    divergent.record_id = "record-divergent";
    await signManifest(divergent, fixture.privateKey);
    const conflict = await putManifest(divergent);
    expect(conflict.status).toBe(409);
    const quarantined = await call(
      `/v1/repositories/${REPOSITORY}/manifests/${fixture.manifest.request_key}`,
      authRequest(),
    );
    expect(quarantined.status).toBe(409);
    expect(quarantined.headers.get("x-again-error-code")).toBe(
      "manifest_state_corrupt",
    );
    await expect(quarantined.json()).resolves.toMatchObject({
      error: { code: "manifest_state_corrupt" },
    });

    const row = await env.DB.prepare(
      "SELECT state FROM manifests WHERE tenant_id = ? AND repository_id = ? AND request_key = ?",
    )
      .bind(TENANT, REPOSITORY, fixture.manifest.request_key)
      .first<{ state: string }>();
    expect(row?.state).toBe("quarantined");
    const conflictCount = await env.DB.prepare(
      "SELECT count(*) AS count FROM manifest_conflicts",
    ).first<{ count: number }>();
    expect(conflictCount?.count).toBe(1);
  });

  it("quarantines the existing manifest when a record id is rebound to another request key", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
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
    const fixture = await prepareEncryptedManifestV2Fixture();
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
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putManifest(fixture.manifest)).status).toBe(201);
    const referenced = await call(
      `/v1/repositories/${REPOSITORY}/blobs/${fixture.manifest.stdout.ciphertext_digest}`,
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
          `/v1/repositories/${REPOSITORY}/blobs/${fixture.manifest.stdout.ciphertext_digest}`,
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

    const stats = await call(
      `/v1/repositories/${REPOSITORY}/stats`,
      authRequest(),
    );
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

  it("keeps repository-scoped stats unchanged by another repository", async () => {
    const scopedSecret = "D".repeat(43);
    await seedToken(TENANT, "repo-a-audit", scopedSecret, REPOSITORY, "audit");
    const scopedRequest: RequestInit = {
      headers: {
        authorization: `Bearer ag1.repo-a-audit.${scopedSecret}`,
        "x-again-repository-generation": GENERATION,
      },
    };
    const beforeResponse = await call(
      `/v1/repositories/${REPOSITORY}/stats`,
      scopedRequest,
    );
    expect(beforeResponse.status).toBe(200);
    const before = await beforeResponse.json<Record<string, unknown>>();
    expect(before).not.toHaveProperty("used_bytes");
    expect(before).not.toHaveProperty("quota_bytes");
    expect(before).not.toHaveProperty("used_metadata_units");
    expect(before).not.toHaveProperty("blob_orphan_candidate_count");
    expect(before).not.toHaveProperty("trust_security_reserve_used_units");

    const createdB = await call(
      "/v1/repositories",
      jsonRequest({ repository_id: "repo-b" }),
    );
    const generationB = (await createdB.json<{ generation_id: string }>())
      .generation_id;
    const bytesB = textEncoder.encode(
      "tenant totals change only in repository b",
    );
    expect(
      (
        await putBlobAtRepository(
          "repo-b",
          bytesB,
          bytesToHex(blake3(bytesB)),
          generationB,
        )
      ).status,
    ).toBe(201);

    const afterResponse = await call(
      `/v1/repositories/${REPOSITORY}/stats`,
      scopedRequest,
    );
    expect(afterResponse.status).toBe(200);
    await expect(afterResponse.json()).resolves.toEqual(before);

    const tenantStats = await call(
      `/v1/repositories/${REPOSITORY}/stats`,
      authRequest(),
    );
    await expect(tenantStats.json()).resolves.toMatchObject({
      used_bytes: bytesB.byteLength,
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
    const limited = await call(
      `/v1/repositories/${REPOSITORY}/stats`,
      authRequest(),
    );
    expect(limited.status).toBe(429);
  });

  it("publishes and serves only a fresh offline-root-signed trust head", async () => {
    const fixture = await prepareTrustBundleFixture();
    const created = await putTrustBundle(fixture.bundle);
    expect(created.status).toBe(201);
    expect(created.headers.get("etag")).toMatch(/^"[0-9a-f]{64}"$/);
    expect(created.headers.get("x-again-repository-generation")).toBe(
      GENERATION,
    );
    expect((await putTrustBundle(fixture.bundle)).status).toBe(204);

    const fetched = await call(
      `/v1/repositories/${REPOSITORY}/trust-bundles/latest`,
      authRequest(),
    );
    expect(fetched.status).toBe(200);
    await expect(fetched.json()).resolves.toEqual(fixture.bundle);

    const history = await env.DB.prepare(
      `SELECT producer_id, public_key_json, first_epoch
         FROM trust_key_history
        WHERE tenant_id = ? AND repository_id = ? AND key_id = 'key-1'`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{
        producer_id: string;
        public_key_json: string;
        first_epoch: number;
      }>();
    expect(history).toMatchObject({
      producer_id: "producer-1",
      first_epoch: 1,
    });
    expect(JSON.parse(history?.public_key_json ?? "null")).toEqual(
      fixture.bundle.active_producer_keys[0]?.public_key,
    );

    const rootApi = await call(
      `/v1/repositories/${REPOSITORY}/trust-roots/root-key-1`,
      jsonRequest({}, BEARER, "PUT"),
    );
    expect(rootApi.status).toBe(404);

    await env.DB.prepare(
      `UPDATE trust_root_keys SET disabled_at = ?
        WHERE tenant_id = ? AND repository_id = ? AND root_key_id = ?`,
    )
      .bind(Math.floor(Date.now() / 1000), TENANT, REPOSITORY, "root-key-1")
      .run();
    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}/trust-bundles/latest`,
          authRequest(),
        )
      ).status,
    ).toBe(404);
    await expect(
      env.DB.prepare(
        `UPDATE trust_root_keys SET disabled_at = NULL
          WHERE tenant_id = ? AND repository_id = ? AND root_key_id = ?`,
      )
        .bind(TENANT, REPOSITORY, "root-key-1")
        .run(),
    ).rejects.toThrow(/trust_root_reenable/);
    await expect(
      env.DB.prepare(
        `UPDATE trust_heads SET updated_at = updated_at + 1
          WHERE tenant_id = ? AND repository_id = ?`,
      )
        .bind(TENANT, REPOSITORY)
        .run(),
    ).rejects.toThrow(/trust_root_disabled/);
  });

  it("rejects a trust bundle that expires while publication is paused before commit", async () => {
    const fixture = await prepareTrustBundleFixture();
    const expiresAt = Math.floor(Date.now() / 1000) + 2;
    fixture.bundle.issued_at_unix_seconds = expiresAt - 2;
    fixture.bundle.expires_at_unix_seconds = expiresAt;
    await signTrustBundle(fixture.bundle, fixture.privateKey);
    const gate = databaseThatPausesMutation(env.DB, "INSERT INTO trust_heads");
    const publication = putTrustBundleUsingEnv(
      { DB: gate.database, BLOBS: env.BLOBS },
      fixture.bundle,
    );
    await gate.entered;
    await waitUntilUnixSecondAfter(expiresAt);
    gate.release();

    const response = await publication;
    expect(response.status).toBe(422);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "expired_trust_bundle" },
    });
    expect(
      await env.DB.prepare(
        `SELECT
           (SELECT count(*) FROM trust_heads
             WHERE tenant_id = ? AND repository_id = ?) AS heads,
           (SELECT count(*) FROM audit_events
             WHERE tenant_id = ? AND repository_id = ?
               AND action = 'trust_bundle.put') AS audits`,
      )
        .bind(TENANT, REPOSITORY, TENANT, REPOSITORY)
        .first<{ heads: number; audits: number }>(),
    ).toEqual({ heads: 0, audits: 0 });
  });

  it("does not return a trust snapshot advanced while its signature is being verified", async () => {
    const fixture = await prepareTrustBundleFixture();
    expect((await putTrustBundle(fixture.bundle)).status).toBe(201);
    const advanced = copyTrustBundle(fixture.bundle);
    advanced.epoch = 2;
    advanced.issued_at_unix_seconds += 1;
    advanced.expires_at_unix_seconds += 1;
    advanced.active_producer_keys = [];
    advanced.revoked_key_ids = ["key-1"];
    await signTrustBundle(advanced, fixture.privateKey);

    const gate = databaseThatPausesFirstQueryAfterRead(
      env.DB,
      "FROM trust_heads h",
    );
    const staleFetch = callUsingEnv(
      { DB: gate.database, BLOBS: env.BLOBS },
      `/v1/repositories/${REPOSITORY}/trust-bundles/latest`,
      authRequest(),
    );
    await gate.entered;
    expect((await putTrustBundle(advanced)).status).toBe(204);
    gate.release();

    const response = await staleFetch;
    expect(response.status).toBe(409);
    await expect(response.json()).resolves.toMatchObject({
      error: { code: "trust_changed" },
    });
  });

  it("admits trust bodies above 64 KiB with exact bounded security-reserve accounting", async () => {
    const fixture = await prepareTrustBundleFixture();
    fixture.bundle.revoked_record_ids = Array.from(
      { length: 512 },
      (_, index) => {
        const prefix = `record-${index.toString().padStart(4, "0")}-`;
        return `${prefix}${"x".repeat(256 - prefix.length)}`;
      },
    );
    await signTrustBundle(fixture.bundle, fixture.privateKey);
    const bodyBytes = textEncoder.encode(
      canonicalTrustBundleJson(fixture.bundle),
    ).byteLength;
    expect(bodyBytes).toBeGreaterThan(64 * 1024);
    expect(bodyBytes).toBeLessThanOrEqual(MAX_TRUST_BUNDLE_JSON_SIZE);

    const before = await metadataUsage();
    const expectedDelta =
      fixture.bundle.revoked_record_ids.length +
      Math.ceil(bodyBytes / 1024) +
      4;
    const securityReserveDelta = expectedDelta - 2;
    await env.DB.prepare(
      `UPDATE tenants
          SET trust_security_reserve_limit = ?, trust_security_repository_limit = ?
        WHERE id = ?`,
    )
      .bind(securityReserveDelta - 1, securityReserveDelta - 1, TENANT)
      .run();
    const overQuota = await putTrustBundle(fixture.bundle);
    expect(overQuota.status).toBe(413);
    await expect(overQuota.json()).resolves.toMatchObject({
      error: { code: "metadata_quota_exceeded" },
    });
    expect(await metadataUsage()).toBe(before);
    const rolledBack = await env.DB.prepare(
      `SELECT
         (SELECT count(*) FROM trust_heads WHERE tenant_id = ?) AS heads,
         (SELECT count(*) FROM trust_key_history WHERE tenant_id = ?) AS history,
         (SELECT count(*) FROM trust_revoked_records WHERE tenant_id = ?) AS revocations`,
    )
      .bind(TENANT, TENANT, TENANT)
      .first<{ heads: number; history: number; revocations: number }>();
    expect(rolledBack).toEqual({ heads: 0, history: 0, revocations: 0 });

    await env.DB.prepare(
      `UPDATE tenants
          SET trust_security_reserve_limit = ?, trust_security_repository_limit = ?
        WHERE id = ?`,
    )
      .bind(securityReserveDelta, securityReserveDelta, TENANT)
      .run();
    expect((await putTrustBundle(fixture.bundle)).status).toBe(201);
    expect(await metadataUsage()).toBe(before + expectedDelta);

    const advanced = copyTrustBundle(fixture.bundle);
    advanced.epoch = 2;
    advanced.issued_at_unix_seconds += 1;
    advanced.expires_at_unix_seconds += 1;
    await signTrustBundle(advanced, fixture.privateKey);
    const usageBeforeAdvance = await metadataUsage();
    const oldHeadUnits = 1 + Math.ceil(bodyBytes / 1024);
    const advancedHeadUnits =
      1 +
      Math.ceil(
        textEncoder.encode(canonicalTrustBundleJson(advanced)).byteLength /
          1024,
      );
    const expectedAdvanceDelta = 2 + advancedHeadUnits - oldHeadUnits;
    await env.DB.prepare(
      "UPDATE tenants SET metadata_quota_units = ? WHERE id = ?",
    )
      .bind(usageBeforeAdvance + expectedAdvanceDelta, TENANT)
      .run();
    expect((await putTrustBundle(advanced)).status).toBe(204);
    expect(await metadataUsage()).toBe(
      usageBeforeAdvance + expectedAdvanceDelta,
    );

    const tooLarge = copyTrustBundle(fixture.bundle);
    tooLarge.revoked_key_ids = Array.from({ length: 4096 }, (_, index) => {
      const prefix = `key-${index.toString().padStart(4, "0")}-`;
      return `${prefix}${"y".repeat(256 - prefix.length)}`;
    });
    tooLarge.revoked_record_ids = Array.from({ length: 4096 }, (_, index) => {
      const prefix = `record-${index.toString().padStart(4, "0")}-`;
      return `${prefix}${"z".repeat(256 - prefix.length)}`;
    });
    expect(() => canonicalTrustBundleJson(tooLarge)).toThrow(/1,500,000-byte/);
  });

  it("commits signed cumulative revocation at exhausted ordinary metadata quota", async () => {
    const fixture = await prepareTrustBundleFixture();
    expect((await putTrustBundle(fixture.bundle)).status).toBe(201);
    const used = await metadataUsage();
    await env.DB.prepare(
      `UPDATE tenants SET metadata_quota_units = used_metadata_units WHERE id = ?`,
    )
      .bind(TENANT)
      .run();

    const revoked = copyTrustBundle(fixture.bundle);
    revoked.epoch = 2;
    revoked.issued_at_unix_seconds += 1;
    revoked.expires_at_unix_seconds += 1;
    revoked.active_producer_keys = [];
    revoked.revoked_key_ids = ["key-1"];
    revoked.revoked_record_ids = ["record-security-stop"];
    await signTrustBundle(revoked, fixture.privateKey);
    expect((await putTrustBundle(revoked)).status).toBe(204);
    expect(await metadataUsage()).toBeGreaterThan(used);
    expect(
      await env.DB.prepare(
        `SELECT
           (SELECT count(*) FROM trust_revoked_keys
             WHERE tenant_id = ? AND repository_id = ? AND key_id = 'key-1') AS keys,
           (SELECT count(*) FROM trust_revoked_records
             WHERE tenant_id = ? AND repository_id = ? AND record_id = 'record-security-stop') AS records`,
      )
        .bind(TENANT, REPOSITORY, TENANT, REPOSITORY)
        .first<{ keys: number; records: number }>(),
    ).toEqual({ keys: 1, records: 1 });
  });

  it("keeps signed trust-remediation capacity isolated between repositories", async () => {
    const createdB = await call(
      "/v1/repositories",
      jsonRequest({ repository_id: "repo-b" }),
    );
    expect(createdB.status).toBe(201);
    const generationB = (await createdB.json<{ generation_id: string }>())
      .generation_id;

    const fixtureA = await prepareTrustBundleFixture();
    const fixtureB = await prepareTrustBundleFixture({
      repositoryId: "repo-b",
      generationId: generationB,
    });
    expect((await putTrustBundle(fixtureA.bundle)).status).toBe(201);
    expect(
      (await putTrustBundleAtRepository("repo-b", fixtureB.bundle, generationB))
        .status,
    ).toBe(201);

    const advancedA = copyTrustBundle(fixtureA.bundle);
    advancedA.epoch = 2;
    advancedA.issued_at_unix_seconds += 1;
    advancedA.expires_at_unix_seconds += 1;
    advancedA.active_producer_keys = [];
    advancedA.revoked_key_ids = ["key-1"];
    advancedA.revoked_record_ids = ["record-a-stop"];
    await signTrustBundle(advancedA, fixtureA.privateKey);
    expect((await putTrustBundle(advancedA)).status).toBe(204);

    const filledA = await env.DB.prepare(
      `SELECT used_units FROM repository_trust_security_reserve_usage
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{ used_units: number }>();
    expect(filledA).not.toBeNull();
    await env.DB.prepare(
      `UPDATE tenants
          SET trust_security_reserve_limit = ?, trust_security_repository_limit = ?
        WHERE id = ?`,
    )
      .bind((filledA?.used_units ?? 1) * 4, filledA?.used_units, TENANT)
      .run();

    const overA = copyTrustBundle(advancedA);
    overA.epoch = 3;
    overA.revoked_record_ids = [
      ...overA.revoked_record_ids,
      "record-a-extra",
    ].sort();
    await signTrustBundle(overA, fixtureA.privateKey);
    const blockedA = await putTrustBundle(overA);
    expect(blockedA.headers.get("x-again-error-code")).toBe(
      "metadata_quota_exceeded",
    );
    expect(blockedA.status).toBe(413);

    const advancedB = copyTrustBundle(fixtureB.bundle);
    advancedB.epoch = 2;
    advancedB.issued_at_unix_seconds += 1;
    advancedB.expires_at_unix_seconds += 1;
    advancedB.active_producer_keys = [];
    advancedB.revoked_key_ids = ["key-1"];
    advancedB.revoked_record_ids = ["record-b-stop"];
    await signTrustBundle(advancedB, fixtureB.privateKey);
    expect(
      (await putTrustBundleAtRepository("repo-b", advancedB, generationB))
        .status,
    ).toBe(204);
    expect(
      await env.DB.prepare(
        `SELECT count(*) AS count FROM trust_revoked_records
          WHERE tenant_id = ? AND repository_id = 'repo-b'
            AND record_id = 'record-b-stop'`,
      )
        .bind(TENANT)
        .first<{ count: number }>(),
    ).toEqual({ count: 1 });
  });

  it("rejects invalid trust signatures, binding changes, and same-epoch equivocation", async () => {
    const fixture = await prepareTrustBundleFixture();
    const invalid = copyTrustBundle(fixture.bundle);
    invalid.signature[0] = (invalid.signature[0] ?? 0) ^ 1;
    expect((await putTrustBundle(invalid)).status).toBe(422);

    const wrongOrigin = copyTrustBundle(fixture.bundle);
    wrongOrigin.endpoint_origin = "https://different.again.invalid";
    await signTrustBundle(wrongOrigin, fixture.privateKey);
    expect((await putTrustBundle(wrongOrigin)).status).toBe(422);

    expect((await putTrustBundle(fixture.bundle)).status).toBe(201);
    const equivocation = copyTrustBundle(fixture.bundle);
    equivocation.allowed_image_digests = ["f".repeat(64)];
    await signTrustBundle(equivocation, fixture.privateKey);
    const conflict = await putTrustBundle(equivocation);
    expect(conflict.status).toBe(409);
    await expect(conflict.json()).resolves.toMatchObject({
      error: { code: "trust_epoch_conflict" },
    });

    const rebound = copyTrustBundle(fixture.bundle);
    rebound.epoch = 2;
    rebound.issued_at_unix_seconds += 1;
    rebound.expires_at_unix_seconds += 1;
    const binding = rebound.active_producer_keys[0];
    if (binding === undefined)
      throw new Error("fixture producer key is missing");
    binding.public_key = Array.from({ length: 32 }, () => 9);
    await signTrustBundle(rebound, fixture.privateKey);
    const rebind = await putTrustBundle(rebound);
    expect(rebind.status).toBe(409);
    await expect(rebind.json()).resolves.toMatchObject({
      error: { code: "trust_key_rebinding" },
    });
  });

  it("persists cumulative trust revocations and rejects rollback", async () => {
    const fixture = await prepareTrustBundleFixture();
    expect((await putTrustBundle(fixture.bundle)).status).toBe(201);

    const revoked = copyTrustBundle(fixture.bundle);
    revoked.epoch = 2;
    revoked.issued_at_unix_seconds += 1;
    revoked.expires_at_unix_seconds += 1;
    revoked.active_producer_keys = [];
    revoked.revoked_key_ids = ["key-1"];
    revoked.revoked_record_ids = ["record-1"];
    await signTrustBundle(revoked, fixture.privateKey);
    expect((await putTrustBundle(revoked)).status).toBe(204);

    const rollback = copyTrustBundle(revoked);
    rollback.epoch = 3;
    rollback.issued_at_unix_seconds += 1;
    rollback.expires_at_unix_seconds += 1;
    rollback.revoked_key_ids = [];
    rollback.revoked_record_ids = [];
    await signTrustBundle(rollback, fixture.privateKey);
    const rejected = await putTrustBundle(rollback);
    expect(rejected.status).toBe(409);
    await expect(rejected.json()).resolves.toMatchObject({
      error: { code: "trust_revocation_rollback" },
    });

    const persisted = await env.DB.prepare(
      `SELECT
         (SELECT count(*) FROM trust_revoked_keys
           WHERE tenant_id = ? AND repository_id = ?) AS keys,
         (SELECT count(*) FROM trust_revoked_records
           WHERE tenant_id = ? AND repository_id = ?) AS records`,
    )
      .bind(TENANT, REPOSITORY, TENANT, REPOSITORY)
      .first<{ keys: number; records: number }>();
    expect(persisted).toEqual({ keys: 1, records: 1 });
  });

  it("serializes concurrent same-epoch trust equivocation at the database boundary", async () => {
    const fixture = await prepareTrustBundleFixture();
    const divergent = copyTrustBundle(fixture.bundle);
    divergent.allowed_image_digests = ["f".repeat(64)];
    await signTrustBundle(divergent, fixture.privateKey);
    const gatedEnv: Env = {
      BLOBS: env.BLOBS,
      DB: databaseWithConcurrentInitialTrustReads(env.DB, 2),
    };
    const responses = await Promise.all([
      putTrustBundleUsingEnv(gatedEnv, fixture.bundle),
      putTrustBundleUsingEnv(gatedEnv, divergent),
    ]);
    expect(responses.map((response) => response.status).sort()).toEqual([
      201, 409,
    ]);

    const head = await env.DB.prepare(
      `SELECT count(*) AS count, epoch
         FROM trust_heads WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{ count: number; epoch: number }>();
    expect(head).toEqual({ count: 1, epoch: 1 });
  });

  it("tombstones repository deletion idempotently and immediately hides normal operations", async () => {
    const bytes = textEncoder.encode("hidden after repository deletion");
    const digest = bytesToHex(blake3(bytes));
    expect((await putBlob(bytes, digest)).status).toBe(201);

    const first = await call(
      `/v1/repositories/${REPOSITORY}`,
      repositoryDeleteRequest(),
    );
    const second = await call(
      `/v1/repositories/${REPOSITORY}`,
      repositoryDeleteRequest(),
    );
    expect(first.status).toBe(202);
    expect(second.status).toBe(202);
    const firstBody = await first.json<{ requested_at_unix_seconds: number }>();
    const secondBody = await second.json<{
      requested_at_unix_seconds: number;
    }>();
    expect(secondBody.requested_at_unix_seconds).toBe(
      firstBody.requested_at_unix_seconds,
    );

    expect(
      (await call(`/v1/repositories/${REPOSITORY}/stats`, authRequest()))
        .status,
    ).toBe(404);
    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
          authRequest(),
        )
      ).status,
    ).toBe(404);
    expect(
      (
        await putBlob(
          textEncoder.encode("new"),
          bytesToHex(blake3(textEncoder.encode("new"))),
        )
      ).status,
    ).toBe(404);
    const lateDigest = "e".repeat(64);
    await expect(
      env.DB.prepare(
        `INSERT INTO blobs(
           tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at
         ) VALUES (?, ?, ?, 0, 'pending', ?, ?)`,
      )
        .bind(
          TENANT,
          REPOSITORY,
          lateDigest,
          firstBody.requested_at_unix_seconds,
          firstBody.requested_at_unix_seconds,
        )
        .run(),
    ).rejects.toThrow(/repository_deleting/);
    expect(
      (
        await call(
          "/v1/repositories",
          jsonRequest({ repository_id: REPOSITORY }),
        )
      ).status,
    ).toBe(409);

    const lifecycle = await env.DB.prepare(
      `SELECT count(*) AS count FROM repository_deletions
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{ count: number }>();
    const audits = await env.DB.prepare(
      `SELECT count(*) AS count FROM audit_events
        WHERE tenant_id = ? AND repository_id = ?
          AND action = 'repository.delete' AND outcome = 'requested'`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{ count: number }>();
    expect(lifecycle?.count).toBe(1);
    expect(audits?.count).toBe(1);
  });

  it("requires the exact repository generation before accepting DELETE", async () => {
    const missing = await call(
      `/v1/repositories/${REPOSITORY}`,
      authRequest(undefined, "DELETE"),
    );
    expect(missing.status).toBe(428);
    await expect(missing.json()).resolves.toMatchObject({
      error: { code: "repository_generation_required" },
    });

    const mismatched = await call(
      `/v1/repositories/${REPOSITORY}`,
      repositoryDeleteRequest("2".repeat(32)),
    );
    expect(mismatched.status).toBe(412);
    await expect(mismatched.json()).resolves.toMatchObject({
      error: { code: "repository_generation_mismatch" },
    });
    expect(
      await env.DB.prepare(
        "SELECT deleted_at FROM repositories WHERE tenant_id = ? AND id = ?",
      )
        .bind(TENANT, REPOSITORY)
        .first<{ deleted_at: number | null }>(),
    ).toEqual({ deleted_at: null });
  });

  it("creates a generation-scoped deletion job and receipt for a direct tombstone", async () => {
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      "UPDATE repositories SET deleted_at = ? WHERE tenant_id = ? AND id = ?",
    )
      .bind(now, TENANT, REPOSITORY)
      .run();
    const lifecycle = await env.DB.prepare(
      `SELECT deletion.generation_id, deletion.phase, receipt.requested_at,
              receipt.completed_at
         FROM repository_deletions deletion
         JOIN repository_deletion_receipts receipt
           ON receipt.tenant_id = deletion.tenant_id
          AND receipt.repository_id = deletion.repository_id
          AND receipt.generation_id = deletion.generation_id
        WHERE deletion.tenant_id = ? AND deletion.repository_id = ?`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{
        generation_id: string;
        phase: string;
        requested_at: number;
        completed_at: number | null;
      }>();
    expect(lifecycle).toEqual({
      generation_id: GENERATION,
      phase: "r2",
      requested_at: now,
      completed_at: null,
    });
    await env.DB.prepare(
      `UPDATE repository_deletions SET phase = 'finalize'
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(TENANT, REPOSITORY)
      .run();
    await expect(
      env.DB.prepare(
        `INSERT INTO audit_events(
           tenant_id, repository_id, actor, action, target_type,
           target_id_sha256, outcome, details_json, created_at
         ) VALUES (?, ?, 'late', 'repository.delete', 'repository', ?,
                   'requested', '{}', ?)`,
      )
        .bind(TENANT, REPOSITORY, "a".repeat(64), now)
        .run(),
    ).rejects.toThrow(/repository_deleting/);
  });

  it("does not let a completed generation-A DELETE target recreated generation B", async () => {
    expect(
      (await call(`/v1/repositories/${REPOSITORY}`, repositoryDeleteRequest()))
        .status,
    ).toBe(202);
    await finishRepositoryDeletion();

    const recreated = await call(
      "/v1/repositories",
      jsonRequest({ repository_id: REPOSITORY }),
    );
    expect(recreated.status).toBe(201);
    const body = await recreated.json<{ generation_id: string }>();
    expect(body.generation_id).toMatch(/^[0-9a-f]{32}$/);
    expect(body.generation_id).not.toBe(GENERATION);

    const oldRetry = await call(
      `/v1/repositories/${REPOSITORY}`,
      repositoryDeleteRequest(),
    );
    expect(oldRetry.status).toBe(200);
    await expect(oldRetry.json()).resolves.toMatchObject({
      generation_id: GENERATION,
      status: "deleted",
    });
    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}/stats`,
          authRequest(undefined, "GET", body.generation_id),
        )
      ).status,
    ).toBe(200);
    expect(
      await env.DB.prepare(
        "SELECT generation_id, deleted_at FROM repositories WHERE tenant_id = ? AND id = ?",
      )
        .bind(TENANT, REPOSITORY)
        .first<{ generation_id: string; deleted_at: number | null }>(),
    ).toEqual({ generation_id: body.generation_id, deleted_at: null });
  });

  it("rejects every stale authenticated generation-A route before it can observe or mutate B", async () => {
    const staleTrust = await prepareTrustBundleFixture();
    const staleManifest = await prepareManifestFixture();
    const scopedTokenId = "token-stale-a";
    const scopedSecret = "S".repeat(43);
    const scopedBearer = `ag1.${scopedTokenId}.${scopedSecret}`;
    await seedToken(TENANT, scopedTokenId, scopedSecret, REPOSITORY, "admin");

    const gate = databaseThatPausesAuthenticatedRequests(env.DB, 9);
    const staleEnv: Env = { DB: gate.database, BLOBS: env.BLOBS };
    const digest = bytesToHex(blake3(textEncoder.encode("generation-b blob")));
    const lateUploadBytes = textEncoder.encode("stale generation-a upload");
    const lateUploadDigest = bytesToHex(blake3(lateUploadBytes));
    const requestKey = "d".repeat(64);
    const staleRequests = [
      callUsingEnv(
        staleEnv,
        `/v1/repositories/${REPOSITORY}/producers/late-key`,
        jsonRequest(
          { producer_id: "late-producer", public_key_hex: "a".repeat(64) },
          scopedBearer,
          "PUT",
          GENERATION,
        ),
      ),
      callUsingEnv(
        staleEnv,
        `/v1/repositories/${REPOSITORY}/producers/key-revoke`,
        {
          method: "DELETE",
          headers: {
            authorization: `Bearer ${scopedBearer}`,
            "x-again-repository-generation": GENERATION,
          },
        },
      ),
      callUsingEnv(staleEnv, `/v1/repositories/${REPOSITORY}/blobs/${digest}`, {
        method: "DELETE",
        headers: {
          authorization: `Bearer ${scopedBearer}`,
          "x-again-repository-generation": GENERATION,
        },
      }),
      callUsingEnv(
        staleEnv,
        `/v1/repositories/${REPOSITORY}/manifests/${requestKey}`,
        {
          method: "DELETE",
          headers: {
            authorization: `Bearer ${scopedBearer}`,
            "x-again-repository-generation": GENERATION,
          },
        },
      ),
      callUsingEnv(staleEnv, `/v1/repositories/${REPOSITORY}/stats`, {
        headers: {
          authorization: `Bearer ${scopedBearer}`,
          "x-again-repository-generation": GENERATION,
        },
      }),
      callUsingEnv(staleEnv, `/v1/repositories/${REPOSITORY}/audit`, {
        headers: {
          authorization: `Bearer ${scopedBearer}`,
          "x-again-repository-generation": GENERATION,
        },
      }),
      callUsingEnv(
        staleEnv,
        `/v1/repositories/${REPOSITORY}/trust-bundles/latest`,
        jsonRequest(staleTrust.bundle, scopedBearer, "PUT", GENERATION),
      ),
      callUsingEnv(
        staleEnv,
        `/v1/repositories/${REPOSITORY}/blobs/${lateUploadDigest}`,
        {
          method: "PUT",
          headers: {
            authorization: `Bearer ${scopedBearer}`,
            "content-type": "application/octet-stream",
            "content-length": String(lateUploadBytes.byteLength),
            "x-again-repository-generation": GENERATION,
          },
          body: lateUploadBytes,
        },
      ),
      callUsingEnv(
        staleEnv,
        `/v1/repositories/${REPOSITORY}/manifests/${staleManifest.manifest.request_key}`,
        jsonRequest(staleManifest.manifest, scopedBearer, "PUT", GENERATION),
      ),
    ];
    await gate.authenticated;

    expect(
      (await call(`/v1/repositories/${REPOSITORY}`, repositoryDeleteRequest()))
        .status,
    ).toBe(202);
    await finishRepositoryDeletion();
    const recreated = await call(
      "/v1/repositories",
      jsonRequest({ repository_id: REPOSITORY }),
    );
    expect(recreated.status).toBe(201);
    const generationB = (await recreated.json<{ generation_id: string }>())
      .generation_id;
    expect(generationB).not.toBe(GENERATION);

    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}/producers/key-revoke`,
          jsonRequest(
            { producer_id: "producer-b", public_key_hex: "b".repeat(64) },
            BEARER,
            "PUT",
            generationB,
          ),
        )
      ).status,
    ).toBe(201);
    const bytes = textEncoder.encode("generation-b blob");
    expect(
      (await putBlobUsingEnv(env, bytes, digest, generationB)).status,
    ).toBe(201);
    const now = Math.floor(Date.now() / 1000);
    const trustBodySha = "d".repeat(64);
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO trust_root_keys(
           tenant_id, repository_id, root_key_id, public_key_hex, created_at
         ) VALUES (?, ?, 'root-b', ?, ?)`,
      ).bind(TENANT, REPOSITORY, "c".repeat(64), now),
      env.DB.prepare(
        `INSERT INTO trust_heads(
           tenant_id, repository_id, epoch, root_key_id, body_sha256, body_json,
           issued_at, expires_at, updated_at
         ) VALUES (?, ?, 1, 'root-b', ?, ?, ?, ?, ?)`,
      ).bind(
        TENANT,
        REPOSITORY,
        trustBodySha,
        JSON.stringify({
          generation_id: generationB,
          active_producer_keys: [],
          revoked_key_ids: [],
          revoked_record_ids: [],
        }),
        now - 1,
        now + 299,
        now,
      ),
    ]);
    await env.DB.prepare(
      `INSERT INTO manifests(
         tenant_id, repository_id, request_key, record_id, body_sha256, body_json,
         state, producer_id, key_id, stdout_digest, stdout_size_bytes,
         stderr_digest, stderr_size_bytes, created_at, expires_at,
         trust_epoch, trust_body_sha256
       ) VALUES (?, ?, ?, 'record-b', ?, ?,
                 'ready', 'producer-b', 'key-revoke', ?, ?, ?, ?, ?, ?, 1, ?)`,
    )
      .bind(
        TENANT,
        REPOSITORY,
        requestKey,
        "c".repeat(64),
        JSON.stringify({ schema_version: 2, generation_id: generationB }),
        digest,
        bytes.byteLength,
        digest,
        bytes.byteLength,
        now,
        now + 300,
        trustBodySha,
      )
      .run();

    gate.release();
    const staleResponses = await Promise.all(staleRequests);
    expect(staleResponses.map((response) => response.status)).toEqual([
      412, 412, 412, 412, 412, 412, 412, 412, 412,
    ]);
    for (const response of staleResponses) {
      expect(response.headers.get("x-again-error-code")).toBe(
        "repository_generation_mismatch",
      );
      await expect(response.json()).resolves.toMatchObject({
        error: { code: "repository_generation_mismatch" },
      });
    }

    expect(
      await env.DB.prepare(
        `SELECT key_id, revoked_at FROM producer_keys
          WHERE tenant_id = ? AND repository_id = ? ORDER BY key_id`,
      )
        .bind(TENANT, REPOSITORY)
        .all<{ key_id: string; revoked_at: number | null }>(),
    ).toMatchObject({ results: [{ key_id: "key-revoke", revoked_at: null }] });
    expect(
      await env.DB.prepare(
        `SELECT state FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(TENANT, REPOSITORY, digest)
        .first<{ state: string }>(),
    ).toEqual({ state: "ready" });
    expect(
      await env.DB.prepare(
        `SELECT state FROM manifests
          WHERE tenant_id = ? AND repository_id = ? AND request_key = ?`,
      )
        .bind(TENANT, REPOSITORY, requestKey)
        .first<{ state: string }>(),
    ).toEqual({ state: "ready" });
    expect(
      await env.BLOBS.head(await blobObjectKey(digest, generationB)),
    ).not.toBeNull();
    expect(
      await env.DB.prepare(
        `SELECT count(*) AS count FROM trust_heads
          WHERE tenant_id = ? AND repository_id = ?`,
      )
        .bind(TENANT, REPOSITORY)
        .first<{ count: number }>(),
    ).toEqual({ count: 1 });
    expect(
      await env.DB.prepare(
        `SELECT count(*) AS count FROM manifests
          WHERE tenant_id = ? AND repository_id = ? AND request_key = ?`,
      )
        .bind(TENANT, REPOSITORY, staleManifest.manifest.request_key)
        .first<{ count: number }>(),
    ).toEqual({ count: 0 });
    expect(
      await env.DB.prepare(
        `SELECT count(*) AS count FROM blobs
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(TENANT, REPOSITORY, lateUploadDigest)
        .first<{ count: number }>(),
    ).toEqual({ count: 0 });
    expect(
      await env.DB.prepare(
        `SELECT count(*) AS count FROM repository_write_leases
          WHERE tenant_id = ? AND repository_id = ?`,
      )
        .bind(TENANT, REPOSITORY)
        .first<{ count: number }>(),
    ).toEqual({ count: 0 });
  });

  it.each(REPOSITORY_D1_CLEANUP_CASES)(
    "does not let a paused generation-A %s cleanup erase generation B",
    async (phase, table) => {
      await seedRepositoryCleanupSentinel(phase, GENERATION);
      const tombstoneTime = Math.floor(Date.now() / 1000);
      await env.DB.prepare(
        `UPDATE repositories SET deleted_at = ?
          WHERE tenant_id = ? AND id = ? AND generation_id = ?`,
      )
        .bind(tombstoneTime, TENANT, REPOSITORY, GENERATION)
        .run();
      await env.DB.prepare(
        `UPDATE repository_deletions
            SET phase = ?, next_attempt_at = 0, lease_id = NULL,
                lease_until = NULL, updated_at = ?
          WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?`,
      )
        .bind(phase, tombstoneTime, TENANT, REPOSITORY, GENERATION)
        .run();

      const gate = databaseThatPausesRepositoryCleanup(env.DB, table);
      const staleRun = runScheduledUsingEnv(
        { DB: gate.database, BLOBS: env.BLOBS },
        "*/15 * * * *",
      );
      await gate.entered;

      await env.DB.prepare(
        `UPDATE repository_deletions
            SET lease_until = 0, next_attempt_at = 0
          WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?`,
      )
        .bind(TENANT, REPOSITORY, GENERATION)
        .run();
      await finishRepositoryDeletion();

      const recreated = await call(
        "/v1/repositories",
        jsonRequest({ repository_id: REPOSITORY }),
      );
      expect(recreated.status).toBe(201);
      const generationB = (await recreated.json<{ generation_id: string }>())
        .generation_id;
      expect(generationB).not.toBe(GENERATION);
      await seedRepositoryCleanupSentinel(phase, generationB);
      expect(await repositoryCleanupSentinelCount(phase)).toBe(1);

      gate.release();
      await staleRun;

      expect(await repositoryCleanupSentinelCount(phase)).toBe(1);
      expect(
        await env.DB.prepare(
          `SELECT generation_id, deleted_at FROM repositories
            WHERE tenant_id = ? AND id = ?`,
        )
          .bind(TENANT, REPOSITORY)
          .first<{ generation_id: string; deleted_at: number | null }>(),
      ).toEqual({ generation_id: generationB, deleted_at: null });
    },
  );

  it("can tombstone a repository even when customer metadata quota is exhausted", async () => {
    const used = await metadataUsage();
    await env.DB.prepare(
      "UPDATE tenants SET metadata_quota_units = ? WHERE id = ?",
    )
      .bind(used, TENANT)
      .run();
    const response = await call(
      `/v1/repositories/${REPOSITORY}`,
      repositoryDeleteRequest(),
    );
    expect(response.status).toBe(202);
    const job = await env.DB.prepare(
      `SELECT count(*) AS count FROM repository_deletions
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{ count: number }>();
    expect(job?.count).toBe(1);
  });

  it("scopes repository tombstones to the authenticated tenant", async () => {
    const otherTenant = "tenant-b";
    const otherToken = "token-b";
    const otherSecret = "B".repeat(43);
    await seedTenant(otherTenant, otherToken, otherSecret, REPOSITORY);

    const deleted = await call(`/v1/repositories/${REPOSITORY}`, {
      method: "DELETE",
      headers: {
        authorization: `Bearer ag1.${otherToken}.${otherSecret}`,
        "if-match": `"${GENERATION}"`,
      },
    });
    expect(deleted.status).toBe(202);
    expect(
      (await call(`/v1/repositories/${REPOSITORY}/stats`, authRequest()))
        .status,
    ).toBe(200);
    const rows = await env.DB.prepare(
      `SELECT tenant_id, deleted_at FROM repositories
        WHERE id = ? ORDER BY tenant_id`,
    )
      .bind(REPOSITORY)
      .all<{ tenant_id: string; deleted_at: number | null }>();
    expect(rows.results).toEqual([
      { tenant_id: TENANT, deleted_at: null },
      { tenant_id: otherTenant, deleted_at: expect.any(Number) },
    ]);
  });

  it("waits for an admitted generation write and removes its aborted R2 object", async () => {
    const bytes = textEncoder.encode("upload admitted before tombstone");
    const digest = bytesToHex(blake3(bytes));
    const blocked = bucketThatBlocksFirstPut(env.BLOBS);
    const blockedEnv: Env = { DB: env.DB, BLOBS: blocked.bucket };
    const upload = putBlobUsingEnv(blockedEnv, bytes, digest);
    await blocked.entered;

    try {
      expect(
        await env.DB.prepare(
          `SELECT count(*) AS count FROM repository_write_leases
            WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?`,
        )
          .bind(TENANT, REPOSITORY, GENERATION)
          .first<{ count: number }>(),
      ).toEqual({ count: 1 });
      expect(
        (
          await call(
            `/v1/repositories/${REPOSITORY}`,
            repositoryDeleteRequest(),
          )
        ).status,
      ).toBe(202);
      await runScheduledUsingEnv(blockedEnv, "*/15 * * * *");
      expect(blocked.listCalls()).toBe(0);
      expect(
        await env.DB.prepare(
          `SELECT phase, empty_confirmations FROM repository_deletions
            WHERE tenant_id = ? AND repository_id = ?`,
        )
          .bind(TENANT, REPOSITORY)
          .first<{ phase: string; empty_confirmations: number }>(),
      ).toEqual({ phase: "r2", empty_confirmations: 0 });
    } finally {
      blocked.release();
    }

    expect((await upload).status).toBe(412);
    expect(
      await env.DB.prepare(
        `SELECT count(*) AS count FROM repository_write_leases
          WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?`,
      )
        .bind(TENANT, REPOSITORY, GENERATION)
        .first<{ count: number }>(),
    ).toEqual({ count: 0 });
    const key = await blobObjectKey(digest);
    expect(await env.BLOBS.head(key)).toBeNull();
    await env.DB.prepare(
      `UPDATE repository_deletions SET next_attempt_at = 0
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(TENANT, REPOSITORY)
      .run();
    await runScheduled();
    expect(await env.BLOBS.head(key)).toBeNull();
  });

  it("never lets an expired generation-A writer clear a recreated B lease", async () => {
    const bytes = textEncoder.encode("expired generation-a upload");
    const digest = bytesToHex(blake3(bytes));
    const blocked = bucketThatBlocksFirstPut(env.BLOBS);
    const blockedEnv: Env = { DB: env.DB, BLOBS: blocked.bucket };
    const upload = putBlobUsingEnv(blockedEnv, bytes, digest);
    await blocked.entered;

    const leaseA = await env.DB.prepare(
      `SELECT lease_id FROM repository_write_leases
        WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?`,
    )
      .bind(TENANT, REPOSITORY, GENERATION)
      .first<{ lease_id: string }>();
    expect(leaseA).not.toBeNull();
    await env.DB.prepare(
      `UPDATE repository_write_leases SET created_at = 0, expires_at = 1
        WHERE tenant_id = ? AND repository_id = ? AND generation_id = ? AND lease_id = ?`,
    )
      .bind(TENANT, REPOSITORY, GENERATION, leaseA?.lease_id)
      .run();

    expect(
      (await call(`/v1/repositories/${REPOSITORY}`, repositoryDeleteRequest()))
        .status,
    ).toBe(202);
    await finishRepositoryDeletion();
    const recreated = await call(
      "/v1/repositories",
      jsonRequest({ repository_id: REPOSITORY }),
    );
    const generationB = (await recreated.json<{ generation_id: string }>())
      .generation_id;
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      `INSERT INTO repository_write_leases(
         tenant_id, repository_id, generation_id, lease_id, created_at, expires_at
       ) VALUES (?, ?, ?, ?, ?, ?)`,
    )
      .bind(TENANT, REPOSITORY, generationB, leaseA?.lease_id, now, now + 900)
      .run();

    blocked.release();
    expect((await upload).status).toBe(412);
    expect(
      await env.DB.prepare(
        `SELECT generation_id, lease_id FROM repository_write_leases
          WHERE tenant_id = ? AND repository_id = ?`,
      )
        .bind(TENANT, REPOSITORY)
        .first<{ generation_id: string; lease_id: string }>(),
    ).toEqual({ generation_id: generationB, lease_id: leaseA?.lease_id });
  });

  it("cleans expired write leases for an active repository", async () => {
    await env.DB.prepare(
      `INSERT INTO repository_write_leases(
         tenant_id, repository_id, generation_id, lease_id, created_at, expires_at
       ) VALUES (?, ?, ?, ?, 0, 1)`,
    )
      .bind(TENANT, REPOSITORY, GENERATION, crypto.randomUUID())
      .run();
    await runScheduled();
    expect(
      await env.DB.prepare(
        `SELECT count(*) AS count FROM repository_write_leases
          WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?`,
      )
        .bind(TENANT, REPOSITORY, GENERATION)
        .first<{ count: number }>(),
    ).toEqual({ count: 0 });
    expect(
      await env.DB.prepare(
        `SELECT deleted_at FROM repositories
          WHERE tenant_id = ? AND id = ?`,
      )
        .bind(TENANT, REPOSITORY)
        .first<{ deleted_at: number | null }>(),
    ).toEqual({ deleted_at: null });
  });

  it("fills spare deletion capacity after every tenant receives a fair first slot", async () => {
    const repositoryA2 = "repo-delete-a2";
    const createdA2 = await call(
      "/v1/repositories",
      jsonRequest({ repository_id: repositoryA2 }),
    );
    expect(createdA2.status).toBe(201);
    const generationA2 = (await createdA2.json<{ generation_id: string }>())
      .generation_id;
    const tenantB = "tenant-delete-throughput-b";
    const repositoryB = "repo-delete-throughput-b";
    const tokenB = "token-delete-throughput-b";
    const secretB = "T".repeat(43);
    await seedTenant(tenantB, tokenB, secretB, repositoryB);

    expect(
      (await call(`/v1/repositories/${REPOSITORY}`, repositoryDeleteRequest()))
        .status,
    ).toBe(202);
    expect(
      (
        await call(`/v1/repositories/${repositoryA2}`, {
          method: "DELETE",
          headers: {
            authorization: `Bearer ${BEARER}`,
            "if-match": `"${generationA2}"`,
          },
        })
      ).status,
    ).toBe(202);
    expect(
      (
        await call(`/v1/repositories/${repositoryB}`, {
          method: "DELETE",
          headers: {
            authorization: `Bearer ag1.${tokenB}.${secretB}`,
            "if-match": `"${GENERATION}"`,
          },
        })
      ).status,
    ).toBe(202);

    await runScheduled();
    const rows = await env.DB.prepare(
      `SELECT tenant_id, repository_id, empty_confirmations
         FROM repository_deletions
        WHERE (tenant_id = ? AND repository_id IN (?, ?))
           OR (tenant_id = ? AND repository_id = ?)
        ORDER BY tenant_id, repository_id`,
    )
      .bind(TENANT, REPOSITORY, repositoryA2, tenantB, repositoryB)
      .all<{
        tenant_id: string;
        repository_id: string;
        empty_confirmations: number;
      }>();
    expect(rows.results).toEqual([
      { tenant_id: TENANT, repository_id: REPOSITORY, empty_confirmations: 1 },
      {
        tenant_id: TENANT,
        repository_id: repositoryA2,
        empty_confirmations: 1,
      },
      {
        tenant_id: tenantB,
        repository_id: repositoryB,
        empty_confirmations: 1,
      },
    ]);
  });

  it("continues another tenant's deletion after the first lease acquisition fails", async () => {
    expect(
      (await call(`/v1/repositories/${REPOSITORY}`, repositoryDeleteRequest()))
        .status,
    ).toBe(202);
    const tenantB = "tenant-delete-b";
    const repositoryB = "repo-delete-b";
    const tokenB = "token-delete-b";
    const secretB = "E".repeat(43);
    await seedTenant(tenantB, tokenB, secretB, repositoryB);
    expect(
      (
        await call(`/v1/repositories/${repositoryB}`, {
          method: "DELETE",
          headers: {
            authorization: `Bearer ag1.${tokenB}.${secretB}`,
            "if-match": `"${GENERATION}"`,
          },
        })
      ).status,
    ).toBe(202);

    await runScheduledUsingEnv(
      {
        DB: databaseThatFailsFirstRepositoryDeletionLease(env.DB),
        BLOBS: env.BLOBS,
      },
      "*/15 * * * *",
    );
    expect(
      await env.DB.prepare(
        `SELECT
           (SELECT empty_confirmations FROM repository_deletions
             WHERE tenant_id = ? AND repository_id = ?) AS a_confirmations,
           (SELECT empty_confirmations FROM repository_deletions
             WHERE tenant_id = ? AND repository_id = ?) AS b_confirmations`,
      )
        .bind(TENANT, REPOSITORY, tenantB, repositoryB)
        .first<{ a_confirmations: number; b_confirmations: number }>(),
    ).toEqual({ a_confirmations: 0, b_confirmations: 1 });
  });

  it("isolates an orphan-owner D1 failure and advances the next tenant", async () => {
    const tenantB = "tenant-orphan-b";
    const repositoryB = "repo-orphan-b";
    await seedTenant(tenantB, "token-orphan-b", "O".repeat(43), repositoryB);
    const now = Math.floor(Date.now() / 1000);
    const incarnationA = "a".repeat(32);
    const incarnationB = "b".repeat(32);
    const digestA = "d".repeat(64);
    const digestB = "e".repeat(64);
    const operationA = "1".repeat(32);
    const operationB = "2".repeat(32);
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO blob_object_orphan_candidates(
           tenant_id, repository_id, generation_id, digest, incarnation_id,
           operation_id, created_at, next_sweep_at, attempts
         ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)`,
      ).bind(
        TENANT,
        REPOSITORY,
        GENERATION,
        digestA,
        incarnationA,
        operationA,
        now,
      ),
      env.DB.prepare(
        `INSERT INTO blob_object_orphan_candidates(
           tenant_id, repository_id, generation_id, digest, incarnation_id,
           operation_id, created_at, next_sweep_at, attempts
         ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)`,
      ).bind(
        tenantB,
        repositoryB,
        GENERATION,
        digestB,
        incarnationB,
        operationB,
        now,
      ),
    ]);
    const keyA = `v1/${TENANT}/${REPOSITORY}/${GENERATION}/blake3/${digestA}/${incarnationA}`;
    const keyB = `v1/${tenantB}/${repositoryB}/${GENERATION}/blake3/${digestB}/${incarnationB}`;
    await env.BLOBS.put(keyA, "a");
    await env.BLOBS.put(keyB, "b");

    await runScheduledUsingEnv(
      {
        DB: databaseThatFailsOrphanOwnerForTenant(env.DB, TENANT),
        BLOBS: env.BLOBS,
      },
      "*/15 * * * *",
    );
    expect(await env.BLOBS.head(keyA)).not.toBeNull();
    expect(await env.BLOBS.head(keyB)).toBeNull();
    expect(
      await env.DB.prepare(
        `SELECT attempts, next_sweep_at FROM blob_object_orphan_candidates
          WHERE tenant_id = ? AND repository_id = ? AND operation_id = ?`,
      )
        .bind(tenantB, repositoryB, operationB)
        .first<{ attempts: number; next_sweep_at: number }>(),
    ).toMatchObject({ attempts: 0, next_sweep_at: expect.any(Number) });
  });

  it("fills spare orphan-sweep capacity after every tenant receives a fair first slot", async () => {
    const tenantB = "tenant-orphan-throughput-b";
    const repositoryB = "repo-orphan-throughput-b";
    await seedTenant(
      tenantB,
      "token-orphan-throughput-b",
      "U".repeat(43),
      repositoryB,
    );
    const now = Math.floor(Date.now() / 1000);
    const candidates = [
      {
        tenant: TENANT,
        repository: REPOSITORY,
        generation: GENERATION,
        digest: "a".repeat(64),
        incarnation: "1".repeat(32),
        operation: "4".repeat(32),
      },
      {
        tenant: TENANT,
        repository: REPOSITORY,
        generation: GENERATION,
        digest: "b".repeat(64),
        incarnation: "2".repeat(32),
        operation: "5".repeat(32),
      },
      {
        tenant: tenantB,
        repository: repositoryB,
        generation: GENERATION,
        digest: "c".repeat(64),
        incarnation: "3".repeat(32),
        operation: "6".repeat(32),
      },
    ];
    for (const candidate of candidates) {
      await env.DB.prepare(
        `INSERT INTO blob_object_orphan_candidates(
           tenant_id, repository_id, generation_id, digest, incarnation_id,
           operation_id, created_at, next_sweep_at, attempts
         ) VALUES (?, ?, ?, ?, ?, ?, ?, 0, 0)`,
      )
        .bind(
          candidate.tenant,
          candidate.repository,
          candidate.generation,
          candidate.digest,
          candidate.incarnation,
          candidate.operation,
          now,
        )
        .run();
      await env.BLOBS.put(
        `v1/${candidate.tenant}/${candidate.repository}/${candidate.generation}/blake3/${candidate.digest}/${candidate.incarnation}`,
        "orphan",
      );
    }

    await runScheduled();
    for (const candidate of candidates) {
      expect(
        await env.BLOBS.head(
          `v1/${candidate.tenant}/${candidate.repository}/${candidate.generation}/blake3/${candidate.digest}/${candidate.incarnation}`,
        ),
      ).toBeNull();
    }
  });

  it("rejects an out-of-prefix graveyard page and still sweeps the next tenant", async () => {
    const tenantB = "tenant-graveyard-b";
    await seedTenant(tenantB, "token-graveyard-b", "Y".repeat(43), "active-b");
    const now = Math.floor(Date.now() / 1000);
    const retiredA = "retired-a";
    const retiredB = "retired-b";
    const generationA = "a".repeat(32);
    const generationB = "b".repeat(32);
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO repository_deletion_receipts(
           tenant_id, repository_id, generation_id, requested_at, completed_at,
           orphan_sweep_due_at
         ) VALUES (?, ?, ?, ?, ?, 0)`,
      ).bind(TENANT, retiredA, generationA, now, now),
      env.DB.prepare(
        `INSERT INTO repository_deletion_receipts(
           tenant_id, repository_id, generation_id, requested_at, completed_at,
           orphan_sweep_due_at
         ) VALUES (?, ?, ?, ?, ?, 0)`,
      ).bind(tenantB, retiredB, generationB, now, now),
    ]);
    const prefixA = `v1/${TENANT}/${retiredA}/${generationA}/`;
    const prefixB = `v1/${tenantB}/${retiredB}/${generationB}/`;
    const outsideKey = `v1/${TENANT}/unrelated/${generationA}/must-survive`;
    const keyB = `${prefixB}late-object`;
    await env.BLOBS.put(outsideKey, "outside");
    await env.BLOBS.put(keyB, "inside-b");

    await runScheduledUsingEnv(
      {
        DB: env.DB,
        BLOBS: bucketThatReturnsWrongPrefixFor(env.BLOBS, prefixA, outsideKey),
      },
      "*/15 * * * *",
    );
    expect(await env.BLOBS.head(outsideKey)).not.toBeNull();
    expect(await env.BLOBS.head(keyB)).toBeNull();
  });

  it("rejects a malformed graveyard receipt before R2 and still sweeps the next tenant", async () => {
    const tenantB = "tenant-graveyard-valid";
    await seedTenant(
      tenantB,
      "token-graveyard-valid",
      "V".repeat(43),
      "active-b",
    );
    const now = Math.floor(Date.now() / 1000);
    const generationA = "a".repeat(32);
    const generationB = "b".repeat(32);
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO repository_deletion_receipts(
           tenant_id, repository_id, generation_id, requested_at, completed_at,
           orphan_sweep_due_at
         ) VALUES (?, 'retired/invalid', ?, ?, ?, 0)`,
      ).bind(TENANT, generationA, now, now),
      env.DB.prepare(
        `INSERT INTO repository_deletion_receipts(
           tenant_id, repository_id, generation_id, requested_at, completed_at,
           orphan_sweep_due_at
         ) VALUES (?, 'retired-valid', ?, ?, ?, 0)`,
      ).bind(tenantB, generationB, now, now),
    ]);
    const keyB = `v1/${tenantB}/retired-valid/${generationB}/late-object`;
    await env.BLOBS.put(keyB, "inside-b");

    await runScheduled();
    expect(await env.BLOBS.head(keyB)).toBeNull();
  });

  it("fills spare graveyard capacity after every tenant receives a fair first slot", async () => {
    const tenantB = "tenant-graveyard-throughput-b";
    await seedTenant(
      tenantB,
      "token-graveyard-throughput-b",
      "W".repeat(43),
      "active-b",
    );
    const now = Math.floor(Date.now() / 1000);
    const receipts = [
      {
        tenant: TENANT,
        repository: "retired-throughput-a1",
        generation: "a".repeat(32),
      },
      {
        tenant: TENANT,
        repository: "retired-throughput-a2",
        generation: "b".repeat(32),
      },
      {
        tenant: tenantB,
        repository: "retired-throughput-b1",
        generation: "c".repeat(32),
      },
    ];
    for (const receipt of receipts) {
      await env.DB.prepare(
        `INSERT INTO repository_deletion_receipts(
           tenant_id, repository_id, generation_id, requested_at, completed_at,
           orphan_sweep_due_at
         ) VALUES (?, ?, ?, ?, ?, 0)`,
      )
        .bind(receipt.tenant, receipt.repository, receipt.generation, now, now)
        .run();
      await env.BLOBS.put(
        `v1/${receipt.tenant}/${receipt.repository}/${receipt.generation}/late-object`,
        "late",
      );
    }

    await runScheduled();
    for (const receipt of receipts) {
      expect(
        await env.BLOBS.head(
          `v1/${receipt.tenant}/${receipt.repository}/${receipt.generation}/late-object`,
        ),
      ).toBeNull();
    }
  });

  it("bounds D1 erasure chunks and resumes a large metadata phase", async () => {
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      `WITH digits(n) AS (
         VALUES (0),(1),(2),(3),(4),(5),(6),(7),(8),(9)
       ), sequence(n) AS (
         SELECT ones.n + 10 * tens.n + 100 * hundreds.n + 1000 * thousands.n
           FROM digits ones
           CROSS JOIN digits tens
           CROSS JOIN digits hundreds
           CROSS JOIN digits thousands
       )
       INSERT INTO audit_events(
         tenant_id, repository_id, actor, action, target_type,
         target_id_sha256, outcome, details_json, created_at
       )
       SELECT ?, ?, 'seed', 'seed', 'seed', printf('%064x', n + 1),
              'seeded', '{}', ?
         FROM sequence WHERE n < 2050`,
    )
      .bind(TENANT, REPOSITORY, now)
      .run();
    await env.DB.prepare(
      "UPDATE repositories SET deleted_at = ? WHERE tenant_id = ? AND id = ?",
    )
      .bind(now, TENANT, REPOSITORY)
      .run();
    await env.DB.prepare(
      `UPDATE repository_deletions
          SET phase = 'audit_events', empty_confirmations = 2,
              last_empty_at = ?, next_attempt_at = 0
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(now, TENANT, REPOSITORY)
      .run();

    await runScheduled();
    expect(
      await env.DB.prepare(
        `SELECT count(*) AS count FROM audit_events
          WHERE tenant_id = ? AND repository_id = ?`,
      )
        .bind(TENANT, REPOSITORY)
        .first<{ count: number }>(),
    ).toEqual({ count: 2 });
    expect(
      await env.DB.prepare(
        `SELECT phase, lease_id FROM repository_deletions
          WHERE tenant_id = ? AND repository_id = ?`,
      )
        .bind(TENANT, REPOSITORY)
        .first<{ phase: string; lease_id: string | null }>(),
    ).toEqual({ phase: "audit_events", lease_id: null });

    await runScheduled();
    expect(
      await env.DB.prepare(
        "SELECT id FROM repositories WHERE tenant_id = ? AND id = ?",
      )
        .bind(TENANT, REPOSITORY)
        .first<{ id: string }>(),
    ).toBeNull();
    expect(
      await env.DB.prepare(
        `SELECT completed_at FROM repository_deletion_receipts
          WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?`,
      )
        .bind(TENANT, REPOSITORY, GENERATION)
        .first<{ completed_at: number | null }>(),
    ).toEqual({ completed_at: expect.any(Number) });
  });

  it("retries an idempotent repository sweep after a partial R2 deletion failure", async () => {
    const prefix = `v1/${TENANT}/${REPOSITORY}/${GENERATION}/`;
    for (const suffix of ["orphan-a", "orphan-b", "orphan-c"]) {
      await env.BLOBS.put(`${prefix}${suffix}`, suffix);
    }
    expect(
      (await call(`/v1/repositories/${REPOSITORY}`, repositoryDeleteRequest()))
        .status,
    ).toBe(202);

    await runScheduledUsingEnv(
      { DB: env.DB, BLOBS: bucketThatPartiallyFailsDelete(env.BLOBS) },
      "*/15 * * * *",
    );
    const deferred = await env.DB.prepare(
      `SELECT attempts, r2_cursor, next_attempt_at FROM repository_deletions
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{
        attempts: number;
        r2_cursor: string | null;
        next_attempt_at: number;
      }>();
    expect(deferred?.attempts).toBe(1);
    expect(deferred?.r2_cursor).toBeNull();
    expect(deferred?.next_attempt_at).toBeGreaterThan(
      Math.floor(Date.now() / 1000),
    );

    await env.DB.prepare(
      `UPDATE repository_deletions SET next_attempt_at = 0
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(TENANT, REPOSITORY)
      .run();
    await runScheduled();
    const remaining = await env.BLOBS.list({ prefix });
    expect(remaining.objects).toHaveLength(0);
    const recovered = await env.DB.prepare(
      `SELECT attempts FROM repository_deletions
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{ attempts: number }>();
    expect(recovered?.attempts).toBe(0);
  });

  it("clears an unusable R2 cursor and empty confirmations before retrying", async () => {
    expect(
      (await call(`/v1/repositories/${REPOSITORY}`, repositoryDeleteRequest()))
        .status,
    ).toBe(202);
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      `UPDATE repository_deletions
          SET r2_cursor = 'stale-cursor', empty_confirmations = 1,
              last_empty_at = ?, next_attempt_at = 0
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(now, TENANT, REPOSITORY)
      .run();
    await runScheduledUsingEnv(
      { DB: env.DB, BLOBS: bucketThatFailsList(env.BLOBS) },
      "*/15 * * * *",
    );
    expect(
      await env.DB.prepare(
        `SELECT attempts, r2_cursor, empty_confirmations, last_empty_at
           FROM repository_deletions
          WHERE tenant_id = ? AND repository_id = ?`,
      )
        .bind(TENANT, REPOSITORY)
        .first<{
          attempts: number;
          r2_cursor: string | null;
          empty_confirmations: number;
          last_empty_at: number | null;
        }>(),
    ).toEqual({
      attempts: 1,
      r2_cursor: null,
      empty_confirmations: 0,
      last_empty_at: null,
    });
  });

  it("restarts a cursor sweep so late objects before the cursor cannot survive", async () => {
    const prefix = `v1/${TENANT}/${REPOSITORY}/${GENERATION}/`;
    for (let index = 0; index < 70; index += 1) {
      await env.BLOBS.put(
        `${prefix}orphans/${String(index).padStart(3, "0")}`,
        "x",
      );
    }
    expect(
      (await call(`/v1/repositories/${REPOSITORY}`, repositoryDeleteRequest()))
        .status,
    ).toBe(202);

    const pagedEnv: Env = {
      DB: env.DB,
      BLOBS: bucketWithListPageLimit(env.BLOBS, 64),
    };
    await runScheduledUsingEnv(pagedEnv, "*/15 * * * *");
    const afterFirstPage = await env.DB.prepare(
      `SELECT r2_cursor FROM repository_deletions
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{ r2_cursor: string | null }>();
    expect(afterFirstPage?.r2_cursor).not.toBeNull();

    const lateKey = `${prefix}000-late-before-cursor`;
    await env.BLOBS.put(lateKey, "late");
    await runScheduledUsingEnv(pagedEnv, "*/15 * * * *");
    expect(await env.BLOBS.head(lateKey)).not.toBeNull();
    await runScheduledUsingEnv(pagedEnv, "*/15 * * * *");
    expect(await env.BLOBS.head(lateKey)).toBeNull();
    await finishRepositoryDeletion(pagedEnv);

    expect(await env.BLOBS.list({ prefix })).toMatchObject({ objects: [] });
    const repository = await env.DB.prepare(
      "SELECT id FROM repositories WHERE tenant_id = ? AND id = ?",
    )
      .bind(TENANT, REPOSITORY)
      .first<{ id: string }>();
    expect(repository).toBeNull();
  });

  it("never collects a referenced blob and collects it after the final manifest is deleted", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putManifest(fixture.manifest)).status).toBe(201);
    const old = Math.floor(Date.now() / 1000) - 7200;
    await env.DB.prepare(
      `UPDATE blobs SET updated_at = ?
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(old, TENANT, REPOSITORY)
      .run();
    await env.DB.prepare(
      `INSERT INTO blob_gc_candidates(
         tenant_id, repository_id, digest, next_check_at, attempts, created_at, updated_at
       ) VALUES (?, ?, ?, 0, 0, ?, ?)`,
    )
      .bind(
        TENANT,
        REPOSITORY,
        fixture.manifest.stdout.ciphertext_digest,
        old,
        old,
      )
      .run();

    await runScheduled();
    const retained = await env.DB.prepare(
      `SELECT state FROM blobs
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
      .bind(TENANT, REPOSITORY, fixture.manifest.stdout.ciphertext_digest)
      .first<{ state: string }>();
    expect(retained?.state).toBe("ready");

    expect(
      (
        await call(
          `/v1/repositories/${REPOSITORY}/manifests/${fixture.manifest.request_key}`,
          authRequest(undefined, "DELETE"),
        )
      ).status,
    ).toBe(204);
    await runScheduled();
    const deleting = await env.DB.prepare(
      `SELECT count(*) AS count FROM blobs
        WHERE tenant_id = ? AND repository_id = ? AND state = 'deleting'`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{ count: number }>();
    expect(deleting?.count).toBe(2);
    await runReconciliation();
    const removed = await env.DB.prepare(
      `SELECT count(*) AS count FROM blobs
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{ count: number }>();
    expect(removed?.count).toBe(0);
  });

  it("retains a GC signal when the final reference disappears after a failed transition", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putManifest(fixture.manifest)).status).toBe(201);
    const old = Math.floor(Date.now() / 1000) - 7200;
    await env.DB.prepare(
      `UPDATE blobs SET updated_at = ?
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(old, TENANT, REPOSITORY)
      .run();
    await env.DB.prepare(
      `INSERT INTO blob_gc_candidates(
         tenant_id, repository_id, digest, next_check_at, attempts, created_at, updated_at
       ) VALUES (?, ?, ?, 0, 0, ?, ?)`,
    )
      .bind(
        TENANT,
        REPOSITORY,
        fixture.manifest.stdout.ciphertext_digest,
        old,
        old,
      )
      .run();

    const interleavedEnv: Env = {
      DB: databaseThatDeletesManifestAfterFailedGcTransition(
        env.DB,
        fixture.manifest.request_key,
      ),
      BLOBS: env.BLOBS,
    };
    await runScheduledUsingEnv(interleavedEnv, "*/15 * * * *");
    expect(
      await env.DB.prepare(
        `SELECT count(*) AS count FROM blob_gc_candidates
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(TENANT, REPOSITORY, fixture.manifest.stdout.ciphertext_digest)
        .first<{ count: number }>(),
    ).toEqual({ count: 1 });
    expect(
      await env.DB.prepare(
        `SELECT state FROM blobs
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(TENANT, REPOSITORY, fixture.manifest.stdout.ciphertext_digest)
        .first<{ state: string }>(),
    ).toEqual({ state: "ready" });

    await runScheduled();
    expect(
      await env.DB.prepare(
        `SELECT state FROM blobs
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(TENANT, REPOSITORY, fixture.manifest.stdout.ciphertext_digest)
        .first<{ state: string }>(),
    ).toEqual({ state: "deleting" });
  });

  it.each([
    ["transition", "ready", "SET state = 'deleting'", true],
    ["post-transition-delete", "ready", "DELETE FROM blob_gc_candidates", true],
    ["reschedule", "ready", "UPDATE blob_gc_candidates", false],
    ["terminal-delete", "deleting", "DELETE FROM blob_gc_candidates", true],
  ] as const)(
    "does not let a paused generation-A GC %s mutate recreated generation B",
    async (_outcome, initialState, mutationMarker, oldEnough) => {
      const digest = "e".repeat(64);
      const now = Math.floor(Date.now() / 1000);
      const blobTime = oldEnough ? now - 3601 : now;
      await env.DB.prepare(
        `INSERT INTO blobs(
           tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
           reconcile_attempts, next_reconcile_at, delete_not_before,
           r2_key, r2_version, r2_etag, r2_sha256
         ) VALUES (?, ?, ?, 0, ?, ?, ?, 0, ?, ?, ?, 'test-version', 'test-etag', ?)`,
      )
        .bind(
          TENANT,
          REPOSITORY,
          digest,
          initialState,
          blobTime,
          blobTime,
          now + 3600,
          initialState === "deleting" ? now + 3600 : null,
          `v1/${TENANT}/${REPOSITORY}/${GENERATION}/blake3/${digest}`,
          "0".repeat(64),
        )
        .run();
      await env.DB.prepare(
        `UPDATE blob_gc_candidates
            SET next_check_at = 0, attempts = 0, updated_at = ?
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(blobTime, TENANT, REPOSITORY, digest)
        .run();

      const gate = databaseThatPausesMutation(env.DB, mutationMarker);
      const staleRun = runScheduledUsingEnv(
        { DB: gate.database, BLOBS: env.BLOBS },
        "*/15 * * * *",
      );
      await gate.entered;

      expect(
        (
          await call(
            `/v1/repositories/${REPOSITORY}`,
            repositoryDeleteRequest(),
          )
        ).status,
      ).toBe(202);
      await finishRepositoryDeletion();
      const recreated = await call(
        "/v1/repositories",
        jsonRequest({ repository_id: REPOSITORY }),
      );
      expect(recreated.status).toBe(201);
      const generationB = (await recreated.json<{ generation_id: string }>())
        .generation_id;
      await env.DB.prepare(
        `INSERT INTO blobs(
           tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
           reconcile_attempts, next_reconcile_at, delete_not_before,
           r2_key, r2_version, r2_etag, r2_sha256
         ) VALUES (?, ?, ?, 0, ?, ?, ?, 0, ?, ?, ?, 'test-version', 'test-etag', ?)`,
      )
        .bind(
          TENANT,
          REPOSITORY,
          digest,
          initialState,
          blobTime,
          blobTime,
          now + 3600,
          initialState === "deleting" ? now + 3600 : null,
          `v1/${TENANT}/${REPOSITORY}/${generationB}/blake3/${digest}`,
          "0".repeat(64),
        )
        .run();
      await env.DB.prepare(
        `UPDATE blob_gc_candidates
            SET next_check_at = 0, attempts = 0, updated_at = ?
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(blobTime, TENANT, REPOSITORY, digest)
        .run();

      gate.release();
      await staleRun;

      expect(
        await env.DB.prepare(
          `SELECT state, updated_at FROM blobs
            WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
        )
          .bind(TENANT, REPOSITORY, digest)
          .first<{ state: string; updated_at: number }>(),
      ).toEqual({ state: initialState, updated_at: blobTime });
      expect(
        await env.DB.prepare(
          `SELECT next_check_at, attempts FROM blob_gc_candidates
            WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
        )
          .bind(TENANT, REPOSITORY, digest)
          .first<{ next_check_at: number; attempts: number }>(),
      ).toEqual({ next_check_at: 0, attempts: 0 });
      expect(
        await env.DB.prepare(
          `SELECT generation_id FROM repositories
            WHERE tenant_id = ? AND id = ? AND deleted_at IS NULL`,
        )
          .bind(TENANT, REPOSITORY)
          .first<{ generation_id: string }>(),
      ).toEqual({ generation_id: generationB });
    },
  );

  it("physically removes expired manifests and schedules their blobs for deletion", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    expect((await putManifest(fixture.manifest)).status).toBe(201);
    const old = Math.floor(Date.now() / 1000) - 7200;
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE manifests SET expires_at = ?
          WHERE tenant_id = ? AND repository_id = ? AND request_key = ?`,
      ).bind(old, TENANT, REPOSITORY, fixture.manifest.request_key),
      env.DB.prepare(
        `UPDATE blobs SET updated_at = ?
          WHERE tenant_id = ? AND repository_id = ?`,
      ).bind(old, TENANT, REPOSITORY),
    ]);

    await runScheduled();
    const manifest = await env.DB.prepare(
      `SELECT request_key FROM manifests
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{ request_key: string }>();
    expect(manifest).toBeNull();
    const queued = await env.DB.prepare(
      `SELECT count(*) AS count FROM blobs
        WHERE tenant_id = ? AND repository_id = ? AND state = 'deleting'`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{ count: number }>();
    expect(queued?.count).toBe(2);
  });

  it("retains quota and repository metadata until R2 is confirmed empty, then releases it", async () => {
    const bytes = textEncoder.encode("quota retained through repository sweep");
    const digest = bytesToHex(blake3(bytes));
    expect((await putBlob(bytes, digest)).status).toBe(201);
    await seedToken(
      TENANT,
      "token-repository",
      "R".repeat(43),
      REPOSITORY,
      "read",
    );
    await prepareTrustBundleFixture();
    const before = await env.DB.prepare(
      "SELECT used_bytes, used_metadata_units FROM tenants WHERE id = ?",
    )
      .bind(TENANT)
      .first<{ used_bytes: number; used_metadata_units: number }>();
    if (before === null) throw new Error("tenant accounting row is missing");

    expect(
      (await call(`/v1/repositories/${REPOSITORY}`, repositoryDeleteRequest()))
        .status,
    ).toBe(202);
    await runScheduled();
    const during = await env.DB.prepare(
      "SELECT used_bytes, used_metadata_units FROM tenants WHERE id = ?",
    )
      .bind(TENANT)
      .first<{ used_bytes: number; used_metadata_units: number }>();
    expect(during?.used_bytes).toBe(before.used_bytes);
    expect(during?.used_metadata_units).toBeGreaterThanOrEqual(
      before.used_metadata_units,
    );
    expect(
      await env.DB.prepare(
        `SELECT count(*) AS count FROM blobs
          WHERE tenant_id = ? AND repository_id = ?`,
      )
        .bind(TENANT, REPOSITORY)
        .first<{ count: number }>(),
    ).toEqual({ count: 1 });

    await finishRepositoryDeletion();
    const after = await env.DB.prepare(
      "SELECT used_bytes, used_metadata_units FROM tenants WHERE id = ?",
    )
      .bind(TENANT)
      .first<{ used_bytes: number; used_metadata_units: number }>();
    expect(after).toEqual({ used_bytes: 0, used_metadata_units: 1 });
    expect(
      await env.DB.prepare(
        `SELECT
           (SELECT count(*) FROM repositories WHERE tenant_id = ? AND id = ?) AS repositories,
           (SELECT count(*) FROM auth_tokens
             WHERE tenant_id = ? AND repository_scope = ?) AS scoped_tokens,
           (SELECT count(*) FROM trust_root_keys
             WHERE tenant_id = ? AND repository_id = ?) AS roots,
           (SELECT count(*) FROM audit_events
             WHERE tenant_id = ? AND repository_id = ?) AS audits`,
      )
        .bind(
          TENANT,
          REPOSITORY,
          TENANT,
          REPOSITORY,
          TENANT,
          REPOSITORY,
          TENANT,
          REPOSITORY,
        )
        .first<{
          repositories: number;
          scoped_tokens: number;
          roots: number;
          audits: number;
        }>(),
    ).toEqual({ repositories: 0, scoped_tokens: 0, roots: 0, audits: 0 });
  });

  it("bounds expired-manifest cleanup per scheduled invocation", async () => {
    const fixture = await prepareEncryptedManifestV2Fixture();
    const trustBodySha = await sha256Hex(
      canonicalTrustBundleJson(fixture.trustBundle),
    );
    const bodyJson = JSON.stringify(fixture.manifest);
    const now = Math.floor(Date.now() / 1000);
    const statements: D1PreparedStatement[] = [];
    for (let index = 0; index < 70; index += 1) {
      statements.push(
        env.DB.prepare(
          `INSERT INTO manifests(
             tenant_id, repository_id, request_key, record_id, body_sha256, body_json,
             state, producer_id, key_id, stdout_digest, stdout_size_bytes,
             stderr_digest, stderr_size_bytes, created_at, expires_at,
             trust_epoch, trust_body_sha256
           ) VALUES (?, ?, ?, ?, ?, ?, 'ready', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
        ).bind(
          TENANT,
          REPOSITORY,
          (index + 1000).toString(16).padStart(64, "0"),
          `retention-record-${index}`,
          "a".repeat(64),
          bodyJson,
          fixture.manifest.producer_id,
          fixture.manifest.signature.key_id,
          fixture.manifest.stdout.ciphertext_digest,
          fixture.manifest.stdout.ciphertext_size_bytes,
          fixture.manifest.stderr.ciphertext_digest,
          fixture.manifest.stderr.ciphertext_size_bytes,
          now - 100,
          now + 3600,
          fixture.trustBundle.epoch,
          trustBodySha,
        ),
      );
    }
    for (let offset = 0; offset < statements.length; offset += 25) {
      await env.DB.batch(statements.slice(offset, offset + 25));
    }
    await env.DB.prepare(
      `UPDATE manifests SET expires_at = ?
        WHERE tenant_id = ? AND repository_id = ?
          AND request_key >= ?`,
    )
      .bind(now - 1, TENANT, REPOSITORY, (1000).toString(16).padStart(64, "0"))
      .run();

    await runScheduled();
    const remaining = await env.DB.prepare(
      `SELECT count(*) AS count FROM manifests
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{ count: number }>();
    expect(remaining?.count).toBe(70 - 64);
  });

  it("fairly cleans an expired manifest for a second tenant within a full batch", async () => {
    const fixtureA = await prepareEncryptedManifestV2Fixture();
    const trustBodyShaA = await sha256Hex(
      canonicalTrustBundleJson(fixtureA.trustBundle),
    );
    const statements: D1PreparedStatement[] = [];
    for (let index = 0; index < 64; index += 1) {
      const manifest = copyEncryptedManifestV2(fixtureA.manifest);
      manifest.request_key = (index + 10_000).toString(16).padStart(64, "0");
      manifest.record_id = `fairness-starver-${index}`;
      await signEncryptedManifestV2(manifest, fixtureA.privateKey);
      statements.push(
        manifestInsert(
          manifest,
          JSON.stringify(manifest),
          fixtureA.trustBundle.epoch,
          trustBodyShaA,
        ),
      );
    }
    for (let offset = 0; offset < statements.length; offset += 25) {
      await env.DB.batch(statements.slice(offset, offset + 25));
    }

    const tenantB = "tenant-fair-manifest";
    const repositoryB = "repo-fair-manifest";
    const tokenB = "token-fair-manifest";
    const secretB = "M".repeat(43);
    const bearerB = `ag1.${tokenB}.${secretB}`;
    await seedTenant(tenantB, tokenB, secretB, repositoryB);
    const fixtureB = await prepareEncryptedManifestV2FixtureAt({
      tenantId: tenantB,
      repositoryId: repositoryB,
      generationId: GENERATION,
      bearer: bearerB,
    });
    expect(
      (
        await call(
          `/v1/repositories/${repositoryB}/manifests/${fixtureB.manifest.request_key}`,
          jsonRequest(fixtureB.manifest, bearerB, "PUT", GENERATION),
        )
      ).status,
    ).toBe(201);

    const expiredAt = Math.floor(Date.now() / 1000) - 1;
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE manifests SET expires_at = ?
          WHERE tenant_id = ? AND repository_id = ?`,
      ).bind(expiredAt, TENANT, REPOSITORY),
      env.DB.prepare(
        `UPDATE manifests SET expires_at = ?
          WHERE tenant_id = ? AND repository_id = ? AND request_key = ?`,
      ).bind(expiredAt, tenantB, repositoryB, fixtureB.manifest.request_key),
    ]);
    await env.DB.batch([
      env.DB.prepare(
        `UPDATE manifest_gc_candidates SET due_at = 0
          WHERE tenant_id = ? AND repository_id = ?`,
      ).bind(TENANT, REPOSITORY),
      env.DB.prepare(
        `UPDATE manifest_gc_candidates SET due_at = 1
          WHERE tenant_id = ? AND repository_id = ? AND request_key = ?`,
      ).bind(tenantB, repositoryB, fixtureB.manifest.request_key),
    ]);

    await runScheduled();
    expect(
      await env.DB.prepare(
        `SELECT request_key FROM manifests
          WHERE tenant_id = ? AND repository_id = ? AND request_key = ?`,
      )
        .bind(tenantB, repositoryB, fixtureB.manifest.request_key)
        .first<{ request_key: string }>(),
    ).toBeNull();
  });

  it("fairly advances a second tenant's blob GC work within a full batch", async () => {
    const tenantB = "tenant-fair-gc";
    const repositoryB = "repo-fair-gc";
    await seedTenant(tenantB, "token-fair-gc", "G".repeat(43), repositoryB);
    const old = Math.floor(Date.now() / 1000) - 7200;
    const statements: D1PreparedStatement[] = [];
    for (let index = 0; index < 64; index += 1) {
      statements.push(
        env.DB.prepare(
          `INSERT INTO blobs(
             tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
             reconcile_attempts, next_reconcile_at,
             r2_key, r2_version, r2_etag, r2_sha256
           ) VALUES (?, ?, ?, 0, 'ready', ?, ?, 0, ?, ?, 'test-version', 'test-etag', ?)`,
        ).bind(
          TENANT,
          REPOSITORY,
          (index + 20_000).toString(16).padStart(64, "0"),
          old,
          old,
          old,
          `test-key-${index}`,
          "0".repeat(64),
        ),
      );
    }
    const digestB = "b".repeat(64);
    statements.push(
      env.DB.prepare(
        `INSERT INTO blobs(
           tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
           reconcile_attempts, next_reconcile_at,
           r2_key, r2_version, r2_etag, r2_sha256
         ) VALUES (?, ?, ?, 0, 'ready', ?, ?, 0, ?, 'test-key-b', 'test-version', 'test-etag', ?)`,
      ).bind(tenantB, repositoryB, digestB, old, old, old, "0".repeat(64)),
    );
    for (let offset = 0; offset < statements.length; offset += 25) {
      await env.DB.batch(statements.slice(offset, offset + 25));
    }
    await env.DB.prepare(
      "UPDATE blob_gc_candidates SET next_check_at = 0",
    ).run();

    await runScheduled();
    expect(
      await env.DB.prepare(
        `SELECT state FROM blobs
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(tenantB, repositoryB, digestB)
        .first<{ state: string }>(),
    ).toEqual({ state: "deleting" });
  });

  it("fairly advances a second tenant's reconciliation within a full batch", async () => {
    const tenantB = "tenant-fair-reconcile";
    const repositoryB = "repo-fair-reconcile";
    await seedTenant(
      tenantB,
      "token-fair-reconcile",
      "R".repeat(43),
      repositoryB,
    );
    const old = Math.floor(Date.now() / 1000) - 7200;
    const statements: D1PreparedStatement[] = [];
    for (let index = 0; index < 16; index += 1) {
      statements.push(
        env.DB.prepare(
          `INSERT INTO blobs(
             tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
             reconcile_attempts, next_reconcile_at
           ) VALUES (?, ?, ?, 0, 'pending', ?, ?, 0, 0)`,
        ).bind(
          TENANT,
          REPOSITORY,
          (index + 30_000).toString(16).padStart(64, "0"),
          old,
          old,
        ),
      );
    }
    const digestB = "c".repeat(64);
    statements.push(
      env.DB.prepare(
        `INSERT INTO blobs(
           tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
           reconcile_attempts, next_reconcile_at
         ) VALUES (?, ?, ?, 0, 'pending', ?, ?, 0, 0)`,
      ).bind(tenantB, repositoryB, digestB, old, old),
    );
    await env.DB.batch(statements);

    await runReconciliation();
    expect(
      await env.DB.prepare(
        `SELECT reconcile_attempts FROM blobs
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(tenantB, repositoryB, digestB)
        .first<{ reconcile_attempts: number }>(),
    ).toEqual({ reconcile_attempts: 1 });
  });

  it("routes lightweight and hash-heavy maintenance to their configured crons", async () => {
    const bytes = textEncoder.encode("cron routing");
    const digest = bytesToHex(blake3(bytes));
    const now = Math.floor(Date.now() / 1000);
    await env.DB.prepare(
      `INSERT INTO blobs(
         tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
         reconcile_attempts, next_reconcile_at
       ) VALUES (?, ?, ?, ?, 'pending', ?, ?, 0, 0)`,
    )
      .bind(TENANT, REPOSITORY, digest, bytes.byteLength, now, now)
      .run();
    const key = `v1/${TENANT}/${REPOSITORY}/${GENERATION}/blake3/${digest}`;
    await env.BLOBS.put(key, bytes, {
      customMetadata: {
        blake3: digest,
        size_bytes: String(bytes.byteLength),
        incarnation_id: "0".repeat(32),
      },
      sha256: await crypto.subtle.digest("SHA-256", bytes),
    });

    await runScheduled();
    expect(
      await env.DB.prepare(
        "SELECT state FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = ?",
      )
        .bind(TENANT, REPOSITORY, digest)
        .first<{ state: string }>(),
    ).toEqual({ state: "pending" });
    await runReconciliation();
    expect(
      await env.DB.prepare(
        "SELECT state FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = ?",
      )
        .bind(TENANT, REPOSITORY, digest)
        .first<{ state: string }>(),
    ).toEqual({ state: "ready" });

    expect(
      (await call(`/v1/repositories/${REPOSITORY}`, repositoryDeleteRequest()))
        .status,
    ).toBe(202);
    await runReconciliation();
    expect(await env.BLOBS.head(key)).not.toBeNull();
    expect(
      await env.DB.prepare(
        `SELECT phase, empty_confirmations FROM repository_deletions
          WHERE tenant_id = ? AND repository_id = ?`,
      )
        .bind(TENANT, REPOSITORY)
        .first<{ phase: string; empty_confirmations: number }>(),
    ).toEqual({ phase: "r2", empty_confirmations: 0 });
    await runScheduled();
    expect(await env.BLOBS.head(key)).toBeNull();
  });

  it("uses indexed due-work plans for retention and lifecycle queues", async () => {
    const plans = await Promise.all([
      explainPlan(
        `SELECT tenant_id, repository_id FROM repository_deletions
          WHERE next_attempt_at <= ? AND (lease_until IS NULL OR lease_until <= ?)
          ORDER BY next_attempt_at, requested_at, tenant_id, repository_id LIMIT ?`,
        0,
        0,
        4,
      ),
      explainPlan(
        `SELECT tenant_id, repository_id, digest FROM blob_gc_candidates
          WHERE next_check_at <= ?
          ORDER BY next_check_at, created_at, tenant_id, repository_id, digest LIMIT ?`,
        0,
        64,
      ),
      explainPlan(
        `SELECT tenant_id, repository_id, request_key FROM manifest_gc_candidates
          WHERE due_at <= ?
          ORDER BY due_at, tenant_id, repository_id, request_key LIMIT ?`,
        0,
        64,
      ),
      explainPlan(
        `SELECT rowid FROM repository_write_leases
          WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?
            AND expires_at <= ?
          ORDER BY expires_at, rowid LIMIT ?`,
        TENANT,
        REPOSITORY,
        GENERATION,
        0,
        256,
      ),
      explainPlan(
        `SELECT digest FROM blobs
          WHERE state IN ('pending', 'deleting') AND next_reconcile_at <= ?
          ORDER BY next_reconcile_at, created_at LIMIT ?`,
        0,
        16,
      ),
      explainPlan(
        `SELECT rowid FROM audit_events
          WHERE tenant_id = ? AND repository_id = ? ORDER BY rowid LIMIT ?`,
        TENANT,
        REPOSITORY,
        256,
      ),
      explainPlan(
        `SELECT rowid FROM manifest_conflicts
          WHERE tenant_id = ? AND repository_id = ? ORDER BY rowid LIMIT ?`,
        TENANT,
        REPOSITORY,
        256,
      ),
      explainPlan(
        `SELECT rowid FROM auth_tokens
          WHERE tenant_id = ? AND repository_scope = ? ORDER BY rowid LIMIT ?`,
        TENANT,
        REPOSITORY,
        256,
      ),
    ]);
    expect(plans[0]).toContain("repository_deletions_due");
    expect(plans[1]).toContain("blob_gc_candidates_due");
    expect(plans[2]).toContain("manifest_gc_candidates_due");
    expect(plans[3]).toContain("repository_write_leases_expiry");
    expect(plans[4]).toContain("blobs_reconcile_due");
    expect(plans[5]).toContain("audit_events_repository_cleanup");
    expect(plans[6]).toContain("manifest_conflicts_repository_cleanup");
    expect(plans[7]).toContain("auth_tokens_repository_cleanup");
    expect(plans.join("\n")).not.toContain("SCAN repository_deletions");
    expect(plans.join("\n")).not.toContain("SCAN blob_gc_candidates");
    expect(plans.join("\n")).not.toContain("SCAN manifest_gc_candidates");
  });
});

function databaseThatPausesRepositoryCleanup(
  database: D1Database,
  table: string,
): {
  database: D1Database;
  entered: Promise<void>;
  release: () => void;
} {
  let signalEntered = (): void => {};
  let signalRelease = (): void => {};
  let paused = false;
  const entered = new Promise<void>((resolve) => {
    signalEntered = resolve;
  });
  const released = new Promise<void>((resolve) => {
    signalRelease = resolve;
  });
  const queries = new WeakMap<object, string>();

  const wrapStatement = (
    statement: D1PreparedStatement,
    query: string,
  ): D1PreparedStatement => {
    const wrapped = new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...values: unknown[]) =>
            wrapStatement(target.bind(...values), query);
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    queries.set(wrapped, query);
    return wrapped;
  };

  const proxied = new Proxy(database, {
    get(target, property) {
      if (property === "prepare") {
        return (query: string) => wrapStatement(target.prepare(query), query);
      }
      if (property === "batch") {
        return async (statements: D1PreparedStatement[]) => {
          const isCleanupBatch = statements.some((statement) => {
            const query = queries.get(statement) ?? "";
            return (
              query.includes(`DELETE FROM ${table}`) &&
              query.includes("repository_deletions deletion")
            );
          });
          if (!paused && isCleanupBatch) {
            paused = true;
            signalEntered();
            await released;
          }
          return target.batch(statements);
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });

  return { database: proxied, entered, release: signalRelease };
}

function databaseThatPausesMutation(
  database: D1Database,
  marker: string,
): {
  database: D1Database;
  entered: Promise<void>;
  release: () => void;
} {
  let signalEntered = (): void => {};
  let signalRelease = (): void => {};
  let paused = false;
  const entered = new Promise<void>((resolve) => {
    signalEntered = resolve;
  });
  const released = new Promise<void>((resolve) => {
    signalRelease = resolve;
  });
  const queries = new WeakMap<object, string>();
  const maybePause = async (query: string): Promise<void> => {
    if (!paused && query.includes(marker)) {
      paused = true;
      signalEntered();
      await released;
    }
  };

  const wrapStatement = (
    statement: D1PreparedStatement,
    query: string,
  ): D1PreparedStatement => {
    const wrapped = new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...values: unknown[]) =>
            wrapStatement(target.bind(...values), query);
        }
        if (property === "run") {
          return async () => {
            await maybePause(query);
            return target.run();
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
    queries.set(wrapped, query);
    return wrapped;
  };

  const proxied = new Proxy(database, {
    get(target, property) {
      if (property === "prepare") {
        return (query: string) => wrapStatement(target.prepare(query), query);
      }
      if (property === "batch") {
        return async (statements: D1PreparedStatement[]) => {
          const query = statements
            .map((statement) => queries.get(statement) ?? "")
            .join("\n");
          await maybePause(query);
          return target.batch(statements);
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { database: proxied, entered, release: signalRelease };
}

function databaseThatPausesFirstQueryAfterRead(
  database: D1Database,
  marker: string,
): {
  database: D1Database;
  entered: Promise<void>;
  release: () => void;
} {
  let signalEntered = (): void => {};
  let signalRelease = (): void => {};
  let paused = false;
  const entered = new Promise<void>((resolve) => {
    signalEntered = resolve;
  });
  const released = new Promise<void>((resolve) => {
    signalRelease = resolve;
  });
  const wrapStatement = (
    statement: D1PreparedStatement,
    query: string,
  ): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...values: unknown[]) =>
            wrapStatement(target.bind(...values), query);
        }
        if (property === "first") {
          return async (columnName?: string) => {
            const result =
              columnName === undefined
                ? await target.first()
                : await target.first(columnName);
            if (!paused && query.includes(marker)) {
              paused = true;
              signalEntered();
              await released;
            }
            return result;
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  const proxied = new Proxy(database, {
    get(target, property) {
      if (property === "prepare") {
        return (query: string) => wrapStatement(target.prepare(query), query);
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { database: proxied, entered, release: signalRelease };
}

function databaseThatPausesExactBundleFinalFence(database: D1Database): {
  database: D1Database;
  entered: Promise<void>;
  release: () => void;
  matchCount: () => number;
} {
  let signalEntered = (): void => {};
  let signalRelease = (): void => {};
  let matches = 0;
  const entered = new Promise<void>((resolve) => {
    signalEntered = resolve;
  });
  const released = new Promise<void>((resolve) => {
    signalRelease = resolve;
  });
  const isExactBundleFinalFence = (query: string): boolean =>
    query.includes("SELECT head.body_json AS trust_body_json") &&
    query.includes("JOIN manifests manifest") &&
    query.includes("AND stdout_blob.incarnation_id = ?") &&
    query.includes("AND stderr_blob.incarnation_id = ?") &&
    query.includes("AND head.epoch = ? AND head.body_sha256 = ?");
  const wrapStatement = (
    statement: D1PreparedStatement,
    query: string,
  ): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...values: unknown[]) =>
            wrapStatement(target.bind(...values), query);
        }
        if (property === "first") {
          return async (columnName?: string) => {
            if (isExactBundleFinalFence(query)) {
              matches += 1;
              if (matches === 1) {
                signalEntered();
                await released;
              }
            }
            return columnName === undefined
              ? target.first()
              : target.first(columnName);
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  const proxied = new Proxy(database, {
    get(target, property) {
      if (property === "prepare") {
        return (query: string) => wrapStatement(target.prepare(query), query);
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return {
    database: proxied,
    entered,
    release: signalRelease,
    matchCount: () => matches,
  };
}

async function seedRepositoryCleanupSentinel(
  phase: (typeof REPOSITORY_D1_CLEANUP_CASES)[number][0],
  generationId: string,
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  const digest = "d".repeat(64);
  switch (phase) {
    case "manifest_conflicts":
      await env.DB.prepare(
        `INSERT INTO manifest_conflicts(
           tenant_id, repository_id, request_key,
           existing_body_sha256, submitted_body_sha256, detected_at
         ) VALUES (?, ?, ?, ?, ?, ?)`,
      )
        .bind(
          TENANT,
          REPOSITORY,
          "c".repeat(64),
          "a".repeat(64),
          "b".repeat(64),
          now,
        )
        .run();
      return;
    case "manifests":
      {
        const fixture = await prepareEncryptedManifestV2Fixture(generationId);
        expect(
          (await putEncryptedManifestV2(fixture.manifest, generationId)).status,
        ).toBe(201);
      }
      return;
    case "blobs":
      await env.DB.prepare(
        `INSERT INTO blobs(
           tenant_id, repository_id, digest, size_bytes, state,
           created_at, updated_at, reconcile_attempts, next_reconcile_at,
           r2_key, r2_version, r2_etag, r2_sha256
         ) VALUES (?, ?, ?, 0, 'ready', ?, ?, 0, ?, 'test-key', 'test-version', 'test-etag', ?)`,
      )
        .bind(TENANT, REPOSITORY, digest, now, now, now, "0".repeat(64))
        .run();
      return;
    case "trust_heads": {
      const body = JSON.stringify({
        generation_id: generationId,
        active_producer_keys: [],
        revoked_key_ids: [],
        revoked_record_ids: [],
      });
      await env.DB.batch([
        env.DB.prepare(
          `INSERT INTO trust_root_keys(
             tenant_id, repository_id, root_key_id, public_key_hex, created_at
           ) VALUES (?, ?, 'cleanup-root', ?, ?)`,
        ).bind(TENANT, REPOSITORY, "a".repeat(64), now),
        env.DB.prepare(
          `INSERT INTO trust_heads(
             tenant_id, repository_id, epoch, root_key_id, body_sha256, body_json,
             issued_at, expires_at, updated_at
           ) VALUES (?, ?, 1, 'cleanup-root', ?, ?, ?, ?, ?)`,
        ).bind(TENANT, REPOSITORY, "b".repeat(64), body, now, now + 300, now),
      ]);
      return;
    }
    case "trust_key_history":
      await env.DB.prepare(
        `INSERT INTO trust_key_history(
           tenant_id, repository_id, key_id, producer_id, public_key_json, first_epoch
         ) VALUES (?, ?, 'cleanup-key', 'cleanup-producer', '{}', 1)`,
      )
        .bind(TENANT, REPOSITORY)
        .run();
      return;
    case "trust_revoked_keys":
      await env.DB.prepare(
        `INSERT INTO trust_revoked_keys(
           tenant_id, repository_id, key_id, first_epoch
         ) VALUES (?, ?, 'cleanup-key', 1)`,
      )
        .bind(TENANT, REPOSITORY)
        .run();
      return;
    case "trust_revoked_records":
      await env.DB.prepare(
        `INSERT INTO trust_revoked_records(
           tenant_id, repository_id, record_id, first_epoch
         ) VALUES (?, ?, 'cleanup-record', 1)`,
      )
        .bind(TENANT, REPOSITORY)
        .run();
      return;
    case "trust_root_keys":
      await env.DB.prepare(
        `INSERT INTO trust_root_keys(
           tenant_id, repository_id, root_key_id, public_key_hex, created_at
         ) VALUES (?, ?, 'cleanup-root', ?, ?)`,
      )
        .bind(TENANT, REPOSITORY, "a".repeat(64), now)
        .run();
      return;
    case "producer_keys":
      await env.DB.prepare(
        `INSERT INTO producer_keys(
           tenant_id, repository_id, key_id, producer_id, public_key_hex, created_at
         ) VALUES (?, ?, 'cleanup-key', 'cleanup-producer', ?, ?)`,
      )
        .bind(TENANT, REPOSITORY, "a".repeat(64), now)
        .run();
      return;
    case "auth_tokens":
      await seedToken(
        TENANT,
        "cleanup-token",
        "C".repeat(43),
        REPOSITORY,
        "read",
      );
      return;
    case "audit_events":
      await env.DB.prepare(
        `INSERT INTO audit_events(
           tenant_id, repository_id, actor, action, target_type,
           target_id_sha256, outcome, details_json, created_at
         ) VALUES (?, ?, 'cleanup-test', 'cleanup-sentinel', 'repository', ?,
                   'present', '{}', ?)`,
      )
        .bind(TENANT, REPOSITORY, "a".repeat(64), now)
        .run();
      return;
  }
}

async function repositoryCleanupSentinelCount(
  phase: (typeof REPOSITORY_D1_CLEANUP_CASES)[number][0],
): Promise<number> {
  const queryByPhase: Record<typeof phase, string> = {
    manifest_conflicts:
      "SELECT count(*) AS count FROM manifest_conflicts WHERE tenant_id = ? AND repository_id = ? AND request_key = '" +
      "c".repeat(64) +
      "'",
    manifests:
      "SELECT count(*) AS count FROM manifests WHERE tenant_id = ? AND repository_id = ? AND record_id = 'encrypted-record-1'",
    blobs:
      "SELECT count(*) AS count FROM blobs WHERE tenant_id = ? AND repository_id = ? AND digest = '" +
      "d".repeat(64) +
      "'",
    trust_heads:
      "SELECT count(*) AS count FROM trust_heads WHERE tenant_id = ? AND repository_id = ? AND body_sha256 = '" +
      "b".repeat(64) +
      "'",
    trust_key_history:
      "SELECT count(*) AS count FROM trust_key_history WHERE tenant_id = ? AND repository_id = ? AND key_id = 'cleanup-key'",
    trust_revoked_keys:
      "SELECT count(*) AS count FROM trust_revoked_keys WHERE tenant_id = ? AND repository_id = ? AND key_id = 'cleanup-key'",
    trust_revoked_records:
      "SELECT count(*) AS count FROM trust_revoked_records WHERE tenant_id = ? AND repository_id = ? AND record_id = 'cleanup-record'",
    trust_root_keys:
      "SELECT count(*) AS count FROM trust_root_keys WHERE tenant_id = ? AND repository_id = ? AND root_key_id = 'cleanup-root'",
    producer_keys:
      "SELECT count(*) AS count FROM producer_keys WHERE tenant_id = ? AND repository_id = ? AND key_id = 'cleanup-key'",
    auth_tokens:
      "SELECT count(*) AS count FROM auth_tokens WHERE tenant_id = ? AND repository_scope = ? AND id = 'cleanup-token'",
    audit_events:
      "SELECT count(*) AS count FROM audit_events WHERE tenant_id = ? AND repository_id = ? AND action = 'cleanup-sentinel'",
  };
  const row = await env.DB.prepare(queryByPhase[phase])
    .bind(TENANT, REPOSITORY)
    .first<{ count: number }>();
  return row?.count ?? 0;
}

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
      "INSERT INTO repositories(tenant_id, id, generation_id, created_at) VALUES (?, ?, ?, ?)",
    ).bind(tenantId, repositoryId, GENERATION, now),
  ]);
  await seedToken(
    tenantId,
    tokenId,
    secret,
    null,
    "admin,read,write,delete,audit",
  );
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

async function call(
  path: string,
  init?: RequestInit,
  stripAutoLength = false,
): Promise<Response> {
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

async function configureBundleReferenceMatrixState(
  state: BundleReferenceMatrixState,
  fixture: {
    manifest: EncryptedRemoteCacheManifestV2;
    privateKey: CryptoKey;
    trustBundle: TrustBundleV1;
    trustPrivateKey: CryptoKey;
  },
): Promise<{
  runtimeEnv: Env;
  manifest: EncryptedRemoteCacheManifestV2;
  generationId: string;
}> {
  let runtimeDb = env.DB;
  let manifest = fixture.manifest;
  let generationId = GENERATION;
  const now = Math.floor(Date.now() / 1000);
  switch (state) {
    case "valid":
      break;
    case "absent_manifest":
      await env.DB.prepare(
        "DELETE FROM manifests WHERE tenant_id = ? AND repository_id = ? AND request_key = ?",
      )
        .bind(TENANT, REPOSITORY, manifest.request_key)
        .run();
      break;
    case "deleted_manifest": {
      const deleted = await call(
        `/v1/repositories/${REPOSITORY}/manifests/${manifest.request_key}`,
        authRequest(undefined, "DELETE"),
      );
      if (deleted.status !== 204)
        throw new Error("failed to create deleted-manifest matrix state");
      break;
    }
    case "expired_manifest":
      manifest = copyEncryptedManifestV2(manifest);
      manifest.created_at_unix_seconds = now - 3_601;
      manifest.expires_at_unix_seconds = now - 1;
      await signEncryptedManifestV2(manifest, fixture.privateKey);
      await replaceStoredManifestBodyForMatrix(manifest);
      break;
    case "future_manifest":
      manifest = copyEncryptedManifestV2(manifest);
      manifest.created_at_unix_seconds = now + 3_600;
      manifest.expires_at_unix_seconds = now + 7_200;
      await signEncryptedManifestV2(manifest, fixture.privateKey);
      await replaceStoredManifestBodyForMatrix(manifest);
      break;
    case "revoked_producer": {
      const revoked = copyTrustBundle(fixture.trustBundle);
      revoked.epoch += 1;
      revoked.issued_at_unix_seconds += 1;
      revoked.expires_at_unix_seconds += 1;
      revoked.active_producer_keys = [];
      revoked.revoked_key_ids = [manifest.signature.key_id];
      await signTrustBundle(revoked, fixture.trustPrivateKey);
      if ((await putTrustBundle(revoked)).status !== 204)
        throw new Error("failed to create revoked-producer matrix state");
      break;
    }
    case "revoked_record": {
      const revoked = copyTrustBundle(fixture.trustBundle);
      revoked.epoch += 1;
      revoked.issued_at_unix_seconds += 1;
      revoked.expires_at_unix_seconds += 1;
      revoked.revoked_record_ids = [manifest.record_id];
      await signTrustBundle(revoked, fixture.trustPrivateKey);
      if ((await putTrustBundle(revoked)).status !== 204)
        throw new Error("failed to create revoked-record matrix state");
      break;
    }
    case "disallowed_binding": {
      const disallowed = copyTrustBundle(fixture.trustBundle);
      disallowed.epoch += 1;
      disallowed.issued_at_unix_seconds += 1;
      disallowed.expires_at_unix_seconds += 1;
      disallowed.allowed_policy_digests = [];
      await signTrustBundle(disallowed, fixture.trustPrivateKey);
      if ((await putTrustBundle(disallowed)).status !== 204)
        throw new Error("failed to create disallowed-binding matrix state");
      break;
    }
    case "quarantined_manifest":
      await env.DB.prepare(
        `UPDATE manifests SET state = 'quarantined'
          WHERE tenant_id = ? AND repository_id = ? AND request_key = ?`,
      )
        .bind(TENANT, REPOSITORY, manifest.request_key)
        .run();
      break;
    case "non_ready_blob":
      await env.DB.prepare(
        `UPDATE blobs SET state = 'pending'
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
      )
        .bind(TENANT, REPOSITORY, manifest.stdout.ciphertext_digest)
        .run();
      break;
    case "inconsistent_metadata":
      await env.DB.prepare(
        `UPDATE manifests SET stderr_size_bytes = stderr_size_bytes + 1
          WHERE tenant_id = ? AND repository_id = ? AND request_key = ?`,
      )
        .bind(TENANT, REPOSITORY, manifest.request_key)
        .run();
      break;
    case "missing_blob":
      await env.BLOBS.delete(
        await blobObjectKey(manifest.stdout.ciphertext_digest),
      );
      break;
    case "corrupt_blob": {
      const digest = manifest.stderr.ciphertext_digest;
      const key = await blobObjectKey(digest);
      const incarnationId = await blobIncarnation(digest);
      const corrupted = Uint8Array.from(
        { length: manifest.stderr.ciphertext_size_bytes },
        (_, index) => ((index * 29) ^ 0xff) & 0xff,
      );
      await env.BLOBS.put(key, corrupted, {
        customMetadata: {
          blake3: digest,
          size_bytes: String(corrupted.byteLength),
          incarnation_id: incarnationId,
        },
        sha256: await crypto.subtle.digest("SHA-256", corrupted),
      });
      break;
    }
    case "missing_trust":
      await env.DB.prepare(
        "DELETE FROM trust_heads WHERE tenant_id = ? AND repository_id = ?",
      )
        .bind(TENANT, REPOSITORY)
        .run();
      break;
    case "expired_trust":
      runtimeDb = databaseThatOverridesTrustHead(env.DB, "expired");
      break;
    case "malformed_trust":
      runtimeDb = databaseThatOverridesTrustHead(env.DB, "malformed");
      break;
    case "disabled_root":
      await env.DB.prepare(
        `UPDATE trust_root_keys SET disabled_at = ?
          WHERE tenant_id = ? AND repository_id = ? AND root_key_id = ?`,
      )
        .bind(
          now,
          TENANT,
          REPOSITORY,
          fixture.trustBundle.root_key_id,
        )
        .run();
      break;
    case "wrong_generation":
      generationId = "2".repeat(32);
      break;
    default: {
      const unreachable: never = state;
      throw new Error(`unhandled bundle/reference matrix state: ${unreachable}`);
    }
  }
  return {
    runtimeEnv: { DB: runtimeDb, BLOBS: env.BLOBS },
    manifest,
    generationId,
  };
}

async function replaceStoredManifestBodyForMatrix(
  manifest: EncryptedRemoteCacheManifestV2,
): Promise<void> {
  const bodyJson = JSON.stringify(manifest);
  const updated = await env.DB.prepare(
    `UPDATE manifests
        SET body_json = ?, body_sha256 = ?, created_at = ?, expires_at = ?
      WHERE tenant_id = ? AND repository_id = ? AND request_key = ?`,
  )
    .bind(
      bodyJson,
      await sha256Hex(bodyJson),
      manifest.created_at_unix_seconds,
      manifest.expires_at_unix_seconds,
      TENANT,
      REPOSITORY,
      manifest.request_key,
    )
    .run();
  if (updated.meta.changes < 1)
    throw new Error("failed to replace stored manifest matrix body");
}

async function observeBundleRoute(
  runtimeEnv: Env,
  manifest: EncryptedRemoteCacheManifestV2,
  generationId: string,
): Promise<ServiceRouteObservation> {
  const response = await callUsingEnv(
    runtimeEnv,
    `/v1/repositories/${REPOSITORY}/lookup-bundles/${manifest.request_key}`,
    authRequest(undefined, "GET", generationId),
  );
  if (response.status !== 200) return observeRouteFailure("bundle", response);
  if (
    response.headers.get("content-type") !==
      "application/vnd.again.lookup-bundle-v1" ||
    response.headers.get("x-again-repository-generation") !== generationId
  ) {
    throw new Error("successful bundle route returned invalid binding headers");
  }
  const wire = new Uint8Array(await response.arrayBuffer());
  const decoded = decodeServiceLookupBundleWire(wire);
  if (wire.byteLength !== Number(response.headers.get("content-length"))) {
    throw new Error("successful bundle route returned the wrong content length");
  }
  return {
    disposition: "hit",
    stage: "bundle",
    status: 200,
    code: null,
    ...decoded,
  };
}

async function observeFiveRequestReferenceRoute(
  runtimeEnv: Env,
  manifest: EncryptedRemoteCacheManifestV2,
  generationId: string,
): Promise<ServiceRouteObservation> {
  const read = async (
    stage: string,
    path: string,
  ): Promise<Uint8Array | ServiceRouteObservation> => {
    const response = await callUsingEnv(
      runtimeEnv,
      path,
      authRequest(undefined, "GET", generationId),
    );
    if (response.status !== 200) return observeRouteFailure(stage, response);
    if (
      response.headers.get("x-again-repository-generation") !== generationId
    ) {
      throw new Error(`${stage} returned the wrong repository generation`);
    }
    return new Uint8Array(await response.arrayBuffer());
  };

  const initialTrust = await read(
    "initial_trust",
    `/v1/repositories/${REPOSITORY}/trust-bundles/latest`,
  );
  if (!(initialTrust instanceof Uint8Array)) return initialTrust;
  const manifestBody = await read(
    "manifest",
    `/v1/repositories/${REPOSITORY}/manifests/${manifest.request_key}`,
  );
  if (!(manifestBody instanceof Uint8Array)) return manifestBody;
  const stdout = await read(
    "stdout_blob",
    `/v1/repositories/${REPOSITORY}/blobs/${manifest.stdout.ciphertext_digest}`,
  );
  if (!(stdout instanceof Uint8Array)) return stdout;
  const stderr = await read(
    "stderr_blob",
    `/v1/repositories/${REPOSITORY}/blobs/${manifest.stderr.ciphertext_digest}`,
  );
  if (!(stderr instanceof Uint8Array)) return stderr;
  const finalTrust = await read(
    "final_trust",
    `/v1/repositories/${REPOSITORY}/trust-bundles/latest`,
  );
  if (!(finalTrust instanceof Uint8Array)) return finalTrust;
  return {
    disposition: "hit",
    stage: "complete",
    status: 200,
    code: null,
    initialTrust,
    manifest: manifestBody,
    stdout,
    stderr,
    finalTrust,
  };
}

async function observeRouteFailure(
  stage: string,
  response: Response,
): Promise<ServiceRouteObservation> {
  const code = response.headers.get("x-again-error-code");
  if (code === null)
    throw new Error(`${stage} failure omitted x-again-error-code`);
  const body = await response.json<{ error?: { code?: string } }>();
  if (body.error?.code !== code)
    throw new Error(`${stage} failure header/body codes diverged`);
  return {
    disposition: code === "manifest_not_found" ? "miss" : "hard_fail",
    stage,
    status: response.status,
    code,
  };
}

function decodeServiceLookupBundleWire(wire: Uint8Array): {
  initialTrust: Uint8Array;
  manifest: Uint8Array;
  stdout: Uint8Array;
  stderr: Uint8Array;
} {
  if (
    wire.byteLength < 32 ||
    new TextDecoder().decode(wire.subarray(0, 8)) !== "AGNBNDL1"
  ) {
    throw new Error("bundle matrix response has an invalid header");
  }
  const view = new DataView(wire.buffer, wire.byteOffset, wire.byteLength);
  if (view.getUint16(8) !== 1 || view.getUint16(10) !== 0) {
    throw new Error("bundle matrix response has an invalid version or flags");
  }
  const lengths = [
    view.getUint32(12),
    view.getUint32(16),
    view.getUint32(20),
    view.getUint32(24),
  ] as const;
  if (view.getUint32(28) !== 0) {
    throw new Error("bundle matrix response has nonzero reserved bits");
  }
  if (32 + lengths.reduce((sum, length) => sum + length, 0) !== wire.length) {
    throw new Error("bundle matrix response has inconsistent lengths");
  }
  let offset = 32;
  const take = (length: number): Uint8Array => {
    const value = wire.slice(offset, offset + length);
    offset += length;
    return value;
  };
  return {
    initialTrust: take(lengths[0]),
    manifest: take(lengths[1]),
    stdout: take(lengths[2]),
    stderr: take(lengths[3]),
  };
}

function authRequest(
  body?: BodyInit,
  method = "GET",
  generationId = GENERATION,
): RequestInit {
  const init: RequestInit = {
    method,
    headers: {
      authorization: `Bearer ${BEARER}`,
      "x-again-repository-generation": generationId,
    },
  };
  if (body !== undefined) init.body = body;
  return init;
}

function repositoryDeleteRequest(generationId = GENERATION): RequestInit {
  return {
    method: "DELETE",
    headers: {
      authorization: `Bearer ${BEARER}`,
      "if-match": `"${generationId}"`,
    },
  };
}

function jsonRequest(
  value: unknown,
  bearer = BEARER,
  method = "POST",
  generationId = GENERATION,
): RequestInit {
  return {
    method,
    headers: {
      authorization: `Bearer ${bearer}`,
      "content-type": "application/json",
      "x-again-repository-generation": generationId,
    },
    body: JSON.stringify(value),
  };
}

async function putBlob(bytes: Uint8Array, digest: string): Promise<Response> {
  return putBlobUsingEnv(env, bytes, digest);
}

async function putBlobAtRepository(
  repositoryId: string,
  bytes: Uint8Array,
  digest: string,
  generationId: string,
  bearer = BEARER,
): Promise<Response> {
  return call(`/v1/repositories/${repositoryId}/blobs/${digest}`, {
    method: "PUT",
    headers: {
      authorization: `Bearer ${bearer}`,
      "content-type": "application/octet-stream",
      "content-length": String(bytes.byteLength),
      "x-again-repository-generation": generationId,
    },
    body: bytes,
  });
}

async function blobIncarnation(digest: string): Promise<string> {
  const row = await env.DB.prepare(
    `SELECT incarnation_id FROM blobs
      WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
  )
    .bind(TENANT, REPOSITORY, digest)
    .first<{ incarnation_id: string }>();
  if (row === null) throw new Error("test blob row is missing");
  return row.incarnation_id;
}

async function blobObjectKey(
  digest: string,
  generationId = GENERATION,
): Promise<string> {
  const incarnationId = await blobIncarnation(digest);
  const suffix = incarnationId === "0".repeat(32) ? "" : `/${incarnationId}`;
  return `v1/${TENANT}/${REPOSITORY}/${generationId}/blake3/${digest}${suffix}`;
}

async function putBlobUsingEnv(
  runtimeEnv: Env,
  bytes: Uint8Array,
  digest: string,
  generationId = GENERATION,
): Promise<Response> {
  return callUsingEnv(
    runtimeEnv,
    `/v1/repositories/${REPOSITORY}/blobs/${digest}`,
    {
      method: "PUT",
      headers: {
        authorization: `Bearer ${BEARER}`,
        "content-type": "application/octet-stream",
        "content-length": String(bytes.byteLength),
        "x-again-repository-generation": generationId,
      },
      body: bytes,
    },
  );
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
              columnName === undefined
                ? await target.first()
                : await target.first(columnName);
            if (
              interceptInitialBlobRead &&
              arrivals < participants &&
              result === null
            ) {
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
            query.includes("SELECT size_bytes, state, updated_at") &&
              query.includes("FROM blobs"),
          );
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function databaseThatPausesAuthenticatedRequests(
  database: D1Database,
  participants: number,
): {
  database: D1Database;
  authenticated: Promise<void>;
  release: () => void;
} {
  let arrivals = 0;
  let signalAuthenticated = (): void => {};
  let signalRelease = (): void => {};
  const authenticated = new Promise<void>((resolve) => {
    signalAuthenticated = resolve;
  });
  const released = new Promise<void>((resolve) => {
    signalRelease = resolve;
  });

  const wrapStatement = (
    statement: D1PreparedStatement,
    interceptRateAdmission: boolean,
  ): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...values: unknown[]) =>
            wrapStatement(target.bind(...values), interceptRateAdmission);
        }
        if (property === "first") {
          return async (columnName?: string) => {
            const result =
              columnName === undefined
                ? await target.first()
                : await target.first(columnName);
            if (
              interceptRateAdmission &&
              arrivals < participants &&
              result !== null
            ) {
              arrivals += 1;
              if (arrivals === participants) signalAuthenticated();
              await released;
            }
            return result;
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });

  const proxied = new Proxy(database, {
    get(target, property) {
      if (property === "prepare") {
        return (query: string) =>
          wrapStatement(
            target.prepare(query),
            query.includes("INSERT INTO rate_windows") &&
              query.includes("RETURNING request_count"),
          );
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });

  return {
    database: proxied,
    authenticated,
    release: signalRelease,
  };
}

function databaseThatFailsFirstRepositoryDeletionLease(
  database: D1Database,
): D1Database {
  let failed = false;
  const wrapStatement = (
    statement: D1PreparedStatement,
    query: string,
  ): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...values: unknown[]) =>
            wrapStatement(target.bind(...values), query);
        }
        if (property === "first") {
          return async (columnName?: string) => {
            if (
              !failed &&
              query.includes("UPDATE repository_deletions") &&
              query.includes("SET lease_id = ?")
            ) {
              failed = true;
              throw new Error("injected repository deletion lease failure");
            }
            return columnName === undefined
              ? target.first()
              : target.first(columnName);
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  return new Proxy(database, {
    get(target, property) {
      if (property === "prepare") {
        return (query: string) => wrapStatement(target.prepare(query), query);
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function databaseThatFailsOrphanOwnerForTenant(
  database: D1Database,
  tenantId: string,
): D1Database {
  const wrapStatement = (
    statement: D1PreparedStatement,
    query: string,
    bindings: readonly unknown[] = [],
  ): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...values: unknown[]) =>
            wrapStatement(target.bind(...values), query, values);
        }
        if (property === "first") {
          return async (columnName?: string) => {
            if (
              query.includes("SELECT blob.state") &&
              query.includes("FROM blobs blob") &&
              bindings[0] === tenantId
            ) {
              throw new Error("injected orphan-owner read failure");
            }
            return columnName === undefined
              ? target.first()
              : target.first(columnName);
          };
        }
        const value = Reflect.get(target, property, target);
        return typeof value === "function" ? value.bind(target) : value;
      },
    });
  return new Proxy(database, {
    get(target, property) {
      if (property === "prepare") {
        return (query: string) => wrapStatement(target.prepare(query), query);
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function databaseThatDropsManifestProducer(database: D1Database): D1Database {
  const wrapStatement = (
    statement: D1PreparedStatement,
    interceptManifestRead: boolean,
  ): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...values: unknown[]) =>
            wrapStatement(target.bind(...values), interceptManifestRead);
        }
        if (property === "first") {
          return async (columnName?: string) => {
            const result =
              columnName === undefined
                ? await target.first()
                : await target.first(columnName);
            if (
              interceptManifestRead &&
              result !== null &&
              typeof result === "object" &&
              !Array.isArray(result)
            ) {
              return {
                ...result,
                producer_key_id: null,
                producer_key_producer_id: null,
                producer_public_key_hex: null,
                key_revoked_at: null,
              };
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
            query.includes("FROM manifests m") &&
              query.includes("LEFT JOIN producer_keys k"),
          );
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function databaseThatOverridesBlobIdentity(
  database: D1Database,
  mode: "legacy-null" | "partial",
): D1Database {
  const wrapStatement = (
    statement: D1PreparedStatement,
    intercept: boolean,
  ): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...values: unknown[]) =>
            wrapStatement(target.bind(...values), intercept);
        }
        if (property === "first") {
          return async (columnName?: string) => {
            const result =
              columnName === undefined
                ? await target.first()
                : await target.first(columnName);
            if (
              !intercept ||
              result === null ||
              typeof result !== "object" ||
              Array.isArray(result)
            ) {
              return result;
            }
            return {
              ...result,
              r2_key: null,
              r2_version: mode === "partial" ? "unexpected-version" : null,
              r2_etag: null,
              r2_sha256: null,
            };
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
            query.includes("SELECT size_bytes, state") &&
              query.includes("r2_key, r2_version, r2_etag, r2_sha256"),
          );
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function databaseWithConcurrentInitialTrustReads(
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
    interceptInitialTrustRead: boolean,
  ): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...values: unknown[]) =>
            wrapStatement(target.bind(...values), interceptInitialTrustRead);
        }
        if (property === "first") {
          return async (columnName?: string) => {
            const result =
              columnName === undefined
                ? await target.first()
                : await target.first(columnName);
            if (
              interceptInitialTrustRead &&
              arrivals < participants &&
              result === null
            ) {
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
            query.includes("FROM trust_heads h") &&
              query.includes("JOIN trust_root_keys"),
          );
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function databaseThatOverridesTrustHead(
  database: D1Database,
  mode: "expired" | "malformed",
): D1Database {
  const wrapStatement = (
    statement: D1PreparedStatement,
    interceptTrustHead: boolean,
  ): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...values: unknown[]) =>
            wrapStatement(target.bind(...values), interceptTrustHead);
        }
        if (property === "first") {
          return async (columnName?: string) => {
            const result =
              columnName === undefined
                ? await target.first()
                : await target.first(columnName);
            if (
              !interceptTrustHead ||
              result === null ||
              typeof result !== "object" ||
              Array.isArray(result)
            ) {
              return result;
            }
            return mode === "expired"
              ? { ...result, expires_at: 1 }
              : { ...result, body_sha256: "0".repeat(64) };
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
            query.includes("SELECT h.epoch") &&
              query.includes("FROM trust_heads h") &&
              query.includes("JOIN trust_root_keys"),
          );
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function databaseThatDeletesManifestAfterFailedGcTransition(
  database: D1Database,
  requestKey: string,
): D1Database {
  let injected = false;
  const wrapStatement = (
    statement: D1PreparedStatement,
    interceptTransition: boolean,
  ): D1PreparedStatement =>
    new Proxy(statement, {
      get(target, property) {
        if (property === "bind") {
          return (...values: unknown[]) =>
            wrapStatement(target.bind(...values), interceptTransition);
        }
        if (property === "run") {
          return async () => {
            const result = await target.run();
            if (interceptTransition && !injected && result.meta.changes === 0) {
              injected = true;
              const now = Math.floor(Date.now() / 1000);
              await database
                .prepare(
                  `UPDATE manifests SET state = 'deleted', deleted_at = ?
                  WHERE tenant_id = ? AND repository_id = ? AND request_key = ?
                    AND state != 'deleted'`,
                )
                .bind(now, TENANT, REPOSITORY, requestKey)
                .run();
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
            query.includes("UPDATE blobs") &&
              query.includes("state = 'deleting'") &&
              query.includes("NOT EXISTS"),
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
        return async (
          key: string,
          _value:
            | ReadableStream
            | ArrayBuffer
            | ArrayBufferView
            | string
            | null
            | Blob,
          options?: R2PutOptions,
        ) =>
          target.put(key, forged, {
            ...options,
            sha256: await crypto.subtle.digest("SHA-256", forged),
          });
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function bucketThatReturnsNullAfterSuccessfulPut(bucket: R2Bucket): R2Bucket {
  return new Proxy(bucket, {
    get(target, property) {
      if (property === "put") {
        return async (
          key: string,
          value:
            | ReadableStream
            | ArrayBuffer
            | ArrayBufferView
            | string
            | null
            | Blob,
          options?: R2PutOptions,
        ): Promise<null> => {
          await target.put(key, value, options);
          return null;
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function bucketThatForbidsBodyBuffering(bucket: R2Bucket): R2Bucket {
  return new Proxy(bucket, {
    get(target, property) {
      if (property === "get") {
        return async (
          key: string,
          options?: R2GetOptions,
        ): Promise<R2ObjectBody | R2Object | null> => {
          const object = await target.get(key, options);
          if (object === null || !("body" in object)) return object;
          return new Proxy(object, {
            get(bodyTarget, bodyProperty) {
              if (
                ["arrayBuffer", "bytes", "text", "json", "blob"].includes(
                  String(bodyProperty),
                )
              ) {
                return (): never => {
                  throw new Error("ciphertext body buffering is forbidden");
                };
              }
              const value = Reflect.get(bodyTarget, bodyProperty, bodyTarget);
              return typeof value === "function"
                ? value.bind(bodyTarget)
                : value;
            },
          });
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function bucketThatTracksResponseBodyPulls(bucket: R2Bucket): {
  bucket: R2Bucket;
  getCount: (key: string) => number;
  pullCount: (key: string) => number;
} {
  const gets = new Map<string, number>();
  const pulls = new Map<string, number>();
  const proxied = new Proxy(bucket, {
    get(target, property) {
      if (property === "get") {
        return async (
          key: string,
          options?: R2GetOptions,
        ): Promise<R2ObjectBody | R2Object | null> => {
          gets.set(key, (gets.get(key) ?? 0) + 1);
          const object = await target.get(key, options);
          if (object === null || !("body" in object)) return object;
          const source = (
            object.body as ReadableStream<Uint8Array>
          ).getReader();
          let released = false;
          const releaseSource = (): void => {
            if (released) return;
            released = true;
            try {
              source.releaseLock();
            } catch {
              // A pending source operation can retain the reader briefly.
            }
          };
          const body = new ReadableStream<Uint8Array>(
            {
              async pull(controller) {
                pulls.set(key, (pulls.get(key) ?? 0) + 1);
                try {
                  const chunk = await source.read();
                  if (chunk.done) {
                    releaseSource();
                    controller.close();
                  } else {
                    controller.enqueue(chunk.value);
                  }
                } catch (error: unknown) {
                  releaseSource();
                  controller.error(error);
                }
              },
              async cancel(reason) {
                try {
                  await source.cancel(reason);
                } finally {
                  releaseSource();
                }
              },
            },
            // A zero high-water mark makes every recorded pull evidence of an
            // actual downstream read rather than eager stream construction.
            { highWaterMark: 0 },
          );
          return new Proxy(object, {
            get(bodyTarget, bodyProperty) {
              if (bodyProperty === "body") return body;
              const value = Reflect.get(bodyTarget, bodyProperty, bodyTarget);
              return typeof value === "function"
                ? value.bind(bodyTarget)
                : value;
            },
          });
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return {
    bucket: proxied,
    getCount: (key: string) => gets.get(key) ?? 0,
    pullCount: (key: string) => pulls.get(key) ?? 0,
  };
}

function bucketThatTracksStreamCancellation(
  bucket: R2Bucket,
  expectedCancellations: number,
): {
  bucket: R2Bucket;
  cancelled: Promise<void>;
  cancelCount: () => number;
} {
  let count = 0;
  let signalCancelled = (): void => {};
  const cancelled = new Promise<void>((resolve) => {
    signalCancelled = resolve;
  });
  const proxied = new Proxy(bucket, {
    get(target, property) {
      if (property === "get") {
        return async (
          key: string,
          options?: R2GetOptions,
        ): Promise<R2ObjectBody | R2Object | null> => {
          const object = await target.get(key, options);
          if (object === null || !("body" in object)) return object;
          const source = (
            object.body as ReadableStream<Uint8Array>
          ).getReader();
          const body = new ReadableStream<Uint8Array>({
            async pull(controller) {
              const chunk = await source.read();
              if (chunk.done) controller.close();
              else controller.enqueue(chunk.value);
            },
            async cancel(reason) {
              count += 1;
              if (count >= expectedCancellations) signalCancelled();
              await source.cancel(reason);
              source.releaseLock();
            },
          });
          return new Proxy(object, {
            get(bodyTarget, bodyProperty) {
              if (bodyProperty === "body") return body;
              const value = Reflect.get(bodyTarget, bodyProperty, bodyTarget);
              return typeof value === "function"
                ? value.bind(bodyTarget)
                : value;
            },
          });
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { bucket: proxied, cancelled, cancelCount: () => count };
}

function bucketThatFailsBodyMidStream(
  bucket: R2Bucket,
  failingKey: string,
): {
  bucket: R2Bucket;
  failureCount: () => number;
  cancelCount: (key: string) => number;
} {
  let failures = 0;
  const cancellations = new Map<string, number>();
  const proxied = new Proxy(bucket, {
    get(target, property) {
      if (property === "get") {
        return async (
          key: string,
          options?: R2GetOptions,
        ): Promise<R2ObjectBody | R2Object | null> => {
          const object = await target.get(key, options);
          if (object === null || !("body" in object)) return object;
          const source = (
            object.body as ReadableStream<Uint8Array>
          ).getReader();
          let sourceFinished = false;
          let emittedPrefix = false;
          const releaseSource = (): void => {
            try {
              source.releaseLock();
            } catch {
              // An in-flight read or cancellation can retain the lock briefly.
            }
          };
          const cancelSource = async (reason: unknown): Promise<void> => {
            if (sourceFinished) return;
            sourceFinished = true;
            cancellations.set(key, (cancellations.get(key) ?? 0) + 1);
            try {
              await source.cancel(reason);
            } finally {
              releaseSource();
            }
          };
          const body = new ReadableStream<Uint8Array>(
            {
              async pull(controller) {
                if (key === failingKey && emittedPrefix) {
                  const error = new Error(
                    "injected lookup bundle R2 body failure",
                  );
                  failures += 1;
                  await cancelSource(error);
                  controller.error(error);
                  return;
                }
                const chunk = await source.read();
                if (chunk.done) {
                  sourceFinished = true;
                  releaseSource();
                  controller.close();
                  return;
                }
                if (key === failingKey) {
                  if (chunk.value.byteLength === 0) return;
                  const prefixLength = Math.max(
                    1,
                    Math.floor(chunk.value.byteLength / 2),
                  );
                  emittedPrefix = true;
                  controller.enqueue(chunk.value.subarray(0, prefixLength));
                  return;
                }
                controller.enqueue(chunk.value);
              },
              async cancel(reason) {
                await cancelSource(reason);
              },
            },
            { highWaterMark: 0 },
          );
          return new Proxy(object, {
            get(bodyTarget, bodyProperty) {
              if (bodyProperty === "body") return body;
              const value = Reflect.get(bodyTarget, bodyProperty, bodyTarget);
              return typeof value === "function"
                ? value.bind(bodyTarget)
                : value;
            },
          });
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return {
    bucket: proxied,
    failureCount: () => failures,
    cancelCount: (key: string) => cancellations.get(key) ?? 0,
  };
}

function bucketThatFailsFirstGet(bucket: R2Bucket): R2Bucket {
  let failed = false;
  return new Proxy(bucket, {
    get(target, property) {
      if (property === "get") {
        return async (key: string): Promise<R2ObjectBody | null> => {
          if (!failed) {
            failed = true;
            throw new Error("injected R2 readback failure");
          }
          return target.get(key);
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function bucketThatPausesFirstGetAfterRead(bucket: R2Bucket): {
  bucket: R2Bucket;
  entered: Promise<void>;
  release: () => void;
} {
  let signalEntered = (): void => {};
  let signalRelease = (): void => {};
  let paused = false;
  const entered = new Promise<void>((resolve) => {
    signalEntered = resolve;
  });
  const released = new Promise<void>((resolve) => {
    signalRelease = resolve;
  });
  const proxied = new Proxy(bucket, {
    get(target, property) {
      if (property === "get") {
        return async (key: string): Promise<R2ObjectBody | null> => {
          const object = await target.get(key);
          if (!paused) {
            paused = true;
            signalEntered();
            await released;
          }
          return object;
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { bucket: proxied, entered, release: signalRelease };
}

function bucketThatPausesGetAfterReadForKey(
  bucket: R2Bucket,
  targetKey: string,
): {
  bucket: R2Bucket;
  entered: Promise<void>;
  release: () => void;
  matchCount: () => number;
} {
  let signalEntered = (): void => {};
  let signalRelease = (): void => {};
  let matches = 0;
  const entered = new Promise<void>((resolve) => {
    signalEntered = resolve;
  });
  const released = new Promise<void>((resolve) => {
    signalRelease = resolve;
  });
  const proxied = new Proxy(bucket, {
    get(target, property) {
      if (property === "get") {
        return async (
          key: string,
          options?: R2GetOptions,
        ): Promise<R2ObjectBody | R2Object | null> => {
          const object = await target.get(key, options);
          if (key === targetKey) {
            matches += 1;
            if (matches === 1) {
              signalEntered();
              await released;
            }
          }
          return object;
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return {
    bucket: proxied,
    entered,
    release: signalRelease,
    matchCount: () => matches,
  };
}

function bucketThatPausesFirstDeleteBeforeMutation(bucket: R2Bucket): {
  bucket: R2Bucket;
  entered: Promise<void>;
  release: () => void;
} {
  let signalEntered = (): void => {};
  let signalRelease = (): void => {};
  let paused = false;
  const entered = new Promise<void>((resolve) => {
    signalEntered = resolve;
  });
  const released = new Promise<void>((resolve) => {
    signalRelease = resolve;
  });
  const proxied = new Proxy(bucket, {
    get(target, property) {
      if (property === "delete") {
        return async (keys: string | string[]): Promise<void> => {
          if (!paused) {
            paused = true;
            signalEntered();
            await released;
          }
          return target.delete(keys);
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { bucket: proxied, entered, release: signalRelease };
}

function controlledRequestBody(bytes: Uint8Array): {
  stream: ReadableStream<Uint8Array>;
  entered: Promise<void>;
  release: () => void;
} {
  let signalEntered = (): void => {};
  let signalRelease = (): void => {};
  let started = false;
  const entered = new Promise<void>((resolve) => {
    signalEntered = resolve;
  });
  const released = new Promise<void>((resolve) => {
    signalRelease = resolve;
  });
  const stream = new ReadableStream<Uint8Array>({
    async pull(controller) {
      if (started) return;
      started = true;
      signalEntered();
      await released;
      controller.enqueue(bytes);
      controller.close();
    },
  });
  return { stream, entered, release: signalRelease };
}

async function readResponseUntilStreamFailure(response: Response): Promise<{
  receivedBytes: number;
  error: unknown;
}> {
  if (response.body === null)
    throw new Error("expected a streaming response body");
  const reader = response.body.getReader();
  let receivedBytes = 0;
  try {
    for (;;) {
      let chunk: ReadableStreamReadResult<Uint8Array>;
      try {
        chunk = await reader.read();
      } catch (error: unknown) {
        return { receivedBytes, error };
      }
      if (chunk.done) {
        throw new Error("injected R2 failure produced a complete bundle");
      }
      receivedBytes += chunk.value.byteLength;
    }
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // A response error can retain the reader lock until propagation settles.
    }
  }
}

function bucketThatBlocksFirstPut(bucket: R2Bucket): {
  bucket: R2Bucket;
  entered: Promise<void>;
  release: () => void;
  listCalls: () => number;
} {
  let blocked = false;
  let listCalls = 0;
  let signalEntered = (): void => {};
  let signalRelease = (): void => {};
  const entered = new Promise<void>((resolve) => {
    signalEntered = resolve;
  });
  const released = new Promise<void>((resolve) => {
    signalRelease = resolve;
  });
  const proxied = new Proxy(bucket, {
    get(target, property) {
      if (property === "put") {
        return async (
          key: string,
          value:
            | ReadableStream
            | ArrayBuffer
            | ArrayBufferView
            | string
            | null
            | Blob,
          options?: R2PutOptions,
        ) => {
          if (!blocked) {
            blocked = true;
            signalEntered();
            await released;
          }
          return target.put(key, value, options);
        };
      }
      if (property === "list") {
        return async (options?: R2ListOptions) => {
          listCalls += 1;
          return target.list(options);
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return {
    bucket: proxied,
    entered,
    release: signalRelease,
    listCalls: () => listCalls,
  };
}

function bucketThatGatesPutsAndFailsFirstDelete(
  bucket: R2Bucket,
  putCount: 1 | 2,
): {
  bucket: R2Bucket;
  entered: readonly Promise<void>[];
  release: readonly (() => void)[];
} {
  const enteredSignals: Array<() => void> = [];
  const releaseSignals: Array<() => void> = [];
  const entered = Array.from(
    { length: putCount },
    () => new Promise<void>((resolve) => enteredSignals.push(resolve)),
  );
  const released = Array.from(
    { length: putCount },
    () => new Promise<void>((resolve) => releaseSignals.push(resolve)),
  );
  let putIndex = 0;
  let deleteFailed = false;
  const proxied = new Proxy(bucket, {
    get(target, property) {
      if (property === "put") {
        return async (
          key: string,
          value:
            | ReadableStream
            | ArrayBuffer
            | ArrayBufferView
            | string
            | null
            | Blob,
          options?: R2PutOptions,
        ) => {
          const index = putIndex;
          putIndex += 1;
          if (index < putCount) {
            enteredSignals[index]?.();
            await released[index];
          }
          return target.put(key, value, options);
        };
      }
      if (property === "delete") {
        return async (keys: string | string[]): Promise<void> => {
          if (!deleteFailed) {
            deleteFailed = true;
            throw new Error("injected orphan cleanup failure");
          }
          return target.delete(keys);
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
  return { bucket: proxied, entered, release: releaseSignals };
}

function bucketThatFailsList(bucket: R2Bucket): R2Bucket {
  return new Proxy(bucket, {
    get(target, property) {
      if (property === "list") {
        return async (): Promise<never> => {
          throw new Error("injected R2 list failure");
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function bucketThatReturnsWrongPrefixFor(
  bucket: R2Bucket,
  expectedPrefix: string,
  wrongKey: string,
): R2Bucket {
  return new Proxy(bucket, {
    get(target, property) {
      if (property === "list") {
        return (options?: R2ListOptions): Promise<R2Objects> => {
          if (options?.prefix === expectedPrefix) {
            return target.list({ prefix: wrongKey, limit: 1, include: [] });
          }
          return target.list(options);
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

async function metadataUsage(): Promise<number> {
  const row = await env.DB.prepare(
    "SELECT used_metadata_units FROM tenants WHERE id = ?",
  )
    .bind(TENANT)
    .first<{ used_metadata_units: number }>();
  if (row === null) throw new Error("seed tenant is missing");
  return row.used_metadata_units;
}

async function activeWriteLeaseCount(): Promise<number> {
  const row = await env.DB.prepare(
    `SELECT count(*) AS count FROM repository_write_leases WHERE expires_at > unixepoch()`,
  ).first<{ count: number }>();
  return row?.count ?? 0;
}

async function explainPlan(
  query: string,
  ...bindings: unknown[]
): Promise<string> {
  const plan = await env.DB.prepare(`EXPLAIN QUERY PLAN ${query}`)
    .bind(...bindings)
    .all<{ detail: string }>();
  return plan.results.map((row) => row.detail).join("\n");
}

function manifestInsert(
  manifest: EncryptedRemoteCacheManifestV2,
  bodyJson: string,
  trustEpoch: number,
  trustBodySha256: string,
): D1PreparedStatement {
  return env.DB.prepare(
    `INSERT INTO manifests(
       tenant_id, repository_id, request_key, record_id, body_sha256, body_json,
       state, producer_id, key_id, stdout_digest, stdout_size_bytes,
       stderr_digest, stderr_size_bytes, created_at, expires_at,
       trust_epoch, trust_body_sha256
     ) VALUES (?, ?, ?, ?, ?, ?, 'ready', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?)`,
  ).bind(
    TENANT,
    REPOSITORY,
    manifest.request_key,
    manifest.record_id,
    "a".repeat(64),
    bodyJson,
    manifest.producer_id,
    manifest.signature.key_id,
    manifest.stdout.ciphertext_digest,
    manifest.stdout.ciphertext_size_bytes,
    manifest.stderr.ciphertext_digest,
    manifest.stderr.ciphertext_size_bytes,
    manifest.created_at_unix_seconds,
    manifest.expires_at_unix_seconds,
    trustEpoch,
    trustBodySha256,
  );
}

async function registerProducer(
  publicKeyHex: string,
  generationId = GENERATION,
): Promise<Response> {
  return call(
    `/v1/repositories/${REPOSITORY}/producers/key-1`,
    jsonRequest(
      { producer_id: "producer-1", public_key_hex: publicKeyHex },
      BEARER,
      "PUT",
      generationId,
    ),
  );
}

async function generateSigningKeys(): Promise<{
  privateKey: CryptoKey;
  publicKeyHex: string;
}> {
  const pair = await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ]);
  if (!("privateKey" in pair))
    throw new Error("Ed25519 key generation did not return a key pair");
  const rawPublicKey = await crypto.subtle.exportKey("raw", pair.publicKey);
  if (!(rawPublicKey instanceof ArrayBuffer))
    throw new Error("Ed25519 public key was not raw bytes");
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

async function signManifest(
  manifest: RemoteCacheManifest | EncryptedRemoteCacheManifestV2,
  privateKey: CryptoKey,
): Promise<void> {
  if (manifest.schema_version === 2) {
    await signEncryptedManifestV2(manifest, privateKey);
    return;
  }
  manifest.signature.signature = Array.from(
    new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        privateKey,
        canonicalManifestBytes(manifest),
      ),
    ),
  );
}

function rustTrustCanonicalVector(): TrustBundleV1 {
  return {
    schema_version: 1,
    root_key_id: "root-vector-1",
    tenant_id: "tenant-vector",
    repository_id: "repo-vector",
    generation_id: "0123456789abcdef0123456789abcdef",
    endpoint_origin: "https://cache.vector.invalid",
    epoch: 42,
    issued_at_unix_seconds: 1_700_000_000,
    expires_at_unix_seconds: 1_700_000_300,
    active_producer_keys: [
      {
        key_id: "key-vector-1",
        producer_id: "producer-vector",
        public_key: Array.from(
          hexToBytes(
            "d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a",
          ),
        ),
      },
    ],
    revoked_key_ids: ["key-old"],
    revoked_record_ids: ["record-old"],
    allowed_policy_digests: ["11".repeat(32)],
    allowed_execution_profile_digests: ["22".repeat(32)],
    allowed_platform_digests: ["33".repeat(32)],
    allowed_image_digests: ["44".repeat(32)],
    signature: Array.from({ length: 64 }, () => 0),
  };
}

function rustManifestV2CanonicalVector(): EncryptedRemoteCacheManifestV2 {
  return {
    schema_version: 2,
    record_id: "record-vector-2",
    tenant_id: "tenant-vector",
    repository_id: "repo-vector",
    generation_id: "0123456789abcdef0123456789abcdef",
    request_key: "01".repeat(32),
    policy_digest: "11".repeat(32),
    classifier_digest: "12".repeat(32),
    execution_profile_digest: "22".repeat(32),
    platform_digest: "33".repeat(32),
    image_digest: "44".repeat(32),
    result_status: "success",
    duration_micros: 987_654,
    proof_schema_version: 1,
    producer_version: "again-vector-0.1.0",
    local_proof_digest: "55".repeat(32),
    privacy: {
      classification: "confidential",
      shareability: "repository",
      secret_tainted: false,
    },
    repository_encryption_key_id: "repository-key-vector",
    stdout: {
      ciphertext_digest: "66".repeat(32),
      ciphertext_size_bytes: 48,
      nonce: Array.from({ length: 24 }, () => 0x77),
    },
    stderr: {
      ciphertext_digest: "88".repeat(32),
      ciphertext_size_bytes: 16,
      nonce: Array.from({ length: 24 }, () => 0x99),
    },
    producer_id: "producer-vector",
    created_at_unix_seconds: 1_700_000_000,
    expires_at_unix_seconds: 1_700_003_600,
    signature: {
      schema_version: 1,
      algorithm: "ed25519",
      key_id: "key-vector-1",
      signature: Array.from({ length: 64 }, () => 0),
    },
  };
}

async function prepareEncryptedManifestV2Fixture(
  generationId = GENERATION,
): Promise<{
  manifest: EncryptedRemoteCacheManifestV2;
  privateKey: CryptoKey;
  trustBundle: TrustBundleV1;
  trustPrivateKey: CryptoKey;
}> {
  return prepareEncryptedManifestV2FixtureAt({
    tenantId: TENANT,
    repositoryId: REPOSITORY,
    generationId,
    bearer: BEARER,
  });
}

async function prepareEncryptedManifestV2FixtureAt(options: {
  tenantId: string;
  repositoryId: string;
  generationId: string;
  bearer: string;
}): Promise<{
  manifest: EncryptedRemoteCacheManifestV2;
  privateKey: CryptoKey;
  trustBundle: TrustBundleV1;
  trustPrivateKey: CryptoKey;
}> {
  const keys = await generateSigningKeys();
  expect(
    (
      await call(
        `/v1/repositories/${options.repositoryId}/producers/key-1`,
        jsonRequest(
          { producer_id: "producer-1", public_key_hex: keys.publicKeyHex },
          options.bearer,
          "PUT",
          options.generationId,
        ),
      )
    ).status,
  ).toBe(201);
  const stdoutCiphertext = Uint8Array.from(
    { length: 48 },
    (_, index) => (index * 17) & 0xff,
  );
  const stderrCiphertext = Uint8Array.from(
    { length: 16 },
    (_, index) => (index * 29) & 0xff,
  );
  const stdoutDigest = bytesToHex(blake3(stdoutCiphertext));
  const stderrDigest = bytesToHex(blake3(stderrCiphertext));
  expect(
    (
      await putBlobAtRepository(
        options.repositoryId,
        stdoutCiphertext,
        stdoutDigest,
        options.generationId,
        options.bearer,
      )
    ).status,
  ).toBe(201);
  expect(
    (
      await putBlobAtRepository(
        options.repositoryId,
        stderrCiphertext,
        stderrDigest,
        options.generationId,
        options.bearer,
      )
    ).status,
  ).toBe(201);
  const now = Math.floor(Date.now() / 1000);
  const manifest: EncryptedRemoteCacheManifestV2 = {
    schema_version: 2,
    record_id: "encrypted-record-1",
    tenant_id: options.tenantId,
    repository_id: options.repositoryId,
    generation_id: options.generationId,
    request_key: "a".repeat(64),
    policy_digest: "1".repeat(64),
    classifier_digest: "2".repeat(64),
    execution_profile_digest: "3".repeat(64),
    platform_digest: "4".repeat(64),
    image_digest: "5".repeat(64),
    result_status: "success",
    duration_micros: 12_345,
    proof_schema_version: 1,
    producer_version: "again-producer-0.1.0",
    local_proof_digest: "6".repeat(64),
    privacy: {
      classification: "confidential",
      shareability: "repository",
      secret_tainted: false,
    },
    repository_encryption_key_id: "repository-key-1",
    stdout: {
      ciphertext_digest: stdoutDigest,
      ciphertext_size_bytes: stdoutCiphertext.byteLength,
      nonce: Array.from({ length: 24 }, () => 1),
    },
    stderr: {
      ciphertext_digest: stderrDigest,
      ciphertext_size_bytes: stderrCiphertext.byteLength,
      nonce: Array.from({ length: 24 }, () => 2),
    },
    producer_id: "producer-1",
    created_at_unix_seconds: now - 1,
    expires_at_unix_seconds: now + 3600,
    signature: {
      schema_version: 1,
      algorithm: "ed25519",
      key_id: "key-1",
      signature: Array.from({ length: 64 }, () => 0),
    },
  };
  await signEncryptedManifestV2(manifest, keys.privateKey);
  const trust = await prepareTrustBundleFixture({
    producerPublicKeyHex: keys.publicKeyHex,
    allowedPolicyDigest: manifest.policy_digest,
    allowedExecutionProfileDigest: manifest.execution_profile_digest,
    allowedPlatformDigest: manifest.platform_digest,
    allowedImageDigest: manifest.image_digest,
    generationId: options.generationId,
    tenantId: options.tenantId,
    repositoryId: options.repositoryId,
  });
  expect(
    (
      await putTrustBundleAtRepository(
        options.repositoryId,
        trust.bundle,
        options.generationId,
        options.bearer,
      )
    ).status,
  ).toBe(201);
  return {
    manifest,
    privateKey: keys.privateKey,
    trustBundle: trust.bundle,
    trustPrivateKey: trust.privateKey,
  };
}

async function signEncryptedManifestV2(
  manifest: EncryptedRemoteCacheManifestV2,
  privateKey: CryptoKey,
): Promise<void> {
  manifest.signature.signature = Array.from(
    new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        privateKey,
        canonicalEncryptedManifestV2Bytes(manifest),
      ),
    ),
  );
}

async function putEncryptedManifestV2(
  manifest: EncryptedRemoteCacheManifestV2,
  generationId = GENERATION,
): Promise<Response> {
  return call(
    `/v1/repositories/${REPOSITORY}/manifests/${manifest.request_key}`,
    jsonRequest(manifest, BEARER, "PUT", generationId),
  );
}

function copyEncryptedManifestV2(
  manifest: EncryptedRemoteCacheManifestV2,
): EncryptedRemoteCacheManifestV2 {
  return structuredClone(manifest);
}

async function prepareTrustBundleFixture(
  options: {
    producerPublicKeyHex?: string;
    allowedPolicyDigest?: string;
    allowedExecutionProfileDigest?: string;
    allowedPlatformDigest?: string;
    allowedImageDigest?: string;
    generationId?: string;
    tenantId?: string;
    repositoryId?: string;
  } = {},
): Promise<{
  bundle: TrustBundleV1;
  privateKey: CryptoKey;
}> {
  const tenantId = options.tenantId ?? TENANT;
  const repositoryId = options.repositoryId ?? REPOSITORY;
  const root = await generateSigningKeys();
  await env.DB.prepare(
    `INSERT INTO trust_root_keys(
       tenant_id, repository_id, root_key_id, public_key_hex, created_at
     ) VALUES (?, ?, 'root-key-1', ?, ?)`,
  )
    .bind(
      tenantId,
      repositoryId,
      root.publicKeyHex,
      Math.floor(Date.now() / 1000),
    )
    .run();
  const producerPublicKeyHex =
    options.producerPublicKeyHex ?? (await generateSigningKeys()).publicKeyHex;
  const now = Math.floor(Date.now() / 1000);
  const bundle: TrustBundleV1 = {
    schema_version: 1,
    root_key_id: "root-key-1",
    tenant_id: tenantId,
    repository_id: repositoryId,
    generation_id: options.generationId ?? GENERATION,
    endpoint_origin: ORIGIN,
    epoch: 1,
    issued_at_unix_seconds: now - 1,
    expires_at_unix_seconds: now + 299,
    active_producer_keys: [
      {
        key_id: "key-1",
        producer_id: "producer-1",
        public_key: Array.from(hexToBytes(producerPublicKeyHex)),
      },
    ],
    revoked_key_ids: [],
    revoked_record_ids: [],
    allowed_policy_digests: [options.allowedPolicyDigest ?? "1".repeat(64)],
    allowed_execution_profile_digests: [
      options.allowedExecutionProfileDigest ?? "2".repeat(64),
    ],
    allowed_platform_digests: [options.allowedPlatformDigest ?? "3".repeat(64)],
    allowed_image_digests: [options.allowedImageDigest ?? "4".repeat(64)],
    signature: Array.from({ length: 64 }, () => 0),
  };
  await signTrustBundle(bundle, root.privateKey);
  return { bundle, privateKey: root.privateKey };
}

async function signTrustBundle(
  bundle: TrustBundleV1,
  privateKey: CryptoKey,
): Promise<void> {
  bundle.signature = Array.from(
    new Uint8Array(
      await crypto.subtle.sign(
        "Ed25519",
        privateKey,
        canonicalTrustBundleBytes(bundle),
      ),
    ),
  );
}

async function putTrustBundle(
  bundle: TrustBundleV1,
  generationId = GENERATION,
): Promise<Response> {
  return putTrustBundleAtRepository(REPOSITORY, bundle, generationId);
}

async function putTrustBundleAtRepository(
  repositoryId: string,
  bundle: TrustBundleV1,
  generationId = GENERATION,
  bearer = BEARER,
): Promise<Response> {
  return call(
    `/v1/repositories/${repositoryId}/trust-bundles/latest`,
    jsonRequest(bundle, bearer, "PUT", generationId),
  );
}

async function putTrustBundleUsingEnv(
  runtimeEnv: Env,
  bundle: TrustBundleV1,
  generationId = GENERATION,
): Promise<Response> {
  return callUsingEnv(
    runtimeEnv,
    `/v1/repositories/${REPOSITORY}/trust-bundles/latest`,
    jsonRequest(bundle, BEARER, "PUT", generationId),
  );
}

function copyTrustBundle(bundle: TrustBundleV1): TrustBundleV1 {
  return structuredClone(bundle);
}

function concatenateBytes(...values: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(
    values.reduce((length, value) => length + value.byteLength, 0),
  );
  let offset = 0;
  for (const value of values) {
    output.set(value, offset);
    offset += value.byteLength;
  }
  return output;
}

function littleEndianInteger(value: Uint8Array): bigint {
  let result = 0n;
  for (let index = value.byteLength - 1; index >= 0; index -= 1) {
    result = (result << 8n) | BigInt(value[index] as number);
  }
  return result;
}

function littleEndianBytes(value: bigint, length: number): Uint8Array {
  const output = new Uint8Array(length);
  let remaining = value;
  for (let index = 0; index < length; index += 1) {
    output[index] = Number(remaining & 0xffn);
    remaining >>= 8n;
  }
  return output;
}

async function putManifest(
  manifest: RemoteCacheManifest | EncryptedRemoteCacheManifestV2,
): Promise<Response> {
  return putManifestUsingEnv(env, manifest);
}

async function putManifestUsingEnv(
  runtimeEnv: Env,
  manifest: RemoteCacheManifest | EncryptedRemoteCacheManifestV2,
): Promise<Response> {
  return callUsingEnv(
    runtimeEnv,
    `/v1/repositories/${REPOSITORY}/manifests/${manifest.request_key}`,
    jsonRequest(manifest, BEARER, "PUT"),
  );
}

async function waitUntilUnixSecondAfter(value: number): Promise<void> {
  while (Math.floor(Date.now() / 1000) <= value) {
    await new Promise<void>((resolve) => setTimeout(resolve, 25));
  }
}

function copyManifest<
  T extends RemoteCacheManifest | EncryptedRemoteCacheManifestV2,
>(manifest: T): T {
  return structuredClone(manifest);
}

async function runScheduled(): Promise<void> {
  return runScheduledUsingEnv(env, "*/15 * * * *");
}

async function runReconciliation(): Promise<void> {
  return runReconciliationUsingEnv(env);
}

async function runReconciliationUsingEnv(runtimeEnv: Env): Promise<void> {
  return runScheduledUsingEnv(runtimeEnv, "7 * * * *");
}

async function runScheduledUsingEnv(
  runtimeEnv: Env,
  cron: string,
): Promise<void> {
  const ctx = createExecutionContext();
  worker.scheduled(
    {
      scheduledTime: Date.now(),
      cron,
      noRetry(): void {},
    },
    runtimeEnv,
    ctx,
  );
  await waitOnExecutionContext(ctx);
}

async function ageRepositoryDeletionConfirmation(
  tenantId: string,
  repositoryId: string,
): Promise<void> {
  const now = Math.floor(Date.now() / 1000);
  await env.DB.prepare(
    `UPDATE repository_deletions
        SET requested_at = ?, last_empty_at = ?, next_attempt_at = 0,
            lease_id = NULL, lease_until = NULL
      WHERE tenant_id = ? AND repository_id = ? AND empty_confirmations = 1`,
  )
    .bind(now - 120, now - 61, tenantId, repositoryId)
    .run();
}

async function finishRepositoryDeletion(runtimeEnv: Env = env): Promise<void> {
  for (let iteration = 0; iteration < 30; iteration += 1) {
    const repository = await env.DB.prepare(
      "SELECT id FROM repositories WHERE tenant_id = ? AND id = ?",
    )
      .bind(TENANT, REPOSITORY)
      .first<{ id: string }>();
    if (repository === null) return;
    const deletion = await env.DB.prepare(
      `SELECT phase, empty_confirmations FROM repository_deletions
        WHERE tenant_id = ? AND repository_id = ?`,
    )
      .bind(TENANT, REPOSITORY)
      .first<{ phase: string; empty_confirmations: number }>();
    if (deletion === null)
      throw new Error(
        "repository deletion job disappeared before finalization",
      );
    if (deletion.phase === "r2" && deletion.empty_confirmations === 1) {
      await ageRepositoryDeletionConfirmation(TENANT, REPOSITORY);
    } else {
      await env.DB.prepare(
        `UPDATE repository_deletions
            SET next_attempt_at = 0, lease_id = NULL, lease_until = NULL
          WHERE tenant_id = ? AND repository_id = ?`,
      )
        .bind(TENANT, REPOSITORY)
        .run();
    }
    await runScheduledUsingEnv(runtimeEnv, "*/15 * * * *");
  }
  throw new Error("repository deletion did not finish within the test bound");
}

function bucketThatPartiallyFailsDelete(bucket: R2Bucket): R2Bucket {
  let injected = false;
  return new Proxy(bucket, {
    get(target, property) {
      if (property === "delete") {
        return async (keys: string | string[]): Promise<void> => {
          const values = typeof keys === "string" ? [keys] : keys;
          if (!injected && values.length > 1) {
            injected = true;
            const first = values[0];
            if (first === undefined)
              throw new Error("injected delete page was empty");
            await target.delete(first);
            throw new Error("injected partial R2 delete failure");
          }
          await target.delete(keys);
        };
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}

function bucketWithListPageLimit(bucket: R2Bucket, limit: number): R2Bucket {
  return new Proxy(bucket, {
    get(target, property) {
      if (property === "list") {
        return async (options: R2ListOptions = {}): Promise<R2Objects> =>
          target.list({
            ...options,
            limit: Math.min(options.limit ?? limit, limit),
          });
      }
      const value = Reflect.get(target, property, target);
      return typeof value === "function" ? value.bind(target) : value;
    },
  });
}
