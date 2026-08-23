import { blake3 } from "@noble/hashes/blake3.js";

import { auditStatement } from "./audit";
import { authenticate, type AuthContext, type Permission } from "./auth";
import {
  canonicalManifestJson,
  parseManifest,
  publicKeyHex,
  verifyManifestSignature,
  type RemoteCacheManifest,
} from "./manifest";
import {
  ApiError,
  MAX_BLOB_SIZE,
  MAX_JSON_SIZE,
  MAX_SMALL_JSON_SIZE,
  assertExactKeys,
  bytesToHex,
  emptyResponse,
  errorResponse,
  jsonResponse,
  nowSeconds,
  readBytesBounded,
  readJsonObject,
  requireDigest,
  requireProtocolIdentifier,
  requireRouteIdentifier,
  requireString,
  sha256Hex,
} from "./util";

const RECONCILE_BATCH_SIZE = 64;
const PENDING_CANCEL_AFTER_SECONDS = 60 * 60;
const PENDING_DELETE_GRACE_SECONDS = 60 * 60;

interface RepositoryRow {
  id: string;
}

interface ProducerKeyRow {
  producer_id: string;
  public_key_hex: string;
  revoked_at: number | null;
}

interface BlobRow {
  size_bytes: number;
  state: "pending" | "ready" | "quarantined" | "deleting";
  updated_at: number;
  reconcile_attempts: number;
  next_reconcile_at: number;
  delete_not_before: number | null;
}

interface ReconcileBlobRow extends BlobRow {
  tenant_id: string;
  repository_id: string;
  digest: string;
}

interface ManifestRow {
  request_key: string;
  record_id: string;
  body_sha256: string;
  body_json: string;
  state: "ready" | "quarantined" | "deleted";
  producer_id: string;
  key_id: string;
  created_at: number;
  expires_at: number;
  key_revoked_at: number | null;
}

interface AuditRow {
  id: number;
  repository_id: string | null;
  actor: string;
  action: string;
  target_type: string;
  target_id_sha256: string;
  outcome: string;
  details_json: string;
  created_at: number;
}

interface StatsRow {
  ready_blobs: number;
  blob_bytes: number;
  pending_blobs: number;
  deleting_blobs: number;
  ready_manifests: number;
  quarantined_blobs: number;
  quarantined_manifests: number;
  used_bytes: number;
  quota_bytes: number;
  used_metadata_units: number;
  metadata_quota_units: number;
}

type R2ObjectState = "missing" | "valid" | "invalid";

interface VerifiedR2Object {
  state: R2ObjectState;
  bytes?: Uint8Array;
}

const worker = {
  async fetch(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
    const requestId = crypto.randomUUID();
    try {
      const response = await route(request, env, ctx);
      response.headers.set("x-request-id", requestId);
      return response;
    } catch (error: unknown) {
      if (error instanceof ApiError) return errorResponse(error, requestId);
      if (databaseErrorContains(error, "metadata_quota_exceeded")) {
        return errorResponse(
          new ApiError(413, "metadata_quota_exceeded", "tenant metadata quota would be exceeded"),
          requestId,
        );
      }
      console.error(
        JSON.stringify({
          event: "request_failed",
          request_id: requestId,
          error: error instanceof Error ? error.name : "UnknownError",
        }),
      );
      return errorResponse(
        new ApiError(500, "internal_error", "request could not be completed"),
        requestId,
      );
    }
  },
  scheduled(_controller: ScheduledController, env: Env, ctx: ExecutionContext): void {
    ctx.waitUntil(reconcileBlobs(env));
  },
} satisfies ExportedHandler<Env>;

export default worker;

async function route(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/v1/health") {
    if (request.method !== "GET") throw methodNotAllowed();
    return jsonResponse({ status: "ok", service: "again-cache", schema_version: 1 });
  }

  const segments = url.pathname.split("/").filter((segment) => segment.length > 0);
  if (segments[0] !== "v1" || segments[1] !== "repositories") {
    throw new ApiError(404, "not_found", "resource not found");
  }

  if (segments.length === 2) {
    if (request.method !== "POST") throw methodNotAllowed();
    return createRepository(request, env, ctx);
  }

  const repositoryId = requireRouteIdentifier(segments[2] ?? "", "repository_id");
  if (segments.length === 4 && segments[3] === "audit") {
    if (request.method !== "GET") throw methodNotAllowed();
    return listAudit(request, env, ctx, repositoryId);
  }
  if (segments.length === 4 && segments[3] === "stats") {
    if (request.method !== "GET") throw methodNotAllowed();
    return getStats(request, env, ctx, repositoryId);
  }
  if (segments.length !== 5) throw new ApiError(404, "not_found", "resource not found");

  const resource = segments[3];
  const identifier = segments[4] ?? "";
  if (resource === "blobs") {
    const digest = requireDigest(identifier, "blob_digest");
    if (request.method === "PUT") return putBlob(request, env, ctx, repositoryId, digest);
    if (request.method === "GET" || request.method === "HEAD") {
      return getBlob(request, env, ctx, repositoryId, digest);
    }
    if (request.method === "DELETE") return deleteBlob(request, env, ctx, repositoryId, digest);
    throw methodNotAllowed();
  }
  if (resource === "manifests") {
    const requestKey = requireDigest(identifier, "request_key");
    if (request.method === "PUT") {
      return putManifest(request, env, ctx, repositoryId, requestKey);
    }
    if (request.method === "GET") return getManifest(request, env, ctx, repositoryId, requestKey);
    if (request.method === "DELETE") {
      return deleteManifest(request, env, ctx, repositoryId, requestKey);
    }
    throw methodNotAllowed();
  }
  if (resource === "producers") {
    const keyId = requireRouteIdentifier(identifier, "key_id");
    if (request.method === "PUT") return putProducer(request, env, ctx, repositoryId, keyId);
    if (request.method === "DELETE") {
      return revokeProducer(request, env, ctx, repositoryId, keyId);
    }
    throw methodNotAllowed();
  }
  throw new ApiError(404, "not_found", "resource not found");
}

async function createRepository(request: Request, env: Env, ctx: ExecutionContext): Promise<Response> {
  const auth = await authenticate(request, env, ctx, null, "admin");
  const body = await readJsonObject(request, MAX_SMALL_JSON_SIZE);
  assertExactKeys(body, ["repository_id"], "repository");
  const repositoryId = requireRouteIdentifier(
    requireString(body.repository_id, "repository_id"),
    "repository_id",
  );
  enforceTokenScope(auth, repositoryId);
  const now = nowSeconds();
  const result = await env.DB.prepare(
    `INSERT OR IGNORE INTO repositories(tenant_id, id, created_at)
     VALUES (?, ?, ?)`,
  )
    .bind(auth.tenantId, repositoryId, now)
    .run();
  const audit = await auditStatement(
    env.DB,
    auth,
    repositoryId,
    "repository.create",
    "repository",
    repositoryId,
    result.meta.changes === 0 ? "exists" : "created",
  );
  await audit.run();
  return jsonResponse(
    { repository_id: repositoryId, created: result.meta.changes !== 0 },
    result.meta.changes === 0 ? 200 : 201,
  );
}

async function putProducer(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  keyId: string,
): Promise<Response> {
  const auth = await authenticateForRepository(request, env, ctx, repositoryId, "admin");
  const body = await readJsonObject(request, MAX_SMALL_JSON_SIZE);
  assertExactKeys(body, ["producer_id", "public_key_hex"], "producer_key");
  const producerId = requireProtocolIdentifier(body.producer_id, "producer_id");
  const keyHex = publicKeyHex(body.public_key_hex);
  const existing = await producerKey(env.DB, auth.tenantId, repositoryId, keyId);
  if (existing !== null) {
    if (
      existing.revoked_at === null &&
      existing.producer_id === producerId &&
      existing.public_key_hex === keyHex
    ) {
      return emptyResponse(204);
    }
    await writeAudit(
      env.DB,
      auth,
      repositoryId,
      "producer.register",
      "producer_key",
      keyId,
      "immutable_conflict",
    );
    throw new ApiError(409, "key_binding_conflict", "key id is already bound or revoked");
  }
  const now = nowSeconds();
  const audit = await auditStatement(
    env.DB,
    auth,
    repositoryId,
    "producer.register",
    "producer_key",
    keyId,
    "created",
  );
  await env.DB.batch([
    env.DB.prepare(
      `INSERT INTO producer_keys(
         tenant_id, repository_id, key_id, producer_id, public_key_hex, created_at
       ) VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(auth.tenantId, repositoryId, keyId, producerId, keyHex, now),
    audit,
  ]);
  return emptyResponse(201);
}

async function revokeProducer(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  keyId: string,
): Promise<Response> {
  const auth = await authenticateForRepository(request, env, ctx, repositoryId, "admin");
  const now = nowSeconds();
  const result = await env.DB.prepare(
    `UPDATE producer_keys SET revoked_at = ?
      WHERE tenant_id = ? AND repository_id = ? AND key_id = ? AND revoked_at IS NULL`,
  )
    .bind(now, auth.tenantId, repositoryId, keyId)
    .run();
  if (result.meta.changes === 0) {
    throw new ApiError(404, "not_found", "producer key not found");
  }
  await writeAudit(
    env.DB,
    auth,
    repositoryId,
    "producer.revoke",
    "producer_key",
    keyId,
    "revoked",
  );
  return emptyResponse(204);
}

async function putBlob(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  digest: string,
): Promise<Response> {
  const auth = await authenticateForRepository(request, env, ctx, repositoryId, "write");
  const mediaType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (mediaType !== "application/octet-stream") {
    throw new ApiError(415, "unsupported_media_type", "blob Content-Type must be application/octet-stream");
  }
  const bytes = await readBytesBounded(request, MAX_BLOB_SIZE, true);
  const actualDigest = bytesToHex(blake3(bytes));
  if (actualDigest !== digest) {
    await writeAudit(env.DB, auth, repositoryId, "blob.put", "blob", digest, "digest_mismatch");
    throw new ApiError(422, "digest_mismatch", "blob bytes do not match the requested BLAKE3 digest");
  }

  let row = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
  if (row?.state === "quarantined") {
    throw new ApiError(409, "blob_quarantined", "blob is quarantined");
  }
  if (row?.state === "deleting") {
    throw new ApiError(409, "blob_deleting", "blob deletion is in progress");
  }
  if (row !== null && row.size_bytes !== bytes.byteLength) {
    await quarantineBlob(env.DB, auth, repositoryId, digest, "size_conflict");
    throw new ApiError(409, "blob_conflict", "existing blob metadata conflicts with upload");
  }
  if (row?.state === "ready") {
    const key = blobKey(auth.tenantId, repositoryId, digest);
    const objectState = await r2ObjectState(env.BLOBS, key, digest, bytes.byteLength);
    if (objectState === "valid") return emptyResponse(204, { etag: quotedDigest(digest) });
    if (objectState === "invalid") {
      await quarantineOrFailOnStateChange(env.DB, auth, repositoryId, digest, "r2_integrity_failure");
      throw new ApiError(409, "blob_integrity_failure", "blob failed storage integrity validation");
    }
    const transitionTime = nowSeconds();
    const transitioned = await env.DB.prepare(
      `UPDATE blobs
          SET state = 'pending', updated_at = ?, reconcile_attempts = 0,
              next_reconcile_at = ?, delete_not_before = NULL
        WHERE tenant_id = ? AND repository_id = ? AND digest = ? AND state = 'ready'`,
    )
      .bind(transitionTime, transitionTime + 60, auth.tenantId, repositoryId, digest)
      .run();
    if (transitioned.meta.changes === 0) {
      throw new ApiError(409, "blob_state_changed", "blob state changed during repair");
    }
    row = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
    if (row?.state !== "pending") {
      throw new ApiError(409, "blob_state_changed", "blob state changed during repair");
    }
  }

  if (row === null) {
    try {
      const now = nowSeconds();
      await env.DB.prepare(
        `INSERT INTO blobs(
           tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
           reconcile_attempts, next_reconcile_at, delete_not_before
         ) VALUES (?, ?, ?, ?, 'pending', ?, ?, 0, ?, NULL)`,
      )
        .bind(auth.tenantId, repositoryId, digest, bytes.byteLength, now, now, now + 60)
        .run();
    } catch (error: unknown) {
      const existing = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
      if (
        existing !== null &&
        existing.size_bytes === bytes.byteLength &&
        existing.state === "pending"
      ) {
        // A concurrent writer may have reserved this exact content between our
        // initial read and insert. Quota triggers run before uniqueness checks,
        // so the compatible reservation must win over a misleading quota error.
        row = existing;
      } else if (databaseErrorContains(error, "metadata_quota_exceeded")) {
        throw new ApiError(
          413,
          "metadata_quota_exceeded",
          "tenant metadata quota would be exceeded",
        );
      } else if (databaseErrorContains(error, "quota_exceeded")) {
        throw new ApiError(413, "quota_exceeded", "tenant storage quota would be exceeded");
      } else if (
        existing === null ||
        existing.size_bytes !== bytes.byteLength ||
        existing.state === "quarantined" ||
        existing.state === "deleting"
      ) {
        throw error;
      } else {
        row = existing;
      }
    }
  }

  // A concurrent writer can complete promotion after our initial read. Treat
  // a byte-verified ready object as an idempotent success instead of failing
  // the pending lease transition below.
  if (row?.state === "ready") {
    const key = blobKey(auth.tenantId, repositoryId, digest);
    const state = await r2ObjectState(env.BLOBS, key, digest, bytes.byteLength);
    if (state === "valid") return emptyResponse(204, { etag: quotedDigest(digest) });
    if (state === "invalid") {
      await quarantineOrFailOnStateChange(env.DB, auth, repositoryId, digest, "r2_integrity_failure");
      throw new ApiError(409, "blob_integrity_failure", "blob failed storage integrity validation");
    }
    const transitionTime = nowSeconds();
    const transitioned = await env.DB.prepare(
      `UPDATE blobs
          SET state = 'pending', updated_at = ?, reconcile_attempts = 0,
              next_reconcile_at = ?, delete_not_before = NULL
        WHERE tenant_id = ? AND repository_id = ? AND digest = ? AND state = 'ready'`,
    )
      .bind(transitionTime, transitionTime + 60, auth.tenantId, repositoryId, digest)
      .run();
    if (transitioned.meta.changes === 0) {
      throw new ApiError(409, "blob_state_changed", "blob state changed during repair");
    }
    row = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
  }

  const key = blobKey(auth.tenantId, repositoryId, digest);
  try {
    const leaseTime = nowSeconds();
    const lease = await env.DB.prepare(
      `UPDATE blobs SET updated_at = ?, next_reconcile_at = ?
        WHERE tenant_id = ? AND repository_id = ? AND digest = ? AND state = 'pending'`,
    )
      .bind(leaseTime, leaseTime + 60, auth.tenantId, repositoryId, digest)
      .run();
    if (lease.meta.changes === 0) {
      throw new ApiError(409, "blob_state_changed", "blob state changed before upload");
    }
    await env.BLOBS.put(key, bytes, {
      onlyIf: { etagDoesNotMatch: "*" },
      httpMetadata: { contentType: "application/octet-stream" },
      customMetadata: { blake3: digest, size_bytes: String(bytes.byteLength) },
    });
    // Promotion never trusts PUT success or object metadata alone. Read the
    // retained object back and hash its actual bytes; a transient read failure
    // leaves the durable `pending` reservation for retry/reconciliation.
    const storedState = await r2ObjectState(env.BLOBS, key, digest, bytes.byteLength);
    if (storedState !== "valid") {
      if (storedState === "invalid") {
        await quarantineOrFailOnStateChange(
          env.DB,
          auth,
          repositoryId,
          digest,
          "r2_integrity_failure",
        );
      }
      throw new ApiError(409, "blob_integrity_failure", "blob failed storage integrity validation");
    }
    const now = nowSeconds();
    const promoted = await env.DB.prepare(
      `UPDATE blobs
          SET state = 'ready', updated_at = ?, reconcile_attempts = 0,
              next_reconcile_at = ?, delete_not_before = NULL
        WHERE tenant_id = ? AND repository_id = ? AND digest = ? AND state = 'pending'`,
    )
      .bind(now, now, auth.tenantId, repositoryId, digest)
      .run();
    if (promoted.meta.changes === 0) {
      const current = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
      if (current?.state !== "ready" || current.size_bytes !== bytes.byteLength) {
        throw new ApiError(409, "blob_state_changed", "blob state changed during upload");
      }
    }
    await writeAudit(env.DB, auth, repositoryId, "blob.put", "blob", digest, "ready");
    return emptyResponse(201, { etag: quotedDigest(digest) });
  } catch (error: unknown) {
    // The pending D1 row intentionally survives. It reserves quota and is the
    // durable outbox record that lets retry/reconciliation repair either side
    // of an R2/D1 partial failure without creating unaccounted storage.
    if (error instanceof ApiError) throw error;
    throw new ApiError(503, "blob_storage_unavailable", "blob storage is temporarily unavailable");
  }
}

async function getBlob(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  digest: string,
): Promise<Response> {
  const auth = await authenticateForRepository(request, env, ctx, repositoryId, "read");
  const row = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
  if (row === null || row.state !== "ready") throw new ApiError(404, "not_found", "blob not found");
  const key = blobKey(auth.tenantId, repositoryId, digest);
  const verified = await verifyR2Object(env.BLOBS, key, digest, row.size_bytes);
  if (verified.state !== "valid" || verified.bytes === undefined) {
    await quarantineOrFailOnStateChange(env.DB, auth, repositoryId, digest, "r2_integrity_failure");
    throw new ApiError(409, "blob_integrity_failure", "blob failed storage integrity validation");
  }
  if (request.method === "HEAD") {
    return emptyResponse(200, blobHeaders(digest, row.size_bytes));
  }
  return new Response(verified.bytes, {
    status: 200,
    headers: blobHeaders(digest, row.size_bytes),
  });
}

async function deleteBlob(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  digest: string,
): Promise<Response> {
  const auth = await authenticateForRepository(request, env, ctx, repositoryId, "delete");
  let row = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
  if (row === null) throw new ApiError(404, "not_found", "blob not found");
  if (row.state === "pending") {
    if (!auth.permissions.has("admin")) {
      throw new ApiError(409, "blob_pending", "pending upload cancellation requires admin permission");
    }
    const now = nowSeconds();
    const cutoff = now - PENDING_CANCEL_AFTER_SECONDS;
    const deleteAt = now + PENDING_DELETE_GRACE_SECONDS;
    const transition = await env.DB.prepare(
      `UPDATE blobs
          SET state = 'deleting', updated_at = ?, next_reconcile_at = ?, delete_not_before = ?
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?
          AND state = 'pending' AND updated_at <= ?`,
    )
      .bind(now, deleteAt, deleteAt, auth.tenantId, repositoryId, digest, cutoff)
      .run();
    if (transition.meta.changes === 0) {
      throw new ApiError(409, "blob_pending", "pending upload is still inside its cancellation lease");
    }
    await env.BLOBS.delete(blobKey(auth.tenantId, repositoryId, digest));
    await writeAudit(env.DB, auth, repositoryId, "blob.cancel", "blob", digest, "deleting_after_grace");
    return emptyResponse(202, { "retry-after": String(PENDING_DELETE_GRACE_SECONDS) });
  }
  if (row.state === "quarantined" && !auth.permissions.has("admin")) {
    throw new ApiError(403, "admin_required", "quarantine remediation requires admin permission");
  }
  if (row.state !== "deleting") {
    const transitionTime = nowSeconds();
    const transition = await env.DB.prepare(
      `UPDATE blobs
          SET state = 'deleting', updated_at = ?, next_reconcile_at = ?, delete_not_before = ?
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?
          AND state IN ('ready', 'quarantined')
          AND NOT EXISTS (
            SELECT 1 FROM manifests
             WHERE tenant_id = ? AND repository_id = ? AND state != 'deleted'
               AND (stdout_digest = ? OR stderr_digest = ?)
          )`,
    )
      .bind(
        transitionTime,
        transitionTime,
        transitionTime,
        auth.tenantId,
        repositoryId,
        digest,
        auth.tenantId,
        repositoryId,
        digest,
        digest,
      )
      .run();
    if (transition.meta.changes === 0) {
      row = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
      if (row?.state !== "deleting") {
        throw new ApiError(409, "blob_referenced", "blob is referenced or changed state");
      }
    } else {
      row = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
      if (row === null) throw new ApiError(404, "not_found", "blob not found");
    }
  }
  if ((row.delete_not_before ?? 0) > nowSeconds()) {
    const retryAfter = Math.max(1, (row.delete_not_before ?? nowSeconds()) - nowSeconds());
    return emptyResponse(202, {
      "retry-after": String(retryAfter),
    });
  }
  const key = blobKey(auth.tenantId, repositoryId, digest);
  await env.BLOBS.delete(key);
  if ((await env.BLOBS.head(key)) !== null) {
    throw new ApiError(503, "delete_incomplete", "blob deletion will be retried");
  }
  const deleted = await env.DB.prepare(
    `DELETE FROM blobs
      WHERE tenant_id = ? AND repository_id = ? AND digest = ? AND state = 'deleting'`,
  )
    .bind(auth.tenantId, repositoryId, digest)
    .run();
  if (deleted.meta.changes !== 0) {
    const audit = await auditStatement(
      env.DB,
      auth,
      repositoryId,
      "blob.delete",
      "blob",
      digest,
      "deleted",
      { size_bytes: row.size_bytes },
    );
    await audit.run();
  } else {
    const current = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
    if (current !== null) {
      throw new ApiError(409, "blob_state_changed", "blob state changed during deletion");
    }
  }
  return emptyResponse(204);
}

async function putManifest(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  requestKey: string,
): Promise<Response> {
  const auth = await authenticateForRepository(request, env, ctx, repositoryId, "write");
  const manifest = parseManifest(await readJsonObject(request, MAX_JSON_SIZE), nowSeconds());
  assertManifestBindings(manifest, auth, repositoryId, requestKey);
  const key = await producerKey(
    env.DB,
    auth.tenantId,
    repositoryId,
    manifest.signature.key_id,
  );
  if (key === null || key.revoked_at !== null || key.producer_id !== manifest.producer_id) {
    throw new ApiError(422, "untrusted_producer", "manifest producer key is not trusted");
  }
  if (!(await verifyManifestSignature(manifest, key.public_key_hex))) {
    await writeAudit(
      env.DB,
      auth,
      repositoryId,
      "manifest.put",
      "manifest",
      requestKey,
      "invalid_signature",
    );
    throw new ApiError(422, "invalid_signature", "manifest signature verification failed");
  }
  await requireReadyBlob(env.DB, auth.tenantId, repositoryId, manifest.stdout);
  await requireReadyBlob(env.DB, auth.tenantId, repositoryId, manifest.stderr);

  const bodyJson = canonicalManifestJson(manifest);
  const bodySha256 = await sha256Hex(bodyJson);
  const existingByRequest = await manifestRow(
    env.DB,
    auth.tenantId,
    repositoryId,
    "request_key",
    requestKey,
  );
  if (existingByRequest !== null) {
    return handleManifestExisting(
      env.DB,
      auth,
      repositoryId,
      requestKey,
      bodySha256,
      existingByRequest,
    );
  }
  const existingByRecord = await manifestRow(
    env.DB,
    auth.tenantId,
    repositoryId,
    "record_id",
    manifest.record_id,
  );
  if (existingByRecord !== null) {
    await quarantineManifestConflict(
      env.DB,
      auth,
      repositoryId,
      existingByRecord.request_key,
      existingByRecord.body_sha256,
      bodySha256,
      "record_id_conflict",
    );
    throw new ApiError(409, "manifest_conflict", "record id is already bound to another manifest");
  }

  const audit = await auditStatement(
    env.DB,
    auth,
    repositoryId,
    "manifest.put",
    "manifest",
    requestKey,
    "ready",
  );
  try {
    await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO manifests(
           tenant_id, repository_id, request_key, record_id, body_sha256, body_json,
           state, producer_id, key_id, stdout_digest, stdout_size_bytes,
           stderr_digest, stderr_size_bytes, created_at, expires_at
         ) VALUES (?, ?, ?, ?, ?, ?, 'ready', ?, ?, ?, ?, ?, ?, ?, ?)`,
      ).bind(
        auth.tenantId,
        repositoryId,
        requestKey,
        manifest.record_id,
        bodySha256,
        bodyJson,
        manifest.producer_id,
        manifest.signature.key_id,
        manifest.stdout.digest,
        manifest.stdout.size_bytes,
        manifest.stderr.digest,
        manifest.stderr.size_bytes,
        manifest.created_at_unix_seconds,
        manifest.expires_at_unix_seconds,
      ),
      audit,
    ]);
  } catch (error: unknown) {
    if (String(error).includes("blob_unavailable")) {
      throw new ApiError(422, "blob_unavailable", "manifest references a blob that is no longer ready");
    }
    const racedByRequest = await manifestRow(
      env.DB,
      auth.tenantId,
      repositoryId,
      "request_key",
      requestKey,
    );
    if (racedByRequest !== null) {
      return handleManifestExisting(
        env.DB,
        auth,
        repositoryId,
        requestKey,
        bodySha256,
        racedByRequest,
      );
    }
    const racedByRecord = await manifestRow(
      env.DB,
      auth.tenantId,
      repositoryId,
      "record_id",
      manifest.record_id,
    );
    if (racedByRecord !== null) {
      await quarantineManifestConflict(
        env.DB,
        auth,
        repositoryId,
        racedByRecord.request_key,
        racedByRecord.body_sha256,
        bodySha256,
        "record_id_conflict",
      );
      throw new ApiError(409, "manifest_conflict", "record id raced with another manifest");
    }
    throw error;
  }
  return emptyResponse(201, { "x-again-body-sha256": bodySha256 });
}

async function getManifest(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  requestKey: string,
): Promise<Response> {
  const auth = await authenticateForRepository(request, env, ctx, repositoryId, "read");
  const row = await manifestRow(
    env.DB,
    auth.tenantId,
    repositoryId,
    "request_key",
    requestKey,
  );
  const now = nowSeconds();
  if (
    row === null ||
    row.state !== "ready" ||
    row.expires_at <= now ||
    row.created_at > now ||
    row.key_revoked_at !== null
  ) {
    throw new ApiError(404, "not_found", "manifest not found");
  }
  const headers = new Headers({
    "cache-control": "private, no-store",
    "content-type": "application/json; charset=utf-8",
    "x-again-body-sha256": row.body_sha256,
    "x-content-type-options": "nosniff",
  });
  return new Response(row.body_json, { status: 200, headers });
}

async function deleteManifest(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  requestKey: string,
): Promise<Response> {
  const auth = await authenticateForRepository(request, env, ctx, repositoryId, "delete");
  const now = nowSeconds();
  const result = await env.DB.prepare(
    `UPDATE manifests SET state = 'deleted', deleted_at = ?
      WHERE tenant_id = ? AND repository_id = ? AND request_key = ? AND state != 'deleted'`,
  )
    .bind(now, auth.tenantId, repositoryId, requestKey)
    .run();
  if (result.meta.changes === 0) {
    throw new ApiError(404, "not_found", "manifest not found");
  }
  await writeAudit(
    env.DB,
    auth,
    repositoryId,
    "manifest.delete",
    "manifest",
    requestKey,
    "deleted",
  );
  return emptyResponse(204);
}

async function listAudit(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
): Promise<Response> {
  const auth = await authenticateForRepository(request, env, ctx, repositoryId, "audit");
  const url = new URL(request.url);
  const limitText = url.searchParams.get("limit") ?? "50";
  const cursorText = url.searchParams.get("cursor");
  if (!/^\d+$/.test(limitText)) throw new ApiError(400, "invalid_limit", "limit must be an integer");
  const limit = Number(limitText);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw new ApiError(400, "invalid_limit", "limit must be between 1 and 100");
  }
  let cursor = Number.MAX_SAFE_INTEGER;
  if (cursorText !== null) {
    if (!/^\d+$/.test(cursorText)) throw new ApiError(400, "invalid_cursor", "cursor is invalid");
    cursor = Number(cursorText);
    if (!Number.isSafeInteger(cursor) || cursor < 1) {
      throw new ApiError(400, "invalid_cursor", "cursor is invalid");
    }
  }
  const result = await env.DB.prepare(
    `SELECT id, repository_id, actor, action, target_type, target_id_sha256,
            outcome, details_json, created_at
       FROM audit_events
      WHERE tenant_id = ? AND repository_id = ? AND id < ?
      ORDER BY id DESC
      LIMIT ?`,
  )
    .bind(auth.tenantId, repositoryId, cursor, limit)
    .all<AuditRow>();
  const events = result.results.map((row) => ({
    id: row.id,
    repository_id: row.repository_id,
    actor: row.actor,
    action: row.action,
    target_type: row.target_type,
    target_id_sha256: row.target_id_sha256,
    outcome: row.outcome,
    details: safeAuditDetails(row.details_json),
    created_at: row.created_at,
  }));
  const last = events.at(-1);
  return jsonResponse({ events, next_cursor: events.length === limit ? last?.id ?? null : null });
}

async function getStats(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
): Promise<Response> {
  const auth = await authenticateForRepository(request, env, ctx, repositoryId, "audit");
  const row = await env.DB.prepare(
    `SELECT
       (SELECT count(*) FROM blobs b
         WHERE b.tenant_id = ? AND b.repository_id = ? AND b.state = 'ready') AS ready_blobs,
       (SELECT coalesce(sum(size_bytes), 0) FROM blobs b
         WHERE b.tenant_id = ? AND b.repository_id = ? AND b.state = 'ready') AS blob_bytes,
       (SELECT count(*) FROM blobs b
         WHERE b.tenant_id = ? AND b.repository_id = ? AND b.state = 'pending') AS pending_blobs,
       (SELECT count(*) FROM blobs b
         WHERE b.tenant_id = ? AND b.repository_id = ? AND b.state = 'deleting') AS deleting_blobs,
       (SELECT count(*) FROM manifests m
         WHERE m.tenant_id = ? AND m.repository_id = ? AND m.state = 'ready') AS ready_manifests,
       (SELECT count(*) FROM blobs b
         WHERE b.tenant_id = ? AND b.repository_id = ? AND b.state = 'quarantined') AS quarantined_blobs,
       (SELECT count(*) FROM manifests m
         WHERE m.tenant_id = ? AND m.repository_id = ? AND m.state = 'quarantined') AS quarantined_manifests,
       t.used_bytes AS used_bytes,
       t.quota_bytes AS quota_bytes,
       t.used_metadata_units AS used_metadata_units,
       t.metadata_quota_units AS metadata_quota_units
     FROM tenants t WHERE t.id = ?`,
  )
    .bind(
      auth.tenantId,
      repositoryId,
      auth.tenantId,
      repositoryId,
      auth.tenantId,
      repositoryId,
      auth.tenantId,
      repositoryId,
      auth.tenantId,
      repositoryId,
      auth.tenantId,
      repositoryId,
      auth.tenantId,
      repositoryId,
      auth.tenantId,
    )
    .first<StatsRow>();
  if (row === null) throw new ApiError(404, "not_found", "tenant not found");
  return jsonResponse(row);
}

async function authenticateForRepository(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  permission: Permission,
): Promise<AuthContext> {
  const auth = await authenticate(request, env, ctx, repositoryId, permission);
  await requireRepository(env.DB, auth.tenantId, repositoryId);
  return auth;
}

async function requireRepository(db: D1Database, tenantId: string, repositoryId: string): Promise<void> {
  const row = await db
    .prepare(
      `SELECT id FROM repositories
        WHERE tenant_id = ? AND id = ? AND deleted_at IS NULL`,
    )
    .bind(tenantId, repositoryId)
    .first<RepositoryRow>();
  if (row === null) throw new ApiError(404, "not_found", "repository not found");
}

function enforceTokenScope(auth: AuthContext, repositoryId: string): void {
  if (auth.repositoryScope !== null && auth.repositoryScope !== repositoryId) {
    throw new ApiError(404, "not_found", "resource not found");
  }
}

async function producerKey(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  keyId: string,
): Promise<ProducerKeyRow | null> {
  return db
    .prepare(
      `SELECT producer_id, public_key_hex, revoked_at
         FROM producer_keys
        WHERE tenant_id = ? AND repository_id = ? AND key_id = ?`,
    )
    .bind(tenantId, repositoryId, keyId)
    .first<ProducerKeyRow>();
}

async function blobRow(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  digest: string,
): Promise<BlobRow | null> {
  return db
    .prepare(
      `SELECT size_bytes, state, updated_at, reconcile_attempts,
              next_reconcile_at, delete_not_before
         FROM blobs
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
    .bind(tenantId, repositoryId, digest)
    .first<BlobRow>();
}

async function manifestRow(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  column: "request_key" | "record_id",
  value: string,
): Promise<ManifestRow | null> {
  return db
    .prepare(
      `SELECT m.request_key, m.record_id, m.body_sha256, m.body_json, m.state,
              m.producer_id, m.key_id, m.created_at, m.expires_at,
              k.revoked_at AS key_revoked_at
         FROM manifests m
         JOIN producer_keys k
           ON k.tenant_id = m.tenant_id
          AND k.repository_id = m.repository_id
          AND k.key_id = m.key_id
        WHERE m.tenant_id = ? AND m.repository_id = ? AND m.${column} = ?`,
    )
    .bind(tenantId, repositoryId, value)
    .first<ManifestRow>();
}

async function handleManifestExisting(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  requestKey: string,
  submittedSha: string,
  existing: ManifestRow,
): Promise<Response> {
  if (existing.state === "ready" && existing.body_sha256 === submittedSha) {
    return emptyResponse(204, { "x-again-body-sha256": submittedSha });
  }
  if (existing.body_sha256 !== submittedSha) {
    await quarantineManifestConflict(
      db,
      auth,
      repositoryId,
      requestKey,
      existing.body_sha256,
      submittedSha,
      "request_key_conflict",
    );
  }
  throw new ApiError(409, "manifest_conflict", "request key is quarantined or conflicts with stored data");
}

async function quarantineManifestConflict(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  requestKey: string,
  existingSha: string,
  submittedSha: string,
  reason: string,
): Promise<void> {
  const now = nowSeconds();
  const audit = await auditStatement(
    db,
    auth,
    repositoryId,
    "manifest.quarantine",
    "manifest",
    requestKey,
    reason,
  );
  await db.batch([
    db.prepare(
      `UPDATE manifests SET state = 'quarantined'
        WHERE tenant_id = ? AND repository_id = ? AND request_key = ?`,
    ).bind(auth.tenantId, repositoryId, requestKey),
    db.prepare(
      `INSERT INTO manifest_conflicts(
         tenant_id, repository_id, request_key,
         existing_body_sha256, submitted_body_sha256, detected_at
       ) VALUES (?, ?, ?, ?, ?, ?)`,
    ).bind(auth.tenantId, repositoryId, requestKey, existingSha, submittedSha, now),
    audit,
  ]);
}

async function requireReadyBlob(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  blob: RemoteCacheManifest["stdout"],
): Promise<void> {
  const row = await blobRow(db, tenantId, repositoryId, blob.digest);
  if (row === null || row.state !== "ready" || row.size_bytes !== blob.size_bytes) {
    throw new ApiError(422, "blob_unavailable", "manifest references a missing or mismatched blob");
  }
}

function assertManifestBindings(
  manifest: RemoteCacheManifest,
  auth: AuthContext,
  repositoryId: string,
  requestKey: string,
): void {
  if (manifest.tenant_id !== auth.tenantId) {
    throw new ApiError(422, "tenant_mismatch", "manifest tenant binding does not match token");
  }
  if (manifest.repository_id !== repositoryId) {
    throw new ApiError(422, "repository_mismatch", "manifest repository binding does not match path");
  }
  if (manifest.request_key !== requestKey) {
    throw new ApiError(422, "request_key_mismatch", "manifest request binding does not match path");
  }
}

async function quarantineBlob(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  digest: string,
  reason: string,
): Promise<boolean> {
  const now = nowSeconds();
  const result = await db
    .prepare(
      `UPDATE blobs
          SET state = 'quarantined', updated_at = ?, next_reconcile_at = ?
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?
          AND state IN ('ready', 'pending')`,
    )
    .bind(now, now, auth.tenantId, repositoryId, digest)
    .run();
  if (result.meta.changes === 0) return false;
  await writeAudit(db, auth, repositoryId, "blob.quarantine", "blob", digest, reason);
  return true;
}

async function quarantineOrFailOnStateChange(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  digest: string,
  reason: string,
): Promise<void> {
  if (!(await quarantineBlob(db, auth, repositoryId, digest, reason))) {
    throw new ApiError(409, "blob_state_changed", "blob state changed during integrity handling");
  }
}

async function verifyR2Object(
  bucket: R2Bucket,
  key: string,
  digest: string,
  size: number,
): Promise<VerifiedR2Object> {
  let object: R2ObjectBody | null;
  try {
    object = await bucket.get(key);
  } catch {
    throw new ApiError(503, "blob_storage_unavailable", "blob storage is temporarily unavailable");
  }
  if (object === null) return { state: "missing" };
  if (
    size > MAX_BLOB_SIZE ||
    object.size !== size ||
    object.customMetadata?.blake3 !== digest ||
    object.customMetadata.size_bytes !== String(size)
  ) {
    return { state: "invalid" };
  }
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(await object.arrayBuffer());
  } catch {
    throw new ApiError(503, "blob_storage_unavailable", "blob storage is temporarily unavailable");
  }
  if (bytes.byteLength !== size || bytesToHex(blake3(bytes)) !== digest) {
    return { state: "invalid" };
  }
  return { state: "valid", bytes };
}

async function r2ObjectState(
  bucket: R2Bucket,
  key: string,
  digest: string,
  size: number,
): Promise<R2ObjectState> {
  return (await verifyR2Object(bucket, key, digest, size)).state;
}

async function reconcileBlobs(env: Env): Promise<void> {
  const now = nowSeconds();
  const rows = await env.DB.prepare(
    `SELECT tenant_id, repository_id, digest, size_bytes, state, updated_at,
            reconcile_attempts, next_reconcile_at, delete_not_before
       FROM blobs
      WHERE state IN ('pending', 'deleting') AND next_reconcile_at <= ?
      ORDER BY next_reconcile_at, created_at
      LIMIT ?`,
  )
    .bind(now, RECONCILE_BATCH_SIZE)
    .all<ReconcileBlobRow>();
  for (const row of rows.results) {
    try {
      const key = blobKey(row.tenant_id, row.repository_id, row.digest);
      if (row.state === "pending") {
        const state = await r2ObjectState(env.BLOBS, key, row.digest, row.size_bytes);
        if (state === "valid") {
          const promoted = await env.DB.prepare(
            `UPDATE blobs
                SET state = 'ready', updated_at = ?, reconcile_attempts = 0,
                    next_reconcile_at = ?, delete_not_before = NULL
              WHERE tenant_id = ? AND repository_id = ? AND digest = ?
                AND state = 'pending' AND reconcile_attempts = ? AND next_reconcile_at = ?`,
          )
            .bind(
              now,
              now,
              row.tenant_id,
              row.repository_id,
              row.digest,
              row.reconcile_attempts,
              row.next_reconcile_at,
            )
            .run();
          if (promoted.meta.changes !== 0) {
            await (await systemAuditStatement(env.DB, row, "blob.reconcile", "promoted")).run();
          }
        } else if (state === "invalid") {
          const quarantined = await env.DB.prepare(
            `UPDATE blobs SET state = 'quarantined', updated_at = ?, next_reconcile_at = ?
              WHERE tenant_id = ? AND repository_id = ? AND digest = ?
                AND state = 'pending' AND reconcile_attempts = ? AND next_reconcile_at = ?`,
          )
            .bind(
              now,
              now,
              row.tenant_id,
              row.repository_id,
              row.digest,
              row.reconcile_attempts,
              row.next_reconcile_at,
            )
            .run();
          if (quarantined.meta.changes !== 0) {
            await (await systemAuditStatement(env.DB, row, "blob.reconcile", "quarantined")).run();
          }
        } else {
          await deferReconciliation(env.DB, row, now);
        }
      } else if (row.state === "deleting") {
        if ((row.delete_not_before ?? 0) > now) continue;
        await env.BLOBS.delete(key);
        if ((await env.BLOBS.head(key)) === null) {
          const deleted = await env.DB.prepare(
            `DELETE FROM blobs
              WHERE tenant_id = ? AND repository_id = ? AND digest = ?
                AND state = 'deleting' AND next_reconcile_at = ?`,
          )
            .bind(row.tenant_id, row.repository_id, row.digest, row.next_reconcile_at)
            .run();
          if (deleted.meta.changes !== 0) {
            await (await systemAuditStatement(env.DB, row, "blob.reconcile", "deleted")).run();
          }
        } else {
          await deferReconciliation(env.DB, row, now);
        }
      }
    } catch (error: unknown) {
      let deferred = false;
      try {
        deferred = await deferReconciliation(env.DB, row, now);
      } catch (backoffError: unknown) {
        console.warn(
          JSON.stringify({
            event: "blob_reconcile_backoff_failed",
            state: row.state,
            error: backoffError instanceof Error ? backoffError.name : "UnknownError",
          }),
        );
      }
      console.warn(
        JSON.stringify({
          event: "blob_reconcile_failed",
          state: row.state,
          deferred,
          error: error instanceof Error ? error.name : "UnknownError",
        }),
      );
    }
  }
  await env.DB.prepare(
    `DELETE FROM rate_windows
      WHERE rowid IN (
        SELECT rowid FROM rate_windows
         WHERE window_start < ?
         ORDER BY window_start
         LIMIT 500
      )`,
  )
    .bind(nowSeconds() - 3600)
    .run();
}

async function systemAuditStatement(
  db: D1Database,
  row: ReconcileBlobRow,
  action: string,
  outcome: string,
): Promise<D1PreparedStatement> {
  const targetHash = await sha256Hex(
    `${row.tenant_id}\0${row.repository_id}\0blob\0${row.digest}`,
  );
  return db
    .prepare(
      `INSERT INTO audit_events(
         tenant_id, repository_id, actor, action, target_type,
         target_id_sha256, outcome, details_json, created_at
       ) VALUES (?, ?, 'system:reconciler', ?, 'blob', ?, ?, '{}', ?)`,
    )
    .bind(row.tenant_id, row.repository_id, action, targetHash, outcome, nowSeconds());
}

async function deferReconciliation(
  db: D1Database,
  row: ReconcileBlobRow,
  now: number,
): Promise<boolean> {
  const exponent = Math.min(row.reconcile_attempts, 6);
  const delay = Math.min(60 * 60, 60 * 2 ** exponent);
  const result = await db
    .prepare(
      `UPDATE blobs
          SET reconcile_attempts = reconcile_attempts + 1, next_reconcile_at = ?
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?
          AND state = ? AND reconcile_attempts = ? AND next_reconcile_at = ?`,
    )
    .bind(
      now + delay,
      row.tenant_id,
      row.repository_id,
      row.digest,
      row.state,
      row.reconcile_attempts,
      row.next_reconcile_at,
    )
    .run();
  return result.meta.changes !== 0;
}

function databaseErrorContains(error: unknown, marker: string): boolean {
  return String(error).includes(marker);
}

function blobKey(tenantId: string, repositoryId: string, digest: string): string {
  return `v1/${tenantId}/${repositoryId}/blake3/${digest}`;
}

function blobHeaders(digest: string, size: number): Headers {
  return new Headers({
    "cache-control": "private, no-store",
    "content-length": String(size),
    "content-type": "application/octet-stream",
    etag: quotedDigest(digest),
    "x-again-blake3": digest,
    "x-content-type-options": "nosniff",
  });
}

function quotedDigest(digest: string): string {
  return `"${digest}"`;
}

async function writeAudit(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  action: string,
  targetType: string,
  targetId: string,
  outcome: string,
): Promise<void> {
  const statement = await auditStatement(
    db,
    auth,
    repositoryId,
    action,
    targetType,
    targetId,
    outcome,
  );
  await statement.run();
}

function safeAuditDetails(value: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return { invalid: true };
  }
}

function methodNotAllowed(): ApiError {
  return new ApiError(405, "method_not_allowed", "method is not allowed for this resource");
}
