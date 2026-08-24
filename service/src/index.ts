import { blake3 } from "@noble/hashes/blake3.js";

import {
  generationGuardedAuditAfterMutationStatement,
  generationGuardedDeletionAuditStatement,
  generationGuardedAuditStatement,
  tenantAdminGenerationGuardedAuditStatement,
} from "./audit";
import { authenticate, type AuthContext, type Permission } from "./auth";
import {
  canonicalManifestJson,
  publicKeyHex,
  verifyManifestSignature,
  type RemoteCacheManifest,
} from "./manifest";
import {
  parseEncryptedManifestV2,
  verifyEncryptedManifestV2Signature,
  type EncryptedRemoteCacheManifestV2,
} from "./manifest-v2";
import {
  encodeLookupBundleV1,
  LOOKUP_BUNDLE_V1_CONTENT_TYPE,
} from "./lookup-bundle-v1";
import {
  assertMonotonicTrustBundle,
  canonicalTrustBundleJson,
  MAX_TRUST_BUNDLE_JSON_SIZE,
  parseTrustBundle,
  verifyTrustBundleSignature,
  type TrustBundleV1,
} from "./trust";
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

const RECONCILE_BATCH_SIZE = 16;
const MANIFEST_CLEANUP_BATCH_SIZE = 64;
const BLOB_GC_BATCH_SIZE = 64;
const REPOSITORY_DELETE_BATCH_SIZE = 4;
const REPOSITORY_DELETE_R2_PAGE_SIZE = 1000;
const REPOSITORY_DELETE_D1_CHUNK_SIZE = 256;
const REPOSITORY_DELETE_D1_CHUNKS_PER_LEASE = 8;
const REPOSITORY_DELETE_LEASE_SECONDS = 5 * 60;
const REPOSITORY_DELETE_EMPTY_CONFIRM_SECONDS = 60;
const REPOSITORY_WRITE_LEASE_SECONDS = 15 * 60;
const UNREFERENCED_BLOB_ADOPTION_SECONDS = 60 * 60;
const PENDING_CANCEL_AFTER_SECONDS = 60 * 60;
const PENDING_DELETE_GRACE_SECONDS = 60 * 60;
const FAST_MAINTENANCE_CRON = "*/15 * * * *";
const BLOB_RECONCILIATION_CRON = "7 * * * *";
const LEGACY_BLOB_INCARNATION = "0".repeat(32);

interface RepositoryRow {
  id: string;
  generation_id: string;
  deleted_at: number | null;
}

interface RepositoryDeletionRow {
  tenant_id: string;
  repository_id: string;
  generation_id: string;
  requested_at: number;
  r2_cursor: string | null;
  empty_confirmations: number;
  last_empty_at: number | null;
  attempts: number;
  next_attempt_at: number;
  lease_id: string | null;
  lease_until: number | null;
  phase: RepositoryDeletionPhase;
  updated_at: number;
}

type RepositoryDeletionPhase =
  | "r2"
  | "manifest_conflicts"
  | "manifests"
  | "blobs"
  | "trust_heads"
  | "trust_key_history"
  | "trust_revoked_keys"
  | "trust_revoked_records"
  | "trust_root_keys"
  | "producer_keys"
  | "auth_tokens"
  | "audit_events"
  | "finalize";

interface RepositoryDeletionReceiptRow {
  requested_at: number;
  completed_at: number | null;
}

interface CompletedRepositoryDeletionReceiptRow {
  tenant_id: string;
  repository_id: string;
  generation_id: string;
}

interface BlobObjectOrphanCandidateRow {
  tenant_id: string;
  repository_id: string;
  generation_id: string;
  digest: string;
  incarnation_id: string;
  operation_id: string;
  attempts: number;
}

interface RepositoryWriteLease {
  leaseId: string;
  generationId: string;
}

interface BlobGcCandidateRow {
  tenant_id: string;
  repository_id: string;
  generation_id: string;
  digest: string;
  incarnation_id: string;
  next_check_at: number;
  attempts: number;
  state: BlobRow["state"];
  blob_updated_at: number;
}

interface ProducerKeyRow {
  producer_id: string;
  public_key_hex: string;
  revoked_at: number | null;
}

interface BlobRow {
  size_bytes: number;
  incarnation_id: string;
  r2_key: string | null;
  r2_version: string | null;
  r2_etag: string | null;
  r2_sha256: string | null;
  state: "pending" | "ready" | "quarantined" | "deleting";
  updated_at: number;
  reconcile_attempts: number;
  next_reconcile_at: number;
  delete_not_before: number | null;
}

interface ReconcileBlobRow extends BlobRow {
  tenant_id: string;
  repository_id: string;
  generation_id: string;
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
  stdout_digest: string;
  stdout_size_bytes: number;
  stderr_digest: string;
  stderr_size_bytes: number;
  created_at: number;
  expires_at: number;
  producer_key_id: string | null;
  producer_key_producer_id: string | null;
  producer_public_key_hex: string | null;
  key_revoked_at: number | null;
  trust_epoch: number | null;
  trust_body_sha256: string | null;
}

interface TrustRootRow {
  public_key_hex: string;
  disabled_at: number | null;
}

interface TrustHeadRow {
  epoch: number;
  root_key_id: string;
  body_sha256: string;
  body_json: string;
  issued_at: number;
  expires_at: number;
  public_key_hex: string;
  root_disabled_at: number | null;
}

interface VerifiedTrustHead {
  bundle: TrustBundleV1;
  bodySha256: string;
}

interface EncryptedManifestTrustAuthorization {
  publicKeyHex: string;
  epoch: number;
  bodySha256: string;
}

interface ReusableManifestCandidate {
  row: ManifestRow;
  manifest: EncryptedRemoteCacheManifestV2;
  stdout: BlobRow;
  stderr: BlobRow;
  trustAuthorization: EncryptedManifestTrustAuthorization;
}

type ServiceManifest = RemoteCacheManifest | EncryptedRemoteCacheManifestV2;

interface ServiceBlobRef {
  digest: string;
  size_bytes: number;
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
  repository_generation_history_count: number;
  repository_generation_history_limit: number;
  blob_orphan_candidate_count: number;
  blob_orphan_candidate_limit: number;
  blob_orphan_repository_count: number;
  blob_orphan_repository_limit: number;
  trust_security_reserve_used_units: number;
  trust_security_reserve_limit: number;
  repository_trust_security_reserve_used_units: number;
  trust_security_repository_limit: number;
  audit_event_count: number;
  audit_event_limit: number;
  audit_partition_limit: number;
}

type R2ObjectState = "missing" | "valid" | "invalid";

interface VerifiedR2Object {
  state: R2ObjectState;
  bytes?: Uint8Array;
  identity?: R2Identity;
}

interface R2Identity {
  key: string;
  version: string;
  etag: string;
  sha256: string;
}

interface StreamedR2Object {
  object: R2ObjectBody;
  stream: ReadableStream<Uint8Array>;
}

const worker = {
  async fetch(
    request: Request,
    env: Env,
    ctx: ExecutionContext,
  ): Promise<Response> {
    const requestId = crypto.randomUUID();
    try {
      const response = await route(request, env, ctx);
      response.headers.set("x-request-id", requestId);
      return response;
    } catch (error: unknown) {
      if (error instanceof ApiError) return errorResponse(error, requestId);
      if (databaseErrorContains(error, "metadata_quota_exceeded")) {
        return errorResponse(
          new ApiError(
            413,
            "metadata_quota_exceeded",
            "tenant metadata quota would be exceeded",
          ),
          requestId,
        );
      }
      if (databaseErrorContains(error, "repository_generation_mismatch")) {
        return errorResponse(
          new ApiError(
            412,
            "repository_generation_mismatch",
            "repository generation changed during the request",
          ),
          requestId,
        );
      }
      if (databaseErrorContains(error, "repository_deleting")) {
        return errorResponse(
          new ApiError(404, "not_found", "repository not found"),
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
  scheduled(
    controller: ScheduledController,
    env: Env,
    ctx: ExecutionContext,
  ): void {
    ctx.waitUntil(runScheduledMaintenance(controller.cron, env));
  },
} satisfies ExportedHandler<Env>;

export default worker;

async function route(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  const url = new URL(request.url);
  if (url.pathname === "/v1/health") {
    if (request.method !== "GET") throw methodNotAllowed();
    return jsonResponse({
      status: "ok",
      service: "again-cache",
      schema_version: 1,
    });
  }

  const segments = url.pathname
    .split("/")
    .filter((segment) => segment.length > 0);
  if (segments[0] !== "v1" || segments[1] !== "repositories") {
    throw new ApiError(404, "not_found", "resource not found");
  }

  if (segments.length === 2) {
    if (request.method !== "POST") throw methodNotAllowed();
    return createRepository(request, env, ctx);
  }

  const repositoryId = requireRouteIdentifier(
    segments[2] ?? "",
    "repository_id",
  );
  if (segments.length === 3) {
    if (request.method === "DELETE") {
      return deleteRepository(request, env, ctx, repositoryId);
    }
    throw methodNotAllowed();
  }
  if (segments.length === 4 && segments[3] === "audit") {
    if (request.method !== "GET") throw methodNotAllowed();
    return listAudit(request, env, ctx, repositoryId);
  }
  if (segments.length === 4 && segments[3] === "stats") {
    if (request.method !== "GET") throw methodNotAllowed();
    return getStats(request, env, ctx, repositoryId);
  }
  if (segments.length !== 5)
    throw new ApiError(404, "not_found", "resource not found");

  const resource = segments[3];
  const identifier = segments[4] ?? "";
  if (resource === "blobs") {
    const digest = requireDigest(identifier, "blob_digest");
    if (request.method === "PUT")
      return putBlob(request, env, ctx, repositoryId, digest);
    if (request.method === "GET" || request.method === "HEAD") {
      return getBlob(request, env, ctx, repositoryId, digest);
    }
    if (request.method === "DELETE")
      return deleteBlob(request, env, ctx, repositoryId, digest);
    throw methodNotAllowed();
  }
  if (resource === "manifests") {
    const requestKey = requireDigest(identifier, "request_key");
    if (request.method === "PUT") {
      return putManifest(request, env, ctx, repositoryId, requestKey);
    }
    if (request.method === "GET")
      return getManifest(request, env, ctx, repositoryId, requestKey);
    if (request.method === "DELETE") {
      return deleteManifest(request, env, ctx, repositoryId, requestKey);
    }
    throw methodNotAllowed();
  }
  if (resource === "lookup-bundles") {
    const requestKey = requireDigest(identifier, "request_key");
    if (request.method === "GET") {
      return getLookupBundle(request, env, ctx, repositoryId, requestKey);
    }
    throw methodNotAllowed();
  }
  if (resource === "producers") {
    const keyId = requireRouteIdentifier(identifier, "key_id");
    if (request.method === "PUT")
      return putProducer(request, env, ctx, repositoryId, keyId);
    if (request.method === "DELETE") {
      return revokeProducer(request, env, ctx, repositoryId, keyId);
    }
    throw methodNotAllowed();
  }
  if (resource === "trust-bundles") {
    if (identifier !== "latest") {
      throw new ApiError(404, "not_found", "resource not found");
    }
    if (request.method === "PUT") {
      return putTrustBundle(request, env, ctx, repositoryId);
    }
    if (request.method === "GET") {
      return getTrustBundle(request, env, ctx, repositoryId);
    }
    throw methodNotAllowed();
  }
  throw new ApiError(404, "not_found", "resource not found");
}

async function createRepository(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
): Promise<Response> {
  const auth = await authenticate(request, env, ctx, null, "admin");
  // A repository-scoped credential belongs to one already-created
  // repository generation. It must never survive deletion and recreate that
  // identifier (or learn the replacement generation) through this route.
  if (auth.repositoryScope !== null) {
    throw new ApiError(404, "not_found", "resource not found");
  }
  const body = await readJsonObject(request, MAX_SMALL_JSON_SIZE);
  assertExactKeys(body, ["repository_id"], "repository");
  const repositoryId = requireRouteIdentifier(
    requireString(body.repository_id, "repository_id"),
    "repository_id",
  );
  const existingBeforeInsert = await repositoryRow(
    env.DB,
    auth.tenantId,
    repositoryId,
  );
  if (existingBeforeInsert !== null) {
    if (existingBeforeInsert.deleted_at !== null) {
      throw new ApiError(
        409,
        "repository_deleting",
        "repository deletion is in progress",
      );
    }
    const audit = await tenantAdminGenerationGuardedAuditStatement(
      env.DB,
      auth.tenantId,
      repositoryId,
      existingBeforeInsert.generation_id,
      auth.tokenId,
      auth.tokenSecretSha256,
      auth.subject,
      "exists",
    );
    if ((await audit.run()).meta.changes === 0)
      throw staleTenantAdminCredential();
    await requireRepositoryGeneration(
      env.DB,
      auth.tenantId,
      repositoryId,
      existingBeforeInsert.generation_id,
    );
    return jsonResponse(
      {
        repository_id: repositoryId,
        generation_id: existingBeforeInsert.generation_id,
        created: false,
      },
      200,
      repositoryGenerationHeaders(existingBeforeInsert.generation_id),
    );
  }
  const now = nowSeconds();
  const generationId = randomGenerationId();
  const creation = env.DB.prepare(
    `INSERT OR IGNORE INTO repositories(tenant_id, id, generation_id, created_at)
     SELECT ?, ?, ?, ?
      WHERE EXISTS (
        SELECT 1 FROM auth_tokens token
         WHERE token.id = ? AND token.tenant_id = ?
           AND token.secret_sha256 = ? AND token.subject = ?
           AND token.repository_scope IS NULL
           AND token.revoked_at IS NULL AND token.expires_at > unixepoch()
           AND instr(',' || token.permissions || ',', ',admin,') > 0
      )
       AND (SELECT count(*) FROM repository_deletion_receipts receipt
             WHERE receipt.tenant_id = ?) < (
               SELECT tenant.repository_generation_history_limit
                 FROM tenants tenant WHERE tenant.id = ?
             )`,
  ).bind(
    auth.tenantId,
    repositoryId,
    generationId,
    now,
    auth.tokenId,
    auth.tenantId,
    auth.tokenSecretSha256,
    auth.subject,
    auth.tenantId,
    auth.tenantId,
  );
  const creationAudit = await tenantAdminGenerationGuardedAuditStatement(
    env.DB,
    auth.tenantId,
    repositoryId,
    generationId,
    auth.tokenId,
    auth.tokenSecretSha256,
    auth.subject,
    "created",
  );
  const creationResults = await env.DB.batch([creation, creationAudit]);
  const created = (creationResults[0]?.meta.changes ?? 0) > 0;
  if (created && (creationResults[1]?.meta.changes ?? 0) === 0) {
    throw staleTenantAdminCredential();
  }
  let admittedGeneration = generationId;
  if (!created) {
    const existing = await repositoryRow(env.DB, auth.tenantId, repositoryId);
    if (existing !== null && existing.deleted_at !== null) {
      throw new ApiError(
        409,
        "repository_deleting",
        "repository deletion is in progress",
      );
    }
    if (existing === null) {
      const currentAdmin = await env.DB.prepare(
        `SELECT (SELECT count(*) FROM repository_deletion_receipts receipt
                  WHERE receipt.tenant_id = token.tenant_id) AS receipt_count,
                tenant.repository_generation_history_limit AS receipt_limit
           FROM auth_tokens token
           JOIN tenants tenant ON tenant.id = token.tenant_id
          WHERE token.id = ? AND token.tenant_id = ? AND token.secret_sha256 = ?
            AND token.subject = ? AND token.repository_scope IS NULL
            AND token.revoked_at IS NULL AND token.expires_at > unixepoch()
            AND instr(',' || token.permissions || ',', ',admin,') > 0`,
      )
        .bind(auth.tokenId, auth.tenantId, auth.tokenSecretSha256, auth.subject)
        .first<{ receipt_count: number; receipt_limit: number }>();
      if (currentAdmin === null) throw staleTenantAdminCredential();
      if (currentAdmin.receipt_count >= currentAdmin.receipt_limit) {
        throw new ApiError(
          413,
          "metadata_quota_exceeded",
          "repository generation history limit has been reached",
        );
      }
      throw staleTenantAdminCredential();
    }
    admittedGeneration = existing.generation_id;
    const existingAudit = await tenantAdminGenerationGuardedAuditStatement(
      env.DB,
      auth.tenantId,
      repositoryId,
      admittedGeneration,
      auth.tokenId,
      auth.tokenSecretSha256,
      auth.subject,
      "exists",
    );
    if ((await existingAudit.run()).meta.changes === 0)
      throw staleTenantAdminCredential();
  }
  await requireRepositoryGeneration(
    env.DB,
    auth.tenantId,
    repositoryId,
    admittedGeneration,
  );
  return jsonResponse(
    {
      repository_id: repositoryId,
      generation_id: admittedGeneration,
      created,
    },
    created ? 201 : 200,
    repositoryGenerationHeaders(admittedGeneration),
  );
}

async function deleteRepository(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
): Promise<Response> {
  const auth = await authenticate(request, env, ctx, repositoryId, "admin");
  const requestedGeneration = requireRepositoryIfMatch(request);
  let existing = await repositoryRow(env.DB, auth.tenantId, repositoryId);
  if (existing === null || existing.generation_id !== requestedGeneration) {
    const historical = await repositoryDeletionReceipt(
      env.DB,
      auth.tenantId,
      repositoryId,
      requestedGeneration,
    );
    if (historical !== null) {
      return repositoryDeletionReceiptResponse(
        repositoryId,
        requestedGeneration,
        historical,
      );
    }
    if (existing === null)
      throw new ApiError(404, "not_found", "repository not found");
    throw new ApiError(
      412,
      "repository_generation_mismatch",
      "repository generation does not match",
    );
  }

  if (existing.deleted_at === null) {
    const now = nowSeconds();
    const tombstoned = await env.DB.prepare(
      `UPDATE repositories SET deleted_at = ?
        WHERE tenant_id = ? AND id = ? AND generation_id = ? AND deleted_at IS NULL`,
    )
      .bind(now, auth.tenantId, repositoryId, requestedGeneration)
      .run();
    if (tombstoned.meta.changes !== 0) {
      try {
        const audit = await generationGuardedDeletionAuditStatement(
          env.DB,
          auth.tenantId,
          repositoryId,
          requestedGeneration,
          auth.subject,
          repositoryId,
        );
        await audit.run();
      } catch (error: unknown) {
        // Deletion must remain available even when an audit insert is blocked
        // by metadata quota or a transient D1 error. The durable lifecycle row
        // still records the deletion request without retaining a clear-text
        // identifier in logs.
        console.warn(
          JSON.stringify({
            event: "repository_delete_audit_failed",
            error: error instanceof Error ? error.name : "UnknownError",
          }),
        );
      }
    }
    existing = await repositoryRow(env.DB, auth.tenantId, repositoryId);
    if (existing === null || existing.generation_id !== requestedGeneration) {
      const racedReceipt = await repositoryDeletionReceipt(
        env.DB,
        auth.tenantId,
        repositoryId,
        requestedGeneration,
      );
      if (racedReceipt !== null) {
        return repositoryDeletionReceiptResponse(
          repositoryId,
          requestedGeneration,
          racedReceipt,
        );
      }
      throw new ApiError(
        409,
        "repository_state_changed",
        "repository changed during deletion",
      );
    }
  }

  const deletion = await repositoryDeletionRow(
    env.DB,
    auth.tenantId,
    repositoryId,
  );
  if (deletion === null || deletion.generation_id !== requestedGeneration) {
    throw new ApiError(
      503,
      "delete_state_unavailable",
      "repository deletion will be retried",
    );
  }
  return jsonResponse(
    {
      repository_id: repositoryId,
      generation_id: requestedGeneration,
      status: "deleting",
      requested_at_unix_seconds: deletion.requested_at,
    },
    202,
    {
      ...repositoryGenerationHeaders(requestedGeneration),
      "retry-after": String(REPOSITORY_DELETE_EMPTY_CONFIRM_SECONDS),
    },
  );
}

async function putProducer(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  keyId: string,
): Promise<Response> {
  const auth = await authenticateForRepository(
    request,
    env,
    ctx,
    repositoryId,
    "admin",
  );
  const repository = await requireRepository(
    env.DB,
    auth.tenantId,
    repositoryId,
  );
  requireRepositoryGenerationRequest(request, repository.generation_id);
  const body = await readJsonObject(request, MAX_SMALL_JSON_SIZE);
  assertExactKeys(body, ["producer_id", "public_key_hex"], "producer_key");
  const producerId = requireProtocolIdentifier(body.producer_id, "producer_id");
  const keyHex = publicKeyHex(body.public_key_hex);
  await requireRepositoryGeneration(
    env.DB,
    auth.tenantId,
    repositoryId,
    repository.generation_id,
  );
  const writeLease = await acquireRepositoryWriteLease(
    env.DB,
    auth.tenantId,
    repositoryId,
    repository.generation_id,
  );
  try {
    await renewRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
    const existing = await producerKey(
      env.DB,
      auth.tenantId,
      repositoryId,
      keyId,
    );
    await renewRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
    if (existing !== null) {
      if (
        existing.revoked_at === null &&
        existing.producer_id === producerId &&
        existing.public_key_hex === keyHex
      ) {
        await requireProducerActiveBinding(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease.generationId,
          keyId,
          producerId,
          keyHex,
        );
        return emptyResponse(
          204,
          repositoryGenerationBindingHeader(writeLease.generationId),
        );
      }
      await writeGenerationGuardedAudit(
        env.DB,
        auth,
        repositoryId,
        writeLease.generationId,
        "producer.register",
        "producer_key",
        keyId,
        "immutable_conflict",
      );
      throw new ApiError(
        409,
        "key_binding_conflict",
        "key id is already bound or revoked",
      );
    }
    const now = nowSeconds();
    const audit = await generationGuardedAuditAfterMutationStatement(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease.generationId,
      auth.subject,
      "producer.register",
      "producer_key",
      keyId,
      "created",
    );
    const results = await env.DB.batch([
      env.DB.prepare(
        `INSERT INTO producer_keys(
         tenant_id, repository_id, key_id, producer_id, public_key_hex, created_at
       )
       SELECT ?, ?, ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1 FROM repositories repository
           WHERE repository.tenant_id = ? AND repository.id = ?
             AND repository.generation_id = ? AND repository.deleted_at IS NULL
        )`,
      ).bind(
        auth.tenantId,
        repositoryId,
        keyId,
        producerId,
        keyHex,
        now,
        auth.tenantId,
        repositoryId,
        writeLease.generationId,
      ),
      audit,
    ]);
    if (
      (results[0]?.meta.changes ?? 0) === 0 ||
      (results[1]?.meta.changes ?? 0) === 0
    ) {
      throw repositoryGenerationChanged();
    }
    return emptyResponse(
      201,
      repositoryGenerationBindingHeader(writeLease.generationId),
    );
  } finally {
    await releaseRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
  }
}

async function revokeProducer(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  keyId: string,
): Promise<Response> {
  const auth = await authenticateForRepository(
    request,
    env,
    ctx,
    repositoryId,
    "admin",
  );
  const repository = await requireRepository(
    env.DB,
    auth.tenantId,
    repositoryId,
  );
  requireRepositoryGenerationRequest(request, repository.generation_id);
  const writeLease = await acquireRepositoryWriteLease(
    env.DB,
    auth.tenantId,
    repositoryId,
    repository.generation_id,
  );
  try {
    await renewRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
    const now = nowSeconds();
    const mutation = env.DB.prepare(
      `UPDATE producer_keys SET revoked_at = ?
      WHERE tenant_id = ? AND repository_id = ? AND key_id = ? AND revoked_at IS NULL
        AND EXISTS (
          SELECT 1 FROM repositories repository
           WHERE repository.tenant_id = producer_keys.tenant_id
             AND repository.id = producer_keys.repository_id
             AND repository.generation_id = ? AND repository.deleted_at IS NULL
        )`,
    ).bind(now, auth.tenantId, repositoryId, keyId, writeLease.generationId);
    const audit = await producerRevokeAuditStatement(
      env.DB,
      auth,
      repositoryId,
      writeLease.generationId,
      keyId,
    );
    const results = await env.DB.batch([audit, mutation]);
    if ((results[1]?.meta.changes ?? 0) === 0) {
      await requireRepositoryGeneration(
        env.DB,
        auth.tenantId,
        repositoryId,
        writeLease.generationId,
      );
      throw new ApiError(404, "not_found", "producer key not found");
    }
    if ((results[0]?.meta.changes ?? 0) === 0)
      throw repositoryGenerationChanged();
    return emptyResponse(
      204,
      repositoryGenerationBindingHeader(writeLease.generationId),
    );
  } finally {
    await releaseRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
  }
}

async function putTrustBundle(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
): Promise<Response> {
  const auth = await authenticateForRepository(
    request,
    env,
    ctx,
    repositoryId,
    "admin",
  );
  const repository = await requireRepository(
    env.DB,
    auth.tenantId,
    repositoryId,
  );
  requireRepositoryGenerationRequest(request, repository.generation_id);
  const bundleBody = await readJsonObject(request, MAX_TRUST_BUNDLE_JSON_SIZE);
  const bundle = parseTrustBundle(bundleBody, nowSeconds());
  assertTrustBundleBindings(
    bundle,
    auth,
    repositoryId,
    repository.generation_id,
    new URL(request.url).origin,
  );
  await requireRepositoryGeneration(
    env.DB,
    auth.tenantId,
    repositoryId,
    repository.generation_id,
  );
  const writeLease = await acquireRepositoryWriteLease(
    env.DB,
    auth.tenantId,
    repositoryId,
    repository.generation_id,
  );
  try {
    await renewRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
    const now = nowSeconds();
    await renewRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
    const bodyJson = canonicalTrustBundleJson(bundle);
    const bodySha = await sha256Hex(bodyJson);

    const root = await trustRootKey(
      env.DB,
      auth.tenantId,
      repositoryId,
      bundle.root_key_id,
    );
    await renewRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
    if (root === null || root.disabled_at !== null) {
      throw new ApiError(
        422,
        "untrusted_root",
        "trust root is not provisioned or is disabled",
      );
    }
    if (!(await verifyTrustBundleSignature(bundle, root.public_key_hex))) {
      await writeGenerationGuardedAudit(
        env.DB,
        auth,
        repositoryId,
        writeLease.generationId,
        "trust_bundle.put",
        "trust_bundle",
        String(bundle.epoch),
        "invalid_signature",
      );
      throw new ApiError(
        422,
        "invalid_signature",
        "trust bundle root signature verification failed",
      );
    }

    const previous = await trustHead(env.DB, auth.tenantId, repositoryId);
    if (previous !== null) {
      let verifiedPrevious: VerifiedTrustHead;
      try {
        verifiedPrevious = await verifyStoredTrustHead(previous, null);
        assertTrustBundleBindings(
          verifiedPrevious.bundle,
          auth,
          repositoryId,
          repository.generation_id,
          new URL(request.url).origin,
        );
      } catch {
        throw new ApiError(
          409,
          "trust_state_corrupt",
          "stored trust state failed validation",
        );
      }
      if (bundle.epoch < previous.epoch) {
        throw new ApiError(
          409,
          "trust_epoch_rollback",
          "trust bundle epoch cannot roll back",
        );
      }
      if (bundle.epoch === previous.epoch) {
        if (bodySha !== previous.body_sha256) {
          throw new ApiError(
            409,
            "trust_epoch_conflict",
            "trust bundle epoch has divergent contents",
          );
        }
        await renewRepositoryWriteLease(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease,
        );
        if (bundle.expires_at_unix_seconds <= nowSeconds()) {
          throw new ApiError(
            422,
            "expired_trust_bundle",
            "trust bundle has expired",
          );
        }
        await requireTrustHeadCurrentForAck(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease.generationId,
          bundle,
          bodySha,
          bodyJson,
        );
        return emptyResponse(204, {
          etag: quotedDigest(bodySha),
          ...repositoryGenerationBindingHeader(writeLease.generationId),
        });
      }
      assertMonotonicTrustBundle(verifiedPrevious.bundle, bundle);
    }

    const audit = await generationGuardedAuditAfterMutationStatement(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease.generationId,
      auth.subject,
      "trust_bundle.put",
      "trust_bundle",
      String(bundle.epoch),
      previous === null ? "created" : "advanced",
    );
    const statement = env.DB.prepare(
      `INSERT INTO trust_heads(
       tenant_id, repository_id, epoch, root_key_id, body_sha256, body_json,
       issued_at, expires_at, updated_at
     ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)
     ON CONFLICT(tenant_id, repository_id) DO UPDATE SET
       epoch = excluded.epoch,
       root_key_id = excluded.root_key_id,
       body_sha256 = excluded.body_sha256,
       body_json = excluded.body_json,
       issued_at = excluded.issued_at,
       expires_at = excluded.expires_at,
       updated_at = excluded.updated_at`,
    ).bind(
      auth.tenantId,
      repositoryId,
      bundle.epoch,
      bundle.root_key_id,
      bodySha,
      bodyJson,
      bundle.issued_at_unix_seconds,
      bundle.expires_at_unix_seconds,
      now,
    );
    try {
      await renewRepositoryWriteLease(
        env.DB,
        auth.tenantId,
        repositoryId,
        writeLease,
      );
      if (bundle.expires_at_unix_seconds <= nowSeconds()) {
        throw new ApiError(
          422,
          "expired_trust_bundle",
          "trust bundle has expired",
        );
      }
      const results = await env.DB.batch([statement, audit]);
      if (
        (results[0]?.meta.changes ?? 0) === 0 ||
        (results[1]?.meta.changes ?? 0) === 0
      ) {
        throw repositoryGenerationChanged();
      }
    } catch (error: unknown) {
      if (databaseErrorContains(error, "trust_epoch_rollback")) {
        throw new ApiError(
          409,
          "trust_epoch_rollback",
          "trust bundle epoch cannot roll back",
        );
      }
      if (databaseErrorContains(error, "trust_epoch_conflict")) {
        throw new ApiError(
          409,
          "trust_epoch_conflict",
          "trust bundle epoch has divergent contents",
        );
      }
      if (databaseErrorContains(error, "trust_root_rebinding")) {
        throw new ApiError(
          409,
          "trust_root_rebinding",
          "trust root identifiers are immutable",
        );
      }
      if (databaseErrorContains(error, "trust_root_disabled")) {
        throw new ApiError(
          409,
          "trust_changed",
          "trust root was disabled during publication",
        );
      }
      if (databaseErrorContains(error, "expired_trust_bundle")) {
        throw new ApiError(
          422,
          "expired_trust_bundle",
          "trust bundle expired before commit",
        );
      }
      if (databaseErrorContains(error, "trust_key_rebinding")) {
        throw new ApiError(
          409,
          "trust_key_rebinding",
          "producer key identifiers are immutable",
        );
      }
      if (
        databaseErrorContains(error, "trust_key_revocation_rollback") ||
        databaseErrorContains(error, "trust_record_revocation_rollback")
      ) {
        throw new ApiError(
          409,
          "trust_revocation_rollback",
          "trust revocations must be cumulative",
        );
      }
      throw error;
    }
    return emptyResponse(previous === null ? 201 : 204, {
      etag: quotedDigest(bodySha),
      ...repositoryGenerationBindingHeader(writeLease.generationId),
    });
  } finally {
    await releaseRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
  }
}

async function getTrustBundle(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
): Promise<Response> {
  const auth = await authenticateForRepository(
    request,
    env,
    ctx,
    repositoryId,
    "read",
  );
  const repository = await requireRepository(
    env.DB,
    auth.tenantId,
    repositoryId,
  );
  requireRepositoryGenerationRequest(request, repository.generation_id);
  const now = nowSeconds();
  const row = await trustHead(env.DB, auth.tenantId, repositoryId);
  if (row === null || row.root_disabled_at !== null || row.expires_at <= now) {
    throw new ApiError(404, "not_found", "fresh trust bundle not found");
  }
  let verified: VerifiedTrustHead;
  try {
    verified = await verifyStoredTrustHead(row, now);
  } catch {
    throw new ApiError(
      409,
      "trust_state_corrupt",
      "stored trust state failed validation",
    );
  }
  const bundle = verified.bundle;
  assertTrustBundleBindings(
    bundle,
    auth,
    repositoryId,
    repository.generation_id,
    new URL(request.url).origin,
  );
  const stillCurrent = await env.DB.prepare(
    `SELECT 1 AS present
         FROM repositories repository
         JOIN trust_heads head
           ON head.tenant_id = repository.tenant_id
          AND head.repository_id = repository.id
         JOIN trust_root_keys root
           ON root.tenant_id = head.tenant_id
          AND root.repository_id = head.repository_id
          AND root.root_key_id = head.root_key_id
        WHERE repository.tenant_id = ? AND repository.id = ?
          AND repository.generation_id = ? AND repository.deleted_at IS NULL
          AND head.epoch = ? AND head.body_sha256 = ? AND head.root_key_id = ?
          AND head.expires_at > unixepoch() AND root.disabled_at IS NULL`,
  )
    .bind(
      auth.tenantId,
      repositoryId,
      repository.generation_id,
      row.epoch,
      row.body_sha256,
      row.root_key_id,
    )
    .first<{ present: number }>();
  if (stillCurrent === null) {
    throw new ApiError(
      409,
      "trust_changed",
      "trust changed during verification",
    );
  }
  return jsonResponse(bundle, 200, {
    etag: quotedDigest(row.body_sha256),
    ...repositoryGenerationBindingHeader(repository.generation_id),
  });
}

async function verifyStoredTrustHead(
  row: TrustHeadRow,
  now: number | null,
): Promise<VerifiedTrustHead> {
  const parsed = JSON.parse(row.body_json) as unknown;
  if (typeof parsed !== "object" || parsed === null || Array.isArray(parsed)) {
    throw new Error("stored trust body is not an object");
  }
  const bundle = parseTrustBundle(parsed as Record<string, unknown>, now);
  const canonical = canonicalTrustBundleJson(bundle);
  const bodySha256 = await sha256Hex(canonical);
  if (
    canonical !== row.body_json ||
    bodySha256 !== row.body_sha256 ||
    bundle.epoch !== row.epoch ||
    bundle.root_key_id !== row.root_key_id ||
    bundle.issued_at_unix_seconds !== row.issued_at ||
    bundle.expires_at_unix_seconds !== row.expires_at ||
    !(await verifyTrustBundleSignature(bundle, row.public_key_hex))
  ) {
    throw new Error("stored trust head failed integrity verification");
  }
  return { bundle, bodySha256 };
}

async function authorizeEncryptedManifestWithCurrentTrust(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  endpointOrigin: string,
  manifest: EncryptedRemoteCacheManifestV2,
  now: number,
): Promise<EncryptedManifestTrustAuthorization> {
  const repository = await requireRepository(db, auth.tenantId, repositoryId);
  const row = await trustHead(db, auth.tenantId, repositoryId);
  if (row === null || row.root_disabled_at !== null || row.expires_at <= now) {
    throw new ApiError(
      422,
      "fresh_trust_required",
      "encrypted manifest publication requires a fresh signed trust bundle",
    );
  }
  let verified: VerifiedTrustHead;
  try {
    verified = await verifyStoredTrustHead(row, now);
  } catch {
    throw new ApiError(
      409,
      "trust_state_corrupt",
      "stored trust state failed integrity validation",
    );
  }
  const bundle = verified.bundle;
  assertTrustBundleBindings(
    bundle,
    auth,
    repositoryId,
    repository.generation_id,
    endpointOrigin,
  );
  if (manifest.generation_id !== repository.generation_id) {
    throw new ApiError(
      422,
      "repository_generation_mismatch",
      "manifest repository generation does not match the live repository",
    );
  }
  if (bundle.revoked_record_ids.includes(manifest.record_id)) {
    throw new ApiError(
      422,
      "record_revoked",
      "manifest record is revoked by current trust",
    );
  }
  if (bundle.revoked_key_ids.includes(manifest.signature.key_id)) {
    throw new ApiError(
      422,
      "producer_revoked",
      "manifest producer key is revoked by current trust",
    );
  }
  const binding = bundle.active_producer_keys.find(
    (candidate) => candidate.key_id === manifest.signature.key_id,
  );
  if (binding === undefined || binding.producer_id !== manifest.producer_id) {
    throw new ApiError(
      422,
      "untrusted_producer",
      "manifest producer is not active in current trust",
    );
  }
  for (const [allowed, actual, code] of [
    [
      bundle.allowed_policy_digests,
      manifest.policy_digest,
      "policy_not_allowed",
    ],
    [
      bundle.allowed_execution_profile_digests,
      manifest.execution_profile_digest,
      "execution_profile_not_allowed",
    ],
    [
      bundle.allowed_platform_digests,
      manifest.platform_digest,
      "platform_not_allowed",
    ],
    [bundle.allowed_image_digests, manifest.image_digest, "image_not_allowed"],
  ] as const) {
    if (!allowed.includes(actual)) {
      throw new ApiError(
        422,
        code,
        "manifest binding is not allowed by current trust",
      );
    }
  }
  return {
    publicKeyHex: bytesToHex(Uint8Array.from(binding.public_key)),
    epoch: bundle.epoch,
    bodySha256: verified.bodySha256,
  };
}

function assertTrustBundleBindings(
  bundle: TrustBundleV1,
  auth: AuthContext,
  repositoryId: string,
  generationId: string,
  endpointOrigin: string,
): void {
  if (bundle.tenant_id !== auth.tenantId) {
    throw new ApiError(
      422,
      "tenant_mismatch",
      "trust bundle tenant does not match token",
    );
  }
  if (bundle.repository_id !== repositoryId) {
    throw new ApiError(
      422,
      "repository_mismatch",
      "trust bundle repository does not match path",
    );
  }
  if (bundle.generation_id !== generationId) {
    throw new ApiError(
      422,
      "repository_generation_mismatch",
      "trust bundle repository generation does not match the live repository",
    );
  }
  if (bundle.endpoint_origin !== endpointOrigin) {
    throw new ApiError(
      422,
      "endpoint_mismatch",
      "trust bundle endpoint origin does not match request",
    );
  }
}

async function putBlob(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  digest: string,
): Promise<Response> {
  const auth = await authenticateForRepository(
    request,
    env,
    ctx,
    repositoryId,
    "write",
  );
  const admittedRepository = await requireRepository(
    env.DB,
    auth.tenantId,
    repositoryId,
  );
  requireRepositoryGenerationRequest(request, admittedRepository.generation_id);
  const mediaType = request.headers
    .get("content-type")
    ?.split(";", 1)[0]
    ?.trim()
    .toLowerCase();
  if (mediaType !== "application/octet-stream") {
    throw new ApiError(
      415,
      "unsupported_media_type",
      "blob Content-Type must be application/octet-stream",
    );
  }
  // Do not hold a mutation lease while an untrusted client controls body
  // progress. The bounded read has its own wall-clock deadline; after it
  // completes we re-observe the repository generation and only then acquire
  // the lease that fences D1/R2 mutation.
  const bytes = await readBytesBounded(request, MAX_BLOB_SIZE, true, 30_000);
  const repository = await requireRepository(
    env.DB,
    auth.tenantId,
    repositoryId,
  );
  requireRepositoryGenerationRequest(request, repository.generation_id);
  const writeLease = await acquireRepositoryWriteLease(
    env.DB,
    auth.tenantId,
    repositoryId,
    repository.generation_id,
  );
  try {
    const actualDigest = bytesToHex(blake3(bytes));
    if (actualDigest !== digest) {
      if (
        !(await writeGenerationGuardedAudit(
          env.DB,
          auth,
          repositoryId,
          writeLease.generationId,
          "blob.put",
          "blob",
          digest,
          "digest_mismatch",
        ))
      ) {
        throw repositoryGenerationChanged();
      }
      throw new ApiError(
        422,
        "digest_mismatch",
        "blob bytes do not match the requested BLAKE3 digest",
      );
    }

    await renewRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
    let row = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
    if (row?.state === "quarantined") {
      throw new ApiError(409, "blob_quarantined", "blob is quarantined");
    }
    if (row?.state === "deleting") {
      throw new ApiError(409, "blob_deleting", "blob deletion is in progress");
    }
    if (row !== null && row.size_bytes !== bytes.byteLength) {
      await quarantineBlob(
        env.DB,
        auth,
        repositoryId,
        writeLease.generationId,
        digest,
        row.incarnation_id,
        "size_conflict",
      );
      throw new ApiError(
        409,
        "blob_conflict",
        "existing blob metadata conflicts with upload",
      );
    }
    if (row?.state === "ready") {
      const repairIncarnation = row.incarnation_id;
      const key = blobKey(
        auth.tenantId,
        repositoryId,
        writeLease.generationId,
        digest,
        row.incarnation_id,
      );
      const objectState = await r2ObjectState(
        env.BLOBS,
        key,
        digest,
        bytes.byteLength,
        row.incarnation_id,
        blobR2Identity(row),
      );
      if (objectState === "valid") {
        await renewRepositoryWriteLease(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease,
        );
        await requireBlobReadyIncarnation(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease.generationId,
          digest,
          row.incarnation_id,
          bytes.byteLength,
        );
        return emptyResponse(204, {
          etag: quotedDigest(digest),
          ...repositoryGenerationBindingHeader(writeLease.generationId),
        });
      }
      if (objectState === "invalid") {
        await quarantineOrFailOnStateChange(
          env.DB,
          auth,
          repositoryId,
          writeLease.generationId,
          digest,
          row.incarnation_id,
          "r2_integrity_failure",
        );
        throw new ApiError(
          409,
          "blob_integrity_failure",
          "blob failed storage integrity validation",
        );
      }
      const transitionTime = nowSeconds();
      const transitioned = await env.DB.prepare(
        `UPDATE blobs
          SET state = 'pending', updated_at = ?, reconcile_attempts = 0,
              next_reconcile_at = ?, delete_not_before = NULL,
              r2_key = NULL, r2_version = NULL, r2_etag = NULL, r2_sha256 = NULL
        WHERE tenant_id = ? AND repository_id = ? AND digest = ? AND state = 'ready'
          AND incarnation_id = ?
          AND EXISTS (
            SELECT 1 FROM repositories repository
             WHERE repository.tenant_id = blobs.tenant_id
               AND repository.id = blobs.repository_id
               AND repository.generation_id = ? AND repository.deleted_at IS NULL
          )`,
      )
        .bind(
          transitionTime,
          transitionTime + 60,
          auth.tenantId,
          repositoryId,
          digest,
          row.incarnation_id,
          writeLease.generationId,
        )
        .run();
      if (transitioned.meta.changes === 0) {
        await requireRepositoryGeneration(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease.generationId,
        );
        throw new ApiError(
          409,
          "blob_state_changed",
          "blob state changed during repair",
        );
      }
      row = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
      if (
        row?.state !== "pending" ||
        row.incarnation_id !== repairIncarnation
      ) {
        throw new ApiError(
          409,
          "blob_state_changed",
          "blob state changed during repair",
        );
      }
    }

    if (row === null) {
      try {
        const now = nowSeconds();
        const incarnationId = randomGenerationId();
        const reserved = await env.DB.prepare(
          `INSERT INTO blobs(
           tenant_id, repository_id, digest, size_bytes, state, created_at, updated_at,
           reconcile_attempts, next_reconcile_at, delete_not_before, incarnation_id
         )
         SELECT ?, ?, ?, ?, 'pending', ?, ?, 0, ?, NULL, ?
          WHERE EXISTS (
            SELECT 1 FROM repositories repository
             WHERE repository.tenant_id = ? AND repository.id = ?
               AND repository.generation_id = ? AND repository.deleted_at IS NULL
          )`,
        )
          .bind(
            auth.tenantId,
            repositoryId,
            digest,
            bytes.byteLength,
            now,
            now,
            now + 60,
            incarnationId,
            auth.tenantId,
            repositoryId,
            writeLease.generationId,
          )
          .run();
        if (reserved.meta.changes === 0) throw repositoryGenerationChanged();
        row = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
        if (row?.incarnation_id !== incarnationId) {
          throw new ApiError(
            409,
            "blob_state_changed",
            "blob reservation changed during creation",
          );
        }
      } catch (error: unknown) {
        const existing = await blobRow(
          env.DB,
          auth.tenantId,
          repositoryId,
          digest,
        );
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
          throw new ApiError(
            413,
            "quota_exceeded",
            "tenant storage quota would be exceeded",
          );
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
      const repairIncarnation = row.incarnation_id;
      const key = blobKey(
        auth.tenantId,
        repositoryId,
        writeLease.generationId,
        digest,
        row.incarnation_id,
      );
      const state = await r2ObjectState(
        env.BLOBS,
        key,
        digest,
        bytes.byteLength,
        row.incarnation_id,
        blobR2Identity(row),
      );
      if (state === "valid") {
        await renewRepositoryWriteLease(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease,
        );
        await requireBlobReadyIncarnation(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease.generationId,
          digest,
          row.incarnation_id,
          bytes.byteLength,
        );
        return emptyResponse(204, {
          etag: quotedDigest(digest),
          ...repositoryGenerationBindingHeader(writeLease.generationId),
        });
      }
      if (state === "invalid") {
        await quarantineOrFailOnStateChange(
          env.DB,
          auth,
          repositoryId,
          writeLease.generationId,
          digest,
          row.incarnation_id,
          "r2_integrity_failure",
        );
        throw new ApiError(
          409,
          "blob_integrity_failure",
          "blob failed storage integrity validation",
        );
      }
      const transitionTime = nowSeconds();
      const transitioned = await env.DB.prepare(
        `UPDATE blobs
          SET state = 'pending', updated_at = ?, reconcile_attempts = 0,
              next_reconcile_at = ?, delete_not_before = NULL,
              r2_key = NULL, r2_version = NULL, r2_etag = NULL, r2_sha256 = NULL
        WHERE tenant_id = ? AND repository_id = ? AND digest = ? AND state = 'ready'
          AND incarnation_id = ?
          AND EXISTS (
            SELECT 1 FROM repositories repository
             WHERE repository.tenant_id = blobs.tenant_id
               AND repository.id = blobs.repository_id
               AND repository.generation_id = ? AND repository.deleted_at IS NULL
          )`,
      )
        .bind(
          transitionTime,
          transitionTime + 60,
          auth.tenantId,
          repositoryId,
          digest,
          row.incarnation_id,
          writeLease.generationId,
        )
        .run();
      if (transitioned.meta.changes === 0) {
        await requireRepositoryGeneration(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease.generationId,
        );
        throw new ApiError(
          409,
          "blob_state_changed",
          "blob state changed during repair",
        );
      }
      row = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
      if (
        row?.state !== "pending" ||
        row.incarnation_id !== repairIncarnation
      ) {
        throw new ApiError(
          409,
          "blob_state_changed",
          "blob state changed during repair",
        );
      }
    }

    if (row === null) {
      throw new ApiError(
        409,
        "blob_state_changed",
        "blob reservation disappeared before upload",
      );
    }
    const key = blobKey(
      auth.tenantId,
      repositoryId,
      writeLease.generationId,
      digest,
      row.incarnation_id,
    );
    let objectPutAttempted = false;
    let objectPutCompleted = false;
    let objectOperationId: string | null = null;
    try {
      await renewRepositoryWriteLease(
        env.DB,
        auth.tenantId,
        repositoryId,
        writeLease,
      );
      const leaseTime = nowSeconds();
      const lease = await env.DB.prepare(
        `UPDATE blobs SET updated_at = ?, next_reconcile_at = ?
        WHERE tenant_id = ? AND repository_id = ? AND digest = ? AND state = 'pending'
          AND incarnation_id = ?
          AND EXISTS (
            SELECT 1 FROM repositories repository
             WHERE repository.tenant_id = blobs.tenant_id
               AND repository.id = blobs.repository_id
               AND repository.generation_id = ? AND repository.deleted_at IS NULL
          )`,
      )
        .bind(
          leaseTime,
          leaseTime + 60,
          auth.tenantId,
          repositoryId,
          digest,
          row.incarnation_id,
          writeLease.generationId,
        )
        .run();
      if (lease.meta.changes === 0) {
        await requireRepositoryGeneration(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease.generationId,
        );
        throw new ApiError(
          409,
          "blob_state_changed",
          "blob state changed before upload",
        );
      }
      objectOperationId = randomGenerationId();
      await registerBlobObjectOperation(
        env.DB,
        auth.tenantId,
        repositoryId,
        writeLease.generationId,
        digest,
        row.incarnation_id,
        objectOperationId,
      );
      objectPutAttempted = true;
      const sha256 = await crypto.subtle.digest("SHA-256", bytes);
      const putObject = await env.BLOBS.put(key, bytes, {
        onlyIf: { etagDoesNotMatch: "*" },
        httpMetadata: { contentType: "application/octet-stream" },
        customMetadata: {
          blake3: digest,
          size_bytes: String(bytes.byteLength),
          incarnation_id: row.incarnation_id,
        },
        sha256,
      });
      objectPutCompleted = putObject !== null;
      // Promotion never trusts PUT success or object metadata alone. Read the
      // retained object back and hash its actual bytes; a transient read failure
      // leaves the durable `pending` reservation for retry/reconciliation.
      const storedObject = await verifyR2Object(
        env.BLOBS,
        key,
        digest,
        bytes.byteLength,
        row.incarnation_id,
      );
      if (
        storedObject.state !== "valid" ||
        storedObject.identity === undefined
      ) {
        if (storedObject.state === "invalid") {
          await quarantineOrFailOnStateChange(
            env.DB,
            auth,
            repositoryId,
            writeLease.generationId,
            digest,
            row.incarnation_id,
            "r2_integrity_failure",
          );
        }
        throw new ApiError(
          409,
          "blob_integrity_failure",
          "blob failed storage integrity validation",
        );
      }
      if (storedObject.identity.sha256 !== bytesToHex(new Uint8Array(sha256))) {
        await quarantineOrFailOnStateChange(
          env.DB,
          auth,
          repositoryId,
          writeLease.generationId,
          digest,
          row.incarnation_id,
          "r2_integrity_failure",
        );
        throw new ApiError(
          409,
          "blob_integrity_failure",
          "blob failed storage integrity validation",
        );
      }
      await renewRepositoryWriteLease(
        env.DB,
        auth.tenantId,
        repositoryId,
        writeLease,
      );
      const promotion = await promoteBlobAndCompleteObjectOperation(
        env.DB,
        auth,
        repositoryId,
        writeLease.generationId,
        digest,
        row.incarnation_id,
        bytes.byteLength,
        objectOperationId,
        storedObject.identity,
      );
      return emptyResponse(promotion === "created" ? 201 : 204, {
        etag: quotedDigest(digest),
        ...repositoryGenerationBindingHeader(writeLease.generationId),
      });
    } catch (error: unknown) {
      // The pending D1 row intentionally survives. It reserves quota and is the
      // durable outbox record that lets retry/reconciliation repair either side
      // of an R2/D1 partial failure without creating unaccounted storage.
      if (objectPutAttempted) {
        await deleteBlobObjectIfUnowned(
          env,
          auth.tenantId,
          repositoryId,
          writeLease.generationId,
          digest,
          row.incarnation_id,
          key,
        ).catch((cleanupError: unknown) => {
          console.warn(
            JSON.stringify({
              event: "blob_orphan_cleanup_failed",
              error:
                cleanupError instanceof Error
                  ? cleanupError.name
                  : "UnknownError",
            }),
          );
        });
      }
      if (objectPutCompleted && objectOperationId !== null) {
        await retireSettledBlobObjectOperation(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease.generationId,
          digest,
          row.incarnation_id,
          objectOperationId,
        ).catch((cleanupError: unknown) => {
          console.warn(
            JSON.stringify({
              event: "blob_operation_retirement_failed",
              error:
                cleanupError instanceof Error
                  ? cleanupError.name
                  : "UnknownError",
            }),
          );
        });
      }
      if (error instanceof ApiError) throw error;
      throw new ApiError(
        503,
        "blob_storage_unavailable",
        "blob storage is temporarily unavailable",
      );
    }
  } finally {
    await releaseRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
  }
}

async function getBlob(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  digest: string,
): Promise<Response> {
  const auth = await authenticateForRepository(
    request,
    env,
    ctx,
    repositoryId,
    "read",
  );
  const repository = await requireRepository(
    env.DB,
    auth.tenantId,
    repositoryId,
  );
  requireRepositoryGenerationRequest(request, repository.generation_id);
  const row = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
  if (row === null || row.state !== "ready")
    throw new ApiError(404, "not_found", "blob not found");
  const key = blobKey(
    auth.tenantId,
    repositoryId,
    repository.generation_id,
    digest,
    row.incarnation_id,
  );
  const storedIdentity = blobR2Identity(row);
  if (storedIdentity !== null && storedIdentity.key !== key) {
    throw new ApiError(
      409,
      "blob_integrity_failure",
      "blob storage key diverged from its generation",
    );
  }
  const verified = await verifyR2Object(
    env.BLOBS,
    key,
    digest,
    row.size_bytes,
    row.incarnation_id,
    storedIdentity,
  );
  if (verified.state !== "valid" || verified.bytes === undefined) {
    await quarantineOrFailOnStateChange(
      env.DB,
      auth,
      repositoryId,
      repository.generation_id,
      digest,
      row.incarnation_id,
      "r2_integrity_failure",
    );
    throw new ApiError(
      409,
      "blob_integrity_failure",
      "blob failed storage integrity validation",
    );
  }
  const stillReady = await env.DB.prepare(
    `SELECT 1 AS present
       FROM blobs blob
       JOIN repositories repository
         ON repository.tenant_id = blob.tenant_id
        AND repository.id = blob.repository_id
      WHERE blob.tenant_id = ? AND blob.repository_id = ? AND blob.digest = ?
        AND blob.incarnation_id = ? AND blob.size_bytes = ? AND blob.state = 'ready'
        AND repository.generation_id = ? AND repository.deleted_at IS NULL`,
  )
    .bind(
      auth.tenantId,
      repositoryId,
      digest,
      row.incarnation_id,
      row.size_bytes,
      repository.generation_id,
    )
    .first<{ present: number }>();
  if (stillReady === null) {
    await requireRepositoryGeneration(
      env.DB,
      auth.tenantId,
      repositoryId,
      repository.generation_id,
    );
    throw new ApiError(
      409,
      "blob_state_changed",
      "blob changed during integrity verification",
    );
  }
  if (request.method === "HEAD") {
    return emptyResponse(
      200,
      blobHeaders(digest, row.size_bytes, repository.generation_id),
    );
  }
  return new Response(verified.bytes, {
    status: 200,
    headers: blobHeaders(digest, row.size_bytes, repository.generation_id),
  });
}

async function deleteBlob(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  digest: string,
): Promise<Response> {
  const auth = await authenticateForRepository(
    request,
    env,
    ctx,
    repositoryId,
    "delete",
  );
  const repository = await requireRepository(
    env.DB,
    auth.tenantId,
    repositoryId,
  );
  requireRepositoryGenerationRequest(request, repository.generation_id);
  const writeLease = await acquireRepositoryWriteLease(
    env.DB,
    auth.tenantId,
    repositoryId,
    repository.generation_id,
  );
  try {
    await renewRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
    let row = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
    await renewRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
    if (row === null) throw new ApiError(404, "not_found", "blob not found");
    const selectedIncarnation = row.incarnation_id;
    if (row.state === "pending") {
      if (!auth.permissions.has("admin")) {
        throw new ApiError(
          409,
          "blob_pending",
          "pending upload cancellation requires admin permission",
        );
      }
      const now = nowSeconds();
      const cutoff = now - PENDING_CANCEL_AFTER_SECONDS;
      const deleteAt = now + PENDING_DELETE_GRACE_SECONDS;
      const transition = env.DB.prepare(
        `UPDATE blobs
          SET state = 'deleting', updated_at = ?, next_reconcile_at = ?, delete_not_before = ?
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?
          AND incarnation_id = ?
          AND state = 'pending' AND updated_at <= ?
          AND EXISTS (
            SELECT 1 FROM repositories repository
             WHERE repository.tenant_id = blobs.tenant_id
               AND repository.id = blobs.repository_id
               AND repository.generation_id = ? AND repository.deleted_at IS NULL
          )`,
      ).bind(
        now,
        deleteAt,
        deleteAt,
        auth.tenantId,
        repositoryId,
        digest,
        selectedIncarnation,
        cutoff,
        writeLease.generationId,
      );
      const cancellationAudit = await blobPendingCancellationAuditStatement(
        env.DB,
        auth,
        repositoryId,
        writeLease.generationId,
        digest,
        selectedIncarnation,
        cutoff,
        deleteAt,
      );
      const cancellationResults = await env.DB.batch([
        cancellationAudit,
        transition,
      ]);
      if (cancellationResults.some((result) => result.meta.changes === 0)) {
        await requireRepositoryGeneration(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease.generationId,
        );
        throw new ApiError(
          409,
          "blob_pending",
          "pending upload is still inside its cancellation lease",
        );
      }
      await env.BLOBS.delete(
        blobKey(
          auth.tenantId,
          repositoryId,
          repository.generation_id,
          digest,
          selectedIncarnation,
        ),
      );
      await renewRepositoryWriteLease(
        env.DB,
        auth.tenantId,
        repositoryId,
        writeLease,
      );
      const current = await env.DB.prepare(
        `SELECT 1 AS present
         FROM blobs blob
         JOIN repositories repository
           ON repository.tenant_id = blob.tenant_id
          AND repository.id = blob.repository_id
        WHERE blob.tenant_id = ? AND blob.repository_id = ? AND blob.digest = ?
          AND blob.incarnation_id = ? AND blob.state = 'deleting'
          AND blob.delete_not_before = ? AND repository.generation_id = ?
          AND repository.deleted_at IS NULL`,
      )
        .bind(
          auth.tenantId,
          repositoryId,
          digest,
          selectedIncarnation,
          deleteAt,
          writeLease.generationId,
        )
        .first<{ present: number }>();
      if (current === null) {
        await requireRepositoryGeneration(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease.generationId,
        );
        throw new ApiError(
          409,
          "blob_state_changed",
          "blob changed during cancellation",
        );
      }
      return emptyResponse(202, {
        "retry-after": String(PENDING_DELETE_GRACE_SECONDS),
        ...repositoryGenerationBindingHeader(writeLease.generationId),
      });
    }
    if (row.state === "quarantined" && !auth.permissions.has("admin")) {
      throw new ApiError(
        403,
        "admin_required",
        "quarantine remediation requires admin permission",
      );
    }
    if (row.state !== "deleting") {
      const transitionTime = nowSeconds();
      const transition = await env.DB.prepare(
        `UPDATE blobs
          SET state = 'deleting', updated_at = ?, next_reconcile_at = ?, delete_not_before = ?
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?
          AND incarnation_id = ?
          AND state IN ('ready', 'quarantined')
          AND NOT EXISTS (
            SELECT 1 FROM manifests
             WHERE tenant_id = ? AND repository_id = ? AND state != 'deleted'
               AND (stdout_digest = ? OR stderr_digest = ?)
          )
          AND EXISTS (
            SELECT 1 FROM repositories repository
             WHERE repository.tenant_id = blobs.tenant_id
               AND repository.id = blobs.repository_id
               AND repository.generation_id = ? AND repository.deleted_at IS NULL
          )`,
      )
        .bind(
          transitionTime,
          transitionTime,
          transitionTime,
          auth.tenantId,
          repositoryId,
          digest,
          selectedIncarnation,
          auth.tenantId,
          repositoryId,
          digest,
          digest,
          writeLease.generationId,
        )
        .run();
      if (transition.meta.changes === 0) {
        await requireRepositoryGeneration(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease.generationId,
        );
        row = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
        if (
          row?.state !== "deleting" ||
          row.incarnation_id !== selectedIncarnation
        ) {
          throw new ApiError(
            409,
            "blob_referenced",
            "blob is referenced or changed state",
          );
        }
      } else {
        row = await blobRow(env.DB, auth.tenantId, repositoryId, digest);
        if (row === null || row.incarnation_id !== selectedIncarnation) {
          throw new ApiError(
            409,
            "blob_state_changed",
            "blob changed during deletion",
          );
        }
      }
    }
    if ((row.delete_not_before ?? 0) > nowSeconds()) {
      await renewRepositoryWriteLease(
        env.DB,
        auth.tenantId,
        repositoryId,
        writeLease,
      );
      const current = await env.DB.prepare(
        `SELECT 1 AS present
         FROM blobs blob
         JOIN repositories repository
           ON repository.tenant_id = blob.tenant_id
          AND repository.id = blob.repository_id
        WHERE blob.tenant_id = ? AND blob.repository_id = ? AND blob.digest = ?
          AND blob.incarnation_id = ? AND blob.state = 'deleting'
          AND blob.delete_not_before = ?
          AND repository.generation_id = ? AND repository.deleted_at IS NULL`,
      )
        .bind(
          auth.tenantId,
          repositoryId,
          digest,
          selectedIncarnation,
          row.delete_not_before,
          writeLease.generationId,
        )
        .first<{ present: number }>();
      if (current === null) {
        await requireRepositoryGeneration(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease.generationId,
        );
        throw new ApiError(
          409,
          "blob_state_changed",
          "blob changed during deletion grace",
        );
      }
      const retryAfter = Math.max(
        1,
        (row.delete_not_before ?? nowSeconds()) - nowSeconds(),
      );
      return emptyResponse(202, {
        "retry-after": String(retryAfter),
        ...repositoryGenerationBindingHeader(writeLease.generationId),
      });
    }
    const key = blobKey(
      auth.tenantId,
      repositoryId,
      repository.generation_id,
      digest,
      selectedIncarnation,
    );
    await env.BLOBS.delete(key);
    if ((await env.BLOBS.head(key)) !== null) {
      throw new ApiError(
        503,
        "delete_incomplete",
        "blob deletion will be retried",
      );
    }
    await renewRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
    const deletion = env.DB.prepare(
      `DELETE FROM blobs
      WHERE tenant_id = ? AND repository_id = ? AND digest = ? AND state = 'deleting'
        AND incarnation_id = ?
        AND EXISTS (
          SELECT 1 FROM repositories repository
           WHERE repository.tenant_id = blobs.tenant_id
             AND repository.id = blobs.repository_id
             AND repository.generation_id = ? AND repository.deleted_at IS NULL
        )`,
    ).bind(
      auth.tenantId,
      repositoryId,
      digest,
      selectedIncarnation,
      writeLease.generationId,
    );
    const audit = await blobDeleteAuditStatement(
      env.DB,
      auth,
      repositoryId,
      writeLease.generationId,
      digest,
      selectedIncarnation,
      row.size_bytes,
    );
    const results = await env.DB.batch([audit, deletion]);
    if ((results[1]?.meta.changes ?? 0) !== 0) {
      if ((results[0]?.meta.changes ?? 0) === 0)
        throw repositoryGenerationChanged();
    } else {
      await requireRepositoryGeneration(
        env.DB,
        auth.tenantId,
        repositoryId,
        writeLease.generationId,
      );
      const current = await blobRow(
        env.DB,
        auth.tenantId,
        repositoryId,
        digest,
      );
      if (current !== null) {
        throw new ApiError(
          409,
          "blob_state_changed",
          "blob state changed during deletion",
        );
      }
    }
    return emptyResponse(
      204,
      repositoryGenerationBindingHeader(writeLease.generationId),
    );
  } finally {
    await releaseRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
  }
}

async function putManifest(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  requestKey: string,
): Promise<Response> {
  const auth = await authenticateForRepository(
    request,
    env,
    ctx,
    repositoryId,
    "write",
  );
  const repository = await requireRepository(
    env.DB,
    auth.tenantId,
    repositoryId,
  );
  requireRepositoryGenerationRequest(request, repository.generation_id);
  const body = await readJsonObject(request, MAX_JSON_SIZE);
  const now = nowSeconds();
  const manifest = parseServiceManifest(body, now);
  assertManifestBindings(
    manifest,
    auth,
    repositoryId,
    repository.generation_id,
    requestKey,
  );
  await requireRepositoryGeneration(
    env.DB,
    auth.tenantId,
    repositoryId,
    repository.generation_id,
  );
  const writeLease = await acquireRepositoryWriteLease(
    env.DB,
    auth.tenantId,
    repositoryId,
    repository.generation_id,
  );
  try {
    await renewRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
    const key = await producerKey(
      env.DB,
      auth.tenantId,
      repositoryId,
      manifest.signature.key_id,
    );
    let trustAuthorization: EncryptedManifestTrustAuthorization | null = null;
    let verificationKeyHex: string;
    if (manifest.schema_version === 2) {
      trustAuthorization = await authorizeEncryptedManifestWithCurrentTrust(
        env.DB,
        auth,
        repositoryId,
        new URL(request.url).origin,
        manifest,
        now,
      );
      verificationKeyHex = trustAuthorization.publicKeyHex;
      if (
        key === null ||
        key.revoked_at !== null ||
        key.producer_id !== manifest.producer_id ||
        key.public_key_hex !== verificationKeyHex
      ) {
        throw new ApiError(
          422,
          "producer_registry_mismatch",
          "current signed trust and immutable producer registration must match",
        );
      }
    } else {
      if (
        key === null ||
        key.revoked_at !== null ||
        key.producer_id !== manifest.producer_id
      ) {
        throw new ApiError(
          422,
          "untrusted_producer",
          "manifest producer key is not trusted",
        );
      }
      verificationKeyHex = key.public_key_hex;
    }
    if (trustAuthorization === null) {
      throw new ApiError(
        422,
        "unsupported_schema",
        "manifest schema_version must be 2 so repository generation is signed",
      );
    }
    if (!(await verifyServiceManifestSignature(manifest, verificationKeyHex))) {
      if (
        !(await writeGenerationGuardedAudit(
          env.DB,
          auth,
          repositoryId,
          writeLease.generationId,
          "manifest.put",
          "manifest",
          requestKey,
          "invalid_signature",
        ))
      ) {
        throw repositoryGenerationChanged();
      }
      throw new ApiError(
        422,
        "invalid_signature",
        "manifest signature verification failed",
      );
    }
    const stdoutBlob = serviceBlobRef(manifest.stdout);
    const stderrBlob = serviceBlobRef(manifest.stderr);
    await requireReadyBlob(env.DB, auth.tenantId, repositoryId, stdoutBlob);
    await requireReadyBlob(env.DB, auth.tenantId, repositoryId, stderrBlob);

    const bodyJson = canonicalServiceManifestJson(manifest);
    const bodySha256 = await sha256Hex(bodyJson);
    const existingByRequest = await manifestRow(
      env.DB,
      auth.tenantId,
      repositoryId,
      "request_key",
      requestKey,
    );
    if (existingByRequest !== null) {
      await renewRepositoryWriteLease(
        env.DB,
        auth.tenantId,
        repositoryId,
        writeLease,
      );
      return handleManifestExisting(
        env.DB,
        auth,
        repositoryId,
        writeLease.generationId,
        requestKey,
        bodySha256,
        existingByRequest,
        trustAuthorization,
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
      await renewRepositoryWriteLease(
        env.DB,
        auth.tenantId,
        repositoryId,
        writeLease,
      );
      await quarantineManifestConflict(
        env.DB,
        auth,
        repositoryId,
        writeLease.generationId,
        existingByRecord.request_key,
        existingByRecord.body_sha256,
        bodySha256,
        "record_id_conflict",
      );
      throw new ApiError(
        409,
        "manifest_conflict",
        "record id is already bound to another manifest",
      );
    }

    const audit = await manifestPutAuditStatement(
      env.DB,
      auth,
      repositoryId,
      writeLease.generationId,
      requestKey,
      manifest.signature.key_id,
      manifest.producer_id,
      verificationKeyHex,
    );
    try {
      await renewRepositoryWriteLease(
        env.DB,
        auth.tenantId,
        repositoryId,
        writeLease,
      );
      if (manifest.expires_at_unix_seconds <= nowSeconds()) {
        throw new ApiError(
          422,
          "expired_manifest",
          "manifest expired before commit",
        );
      }
      const results = await env.DB.batch([
        audit,
        env.DB.prepare(
          `INSERT INTO manifests(
           tenant_id, repository_id, request_key, record_id, body_sha256, body_json,
           state, producer_id, key_id, stdout_digest, stdout_size_bytes,
           stderr_digest, stderr_size_bytes, created_at, expires_at,
           trust_epoch, trust_body_sha256
         )
         SELECT ?, ?, ?, ?, ?, ?, 'ready', ?, ?, ?, ?, ?, ?, ?, ?, ?, ?
          WHERE EXISTS (
            SELECT 1 FROM repositories repository
             WHERE repository.tenant_id = ? AND repository.id = ?
               AND repository.generation_id = ? AND repository.deleted_at IS NULL
          )
           AND EXISTS (
             SELECT 1 FROM producer_keys producer
              WHERE producer.tenant_id = ? AND producer.repository_id = ?
                AND producer.key_id = ? AND producer.producer_id = ?
                AND producer.public_key_hex = ? AND producer.revoked_at IS NULL
           )`,
        ).bind(
          auth.tenantId,
          repositoryId,
          requestKey,
          manifest.record_id,
          bodySha256,
          bodyJson,
          manifest.producer_id,
          manifest.signature.key_id,
          stdoutBlob.digest,
          stdoutBlob.size_bytes,
          stderrBlob.digest,
          stderrBlob.size_bytes,
          manifest.created_at_unix_seconds,
          manifest.expires_at_unix_seconds,
          trustAuthorization?.epoch ?? null,
          trustAuthorization?.bodySha256 ?? null,
          auth.tenantId,
          repositoryId,
          writeLease.generationId,
          auth.tenantId,
          repositoryId,
          manifest.signature.key_id,
          manifest.producer_id,
          verificationKeyHex,
        ),
      ]);
      if (
        (results[0]?.meta.changes ?? 0) === 0 ||
        (results[1]?.meta.changes ?? 0) === 0
      ) {
        await requireRepositoryGeneration(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease.generationId,
        );
        throw new ApiError(
          409,
          "trust_changed",
          "producer authorization changed before commit",
        );
      }
    } catch (error: unknown) {
      if (databaseErrorContains(error, "expired_manifest")) {
        throw new ApiError(
          422,
          "expired_manifest",
          "manifest expired before commit",
        );
      }
      if (String(error).includes("blob_unavailable")) {
        throw new ApiError(
          422,
          "blob_unavailable",
          "manifest references a blob that is no longer ready",
        );
      }
      if (databaseErrorContains(error, "manifest_producer_unavailable")) {
        throw new ApiError(
          409,
          "trust_changed",
          "producer authorization changed while the manifest was being committed",
        );
      }
      if (
        databaseErrorContains(error, "encrypted_manifest_trust_required") ||
        databaseErrorContains(error, "encrypted_manifest_trust_changed")
      ) {
        throw new ApiError(
          409,
          "trust_changed",
          "signed trust changed while the encrypted manifest was being committed",
        );
      }
      const racedByRequest = await manifestRow(
        env.DB,
        auth.tenantId,
        repositoryId,
        "request_key",
        requestKey,
      );
      if (racedByRequest !== null) {
        await renewRepositoryWriteLease(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease,
        );
        return handleManifestExisting(
          env.DB,
          auth,
          repositoryId,
          writeLease.generationId,
          requestKey,
          bodySha256,
          racedByRequest,
          trustAuthorization,
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
        await renewRepositoryWriteLease(
          env.DB,
          auth.tenantId,
          repositoryId,
          writeLease,
        );
        await quarantineManifestConflict(
          env.DB,
          auth,
          repositoryId,
          writeLease.generationId,
          racedByRecord.request_key,
          racedByRecord.body_sha256,
          bodySha256,
          "record_id_conflict",
        );
        throw new ApiError(
          409,
          "manifest_conflict",
          "record id raced with another manifest",
        );
      }
      throw error;
    }
    return emptyResponse(201, {
      "x-again-body-sha256": bodySha256,
      ...repositoryGenerationBindingHeader(writeLease.generationId),
    });
  } finally {
    await releaseRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
  }
}

async function loadReusableManifestCandidate(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  generationId: string,
  requestKey: string,
  endpointOrigin: string,
): Promise<ReusableManifestCandidate> {
  await requireRepositoryGeneration(
    db,
    auth.tenantId,
    repositoryId,
    generationId,
  );
  const row = await manifestRow(
    db,
    auth.tenantId,
    repositoryId,
    "request_key",
    requestKey,
  );
  if (row === null || row.state === "deleted") throw manifestNotFound();
  if (row.state !== "ready") {
    throw new ApiError(
      409,
      "manifest_state_corrupt",
      "manifest is not reusable",
    );
  }
  let parsedBody: Record<string, unknown>;
  try {
    const decoded = JSON.parse(row.body_json) as unknown;
    if (
      typeof decoded !== "object" ||
      decoded === null ||
      Array.isArray(decoded)
    ) {
      throw new Error("manifest body is not an object");
    }
    parsedBody = decoded as Record<string, unknown>;
  } catch {
    throw new ApiError(
      409,
      "manifest_state_corrupt",
      "stored manifest body is invalid",
    );
  }
  let manifest: ServiceManifest;
  try {
    manifest = parseServiceManifest(parsedBody, null);
  } catch {
    throw new ApiError(
      409,
      "manifest_state_corrupt",
      "stored manifest body is invalid",
    );
  }
  if (manifest.schema_version !== 2) {
    throw new ApiError(
      409,
      "manifest_state_corrupt",
      "stored manifest is not encrypted v2",
    );
  }
  const stdoutRef = serviceBlobRef(manifest.stdout);
  const stderrRef = serviceBlobRef(manifest.stderr);
  if (
    canonicalServiceManifestJson(manifest) !== row.body_json ||
    (await sha256Hex(row.body_json)) !== row.body_sha256 ||
    manifest.tenant_id !== auth.tenantId ||
    manifest.repository_id !== repositoryId ||
    manifest.generation_id !== generationId ||
    manifest.request_key !== row.request_key ||
    manifest.request_key !== requestKey ||
    manifest.record_id !== row.record_id ||
    manifest.producer_id !== row.producer_id ||
    manifest.signature.key_id !== row.key_id ||
    manifest.created_at_unix_seconds !== row.created_at ||
    manifest.expires_at_unix_seconds !== row.expires_at ||
    stdoutRef.digest !== row.stdout_digest ||
    stdoutRef.size_bytes !== row.stdout_size_bytes ||
    stderrRef.digest !== row.stderr_digest ||
    stderrRef.size_bytes !== row.stderr_size_bytes
  ) {
    throw new ApiError(
      409,
      "manifest_state_corrupt",
      "stored manifest metadata diverged",
    );
  }
  if (
    row.producer_key_id === null ||
    row.producer_public_key_hex === null ||
    row.producer_key_producer_id !== row.producer_id ||
    row.trust_epoch === null ||
    row.trust_body_sha256 === null
  ) {
    throw new ApiError(
      409,
      "manifest_state_corrupt",
      "stored manifest provenance is invalid",
    );
  }
  if (
    !(await verifyEncryptedManifestV2Signature(
      manifest,
      row.producer_public_key_hex,
    ))
  ) {
    throw new ApiError(
      409,
      "manifest_state_corrupt",
      "stored encrypted manifest signature is invalid",
    );
  }
  const [stdout, stderr] = await Promise.all([
    blobRow(db, auth.tenantId, repositoryId, row.stdout_digest),
    blobRow(db, auth.tenantId, repositoryId, row.stderr_digest),
  ]);
  if (
    stdout?.state !== "ready" ||
    stdout.size_bytes !== row.stdout_size_bytes ||
    stderr?.state !== "ready" ||
    stderr.size_bytes !== row.stderr_size_bytes
  ) {
    throw new ApiError(
      409,
      "manifest_state_corrupt",
      "manifest references unavailable blobs",
    );
  }
  await requireRepositoryGeneration(
    db,
    auth.tenantId,
    repositoryId,
    generationId,
  );
  const now = nowSeconds();
  if (
    manifest.expires_at_unix_seconds <= now ||
    manifest.created_at_unix_seconds > now
  ) {
    throw manifestNotFound();
  }
  let trustAuthorization: EncryptedManifestTrustAuthorization;
  try {
    trustAuthorization = await authorizeEncryptedManifestWithCurrentTrust(
      db,
      auth,
      repositoryId,
      endpointOrigin,
      manifest,
      nowSeconds(),
    );
  } catch (error: unknown) {
    await requireRepositoryGeneration(
      db,
      auth.tenantId,
      repositoryId,
      generationId,
    );
    if (error instanceof ApiError && error.code === "trust_state_corrupt")
      throw error;
    if (
      error instanceof ApiError &&
      [
        "record_revoked",
        "producer_revoked",
        "untrusted_producer",
        "policy_not_allowed",
        "execution_profile_not_allowed",
        "platform_not_allowed",
        "image_not_allowed",
      ].includes(error.code)
    ) {
      throw manifestNotFound();
    }
    if (error instanceof ApiError && error.code === "not_found") {
      throw repositoryGenerationChanged();
    }
    throw error;
  }
  await requireRepositoryGeneration(
    db,
    auth.tenantId,
    repositoryId,
    generationId,
  );
  // A database producer revocation is a miss only after current signed trust
  // has itself been proven valid and fresh.
  if (row.key_revoked_at !== null) throw manifestNotFound();
  return { row, manifest, stdout, stderr, trustAuthorization };
}

async function getManifest(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  requestKey: string,
): Promise<Response> {
  const auth = await authenticateForRepository(
    request,
    env,
    ctx,
    repositoryId,
    "read",
  );
  const repository = await requireRepository(
    env.DB,
    auth.tenantId,
    repositoryId,
  );
  requireRepositoryGenerationRequest(request, repository.generation_id);
  const candidate = await loadReusableManifestCandidate(
    env.DB,
    auth,
    repositoryId,
    repository.generation_id,
    requestKey,
    new URL(request.url).origin,
  );
  const {
    row,
    manifest,
    trustAuthorization: releaseTrustAuthorization,
  } = candidate;
  const headers = new Headers({
    "cache-control": "private, no-store",
    "content-type": "application/json; charset=utf-8",
    "x-again-body-sha256": row.body_sha256,
    "x-content-type-options": "nosniff",
    ...repositoryGenerationBindingHeader(repository.generation_id),
  });
  const releaseFence = await env.DB.prepare(
    `SELECT 1 AS present
         FROM repositories repository
         JOIN manifests manifest
           ON manifest.tenant_id = repository.tenant_id
          AND manifest.repository_id = repository.id
         JOIN producer_keys producer
           ON producer.tenant_id = manifest.tenant_id
          AND producer.repository_id = manifest.repository_id
          AND producer.key_id = manifest.key_id
        WHERE repository.tenant_id = ? AND repository.id = ?
          AND repository.generation_id = ? AND repository.deleted_at IS NULL
          AND manifest.request_key = ? AND manifest.body_sha256 = ?
          AND manifest.state = 'ready' AND manifest.expires_at > unixepoch()
          AND manifest.created_at <= unixepoch()
          AND producer.key_id = ? AND producer.producer_id = ?
          AND producer.public_key_hex = ? AND producer.revoked_at IS NULL
          AND EXISTS (
            SELECT 1 FROM blobs stdout_blob
             WHERE stdout_blob.tenant_id = manifest.tenant_id
               AND stdout_blob.repository_id = manifest.repository_id
               AND stdout_blob.digest = manifest.stdout_digest
               AND stdout_blob.size_bytes = manifest.stdout_size_bytes
               AND stdout_blob.state = 'ready'
          )
          AND EXISTS (
            SELECT 1 FROM blobs stderr_blob
             WHERE stderr_blob.tenant_id = manifest.tenant_id
               AND stderr_blob.repository_id = manifest.repository_id
               AND stderr_blob.digest = manifest.stderr_digest
               AND stderr_blob.size_bytes = manifest.stderr_size_bytes
               AND stderr_blob.state = 'ready'
          )
          AND (
            ? IS NULL
            OR EXISTS (
              SELECT 1 FROM trust_heads head
              JOIN trust_root_keys root
                ON root.tenant_id = head.tenant_id
               AND root.repository_id = head.repository_id
               AND root.root_key_id = head.root_key_id
             WHERE head.tenant_id = manifest.tenant_id
               AND head.repository_id = manifest.repository_id
               AND head.epoch = ? AND head.body_sha256 = ?
               AND head.expires_at > unixepoch() AND root.disabled_at IS NULL
            )
          )`,
  )
    .bind(
      auth.tenantId,
      repositoryId,
      repository.generation_id,
      requestKey,
      row.body_sha256,
      row.key_id,
      row.producer_id,
      row.producer_public_key_hex,
      releaseTrustAuthorization?.epoch ?? null,
      releaseTrustAuthorization?.epoch ?? null,
      releaseTrustAuthorization?.bodySha256 ?? null,
    )
    .first<{ present: number }>();
  if (releaseFence === null) {
    await requireRepositoryGeneration(
      env.DB,
      auth.tenantId,
      repositoryId,
      repository.generation_id,
    );
    const current = await manifestRow(
      env.DB,
      auth.tenantId,
      repositoryId,
      "request_key",
      requestKey,
    );
    await requireRepositoryGeneration(
      env.DB,
      auth.tenantId,
      repositoryId,
      repository.generation_id,
    );
    const releaseNow = nowSeconds();
    if (
      current === null ||
      current.state === "deleted" ||
      current.expires_at <= releaseNow ||
      current.created_at > releaseNow
    ) {
      throw manifestNotFound();
    }
    if (
      current.state !== "ready" ||
      current.body_sha256 !== row.body_sha256 ||
      current.producer_key_id === null ||
      current.producer_public_key_hex === null
    ) {
      throw new ApiError(
        409,
        "manifest_state_corrupt",
        "manifest changed during verification",
      );
    }
    const [currentStdout, currentStderr] = await Promise.all([
      blobRow(env.DB, auth.tenantId, repositoryId, current.stdout_digest),
      blobRow(env.DB, auth.tenantId, repositoryId, current.stderr_digest),
    ]);
    await requireRepositoryGeneration(
      env.DB,
      auth.tenantId,
      repositoryId,
      repository.generation_id,
    );
    if (
      currentStdout?.state !== "ready" ||
      currentStdout.size_bytes !== current.stdout_size_bytes ||
      currentStderr?.state !== "ready" ||
      currentStderr.size_bytes !== current.stderr_size_bytes
    ) {
      throw new ApiError(
        409,
        "manifest_state_corrupt",
        "manifest references unavailable blobs",
      );
    }
    if (releaseTrustAuthorization !== null) {
      if (manifest.schema_version !== 2) {
        throw new ApiError(
          409,
          "manifest_state_corrupt",
          "manifest trust provenance is invalid",
        );
      }
      let currentAuthorization: EncryptedManifestTrustAuthorization;
      try {
        currentAuthorization = await authorizeEncryptedManifestWithCurrentTrust(
          env.DB,
          auth,
          repositoryId,
          new URL(request.url).origin,
          manifest,
          nowSeconds(),
        );
      } catch (error: unknown) {
        if (error instanceof ApiError && error.code === "trust_state_corrupt")
          throw error;
        if (
          error instanceof ApiError &&
          [
            "record_revoked",
            "producer_revoked",
            "untrusted_producer",
            "policy_not_allowed",
            "execution_profile_not_allowed",
            "platform_not_allowed",
            "image_not_allowed",
          ].includes(error.code)
        ) {
          throw manifestNotFound();
        }
        if (error instanceof ApiError && error.code === "not_found") {
          throw repositoryGenerationChanged();
        }
        throw error;
      }
      if (
        currentAuthorization.epoch !== releaseTrustAuthorization.epoch ||
        currentAuthorization.bodySha256 !== releaseTrustAuthorization.bodySha256
      ) {
        throw new ApiError(
          409,
          "trust_changed",
          "trust changed during manifest verification",
        );
      }
      if (current.key_revoked_at !== null) throw manifestNotFound();
      throw new ApiError(
        409,
        "manifest_state_corrupt",
        "manifest changed during verification",
      );
    }
    throw new ApiError(
      409,
      "manifest_state_corrupt",
      "manifest changed during verification",
    );
  }
  return new Response(row.body_json, { status: 200, headers });
}

async function getLookupBundle(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  requestKey: string,
): Promise<Response> {
  const auth = await authenticateForRepository(
    request,
    env,
    ctx,
    repositoryId,
    "read",
  );
  const repository = await requireRepository(
    env.DB,
    auth.tenantId,
    repositoryId,
  );
  requireRepositoryGenerationRequest(request, repository.generation_id);
  const origin = new URL(request.url).origin;
  const candidate = await loadReusableManifestCandidate(
    env.DB,
    auth,
    repositoryId,
    repository.generation_id,
    requestKey,
    origin,
  );
  const stdoutIdentity = requireBundleBlobIdentity(
    candidate.stdout,
    auth.tenantId,
    repositoryId,
    repository.generation_id,
    candidate.row.stdout_digest,
  );
  const stderrIdentity = requireBundleBlobIdentity(
    candidate.stderr,
    auth.tenantId,
    repositoryId,
    repository.generation_id,
    candidate.row.stderr_digest,
  );

  const reads = await Promise.allSettled([
    getExactStreamedR2Object(
      env.BLOBS,
      stdoutIdentity,
      candidate.row.stdout_digest,
      candidate.row.stdout_size_bytes,
      candidate.stdout.incarnation_id,
    ),
    getExactStreamedR2Object(
      env.BLOBS,
      stderrIdentity,
      candidate.row.stderr_digest,
      candidate.row.stderr_size_bytes,
      candidate.stderr.incarnation_id,
    ),
  ]);
  const opened = reads
    .filter(
      (result): result is PromiseFulfilledResult<StreamedR2Object> =>
        result.status === "fulfilled",
    )
    .map((result) => result.value);
  const rejected = reads.find(
    (result): result is PromiseRejectedResult => result.status === "rejected",
  );
  if (rejected !== undefined) {
    await cancelStreamedR2Objects(opened, rejected.reason);
    throw rejected.reason;
  }
  const stdoutObject = opened[0];
  const stderrObject = opened[1];
  if (stdoutObject === undefined || stderrObject === undefined) {
    await cancelStreamedR2Objects(opened, "incomplete bundle R2 reads");
    throw new ApiError(
      503,
      "blob_storage_unavailable",
      "blob storage is temporarily unavailable",
    );
  }

  let handedOff = false;
  try {
    await requireRepositoryGeneration(
      env.DB,
      auth.tenantId,
      repositoryId,
      repository.generation_id,
    );
    // Reauthorize after both external reads. Revocation or allowlist changes
    // committed while either R2 GET was pending are therefore never released.
    const releaseAuthorization = await authorizeBundleCandidate(
      env.DB,
      auth,
      repositoryId,
      origin,
      candidate.manifest,
    );
    const releaseTrust = await requireVerifiedTrustHeadForBundle(
      env.DB,
      auth,
      repositoryId,
      repository.generation_id,
      origin,
      releaseAuthorization,
    );
    const final = await env.DB.prepare(
      `SELECT head.body_json AS trust_body_json
           FROM repositories repository
           JOIN manifests manifest
             ON manifest.tenant_id = repository.tenant_id
            AND manifest.repository_id = repository.id
           JOIN producer_keys producer
             ON producer.tenant_id = manifest.tenant_id
            AND producer.repository_id = manifest.repository_id
            AND producer.key_id = manifest.key_id
           JOIN blobs stdout_blob
             ON stdout_blob.tenant_id = manifest.tenant_id
            AND stdout_blob.repository_id = manifest.repository_id
            AND stdout_blob.digest = manifest.stdout_digest
           JOIN blobs stderr_blob
             ON stderr_blob.tenant_id = manifest.tenant_id
            AND stderr_blob.repository_id = manifest.repository_id
            AND stderr_blob.digest = manifest.stderr_digest
           JOIN trust_heads head
             ON head.tenant_id = manifest.tenant_id
            AND head.repository_id = manifest.repository_id
           JOIN trust_root_keys root
             ON root.tenant_id = head.tenant_id
            AND root.repository_id = head.repository_id
            AND root.root_key_id = head.root_key_id
          WHERE repository.tenant_id = ? AND repository.id = ?
            AND repository.generation_id = ? AND repository.deleted_at IS NULL
            AND manifest.request_key = ? AND manifest.body_sha256 = ?
            AND manifest.body_json = ? AND manifest.record_id = ?
            AND manifest.state = 'ready' AND manifest.expires_at > unixepoch()
            AND manifest.created_at <= unixepoch()
            AND manifest.created_at = ? AND manifest.expires_at = ?
            AND manifest.trust_epoch = ? AND manifest.trust_body_sha256 = ?
            AND manifest.producer_id = ? AND manifest.key_id = ?
            AND manifest.stdout_digest = ? AND manifest.stdout_size_bytes = ?
            AND manifest.stderr_digest = ? AND manifest.stderr_size_bytes = ?
            AND producer.producer_id = ? AND producer.public_key_hex = ?
            AND producer.revoked_at IS NULL
            AND stdout_blob.state = 'ready' AND stdout_blob.size_bytes = ?
            AND stdout_blob.incarnation_id = ? AND stdout_blob.r2_key = ?
            AND stdout_blob.r2_version = ? AND stdout_blob.r2_etag = ?
            AND stdout_blob.r2_sha256 = ?
            AND stderr_blob.state = 'ready' AND stderr_blob.size_bytes = ?
            AND stderr_blob.incarnation_id = ? AND stderr_blob.r2_key = ?
            AND stderr_blob.r2_version = ? AND stderr_blob.r2_etag = ?
            AND stderr_blob.r2_sha256 = ?
            AND head.epoch = ? AND head.body_sha256 = ? AND head.body_json = ?
            AND head.root_key_id = ? AND head.expires_at > unixepoch()
            AND root.public_key_hex = ? AND root.disabled_at IS NULL`,
    )
      .bind(
        auth.tenantId,
        repositoryId,
        repository.generation_id,
        requestKey,
        candidate.row.body_sha256,
        candidate.row.body_json,
        candidate.row.record_id,
        candidate.row.created_at,
        candidate.row.expires_at,
        candidate.row.trust_epoch,
        candidate.row.trust_body_sha256,
        candidate.row.producer_id,
        candidate.row.key_id,
        candidate.row.stdout_digest,
        candidate.row.stdout_size_bytes,
        candidate.row.stderr_digest,
        candidate.row.stderr_size_bytes,
        candidate.row.producer_id,
        candidate.row.producer_public_key_hex,
        candidate.row.stdout_size_bytes,
        candidate.stdout.incarnation_id,
        stdoutIdentity.key,
        stdoutIdentity.version,
        stdoutIdentity.etag,
        stdoutIdentity.sha256,
        candidate.row.stderr_size_bytes,
        candidate.stderr.incarnation_id,
        stderrIdentity.key,
        stderrIdentity.version,
        stderrIdentity.etag,
        stderrIdentity.sha256,
        releaseAuthorization.epoch,
        releaseAuthorization.bodySha256,
        releaseTrust.row.body_json,
        releaseTrust.row.root_key_id,
        releaseTrust.row.public_key_hex,
      )
      .first<{ trust_body_json: string }>();
    if (final === null) {
      await requireRepositoryGeneration(
        env.DB,
        auth.tenantId,
        repositoryId,
        repository.generation_id,
      );
      // Preserve the reference route's miss-versus-hard-error classifier for
      // trust and availability transitions that raced the final join.
      await loadReusableManifestCandidate(
        env.DB,
        auth,
        repositoryId,
        repository.generation_id,
        requestKey,
        origin,
      );
      throw new ApiError(
        409,
        "manifest_state_corrupt",
        "bundle state changed before release",
      );
    }
    const encoded = encodeLookupBundleV1({
      initialTrustJson: new TextEncoder().encode(final.trust_body_json),
      manifestJson: new TextEncoder().encode(candidate.row.body_json),
      stdoutCiphertext: {
        stream: stdoutObject.stream,
        length: candidate.row.stdout_size_bytes,
      },
      stderrCiphertext: {
        stream: stderrObject.stream,
        length: candidate.row.stderr_size_bytes,
      },
    });
    const response = new Response(encoded.body, {
      status: 200,
      headers: {
        "cache-control": "private, no-store",
        "content-length": String(encoded.contentLength),
        "content-type": LOOKUP_BUNDLE_V1_CONTENT_TYPE,
        "x-again-repository-generation": repository.generation_id,
        "x-content-type-options": "nosniff",
      },
    });
    handedOff = true;
    return response;
  } finally {
    if (!handedOff) {
      await cancelStreamedR2Objects(
        [stdoutObject, stderrObject],
        "bundle release failed",
      );
    }
  }
}

async function authorizeBundleCandidate(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  endpointOrigin: string,
  manifest: EncryptedRemoteCacheManifestV2,
): Promise<EncryptedManifestTrustAuthorization> {
  try {
    const authorization = await authorizeEncryptedManifestWithCurrentTrust(
      db,
      auth,
      repositoryId,
      endpointOrigin,
      manifest,
      nowSeconds(),
    );
    await requireRepositoryGeneration(
      db,
      auth.tenantId,
      repositoryId,
      manifest.generation_id,
    );
    return authorization;
  } catch (error: unknown) {
    await requireRepositoryGeneration(
      db,
      auth.tenantId,
      repositoryId,
      manifest.generation_id,
    );
    if (error instanceof ApiError && error.code === "trust_state_corrupt")
      throw error;
    if (
      error instanceof ApiError &&
      [
        "record_revoked",
        "producer_revoked",
        "untrusted_producer",
        "policy_not_allowed",
        "execution_profile_not_allowed",
        "platform_not_allowed",
        "image_not_allowed",
      ].includes(error.code)
    ) {
      throw manifestNotFound();
    }
    throw error;
  }
}

async function requireVerifiedTrustHeadForBundle(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  generationId: string,
  endpointOrigin: string,
  authorization: EncryptedManifestTrustAuthorization,
): Promise<{ row: TrustHeadRow; verified: VerifiedTrustHead }> {
  await requireRepositoryGeneration(
    db,
    auth.tenantId,
    repositoryId,
    generationId,
  );
  const row = await trustHead(db, auth.tenantId, repositoryId);
  if (
    row === null ||
    row.root_disabled_at !== null ||
    row.expires_at <= nowSeconds()
  ) {
    await requireRepositoryGeneration(
      db,
      auth.tenantId,
      repositoryId,
      generationId,
    );
    throw new ApiError(404, "not_found", "fresh trust bundle not found");
  }
  await requireRepositoryGeneration(
    db,
    auth.tenantId,
    repositoryId,
    generationId,
  );
  let verified: VerifiedTrustHead;
  try {
    verified = await verifyStoredTrustHead(row, nowSeconds());
  } catch {
    throw new ApiError(
      409,
      "trust_state_corrupt",
      "stored trust state failed validation",
    );
  }
  assertTrustBundleBindings(
    verified.bundle,
    auth,
    repositoryId,
    generationId,
    endpointOrigin,
  );
  await requireRepositoryGeneration(
    db,
    auth.tenantId,
    repositoryId,
    generationId,
  );
  if (
    row.epoch !== authorization.epoch ||
    row.body_sha256 !== authorization.bodySha256
  ) {
    throw new ApiError(
      409,
      "trust_changed",
      "trust changed during bundle authorization",
    );
  }
  return { row, verified };
}

function requireBundleBlobIdentity(
  row: BlobRow,
  tenantId: string,
  repositoryId: string,
  generationId: string,
  digest: string,
): R2Identity {
  const identity = blobR2Identity(row);
  const expectedKey = blobKey(
    tenantId,
    repositoryId,
    generationId,
    digest,
    row.incarnation_id,
  );
  if (identity === null || identity.key !== expectedKey) {
    throw new ApiError(
      409,
      "blob_integrity_failure",
      "blob lacks a generation-bound storage identity",
    );
  }
  return identity;
}

async function getExactStreamedR2Object(
  bucket: R2Bucket,
  identity: R2Identity,
  digest: string,
  size: number,
  incarnationId: string,
): Promise<StreamedR2Object> {
  let object: R2ObjectBody | R2Object | null;
  try {
    object = await bucket.get(identity.key, {
      onlyIf: { etagMatches: identity.etag },
    });
  } catch {
    throw new ApiError(
      503,
      "blob_storage_unavailable",
      "blob storage is temporarily unavailable",
    );
  }
  if (object === null || !("body" in object)) {
    throw new ApiError(
      409,
      "blob_integrity_failure",
      "blob storage identity is unavailable",
    );
  }
  const sha256 = object.checksums.sha256;
  if (
    object.key !== identity.key ||
    object.version !== identity.version ||
    object.etag !== identity.etag ||
    object.size !== size ||
    sha256 === undefined ||
    bytesToHex(new Uint8Array(sha256)) !== identity.sha256 ||
    object.customMetadata?.blake3 !== digest ||
    object.customMetadata?.size_bytes !== String(size) ||
    object.customMetadata?.incarnation_id !== incarnationId
  ) {
    await object.body
      .cancel("bundle R2 identity mismatch")
      .catch(() => undefined);
    throw new ApiError(
      409,
      "blob_integrity_failure",
      "blob failed storage identity validation",
    );
  }
  return { object, stream: object.body as ReadableStream<Uint8Array> };
}

async function cancelStreamedR2Objects(
  objects: readonly StreamedR2Object[],
  reason: unknown,
): Promise<void> {
  await Promise.allSettled(
    objects.map(async ({ stream }) => {
      if (!stream.locked) await stream.cancel(reason);
    }),
  );
}

async function deleteManifest(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
  requestKey: string,
): Promise<Response> {
  const auth = await authenticateForRepository(
    request,
    env,
    ctx,
    repositoryId,
    "delete",
  );
  const repository = await requireRepository(
    env.DB,
    auth.tenantId,
    repositoryId,
  );
  requireRepositoryGenerationRequest(request, repository.generation_id);
  const writeLease = await acquireRepositoryWriteLease(
    env.DB,
    auth.tenantId,
    repositoryId,
    repository.generation_id,
  );
  try {
    await renewRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
    const now = nowSeconds();
    const mutation = env.DB.prepare(
      `UPDATE manifests SET state = 'deleted', deleted_at = ?
      WHERE tenant_id = ? AND repository_id = ? AND request_key = ? AND state != 'deleted'
        AND EXISTS (
          SELECT 1 FROM repositories repository
           WHERE repository.tenant_id = manifests.tenant_id
             AND repository.id = manifests.repository_id
             AND repository.generation_id = ? AND repository.deleted_at IS NULL
        )`,
    ).bind(
      now,
      auth.tenantId,
      repositoryId,
      requestKey,
      writeLease.generationId,
    );
    const audit = await manifestDeleteAuditStatement(
      env.DB,
      auth,
      repositoryId,
      writeLease.generationId,
      requestKey,
    );
    const results = await env.DB.batch([audit, mutation]);
    if ((results[1]?.meta.changes ?? 0) === 0) {
      await requireRepositoryGeneration(
        env.DB,
        auth.tenantId,
        repositoryId,
        writeLease.generationId,
      );
      throw new ApiError(404, "not_found", "manifest not found");
    }
    if ((results[0]?.meta.changes ?? 0) === 0)
      throw repositoryGenerationChanged();
    return emptyResponse(
      204,
      repositoryGenerationBindingHeader(writeLease.generationId),
    );
  } finally {
    await releaseRepositoryWriteLease(
      env.DB,
      auth.tenantId,
      repositoryId,
      writeLease,
    );
  }
}

async function listAudit(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
): Promise<Response> {
  const auth = await authenticateForRepository(
    request,
    env,
    ctx,
    repositoryId,
    "audit",
  );
  const repository = await requireRepository(
    env.DB,
    auth.tenantId,
    repositoryId,
  );
  requireRepositoryGenerationRequest(request, repository.generation_id);
  const url = new URL(request.url);
  const limitText = url.searchParams.get("limit") ?? "50";
  const cursorText = url.searchParams.get("cursor");
  if (!/^\d+$/.test(limitText))
    throw new ApiError(400, "invalid_limit", "limit must be an integer");
  const limit = Number(limitText);
  if (!Number.isSafeInteger(limit) || limit < 1 || limit > 100) {
    throw new ApiError(400, "invalid_limit", "limit must be between 1 and 100");
  }
  let cursor = Number.MAX_SAFE_INTEGER;
  if (cursorText !== null) {
    if (!/^\d+$/.test(cursorText))
      throw new ApiError(400, "invalid_cursor", "cursor is invalid");
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
  await requireRepositoryGeneration(
    env.DB,
    auth.tenantId,
    repositoryId,
    repository.generation_id,
  );
  return jsonResponse(
    {
      events,
      next_cursor: events.length === limit ? (last?.id ?? null) : null,
    },
    200,
    repositoryGenerationBindingHeader(repository.generation_id),
  );
}

async function getStats(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string,
): Promise<Response> {
  const auth = await authenticateForRepository(
    request,
    env,
    ctx,
    repositoryId,
    "audit",
  );
  const repository = await requireRepository(
    env.DB,
    auth.tenantId,
    repositoryId,
  );
  requireRepositoryGenerationRequest(request, repository.generation_id);
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
       (SELECT count(*) FROM blob_object_orphan_candidates candidate
         WHERE candidate.tenant_id = ?) AS blob_orphan_candidate_count,
       (SELECT count(*) FROM blob_object_orphan_candidates candidate
         WHERE candidate.tenant_id = ? AND candidate.repository_id = ?
       ) AS blob_orphan_repository_count,
       (SELECT count(*) FROM repository_deletion_receipts receipt
         WHERE receipt.tenant_id = ?) AS repository_generation_history_count,
       (SELECT usage.used_units FROM tenant_trust_security_reserve_usage usage
         WHERE usage.tenant_id = ?) AS trust_security_reserve_used_units,
       (SELECT usage.used_units FROM repository_trust_security_reserve_usage usage
         WHERE usage.tenant_id = ? AND usage.repository_id = ?
       ) AS repository_trust_security_reserve_used_units,
       (SELECT count(*) FROM audit_events audit
         WHERE audit.tenant_id = ?) AS audit_event_count,
       t.used_bytes AS used_bytes,
       t.quota_bytes AS quota_bytes,
       t.used_metadata_units AS used_metadata_units,
       t.metadata_quota_units AS metadata_quota_units,
       t.blob_orphan_candidate_limit AS blob_orphan_candidate_limit,
       t.blob_orphan_repository_limit AS blob_orphan_repository_limit,
       t.repository_generation_history_limit AS repository_generation_history_limit,
       t.trust_security_reserve_limit AS trust_security_reserve_limit,
       t.trust_security_repository_limit AS trust_security_repository_limit,
       t.audit_event_limit AS audit_event_limit,
       t.audit_partition_limit AS audit_partition_limit
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
      auth.tenantId,
      repositoryId,
      auth.tenantId,
      auth.tenantId,
      auth.tenantId,
      repositoryId,
      auth.tenantId,
      auth.tenantId,
    )
    .first<StatsRow>();
  if (row === null) throw new ApiError(404, "not_found", "tenant not found");
  await requireRepositoryGeneration(
    env.DB,
    auth.tenantId,
    repositoryId,
    repository.generation_id,
  );
  if (auth.repositoryScope !== null) {
    return jsonResponse(
      {
        ready_blobs: row.ready_blobs,
        blob_bytes: row.blob_bytes,
        pending_blobs: row.pending_blobs,
        deleting_blobs: row.deleting_blobs,
        ready_manifests: row.ready_manifests,
        quarantined_blobs: row.quarantined_blobs,
        quarantined_manifests: row.quarantined_manifests,
        blob_orphan_repository_count: row.blob_orphan_repository_count,
        blob_orphan_repository_limit: row.blob_orphan_repository_limit,
        blob_orphan_repository_near_limit:
          row.blob_orphan_repository_count * 5 >=
          row.blob_orphan_repository_limit * 4,
        repository_trust_security_reserve_used_units:
          row.repository_trust_security_reserve_used_units,
        trust_security_repository_limit: row.trust_security_repository_limit,
        repository_trust_security_reserve_near_limit:
          row.repository_trust_security_reserve_used_units * 5 >=
          row.trust_security_repository_limit * 4,
      },
      200,
      repositoryGenerationBindingHeader(repository.generation_id),
    );
  }
  return jsonResponse(
    {
      ...row,
      blob_orphan_candidate_near_limit:
        row.blob_orphan_candidate_count * 5 >=
        row.blob_orphan_candidate_limit * 4,
      blob_orphan_repository_near_limit:
        row.blob_orphan_repository_count * 5 >=
        row.blob_orphan_repository_limit * 4,
      repository_generation_history_near_limit:
        row.repository_generation_history_count * 5 >=
        row.repository_generation_history_limit * 4,
      trust_security_reserve_near_limit:
        row.trust_security_reserve_used_units * 5 >=
        row.trust_security_reserve_limit * 4,
      repository_trust_security_reserve_near_limit:
        row.repository_trust_security_reserve_used_units * 5 >=
        row.trust_security_repository_limit * 4,
      audit_event_near_limit:
        row.audit_event_count * 5 >= row.audit_event_limit * 4,
    },
    200,
    repositoryGenerationBindingHeader(repository.generation_id),
  );
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

async function requireRepository(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
): Promise<RepositoryRow> {
  const row = await db
    .prepare(
      `SELECT id, generation_id, deleted_at FROM repositories
        WHERE tenant_id = ? AND id = ? AND deleted_at IS NULL`,
    )
    .bind(tenantId, repositoryId)
    .first<RepositoryRow>();
  if (row === null)
    throw new ApiError(404, "not_found", "repository not found");
  return row;
}

async function requireRepositoryGeneration(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  generationId: string,
): Promise<void> {
  const row = await db
    .prepare(
      `SELECT 1 AS present FROM repositories
      WHERE tenant_id = ? AND id = ? AND generation_id = ? AND deleted_at IS NULL`,
    )
    .bind(tenantId, repositoryId, generationId)
    .first<{ present: number }>();
  if (row === null) throw repositoryGenerationChanged();
}

async function repositoryRow(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
): Promise<RepositoryRow | null> {
  return db
    .prepare(
      `SELECT id, generation_id, deleted_at FROM repositories
        WHERE tenant_id = ? AND id = ?`,
    )
    .bind(tenantId, repositoryId)
    .first<RepositoryRow>();
}

async function repositoryDeletionRow(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
): Promise<RepositoryDeletionRow | null> {
  return db
    .prepare(
      `SELECT tenant_id, repository_id, generation_id, requested_at, r2_cursor,
              empty_confirmations, last_empty_at, attempts, next_attempt_at,
              lease_id, lease_until, phase, updated_at
         FROM repository_deletions
        WHERE tenant_id = ? AND repository_id = ?`,
    )
    .bind(tenantId, repositoryId)
    .first<RepositoryDeletionRow>();
}

async function repositoryDeletionReceipt(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  generationId: string,
): Promise<RepositoryDeletionReceiptRow | null> {
  return db
    .prepare(
      `SELECT requested_at, completed_at
         FROM repository_deletion_receipts
        WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?`,
    )
    .bind(tenantId, repositoryId, generationId)
    .first<RepositoryDeletionReceiptRow>();
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

async function requireProducerActiveBinding(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  generationId: string,
  keyId: string,
  producerId: string,
  publicKeyHexValue: string,
): Promise<void> {
  const row = await db
    .prepare(
      `SELECT 1 AS present
       FROM producer_keys key
       JOIN repositories repository
         ON repository.tenant_id = key.tenant_id
        AND repository.id = key.repository_id
      WHERE key.tenant_id = ? AND key.repository_id = ? AND key.key_id = ?
        AND key.producer_id = ? AND key.public_key_hex = ? AND key.revoked_at IS NULL
        AND repository.generation_id = ? AND repository.deleted_at IS NULL`,
    )
    .bind(
      tenantId,
      repositoryId,
      keyId,
      producerId,
      publicKeyHexValue,
      generationId,
    )
    .first<{ present: number }>();
  if (row === null) {
    await requireRepositoryGeneration(db, tenantId, repositoryId, generationId);
    throw new ApiError(
      409,
      "key_binding_conflict",
      "producer key changed before acknowledgement",
    );
  }
}

async function trustRootKey(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  rootKeyId: string,
): Promise<TrustRootRow | null> {
  return db
    .prepare(
      `SELECT public_key_hex, disabled_at
         FROM trust_root_keys
        WHERE tenant_id = ? AND repository_id = ? AND root_key_id = ?`,
    )
    .bind(tenantId, repositoryId, rootKeyId)
    .first<TrustRootRow>();
}

async function trustHead(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
): Promise<TrustHeadRow | null> {
  return db
    .prepare(
      `SELECT h.epoch, h.root_key_id, h.body_sha256, h.body_json,
              h.issued_at, h.expires_at, root.public_key_hex,
              root.disabled_at AS root_disabled_at
         FROM trust_heads h
         JOIN trust_root_keys root
           ON root.tenant_id = h.tenant_id
          AND root.repository_id = h.repository_id
          AND root.root_key_id = h.root_key_id
        WHERE h.tenant_id = ? AND h.repository_id = ?`,
    )
    .bind(tenantId, repositoryId)
    .first<TrustHeadRow>();
}

async function requireTrustHeadCurrentForAck(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  generationId: string,
  bundle: TrustBundleV1,
  bodySha256: string,
  bodyJson: string,
): Promise<void> {
  const row = await db
    .prepare(
      `SELECT 1 AS present
       FROM trust_heads head
       JOIN repositories repository
         ON repository.tenant_id = head.tenant_id
        AND repository.id = head.repository_id
       JOIN trust_root_keys root
         ON root.tenant_id = head.tenant_id
        AND root.repository_id = head.repository_id
        AND root.root_key_id = head.root_key_id
      WHERE head.tenant_id = ? AND head.repository_id = ?
        AND head.epoch = ? AND head.root_key_id = ?
        AND head.body_sha256 = ? AND head.body_json = ?
        AND head.issued_at = ? AND head.expires_at = ?
        AND head.expires_at > unixepoch() AND root.disabled_at IS NULL
        AND repository.generation_id = ? AND repository.deleted_at IS NULL`,
    )
    .bind(
      tenantId,
      repositoryId,
      bundle.epoch,
      bundle.root_key_id,
      bodySha256,
      bodyJson,
      bundle.issued_at_unix_seconds,
      bundle.expires_at_unix_seconds,
      generationId,
    )
    .first<{ present: number }>();
  if (row === null) {
    await requireRepositoryGeneration(db, tenantId, repositoryId, generationId);
    throw new ApiError(
      409,
      "trust_changed",
      "signed trust changed before acknowledgement",
    );
  }
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
              next_reconcile_at, delete_not_before, incarnation_id,
              r2_key, r2_version, r2_etag, r2_sha256
         FROM blobs
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?`,
    )
    .bind(tenantId, repositoryId, digest)
    .first<BlobRow>();
}

async function requireBlobReadyIncarnation(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  generationId: string,
  digest: string,
  incarnationId: string,
  sizeBytes: number,
): Promise<void> {
  const row = await db
    .prepare(
      `SELECT 1 AS present
       FROM blobs blob
       JOIN repositories repository
         ON repository.tenant_id = blob.tenant_id
        AND repository.id = blob.repository_id
      WHERE blob.tenant_id = ? AND blob.repository_id = ? AND blob.digest = ?
        AND blob.incarnation_id = ? AND blob.size_bytes = ? AND blob.state = 'ready'
        AND repository.generation_id = ? AND repository.deleted_at IS NULL`,
    )
    .bind(
      tenantId,
      repositoryId,
      digest,
      incarnationId,
      sizeBytes,
      generationId,
    )
    .first<{ present: number }>();
  if (row === null) {
    await requireRepositoryGeneration(db, tenantId, repositoryId, generationId);
    throw new ApiError(
      409,
      "blob_state_changed",
      "blob changed during verification",
    );
  }
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
              m.stdout_digest, m.stdout_size_bytes,
              m.stderr_digest, m.stderr_size_bytes,
              m.trust_epoch, m.trust_body_sha256,
              k.key_id AS producer_key_id,
              k.producer_id AS producer_key_producer_id,
              k.public_key_hex AS producer_public_key_hex,
              k.revoked_at AS key_revoked_at
         FROM manifests m
         LEFT JOIN producer_keys k
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
  generationId: string,
  requestKey: string,
  submittedSha: string,
  existing: ManifestRow,
  currentTrust: EncryptedManifestTrustAuthorization,
): Promise<Response> {
  if (existing.state === "ready" && existing.body_sha256 === submittedSha) {
    await requireManifestReadyForAck(
      db,
      auth.tenantId,
      repositoryId,
      generationId,
      requestKey,
      submittedSha,
      existing,
      currentTrust,
    );
    return emptyResponse(204, {
      "x-again-body-sha256": submittedSha,
      ...repositoryGenerationBindingHeader(generationId),
    });
  }
  if (existing.body_sha256 !== submittedSha) {
    await quarantineManifestConflict(
      db,
      auth,
      repositoryId,
      generationId,
      requestKey,
      existing.body_sha256,
      submittedSha,
      "request_key_conflict",
    );
  }
  throw new ApiError(
    409,
    "manifest_conflict",
    "request key is quarantined or conflicts with stored data",
  );
}

async function requireManifestReadyForAck(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  generationId: string,
  requestKey: string,
  bodySha256: string,
  captured: ManifestRow,
  currentTrust: EncryptedManifestTrustAuthorization,
): Promise<void> {
  const row = await db
    .prepare(
      `SELECT 1 AS present
       FROM manifests manifest
       JOIN repositories repository
         ON repository.tenant_id = manifest.tenant_id
        AND repository.id = manifest.repository_id
       JOIN producer_keys producer
         ON producer.tenant_id = manifest.tenant_id
        AND producer.repository_id = manifest.repository_id
        AND producer.key_id = manifest.key_id
      WHERE manifest.tenant_id = ? AND manifest.repository_id = ?
        AND manifest.request_key = ? AND manifest.body_sha256 = ?
        AND manifest.state = 'ready' AND manifest.expires_at > unixepoch()
        AND manifest.created_at <= unixepoch()
        AND producer.key_id = ? AND producer.producer_id = ?
        AND producer.public_key_hex = ? AND producer.revoked_at IS NULL
        AND repository.generation_id = ? AND repository.deleted_at IS NULL
        AND EXISTS (
          SELECT 1 FROM blobs stdout_blob
           WHERE stdout_blob.tenant_id = manifest.tenant_id
             AND stdout_blob.repository_id = manifest.repository_id
             AND stdout_blob.digest = manifest.stdout_digest
             AND stdout_blob.size_bytes = manifest.stdout_size_bytes
             AND stdout_blob.state = 'ready'
        )
        AND EXISTS (
          SELECT 1 FROM blobs stderr_blob
           WHERE stderr_blob.tenant_id = manifest.tenant_id
             AND stderr_blob.repository_id = manifest.repository_id
             AND stderr_blob.digest = manifest.stderr_digest
             AND stderr_blob.size_bytes = manifest.stderr_size_bytes
             AND stderr_blob.state = 'ready'
        )
        AND manifest.trust_epoch IS NOT NULL
        AND manifest.trust_body_sha256 IS NOT NULL
        AND manifest.trust_epoch <= ?
        AND EXISTS (
          SELECT 1 FROM trust_heads head
          JOIN trust_root_keys root
            ON root.tenant_id = head.tenant_id
           AND root.repository_id = head.repository_id
           AND root.root_key_id = head.root_key_id
         WHERE head.tenant_id = manifest.tenant_id
           AND head.repository_id = manifest.repository_id
           AND head.epoch = ?
           AND head.body_sha256 = ?
           AND head.expires_at > unixepoch() AND root.disabled_at IS NULL
        )`,
    )
    .bind(
      tenantId,
      repositoryId,
      requestKey,
      bodySha256,
      captured.key_id,
      captured.producer_id,
      captured.producer_public_key_hex,
      generationId,
      currentTrust.epoch,
      currentTrust.epoch,
      currentTrust.bodySha256,
    )
    .first<{ present: number }>();
  if (row === null) {
    await requireRepositoryGeneration(db, tenantId, repositoryId, generationId);
    throw new ApiError(
      409,
      "manifest_conflict",
      "manifest dependencies changed before acknowledgement",
    );
  }
}

async function quarantineManifestConflict(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  generationId: string,
  requestKey: string,
  existingSha: string,
  submittedSha: string,
  reason: string,
): Promise<void> {
  const now = nowSeconds();
  const targetHash = await sha256Hex(
    `${auth.tenantId}\0${repositoryId}\0manifest\0${requestKey}`,
  );
  const exactReadyGuard = `
    SELECT 1 FROM manifests manifest
    JOIN repositories repository
      ON repository.tenant_id = manifest.tenant_id
     AND repository.id = manifest.repository_id
   WHERE manifest.tenant_id = ? AND manifest.repository_id = ?
     AND manifest.request_key = ? AND manifest.state = 'ready'
     AND manifest.body_sha256 = ? AND repository.generation_id = ?
     AND repository.deleted_at IS NULL`;
  const results = await db.batch([
    db
      .prepare(
        `INSERT INTO audit_events(
         tenant_id, repository_id, actor, action, target_type,
         target_id_sha256, outcome, details_json, created_at
       )
       SELECT ?, ?, ?, 'manifest.quarantine', 'manifest', ?, ?, '{}', ?
        WHERE EXISTS (${exactReadyGuard})`,
      )
      .bind(
        auth.tenantId,
        repositoryId,
        auth.subject,
        targetHash,
        reason,
        now,
        auth.tenantId,
        repositoryId,
        requestKey,
        existingSha,
        generationId,
      ),
    db
      .prepare(
        `INSERT INTO manifest_conflicts(
         tenant_id, repository_id, request_key,
         existing_body_sha256, submitted_body_sha256, detected_at
       )
       SELECT ?, ?, ?, ?, ?, ?
        WHERE EXISTS (${exactReadyGuard})`,
      )
      .bind(
        auth.tenantId,
        repositoryId,
        requestKey,
        existingSha,
        submittedSha,
        now,
        auth.tenantId,
        repositoryId,
        requestKey,
        existingSha,
        generationId,
      ),
    db
      .prepare(
        `UPDATE manifests SET state = 'quarantined'
        WHERE tenant_id = ? AND repository_id = ? AND request_key = ?
          AND state = 'ready' AND body_sha256 = ?
          AND EXISTS (
            SELECT 1 FROM repositories repository
             WHERE repository.tenant_id = manifests.tenant_id
               AND repository.id = manifests.repository_id
               AND repository.generation_id = ? AND repository.deleted_at IS NULL
          )`,
      )
      .bind(auth.tenantId, repositoryId, requestKey, existingSha, generationId),
  ]);
  if (results.some((result) => result.meta.changes === 0)) {
    await requireRepositoryGeneration(
      db,
      auth.tenantId,
      repositoryId,
      generationId,
    );
    throw new ApiError(
      409,
      "manifest_conflict",
      "manifest changed during conflict handling",
    );
  }
}

function parseServiceManifest(
  value: Record<string, unknown>,
  now: number | null,
): ServiceManifest {
  if (value.schema_version === 2) return parseEncryptedManifestV2(value, now);
  throw new ApiError(
    422,
    "unsupported_schema",
    "manifest schema_version must be 2 so repository generation is signed",
  );
}

function canonicalServiceManifestJson(manifest: ServiceManifest): string {
  return manifest.schema_version === 1
    ? canonicalManifestJson(manifest)
    : JSON.stringify(manifest);
}

async function verifyServiceManifestSignature(
  manifest: ServiceManifest,
  publicKeyHex: string,
): Promise<boolean> {
  return manifest.schema_version === 1
    ? verifyManifestSignature(manifest, publicKeyHex)
    : verifyEncryptedManifestV2Signature(manifest, publicKeyHex);
}

function serviceBlobRef(
  stream:
    RemoteCacheManifest["stdout"] | EncryptedRemoteCacheManifestV2["stdout"],
): ServiceBlobRef {
  if ("digest" in stream) return stream;
  return {
    digest: stream.ciphertext_digest,
    size_bytes: stream.ciphertext_size_bytes,
  };
}

async function requireReadyBlob(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  blob: ServiceBlobRef,
): Promise<void> {
  const row = await blobRow(db, tenantId, repositoryId, blob.digest);
  if (
    row === null ||
    row.state !== "ready" ||
    row.size_bytes !== blob.size_bytes
  ) {
    throw new ApiError(
      422,
      "blob_unavailable",
      "manifest references a missing or mismatched blob",
    );
  }
}

function assertManifestBindings(
  manifest: ServiceManifest,
  auth: AuthContext,
  repositoryId: string,
  generationId: string,
  requestKey: string,
): void {
  if (manifest.tenant_id !== auth.tenantId) {
    throw new ApiError(
      422,
      "tenant_mismatch",
      "manifest tenant binding does not match token",
    );
  }
  if (manifest.repository_id !== repositoryId) {
    throw new ApiError(
      422,
      "repository_mismatch",
      "manifest repository binding does not match path",
    );
  }
  if (
    manifest.schema_version === 2 &&
    manifest.generation_id !== generationId
  ) {
    throw new ApiError(
      422,
      "repository_generation_mismatch",
      "manifest repository generation does not match the live repository",
    );
  }
  if (manifest.request_key !== requestKey) {
    throw new ApiError(
      422,
      "request_key_mismatch",
      "manifest request binding does not match path",
    );
  }
}

async function quarantineBlob(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  generationId: string,
  digest: string,
  incarnationId: string,
  reason: string,
): Promise<boolean> {
  const now = nowSeconds();
  const mutation = db
    .prepare(
      `UPDATE blobs
          SET state = 'quarantined', updated_at = ?, next_reconcile_at = ?
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?
          AND incarnation_id = ?
          AND state IN ('ready', 'pending')
          AND EXISTS (
            SELECT 1 FROM repositories repository
             WHERE repository.tenant_id = blobs.tenant_id
               AND repository.id = blobs.repository_id
               AND repository.generation_id = ?
               AND repository.deleted_at IS NULL
          )`,
    )
    .bind(
      now,
      now,
      auth.tenantId,
      repositoryId,
      digest,
      incarnationId,
      generationId,
    );
  const audit = await blobQuarantineAuditStatement(
    db,
    auth,
    repositoryId,
    generationId,
    digest,
    incarnationId,
    reason,
  );
  const results = await db.batch([audit, mutation]);
  if ((results[1]?.meta.changes ?? 0) === 0) return false;
  if ((results[0]?.meta.changes ?? 0) === 0)
    throw repositoryGenerationChanged();
  return true;
}

async function quarantineOrFailOnStateChange(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  generationId: string,
  digest: string,
  incarnationId: string,
  reason: string,
): Promise<void> {
  if (
    !(await quarantineBlob(
      db,
      auth,
      repositoryId,
      generationId,
      digest,
      incarnationId,
      reason,
    ))
  ) {
    await requireActiveRepositoryGenerationForMutation(
      db,
      auth.tenantId,
      repositoryId,
      generationId,
    );
    throw new ApiError(
      409,
      "blob_state_changed",
      "blob state changed during integrity handling",
    );
  }
}

async function verifyR2Object(
  bucket: R2Bucket,
  key: string,
  digest: string,
  size: number,
  incarnationId: string,
  expectedIdentity: R2Identity | null = null,
): Promise<VerifiedR2Object> {
  let object: R2ObjectBody | null;
  try {
    object = await bucket.get(key);
  } catch {
    throw new ApiError(
      503,
      "blob_storage_unavailable",
      "blob storage is temporarily unavailable",
    );
  }
  if (object === null) return { state: "missing" };
  if (
    size > MAX_BLOB_SIZE ||
    object.key !== key ||
    object.size !== size ||
    object.customMetadata?.blake3 !== digest ||
    object.customMetadata?.size_bytes !== String(size) ||
    (incarnationId !== LEGACY_BLOB_INCARNATION &&
      object.customMetadata?.incarnation_id !== incarnationId)
  ) {
    return { state: "invalid" };
  }
  const checksum = object.checksums.sha256;
  const identity =
    checksum === undefined ||
    object.version.length === 0 ||
    object.etag.length === 0
      ? undefined
      : {
          key: object.key,
          version: object.version,
          etag: object.etag,
          sha256: bytesToHex(new Uint8Array(checksum)),
        };
  if (
    expectedIdentity !== null &&
    (identity === undefined ||
      identity.key !== expectedIdentity.key ||
      identity.version !== expectedIdentity.version ||
      identity.etag !== expectedIdentity.etag ||
      identity.sha256 !== expectedIdentity.sha256)
  ) {
    return { state: "invalid" };
  }
  let bytes: Uint8Array;
  try {
    bytes = new Uint8Array(await object.arrayBuffer());
  } catch {
    throw new ApiError(
      503,
      "blob_storage_unavailable",
      "blob storage is temporarily unavailable",
    );
  }
  if (bytes.byteLength !== size || bytesToHex(blake3(bytes)) !== digest) {
    return { state: "invalid" };
  }
  return identity === undefined
    ? { state: "valid", bytes }
    : { state: "valid", bytes, identity };
}

async function verifyR2ObjectForReconcile(
  bucket: R2Bucket,
  key: string,
  digest: string,
  size: number,
  incarnationId: string,
): Promise<VerifiedR2Object> {
  let object: R2ObjectBody | null;
  try {
    object = await bucket.get(key);
  } catch {
    throw new ApiError(
      503,
      "blob_storage_unavailable",
      "blob storage is temporarily unavailable",
    );
  }
  if (object === null) return { state: "missing" };
  const checksum = object.checksums.sha256;
  if (
    size > MAX_BLOB_SIZE ||
    object.key !== key ||
    object.size !== size ||
    checksum === undefined ||
    object.version.length === 0 ||
    object.etag.length === 0 ||
    object.customMetadata?.blake3 !== digest ||
    object.customMetadata?.size_bytes !== String(size) ||
    object.customMetadata?.incarnation_id !== incarnationId
  ) {
    await object.body
      .cancel("reconcile metadata mismatch")
      .catch(() => undefined);
    return { state: "invalid" };
  }
  const reader = (object.body as ReadableStream<Uint8Array>).getReader();
  const hasher = blake3.create();
  let observed = 0;
  let complete = false;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      if (value.byteLength === 0) continue;
      if (value.byteLength > size - observed) return { state: "invalid" };
      observed += value.byteLength;
      hasher.update(value);
    }
    complete = true;
  } catch {
    throw new ApiError(
      503,
      "blob_storage_unavailable",
      "blob storage is temporarily unavailable",
    );
  } finally {
    if (!complete)
      await reader.cancel("reconcile stream incomplete").catch(() => undefined);
    reader.releaseLock();
  }
  if (observed !== size || bytesToHex(hasher.digest()) !== digest) {
    return { state: "invalid" };
  }
  return {
    state: "valid",
    identity: {
      key: object.key,
      version: object.version,
      etag: object.etag,
      sha256: bytesToHex(new Uint8Array(checksum)),
    },
  };
}

function blobR2Identity(row: BlobRow): R2Identity | null {
  const fields = [row.r2_key, row.r2_version, row.r2_etag, row.r2_sha256];
  if (fields.every((field) => field === null)) return null;
  if (fields.some((field) => field === null)) {
    throw new ApiError(
      409,
      "blob_integrity_failure",
      "blob has an incomplete storage identity",
    );
  }
  const [key, version, etag, sha256] = fields as [
    string,
    string,
    string,
    string,
  ];
  if (
    key.length === 0 ||
    version.length === 0 ||
    etag.length === 0 ||
    !/^[0-9a-f]{64}$/.test(sha256)
  ) {
    throw new ApiError(
      409,
      "blob_integrity_failure",
      "blob has an invalid storage identity",
    );
  }
  return { key, version, etag, sha256 };
}

async function deleteBlobObjectIfUnowned(
  env: Env,
  tenantId: string,
  repositoryId: string,
  generationId: string,
  digest: string,
  incarnationId: string,
  key: string,
): Promise<void> {
  const owner = await env.DB.prepare(
    `SELECT 1 AS present
       FROM blobs blob
       JOIN repositories repository
         ON repository.tenant_id = blob.tenant_id
        AND repository.id = blob.repository_id
      WHERE blob.tenant_id = ? AND blob.repository_id = ? AND blob.digest = ?
        AND blob.incarnation_id = ? AND repository.generation_id = ?
        AND repository.deleted_at IS NULL`,
  )
    .bind(tenantId, repositoryId, digest, incarnationId, generationId)
    .first<{ present: number }>();
  if (owner === null) await env.BLOBS.delete(key);
}

async function registerBlobObjectOperation(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  generationId: string,
  digest: string,
  incarnationId: string,
  operationId: string,
): Promise<void> {
  const now = nowSeconds();
  const result = await db
    .prepare(
      `INSERT INTO blob_object_orphan_candidates(
       tenant_id, repository_id, generation_id, digest, incarnation_id,
       operation_id, created_at, next_sweep_at, attempts
     )
     SELECT ?, ?, ?, ?, ?, ?, ?, ?, 0
      WHERE EXISTS (
        SELECT 1 FROM blobs blob
        JOIN repositories repository
          ON repository.tenant_id = blob.tenant_id
         AND repository.id = blob.repository_id
       WHERE blob.tenant_id = ? AND blob.repository_id = ? AND blob.digest = ?
         AND blob.incarnation_id = ? AND blob.state = 'pending'
         AND repository.generation_id = ? AND repository.deleted_at IS NULL
      )
       AND (
         EXISTS (
           SELECT 1 FROM blob_object_orphan_candidates candidate
            WHERE candidate.tenant_id = ? AND candidate.repository_id = ?
              AND candidate.generation_id = ? AND candidate.digest = ?
              AND candidate.incarnation_id = ? AND candidate.operation_id = ?
         )
         OR (
           (SELECT count(*) FROM blob_object_orphan_candidates candidate
             WHERE candidate.tenant_id = ?) < (
               SELECT tenant.blob_orphan_candidate_limit
                 FROM tenants tenant WHERE tenant.id = ?
             )
           AND (SELECT count(*) FROM blob_object_orphan_candidates candidate
                 WHERE candidate.tenant_id = ? AND candidate.repository_id = ?) < (
               SELECT tenant.blob_orphan_repository_limit
                 FROM tenants tenant WHERE tenant.id = ?
             )
         )
       )
     ON CONFLICT(
       tenant_id, repository_id, generation_id, digest, incarnation_id, operation_id
     )
     DO UPDATE SET next_sweep_at = min(next_sweep_at, excluded.next_sweep_at)`,
    )
    .bind(
      tenantId,
      repositoryId,
      generationId,
      digest,
      incarnationId,
      operationId,
      now,
      now,
      tenantId,
      repositoryId,
      digest,
      incarnationId,
      generationId,
      tenantId,
      repositoryId,
      generationId,
      digest,
      incarnationId,
      operationId,
      tenantId,
      tenantId,
      tenantId,
      repositoryId,
      tenantId,
    )
    .run();
  if (result.meta.changes === 0) {
    await requireRepositoryGeneration(db, tenantId, repositoryId, generationId);
    const diagnostic = await db
      .prepare(
        `SELECT
         EXISTS (
           SELECT 1 FROM blobs blob
           JOIN repositories repository
             ON repository.tenant_id = blob.tenant_id
            AND repository.id = blob.repository_id
          WHERE blob.tenant_id = ? AND blob.repository_id = ? AND blob.digest = ?
            AND blob.incarnation_id = ? AND blob.state = 'pending'
            AND repository.generation_id = ? AND repository.deleted_at IS NULL
         ) AS pending,
         (SELECT count(*) FROM blob_object_orphan_candidates candidate
           WHERE candidate.tenant_id = ?) AS candidate_count,
         (SELECT tenant.blob_orphan_candidate_limit FROM tenants tenant
           WHERE tenant.id = ?) AS candidate_limit,
         (SELECT count(*) FROM blob_object_orphan_candidates candidate
           WHERE candidate.tenant_id = ? AND candidate.repository_id = ?
         ) AS repository_candidate_count,
         (SELECT tenant.blob_orphan_repository_limit FROM tenants tenant
           WHERE tenant.id = ?) AS repository_candidate_limit`,
      )
      .bind(
        tenantId,
        repositoryId,
        digest,
        incarnationId,
        generationId,
        tenantId,
        tenantId,
        tenantId,
        repositoryId,
        tenantId,
      )
      .first<{
        pending: number;
        candidate_count: number;
        candidate_limit: number;
        repository_candidate_count: number;
        repository_candidate_limit: number;
      }>();
    if (
      diagnostic?.pending === 1 &&
      diagnostic.repository_candidate_count >=
        diagnostic.repository_candidate_limit
    ) {
      throw new ApiError(
        413,
        "metadata_quota_exceeded",
        "repository unresolved blob operation limit has been reached",
      );
    }
    if (
      diagnostic?.pending === 1 &&
      diagnostic.candidate_count >= diagnostic.candidate_limit
    ) {
      throw new ApiError(
        413,
        "metadata_quota_exceeded",
        "unresolved blob operation limit has been reached",
      );
    }
    throw new ApiError(
      409,
      "blob_state_changed",
      "blob changed before object upload",
    );
  }
}

async function promoteBlobAndCompleteObjectOperation(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  generationId: string,
  digest: string,
  incarnationId: string,
  sizeBytes: number,
  operationId: string,
  identity: R2Identity,
): Promise<"created" | "already_ready"> {
  const targetHash = await sha256Hex(
    `${auth.tenantId}\0${repositoryId}\0blob\0${digest}`,
  );
  const transitionTime = nowSeconds();
  const exactPendingAndOperation = `
    SELECT 1 FROM blobs blob
    JOIN repositories repository
      ON repository.tenant_id = blob.tenant_id
     AND repository.id = blob.repository_id
   WHERE blob.tenant_id = ? AND blob.repository_id = ? AND blob.digest = ?
     AND blob.incarnation_id = ? AND blob.size_bytes = ? AND blob.state = 'pending'
     AND repository.generation_id = ? AND repository.deleted_at IS NULL
     AND EXISTS (
       SELECT 1 FROM blob_object_orphan_candidates candidate
        WHERE candidate.tenant_id = ? AND candidate.repository_id = ?
          AND candidate.generation_id = ? AND candidate.digest = ?
          AND candidate.incarnation_id = ? AND candidate.operation_id = ?
     )`;
  const audit = db
    .prepare(
      `INSERT INTO audit_events(
       tenant_id, repository_id, actor, action, target_type,
       target_id_sha256, outcome, details_json, created_at
     )
     SELECT ?, ?, ?, 'blob.put', 'blob', ?, 'ready', '{}', ?
      WHERE EXISTS (${exactPendingAndOperation})`,
    )
    .bind(
      auth.tenantId,
      repositoryId,
      auth.subject,
      targetHash,
      transitionTime,
      auth.tenantId,
      repositoryId,
      digest,
      incarnationId,
      sizeBytes,
      generationId,
      auth.tenantId,
      repositoryId,
      generationId,
      digest,
      incarnationId,
      operationId,
    );
  const promotion = db
    .prepare(
      `UPDATE blobs
        SET state = 'ready', updated_at = ?, reconcile_attempts = 0,
            next_reconcile_at = ?, delete_not_before = NULL,
            r2_key = ?, r2_version = ?, r2_etag = ?, r2_sha256 = ?
      WHERE tenant_id = ? AND repository_id = ? AND digest = ? AND state = 'pending'
        AND incarnation_id = ? AND size_bytes = ?
        AND EXISTS (
          SELECT 1 FROM repositories repository
           WHERE repository.tenant_id = blobs.tenant_id
             AND repository.id = blobs.repository_id
             AND repository.generation_id = ? AND repository.deleted_at IS NULL
        )
        AND EXISTS (
          SELECT 1 FROM blob_object_orphan_candidates candidate
           WHERE candidate.tenant_id = blobs.tenant_id
             AND candidate.repository_id = blobs.repository_id
             AND candidate.generation_id = ? AND candidate.digest = blobs.digest
             AND candidate.incarnation_id = blobs.incarnation_id
             AND candidate.operation_id = ?
        )`,
    )
    .bind(
      transitionTime,
      transitionTime,
      identity.key,
      identity.version,
      identity.etag,
      identity.sha256,
      auth.tenantId,
      repositoryId,
      digest,
      incarnationId,
      sizeBytes,
      generationId,
      generationId,
      operationId,
    );
  const completion = db
    .prepare(
      `DELETE FROM blob_object_orphan_candidates
      WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?
        AND digest = ? AND incarnation_id = ? AND operation_id = ?
        AND EXISTS (
          SELECT 1 FROM blobs blob
          JOIN repositories repository
            ON repository.tenant_id = blob.tenant_id
           AND repository.id = blob.repository_id
         WHERE blob.tenant_id = ? AND blob.repository_id = ? AND blob.digest = ?
           AND blob.incarnation_id = ? AND blob.size_bytes = ? AND blob.state = 'ready'
           AND blob.r2_key = ? AND blob.r2_version = ?
           AND blob.r2_etag = ? AND blob.r2_sha256 = ?
           AND repository.generation_id = ? AND repository.deleted_at IS NULL
        )`,
    )
    .bind(
      auth.tenantId,
      repositoryId,
      generationId,
      digest,
      incarnationId,
      operationId,
      auth.tenantId,
      repositoryId,
      digest,
      incarnationId,
      sizeBytes,
      identity.key,
      identity.version,
      identity.etag,
      identity.sha256,
      generationId,
    );
  const results = await db.batch([audit, promotion, completion]);
  const auditChanges = results[0]?.meta.changes ?? 0;
  const promotionChanges = results[1]?.meta.changes ?? 0;
  const completionChanges = results[2]?.meta.changes ?? 0;
  if (auditChanges > 0 && promotionChanges === 1 && completionChanges === 1) {
    return "created";
  }
  if (auditChanges === 0 && promotionChanges === 0 && completionChanges === 1) {
    return "already_ready";
  }
  await requireRepositoryGeneration(
    db,
    auth.tenantId,
    repositoryId,
    generationId,
  );
  throw new ApiError(
    409,
    "blob_state_changed",
    "blob operation changed before acknowledgement",
  );
}

async function retireSettledBlobObjectOperation(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  generationId: string,
  digest: string,
  incarnationId: string,
  operationId: string,
): Promise<void> {
  // A fulfilled R2 PUT can no longer arrive late. Retire only this handler's
  // operation and only while an exact authoritative row still owns the
  // incarnation; if ownership disappeared, retain the candidate so the
  // sweeper removes the already-written object.
  await db
    .prepare(
      `DELETE FROM blob_object_orphan_candidates
      WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?
        AND digest = ? AND incarnation_id = ? AND operation_id = ?
        AND EXISTS (
          SELECT 1 FROM blobs blob
          JOIN repositories repository
            ON repository.tenant_id = blob.tenant_id
           AND repository.id = blob.repository_id
         WHERE blob.tenant_id = ? AND blob.repository_id = ? AND blob.digest = ?
           AND blob.incarnation_id = ? AND repository.generation_id = ?
        )`,
    )
    .bind(
      tenantId,
      repositoryId,
      generationId,
      digest,
      incarnationId,
      operationId,
      tenantId,
      repositoryId,
      digest,
      incarnationId,
      generationId,
    )
    .run();
}

async function r2ObjectState(
  bucket: R2Bucket,
  key: string,
  digest: string,
  size: number,
  incarnationId: string,
  expectedIdentity: R2Identity | null = null,
): Promise<R2ObjectState> {
  return (
    await verifyR2Object(
      bucket,
      key,
      digest,
      size,
      incarnationId,
      expectedIdentity,
    )
  ).state;
}

async function runScheduledMaintenance(cron: string, env: Env): Promise<void> {
  if (cron === FAST_MAINTENANCE_CRON) {
    await runFastMaintenance(env);
    return;
  }
  if (cron === BLOB_RECONCILIATION_CRON) {
    const outcomes = [
      await runMaintenanceStep("blob_reconcile", () => reconcileBlobs(env)),
    ];
    if (outcomes.some((outcome) => !outcome)) {
      throw new Error("one or more maintenance steps failed");
    }
    return;
  }
  throw new Error(`unsupported maintenance cron: ${cron}`);
}

async function runFastMaintenance(env: Env): Promise<void> {
  const outcomes = [
    await runMaintenanceStep("manifest_cleanup", () => cleanupManifests(env)),
    await runMaintenanceStep("blob_gc", () => processBlobGcCandidates(env)),
    await runMaintenanceStep("blob_orphan_cleanup", () =>
      sweepBlobObjectOrphans(env),
    ),
    await runMaintenanceStep("repository_delete", () =>
      processRepositoryDeletions(env),
    ),
    await runMaintenanceStep("repository_graveyard", () =>
      sweepDeletedRepositoryPrefixes(env),
    ),
    await runMaintenanceStep("expired_write_leases", () =>
      cleanupExpiredWriteLeases(env.DB),
    ),
    await runMaintenanceStep("rate_window_cleanup", () =>
      cleanupRateWindows(env.DB),
    ),
  ];
  if (outcomes.some((outcome) => !outcome)) {
    throw new Error("one or more maintenance steps failed");
  }
}

async function cleanupExpiredWriteLeases(db: D1Database): Promise<void> {
  await db
    .prepare(
      `DELETE FROM repository_write_leases
      WHERE rowid IN (
        SELECT rowid FROM repository_write_leases
         WHERE expires_at <= ?
         ORDER BY expires_at, tenant_id, repository_id, generation_id, lease_id
         LIMIT 500
      )`,
    )
    .bind(nowSeconds())
    .run();
}

async function sweepBlobObjectOrphans(env: Env): Promise<void> {
  const now = nowSeconds();
  const rows = await env.DB.prepare(
    `WITH ranked AS (
       SELECT tenant_id, repository_id, generation_id, digest, incarnation_id,
              operation_id, attempts, next_sweep_at, created_at,
              row_number() OVER (
                PARTITION BY tenant_id
                ORDER BY next_sweep_at, created_at, repository_id, generation_id,
                         digest, incarnation_id, operation_id
              ) AS tenant_rank
         FROM blob_object_orphan_candidates
        WHERE next_sweep_at <= ?
     )
     SELECT tenant_id, repository_id, generation_id, digest, incarnation_id,
            operation_id, attempts
       FROM ranked
      ORDER BY tenant_rank, next_sweep_at, created_at, tenant_id, repository_id, generation_id,
               digest, incarnation_id, operation_id
      LIMIT ?`,
  )
    .bind(now, BLOB_GC_BATCH_SIZE)
    .all<BlobObjectOrphanCandidateRow>();
  for (const row of rows.results) {
    try {
      const owner = await env.DB.prepare(
        `SELECT blob.state
           FROM blobs blob
           JOIN repositories repository
             ON repository.tenant_id = blob.tenant_id
            AND repository.id = blob.repository_id
          WHERE blob.tenant_id = ? AND blob.repository_id = ? AND blob.digest = ?
            AND blob.incarnation_id = ? AND repository.generation_id = ?
            AND repository.deleted_at IS NULL`,
      )
        .bind(
          row.tenant_id,
          row.repository_id,
          row.digest,
          row.incarnation_id,
          row.generation_id,
        )
        .first<{ state: BlobRow["state"] }>();
      let failed = false;
      if (owner === null) {
        try {
          const key = blobKey(
            row.tenant_id,
            row.repository_id,
            row.generation_id,
            row.digest,
            row.incarnation_id,
          );
          await env.BLOBS.delete(key);
          failed = (await env.BLOBS.head(key)) !== null;
        } catch {
          failed = true;
        }
      }
      const attempts = failed ? row.attempts + 1 : row.attempts;
      const delay = failed
        ? Math.min(60 * 60, 60 * 2 ** Math.min(row.attempts, 6))
        : REPOSITORY_DELETE_EMPTY_CONFIRM_SECONDS;
      await env.DB.prepare(
        `UPDATE blob_object_orphan_candidates
            SET attempts = ?, next_sweep_at = ?
          WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?
            AND digest = ? AND incarnation_id = ? AND operation_id = ?
            AND attempts = ?`,
      )
        .bind(
          attempts,
          now + delay,
          row.tenant_id,
          row.repository_id,
          row.generation_id,
          row.digest,
          row.incarnation_id,
          row.operation_id,
          row.attempts,
        )
        .run();
    } catch (error: unknown) {
      const delay = Math.min(60 * 60, 60 * 2 ** Math.min(row.attempts, 6));
      await env.DB.prepare(
        `UPDATE blob_object_orphan_candidates
            SET attempts = attempts + 1, next_sweep_at = ?
          WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?
            AND digest = ? AND incarnation_id = ? AND operation_id = ?
            AND attempts = ?`,
      )
        .bind(
          now + delay,
          row.tenant_id,
          row.repository_id,
          row.generation_id,
          row.digest,
          row.incarnation_id,
          row.operation_id,
          row.attempts,
        )
        .run()
        .catch(() => undefined);
      console.warn(
        JSON.stringify({
          event: "blob_orphan_sweep_failed",
          error: error instanceof Error ? error.name : "UnknownError",
        }),
      );
    }
  }
}

async function sweepDeletedRepositoryPrefixes(env: Env): Promise<void> {
  const now = nowSeconds();
  const rows = await env.DB.prepare(
    `WITH ranked AS (
       SELECT tenant_id, repository_id, generation_id, completed_at, orphan_sweep_due_at,
              row_number() OVER (
                PARTITION BY tenant_id
                ORDER BY orphan_sweep_due_at, completed_at, repository_id, generation_id
              ) AS tenant_rank
         FROM repository_deletion_receipts
        WHERE completed_at IS NOT NULL AND orphan_sweep_due_at <= ?
     )
     SELECT tenant_id, repository_id, generation_id
       FROM ranked
      ORDER BY tenant_rank, orphan_sweep_due_at, completed_at, tenant_id, repository_id,
               generation_id
      LIMIT ?`,
  )
    .bind(now, REPOSITORY_DELETE_BATCH_SIZE)
    .all<CompletedRepositoryDeletionReceiptRow>();
  for (const row of rows.results) {
    try {
      requireRouteIdentifier(row.tenant_id, "tenant_id");
      requireRouteIdentifier(row.repository_id, "repository_id");
      requireGenerationId(row.generation_id);
      const prefix = repositoryBlobPrefix(
        row.tenant_id,
        row.repository_id,
        row.generation_id,
      );
      const page = await env.BLOBS.list({
        prefix,
        limit: REPOSITORY_DELETE_R2_PAGE_SIZE,
        include: [],
      });
      if (page.objects.length > REPOSITORY_DELETE_R2_PAGE_SIZE) {
        throw new Error("R2 returned an oversized graveyard page");
      }
      const keys = page.objects.map((object) => object.key);
      if (keys.some((key) => !key.startsWith(prefix))) {
        throw new Error("R2 returned an object outside the graveyard prefix");
      }
      if (keys.length !== 0) {
        await env.BLOBS.delete(keys);
      }
      await env.DB.prepare(
        `UPDATE repository_deletion_receipts
            SET orphan_sweep_due_at = ?
          WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?
            AND completed_at IS NOT NULL AND orphan_sweep_due_at <= ?`,
      )
        .bind(
          now + REPOSITORY_DELETE_EMPTY_CONFIRM_SECONDS,
          row.tenant_id,
          row.repository_id,
          row.generation_id,
          now,
        )
        .run();
    } catch (error: unknown) {
      await env.DB.prepare(
        `UPDATE repository_deletion_receipts
            SET orphan_sweep_due_at = ?
          WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?
            AND completed_at IS NOT NULL AND orphan_sweep_due_at <= ?`,
      )
        .bind(
          now + REPOSITORY_DELETE_EMPTY_CONFIRM_SECONDS,
          row.tenant_id,
          row.repository_id,
          row.generation_id,
          now,
        )
        .run()
        .catch(() => undefined);
      console.warn(
        JSON.stringify({
          event: "repository_graveyard_sweep_failed",
          error: error instanceof Error ? error.name : "UnknownError",
        }),
      );
    }
  }
}

async function cleanupRateWindows(db: D1Database): Promise<void> {
  await db
    .prepare(
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

async function runMaintenanceStep(
  name: string,
  operation: () => Promise<void>,
): Promise<boolean> {
  try {
    await operation();
    return true;
  } catch (error: unknown) {
    console.warn(
      JSON.stringify({
        event: "maintenance_step_failed",
        step: name,
        error: error instanceof Error ? error.name : "UnknownError",
      }),
    );
    return false;
  }
}

async function cleanupManifests(env: Env): Promise<void> {
  const now = nowSeconds();
  await env.DB.prepare(
    `DELETE FROM manifests
      WHERE (tenant_id, repository_id, request_key) IN (
        SELECT tenant_id, repository_id, request_key
          FROM (
            SELECT candidate.tenant_id, candidate.repository_id, candidate.request_key,
                   candidate.due_at,
                   row_number() OVER (
                     PARTITION BY candidate.tenant_id
                     ORDER BY candidate.due_at, candidate.repository_id,
                              candidate.request_key
                   ) AS tenant_rank
              FROM manifest_gc_candidates candidate
              JOIN repositories repository
                ON repository.tenant_id = candidate.tenant_id
               AND repository.id = candidate.repository_id
               AND repository.deleted_at IS NULL
             WHERE candidate.due_at <= ?
          ) ranked
         ORDER BY tenant_rank, due_at, tenant_id, repository_id, request_key
         LIMIT ?
      )`,
  )
    .bind(now, MANIFEST_CLEANUP_BATCH_SIZE)
    .run();
}

async function processBlobGcCandidates(env: Env): Promise<void> {
  const now = nowSeconds();
  const rows = await env.DB.prepare(
    `WITH ranked AS (
       SELECT candidate.tenant_id, candidate.repository_id, repository.generation_id,
              candidate.digest, candidate.next_check_at, candidate.created_at,
              candidate.attempts, blob.state,
              blob.updated_at AS blob_updated_at, blob.incarnation_id,
              row_number() OVER (
                PARTITION BY candidate.tenant_id
                ORDER BY candidate.next_check_at, candidate.created_at,
                         candidate.repository_id, candidate.digest
              ) AS tenant_rank
         FROM blob_gc_candidates candidate
         JOIN repositories repository
           ON repository.tenant_id = candidate.tenant_id
          AND repository.id = candidate.repository_id
          AND repository.deleted_at IS NULL
         JOIN blobs blob
           ON blob.tenant_id = candidate.tenant_id
          AND blob.repository_id = candidate.repository_id
          AND blob.digest = candidate.digest
        WHERE candidate.next_check_at <= ?
     )
     SELECT tenant_id, repository_id, generation_id, digest, next_check_at,
            attempts, state, blob_updated_at, incarnation_id
       FROM ranked
      ORDER BY tenant_rank, next_check_at, created_at,
               tenant_id, repository_id, digest
      LIMIT ?`,
  )
    .bind(now, BLOB_GC_BATCH_SIZE)
    .all<BlobGcCandidateRow>();

  for (const row of rows.results) {
    try {
      const pendingCutoff = now - UNREFERENCED_BLOB_ADOPTION_SECONDS;
      if (row.blob_updated_at > pendingCutoff) {
        await rescheduleBlobGcCandidate(
          env.DB,
          row,
          row.blob_updated_at + UNREFERENCED_BLOB_ADOPTION_SECONDS,
          false,
        );
        continue;
      }

      const transitioned = await env.DB.prepare(
        `UPDATE blobs
            SET state = 'deleting', updated_at = ?, next_reconcile_at = ?,
                delete_not_before = ?
          WHERE tenant_id = ? AND repository_id = ? AND digest = ?
            AND incarnation_id = ?
            AND (
              state IN ('ready', 'quarantined')
              OR (state = 'pending' AND updated_at <= ?)
            )
            AND state = ? AND updated_at = ?
            AND EXISTS (
              SELECT 1 FROM repositories repository
               WHERE repository.tenant_id = blobs.tenant_id
                 AND repository.id = blobs.repository_id
                 AND repository.generation_id = ?
                 AND repository.deleted_at IS NULL
            )
            AND NOT EXISTS (
              SELECT 1 FROM manifests manifest
               WHERE manifest.tenant_id = blobs.tenant_id
                 AND manifest.repository_id = blobs.repository_id
                 AND manifest.state != 'deleted'
                 AND manifest.expires_at > ?
                 AND (manifest.stdout_digest = blobs.digest
                      OR manifest.stderr_digest = blobs.digest)
            )`,
      )
        .bind(
          now,
          now,
          now,
          row.tenant_id,
          row.repository_id,
          row.digest,
          row.incarnation_id,
          pendingCutoff,
          row.state,
          row.blob_updated_at,
          row.generation_id,
          now,
        )
        .run();
      if (transitioned.meta.changes !== 0) {
        await deleteBlobGcCandidate(env.DB, row);
        continue;
      }

      const current = await blobRow(
        env.DB,
        row.tenant_id,
        row.repository_id,
        row.digest,
      );
      if (
        current?.incarnation_id === row.incarnation_id &&
        current.state === "pending" &&
        current.updated_at > pendingCutoff
      ) {
        await rescheduleBlobGcCandidate(
          env.DB,
          row,
          current.updated_at + UNREFERENCED_BLOB_ADOPTION_SECONDS,
          false,
        );
      } else {
        // Re-evaluate the reason for the failed transition atomically with
        // candidate deletion. A manifest can be deleted between the UPDATE
        // above and this statement; in that interleaving its trigger has
        // refreshed this same queue row. The candidate must survive whenever
        // there is no longer a live reference.
        await deleteBlobGcCandidateIfReferencedOrTerminal(env.DB, row, now);
      }
    } catch (error: unknown) {
      try {
        await rescheduleBlobGcCandidate(env.DB, row, now, true);
      } catch (backoffError: unknown) {
        console.warn(
          JSON.stringify({
            event: "blob_gc_backoff_failed",
            error:
              backoffError instanceof Error
                ? backoffError.name
                : "UnknownError",
          }),
        );
      }
      console.warn(
        JSON.stringify({
          event: "blob_gc_failed",
          error: error instanceof Error ? error.name : "UnknownError",
        }),
      );
    }
  }
}

async function deleteBlobGcCandidateIfReferencedOrTerminal(
  db: D1Database,
  row: BlobGcCandidateRow,
  now: number,
): Promise<void> {
  await db
    .prepare(
      `DELETE FROM blob_gc_candidates
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?
          AND attempts = ? AND next_check_at = ?
          AND EXISTS (
            SELECT 1 FROM repositories repository
             WHERE repository.tenant_id = blob_gc_candidates.tenant_id
               AND repository.id = blob_gc_candidates.repository_id
               AND repository.generation_id = ?
               AND repository.deleted_at IS NULL
          )
          AND EXISTS (
            SELECT 1 FROM blobs selected_blob
             WHERE selected_blob.tenant_id = blob_gc_candidates.tenant_id
               AND selected_blob.repository_id = blob_gc_candidates.repository_id
               AND selected_blob.digest = blob_gc_candidates.digest
               AND selected_blob.incarnation_id = ?
          )
          AND (
            NOT EXISTS (
              SELECT 1 FROM blobs blob
               WHERE blob.tenant_id = blob_gc_candidates.tenant_id
                 AND blob.repository_id = blob_gc_candidates.repository_id
                 AND blob.digest = blob_gc_candidates.digest
            )
            OR EXISTS (
              SELECT 1 FROM blobs blob
               WHERE blob.tenant_id = blob_gc_candidates.tenant_id
                 AND blob.repository_id = blob_gc_candidates.repository_id
                 AND blob.digest = blob_gc_candidates.digest
                 AND blob.state = 'deleting'
            )
            OR EXISTS (
              SELECT 1 FROM manifests manifest
               WHERE manifest.tenant_id = blob_gc_candidates.tenant_id
                 AND manifest.repository_id = blob_gc_candidates.repository_id
                 AND manifest.state != 'deleted'
                 AND manifest.expires_at > ?
                 AND (manifest.stdout_digest = blob_gc_candidates.digest
                      OR manifest.stderr_digest = blob_gc_candidates.digest)
            )
          )`,
    )
    .bind(
      row.tenant_id,
      row.repository_id,
      row.digest,
      row.attempts,
      row.next_check_at,
      row.generation_id,
      row.incarnation_id,
      now,
    )
    .run();
}

async function deleteBlobGcCandidate(
  db: D1Database,
  row: BlobGcCandidateRow,
): Promise<void> {
  await db
    .prepare(
      `DELETE FROM blob_gc_candidates
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?
          AND attempts = ? AND next_check_at = ?
          AND EXISTS (
            SELECT 1 FROM repositories repository
             WHERE repository.tenant_id = blob_gc_candidates.tenant_id
               AND repository.id = blob_gc_candidates.repository_id
               AND repository.generation_id = ?
               AND repository.deleted_at IS NULL
          )
          AND EXISTS (
            SELECT 1 FROM blobs selected_blob
             WHERE selected_blob.tenant_id = blob_gc_candidates.tenant_id
               AND selected_blob.repository_id = blob_gc_candidates.repository_id
               AND selected_blob.digest = blob_gc_candidates.digest
               AND selected_blob.incarnation_id = ?
          )`,
    )
    .bind(
      row.tenant_id,
      row.repository_id,
      row.digest,
      row.attempts,
      row.next_check_at,
      row.generation_id,
      row.incarnation_id,
    )
    .run();
}

async function rescheduleBlobGcCandidate(
  db: D1Database,
  row: BlobGcCandidateRow,
  requestedTime: number,
  backoff: boolean,
): Promise<void> {
  const attempts = backoff ? row.attempts + 1 : 0;
  const delay = backoff
    ? Math.min(60 * 60, 60 * 2 ** Math.min(row.attempts, 6))
    : 0;
  const nextCheck = Math.max(requestedTime, nowSeconds() + delay);
  await db
    .prepare(
      `UPDATE blob_gc_candidates
          SET attempts = ?, next_check_at = ?, updated_at = ?
        WHERE tenant_id = ? AND repository_id = ? AND digest = ?
          AND attempts = ? AND next_check_at = ?
          AND EXISTS (
            SELECT 1 FROM repositories repository
             WHERE repository.tenant_id = blob_gc_candidates.tenant_id
               AND repository.id = blob_gc_candidates.repository_id
               AND repository.generation_id = ?
               AND repository.deleted_at IS NULL
          )
          AND EXISTS (
            SELECT 1 FROM blobs selected_blob
             WHERE selected_blob.tenant_id = blob_gc_candidates.tenant_id
               AND selected_blob.repository_id = blob_gc_candidates.repository_id
               AND selected_blob.digest = blob_gc_candidates.digest
               AND selected_blob.incarnation_id = ?
          )`,
    )
    .bind(
      attempts,
      nextCheck,
      nowSeconds(),
      row.tenant_id,
      row.repository_id,
      row.digest,
      row.attempts,
      row.next_check_at,
      row.generation_id,
      row.incarnation_id,
    )
    .run();
}

async function processRepositoryDeletions(env: Env): Promise<void> {
  const selectionTime = nowSeconds();
  const due = await env.DB.prepare(
    `WITH ranked AS (
       SELECT tenant_id, repository_id, generation_id, requested_at, r2_cursor,
              empty_confirmations, last_empty_at, attempts, next_attempt_at,
              lease_id, lease_until, phase, updated_at,
              row_number() OVER (
                PARTITION BY tenant_id
                ORDER BY next_attempt_at, requested_at, repository_id
              ) AS tenant_rank
         FROM repository_deletions
        WHERE next_attempt_at <= ? AND (lease_until IS NULL OR lease_until <= ?)
     )
     SELECT tenant_id, repository_id, generation_id, requested_at, r2_cursor,
            empty_confirmations, last_empty_at, attempts, next_attempt_at,
            lease_id, lease_until, phase, updated_at
       FROM ranked
      ORDER BY tenant_rank, next_attempt_at, requested_at, tenant_id, repository_id
      LIMIT ?`,
  )
    .bind(selectionTime, selectionTime, REPOSITORY_DELETE_BATCH_SIZE)
    .all<RepositoryDeletionRow>();

  for (const candidate of due.results) {
    const now = nowSeconds();
    const leaseId = crypto.randomUUID();
    let leased: RepositoryDeletionRow | null = null;
    try {
      leased = await env.DB.prepare(
        `UPDATE repository_deletions
            SET lease_id = ?, lease_until = ?, next_attempt_at = ?, updated_at = ?
          WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?
            AND phase = ? AND updated_at = ?
            AND next_attempt_at <= ? AND (lease_until IS NULL OR lease_until <= ?)
          RETURNING tenant_id, repository_id, generation_id, requested_at, r2_cursor,
                    empty_confirmations, last_empty_at, attempts, next_attempt_at,
                    lease_id, lease_until, phase, updated_at`,
      )
        .bind(
          leaseId,
          now + REPOSITORY_DELETE_LEASE_SECONDS,
          now + REPOSITORY_DELETE_LEASE_SECONDS,
          now,
          candidate.tenant_id,
          candidate.repository_id,
          candidate.generation_id,
          candidate.phase,
          candidate.updated_at,
          now,
          now,
        )
        .first<RepositoryDeletionRow>();
      if (leased === null) continue;
      await processRepositoryDeletionLease(env, leased, leaseId, now);
    } catch (error: unknown) {
      if (leased !== null) {
        try {
          await deferRepositoryDeletion(env.DB, leased, leaseId, now);
        } catch (backoffError: unknown) {
          console.warn(
            JSON.stringify({
              event: "repository_delete_backoff_failed",
              error:
                backoffError instanceof Error
                  ? backoffError.name
                  : "UnknownError",
            }),
          );
        }
      }
      console.warn(
        JSON.stringify({
          event: "repository_delete_sweep_failed",
          attempt: (leased ?? candidate).attempts + 1,
          error: error instanceof Error ? error.name : "UnknownError",
        }),
      );
    }
  }
}

async function processRepositoryDeletionLease(
  env: Env,
  row: RepositoryDeletionRow,
  leaseId: string,
  now: number,
): Promise<void> {
  requireRouteIdentifier(row.tenant_id, "tenant_id");
  requireRouteIdentifier(row.repository_id, "repository_id");
  requireGenerationId(row.generation_id);
  if (row.phase !== "r2") {
    await processRepositoryD1Cleanup(env.DB, row, leaseId, now);
    return;
  }

  const expiredLeases = await env.DB.prepare(
    `DELETE FROM repository_write_leases
      WHERE rowid IN (
        SELECT rowid FROM repository_write_leases
         WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?
           AND expires_at <= ?
         ORDER BY expires_at, rowid
         LIMIT ?
      )`,
  )
    .bind(
      row.tenant_id,
      row.repository_id,
      row.generation_id,
      now,
      REPOSITORY_DELETE_D1_CHUNK_SIZE,
    )
    .run();
  const activeWriteLease = await env.DB.prepare(
    `SELECT expires_at FROM repository_write_leases
      WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?
      ORDER BY expires_at, lease_id LIMIT 1`,
  )
    .bind(row.tenant_id, row.repository_id, row.generation_id)
    .first<{ expires_at: number }>();
  if (
    activeWriteLease !== null ||
    expiredLeases.meta.changes >= REPOSITORY_DELETE_D1_CHUNK_SIZE
  ) {
    const nextAttempt =
      activeWriteLease === null
        ? now
        : Math.max(now + 1, activeWriteLease.expires_at);
    await releaseRepositoryDeletionLease(
      env.DB,
      row,
      leaseId,
      now,
      nextAttempt,
      true,
    );
    return;
  }

  const prefix = repositoryBlobPrefix(
    row.tenant_id,
    row.repository_id,
    row.generation_id,
  );
  const options: R2ListOptions = {
    prefix,
    limit: REPOSITORY_DELETE_R2_PAGE_SIZE,
    include: [],
  };
  if (row.r2_cursor !== null) options.cursor = row.r2_cursor;
  const page = await env.BLOBS.list(options);
  if (page.objects.length > REPOSITORY_DELETE_R2_PAGE_SIZE) {
    throw new Error("R2 returned an oversized deletion page");
  }
  if (
    page.truncated &&
    (page.cursor === undefined || page.cursor.length === 0)
  ) {
    throw new Error("R2 returned a truncated page without a cursor");
  }
  if (
    page.truncated &&
    page.objects.length === 0 &&
    page.cursor === row.r2_cursor
  ) {
    throw new Error("R2 deletion cursor made no progress");
  }
  const keys = page.objects.map((object) => object.key);
  if (keys.some((key) => !key.startsWith(prefix))) {
    throw new Error("R2 returned an object outside the deletion prefix");
  }

  if (keys.length > 0) {
    await env.BLOBS.delete(keys);
    await updateRepositoryDeletionR2Progress(
      env.DB,
      row,
      leaseId,
      page.truncated ? (page.cursor ?? null) : null,
      now,
    );
    return;
  }

  if (page.truncated || row.r2_cursor !== null) {
    await updateRepositoryDeletionR2Progress(
      env.DB,
      row,
      leaseId,
      page.truncated ? (page.cursor ?? null) : null,
      now,
    );
    return;
  }

  if (row.empty_confirmations === 0 || row.last_empty_at === null) {
    await env.DB.prepare(
      `UPDATE repository_deletions
          SET r2_cursor = NULL, empty_confirmations = 1, last_empty_at = ?,
              attempts = 0, next_attempt_at = ?, lease_id = NULL,
              lease_until = NULL, updated_at = ?
        WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?
          AND lease_id = ? AND phase = 'r2'`,
    )
      .bind(
        now,
        now + REPOSITORY_DELETE_EMPTY_CONFIRM_SECONDS,
        now,
        row.tenant_id,
        row.repository_id,
        row.generation_id,
        leaseId,
      )
      .run();
    return;
  }

  if (row.last_empty_at + REPOSITORY_DELETE_EMPTY_CONFIRM_SECONDS > now) {
    await env.DB.prepare(
      `UPDATE repository_deletions
          SET next_attempt_at = ?, lease_id = NULL, lease_until = NULL, updated_at = ?
        WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?
          AND lease_id = ? AND phase = 'r2'`,
    )
      .bind(
        row.last_empty_at + REPOSITORY_DELETE_EMPTY_CONFIRM_SECONDS,
        now,
        row.tenant_id,
        row.repository_id,
        row.generation_id,
        leaseId,
      )
      .run();
    return;
  }

  const advanced = await env.DB.prepare(
    `UPDATE repository_deletions
        SET phase = 'manifest_conflicts', r2_cursor = NULL,
            empty_confirmations = 2, attempts = 0, next_attempt_at = ?,
            lease_id = NULL, lease_until = NULL, updated_at = ?
      WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?
        AND lease_id = ? AND phase = 'r2'`,
  )
    .bind(
      now,
      now,
      row.tenant_id,
      row.repository_id,
      row.generation_id,
      leaseId,
    )
    .run();
  if (advanced.meta.changes === 0) {
    throw new Error("repository deletion lease changed before D1 cleanup");
  }
}

async function updateRepositoryDeletionR2Progress(
  db: D1Database,
  row: RepositoryDeletionRow,
  leaseId: string,
  cursor: string | null,
  now: number,
): Promise<void> {
  const result = await db
    .prepare(
      `UPDATE repository_deletions
        SET r2_cursor = ?, empty_confirmations = 0, last_empty_at = NULL,
            attempts = 0, next_attempt_at = ?, lease_id = NULL,
            lease_until = NULL, updated_at = ?
      WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?
        AND lease_id = ? AND phase = 'r2'`,
    )
    .bind(
      cursor,
      now,
      now,
      row.tenant_id,
      row.repository_id,
      row.generation_id,
      leaseId,
    )
    .run();
  if (result.meta.changes === 0) {
    throw new Error("repository deletion lease changed during R2 progress");
  }
}

const REPOSITORY_D1_PHASES: ReadonlyArray<{
  phase: Exclude<RepositoryDeletionPhase, "r2" | "finalize">;
  next: RepositoryDeletionPhase;
  table: string;
  repositoryColumn: string;
}> = [
  {
    phase: "manifest_conflicts",
    next: "manifests",
    table: "manifest_conflicts",
    repositoryColumn: "repository_id",
  },
  {
    phase: "manifests",
    next: "blobs",
    table: "manifests",
    repositoryColumn: "repository_id",
  },
  {
    phase: "blobs",
    next: "trust_heads",
    table: "blobs",
    repositoryColumn: "repository_id",
  },
  {
    phase: "trust_heads",
    next: "trust_key_history",
    table: "trust_heads",
    repositoryColumn: "repository_id",
  },
  {
    phase: "trust_key_history",
    next: "trust_revoked_keys",
    table: "trust_key_history",
    repositoryColumn: "repository_id",
  },
  {
    phase: "trust_revoked_keys",
    next: "trust_revoked_records",
    table: "trust_revoked_keys",
    repositoryColumn: "repository_id",
  },
  {
    phase: "trust_revoked_records",
    next: "trust_root_keys",
    table: "trust_revoked_records",
    repositoryColumn: "repository_id",
  },
  {
    phase: "trust_root_keys",
    next: "producer_keys",
    table: "trust_root_keys",
    repositoryColumn: "repository_id",
  },
  {
    phase: "producer_keys",
    next: "auth_tokens",
    table: "producer_keys",
    repositoryColumn: "repository_id",
  },
  {
    phase: "auth_tokens",
    next: "audit_events",
    table: "auth_tokens",
    repositoryColumn: "repository_scope",
  },
  {
    phase: "audit_events",
    next: "finalize",
    table: "audit_events",
    repositoryColumn: "repository_id",
  },
];

async function processRepositoryD1Cleanup(
  db: D1Database,
  row: RepositoryDeletionRow,
  leaseId: string,
  now: number,
): Promise<void> {
  let phase = row.phase;
  for (
    let chunk = 0;
    chunk < REPOSITORY_DELETE_D1_CHUNKS_PER_LEASE;
    chunk += 1
  ) {
    if (phase === "finalize") {
      await finalizeRepositoryDeletion(db, row, leaseId, now);
      return;
    }
    const definition = REPOSITORY_D1_PHASES.find(
      (candidate) => candidate.phase === phase,
    );
    if (definition === undefined)
      throw new Error("invalid repository D1 cleanup phase");
    const mutationTime = nowSeconds();
    const targetPredicate = `target.tenant_id = ? AND target.${definition.repositoryColumn} = ?`;
    const remainingPredicate = `tenant_id = ? AND ${definition.repositoryColumn} = ?`;
    const results = await db.batch([
      db
        .prepare(
          `DELETE FROM ${definition.table}
          WHERE rowid IN (
            SELECT target.rowid FROM ${definition.table} target
             WHERE ${targetPredicate}
               AND EXISTS (
                 SELECT 1 FROM repository_deletions deletion
                  WHERE deletion.tenant_id = ? AND deletion.repository_id = ?
                    AND deletion.generation_id = ? AND deletion.lease_id = ?
                    AND deletion.phase = ? AND deletion.lease_until > ?
               )
               AND EXISTS (
                 SELECT 1 FROM repositories repository
                  WHERE repository.tenant_id = ? AND repository.id = ?
                    AND repository.generation_id = ?
                    AND repository.deleted_at IS NOT NULL
               )
             ORDER BY rowid
             LIMIT ?
          )`,
        )
        .bind(
          row.tenant_id,
          row.repository_id,
          row.tenant_id,
          row.repository_id,
          row.generation_id,
          leaseId,
          phase,
          mutationTime,
          row.tenant_id,
          row.repository_id,
          row.generation_id,
          REPOSITORY_DELETE_D1_CHUNK_SIZE,
        ),
      db
        .prepare(
          `UPDATE repository_deletions
            SET phase = ?, attempts = 0, updated_at = ?
          WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?
            AND lease_id = ? AND phase = ?
            AND lease_until > ?
            AND EXISTS (
              SELECT 1 FROM repositories repository
               WHERE repository.tenant_id = repository_deletions.tenant_id
                 AND repository.id = repository_deletions.repository_id
                 AND repository.generation_id = repository_deletions.generation_id
                 AND repository.deleted_at IS NOT NULL
            )
            AND NOT EXISTS (
              SELECT 1 FROM ${definition.table} WHERE ${remainingPredicate}
            )`,
        )
        .bind(
          definition.next,
          mutationTime,
          row.tenant_id,
          row.repository_id,
          row.generation_id,
          leaseId,
          phase,
          mutationTime,
          row.tenant_id,
          row.repository_id,
        ),
    ]);
    if ((results[1]?.meta.changes ?? 0) !== 0) {
      phase = definition.next;
    }
  }
  await releaseRepositoryDeletionLease(db, row, leaseId, now, now, false);
}

async function finalizeRepositoryDeletion(
  db: D1Database,
  row: RepositoryDeletionRow,
  leaseId: string,
  now: number,
): Promise<void> {
  const guardedDelete = db
    .prepare(
      `DELETE FROM repositories
      WHERE tenant_id = ? AND id = ? AND generation_id = ? AND deleted_at IS NOT NULL
        AND EXISTS (
          SELECT 1 FROM repository_deletions deletion
           WHERE deletion.tenant_id = ? AND deletion.repository_id = ?
             AND deletion.generation_id = ? AND deletion.lease_id = ?
             AND deletion.phase = 'finalize'
        )
        AND NOT EXISTS (
          SELECT 1 FROM repository_write_leases
           WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?
        )
        AND NOT EXISTS (SELECT 1 FROM manifest_conflicts WHERE tenant_id = ? AND repository_id = ?)
        AND NOT EXISTS (SELECT 1 FROM manifests WHERE tenant_id = ? AND repository_id = ?)
        AND NOT EXISTS (SELECT 1 FROM blobs WHERE tenant_id = ? AND repository_id = ?)
        AND NOT EXISTS (SELECT 1 FROM trust_heads WHERE tenant_id = ? AND repository_id = ?)
        AND NOT EXISTS (SELECT 1 FROM trust_key_history WHERE tenant_id = ? AND repository_id = ?)
        AND NOT EXISTS (SELECT 1 FROM trust_revoked_keys WHERE tenant_id = ? AND repository_id = ?)
        AND NOT EXISTS (SELECT 1 FROM trust_revoked_records WHERE tenant_id = ? AND repository_id = ?)
        AND NOT EXISTS (SELECT 1 FROM trust_root_keys WHERE tenant_id = ? AND repository_id = ?)
        AND NOT EXISTS (SELECT 1 FROM producer_keys WHERE tenant_id = ? AND repository_id = ?)
        AND NOT EXISTS (SELECT 1 FROM auth_tokens WHERE tenant_id = ? AND repository_scope = ?)
        AND NOT EXISTS (SELECT 1 FROM audit_events WHERE tenant_id = ? AND repository_id = ?)`,
    )
    .bind(
      row.tenant_id,
      row.repository_id,
      row.generation_id,
      row.tenant_id,
      row.repository_id,
      row.generation_id,
      leaseId,
      row.tenant_id,
      row.repository_id,
      row.generation_id,
      row.tenant_id,
      row.repository_id,
      row.tenant_id,
      row.repository_id,
      row.tenant_id,
      row.repository_id,
      row.tenant_id,
      row.repository_id,
      row.tenant_id,
      row.repository_id,
      row.tenant_id,
      row.repository_id,
      row.tenant_id,
      row.repository_id,
      row.tenant_id,
      row.repository_id,
      row.tenant_id,
      row.repository_id,
      row.tenant_id,
      row.repository_id,
      row.tenant_id,
      row.repository_id,
    );
  const results = await db.batch([
    guardedDelete,
    db
      .prepare(
        `UPDATE repository_deletion_receipts
          SET completed_at = coalesce(completed_at, ?)
        WHERE tenant_id = ? AND repository_id = ? AND generation_id = ?
          AND NOT EXISTS (
            SELECT 1 FROM repositories repository
             WHERE repository.tenant_id = ? AND repository.id = ?
          )`,
      )
      .bind(
        now,
        row.tenant_id,
        row.repository_id,
        row.generation_id,
        row.tenant_id,
        row.repository_id,
      ),
  ]);
  if (
    (results[0]?.meta.changes ?? 0) === 0 &&
    (results[1]?.meta.changes ?? 0) === 0
  ) {
    throw new Error(
      "repository deletion preconditions changed before finalization",
    );
  }
  console.log(JSON.stringify({ event: "repository_delete_finalized" }));
}

async function releaseRepositoryDeletionLease(
  db: D1Database,
  row: RepositoryDeletionRow,
  leaseId: string,
  now: number,
  nextAttempt: number,
  resetR2Confirmation: boolean,
): Promise<void> {
  await db
    .prepare(
      `UPDATE repository_deletions
        SET r2_cursor = CASE WHEN ? THEN NULL ELSE r2_cursor END,
            empty_confirmations = CASE WHEN ? THEN 0 ELSE empty_confirmations END,
            last_empty_at = CASE WHEN ? THEN NULL ELSE last_empty_at END,
            attempts = 0, next_attempt_at = ?, lease_id = NULL,
            lease_until = NULL, updated_at = ?
      WHERE tenant_id = ? AND repository_id = ? AND generation_id = ? AND lease_id = ?`,
    )
    .bind(
      resetR2Confirmation ? 1 : 0,
      resetR2Confirmation ? 1 : 0,
      resetR2Confirmation ? 1 : 0,
      nextAttempt,
      now,
      row.tenant_id,
      row.repository_id,
      row.generation_id,
      leaseId,
    )
    .run();
}

async function deferRepositoryDeletion(
  db: D1Database,
  row: RepositoryDeletionRow,
  leaseId: string,
  now: number,
): Promise<void> {
  const delay = Math.min(60 * 60, 30 * 2 ** Math.min(row.attempts, 7));
  await db
    .prepare(
      `UPDATE repository_deletions
          SET attempts = attempts + 1, next_attempt_at = ?,
              r2_cursor = CASE WHEN phase = 'r2' THEN NULL ELSE r2_cursor END,
              empty_confirmations = CASE WHEN phase = 'r2' THEN 0 ELSE empty_confirmations END,
              last_empty_at = CASE WHEN phase = 'r2' THEN NULL ELSE last_empty_at END,
              lease_id = NULL, lease_until = NULL, updated_at = ?
        WHERE tenant_id = ? AND repository_id = ? AND generation_id = ? AND lease_id = ?`,
    )
    .bind(
      now + delay,
      now,
      row.tenant_id,
      row.repository_id,
      row.generation_id,
      leaseId,
    )
    .run();
}

async function reconcileBlobs(env: Env): Promise<void> {
  const now = nowSeconds();
  const rows = await env.DB.prepare(
    `WITH ranked AS (
       SELECT blob.tenant_id, blob.repository_id, repository.generation_id,
              blob.digest, blob.size_bytes, blob.incarnation_id,
              blob.r2_key, blob.r2_version, blob.r2_etag, blob.r2_sha256,
              blob.state, blob.updated_at, blob.reconcile_attempts,
              blob.next_reconcile_at, blob.delete_not_before, blob.created_at,
              row_number() OVER (
                PARTITION BY blob.tenant_id
                ORDER BY blob.next_reconcile_at, blob.created_at,
                         blob.repository_id, blob.digest
              ) AS tenant_rank
         FROM blobs blob
         JOIN repositories repository
           ON repository.tenant_id = blob.tenant_id
          AND repository.id = blob.repository_id
          AND repository.deleted_at IS NULL
        WHERE blob.state IN ('pending', 'deleting') AND blob.next_reconcile_at <= ?
     )
     SELECT tenant_id, repository_id, generation_id, digest, size_bytes,
            incarnation_id, r2_key, r2_version, r2_etag, r2_sha256,
            state, updated_at, reconcile_attempts,
            next_reconcile_at, delete_not_before
       FROM ranked
      ORDER BY tenant_rank, next_reconcile_at, created_at,
               tenant_id, repository_id, digest
      LIMIT ?`,
  )
    .bind(now, RECONCILE_BATCH_SIZE)
    .all<ReconcileBlobRow>();
  for (const row of rows.results) {
    try {
      const key = blobKey(
        row.tenant_id,
        row.repository_id,
        row.generation_id,
        row.digest,
        row.incarnation_id,
      );
      if (row.state === "pending") {
        const verified = await verifyR2ObjectForReconcile(
          env.BLOBS,
          key,
          row.digest,
          row.size_bytes,
          row.incarnation_id,
        );
        if (verified.state === "valid" && verified.identity !== undefined) {
          const promoted = await runReconcileMutationWithAudit(
            env.DB,
            row,
            "promoted",
            env.DB.prepare(
              `UPDATE blobs
                SET state = 'ready', updated_at = ?, reconcile_attempts = 0,
                    next_reconcile_at = ?, delete_not_before = NULL,
                    r2_key = ?, r2_version = ?, r2_etag = ?, r2_sha256 = ?
              WHERE tenant_id = ? AND repository_id = ? AND digest = ?
                AND incarnation_id = ?
                AND state = 'pending' AND reconcile_attempts = ? AND next_reconcile_at = ?
                AND EXISTS (
                  SELECT 1 FROM repositories repository
                   WHERE repository.tenant_id = blobs.tenant_id
                     AND repository.id = blobs.repository_id
                     AND repository.generation_id = ?
                     AND repository.deleted_at IS NULL
                )`,
            ).bind(
              now,
              now,
              verified.identity.key,
              verified.identity.version,
              verified.identity.etag,
              verified.identity.sha256,
              row.tenant_id,
              row.repository_id,
              row.digest,
              row.incarnation_id,
              row.reconcile_attempts,
              row.next_reconcile_at,
              row.generation_id,
            ),
          );
          if (!promoted) continue;
        } else if (
          verified.state === "invalid" ||
          (verified.state === "valid" && verified.identity === undefined)
        ) {
          await runReconcileMutationWithAudit(
            env.DB,
            row,
            "quarantined",
            env.DB.prepare(
              `UPDATE blobs SET state = 'quarantined', updated_at = ?, next_reconcile_at = ?
              WHERE tenant_id = ? AND repository_id = ? AND digest = ?
                AND incarnation_id = ?
                AND state = 'pending' AND reconcile_attempts = ? AND next_reconcile_at = ?
                AND EXISTS (
                  SELECT 1 FROM repositories repository
                   WHERE repository.tenant_id = blobs.tenant_id
                     AND repository.id = blobs.repository_id
                     AND repository.generation_id = ?
                     AND repository.deleted_at IS NULL
                )`,
            ).bind(
              now,
              now,
              row.tenant_id,
              row.repository_id,
              row.digest,
              row.incarnation_id,
              row.reconcile_attempts,
              row.next_reconcile_at,
              row.generation_id,
            ),
          );
        } else {
          await deferReconciliation(env.DB, row, now);
        }
      } else if (row.state === "deleting") {
        if ((row.delete_not_before ?? 0) > now) continue;
        await env.BLOBS.delete(key);
        if ((await env.BLOBS.head(key)) === null) {
          await runReconcileMutationWithAudit(
            env.DB,
            row,
            "deleted",
            env.DB.prepare(
              `DELETE FROM blobs
              WHERE tenant_id = ? AND repository_id = ? AND digest = ?
                AND incarnation_id = ?
                AND state = 'deleting' AND reconcile_attempts = ?
                AND next_reconcile_at = ?
                AND EXISTS (
                  SELECT 1 FROM repositories repository
                   WHERE repository.tenant_id = blobs.tenant_id
                     AND repository.id = blobs.repository_id
                     AND repository.generation_id = ?
                     AND repository.deleted_at IS NULL
                )`,
            ).bind(
              row.tenant_id,
              row.repository_id,
              row.digest,
              row.incarnation_id,
              row.reconcile_attempts,
              row.next_reconcile_at,
              row.generation_id,
            ),
          );
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
            error:
              backoffError instanceof Error
                ? backoffError.name
                : "UnknownError",
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
}

async function runReconcileMutationWithAudit(
  db: D1Database,
  row: ReconcileBlobRow,
  outcome: string,
  mutation: D1PreparedStatement,
): Promise<boolean> {
  const targetHash = await sha256Hex(
    `${row.tenant_id}\0${row.repository_id}\0blob\0${row.digest}`,
  );
  const audit = db
    .prepare(
      `INSERT INTO audit_events(
       tenant_id, repository_id, actor, action, target_type,
       target_id_sha256, outcome, details_json, created_at
     )
     SELECT ?, ?, 'system:reconciler', 'blob.reconcile', 'blob', ?, ?, '{}', ?
      WHERE EXISTS (
        SELECT 1 FROM repositories repository
         WHERE repository.tenant_id = ? AND repository.id = ?
           AND repository.generation_id = ? AND repository.deleted_at IS NULL
      )
        AND EXISTS (
          SELECT 1 FROM blobs blob
           WHERE blob.tenant_id = ? AND blob.repository_id = ? AND blob.digest = ?
             AND blob.incarnation_id = ?
             AND blob.state = ? AND blob.reconcile_attempts = ?
             AND blob.next_reconcile_at = ?
        )`,
    )
    .bind(
      row.tenant_id,
      row.repository_id,
      targetHash,
      outcome,
      nowSeconds(),
      row.tenant_id,
      row.repository_id,
      row.generation_id,
      row.tenant_id,
      row.repository_id,
      row.digest,
      row.incarnation_id,
      row.state,
      row.reconcile_attempts,
      row.next_reconcile_at,
    );
  const results = await db.batch([audit, mutation]);
  const audited = (results[0]?.meta.changes ?? 0) > 0;
  const changed = (results[1]?.meta.changes ?? 0) > 0;
  if (changed !== audited) {
    throw new Error(
      "blob reconciliation mutation/audit generation fence diverged",
    );
  }
  return changed;
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
          AND incarnation_id = ?
          AND state = ? AND reconcile_attempts = ? AND next_reconcile_at = ?
          AND EXISTS (
            SELECT 1 FROM repositories repository
             WHERE repository.tenant_id = blobs.tenant_id
               AND repository.id = blobs.repository_id
               AND repository.generation_id = ?
               AND repository.deleted_at IS NULL
          )`,
    )
    .bind(
      now + delay,
      row.tenant_id,
      row.repository_id,
      row.digest,
      row.incarnation_id,
      row.state,
      row.reconcile_attempts,
      row.next_reconcile_at,
      row.generation_id,
    )
    .run();
  return result.meta.changes !== 0;
}

function databaseErrorContains(error: unknown, marker: string): boolean {
  return String(error).includes(marker);
}

function randomGenerationId(): string {
  const bytes = new Uint8Array(16);
  crypto.getRandomValues(bytes);
  return bytesToHex(bytes);
}

function requireGenerationId(value: string): void {
  if (!/^[0-9a-f]{32}$/.test(value)) {
    throw new Error("invalid repository generation in lifecycle state");
  }
}

function repositoryGenerationHeaders(
  generationId: string,
): Record<string, string> {
  return {
    etag: `"${generationId}"`,
    "x-again-repository-generation": generationId,
  };
}

function repositoryGenerationBindingHeader(
  generationId: string,
): Record<string, string> {
  requireGenerationId(generationId);
  return { "x-again-repository-generation": generationId };
}

function requireRepositoryGenerationRequest(
  request: Request,
  expectedGeneration: string,
): void {
  requireGenerationId(expectedGeneration);
  const supplied = request.headers.get("x-again-repository-generation");
  if (supplied === null) {
    throw new ApiError(
      428,
      "repository_generation_required",
      "X-Again-Repository-Generation is required",
    );
  }
  if (!/^[0-9a-f]{32}$/.test(supplied)) {
    throw new ApiError(
      400,
      "invalid_repository_generation",
      "X-Again-Repository-Generation must contain one lower-case 128-bit generation",
    );
  }
  if (supplied !== expectedGeneration) {
    throw new ApiError(
      412,
      "repository_generation_mismatch",
      "repository generation does not match the live repository",
    );
  }
}

function repositoryGenerationChanged(): ApiError {
  return new ApiError(
    412,
    "repository_generation_mismatch",
    "repository generation changed during the operation",
  );
}

function staleTenantAdminCredential(): ApiError {
  return new ApiError(401, "unauthorized", "valid bearer token required");
}

async function requireActiveRepositoryGenerationForMutation(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  generationId: string,
): Promise<void> {
  await requireRepositoryGeneration(db, tenantId, repositoryId, generationId);
}

function requireRepositoryIfMatch(request: Request): string {
  const value = request.headers.get("if-match");
  if (value === null) {
    throw new ApiError(
      428,
      "repository_generation_required",
      "If-Match repository generation is required",
    );
  }
  const match = /^"([0-9a-f]{32})"$/.exec(value.trim());
  if (match?.[1] === undefined) {
    throw new ApiError(
      400,
      "invalid_repository_generation",
      "If-Match must contain one repository generation ETag",
    );
  }
  return match[1];
}

function repositoryDeletionReceiptResponse(
  repositoryId: string,
  generationId: string,
  receipt: RepositoryDeletionReceiptRow,
): Response {
  const completed = receipt.completed_at !== null;
  return jsonResponse(
    {
      repository_id: repositoryId,
      generation_id: generationId,
      status: completed ? "deleted" : "deleting",
      requested_at_unix_seconds: receipt.requested_at,
      completed_at_unix_seconds: receipt.completed_at,
    },
    completed ? 200 : 202,
    {
      ...repositoryGenerationHeaders(generationId),
      ...(completed
        ? {}
        : { "retry-after": String(REPOSITORY_DELETE_EMPTY_CONFIRM_SECONDS) }),
    },
  );
}

async function acquireRepositoryWriteLease(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  expectedGeneration: string,
): Promise<RepositoryWriteLease> {
  requireGenerationId(expectedGeneration);
  const leaseId = crypto.randomUUID();
  const now = nowSeconds();
  const row = await db
    .prepare(
      `INSERT INTO repository_write_leases(
         tenant_id, repository_id, generation_id, lease_id, created_at, expires_at
       )
       SELECT tenant_id, id, generation_id, ?, ?, ?
         FROM repositories
        WHERE tenant_id = ? AND id = ? AND generation_id = ? AND deleted_at IS NULL
       RETURNING generation_id`,
    )
    .bind(
      leaseId,
      now,
      now + REPOSITORY_WRITE_LEASE_SECONDS,
      tenantId,
      repositoryId,
      expectedGeneration,
    )
    .first<{ generation_id: string }>();
  if (row === null) {
    throw new ApiError(
      412,
      "repository_generation_mismatch",
      "repository generation changed before the write lease was acquired",
    );
  }
  return { leaseId, generationId: row.generation_id };
}

async function releaseRepositoryWriteLease(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  lease: RepositoryWriteLease,
): Promise<void> {
  try {
    await db
      .prepare(
        `DELETE FROM repository_write_leases
          WHERE tenant_id = ? AND repository_id = ?
            AND generation_id = ? AND lease_id = ?`,
      )
      .bind(tenantId, repositoryId, lease.generationId, lease.leaseId)
      .run();
  } catch (error: unknown) {
    console.warn(
      JSON.stringify({
        event: "repository_write_lease_release_failed",
        error: error instanceof Error ? error.name : "UnknownError",
      }),
    );
  }
}

async function renewRepositoryWriteLease(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  lease: RepositoryWriteLease,
): Promise<void> {
  requireGenerationId(lease.generationId);
  const now = nowSeconds();
  const renewed = await db
    .prepare(
      `UPDATE repository_write_leases
          SET expires_at = ?
        WHERE tenant_id = ? AND repository_id = ?
          AND generation_id = ? AND lease_id = ? AND expires_at > ?
          AND EXISTS (
            SELECT 1 FROM repositories repository
             WHERE repository.tenant_id = repository_write_leases.tenant_id
               AND repository.id = repository_write_leases.repository_id
               AND repository.generation_id = repository_write_leases.generation_id
               AND repository.deleted_at IS NULL
          )`,
    )
    .bind(
      now + REPOSITORY_WRITE_LEASE_SECONDS,
      tenantId,
      repositoryId,
      lease.generationId,
      lease.leaseId,
      now,
    )
    .run();
  if (renewed.meta.changes === 0) {
    throw new ApiError(
      412,
      "repository_generation_mismatch",
      "repository generation changed or the write lease expired",
    );
  }
}

function blobKey(
  tenantId: string,
  repositoryId: string,
  generationId: string,
  digest: string,
  incarnationId: string,
): string {
  const legacySuffix =
    incarnationId === LEGACY_BLOB_INCARNATION ? "" : `/${incarnationId}`;
  return `v1/${tenantId}/${repositoryId}/${generationId}/blake3/${digest}${legacySuffix}`;
}

function repositoryBlobPrefix(
  tenantId: string,
  repositoryId: string,
  generationId: string,
): string {
  return `v1/${tenantId}/${repositoryId}/${generationId}/`;
}

function blobHeaders(
  digest: string,
  size: number,
  generationId: string,
): Headers {
  return new Headers({
    "cache-control": "private, no-store",
    "content-length": String(size),
    "content-type": "application/octet-stream",
    etag: quotedDigest(digest),
    "x-again-blake3": digest,
    "x-again-repository-generation": generationId,
    "x-content-type-options": "nosniff",
  });
}

function quotedDigest(digest: string): string {
  return `"${digest}"`;
}

async function producerRevokeAuditStatement(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  generationId: string,
  keyId: string,
): Promise<D1PreparedStatement> {
  const targetHash = await sha256Hex(
    `${auth.tenantId}\0${repositoryId}\0producer_key\0${keyId}`,
  );
  return db
    .prepare(
      `INSERT INTO audit_events(
       tenant_id, repository_id, actor, action, target_type,
       target_id_sha256, outcome, details_json, created_at
     )
     SELECT ?, ?, ?, 'producer.revoke', 'producer_key', ?, 'revoked', '{}', ?
      WHERE EXISTS (
        SELECT 1 FROM producer_keys key
        JOIN repositories repository
          ON repository.tenant_id = key.tenant_id
         AND repository.id = key.repository_id
       WHERE key.tenant_id = ? AND key.repository_id = ? AND key.key_id = ?
         AND key.revoked_at IS NULL AND repository.generation_id = ?
         AND repository.deleted_at IS NULL
      )`,
    )
    .bind(
      auth.tenantId,
      repositoryId,
      auth.subject,
      targetHash,
      nowSeconds(),
      auth.tenantId,
      repositoryId,
      keyId,
      generationId,
    );
}

async function manifestDeleteAuditStatement(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  generationId: string,
  requestKey: string,
): Promise<D1PreparedStatement> {
  const targetHash = await sha256Hex(
    `${auth.tenantId}\0${repositoryId}\0manifest\0${requestKey}`,
  );
  return db
    .prepare(
      `INSERT INTO audit_events(
       tenant_id, repository_id, actor, action, target_type,
       target_id_sha256, outcome, details_json, created_at
     )
     SELECT ?, ?, ?, 'manifest.delete', 'manifest', ?, 'deleted', '{}', ?
      WHERE EXISTS (
        SELECT 1 FROM manifests manifest
        JOIN repositories repository
          ON repository.tenant_id = manifest.tenant_id
         AND repository.id = manifest.repository_id
       WHERE manifest.tenant_id = ? AND manifest.repository_id = ?
         AND manifest.request_key = ? AND manifest.state != 'deleted'
         AND repository.generation_id = ? AND repository.deleted_at IS NULL
      )`,
    )
    .bind(
      auth.tenantId,
      repositoryId,
      auth.subject,
      targetHash,
      nowSeconds(),
      auth.tenantId,
      repositoryId,
      requestKey,
      generationId,
    );
}

async function manifestPutAuditStatement(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  generationId: string,
  requestKey: string,
  keyId: string,
  producerId: string,
  publicKeyHexValue: string,
): Promise<D1PreparedStatement> {
  const targetHash = await sha256Hex(
    `${auth.tenantId}\0${repositoryId}\0manifest\0${requestKey}`,
  );
  return db
    .prepare(
      `INSERT INTO audit_events(
       tenant_id, repository_id, actor, action, target_type,
       target_id_sha256, outcome, details_json, created_at
     )
     SELECT ?, ?, ?, 'manifest.put', 'manifest', ?, 'ready', '{}', ?
      WHERE EXISTS (
        SELECT 1 FROM producer_keys producer
        JOIN repositories repository
          ON repository.tenant_id = producer.tenant_id
         AND repository.id = producer.repository_id
       WHERE producer.tenant_id = ? AND producer.repository_id = ?
         AND producer.key_id = ? AND producer.producer_id = ?
         AND producer.public_key_hex = ? AND producer.revoked_at IS NULL
         AND repository.generation_id = ? AND repository.deleted_at IS NULL
      )`,
    )
    .bind(
      auth.tenantId,
      repositoryId,
      auth.subject,
      targetHash,
      nowSeconds(),
      auth.tenantId,
      repositoryId,
      keyId,
      producerId,
      publicKeyHexValue,
      generationId,
    );
}

async function blobQuarantineAuditStatement(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  generationId: string,
  digest: string,
  incarnationId: string,
  outcome: string,
): Promise<D1PreparedStatement> {
  const targetHash = await sha256Hex(
    `${auth.tenantId}\0${repositoryId}\0blob\0${digest}`,
  );
  return db
    .prepare(
      `INSERT INTO audit_events(
       tenant_id, repository_id, actor, action, target_type,
       target_id_sha256, outcome, details_json, created_at
     )
     SELECT ?, ?, ?, 'blob.quarantine', 'blob', ?, ?, '{}', ?
      WHERE EXISTS (
        SELECT 1 FROM blobs blob
        JOIN repositories repository
          ON repository.tenant_id = blob.tenant_id
         AND repository.id = blob.repository_id
       WHERE blob.tenant_id = ? AND blob.repository_id = ? AND blob.digest = ?
         AND blob.incarnation_id = ? AND blob.state IN ('ready', 'pending')
         AND repository.generation_id = ? AND repository.deleted_at IS NULL
      )`,
    )
    .bind(
      auth.tenantId,
      repositoryId,
      auth.subject,
      targetHash,
      outcome,
      nowSeconds(),
      auth.tenantId,
      repositoryId,
      digest,
      incarnationId,
      generationId,
    );
}

async function blobDeleteAuditStatement(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  generationId: string,
  digest: string,
  incarnationId: string,
  sizeBytes: number,
): Promise<D1PreparedStatement> {
  const targetHash = await sha256Hex(
    `${auth.tenantId}\0${repositoryId}\0blob\0${digest}`,
  );
  return db
    .prepare(
      `INSERT INTO audit_events(
       tenant_id, repository_id, actor, action, target_type,
       target_id_sha256, outcome, details_json, created_at
     )
     SELECT ?, ?, ?, 'blob.delete', 'blob', ?, 'deleted', ?, ?
      WHERE EXISTS (
        SELECT 1 FROM blobs blob
        JOIN repositories repository
          ON repository.tenant_id = blob.tenant_id
         AND repository.id = blob.repository_id
       WHERE blob.tenant_id = ? AND blob.repository_id = ? AND blob.digest = ?
         AND blob.incarnation_id = ? AND blob.state = 'deleting'
         AND repository.generation_id = ? AND repository.deleted_at IS NULL
      )`,
    )
    .bind(
      auth.tenantId,
      repositoryId,
      auth.subject,
      targetHash,
      JSON.stringify({ size_bytes: sizeBytes }),
      nowSeconds(),
      auth.tenantId,
      repositoryId,
      digest,
      incarnationId,
      generationId,
    );
}

async function blobPendingCancellationAuditStatement(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  generationId: string,
  digest: string,
  incarnationId: string,
  pendingUpdatedAtCutoff: number,
  deleteNotBefore: number,
): Promise<D1PreparedStatement> {
  const targetHash = await sha256Hex(
    `${auth.tenantId}\0${repositoryId}\0blob\0${digest}`,
  );
  return db
    .prepare(
      `INSERT INTO audit_events(
       tenant_id, repository_id, actor, action, target_type,
       target_id_sha256, outcome, details_json, created_at
     )
     SELECT ?, ?, ?, 'blob.cancel', 'blob', ?, 'deleting_after_grace', ?, ?
      WHERE EXISTS (
        SELECT 1 FROM blobs blob
        JOIN repositories repository
          ON repository.tenant_id = blob.tenant_id
         AND repository.id = blob.repository_id
       WHERE blob.tenant_id = ? AND blob.repository_id = ? AND blob.digest = ?
         AND blob.incarnation_id = ? AND blob.state = 'pending'
         AND blob.updated_at <= ? AND repository.generation_id = ?
         AND repository.deleted_at IS NULL
      )`,
    )
    .bind(
      auth.tenantId,
      repositoryId,
      auth.subject,
      targetHash,
      JSON.stringify({ delete_not_before: deleteNotBefore }),
      nowSeconds(),
      auth.tenantId,
      repositoryId,
      digest,
      incarnationId,
      pendingUpdatedAtCutoff,
      generationId,
    );
}

async function writeGenerationGuardedAudit(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string,
  generationId: string,
  action: string,
  targetType: string,
  targetId: string,
  outcome: string,
): Promise<boolean> {
  requireGenerationId(generationId);
  const statement = await generationGuardedAuditStatement(
    db,
    auth.tenantId,
    repositoryId,
    generationId,
    auth.subject,
    action,
    targetType,
    targetId,
    outcome,
  );
  const result = await statement.run();
  return result.meta.changes > 0;
}

function safeAuditDetails(value: string): unknown {
  try {
    return JSON.parse(value) as unknown;
  } catch {
    return { invalid: true };
  }
}

function methodNotAllowed(): ApiError {
  return new ApiError(
    405,
    "method_not_allowed",
    "method is not allowed for this resource",
  );
}

function manifestNotFound(): ApiError {
  return new ApiError(404, "manifest_not_found", "manifest not found");
}
