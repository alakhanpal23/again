export const MAX_BLOB_SIZE = 16 * 1024 * 1024;
export const MAX_JSON_SIZE = 64 * 1024;
export const MAX_SMALL_JSON_SIZE = 4 * 1024;
const MAX_BODY_CHUNKS = 4096;
const STREAM_CANCEL_GRACE_MS = 10;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });
const SERVICE_ERROR_CODES = new Set([
  "active_key_revoked",
  "admin_required",
  "blob_conflict",
  "blob_deleting",
  "blob_integrity_failure",
  "blob_pending",
  "blob_quarantined",
  "blob_referenced",
  "blob_state_changed",
  "blob_storage_unavailable",
  "blob_unavailable",
  "body_too_large",
  "content_length_mismatch",
  "delete_incomplete",
  "delete_state_unavailable",
  "digest_mismatch",
  "endpoint_mismatch",
  "execution_profile_not_allowed",
  "expired_manifest",
  "expired_trust_bundle",
  "fresh_trust_required",
  "future_manifest",
  "future_trust_bundle",
  "image_not_allowed",
  "internal_error",
  "invalid_blob_size",
  "invalid_byte_array",
  "invalid_content_length",
  "invalid_cursor",
  "invalid_digest",
  "invalid_epoch",
  "invalid_field",
  "invalid_fields",
  "invalid_hex",
  "invalid_identifier",
  "invalid_json",
  "invalid_json_shape",
  "invalid_lifetime",
  "invalid_limit",
  "invalid_origin",
  "invalid_producer_public_key",
  "invalid_public_key",
  "invalid_repository_generation",
  "invalid_signature",
  "key_binding_conflict",
  "length_required",
  "local_only",
  "manifest_conflict",
  "manifest_not_found",
  "manifest_state_corrupt",
  "metadata_quota_exceeded",
  "method_not_allowed",
  "nonce_reuse",
  "nonempty_stderr",
  "not_found",
  "permission_denied",
  "platform_not_allowed",
  "policy_not_allowed",
  "producer_registry_mismatch",
  "producer_revoked",
  "quota_exceeded",
  "rate_limited",
  "record_revoked",
  "request_timeout",
  "repository_deleting",
  "repository_generation_mismatch",
  "repository_generation_required",
  "repository_mismatch",
  "repository_state_changed",
  "request_key_mismatch",
  "secret_tainted",
  "tenant_mismatch",
  "too_many_entries",
  "truncated_body",
  "trust_bundle_too_large",
  "trust_changed",
  "trust_epoch_conflict",
  "trust_epoch_rollback",
  "trust_key_rebinding",
  "trust_record_revocation_rollback",
  "trust_revocation_rollback",
  "trust_root_rebinding",
  "trust_state_corrupt",
  "unauthorized",
  "unencrypted_confidential",
  "unsorted_or_duplicate",
  "unsupported_media_type",
  "unsupported_proof",
  "unsupported_result_status",
  "unsupported_schema",
  "unsupported_signature",
  "untrusted_producer",
  "untrusted_root",
]);

export class ApiError extends Error {
  constructor(
    readonly status: number,
    readonly code: string,
    message: string,
  ) {
    super(message);
    this.name = "ApiError";
  }
}

export function jsonResponse(value: unknown, status = 200, extra?: HeadersInit): Response {
  const headers = responseHeaders(extra);
  headers.set("content-type", "application/json; charset=utf-8");
  return new Response(JSON.stringify(value), { status, headers });
}

export function emptyResponse(status: number, extra?: HeadersInit): Response {
  return new Response(null, { status, headers: responseHeaders(extra) });
}

export function errorResponse(error: ApiError, requestId: string): Response {
  const code = SERVICE_ERROR_CODES.has(error.code) ? error.code : "internal_error";
  const status = code === error.code ? error.status : 500;
  const message = code === error.code ? error.message : "request could not be completed";
  return jsonResponse(
    {
      error: {
        code,
        message,
        request_id: requestId,
      },
    },
    status,
    { "x-again-error-code": code, "x-request-id": requestId },
  );
}

function responseHeaders(extra?: HeadersInit): Headers {
  const headers = new Headers(extra);
  headers.set("cache-control", "no-store");
  headers.set("x-content-type-options", "nosniff");
  return headers;
}

export async function readBytesBounded(
  request: Request,
  maximum: number,
  requireLength = false,
  timeoutMilliseconds?: number,
): Promise<Uint8Array> {
  const declared = request.headers.get("content-length");
  if (requireLength && declared === null) {
    throw new ApiError(411, "length_required", "Content-Length is required");
  }
  if (declared !== null) {
    if (!/^\d+$/.test(declared)) {
      throw new ApiError(400, "invalid_content_length", "Content-Length is invalid");
    }
    const length = Number(declared);
    if (!Number.isSafeInteger(length) || length > maximum) {
      throw new ApiError(413, "body_too_large", "request body exceeds the limit");
    }
  }

  if (request.body === null) {
    if (declared !== null && declared !== "0") {
      throw new ApiError(400, "truncated_body", "request body is shorter than Content-Length");
    }
    return new Uint8Array();
  }

  const reader = request.body.getReader();
  const chunks: Uint8Array[] = [];
  let total = 0;
  let chunkReads = 0;
  const deadline =
    timeoutMilliseconds === undefined ? null : Date.now() + Math.max(0, timeoutMilliseconds);
  try {
    for (;;) {
      const { done, value } = await readStreamChunkBefore(reader, deadline);
      if (done) break;
      chunkReads += 1;
      if (chunkReads > MAX_BODY_CHUNKS) {
        await cancelStreamReaderBounded(reader, "body chunk limit exceeded");
        throw new ApiError(413, "body_too_large", "request body is too fragmented");
      }
      if (value.byteLength === 0) continue;
      total += value.byteLength;
      if (total > maximum) {
        await cancelStreamReaderBounded(reader, "body limit exceeded");
        throw new ApiError(413, "body_too_large", "request body exceeds the limit");
      }
      chunks.push(value);
    }
  } catch (error: unknown) {
    if (error instanceof ApiError && error.code === "request_timeout") {
      await cancelStreamReaderBounded(reader, "request body deadline exceeded");
    }
    throw error;
  } finally {
    try {
      reader.releaseLock();
    } catch {
      // A source that ignores cancellation may retain its pending read. The
      // request still fails at the absolute deadline; never wait forever just
      // to release an adversarial stream lock.
    }
  }
  if (declared !== null && total !== Number(declared)) {
    throw new ApiError(400, "content_length_mismatch", "body length does not match Content-Length");
  }
  const output = new Uint8Array(total);
  let offset = 0;
  for (const chunk of chunks) {
    output.set(chunk, offset);
    offset += chunk.byteLength;
  }
  return output;
}

async function cancelStreamReaderBounded(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  reason: string,
): Promise<void> {
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    await Promise.race([
      reader.cancel(reason).catch(() => undefined),
      new Promise<void>((resolve) => {
        timer = setTimeout(resolve, STREAM_CANCEL_GRACE_MS);
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

async function readStreamChunkBefore(
  reader: ReadableStreamDefaultReader<Uint8Array>,
  deadline: number | null,
): Promise<ReadableStreamReadResult<Uint8Array>> {
  if (deadline === null) return reader.read();
  const remaining = deadline - Date.now();
  if (remaining <= 0) {
    throw new ApiError(408, "request_timeout", "request body exceeded its time limit");
  }
  let timer: ReturnType<typeof setTimeout> | undefined;
  try {
    return await Promise.race([
      reader.read(),
      new Promise<never>((_resolve, reject) => {
        timer = setTimeout(
          () => reject(new ApiError(408, "request_timeout", "request body exceeded its time limit")),
          remaining,
        );
      }),
    ]);
  } finally {
    if (timer !== undefined) clearTimeout(timer);
  }
}

export async function readJsonObject(request: Request, maximum: number): Promise<Record<string, unknown>> {
  const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") {
    throw new ApiError(415, "unsupported_media_type", "Content-Type must be application/json");
  }
  const bytes = await readBytesBounded(request, maximum, false, 30_000);
  let value: unknown;
  try {
    value = JSON.parse(decoder.decode(bytes));
  } catch {
    throw new ApiError(400, "invalid_json", "request body must be valid UTF-8 JSON");
  }
  if (!isRecord(value)) {
    throw new ApiError(400, "invalid_json_shape", "request body must be a JSON object");
  }
  return value;
}

export function isRecord(value: unknown): value is Record<string, unknown> {
  return typeof value === "object" && value !== null && !Array.isArray(value);
}

export function assertExactKeys(
  value: Record<string, unknown>,
  expected: readonly string[],
  field: string,
): void {
  const actual = Object.keys(value).sort();
  const wanted = [...expected].sort();
  if (actual.length !== wanted.length || actual.some((key, index) => key !== wanted[index])) {
    throw new ApiError(400, "invalid_fields", `${field} contains missing or unknown fields`);
  }
}

export function requireString(value: unknown, field: string): string {
  if (typeof value !== "string") {
    throw new ApiError(400, "invalid_field", `${field} must be a string`);
  }
  return value;
}

export function requireBoolean(value: unknown, field: string): boolean {
  if (typeof value !== "boolean") {
    throw new ApiError(400, "invalid_field", `${field} must be a boolean`);
  }
  return value;
}

export function requireSafeInteger(value: unknown, field: string): number {
  if (typeof value !== "number" || !Number.isSafeInteger(value) || value < 0) {
    throw new ApiError(400, "invalid_field", `${field} must be a non-negative safe integer`);
  }
  return value;
}

export function requireProtocolIdentifier(value: unknown, field: string): string {
  const identifier = requireString(value, field);
  const encodedLength = encoder.encode(identifier).byteLength;
  if (
    encodedLength === 0 ||
    encodedLength > 256 ||
    /[\p{Cc}\p{White_Space}\ud800-\udfff]/u.test(identifier)
  ) {
    throw new ApiError(400, "invalid_identifier", `${field} is not a valid protocol identifier`);
  }
  return identifier;
}

export function requireRouteIdentifier(value: string, field: string): string {
  if (!/^[A-Za-z0-9][A-Za-z0-9._:-]{0,127}$/.test(value)) {
    throw new ApiError(400, "invalid_identifier", `${field} is not a valid route identifier`);
  }
  return value;
}

export function requireDigest(value: unknown, field: string): string {
  const digest = requireString(value, field);
  if (!/^[0-9a-f]{64}$/.test(digest)) {
    throw new ApiError(400, "invalid_digest", `${field} must be a lower-case 64-character digest`);
  }
  return digest;
}

export async function sha256Hex(value: Uint8Array | string): Promise<string> {
  const bytes = typeof value === "string" ? encoder.encode(value) : value;
  return bytesToHex(new Uint8Array(await crypto.subtle.digest("SHA-256", bytes)));
}

export function bytesToHex(value: Uint8Array): string {
  let output = "";
  for (const byte of value) output += byte.toString(16).padStart(2, "0");
  return output;
}

export function hexToBytes(value: string): Uint8Array {
  if (!/^[0-9a-f]*$/.test(value) || value.length % 2 !== 0) {
    throw new ApiError(400, "invalid_hex", "hex value is malformed");
  }
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

export function nowSeconds(): number {
  return Math.floor(Date.now() / 1000);
}
