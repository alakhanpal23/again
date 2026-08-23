export const MAX_BLOB_SIZE = 16 * 1024 * 1024;
export const MAX_JSON_SIZE = 64 * 1024;
export const MAX_SMALL_JSON_SIZE = 4 * 1024;

const encoder = new TextEncoder();
const decoder = new TextDecoder("utf-8", { fatal: true, ignoreBOM: false });

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
  return jsonResponse(
    {
      error: {
        code: error.code,
        message: error.message,
        request_id: requestId,
      },
    },
    error.status,
    { "x-request-id": requestId },
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
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maximum) {
        await reader.cancel("body limit exceeded");
        throw new ApiError(413, "body_too_large", "request body exceeds the limit");
      }
      chunks.push(value);
    }
  } finally {
    reader.releaseLock();
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

export async function readJsonObject(request: Request, maximum: number): Promise<Record<string, unknown>> {
  const contentType = request.headers.get("content-type")?.split(";", 1)[0]?.trim().toLowerCase();
  if (contentType !== "application/json") {
    throw new ApiError(415, "unsupported_media_type", "Content-Type must be application/json");
  }
  const bytes = await readBytesBounded(request, maximum);
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
