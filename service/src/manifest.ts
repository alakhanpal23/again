import {
  ApiError,
  assertExactKeys,
  bytesToHex,
  hexToBytes,
  isRecord,
  requireBoolean,
  requireDigest,
  requireProtocolIdentifier,
  requireSafeInteger,
  requireString,
} from "./util";

const SIGNING_DOMAIN = new TextEncoder().encode("again.remote-cache.manifest.v1");
const MAX_BLOB_SIZE = 16 * 1024 * 1024;
const MAX_LIFETIME_SECONDS = 30 * 24 * 60 * 60;

export interface BlobRef {
  digest: string;
  size_bytes: number;
}

export type PrivacyClass = "public" | "internal" | "confidential" | "secret";
export type Shareability = "local_only" | "tenant" | "repository";

export interface RemoteCacheManifest {
  schema_version: 1;
  record_id: string;
  tenant_id: string;
  repository_id: string;
  request_key: string;
  policy_digest: string;
  execution_profile_digest: string;
  platform_digest: string;
  image_digest: string;
  stdout: BlobRef;
  stderr: BlobRef;
  producer_id: string;
  created_at_unix_seconds: number;
  expires_at_unix_seconds: number;
  privacy: {
    classification: PrivacyClass;
    shareability: Shareability;
    secret_tainted: boolean;
  };
  signature: {
    schema_version: number;
    algorithm: "ed25519";
    key_id: string;
    signature: number[];
  };
}

export function parseManifest(value: Record<string, unknown>, now: number | null): RemoteCacheManifest {
  assertExactKeys(
    value,
    [
      "schema_version",
      "record_id",
      "tenant_id",
      "repository_id",
      "request_key",
      "policy_digest",
      "execution_profile_digest",
      "platform_digest",
      "image_digest",
      "stdout",
      "stderr",
      "producer_id",
      "created_at_unix_seconds",
      "expires_at_unix_seconds",
      "privacy",
      "signature",
    ],
    "manifest",
  );
  if (value.schema_version !== 1) {
    throw new ApiError(422, "unsupported_schema", "manifest schema_version must be 1");
  }
  const stdout = parseBlob(value.stdout, "stdout");
  const stderr = parseBlob(value.stderr, "stderr");
  const privacy = parsePrivacy(value.privacy);
  const signature = parseSignature(value.signature);
  const created = requireSafeInteger(value.created_at_unix_seconds, "created_at_unix_seconds");
  const expires = requireSafeInteger(value.expires_at_unix_seconds, "expires_at_unix_seconds");
  if (expires <= created || expires - created > MAX_LIFETIME_SECONDS) {
    throw new ApiError(422, "invalid_lifetime", "manifest lifetime must be positive and at most 30 days");
  }
  if (now !== null && expires <= now) {
    throw new ApiError(422, "expired_manifest", "manifest has expired");
  }
  if (now !== null && created > now + 300) {
    throw new ApiError(422, "future_manifest", "manifest creation time is too far in the future");
  }
  if (privacy.classification === "confidential") {
    throw new ApiError(
      422,
      "unencrypted_confidential",
      "confidential manifests require an encrypted schema",
    );
  }
  if (privacy.secret_tainted || privacy.classification === "secret") {
    throw new ApiError(422, "secret_tainted", "secret-tainted manifests must remain local");
  }
  if (privacy.shareability === "local_only") {
    throw new ApiError(422, "local_only", "local-only manifests cannot be uploaded");
  }

  return {
    schema_version: 1,
    record_id: requireProtocolIdentifier(value.record_id, "record_id"),
    tenant_id: requireProtocolIdentifier(value.tenant_id, "tenant_id"),
    repository_id: requireProtocolIdentifier(value.repository_id, "repository_id"),
    request_key: requireDigest(value.request_key, "request_key"),
    policy_digest: requireDigest(value.policy_digest, "policy_digest"),
    execution_profile_digest: requireDigest(
      value.execution_profile_digest,
      "execution_profile_digest",
    ),
    platform_digest: requireDigest(value.platform_digest, "platform_digest"),
    image_digest: requireDigest(value.image_digest, "image_digest"),
    stdout,
    stderr,
    producer_id: requireProtocolIdentifier(value.producer_id, "producer_id"),
    created_at_unix_seconds: created,
    expires_at_unix_seconds: expires,
    privacy,
    signature,
  };
}

function parseBlob(value: unknown, field: string): BlobRef {
  if (!isRecord(value)) throw new ApiError(400, "invalid_field", `${field} must be an object`);
  assertExactKeys(value, ["digest", "size_bytes"], field);
  const size = requireSafeInteger(value.size_bytes, `${field}.size_bytes`);
  if (size > MAX_BLOB_SIZE) {
    throw new ApiError(422, "invalid_blob_size", `${field} exceeds the maximum blob size`);
  }
  return { digest: requireDigest(value.digest, `${field}.digest`), size_bytes: size };
}

function parsePrivacy(value: unknown): RemoteCacheManifest["privacy"] {
  if (!isRecord(value)) throw new ApiError(400, "invalid_field", "privacy must be an object");
  assertExactKeys(value, ["classification", "shareability", "secret_tainted"], "privacy");
  const classification = requireString(value.classification, "privacy.classification");
  if (!isPrivacyClass(classification)) {
    throw new ApiError(400, "invalid_field", "privacy.classification is unsupported");
  }
  const shareability = requireString(value.shareability, "privacy.shareability");
  if (!isShareability(shareability)) {
    throw new ApiError(400, "invalid_field", "privacy.shareability is unsupported");
  }
  return {
    classification,
    shareability,
    secret_tainted: requireBoolean(value.secret_tainted, "privacy.secret_tainted"),
  };
}

function parseSignature(value: unknown): RemoteCacheManifest["signature"] {
  if (!isRecord(value)) throw new ApiError(400, "invalid_field", "signature must be an object");
  assertExactKeys(value, ["schema_version", "algorithm", "key_id", "signature"], "signature");
  if (value.schema_version !== 1 || value.algorithm !== "ed25519") {
    throw new ApiError(422, "unsupported_signature", "only signature schema 1 with Ed25519 is accepted");
  }
  if (!Array.isArray(value.signature) || value.signature.length !== 64) {
    throw new ApiError(400, "invalid_signature", "Ed25519 signature must contain exactly 64 bytes");
  }
  const bytes: number[] = [];
  for (const byte of value.signature) {
    if (typeof byte !== "number" || !Number.isInteger(byte) || byte < 0 || byte > 255) {
      throw new ApiError(400, "invalid_signature", "signature contains an invalid byte");
    }
    bytes.push(byte);
  }
  return {
    schema_version: 1,
    algorithm: "ed25519",
    key_id: requireProtocolIdentifier(value.key_id, "signature.key_id"),
    signature: bytes,
  };
}

export function canonicalManifestJson(manifest: RemoteCacheManifest): string {
  return JSON.stringify(manifest);
}

export function canonicalManifestBytes(manifest: RemoteCacheManifest): Uint8Array {
  const output: number[] = [];
  putBytes(output, SIGNING_DOMAIN);
  putU16(output, manifest.schema_version);
  putString(output, manifest.record_id);
  putString(output, manifest.tenant_id);
  putString(output, manifest.repository_id);
  putBytes(output, hexToBytes(manifest.request_key));
  putBytes(output, hexToBytes(manifest.policy_digest));
  putBytes(output, hexToBytes(manifest.execution_profile_digest));
  putBytes(output, hexToBytes(manifest.platform_digest));
  putBytes(output, hexToBytes(manifest.image_digest));
  putBlob(output, manifest.stdout);
  putBlob(output, manifest.stderr);
  putString(output, manifest.producer_id);
  putU64(output, manifest.created_at_unix_seconds);
  putU64(output, manifest.expires_at_unix_seconds);
  output.push(privacyTag(manifest.privacy.classification));
  output.push(shareabilityTag(manifest.privacy.shareability));
  output.push(manifest.privacy.secret_tainted ? 1 : 0);
  output.push(1);
  putU16(output, manifest.signature.schema_version);
  output.push(1);
  putString(output, manifest.signature.key_id);
  return Uint8Array.from(output);
}

export async function verifyManifestSignature(
  manifest: RemoteCacheManifest,
  publicKeyHex: string,
): Promise<boolean> {
  try {
    const publicKey = await crypto.subtle.importKey(
      "raw",
      hexToBytes(publicKeyHex),
      { name: "Ed25519" },
      false,
      ["verify"],
    );
    return await crypto.subtle.verify(
      "Ed25519",
      publicKey,
      Uint8Array.from(manifest.signature.signature),
      canonicalManifestBytes(manifest),
    );
  } catch {
    return false;
  }
}

export function publicKeyHex(value: unknown): string {
  const key = requireString(value, "public_key_hex");
  if (!/^[0-9a-f]{64}$/.test(key)) {
    throw new ApiError(400, "invalid_public_key", "public_key_hex must encode 32 bytes in lower-case hex");
  }
  return key;
}

function putBlob(output: number[], blob: BlobRef): void {
  putBytes(output, hexToBytes(blob.digest));
  putU64(output, blob.size_bytes);
}

function putString(output: number[], value: string): void {
  putBytes(output, new TextEncoder().encode(value));
}

function putBytes(output: number[], value: Uint8Array): void {
  putU64(output, value.length);
  output.push(...value);
}

function putU16(output: number[], value: number): void {
  output.push(value & 0xff, (value >>> 8) & 0xff);
}

function putU64(output: number[], value: number): void {
  let remaining = BigInt(value);
  for (let index = 0; index < 8; index += 1) {
    output.push(Number(remaining & 0xffn));
    remaining >>= 8n;
  }
}

function privacyTag(value: PrivacyClass): number {
  return { public: 1, internal: 2, confidential: 3, secret: 4 }[value];
}

function shareabilityTag(value: Shareability): number {
  return { local_only: 1, tenant: 2, repository: 3 }[value];
}

function isPrivacyClass(value: string): value is PrivacyClass {
  return value === "public" || value === "internal" || value === "confidential" || value === "secret";
}

function isShareability(value: string): value is Shareability {
  return value === "local_only" || value === "tenant" || value === "repository";
}

export function digestDebug(value: Uint8Array): string {
  return bytesToHex(value);
}
