import {
  ApiError,
  assertExactKeys,
  hexToBytes,
  isRecord,
  requireDigest,
  requireProtocolIdentifier,
  requireSafeInteger,
  requireString,
} from "./util";
import { verifyEd25519Strict } from "./ed25519-strict";
import type { PrivacyClass, Shareability } from "./manifest";

const SIGNING_DOMAIN = new TextEncoder().encode("again.remote-cache.encrypted-manifest.v2");
const MAX_CIPHERTEXT_SIZE = 16 * 1024 * 1024;
const POLY1305_TAG_BYTES = 16;
const MAX_LIFETIME_SECONDS = 30 * 24 * 60 * 60;

export interface EncryptedStreamRefV2 {
  ciphertext_digest: string;
  ciphertext_size_bytes: number;
  nonce: number[];
}

export interface EncryptedRemoteCacheManifestV2 {
  schema_version: 2;
  record_id: string;
  tenant_id: string;
  repository_id: string;
  generation_id: string;
  request_key: string;
  policy_digest: string;
  classifier_digest: string;
  execution_profile_digest: string;
  platform_digest: string;
  image_digest: string;
  result_status: "success";
  duration_micros: number;
  proof_schema_version: 1;
  producer_version: string;
  local_proof_digest: string;
  privacy: {
    classification: PrivacyClass;
    shareability: Shareability;
    secret_tainted: boolean;
  };
  repository_encryption_key_id: string;
  stdout: EncryptedStreamRefV2;
  stderr: EncryptedStreamRefV2;
  producer_id: string;
  created_at_unix_seconds: number;
  expires_at_unix_seconds: number;
  signature: {
    schema_version: 1;
    algorithm: "ed25519";
    key_id: string;
    signature: number[];
  };
}

export function parseEncryptedManifestV2(
  value: Record<string, unknown>,
  now: number | null,
): EncryptedRemoteCacheManifestV2 {
  assertExactKeys(
    value,
    [
      "schema_version",
      "record_id",
      "tenant_id",
      "repository_id",
      "generation_id",
      "request_key",
      "policy_digest",
      "classifier_digest",
      "execution_profile_digest",
      "platform_digest",
      "image_digest",
      "result_status",
      "duration_micros",
      "proof_schema_version",
      "producer_version",
      "local_proof_digest",
      "privacy",
      "repository_encryption_key_id",
      "stdout",
      "stderr",
      "producer_id",
      "created_at_unix_seconds",
      "expires_at_unix_seconds",
      "signature",
    ],
    "encrypted_manifest_v2",
  );
  if (value.schema_version !== 2) {
    throw new ApiError(422, "unsupported_schema", "encrypted manifest schema_version must be 2");
  }
  if (value.result_status !== "success") {
    throw new ApiError(422, "unsupported_result_status", "only successful results are shareable");
  }
  if (value.proof_schema_version !== 1) {
    throw new ApiError(422, "unsupported_proof", "local result proof schema_version must be 1");
  }

  const created = requireSafeInteger(value.created_at_unix_seconds, "created_at_unix_seconds");
  const expires = requireSafeInteger(value.expires_at_unix_seconds, "expires_at_unix_seconds");
  if (expires <= created || expires - created > MAX_LIFETIME_SECONDS) {
    throw new ApiError(422, "invalid_lifetime", "manifest lifetime must be positive and at most 30 days");
  }
  if (now !== null && expires <= now) {
    throw new ApiError(422, "expired_manifest", "manifest has expired");
  }
  if (now !== null && created > now) {
    throw new ApiError(422, "future_manifest", "manifest creation time cannot be in the future");
  }

  const privacy = parsePrivacy(value.privacy);
  const stdout = parseEncryptedStream(value.stdout, "stdout");
  const stderr = parseEncryptedStream(value.stderr, "stderr");
  if (stderr.ciphertext_size_bytes !== POLY1305_TAG_BYTES) {
    throw new ApiError(422, "nonempty_stderr", "validated stderr must contain only an authentication tag");
  }
  if (bytesEqual(stdout.nonce, stderr.nonce)) {
    throw new ApiError(422, "nonce_reuse", "encrypted stream nonces must be distinct");
  }

  return {
    schema_version: 2,
    record_id: requireProtocolIdentifier(value.record_id, "record_id"),
    tenant_id: requireProtocolIdentifier(value.tenant_id, "tenant_id"),
    repository_id: requireProtocolIdentifier(value.repository_id, "repository_id"),
    generation_id: requireGenerationId(value.generation_id),
    request_key: requireDigest(value.request_key, "request_key"),
    policy_digest: requireDigest(value.policy_digest, "policy_digest"),
    classifier_digest: requireDigest(value.classifier_digest, "classifier_digest"),
    execution_profile_digest: requireDigest(
      value.execution_profile_digest,
      "execution_profile_digest",
    ),
    platform_digest: requireDigest(value.platform_digest, "platform_digest"),
    image_digest: requireDigest(value.image_digest, "image_digest"),
    result_status: "success",
    duration_micros: requireSafeInteger(value.duration_micros, "duration_micros"),
    proof_schema_version: 1,
    producer_version: requireProtocolIdentifier(value.producer_version, "producer_version"),
    local_proof_digest: requireDigest(value.local_proof_digest, "local_proof_digest"),
    privacy,
    repository_encryption_key_id: requireProtocolIdentifier(
      value.repository_encryption_key_id,
      "repository_encryption_key_id",
    ),
    stdout,
    stderr,
    producer_id: requireProtocolIdentifier(value.producer_id, "producer_id"),
    created_at_unix_seconds: created,
    expires_at_unix_seconds: expires,
    signature: parseSignature(value.signature),
  };
}

export function canonicalEncryptedManifestV2Bytes(
  manifest: EncryptedRemoteCacheManifestV2,
): Uint8Array {
  const output: number[] = [];
  putBytes(output, SIGNING_DOMAIN);
  putU16(output, manifest.schema_version);
  putString(output, manifest.record_id);
  putString(output, manifest.tenant_id);
  putString(output, manifest.repository_id);
  putString(output, manifest.generation_id);
  putDigest(output, manifest.request_key);
  putDigest(output, manifest.policy_digest);
  putDigest(output, manifest.classifier_digest);
  putDigest(output, manifest.execution_profile_digest);
  putDigest(output, manifest.platform_digest);
  putDigest(output, manifest.image_digest);
  output.push(1);
  putU64(output, manifest.duration_micros);
  putU16(output, manifest.proof_schema_version);
  putString(output, manifest.producer_version);
  putDigest(output, manifest.local_proof_digest);
  output.push(privacyTag(manifest.privacy.classification));
  output.push(shareabilityTag(manifest.privacy.shareability));
  output.push(manifest.privacy.secret_tainted ? 1 : 0);
  putString(output, manifest.repository_encryption_key_id);
  putEncryptedStream(output, manifest.stdout);
  putEncryptedStream(output, manifest.stderr);
  putString(output, manifest.producer_id);
  putU64(output, manifest.created_at_unix_seconds);
  putU64(output, manifest.expires_at_unix_seconds);
  putU16(output, manifest.signature.schema_version);
  output.push(1);
  putString(output, manifest.signature.key_id);
  return Uint8Array.from(output);
}

export async function verifyEncryptedManifestV2Signature(
  manifest: EncryptedRemoteCacheManifestV2,
  publicKeyHex: string,
): Promise<boolean> {
  try {
    return verifyEd25519Strict(
      canonicalEncryptedManifestV2Bytes(manifest),
      Uint8Array.from(manifest.signature.signature),
      hexToBytes(publicKeyHex),
    );
  } catch {
    return false;
  }
}

function parseEncryptedStream(value: unknown, field: string): EncryptedStreamRefV2 {
  if (!isRecord(value)) throw new ApiError(400, "invalid_field", `${field} must be an object`);
  assertExactKeys(value, ["ciphertext_digest", "ciphertext_size_bytes", "nonce"], field);
  const size = requireSafeInteger(value.ciphertext_size_bytes, `${field}.ciphertext_size_bytes`);
  if (size < POLY1305_TAG_BYTES || size > MAX_CIPHERTEXT_SIZE) {
    throw new ApiError(422, "invalid_blob_size", `${field} ciphertext size is outside the limit`);
  }
  return {
    ciphertext_digest: requireDigest(value.ciphertext_digest, `${field}.ciphertext_digest`),
    ciphertext_size_bytes: size,
    nonce: requireByteArray(value.nonce, 24, `${field}.nonce`),
  };
}

function parsePrivacy(value: unknown): EncryptedRemoteCacheManifestV2["privacy"] {
  if (!isRecord(value)) throw new ApiError(400, "invalid_field", "privacy must be an object");
  assertExactKeys(value, ["classification", "shareability", "secret_tainted"], "privacy");
  const classification = requireString(value.classification, "privacy.classification");
  if (
    classification !== "public" &&
    classification !== "internal" &&
    classification !== "confidential" &&
    classification !== "secret"
  ) {
    throw new ApiError(400, "invalid_field", "privacy.classification is unsupported");
  }
  const shareability = requireString(value.shareability, "privacy.shareability");
  if (shareability !== "local_only" && shareability !== "tenant" && shareability !== "repository") {
    throw new ApiError(400, "invalid_field", "privacy.shareability is unsupported");
  }
  if (value.secret_tainted !== false || classification === "secret") {
    throw new ApiError(422, "secret_tainted", "secret-tainted manifests must remain local");
  }
  if (shareability === "local_only") {
    throw new ApiError(422, "local_only", "local-only manifests cannot be uploaded");
  }
  return { classification, shareability, secret_tainted: false };
}

function parseSignature(value: unknown): EncryptedRemoteCacheManifestV2["signature"] {
  if (!isRecord(value)) throw new ApiError(400, "invalid_field", "signature must be an object");
  assertExactKeys(value, ["schema_version", "algorithm", "key_id", "signature"], "signature");
  if (value.schema_version !== 1 || value.algorithm !== "ed25519") {
    throw new ApiError(422, "unsupported_signature", "only signature schema 1 with Ed25519 is accepted");
  }
  return {
    schema_version: 1,
    algorithm: "ed25519",
    key_id: requireProtocolIdentifier(value.key_id, "signature.key_id"),
    signature: requireByteArray(value.signature, 64, "signature.signature"),
  };
}

function requireByteArray(value: unknown, length: number, field: string): number[] {
  if (!Array.isArray(value) || value.length !== length) {
    throw new ApiError(400, "invalid_byte_array", `${field} must contain exactly ${length} bytes`);
  }
  return value.map((entry) => {
    if (typeof entry !== "number" || !Number.isInteger(entry) || entry < 0 || entry > 255) {
      throw new ApiError(400, "invalid_byte_array", `${field} contains an invalid byte`);
    }
    return entry;
  });
}

function requireGenerationId(value: unknown): string {
  const generation = requireString(value, "generation_id");
  if (!/^[0-9a-f]{32}$/.test(generation)) {
    throw new ApiError(
      400,
      "invalid_repository_generation",
      "generation_id must be exactly 32 lower-case hexadecimal characters",
    );
  }
  return generation;
}

function bytesEqual(left: readonly number[], right: readonly number[]): boolean {
  return left.length === right.length && left.every((value, index) => value === right[index]);
}

function putEncryptedStream(output: number[], stream: EncryptedStreamRefV2): void {
  putDigest(output, stream.ciphertext_digest);
  putU64(output, stream.ciphertext_size_bytes);
  putBytes(output, Uint8Array.from(stream.nonce));
}

function putDigest(output: number[], digest: string): void {
  putBytes(output, hexToBytes(digest));
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
