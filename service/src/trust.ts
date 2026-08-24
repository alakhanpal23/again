import { isCanonicalEd25519PublicKey, verifyEd25519Strict } from "./ed25519-strict";
import {
  ApiError,
  assertExactKeys,
  bytesToHex,
  hexToBytes,
  isRecord,
  requireDigest,
  requireSafeInteger,
  requireString,
} from "./util";

const SIGNING_DOMAIN = new TextEncoder().encode("again.trust-bundle.v1");
const MAX_LIFETIME_SECONDS = 5 * 60;
const MAX_FUTURE_SKEW_SECONDS = 30;
const MAX_ENTRIES_PER_SET = 4_096;
const MAX_IDENTIFIER_BYTES = 256;
const MAX_ORIGIN_BYTES = 2_048;
const encoder = new TextEncoder();

// D1 currently limits any string/BLOB and the complete row containing it to
// 2,000,000 bytes. Keep enough headroom for the trust-head metadata columns,
// indexes, and SQLite record encoding while allowing substantially larger
// bounded trust sets than the ordinary 64 KiB manifest envelope.
export const MAX_TRUST_BUNDLE_JSON_SIZE = 1_500_000;

export interface ProducerKeyBindingV1 {
  key_id: string;
  producer_id: string;
  public_key: number[];
}

export interface TrustBundleV1 {
  schema_version: 1;
  root_key_id: string;
  tenant_id: string;
  repository_id: string;
  generation_id: string;
  endpoint_origin: string;
  epoch: number;
  issued_at_unix_seconds: number;
  expires_at_unix_seconds: number;
  active_producer_keys: ProducerKeyBindingV1[];
  revoked_key_ids: string[];
  revoked_record_ids: string[];
  allowed_policy_digests: string[];
  allowed_execution_profile_digests: string[];
  allowed_platform_digests: string[];
  allowed_image_digests: string[];
  signature: number[];
}

export function parseTrustBundle(value: Record<string, unknown>, now: number | null): TrustBundleV1 {
  assertExactKeys(
    value,
    [
      "schema_version",
      "root_key_id",
      "tenant_id",
      "repository_id",
      "generation_id",
      "endpoint_origin",
      "epoch",
      "issued_at_unix_seconds",
      "expires_at_unix_seconds",
      "active_producer_keys",
      "revoked_key_ids",
      "revoked_record_ids",
      "allowed_policy_digests",
      "allowed_execution_profile_digests",
      "allowed_platform_digests",
      "allowed_image_digests",
      "signature",
    ],
    "trust_bundle",
  );
  if (value.schema_version !== 1) {
    throw new ApiError(422, "unsupported_schema", "trust bundle schema_version must be 1");
  }

  const epoch = requireSafeInteger(value.epoch, "epoch");
  if (epoch === 0) throw new ApiError(422, "invalid_epoch", "trust bundle epoch must be non-zero");
  const issued = requireSafeInteger(value.issued_at_unix_seconds, "issued_at_unix_seconds");
  const expires = requireSafeInteger(value.expires_at_unix_seconds, "expires_at_unix_seconds");
  if (expires <= issued || expires - issued > MAX_LIFETIME_SECONDS) {
    throw new ApiError(
      422,
      "invalid_lifetime",
      "trust bundle lifetime must be positive and at most five minutes",
    );
  }
  if (now !== null) {
    if (issued > now + MAX_FUTURE_SKEW_SECONDS) {
      throw new ApiError(422, "future_trust_bundle", "trust bundle issue time is too far in the future");
    }
    if (expires <= now) throw new ApiError(422, "expired_trust_bundle", "trust bundle has expired");
  }

  const active = requireArray(value.active_producer_keys, "active_producer_keys").map(
    (entry, index) => parseProducerKey(entry, `active_producer_keys[${index}]`),
  );
  checkBounded(active, "active_producer_keys");
  requireStrictlySorted(active, (entry) => entry.key_id, "active_producer_keys");

  const revokedKeys = parseIdentifierList(value.revoked_key_ids, "revoked_key_ids");
  const revokedRecords = parseIdentifierList(value.revoked_record_ids, "revoked_record_ids");
  const allowedPolicies = parseDigestList(value.allowed_policy_digests, "allowed_policy_digests");
  const allowedExecutions = parseDigestList(
    value.allowed_execution_profile_digests,
    "allowed_execution_profile_digests",
  );
  const allowedPlatforms = parseDigestList(value.allowed_platform_digests, "allowed_platform_digests");
  const allowedImages = parseDigestList(value.allowed_image_digests, "allowed_image_digests");
  const revoked = new Set(revokedKeys);
  if (active.some((entry) => revoked.has(entry.key_id))) {
    throw new ApiError(422, "active_key_revoked", "an active producer key is also revoked");
  }

  return {
    schema_version: 1,
    root_key_id: requireIdentifier(value.root_key_id, "root_key_id"),
    tenant_id: requireIdentifier(value.tenant_id, "tenant_id"),
    repository_id: requireIdentifier(value.repository_id, "repository_id"),
    generation_id: requireGenerationId(value.generation_id),
    endpoint_origin: requireCanonicalHttpsOrigin(value.endpoint_origin),
    epoch,
    issued_at_unix_seconds: issued,
    expires_at_unix_seconds: expires,
    active_producer_keys: active,
    revoked_key_ids: revokedKeys,
    revoked_record_ids: revokedRecords,
    allowed_policy_digests: allowedPolicies,
    allowed_execution_profile_digests: allowedExecutions,
    allowed_platform_digests: allowedPlatforms,
    allowed_image_digests: allowedImages,
    signature: requireByteArray(value.signature, 64, "signature"),
  };
}

export function canonicalTrustBundleJson(bundle: TrustBundleV1): string {
  const json = JSON.stringify(bundle);
  if (encoder.encode(json).byteLength > MAX_TRUST_BUNDLE_JSON_SIZE) {
    throw new ApiError(
      413,
      "trust_bundle_too_large",
      "canonical trust bundle exceeds the 1,500,000-byte storage limit",
    );
  }
  return json;
}

export function canonicalTrustBundleBytes(bundle: TrustBundleV1): Uint8Array {
  const output: number[] = [];
  putBytes(output, SIGNING_DOMAIN);
  putU16(output, bundle.schema_version);
  putString(output, bundle.root_key_id);
  putString(output, bundle.tenant_id);
  putString(output, bundle.repository_id);
  putString(output, bundle.generation_id);
  putString(output, bundle.endpoint_origin);
  putU64(output, bundle.epoch);
  putU64(output, bundle.issued_at_unix_seconds);
  putU64(output, bundle.expires_at_unix_seconds);
  putU64(output, bundle.active_producer_keys.length);
  for (const binding of bundle.active_producer_keys) {
    putString(output, binding.key_id);
    putString(output, binding.producer_id);
    putBytes(output, Uint8Array.from(binding.public_key));
  }
  putStrings(output, bundle.revoked_key_ids);
  putStrings(output, bundle.revoked_record_ids);
  putDigests(output, bundle.allowed_policy_digests);
  putDigests(output, bundle.allowed_execution_profile_digests);
  putDigests(output, bundle.allowed_platform_digests);
  putDigests(output, bundle.allowed_image_digests);
  return Uint8Array.from(output);
}

export async function verifyTrustBundleSignature(
  bundle: TrustBundleV1,
  publicKeyHex: string,
): Promise<boolean> {
  try {
    return verifyEd25519Strict(
      canonicalTrustBundleBytes(bundle),
      Uint8Array.from(bundle.signature),
      hexToBytes(publicKeyHex),
    );
  } catch {
    return false;
  }
}

export function assertMonotonicTrustBundle(
  previous: TrustBundleV1,
  candidate: TrustBundleV1,
): void {
  if (candidate.epoch < previous.epoch) {
    throw new ApiError(409, "trust_epoch_rollback", "trust bundle epoch cannot roll back");
  }
  const historical = new Map(
    previous.active_producer_keys.map((binding) => [
      binding.key_id,
      `${binding.producer_id}\0${bytesToHex(Uint8Array.from(binding.public_key))}`,
    ]),
  );
  for (const binding of candidate.active_producer_keys) {
    const prior = historical.get(binding.key_id);
    const current = `${binding.producer_id}\0${bytesToHex(Uint8Array.from(binding.public_key))}`;
    if (prior !== undefined && prior !== current) {
      throw new ApiError(409, "trust_key_rebinding", "producer key identifiers are immutable");
    }
    if (previous.revoked_key_ids.includes(binding.key_id)) {
      throw new ApiError(409, "trust_revocation_rollback", "revoked producer keys cannot reactivate");
    }
  }
  requireSuperset(previous.revoked_key_ids, candidate.revoked_key_ids, "trust_revocation_rollback");
  requireSuperset(
    previous.revoked_record_ids,
    candidate.revoked_record_ids,
    "trust_record_revocation_rollback",
  );
}

function parseProducerKey(value: unknown, field: string): ProducerKeyBindingV1 {
  if (!isRecord(value)) throw new ApiError(400, "invalid_field", `${field} must be an object`);
  assertExactKeys(value, ["key_id", "producer_id", "public_key"], field);
  const publicKey = requireByteArray(value.public_key, 32, `${field}.public_key`);
  if (!isCanonicalEd25519PublicKey(Uint8Array.from(publicKey))) {
    throw new ApiError(422, "invalid_producer_public_key", `${field}.public_key is not valid Ed25519`);
  }
  return {
    key_id: requireIdentifier(value.key_id, `${field}.key_id`),
    producer_id: requireIdentifier(value.producer_id, `${field}.producer_id`),
    public_key: publicKey,
  };
}

function parseIdentifierList(value: unknown, field: string): string[] {
  const values = requireArray(value, field).map((entry) => requireIdentifier(entry, field));
  checkBounded(values, field);
  requireStrictlySorted(values, (entry) => entry, field);
  return values;
}

function parseDigestList(value: unknown, field: string): string[] {
  const values = requireArray(value, field).map((entry) => requireDigest(entry, field));
  checkBounded(values, field);
  requireStrictlySorted(values, (entry) => entry, field);
  return values;
}

function requireArray(value: unknown, field: string): unknown[] {
  if (!Array.isArray(value)) throw new ApiError(400, "invalid_field", `${field} must be an array`);
  return value;
}

function requireByteArray(value: unknown, length: number, field: string): number[] {
  const values = requireArray(value, field);
  if (values.length !== length) {
    throw new ApiError(400, "invalid_byte_array", `${field} must contain exactly ${length} bytes`);
  }
  return values.map((entry) => {
    if (typeof entry !== "number" || !Number.isInteger(entry) || entry < 0 || entry > 255) {
      throw new ApiError(400, "invalid_byte_array", `${field} contains an invalid byte`);
    }
    return entry;
  });
}

function requireIdentifier(value: unknown, field: string): string {
  const identifier = requireString(value, field);
  if (
    encoder.encode(identifier).byteLength === 0 ||
    encoder.encode(identifier).byteLength > MAX_IDENTIFIER_BYTES ||
    /[\p{Cc}\p{White_Space}\ud800-\udfff]/u.test(identifier)
  ) {
    throw new ApiError(400, "invalid_identifier", `${field} is not a valid protocol identifier`);
  }
  return identifier;
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

function requireCanonicalHttpsOrigin(value: unknown): string {
  const origin = requireString(value, "endpoint_origin");
  if (encoder.encode(origin).byteLength > MAX_ORIGIN_BYTES || !/^[\x00-\x7f]*$/.test(origin)) {
    throw new ApiError(400, "invalid_origin", "endpoint_origin must be a canonical HTTPS origin");
  }
  let parsed: URL;
  try {
    parsed = new URL(origin);
  } catch {
    throw new ApiError(400, "invalid_origin", "endpoint_origin must be a canonical HTTPS origin");
  }
  if (
    parsed.protocol !== "https:" ||
    parsed.username !== "" ||
    parsed.password !== "" ||
    parsed.pathname !== "/" ||
    parsed.search !== "" ||
    parsed.hash !== "" ||
    parsed.origin !== origin
  ) {
    throw new ApiError(400, "invalid_origin", "endpoint_origin must be a canonical HTTPS origin");
  }
  return origin;
}

function checkBounded(values: readonly unknown[], field: string): void {
  if (values.length > MAX_ENTRIES_PER_SET) {
    throw new ApiError(422, "too_many_entries", `${field} exceeds the entry limit`);
  }
}

function requireStrictlySorted<T>(
  values: readonly T[],
  key: (value: T) => string,
  field: string,
): void {
  for (let index = 1; index < values.length; index += 1) {
    const previous = key(values[index - 1] as T);
    const current = key(values[index] as T);
    if (compareUtf8(previous, current) >= 0) {
      throw new ApiError(422, "unsorted_or_duplicate", `${field} must be strictly sorted`);
    }
  }
}

function compareUtf8(left: string, right: string): number {
  const leftBytes = encoder.encode(left);
  const rightBytes = encoder.encode(right);
  const shared = Math.min(leftBytes.length, rightBytes.length);
  for (let index = 0; index < shared; index += 1) {
    const difference = (leftBytes[index] as number) - (rightBytes[index] as number);
    if (difference !== 0) return difference;
  }
  return leftBytes.length - rightBytes.length;
}

function requireSuperset(previous: readonly string[], candidate: readonly string[], code: string): void {
  const next = new Set(candidate);
  if (previous.some((entry) => !next.has(entry))) {
    throw new ApiError(409, code, "trust revocations must be cumulative");
  }
}

function putStrings(output: number[], values: readonly string[]): void {
  putU64(output, values.length);
  for (const value of values) putString(output, value);
}

function putDigests(output: number[], values: readonly string[]): void {
  putU64(output, values.length);
  for (const value of values) putBytes(output, hexToBytes(value));
}

function putString(output: number[], value: string): void {
  putBytes(output, encoder.encode(value));
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
