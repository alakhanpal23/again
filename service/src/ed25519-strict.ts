import { ed25519 } from "@noble/curves/ed25519.js";
import { sha512 } from "@noble/hashes/sha2.js";

const PUBLIC_KEY_BYTES = 32;
const SIGNATURE_BYTES = 64;

/**
 * Match ed25519-dalek's `verify_strict`: require canonical point encodings,
 * reject small-order public keys and R values, require S < L, and compare the
 * exact uncofactored verification equation. This is deliberately stricter
 * than RFC 8032's cofactored equation, which can accept signatures that the
 * Rust cache consumer rejects.
 */
export function verifyEd25519Strict(
  message: Uint8Array,
  signature: Uint8Array,
  publicKey: Uint8Array,
): boolean {
  if (signature.byteLength !== SIGNATURE_BYTES || publicKey.byteLength !== PUBLIC_KEY_BYTES) {
    return false;
  }
  try {
    const rBytes = signature.slice(0, PUBLIC_KEY_BYTES);
    const publicPoint = ed25519.Point.fromBytes(publicKey, false);
    const rPoint = ed25519.Point.fromBytes(rBytes, false);
    if (publicPoint.isSmallOrder() || rPoint.isSmallOrder()) return false;

    const scalarOrder = ed25519.Point.CURVE().n;
    const s = littleEndianInteger(signature.subarray(PUBLIC_KEY_BYTES));
    if (s >= scalarOrder) return false;
    const challenge =
      littleEndianInteger(sha512(concatenate(rBytes, publicKey, message))) % scalarOrder;
    const expectedR = ed25519.Point.BASE.multiplyUnsafe(s).subtract(
      publicPoint.multiplyUnsafe(challenge),
    );
    return equalBytes(expectedR.toBytes(), rBytes);
  } catch {
    return false;
  }
}

export function isCanonicalEd25519PublicKey(publicKey: Uint8Array): boolean {
  if (publicKey.byteLength !== PUBLIC_KEY_BYTES) return false;
  try {
    ed25519.Point.fromBytes(publicKey, false);
    return true;
  } catch {
    return false;
  }
}

function concatenate(...values: readonly Uint8Array[]): Uint8Array {
  const output = new Uint8Array(values.reduce((length, value) => length + value.byteLength, 0));
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

function equalBytes(left: Uint8Array, right: Uint8Array): boolean {
  return left.byteLength === right.byteLength && left.every((byte, index) => byte === right[index]);
}
