/** Exact wire framing for the one-response encrypted team lookup. */

export const LOOKUP_BUNDLE_V1_CONTENT_TYPE = "application/vnd.again.lookup-bundle-v1";
export const LOOKUP_BUNDLE_V1_HEADER_BYTES = 32;
export const LOOKUP_BUNDLE_V1_VERSION = 1;
export const LOOKUP_BUNDLE_V1_MAX_TRUST_BYTES = 1_500_000;
export const LOOKUP_BUNDLE_V1_MAX_MANIFEST_BYTES = 64 * 1024;
export const LOOKUP_BUNDLE_V1_MAX_CIPHERTEXT_BYTES = 16 * 1024 * 1024;
export const LOOKUP_BUNDLE_V1_MAX_RESPONSE_BYTES = 40 * 1024 * 1024;

const MAGIC = new TextEncoder().encode("AGNBNDL1");

export interface LookupBundleV1CiphertextSource {
  /** Unconsumed R2 body stream retained after the final D1 fence. */
  readonly stream: ReadableStream<Uint8Array>;
  /** Exact R2/D1-fenced byte length. */
  readonly length: number;
}

export interface LookupBundleV1Parts {
  readonly initialTrustJson: Uint8Array;
  readonly manifestJson: Uint8Array;
  readonly stdoutCiphertext: LookupBundleV1CiphertextSource;
  readonly stderrCiphertext: LookupBundleV1CiphertextSource;
}

export class LookupBundleV1EncodingError extends Error {
  constructor(
    readonly code:
      | "empty_required_field"
      | "field_too_large"
      | "invalid_declared_length"
      | "response_too_large"
      | "source_locked"
      | "source_overflow"
      | "source_truncated",
    readonly field: "trust" | "manifest" | "stdout" | "stderr" | undefined = undefined,
  ) {
    super(`lookup bundle v1 encoding failed: ${code}${field === undefined ? "" : ` (${field})`}`);
    this.name = "LookupBundleV1EncodingError";
  }
}

export interface EncodedLookupBundleV1 {
  contentLength: number;
  body: ReadableStream<Uint8Array>;
  /** Resolves after the pump and all reader cleanup finish; it never rejects. */
  completion: Promise<void>;
}

/**
 * Validate exact field limits and construct a bounded streaming body without
 * ever materializing either potentially 16 MiB ciphertext in JavaScript.
 *
 * Callers must invoke this only after all R2 reads and the final atomic D1
 * generation/manifest/blob/trust fence. Construction immediately starts the
 * backpressured pump; this function does not authenticate any input.
 */
export function encodeLookupBundleV1(parts: LookupBundleV1Parts): EncodedLookupBundleV1 {
  const lengths = validateLengths(parts);
  const header = encodeHeader(lengths);
  // The signed JSON fields are bounded and copied so caller mutation after the
  // final fence cannot alter bytes already represented by the fixed header.
  const trust = parts.initialTrustJson.slice();
  const manifest = parts.manifestJson.slice();
  if (parts.stdoutCiphertext.stream.locked) {
    throw new LookupBundleV1EncodingError("source_locked", "stdout");
  }
  if (parts.stderrCiphertext.stream.locked) {
    throw new LookupBundleV1EncodingError("source_locked", "stderr");
  }

  const pumpFixed = new FixedLengthStream(lengths.total);
  const exposed = exposeFixedLengthBody(pumpFixed.readable);
  const responseFixed = new FixedLengthStream(lengths.total);
  const writer = pumpFixed.writable.getWriter();
  const stdoutReader = parts.stdoutCiphertext.stream.getReader();
  let stderrReader: ReadableStreamDefaultReader<Uint8Array>;
  try {
    stderrReader = parts.stderrCiphertext.stream.getReader();
  } catch (error: unknown) {
    releaseReader(stdoutReader);
    writer.releaseLock();
    throw error;
  }
  const pumpCompletion = pumpLookupBundle(
    writer,
    stdoutReader,
    stderrReader,
    header,
    trust,
    manifest,
    lengths,
    exposed.cancellation,
  );
  // Only a FixedLengthStream that directly produces the Response body carries
  // Workers' automatic Content-Length brand.  The generic middle readable is
  // still required to signal downstream cancellation while an R2 read is
  // pending.  pipeTo propagates cancellation/error in both directions without
  // buffering the ciphertexts, and allSettled makes cleanup observable without
  // creating a rejected promise a caller must remember to catch.
  const responseTransfer = exposed.body.pipeTo(responseFixed.writable);
  const completion = Promise.allSettled([pumpCompletion, responseTransfer]).then(
    () => undefined,
  );
  return {
    contentLength: lengths.total,
    body: responseFixed.readable,
    completion,
  };
}

interface LookupBundleV1Lengths {
  trust: number;
  manifest: number;
  stdout: number;
  stderr: number;
  total: number;
}

function validateLengths(parts: LookupBundleV1Parts): LookupBundleV1Lengths {
  const trust = parts.initialTrustJson.byteLength;
  const manifest = parts.manifestJson.byteLength;
  const stdout = requireDeclaredLength(parts.stdoutCiphertext.length, "stdout");
  const stderr = requireDeclaredLength(parts.stderrCiphertext.length, "stderr");
  if (trust === 0 || manifest === 0) {
    throw new LookupBundleV1EncodingError("empty_required_field");
  }
  if (
    trust > LOOKUP_BUNDLE_V1_MAX_TRUST_BYTES ||
    manifest > LOOKUP_BUNDLE_V1_MAX_MANIFEST_BYTES ||
    stdout > LOOKUP_BUNDLE_V1_MAX_CIPHERTEXT_BYTES ||
    stderr > LOOKUP_BUNDLE_V1_MAX_CIPHERTEXT_BYTES
  ) {
    throw new LookupBundleV1EncodingError("field_too_large");
  }
  const total = LOOKUP_BUNDLE_V1_HEADER_BYTES + trust + manifest + stdout + stderr;
  if (!Number.isSafeInteger(total) || total > LOOKUP_BUNDLE_V1_MAX_RESPONSE_BYTES) {
    throw new LookupBundleV1EncodingError("response_too_large");
  }
  return { trust, manifest, stdout, stderr, total };
}

function requireDeclaredLength(value: number, field: "stdout" | "stderr"): number {
  if (!Number.isSafeInteger(value) || value < 0) {
    throw new LookupBundleV1EncodingError("invalid_declared_length", field);
  }
  return value;
}

function encodeHeader(lengths: LookupBundleV1Lengths): Uint8Array {
  const header = new Uint8Array(LOOKUP_BUNDLE_V1_HEADER_BYTES);
  header.set(MAGIC, 0);
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  view.setUint16(8, LOOKUP_BUNDLE_V1_VERSION, false);
  view.setUint16(10, 0, false);
  view.setUint32(12, lengths.trust, false);
  view.setUint32(16, lengths.manifest, false);
  view.setUint32(20, lengths.stdout, false);
  view.setUint32(24, lengths.stderr, false);
  view.setUint32(28, 0, false);
  return header;
}

async function pumpLookupBundle(
  writer: WritableStreamDefaultWriter<ArrayBuffer | ArrayBufferView>,
  stdoutReader: ReadableStreamDefaultReader<Uint8Array>,
  stderrReader: ReadableStreamDefaultReader<Uint8Array>,
  header: Uint8Array,
  trust: Uint8Array,
  manifest: Uint8Array,
  lengths: LookupBundleV1Lengths,
  outputCancellation: Promise<{ reason: unknown }>,
): Promise<void> {
  try {
    await writer.write(header);
    await writer.write(trust);
    await writer.write(manifest);
    await pumpExactSource(writer, stdoutReader, lengths.stdout, "stdout", outputCancellation);
    await pumpExactSource(writer, stderrReader, lengths.stderr, "stderr", outputCancellation);
    await writer.close();
  } catch (error: unknown) {
    await Promise.allSettled([stdoutReader.cancel(error), stderrReader.cancel(error)]);
    // FixedLengthStream's writable can remain in an abort-pending state after
    // its readable has already been cancelled.  Initiate the abort so source
    // failures reach a live consumer, but never let that platform promise
    // prevent the two R2 reader cancellations from completing.
    void writer.abort(error).catch(() => undefined);
  } finally {
    releaseReader(stdoutReader);
    releaseReader(stderrReader);
    try {
      writer.releaseLock();
    } catch {
      // A platform cancellation can release/error the writer first.
    }
  }
}

async function pumpExactSource(
  writer: WritableStreamDefaultWriter<ArrayBuffer | ArrayBufferView>,
  reader: ReadableStreamDefaultReader<Uint8Array>,
  expectedLength: number,
  field: "stdout" | "stderr",
  outputCancellation: Promise<{ reason: unknown }>,
): Promise<void> {
  let observedLength = 0;
  for (;;) {
    const next = await Promise.race([
      reader.read().then((result) => ({ kind: "source" as const, result })),
      outputCancellation.then((result) => ({ kind: "output" as const, result })),
    ]);
    if (next.kind === "output") {
      throw next.result.reason;
    }
    const { done, value } = next.result;
    if (done) {
      if (observedLength !== expectedLength) {
        throw new LookupBundleV1EncodingError("source_truncated", field);
      }
      return;
    }
    if (value.byteLength === 0) continue;
    if (value.byteLength > expectedLength - observedLength) {
      throw new LookupBundleV1EncodingError("source_overflow", field);
    }
    await writer.write(value);
    observedLength += value.byteLength;
  }
}

function exposeFixedLengthBody(fixedBody: ReadableStream<Uint8Array>): {
  body: ReadableStream<Uint8Array>;
  cancellation: Promise<{ reason: unknown }>;
} {
  const reader = fixedBody.getReader();
  let signalCancellation: ((value: { reason: unknown }) => void) | undefined;
  let released = false;
  const cancellation = new Promise<{ reason: unknown }>((resolve) => {
    signalCancellation = resolve;
  });
  const release = (): void => {
    if (released) return;
    released = true;
    try {
      reader.releaseLock();
    } catch {
      // Cancellation can keep an internal FixedLengthStream read pending.
    }
  };
  const body = new ReadableStream<Uint8Array>({
    async pull(controller) {
      try {
        const { done, value } = await reader.read();
        if (done) {
          release();
          controller.close();
          return;
        }
        controller.enqueue(value);
      } catch (error: unknown) {
        release();
        controller.error(error);
      }
    },
    async cancel(reason) {
      signalCancellation?.({ reason });
      try {
        await reader.cancel(reason);
      } finally {
        release();
      }
    },
  });
  return { body, cancellation };
}

function releaseReader(reader: ReadableStreamDefaultReader<Uint8Array>): void {
  try {
    reader.releaseLock();
  } catch {
    // A pending read retains the lock until source cancellation settles.
  }
}
