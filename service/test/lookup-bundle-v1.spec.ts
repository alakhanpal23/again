import { describe, expect, it, vi } from "vitest";
import {
  LOOKUP_BUNDLE_V1_CONTENT_TYPE,
  LOOKUP_BUNDLE_V1_HEADER_BYTES,
  LOOKUP_BUNDLE_V1_MAX_CIPHERTEXT_BYTES,
  LOOKUP_BUNDLE_V1_MAX_MANIFEST_BYTES,
  LOOKUP_BUNDLE_V1_MAX_RESPONSE_BYTES,
  LOOKUP_BUNDLE_V1_MAX_TRUST_BYTES,
  LookupBundleV1EncodingError,
  encodeLookupBundleV1,
  type LookupBundleV1CiphertextSource,
  type LookupBundleV1Parts,
} from "../src/lookup-bundle-v1";
import wireFixture from "./fixtures/lookup-bundle-v1-wire.json";

const encoder = new TextEncoder();

function sourceFromBytes(bytes: Uint8Array): LookupBundleV1CiphertextSource {
  return {
    length: bytes.byteLength,
    stream: new ReadableStream<Uint8Array>({
      start(controller) {
        if (bytes.byteLength > 0) controller.enqueue(bytes);
        controller.close();
      },
    }),
  };
}

function fixture(overrides: Partial<LookupBundleV1Parts> = {}): LookupBundleV1Parts {
  return {
    initialTrustJson: encoder.encode('{"trust":true}'),
    manifestJson: encoder.encode('{"manifest":true}'),
    stdoutCiphertext: sourceFromBytes(encoder.encode("stdout-ciphertext")),
    stderrCiphertext: sourceFromBytes(encoder.encode("stderr-ciphertext")),
    ...overrides,
  };
}

async function readAll(stream: ReadableStream<Uint8Array>): Promise<Uint8Array> {
  return new Uint8Array(await new Response(stream).arrayBuffer());
}

async function drain(stream: ReadableStream<Uint8Array>): Promise<number> {
  const reader = stream.getReader();
  let total = 0;
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) return total;
      total += value.byteLength;
    }
  } finally {
    reader.releaseLock();
  }
}

function fromHex(value: string): Uint8Array {
  if (value.length % 2 !== 0 || !/^[0-9a-f]*$/.test(value)) {
    throw new Error("fixture hex is invalid");
  }
  const bytes = new Uint8Array(value.length / 2);
  for (let index = 0; index < bytes.length; index += 1) {
    bytes[index] = Number.parseInt(value.slice(index * 2, index * 2 + 2), 16);
  }
  return bytes;
}

function toHex(value: Uint8Array): string {
  return Array.from(value, (byte) => byte.toString(16).padStart(2, "0")).join("");
}

function lazyExactSource(
  length: number,
  state: { pulls: number; largestAllocation: number },
): LookupBundleV1CiphertextSource {
  let remaining = length;
  return {
    length,
    stream: new ReadableStream<Uint8Array>({
      pull(controller) {
        state.pulls += 1;
        if (remaining === 0) {
          controller.close();
          return;
        }
        const chunkLength = Math.min(64 * 1024, remaining);
        state.largestAllocation = Math.max(state.largestAllocation, chunkLength);
        const chunk = new Uint8Array(chunkLength);
        chunk.fill(state.pulls & 0xff);
        remaining -= chunkLength;
        controller.enqueue(chunk);
      },
    }),
  };
}

function controlledPendingSource(
  length: number,
  onCancel: (reason: unknown) => void,
): { source: LookupBundleV1CiphertextSource; pulled: Promise<void> } {
  let signalPull: (() => void) | undefined;
  const pulled = new Promise<void>((resolve) => {
    signalPull = resolve;
  });
  return {
    source: {
      length,
      stream: new ReadableStream<Uint8Array>(
        {
          pull() {
            signalPull?.();
          },
          cancel(reason) {
            onCancel(reason);
          },
        },
        { highWaterMark: 0 },
      ),
    },
    pulled,
  };
}

describe("lookup bundle v1 framing", () => {
  it("matches the retained Rust parser wire vector byte for byte", async () => {
    expect(wireFixture.schema).toBe("again.lookup-bundle-v1-wire-fixture.v1");
    const encoded = encodeLookupBundleV1({
      initialTrustJson: fromHex(wireFixture.initial_trust_hex),
      manifestJson: fromHex(wireFixture.manifest_hex),
      stdoutCiphertext: sourceFromBytes(fromHex(wireFixture.stdout_ciphertext_hex)),
      stderrCiphertext: sourceFromBytes(fromHex(wireFixture.stderr_ciphertext_hex)),
    });
    const bytes = await readAll(encoded.body);
    await encoded.completion;
    expect(toHex(bytes)).toBe(wireFixture.expected_wire_hex);
    const sha256 = new Uint8Array(await crypto.subtle.digest("SHA-256", bytes));
    expect(toHex(sha256)).toBe(wireFixture.expected_sha256);
  });

  it("emits the exact Rust-compatible header and payload without base64", async () => {
    const trust = encoder.encode('{"trust":true}');
    const manifest = encoder.encode('{"manifest":true}');
    const stdout = encoder.encode("stdout-ciphertext");
    const stderr = encoder.encode("stderr-ciphertext");
    const encoded = encodeLookupBundleV1({
      initialTrustJson: trust,
      manifestJson: manifest,
      stdoutCiphertext: sourceFromBytes(stdout),
      stderrCiphertext: sourceFromBytes(stderr),
    });
    const bytes = await readAll(encoded.body);
    await encoded.completion;
    expect(LOOKUP_BUNDLE_V1_CONTENT_TYPE).toBe("application/vnd.again.lookup-bundle-v1");
    expect(encoded.contentLength).toBe(bytes.byteLength);
    expect(new TextDecoder().decode(bytes.subarray(0, 8))).toBe("AGNBNDL1");
    const header = new DataView(bytes.buffer, bytes.byteOffset, LOOKUP_BUNDLE_V1_HEADER_BYTES);
    expect(header.getUint16(8, false)).toBe(1);
    expect(header.getUint16(10, false)).toBe(0);
    expect(header.getUint32(12, false)).toBe(trust.byteLength);
    expect(header.getUint32(16, false)).toBe(manifest.byteLength);
    expect(header.getUint32(20, false)).toBe(stdout.byteLength);
    expect(header.getUint32(24, false)).toBe(stderr.byteLength);
    expect(header.getUint32(28, false)).toBe(0);
    expect(bytes.subarray(LOOKUP_BUNDLE_V1_HEADER_BYTES)).toEqual(
      new Uint8Array([...trust, ...manifest, ...stdout, ...stderr]),
    );
  });

  it("returns the outer FixedLengthStream readable directly for Response branding", async () => {
    const platformFixedLengthStream = FixedLengthStream;
    const fixedBodies: ReadableStream<Uint8Array>[] = [];
    const TrackingFixedLengthStream = function (length: number | bigint): FixedLengthStream {
      const fixed = new platformFixedLengthStream(length);
      fixedBodies.push(fixed.readable);
      return fixed;
    } as unknown as typeof FixedLengthStream;
    vi.stubGlobal("FixedLengthStream", TrackingFixedLengthStream);
    try {
      const encoded = encodeLookupBundleV1(fixture());
      expect(fixedBodies).toHaveLength(2);
      expect(encoded.body).toBe(fixedBodies[1]);
      expect((await readAll(encoded.body)).byteLength).toBe(encoded.contentLength);
      await encoded.completion;
    } finally {
      vi.unstubAllGlobals();
    }
  });

  it("allows exact zero-length lazy ciphertext streams", async () => {
    const encoded = encodeLookupBundleV1(
      fixture({
        stdoutCiphertext: sourceFromBytes(new Uint8Array()),
        stderrCiphertext: sourceFromBytes(new Uint8Array()),
      }),
    );
    expect((await readAll(encoded.body)).byteLength).toBe(
      LOOKUP_BUNDLE_V1_HEADER_BYTES +
        fixture().initialTrustJson.byteLength +
        fixture().manifestJson.byteLength,
    );
    await encoded.completion;
  });

  it("never accepts empty trust or manifest JSON", () => {
    for (const parts of [
      fixture({ initialTrustJson: new Uint8Array() }),
      fixture({ manifestJson: new Uint8Array() }),
    ]) {
      expect(() => encodeLookupBundleV1(parts)).toThrowError(
        new LookupBundleV1EncodingError("empty_required_field"),
      );
    }
  });

  it("rejects every field over its exact limit without locking a source", () => {
    const cases: LookupBundleV1Parts[] = [
      fixture({ initialTrustJson: new Uint8Array(LOOKUP_BUNDLE_V1_MAX_TRUST_BYTES + 1) }),
      fixture({ manifestJson: new Uint8Array(LOOKUP_BUNDLE_V1_MAX_MANIFEST_BYTES + 1) }),
      fixture({
        stdoutCiphertext: {
          length: LOOKUP_BUNDLE_V1_MAX_CIPHERTEXT_BYTES + 1,
          stream: new ReadableStream<Uint8Array>(),
        },
      }),
      fixture({
        stderrCiphertext: {
          length: LOOKUP_BUNDLE_V1_MAX_CIPHERTEXT_BYTES + 1,
          stream: new ReadableStream<Uint8Array>(),
        },
      }),
    ];
    for (const parts of cases) {
      expect(() => encodeLookupBundleV1(parts)).toThrowError(
        new LookupBundleV1EncodingError("field_too_large"),
      );
      expect(parts.stdoutCiphertext.stream.locked).toBe(false);
      expect(parts.stderrCiphertext.stream.locked).toBe(false);
    }
  });

  it("rejects negative, fractional, non-finite, and unsafe declared lengths", () => {
    for (const invalid of [-1, 0.5, Number.NaN, Number.POSITIVE_INFINITY, 2 ** 53]) {
      expect(() =>
        encodeLookupBundleV1(
          fixture({
            stdoutCiphertext: {
              length: invalid,
              stream: new ReadableStream<Uint8Array>(),
            },
          }),
        ),
      ).toThrowError(new LookupBundleV1EncodingError("invalid_declared_length", "stdout"));
    }
  });

  it("streams both maximum ciphertexts lazily without a ciphertext-sized allocation", async () => {
    const stdoutState = { pulls: 0, largestAllocation: 0 };
    const stderrState = { pulls: 0, largestAllocation: 0 };
    const encoded = encodeLookupBundleV1({
      initialTrustJson: encoder.encode("t"),
      manifestJson: encoder.encode("m"),
      stdoutCiphertext: lazyExactSource(LOOKUP_BUNDLE_V1_MAX_CIPHERTEXT_BYTES, stdoutState),
      stderrCiphertext: lazyExactSource(LOOKUP_BUNDLE_V1_MAX_CIPHERTEXT_BYTES, stderrState),
    });
    expect(stdoutState.pulls).toBeLessThanOrEqual(1);
    expect(stderrState.pulls).toBeLessThanOrEqual(1);
    await expect(drain(encoded.body)).resolves.toBe(encoded.contentLength);
    await encoded.completion;
    expect(stdoutState.pulls).toBeGreaterThan(1);
    expect(stderrState.pulls).toBeGreaterThan(1);
    expect(stdoutState.largestAllocation).toBe(64 * 1024);
    expect(stderrState.largestAllocation).toBe(64 * 1024);
  });

  it("rejects premature EOF in either stream and cancels an untouched reader", async () => {
    const stderrCancelled = vi.fn();
    const encoded = encodeLookupBundleV1(
      fixture({
        stdoutCiphertext: { ...sourceFromBytes(encoder.encode("ab")), length: 3 },
        stderrCiphertext: controlledPendingSource(1, stderrCancelled).source,
      }),
    );
    await expect(drain(encoded.body)).rejects.toMatchObject({
      code: "source_truncated",
      field: "stdout",
    });
    await encoded.completion;
    expect(stderrCancelled).toHaveBeenCalledOnce();

    const stderrEncoded = encodeLookupBundleV1(
      fixture({
        stdoutCiphertext: sourceFromBytes(new Uint8Array()),
        stderrCiphertext: { ...sourceFromBytes(encoder.encode("ab")), length: 3 },
      }),
    );
    await expect(drain(stderrEncoded.body)).rejects.toMatchObject({
      code: "source_truncated",
      field: "stderr",
    });
    await stderrEncoded.completion;
  });

  it("rejects any non-empty byte beyond a declared stream length", async () => {
    for (const field of ["stdout", "stderr"] as const) {
      const extra = { ...sourceFromBytes(encoder.encode("ab")), length: 1 };
      const encoded = encodeLookupBundleV1(
        fixture(
          field === "stdout"
            ? { stdoutCiphertext: extra, stderrCiphertext: sourceFromBytes(new Uint8Array()) }
            : { stdoutCiphertext: sourceFromBytes(new Uint8Array()), stderrCiphertext: extra },
        ),
      );
      await expect(drain(encoded.body)).rejects.toMatchObject({ code: "source_overflow", field });
      await encoded.completion;
    }
  });

  it("propagates a source error through the response and cancels the untouched stream", async () => {
    const stderrCancelled = vi.fn();
    const expected = new Error("stdout exploded");
    const encoded = encodeLookupBundleV1(
      fixture({
        stdoutCiphertext: {
          length: 1,
          stream: new ReadableStream<Uint8Array>({
            pull(controller) {
              controller.error(expected);
            },
          }),
        },
        stderrCiphertext: controlledPendingSource(1, stderrCancelled).source,
      }),
    );
    await expect(drain(encoded.body)).rejects.toThrow("stdout exploded");
    await encoded.completion;
    expect(stderrCancelled).toHaveBeenCalledOnce();

    const stderrExpected = new Error("stderr exploded");
    const stderrEncoded = encodeLookupBundleV1(
      fixture({
        stdoutCiphertext: sourceFromBytes(new Uint8Array()),
        stderrCiphertext: {
          length: 1,
          stream: new ReadableStream<Uint8Array>({
            pull(controller) {
              controller.error(stderrExpected);
            },
          }),
        },
      }),
    );
    await expect(drain(stderrEncoded.body)).rejects.toThrow("stderr exploded");
    await stderrEncoded.completion;
  });

  it("cancels both sources when the consumer disconnects before reading", async () => {
    const stdoutCancelled = vi.fn();
    const stderrCancelled = vi.fn();
    const encoded = encodeLookupBundleV1(
      fixture({
        stdoutCiphertext: controlledPendingSource(1, stdoutCancelled).source,
        stderrCiphertext: controlledPendingSource(1, stderrCancelled).source,
      }),
    );
    await encoded.body.cancel("client disconnected");
    await encoded.completion;
    expect(stdoutCancelled).toHaveBeenCalledOnce();
    expect(stderrCancelled).toHaveBeenCalledOnce();
    expect(stdoutCancelled).toHaveBeenCalledWith(
      expect.objectContaining({ message: "client disconnected" }),
    );
    expect(stderrCancelled).toHaveBeenCalledWith(
      expect.objectContaining({ message: "client disconnected" }),
    );
  });

  it("cancels both sources while a stdout read is pending", async () => {
    const stdoutCancelled = vi.fn();
    const stderrCancelled = vi.fn();
    const stdout = controlledPendingSource(1, stdoutCancelled);
    const encoded = encodeLookupBundleV1(
      fixture({
        stdoutCiphertext: stdout.source,
        stderrCiphertext: controlledPendingSource(1, stderrCancelled).source,
      }),
    );
    const reader = encoded.body.getReader();
    const consuming = consumeReader(reader).catch((error: unknown) => error);
    await stdout.pulled;
    await reader.cancel("client disconnected during stdout");
    expect(await consuming).toMatchObject({ message: "client disconnected during stdout" });
    await encoded.completion;
    expect(stdoutCancelled).toHaveBeenCalledOnce();
    expect(stderrCancelled).toHaveBeenCalledOnce();
    expect(stdoutCancelled).toHaveBeenCalledWith(
      expect.objectContaining({ message: "client disconnected during stdout" }),
    );
    expect(stderrCancelled).toHaveBeenCalledWith(
      expect.objectContaining({ message: "client disconnected during stdout" }),
    );
  });

  it("cancels the remaining stderr source while its read is pending", async () => {
    const stderrCancelled = vi.fn();
    const stderr = controlledPendingSource(1, stderrCancelled);
    const encoded = encodeLookupBundleV1(
      fixture({
        stdoutCiphertext: sourceFromBytes(encoder.encode("o")),
        stderrCiphertext: stderr.source,
      }),
    );
    const reader = encoded.body.getReader();
    const consuming = consumeReader(reader).catch((error: unknown) => error);
    await stderr.pulled;
    await reader.cancel("client disconnected during stderr");
    expect(await consuming).toMatchObject({ message: "client disconnected during stderr" });
    await encoded.completion;
    expect(stderrCancelled).toHaveBeenCalledOnce();
    expect(stderrCancelled).toHaveBeenCalledWith(
      expect.objectContaining({ message: "client disconnected during stderr" }),
    );
  });

  it("copies bounded JSON fields before asynchronous streaming begins", async () => {
    const trust = encoder.encode("trust");
    const manifest = encoder.encode("manifest");
    const encoded = encodeLookupBundleV1({
      initialTrustJson: trust,
      manifestJson: manifest,
      stdoutCiphertext: sourceFromBytes(new Uint8Array()),
      stderrCiphertext: sourceFromBytes(new Uint8Array()),
    });
    trust.fill(0);
    manifest.fill(0);
    const bytes = await readAll(encoded.body);
    await encoded.completion;
    expect(new TextDecoder().decode(bytes.subarray(LOOKUP_BUNDLE_V1_HEADER_BYTES))).toBe(
      "trustmanifest",
    );
  });

  it("rejects already locked ciphertext streams before starting the pump", async () => {
    const locked = sourceFromBytes(encoder.encode("locked"));
    const reader = locked.stream.getReader();
    expect(() => encodeLookupBundleV1(fixture({ stdoutCiphertext: locked }))).toThrowError(
      new LookupBundleV1EncodingError("source_locked", "stdout"),
    );
    await reader.cancel();
  });

  it("keeps the protocol maximum below the cumulative response ceiling", () => {
    const maximum =
      LOOKUP_BUNDLE_V1_HEADER_BYTES +
      LOOKUP_BUNDLE_V1_MAX_TRUST_BYTES +
      LOOKUP_BUNDLE_V1_MAX_MANIFEST_BYTES +
      2 * LOOKUP_BUNDLE_V1_MAX_CIPHERTEXT_BYTES;
    expect(maximum).toBeLessThan(LOOKUP_BUNDLE_V1_MAX_RESPONSE_BYTES);
  });
});

async function consumeReader(reader: ReadableStreamDefaultReader<Uint8Array>): Promise<void> {
  for (;;) {
    const { done } = await reader.read();
    if (done) return;
  }
}
