import {
  LOOKUP_BUNDLE_V1_CONTENT_TYPE,
  LOOKUP_BUNDLE_V1_HEADER_BYTES,
  LOOKUP_BUNDLE_V1_MAX_CIPHERTEXT_BYTES,
  encodeLookupBundleV1,
  type LookupBundleV1CiphertextSource,
} from "../service/src/lookup-bundle-v1";

const encoder = new TextEncoder();
const TRUST_JSON = encoder.encode(
  '{"epoch":7,"repository_generation":"benchmark-generation","schema":"again.lookup-bundle-benchmark-trust.v1"}',
);
const MANIFEST_JSON = encoder.encode(
  '{"request_digest":"benchmark-request","schema":"again.lookup-bundle-benchmark-manifest.v1"}',
);
const CHUNK_BYTES = 64 * 1024;
const SCOPE = "again-lookup-bundle-benchmark-fixture-v1";

interface Metrics {
  activeBundleResponses: number;
  peakActiveBundleResponses: number;
  streamingBundleResponses: number;
  peakStreamingBundleResponses: number;
  streamStartedBundleResponses: number;
  activeCiphertextSources: number;
  peakActiveCiphertextSources: number;
  constructedCiphertextSources: number;
  streamBarrierExpectedResponses: number;
  streamBarrierArrivedResponses: number;
  streamBarrierReleased: boolean;
  streamBarrierReleaseActiveSources: number;
  streamBarrierReleaseConstructedSources: number;
  generatedChunks: number;
  generatedBytes: number;
  largestGeneratedChunkBytes: number;
  cancelledSources: number;
  directWriterClosedRejectedSignals: number;
  directWriterClosedResolvedSignals: number;
  directWriterClosedLastSignalDelayMs: number | null;
  requestSignalAbortSignals: number;
  requestSignalLastAbortDelayMs: number | null;
  bundleStrategies: Record<string, number>;
  requests: Record<string, number>;
}

let metrics = freshMetrics();
let nextBundleResponseId = 1;
let streamBarrier: StreamBarrier | undefined;

interface StreamBarrier {
  readonly expected: number;
  readonly responseIds: Set<number>;
  readonly released: Promise<void>;
  release: (() => void) | undefined;
}

function freshMetrics(): Metrics {
  return {
    activeBundleResponses: 0,
    peakActiveBundleResponses: 0,
    streamingBundleResponses: 0,
    peakStreamingBundleResponses: 0,
    streamStartedBundleResponses: 0,
    activeCiphertextSources: 0,
    peakActiveCiphertextSources: 0,
    constructedCiphertextSources: 0,
    streamBarrierExpectedResponses: 0,
    streamBarrierArrivedResponses: 0,
    streamBarrierReleased: false,
    streamBarrierReleaseActiveSources: 0,
    streamBarrierReleaseConstructedSources: 0,
    generatedChunks: 0,
    generatedBytes: 0,
    largestGeneratedChunkBytes: 0,
    cancelledSources: 0,
    directWriterClosedRejectedSignals: 0,
    directWriterClosedResolvedSignals: 0,
    directWriterClosedLastSignalDelayMs: null,
    requestSignalAbortSignals: 0,
    requestSignalLastAbortDelayMs: null,
    bundleStrategies: {},
    requests: {},
  };
}

function countRequest(name: string): void {
  metrics.requests[name] = (metrics.requests[name] ?? 0) + 1;
}

function commonHeaders(contentType: string): Headers {
  return new Headers({
    "Cache-Control": "no-store",
    "Content-Type": contentType,
    "X-Again-Benchmark-Scope": SCOPE,
  });
}

function jsonResponse(value: unknown, status = 200): Response {
  return new Response(JSON.stringify(value), {
    status,
    headers: commonHeaders("application/json"),
  });
}

function parseInteger(
  url: URL,
  name: string,
  defaultValue: number,
  maximum: number,
): number {
  const raw = url.searchParams.get(name);
  if (raw === null) return defaultValue;
  if (!/^(0|[1-9][0-9]*)$/.test(raw)) throw new Error(`invalid ${name}`);
  const parsed = Number(raw);
  if (!Number.isSafeInteger(parsed) || parsed > maximum) throw new Error(`invalid ${name}`);
  return parsed;
}

function sleep(milliseconds: number): Promise<void> {
  if (milliseconds === 0) return Promise.resolve();
  return new Promise((resolve) => setTimeout(resolve, milliseconds));
}

function deterministicSource(
  length: number,
  byte: number,
  chunkDelayMs: number,
  onFirstPull: () => Promise<void>,
  pendingAfterFirstPull = false,
): LookupBundleV1CiphertextSource {
  let remaining = length;
  let firstPull = true;
  let finished = false;
  metrics.constructedCiphertextSources += 1;
  metrics.activeCiphertextSources += 1;
  metrics.peakActiveCiphertextSources = Math.max(
    metrics.peakActiveCiphertextSources,
    metrics.activeCiphertextSources,
  );
  const finish = (): void => {
    if (finished) return;
    finished = true;
    metrics.activeCiphertextSources -= 1;
  };
  return {
    length,
    stream: new ReadableStream<Uint8Array>(
      {
        async pull(controller) {
          if (firstPull) {
            firstPull = false;
            await onFirstPull();
          }
          if (pendingAfterFirstPull) return;
          if (remaining === 0) {
            finish();
            controller.close();
            return;
          }
          if (chunkDelayMs !== 0) await sleep(chunkDelayMs);
          const chunkLength = Math.min(CHUNK_BYTES, remaining);
          const chunk = new Uint8Array(chunkLength);
          chunk.fill(byte);
          remaining -= chunkLength;
          metrics.generatedChunks += 1;
          metrics.generatedBytes += chunkLength;
          metrics.largestGeneratedChunkBytes = Math.max(
            metrics.largestGeneratedChunkBytes,
            chunkLength,
          );
          controller.enqueue(chunk);
        },
        cancel() {
          metrics.cancelledSources += 1;
          remaining = 0;
          finish();
        },
      },
      { highWaterMark: 0 },
    ),
  };
}

async function waitForStreamBarrier(responseId: number, expected: number): Promise<void> {
  if (expected === 0) return;
  if (streamBarrier === undefined) {
    let release: (() => void) | undefined;
    const released = new Promise<void>((resolve) => {
      release = resolve;
    });
    streamBarrier = { expected, responseIds: new Set<number>(), released, release };
    metrics.streamBarrierExpectedResponses = expected;
  }
  if (streamBarrier.expected !== expected) throw new Error("inconsistent stream barrier size");
  streamBarrier.responseIds.add(responseId);
  metrics.streamBarrierArrivedResponses = streamBarrier.responseIds.size;
  if (streamBarrier.responseIds.size === expected && !metrics.streamBarrierReleased) {
    metrics.streamBarrierReleased = true;
    metrics.streamBarrierReleaseActiveSources = metrics.activeCiphertextSources;
    metrics.streamBarrierReleaseConstructedSources = metrics.constructedCiphertextSources;
    streamBarrier.release?.();
    streamBarrier.release = undefined;
  }
  await new Promise<void>((resolve, reject) => {
    const timeout = setTimeout(() => reject(new Error("stream barrier timed out")), 5_000);
    streamBarrier?.released.then(
      () => {
        clearTimeout(timeout);
        resolve();
      },
      (error: unknown) => {
        clearTimeout(timeout);
        reject(error);
      },
    );
  });
}

interface DirectEncodedBundle {
  readonly contentLength: number;
  readonly body: ReadableStream<Uint8Array>;
  readonly completion: Promise<void>;
}

type WriterClosedSignal =
  | { readonly kind: "resolved" }
  | { readonly kind: "rejected"; readonly error: unknown };

interface DirectCancellation {
  readonly promise: Promise<{ readonly reason: unknown }>;
  dispose(): void;
}

/**
 * Experimental one-FixedLengthStream construction used only by this benchmark.
 * It tests whether writer.closed is a prompt downstream-cancellation signal in
 * workerd; production continues to use encodeLookupBundleV1.
 */
function encodeDirectBenchmarkBundle(
  stdout: LookupBundleV1CiphertextSource,
  stderr: LookupBundleV1CiphertextSource,
  requestSignal: AbortSignal | undefined,
): DirectEncodedBundle {
  const total =
    LOOKUP_BUNDLE_V1_HEADER_BYTES +
    TRUST_JSON.byteLength +
    MANIFEST_JSON.byteLength +
    stdout.length +
    stderr.length;
  const header = new Uint8Array(LOOKUP_BUNDLE_V1_HEADER_BYTES);
  header.set(encoder.encode("AGNBNDL1"), 0);
  const view = new DataView(header.buffer, header.byteOffset, header.byteLength);
  view.setUint16(8, 1, false);
  view.setUint16(10, 0, false);
  view.setUint32(12, TRUST_JSON.byteLength, false);
  view.setUint32(16, MANIFEST_JSON.byteLength, false);
  view.setUint32(20, stdout.length, false);
  view.setUint32(24, stderr.length, false);
  view.setUint32(28, 0, false);

  const fixed = new FixedLengthStream(total);
  const writer = fixed.writable.getWriter();
  const stdoutReader = stdout.stream.getReader();
  const stderrReader = stderr.stream.getReader();
  const startedAt = performance.now();
  const writerClosed: Promise<WriterClosedSignal> = writer.closed.then(
    () => {
      metrics.directWriterClosedResolvedSignals += 1;
      metrics.directWriterClosedLastSignalDelayMs = performance.now() - startedAt;
      return { kind: "resolved" as const };
    },
    (error: unknown) => {
      metrics.directWriterClosedRejectedSignals += 1;
      metrics.directWriterClosedLastSignalDelayMs = performance.now() - startedAt;
      return { kind: "rejected" as const, error };
    },
  );
  const cancellation = directCancellation(writerClosed, requestSignal, startedAt);
  const pump = pumpDirectBenchmarkBundle(
    writer,
    stdoutReader,
    stderrReader,
    header,
    stdout.length,
    stderr.length,
    cancellation.promise,
  );
  return {
    contentLength: total,
    body: fixed.readable,
    completion: Promise.allSettled([pump]).then(() => {
      cancellation.dispose();
    }),
  };
}

function directCancellation(
  writerClosed: Promise<WriterClosedSignal>,
  requestSignal: AbortSignal | undefined,
  startedAt: number,
): DirectCancellation {
  let settle: ((value: { reason: unknown }) => void) | undefined;
  let settled = false;
  const promise = new Promise<{ reason: unknown }>((resolve) => {
    settle = resolve;
  });
  const resolveOnce = (reason: unknown): void => {
    if (settled) return;
    settled = true;
    settle?.({ reason });
  };
  void writerClosed.then((signal) => {
    if (signal.kind === "rejected") resolveOnce(signal.error);
  });
  const onRequestAbort = (): void => {
    metrics.requestSignalAbortSignals += 1;
    metrics.requestSignalLastAbortDelayMs = performance.now() - startedAt;
    resolveOnce(requestSignal?.reason ?? new Error("incoming request aborted"));
  };
  if (requestSignal?.aborted === true) {
    onRequestAbort();
  } else {
    requestSignal?.addEventListener("abort", onRequestAbort, { once: true });
  }
  return {
    promise,
    dispose() {
      requestSignal?.removeEventListener("abort", onRequestAbort);
    },
  };
}

async function pumpDirectBenchmarkBundle(
  writer: WritableStreamDefaultWriter<ArrayBuffer | ArrayBufferView>,
  stdoutReader: ReadableStreamDefaultReader<Uint8Array>,
  stderrReader: ReadableStreamDefaultReader<Uint8Array>,
  header: Uint8Array,
  stdoutLength: number,
  stderrLength: number,
  cancellation: Promise<{ readonly reason: unknown }>,
): Promise<void> {
  try {
    await writer.write(header);
    await writer.write(TRUST_JSON);
    await writer.write(MANIFEST_JSON);
    await pumpDirectExactSource(writer, stdoutReader, stdoutLength, cancellation);
    await pumpDirectExactSource(writer, stderrReader, stderrLength, cancellation);
    await writer.close();
  } catch (error: unknown) {
    await Promise.allSettled([stdoutReader.cancel(error), stderrReader.cancel(error)]);
    void writer.abort(error).catch(() => undefined);
  } finally {
    try {
      stdoutReader.releaseLock();
    } catch {
      // Downstream cancellation can release/error the reader first.
    }
    try {
      stderrReader.releaseLock();
    } catch {
      // Downstream cancellation can release/error the reader first.
    }
    try {
      writer.releaseLock();
    } catch {
      // Downstream cancellation can release/error the writer first.
    }
  }
}

async function pumpDirectExactSource(
  writer: WritableStreamDefaultWriter<ArrayBuffer | ArrayBufferView>,
  reader: ReadableStreamDefaultReader<Uint8Array>,
  expectedLength: number,
  cancellation: Promise<{ readonly reason: unknown }>,
): Promise<void> {
  let observed = 0;
  for (;;) {
    const next = await Promise.race([
      reader.read().then((result) => ({ kind: "source" as const, result })),
      cancellation.then((signal) => ({ kind: "cancellation" as const, signal })),
    ]);
    if (next.kind === "cancellation") {
      throw next.signal.reason;
    }
    const { done, value } = next.result;
    if (done) {
      if (observed !== expectedLength) throw new Error("direct benchmark source truncated");
      return;
    }
    if (value.byteLength > expectedLength - observed) {
      throw new Error("direct benchmark source overflowed");
    }
    if (value.byteLength !== 0) {
      await writer.write(value);
      observed += value.byteLength;
    }
  }
}

async function fixedStreamResponse(
  source: LookupBundleV1CiphertextSource,
  context: ExecutionContext,
): Promise<Response> {
  const fixed = new FixedLengthStream(source.length);
  const transfer = source.stream.pipeTo(fixed.writable);
  context.waitUntil(Promise.allSettled([transfer]).then(() => undefined));
  return new Response(fixed.readable, {
    headers: commonHeaders("application/octet-stream"),
  });
}

function boundedBody(url: URL): { size: number; rttMs: number; chunkDelayMs: number } {
  return {
    size: parseInteger(url, "size", 0, LOOKUP_BUNDLE_V1_MAX_CIPHERTEXT_BYTES),
    rttMs: parseInteger(url, "rtt_ms", 0, 1_000),
    chunkDelayMs: parseInteger(url, "chunk_delay_ms", 0, 50),
  };
}

async function serveBundle(
  request: Request,
  url: URL,
  context: ExecutionContext,
): Promise<Response> {
  const { size, rttMs, chunkDelayMs } = boundedBody(url);
  const streamBarrierResponses = parseInteger(url, "stream_barrier", 0, 16);
  const responseId = nextBundleResponseId;
  const strategy = url.searchParams.get("strategy") ?? "bridge";
  if (strategy !== "bridge" && strategy !== "direct" && strategy !== "direct_signal") {
    throw new Error("invalid bundle strategy");
  }
  const pendingSource = parseInteger(url, "pending_source", 0, 1) === 1;
  nextBundleResponseId += 1;
  countRequest("bundle");
  metrics.bundleStrategies[strategy] = (metrics.bundleStrategies[strategy] ?? 0) + 1;
  await sleep(rttMs);
  metrics.activeBundleResponses += 1;
  metrics.peakActiveBundleResponses = Math.max(
    metrics.peakActiveBundleResponses,
    metrics.activeBundleResponses,
  );
  let streamingStarted = false;
  const startStreaming = async (): Promise<void> => {
    if (streamingStarted) return;
    streamingStarted = true;
    metrics.streamingBundleResponses += 1;
    metrics.streamStartedBundleResponses += 1;
    metrics.peakStreamingBundleResponses = Math.max(
      metrics.peakStreamingBundleResponses,
      metrics.streamingBundleResponses,
    );
    await waitForStreamBarrier(responseId, streamBarrierResponses);
  };
  const stdout = deterministicSource(
    size,
    0xa5,
    chunkDelayMs,
    startStreaming,
    pendingSource,
  );
  const stderr = deterministicSource(size, 0x5a, chunkDelayMs, startStreaming);
  const encoded =
    strategy === "bridge"
      ? encodeLookupBundleV1({
          initialTrustJson: TRUST_JSON,
          manifestJson: MANIFEST_JSON,
          stdoutCiphertext: stdout,
          stderrCiphertext: stderr,
        })
      : encodeDirectBenchmarkBundle(
          stdout,
          stderr,
          strategy === "direct_signal" ? request.signal : undefined,
        );
  context.waitUntil(
    encoded.completion.finally(() => {
      metrics.activeBundleResponses -= 1;
      if (streamingStarted) metrics.streamingBundleResponses -= 1;
    }),
  );
  return new Response(encoded.body, {
    headers: commonHeaders(LOOKUP_BUNDLE_V1_CONTENT_TYPE),
  });
}

async function serveReference(
  route: string,
  url: URL,
  context: ExecutionContext,
): Promise<Response> {
  const { size, rttMs, chunkDelayMs } = boundedBody(url);
  countRequest(route);
  await sleep(rttMs);
  switch (route) {
    case "reference_initial_trust":
    case "reference_final_trust":
      return new Response(TRUST_JSON, { headers: commonHeaders("application/json") });
    case "reference_manifest":
      return new Response(MANIFEST_JSON, { headers: commonHeaders("application/json") });
    case "reference_stdout":
      return fixedStreamResponse(
        deterministicSource(size, 0xa5, chunkDelayMs, async () => undefined),
        context,
      );
    case "reference_stderr":
      return fixedStreamResponse(
        deterministicSource(size, 0x5a, chunkDelayMs, async () => undefined),
        context,
      );
    default:
      return jsonResponse({ error: "unknown reference route" }, 404);
  }
}

export default {
  async fetch(request: Request, _env: unknown, context: ExecutionContext): Promise<Response> {
    const url = new URL(request.url);
    try {
      if (url.pathname === "/health" && request.method === "GET") {
        return jsonResponse({ ok: true, scope: SCOPE });
      }
      if (url.pathname === "/metrics" && request.method === "GET") {
        return jsonResponse({ ...metrics, scope: SCOPE });
      }
      if (url.pathname === "/metrics/reset" && request.method === "POST") {
        if (
          metrics.activeBundleResponses !== 0 ||
          metrics.streamingBundleResponses !== 0 ||
          metrics.activeCiphertextSources !== 0
        ) {
          return jsonResponse({ error: "bundle responses still active" }, 409);
        }
        metrics = freshMetrics();
        streamBarrier = undefined;
        nextBundleResponseId = 1;
        return jsonResponse({ ok: true, scope: SCOPE });
      }
      if (url.pathname === "/bundle" && request.method === "GET") {
        return await serveBundle(request, url, context);
      }
      if (url.pathname === "/bundle/final-trust" && request.method === "GET") {
        const { rttMs } = boundedBody(url);
        countRequest("bundle_final_trust");
        await sleep(rttMs);
        return new Response(TRUST_JSON, { headers: commonHeaders("application/json") });
      }
      const referenceRoutes: Record<string, string> = {
        "/reference/initial-trust": "reference_initial_trust",
        "/reference/manifest": "reference_manifest",
        "/reference/stdout": "reference_stdout",
        "/reference/stderr": "reference_stderr",
        "/reference/final-trust": "reference_final_trust",
      };
      const referenceRoute = referenceRoutes[url.pathname];
      if (referenceRoute !== undefined && request.method === "GET") {
        return await serveReference(referenceRoute, url, context);
      }
      return jsonResponse({ error: "not found" }, 404);
    } catch (error: unknown) {
      return jsonResponse(
        { error: error instanceof Error ? error.message : "unknown benchmark worker error" },
        400,
      );
    }
  },
};
