# Lookup bundle v1 performance harness

This harness compares lookup bundle v1's two serial HTTP requests with the
legacy reference flow's five serial HTTP requests. The default run starts a
dedicated Worker under local Wrangler/workerd and uses actual loopback HTTP.
It does not exercise the production D1/R2 service and must not be cited as
Cloudflare edge, public-network, command, agent, token, or cost performance.

## Current status

Bundle v1 is manually selectable only for controlled experiments and remains
unshipped. The retained 100-repetition, 50 ms
local matrix fails the unchanged 40% p95 gate at the maximum payload, and the
actual-HTTP pending-read cancellation gate is not satisfied. The production
encoder remains the conservative two-`FixedLengthStream` cancellation bridge;
the benchmark-only direct encoders are not product candidates.

Retained local evidence:

- `results/2026-08-23-lookup-bundle-v1-50ms-matrix-v1.json`: production bridge,
  100 measured repetitions plus two warmups, 0 B/4 KiB/1 MiB/16 MiB per
  stream, 50 ms injected response-start delay, exact 2-vs-5 request counts,
  raw stage timings, true four-response streaming overlap, and an
  indefinitely-pending bridge disconnect probe;
- `results/2026-08-23-lookup-bundle-v1-finite-disconnect-v1.json`: the bridge
  cancels both finite sources 62.5 ms after an actual loopback TCP reset;
- `results/2026-08-23-lookup-bundle-v1-pending-disconnect-request-signal-v1.json`:
  the benchmark-only one-stream encoder with `enable_request_signal` does not
  observe `Request.signal` or cancel either indefinitely-pending source within
  the three-second local-workerd window.

At 50 ms, measured bundle/reference p95 and improvement were 119.664/294.793
ms (59.41%) at 0 B, 119.658/296.251 ms (59.61%) at 4 KiB,
143.222/299.455 ms (52.17%) at 1 MiB, and 338.542/342.682 ms (1.208%) at
16 MiB. The 16 MiB cell is a decisive local performance-gate failure; it must
not be averaged with the smaller passing cells.

Each `--rtts-ms` value is injected once inside the Worker before each response
starts. It is a deterministic model of one fixed request round trip, not a
packet-level latency emulator. Both protocols stream the same deterministic
stdout and stderr bytes, and the client incrementally hashes rather than
buffers the ciphertext streams.

Reproduce the decisive matrix with a new output filename:

```bash
python3 -B bench/lookup_bundle_v1_benchmark.py \
  --repetitions 100 \
  --warmups 2 \
  --sizes 0,4096,1048576,16777216 \
  --rtts-ms 50 \
  --bundle-strategy bridge \
  --cancellation-source pending \
  --json-out bench/results/YYYY-MM-DD-lookup-bundle-v1-50ms.json
```

The retained JSON contains source and dirty-tree provenance, runtime versions,
all per-repetition and per-stage timings, exact server/client request counts,
stream fingerprints, cancellation observations, and four concurrent
maximum-size responses. The concurrency probe records Wrangler's process-tree
RSS delta, but explicitly does not interpret it as Worker isolate heap usage.
Each completed matrix cell is atomically checkpointed beside `--json-out` as
`<result>.partial`; the partial file is removed only after the final result has
been written. A failed run retains its last completed-cell checkpoint.

The unit suite proves that explicit `encoded.body.cancel()` propagates through
the bridge and cancels both sources, including while a source read is pending.
That unit signal is not equivalent to an actual HTTP disconnect. A finite-source
TCP-reset probe also passes, but the retained pending-source TCP-reset probe
leaves both sources and the response active after three seconds in local
workerd. Do not claim end-to-end prompt cancellation from either weaker pass.

The optional `--bundle-strategy direct` path is a rejected research probe. A
single direct `FixedLengthStream` removes the bridge overhead, but
`writer.closed` does not settle if an upstream `reader.read()` remains
indefinitely pending. `--bundle-strategy direct_signal` additionally races the
read against the incoming request's signal. Cloudflare documents that signal
behind the [`enable_request_signal` compatibility
flag](https://developers.cloudflare.com/changelog/post/2025-05-22-handle-request-cancellation/),
but the retained local-workerd TCP-reset probe did not observe it. That local
result is not evidence about deployed-edge behavior; it is also not sufficient
to ship the direct design. Production therefore keeps the explicit bridge.

`--base-url` can drive a caller-managed compatible instance of
`lookup_bundle_worker.ts` over HTTPS. The result records that transport as
caller-managed and does not infer deployment provenance. Do not expose this
unauthenticated synthetic benchmark Worker as a persistent public service.

Do not spend the full 0/20/50/100 ms matrix while the decisive 16 MiB 50 ms
cell fails. If an implementation later passes that cell without weakening
cancellation, the remaining ship evidence is still required:

- 100,000 generated stateful D1/R2 bundle/reference disposition and byte
  comparisons; the existing 100,000-case Rust corpus is synthetic
  parser/mapper parity and does not satisfy this gate;
- the full matrix through a public-CA HTTPS tunnel;
- direct evidence that four concurrent maximum responses remain below the
  Cloudflare 128 MiB isolate limit;
- stateful zero-stale-hit behavior against the real D1/R2 service.
