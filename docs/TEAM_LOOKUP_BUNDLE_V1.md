# Team lookup bundle v1

Status: implemented experimental Worker route, Rust client, and live lifecycle.
Bundle v1 is opt-in experimental and unshipped; the service itself is
undeployed. Controlled tests may select the strict `bundle_v1` profile value,
but operator and CI examples remain on `legacy_v2` until every remaining ship
gate below passes.

## Goal

Replace the five serial team-hit GETs (initial trust, manifest, two
ciphertexts, final trust) with two bounded GETs without weakening any local
verification or repository-generation/revocation fence:

1. one bundled payload containing initial trust, manifest, and both
   ciphertexts;
2. the existing latest-trust GET after authenticated client decryption.

A true one-response version is explicitly rejected for v1. Without a
bidirectional client acknowledgement, the server must sample trust before up
to 34 MiB is received and decrypted. A revocation committed in that interval
would be missed, while the reference flow can catch it.

```text
GET /v1/repositories/{repository_id}/lookup-bundles/{request_digest}
X-Again-Repository-Generation: {generation_id}
Authorization: Bearer {read_token}
```

Only a typed `manifest_not_found` response is a cache miss. That code means
there is no *reusable candidate*, not merely that no row exists: an absent or
deleted candidate, a normally expired/not-yet-valid candidate, or a candidate
made unusable by current producer/record revocation or trust allowlists all
produce the same miss disposition as the five-request reference path. Missing
trust, missing/corrupt blob data for an otherwise reusable candidate,
generation changes, quarantined/inconsistent metadata, and malformed signed
objects are fail-closed errors and can never be converted into hits.

## Response

Success is `200` with:

```text
Content-Type: application/vnd.again.lookup-bundle-v1
Cache-Control: no-store
X-Again-Repository-Generation: {generation_id}
```

The body uses a fixed 32-byte header followed by four exact byte strings:

| Offset | Encoding | Meaning |
|---:|---|---|
| 0 | 8 bytes | ASCII `AGNBNDL1` |
| 8 | u16 big endian | schema version, exactly `1` |
| 10 | u16 big endian | flags, exactly `0` |
| 12 | u32 big endian | initial signed trust JSON length |
| 16 | u32 big endian | encrypted manifest JSON length |
| 20 | u32 big endian | stdout ciphertext length |
| 24 | u32 big endian | stderr ciphertext length |
| 28 | u32 big endian | reserved, exactly `0` |

Payload order is initial signed trust JSON, encrypted manifest JSON, stdout
ciphertext, stderr ciphertext. No base64 or compression is used. The container
is not itself trusted: the root signature, producer signature, manifest
bindings, ciphertext size/digest, AEAD authentication, and local privacy scan
remain the authority.

Every length is checked before allocation. V1 limits remain:

- trust JSON: 1,500,000 bytes;
- manifest JSON: 64 KiB;
- each ciphertext: 16 MiB;
- complete response: the profile's cumulative response-byte ceiling, never
  above 40 MiB;
- one payload request plus one post-decrypt trust request against the profile
  request and wall-clock budgets.

Content-Length, if present, must equal the checked sum. Trailing bytes,
reserved bits, duplicate generation headers, an unknown content type, an
unknown version, integer overflow, premature EOF, or a length inconsistent
with the signed manifest is corruption.

## Service construction order

The Worker must not begin the response stream until all external reads and the
final fence complete:

1. Authenticate the read token and authorize the tenant/repository.
2. Acquire or verify the exact request generation from the mandatory header.
3. Read the encrypted manifest and its normalized stdout/stderr blob
   references. Return typed `manifest_not_found` for the ordinary
   no-reusable-candidate states in the disposition matrix below.
4. Read both generation-prefixed R2 ciphertext objects with exact stored sizes
   and digests. Do not stream either object to the caller yet.
5. After both R2 awaits, perform a final D1 query that atomically proves:
   - the repository is active at the requested generation;
   - the same manifest is still ready and still names the same blob rows;
   - both blob rows remain ready with the same storage keys, sizes, and
     digests;
   - a current signed trust head exists for this same generation.
6. Return that initial authorization trust body, the unchanged manifest body, and the two
   validated ciphertexts. Attach the exact generation header and `no-store`.

Any generation change or row transition during an R2 await returns typed
`repository_generation_mismatch` or corruption. A stale generation-A handler
must never quarantine, delete, promote, defer, audit, or otherwise mutate
generation-B state.

### Exact disposition matrix

The bundle endpoint and the five-request reference must agree on these
observable outcomes before rollout:

| Candidate/service state | HTTP/API result | Client disposition |
|---|---|---|
| no manifest row, deleted row, ordinary expiry, not-yet-valid row | typed `manifest_not_found` | cache miss |
| current trust revokes the producer key or record, or disallows a signed candidate binding | typed `manifest_not_found` | cache miss |
| ready candidate with current trust and two valid R2 objects | bundle `200`, then final trust | authenticated hit if local verification also passes |
| quarantined/non-ready corruption state or inconsistent manifest/blob metadata | typed corruption/state error | fail closed; never a miss or hit |
| missing/wrong-digest/wrong-size R2 object for an otherwise reusable candidate | typed corruption error | fail closed; never a miss or hit |
| missing/expired/malformed trust head or disabled root | typed trust/state error | fail closed; never a miss or hit |
| stale/wrong repository generation at any fence | `repository_generation_mismatch` | fail closed; never a miss or hit |
| malformed request, auth failure, budget/timeout/transport failure | existing typed error | fail closed or CLI's documented degraded-local route; never a remote hit |

`manifest_not_found` must be selected from authenticated, exact-generation
metadata. It must not hide parse failures, signature failures, impossible row
relationships, or missing ciphertext that should exist.

### R2 object identity and bounded-memory streaming

The implementation must use a `ReadableStream` after the final fence. It must
not call `arrayBuffer()` for either ciphertext or retain two ciphertext-sized
JavaScript buffers. [Cloudflare Workers has a 128 MiB limit per
isolate](https://developers.cloudflare.com/workers/platform/limits/#memory),
shared by concurrent requests; the two 16 MiB fields alone would otherwise
consume roughly 32 MiB per request before V8, trust, manifest, database, and
response overhead.

Blob readiness therefore binds more than caller-supplied custom metadata. On
upload, the Worker computes SHA-256 over the same already-bounded bytes, passes
that checksum to `R2.put`, and records the successful R2 object's immutable
upload identity (`version`, exact ETag, SHA-256, size, key, and incarnation) in
D1. A ready row without every field is corruption and is never eligible for a
bundle.

For a bundle lookup, the Worker obtains each `R2ObjectBody` with an exact ETag
precondition and checks its returned key, version, ETag, size, stored SHA-256,
and custom incarnation/BLAKE3 metadata against D1. It retains only the two
unconsumed body streams and their small metadata objects. The final atomic D1
query then proves that the same blob incarnations and R2 upload identities are
still ready alongside the same manifest, trust head, and repository
generation. Only after that query succeeds may the response stream enqueue
the header, trust JSON, manifest JSON, stdout body, and stderr body in order.

The [R2 Workers
binding](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/)
returns object bodies as streams and [R2 is strongly
consistent](https://developers.cloudflare.com/r2/reference/consistency/), so
this preserves the final-fence ordering without materializing the encrypted
outputs in the isolate. The client remains the ultimate byte authority: it
checks each signed BLAKE3 digest and size, authenticates each AEAD stream, and
performs the mandatory post-decryption latest-trust request before plaintext
can be released. A replacement, truncated stream, or stream error can fail the
client but can never become a hit.

Streaming R2 bytes before the final D1 fence is forbidden. A response stream
must cancel both remaining R2 readers when the client disconnects or any source
stream fails. The service must not log any payload bytes, encryption metadata,
or raw object identities.

## Client acceptance order

The Rust client:

1. seals endpoint, repository, generation, budget, request, runtime, and
   output-independent privacy admission before network I/O;
2. sends one generation-bound payload GET and applies the existing strict HTTPS,
   redirect, deadline, status/error-code, header, and body limits;
3. parses the fixed envelope without trusting or decrypting it;
4. verifies and durably checkpoints the returned root-signed initial trust bundle;
5. verifies trust freshness, epoch, generation, revocation, allowlists, the
   producer signature, and every request/policy/runtime/image binding;
6. checks both ciphertext sizes and digests, then authenticates/decrypts them;
7. rescans plaintext under the local sharing policy but keeps it quarantined;
8. performs the existing generation-bound latest-trust GET after decryption,
   verifies and durably checkpoints that signed bundle, and re-verifies the
   manifest against its current revocations, allowlists, generation and
   lifetime;
9. rebuilds the live request and runtime binding and samples the clock
   immediately before returning the unforgeable verified-result capability;
10. performs the CLI's independent final request/runtime/clock check before
   writing exact stdout/stderr.

The bundled trust object replaces only the first authorization request. The
small second request is mandatory because it occurs after client receipt and
decryption and therefore preserves the reference revocation fence. The trust
GET itself must re-read and fence the exact latest epoch/body/root/generation
immediately before responding; checking repository generation alone is not
sufficient.

## Compatibility and rollout

- Keep the five-request implementation as the rollout reference. The
  deterministic 100,000-case Rust protocol comparison now returns identical
  dispositions and bytes, but it synthesizes response states and does not
  execute the Worker, D1, or R2. A 100,000-case stateful path is still missing.
- The strict profile must include `"lookup_protocol": "bundle_v1"` and a
  request budget of at least two to select this path. The required alternative
  value `"legacy_v2"` selects only the five-request reference path. There is
  no implicit default, capability probing, or silent fallback after a miss,
  corrupt response, authentication failure, or unavailable bundle endpoint.
- Bundle absence on an older service is configuration mismatch, not cache
  miss. This prevents an attacker or proxy from forcing extra executions by
  rewriting endpoint capabilities.

## Required tests

Service tests must cover:

- exact byte framing at zero, ordinary, and maximum stream sizes;
- the complete disposition matrix above, including differential comparison
  with the reference manifest route for every row/trust state;
- cross-tenant, cross-repository, wrong-generation, expired/revoked trust, and
  non-ready/quarantined rows;
- corrupt/truncated/wrong-digest R2 objects;
- trust rotation while either R2 GET is paused: the payload carries a valid
  initial trust head and the mandatory post-decrypt GET observes the latest
  revocation;
- generation A paused during each R2 GET, deletion/finalization/recreation as
  B with the same request and blob digest, then A resume: B remains untouched
  and A cannot return a success;
- metadata transition after R2 read but before the final query;
- no response-body stream starts before the final fence;
- R2 version, ETag, SHA-256, size, custom-metadata, and incarnation mismatches;
- client cancellation and failure of either streamed R2 body;
- bounded memory/body behavior with no ciphertext-sized JavaScript buffer and
  no secret-bearing logs or audit fields.

Rust tests must cover:

- every malformed header/length/content-type/trailing-byte case;
- response and deadline budgets, exact generation header, and strict service
  error classification;
- signature, epoch, expiry, revocation, policy, runtime, request, producer,
  digest, size, AEAD, and privacy failures never returning a hit;
- input/runtime/clock changes before decrypt and before presentation;
- revocation after the payload response or after authenticated decryption is
  caught by the mandatory second trust GET;
- byte-for-byte equality with the five-request reference path;
- no request retry and no third command execution on any failure.

The live two-client E2E must prove publisher miss/publish, independent reader
hit, corruption quarantine, producer revocation, generation-A deletion and
generation-B recreation, stale-A refusal, and final exact output over public
CA-valid HTTPS.

## Performance gate

Retain raw benchmark JSON with source revision, dirty-tree state, host/runtime,
payload sizes, request counts, and per-stage timings. Compare bundle v1 with
the five-request reference over at least 100 repetitions for 0 B, 4 KiB,
1 MiB, and 16 MiB streams under local Worker, injected 20/50/100 ms RTT, and
the live HTTPS tunnel.

Ship bundle v1 only if it preserves exact dispositions/bytes, has zero stale
hits, uses exactly two requests, and improves p95 warm shared-hit latency by at least
40% at 50 ms injected RTT. Do not claim command or agent speedup from protocol
latency alone; report both separately.

In addition, exercise at least four concurrent maximum-size bundle responses
in one local Worker isolate. The endpoint must remain below the platform's
128 MiB isolate limit without buffering either ciphertext and must complete or
fail each client independently. A test that only encodes preallocated
`Uint8Array` values does not satisfy this gate.

### Retained local evidence (2026-08-23)

The reproducible local Wrangler/workerd harness is
[`bench/lookup_bundle_v1_benchmark.py`](../bench/lookup_bundle_v1_benchmark.py). It uses actual loopback HTTP and an
immutable streaming Worker fixture. Its delay is injected once before each
response starts; it is not packet-level RTT emulation and is not Cloudflare
edge or public-network evidence. It also does not execute the production D1/R2
route.

Correctness evidence exists at three distinct layers:

- the deterministic Rust
  [`lookup_bundle_state_matrix_protocol_parity_100k`](../src/team_pull/team_lookup_bundle_differential.rs)
  test passes 100,000 bundle/reference disposition-and-byte comparisons, but
  those cases are synthetic protocol/parser/mapper inputs rather than stateful
  D1/R2 operations;
- the actual Worker
  [`service.spec.ts` matrix](../service/test/service.spec.ts) passes 18
  enumerated states through both the bundle route and the five-request route,
  including hit-byte equality, ordinary misses, corruption/trust failures, and
  generation mismatch;
- [`2026-08-23-team-live-e2e-bundle-v1.json`](../bench/results/2026-08-23-team-live-e2e-bundle-v1.json)
  records a manual two-client lifecycle through production rustls over a
  public-CA Quick Tunnel to local Wrangler D1/R2: publish, exact hit, trust
  rotation, corruption quarantine, producer revocation, generation
  deletion/recreation, stale refusal, and republish/hit all pass.

The live run is one dirty-tree, single-host lifecycle, not a deployed service,
the full live performance matrix, or the missing cross-layer race that changes
trust after authenticated decryption but before the client's final-trust
request.

[`2026-08-23-lookup-bundle-v1-50ms-matrix-v1.json`](../bench/results/2026-08-23-lookup-bundle-v1-50ms-matrix-v1.json) retains 100
measured repetitions plus two warmups for each required payload size at the
decisive 50 ms delay:

| Ciphertext bytes per stream | Bundle p95 | Five-request p95 | Improvement | 40% gate |
|---:|---:|---:|---:|:---:|
| 0 | 119.664 ms | 294.793 ms | 59.41% | pass |
| 4,096 | 119.658 ms | 296.251 ms | 59.61% | pass |
| 1,048,576 | 143.222 ms | 299.455 ms | 52.17% | pass |
| 16,777,216 | 338.542 ms | 342.682 ms | 1.208% | **fail** |

All measured response bytes and incremental stream hashes matched. The exact
two-versus-five request gate passed: server counters matched 408 bundle payload
requests plus 408 bundle final-trust requests and 408 of each of the five
reference request types, including warmups. The four-way overlap gate also
passed: a source-pull barrier proved four distinct maximum-size responses were
simultaneously streaming with eight live sources before release. The observed
2,096 KiB Wrangler-process-tree RSS delta is not isolate heap and does not
satisfy the 128 MiB Cloudflare gate.

Cancellation evidence has three distinct scopes:

- service unit tests pass when the test directly cancels the encoded body,
  including a pending source read;
- [`2026-08-23-lookup-bundle-v1-finite-disconnect-v1.json`](../bench/results/2026-08-23-lookup-bundle-v1-finite-disconnect-v1.json)
  passes for an actual loopback TCP reset after finite source chunks have
  flowed: 2/2 sources settle as cancelled in 62.5 ms;
- the 50 ms matrix artifact's actual TCP-reset probe fails when the first
  source read remains indefinitely pending: after 3.014 seconds, 0/2 sources
  are cancelled and the response remains active.

The benchmark-only one-`FixedLengthStream` `Request.signal` experiment is also
not a solution. In
[`2026-08-23-lookup-bundle-v1-pending-disconnect-request-signal-v1.json`](../bench/results/2026-08-23-lookup-bundle-v1-pending-disconnect-request-signal-v1.json),
local workerd runs with `enable_request_signal`, but an actual TCP reset does
not fire the incoming signal or `writer.closed` and cancels zero of two pending
sources within 3.043 seconds. Cloudflare's
[`Request.signal` documentation](https://developers.cloudflare.com/workers/runtime-apis/request/#properties)
describes the platform feature; this local negative result must not be
generalized to deployed edge behavior, but it provides no ship evidence.

Therefore the unchanged 40% maximum-payload performance gate and the actual
pending-read disconnect gate both fail locally. The production encoder remains
the conservative bridge, the faster direct encoder remains benchmark-only,
and bundle v1 stays opt-in experimental and unshipped. The full four-payload by
four-delay (0/20/50/100 ms) local matrix plus live counterpart, direct proof of
current Worker-isolate heap usage, 100,000-case stateful D1/R2 path, and cross-layer
post-decrypt trust race all remain missing. The remaining performance matrix
should not be run until a candidate passes the decisive 16 MiB/50 ms gate
without weakening cancellation.
