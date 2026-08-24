# Benchmarks

## Direct product benchmark

[`direct_benchmark.py`](direct_benchmark.py) is the current product harness. It
invokes explicit `again run -- <argv...>` with stdin, stdout, and stderr all
non-TTY. It does not install or exercise Codex hooks, and it requires every warm
hit to return the complete byte-for-byte streams. Warm measurements include the
real fixed-argument exact-executable capability-probe child; they are not
zero-process-spawn measurements and do not rerun the requested work.

Build a release binary and write evidence to a new path:

```bash
cargo build --release
python3 -B bench/direct_benchmark.py \
  --binary target/release/again \
  --size-mib 2048 \
  --json-out bench/results/YYYY-MM-DD-direct.json
```

Add `--enforce-speed-gate` when the run must exit non-zero unless the speed gate
passes. An existing JSON path is never overwritten. Without `--json-out`, the
result is printed to stdout.

The default fixture splits 2 GiB of logical sparse-file input across four files,
runs five native baselines and fifteen warm Again calls, and allows 120 seconds
per process. Each captured stream has a 16 MiB harness limit. The optional
`--memory-limit-mib` applies an inherited address-space limit on supported
platforms; it is unavailable on Darwin, where the harness records observed child
peak RSS instead.

The harness uses a fresh temporary Git workspace and external Again state, fixes
`LC_ALL=C` and `PATH=/usr/bin:/bin`, unsets `GREP_OPTIONS`, and removes every
inherited `DYLD_*`, `LD_*`, `Malloc*`, `MALLOC_*`, sanitizer-option, locale,
terminal, and timezone override that the v0 ambient-input policy rejects. The
retained result records the exact removed names under
`unmodeled_loader_locale_terminal_inputs_removed`. It runs native `grep` against
the same explicit files as Again and verifies:

- the cold result exactly matches native exit status, stdout, and stderr;
- every warm event is `replayed_full` and returns the complete exact streams;
- every warm timing includes current identity/context validation and the
  exact-executable capability probe;
- a controlled input mutation that leaves native output unchanged still misses;
- stats report only full replays, with no compact replays or omitted bytes;
- retained evidence includes source, harness and binary provenance, raw timing
  distributions, exact stream hashes, and bounded resource observations.

The correctness gate must pass. The speed gate is applicable only when native
p50 is at least 500 ms; it then requires native p50 divided by warm Again p95 to
be at least 3x. Below that baseline the speed gate is `not_applicable`, because
trivial commands can be slower after process and fingerprint overhead. A script
result is evidence only for its recorded commit, binary, host, and fixture.

## Polyglot explicit-product corpus

[`polyglot_reuse_corpus.py`](polyglot_reuse_corpus.py) drives the real explicit
CLI through five synthetic repository layouts (Rust, Python, Go, TypeScript,
and shell). At the default 100 cases per language it performs 1,010 Again
invocations: a cold and warm call for every file, then a mutation miss and a
new-epoch hit in every repository. It compares exact status/stdout/stderr with
the corresponding native command and checks the resulting execution/full-hit
counters.

```bash
cargo +1.88.0 build --release --locked
python3 -B bench/polyglot_reuse_corpus.py \
  --binary target/release/again \
  --cases-per-language 100 \
  --json-out bench/results/YYYY-MM-DD-polyglot-reuse.json
```

This corpus is a compatibility and invalidation gate. The fixture commands are
intentionally tiny, so it records their timing but does not require or claim a
speedup. A valid result can—and on the retained run does—report zero estimated
net time saved.

## Explicit reference benchmark

[`reference_benchmark.py`](reference_benchmark.py) compares exact full-stream
hits with the opt-in `again reference -- <argv...>` path over the same stored
result. It proves cold and invalidated reference misses execute nothing, every
reference names the original result and stream digests, `again show` recovers
the exact bytes, and stats equal the directly observed positive byte reduction.

```bash
cargo +1.88.0 build --release --locked
python3 -B bench/reference_benchmark.py \
  --binary target/release/again \
  --size-kib 1024 \
  --iterations 25 \
  --json-out bench/results/YYYY-MM-DD-reference.json
```

The default gates require at least 99% output-byte reduction for the 1 MiB
fixture and reference p95 at or below 100 ms. This is tokenizer-independent
wire/output evidence. The harness does not invoke Codex, an LLM, or a tokenizer
and therefore must not be cited as measured model-token or task-cost reduction.
Each child uses a 16 MiB `RLIMIT_FSIZE`/capture ceiling; this cannot be lowered
to the fixture output size because the limit also applies to Again's SQLite and
CAS files, not only its redirected stdout and stderr.

## Team lookup bundle v1 evidence

The two-request `bundle_v1` Worker route, strict Rust client, and manual
two-client lifecycle are implemented, but the profile is manually selectable
only for controlled tests and the protocol is unshipped. The retained performance harness
[`lookup_bundle_v1_benchmark.py`](lookup_bundle_v1_benchmark.py) starts a
dedicated immutable Worker under local Wrangler/workerd and uses actual
loopback HTTP. It does not exercise production D1/R2 state, Cloudflare edge, a
command, an agent, a tokenizer, or cost.

[`results/2026-08-23-lookup-bundle-v1-50ms-matrix-v1.json`](results/2026-08-23-lookup-bundle-v1-50ms-matrix-v1.json)
records 100 measured repetitions plus two warmups per size with one 50 ms
response-start delay per request:

| Ciphertext bytes per stream | Bundle p95 | Five-request p95 | Improvement | 40% gate |
|---:|---:|---:|---:|:---:|
| 0 | 119.664 ms | 294.793 ms | 59.41% | pass |
| 4 KiB | 119.658 ms | 296.251 ms | 59.61% | pass |
| 1 MiB | 143.222 ms | 299.455 ms | 52.17% | pass |
| 16 MiB | 338.542 ms | 342.682 ms | 1.208% | **fail** |

The artifact passes exact two-versus-five request accounting, exact response
bytes/hashes, and the four-way maximum-response overlap gate. Its process-tree
RSS observation is not direct Worker-isolate heap evidence. Its actual TCP-reset
probe fails with an indefinitely pending first source read: 0/2 sources are
cancelled after 3.014 seconds. The separate
[`finite-disconnect` artifact](results/2026-08-23-lookup-bundle-v1-finite-disconnect-v1.json)
passes the weaker finite case with 2/2 sources cancelled in 62.5 ms.

Correctness evidence has separate scopes. The Rust
[`100,000-case protocol parity test`](../src/team_pull/team_lookup_bundle_differential.rs)
uses synthetic responses and does not execute D1/R2. The actual Worker
[`18-state route matrix`](../service/test/service.spec.ts) exercises isolated
D1/R2 and matches the bundle and reference outcome classes/hit bytes. The
[`manual lifecycle result`](results/2026-08-23-team-live-e2e-bundle-v1.json)
passes publication, independent exact reuse, trust rotation, corruption,
revocation, and deletion/recreation through production rustls over a public-CA
Quick Tunnel into local Wrangler D1/R2; it is a single-host dirty-tree run, not
a deployment or performance matrix.

The full four-size by four-delay local matrix plus live counterpart, direct proof
of current Worker-isolate heap usage, 100,000-case stateful D1/R2 path, and cross-layer
post-decrypt trust race remain missing. See the exact [rollout contract and
evidence](../docs/TEAM_LOOKUP_BUNDLE_V1.md).

## Retained diagnostic artifacts

The following files are retained for regression archaeology, not as current
release gates. [`direct-current-v2`](results/2026-08-23-direct-current-v2.json)
and [`direct-release-current-v2`](results/2026-08-23-direct-release-current-v2.json)
are dirty-tree debug/release precursors superseded by the documented
[`direct-net-current-v3`](results/2026-08-23-direct-net-current-v3.json) run.
The bundle [`maximum-payload diagnostic`](results/2026-08-23-lookup-bundle-v1-max-diagnostic-bridge-v1.json)
and [`stream probes`](results/2026-08-23-lookup-bundle-v1-stream-probes-v1.json)
record rejected or intermediate encoder/cancellation investigations; they do
not override the decisive matrix or pending-disconnect failure above. The
[`runtime-attestation`](results/2026-08-23-runtime-attestation-v1.json),
[`fresh-process runtime-checkpoint`](results/2026-08-23-runtime-checkpoint-fast-v1.json),
and [`team session digest-cache`](results/2026-08-23-team-session-digest-cache-v1.json)
files are standalone local microbenchmarks. They characterize their exact host,
binary, and fixture only and make no end-to-end product-speed claim.

## Experimental hook regression harnesses

[`benchmark.py`](benchmark.py) and [`slow_gate.py`](slow_gate.py) explicitly use
`again hook --experimental-unsafe-rewrite`. They exercise dormant exact-envelope,
opaque-handoff, runtime-check, and replay plumbing. Production hooks emit no
automatic allow/rewrite decision, so these scripts are experimental regressions,
not product benchmarks and not release evidence.

```bash
python3 bench/benchmark.py \
  --binary target/release/again \
  --iterations 15 \
  --json-out bench/results/YYYY-MM-DD-experimental-hook.json

python3 -B bench/slow_gate.py \
  --binary target/release/again \
  --size-mib 2048 \
  --json-out bench/results/YYYY-MM-DD-experimental-slow-gate.json
```

These scripts require exact full streams if run against current code. Their hook
and opaque-execution thresholds are script-local regression signals only. They
must never be used to justify automatic-hook, product-latency, or release claims.

[`results/2026-08-23-direct-net-current-v3.json`](results/2026-08-23-direct-net-current-v3.json)
is the current dirty-working-tree explicit-CLI/full-stream result. It passed
correctness and the conditional 3x gate on its recorded 2 GiB sparse `grep`
fixture: native p50 593.929 ms, warm Again p95 12.013 ms, or 49.442x, with
7,260 ms of positive net savings across 15 hits. The earlier clean-commit
[`direct-v1`](results/2026-08-23-direct-v1.json) timing/exactness result remains
retained, but its gross savings counter is superseded. Neither run claims first
runs or arbitrary commands are faster. Historical automatic-hook results remain
only for provenance; see [`docs/EVIDENCE.md`](../docs/EVIDENCE.md).
