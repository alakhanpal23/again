# Benchmarks

## Gateway reuse value probe

`python3 bench/gateway_reuse_value_probe_v1.py --source-files 1000 --output
bench/results/<date>-gateway-reuse-value.json` compares a live stdio MCP
session with the hidden diagnostic `mcp serve --execute-only` mode. Both modes
run the same provider and return identical content; the diagnostic mode skips
candidate lookup and storage. Each case records 40 warm calls, cold latency,
p50/p95, and physical executions. The
[pre-bypass 1,000-file run](results/2026-09-23-gateway-reuse-value-probe-v3.json)
found direct execution faster for read, stat, tree, and a simple search. The
[post-bypass run](results/2026-09-23-gateway-reuse-value-probe-v7.json) confirms
that the default gateway executes all eight built-in `repo.*` tools directly
when no shared task is active, bringing their latency close to the
execute-only path. Task-bound calls still retain proof and shared context.
These are local dirty-source diagnostics, not a universal value model or an
agent-level speed result.

The later [one-file](results/2026-09-23-gateway-reuse-value-probe-small-v8.json)
and [250-file](results/2026-09-23-gateway-reuse-value-probe-250-v8.json)
standalone runs include `git.status`. An index below 16 KiB retains reuse;
the 250-file index exceeds that threshold and the default executes directly.
The gate only removes reuse authority and makes no new claim about Git output.

`python3 bench/gateway_task_reuse_value_probe_v1.py --source-files 1000
--output bench/results/<date>-gateway-task-reuse-value.json` runs the same
comparison through the authenticated daemon after `task.start`. Its hidden
`mcp daemon serve --execute-only` control retains the task setup and provider
path but skips reuse lookup and storage. The [one-file](results/2026-09-23-gateway-task-reuse-value-probe-small-v2.json),
[250-file](results/2026-09-23-gateway-task-reuse-value-probe-250-v1.json),
and [1,000-file](results/2026-09-23-gateway-task-reuse-value-probe-v2.json)
reports show that the earlier warm task-bound `repo.*` cache hits were slower
than direct execution on these fixtures, despite avoiding physical executions
and supplying verified shared context. The newer [one-file](results/2026-09-23-gateway-task-reuse-value-probe-fast-small-v9.json)
and [1,000-file](results/2026-09-23-gateway-task-reuse-value-probe-fast-v9.json)
runs exercise the current policy: the first call stores a source-backed result;
subsequent same-task calls with an identical fresh provider result execute
directly and return no cache-result ID. A changed result falls back to full
proof and publishes a new verified result. Large-index `git.status` uses the
same path; small-index Git status keeps reuse. These probes measure per-call
latency, not the downstream value of context to another agent.

## Installed client setup probe

[`agent_gateway_client_setup_v1.py`](agent_gateway_client_setup_v1.py) exercises
the current `again mcp setup` flow against an installed Codex or Claude CLI in
a disposable private client home. It checks apply, inspect, idempotent apply,
and removal without making model calls or changing the user's normal client
configuration. For Codex, it also verifies the personal skill and task-start
guidance. Run it with a daemon-enabled binary:

```bash
cargo build --locked --features daemon
python3 bench/agent_gateway_client_setup_v1.py \
  --again-bin target/debug/again --client codex \
  --workspace "$(pwd -P)" --json-out /tmp/again-codex-setup-probe.json
```

The report binds the client and Again binary bytes, but it does not prove that
the binary came from the recorded Git revision. A dirty-worktree run is a local
diagnostic, not release qualification. The current
[`local Codex probe`](results/2026-09-22-codex-setup-local-probe-v1.json) used
Codex CLI 0.156.0, passed all four setup operations, and made zero model calls.
Claude still needs a run with an installed client binary.

## Local Codex live MCP probe

`python3 bench/agent_gateway_codex_live_probe_v1.py --output
bench/results/<date>-codex-live-probe-v1.json` runs one authenticated Codex
session in a disposable repository with the current user's existing login. It
loads only the explicit Again MCP configuration, calls `task.start` and
`repo.read`, and verifies the fixture is unchanged. Noninteractive Codex needs
`--approve-for-me` to allow MCP calls; its default `never` approval mode
refused both tools in the diagnostic run. This probe confirms tool discovery
and use, but does not measure task quality, repeated-call savings, or source
binding while the checkout is dirty. The current
[`local run`](results/2026-09-23-codex-live-probe-v1.json) passed.

The same harness with `--repeat-read` asks Codex for two identical `repo.read`
calls and checks the durable gateway counters. The
[`local repeat probe`](results/2026-09-23-codex-repeat-probe-v1.json) recorded two
requests, one physical execution, one exact hit, one avoided provider call,
and zero false-hit quarantines. This verifies one narrow repeated call shape;
it does not establish a general speed or cost improvement.

`python3 bench/agent_gateway_codex_context_probe_v1.py --output
bench/results/<date>-codex-context-probe-v1.json` runs two separate Codex
sessions in the same disposable repository. The first reads and publishes an
unverified suggestion; the second joins the exact task and reads it through
`context.delta`. The [local run](results/2026-09-23-codex-context-probe-v1.json)
passed. It is a cross-session integration diagnostic, not a concurrent editing
or acceleration result.

## Codex editable pair diagnostic

`python3 bench/agent_gateway_codex_pair_diagnostic_v1.py --output
bench/results/<date>-codex-editable-pair-diagnostic.json` runs one baseline
Codex edit and one Again-enabled edit on the same fixed calculator fixture. It
retains the complete synthetic-fixture Codex JSONL events beside a summary with
provider-reported usage, first edit timing, the strict one-file oracle, and
Again's durable counters. The runs use the current authenticated Codex CLI,
`--approve-for-me`, a pinned model argument, and disposable repositories.

The [v1](results/2026-09-23-codex-editable-pair-diagnostic-v1.json) through
[v5](results/2026-09-23-codex-editable-pair-diagnostic-v5.json) local diagnostics
all produced the accepted patch and passing tests. Bounded source previews
let Codex edit without a separate pre-edit `repo.read` in v2 through v5. In v4,
baseline and Again first edits took 17.1 and 16.8 seconds, while validated
completion took 23.4 and 28.7 seconds. In v5 the corresponding times were
19.7 and 17.9 seconds for first edit, and 31.1 and 26.9 seconds for completion.
These are single unbalanced pairs on dirty source and differing binary
revisions; their mixed results do not establish acceleration or a causal
before/after effect. The v5 recorded harness hash matches the current script.

## Local beta release gate

[`local_beta_gate.py`](local_beta_gate.py) is the fail-closed final aggregator
for the daemon/task-lifecycle local beta. It requires the ordered 12-step
release-binary product scenario, a 100-client automatic-daemon chaos run,
exactly four native package smokes, authenticated 14-asset release evidence,
the authenticated task lifecycle gate, and balanced existing-user or
controlled-agent Codex/Claude evidence. All inputs must bind to one source
commit, and product/task/chaos/agent observations must bind to one binary.
The output contains only compact digests and release decisions.

The complete evidence schemas, beta chaos command, aggregation command, privacy
rules, and Wave 2 integration boundary are documented in
[`LOCAL_BETA_GATE.md`](../docs/LOCAL_BETA_GATE.md). No existing private-alpha
artifact satisfies this gate: in particular, a quick 2-client chaos report or
a deterministic/dry-run agent report is an explicit non-pass.

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

## Paired editable-agent benchmark

[`agent_gateway_editable_pair.py`](agent_gateway_editable_pair.py) is the
fail-closed editable companion to the existing read-only real-agent harness. It
creates independent identical Git fixtures, permits exactly one known source
repair, rejects test/collateral edits, runs a fixed acceptance suite, alternates
baseline/Again order, and retains monotonic first-edit, accepted-edit,
validation, final-outcome, and total timing markers. Live mode requires explicit
network authorization, a credential environment-name binding, pinned model and
settings IDs, absolute command arrays with standalone placeholders, and an
exact Again binary. An Again treatment passes only when durable workspace
gateway/context counters move; a command label or socket alone is not evidence.

Qualify the harness and oracle offline before any paid run:

```bash
python3 -B bench/agent_gateway_editable_pair.py \
  --mode qualify \
  --runs 10 \
  --json-out bench/results/YYYY-MM-DD-agent-gateway-editable-qualification.json
```

The retained
[`2026-08-29 qualification`](results/2026-08-29-agent-gateway-editable-pair-qualification-v1.json)
passed 10/10 baseline and 10/10 treatment-shaped observations. It measures a
deterministic reference editor and the harness only: it is not real-agent task
quality, model usage, or Again acceleration evidence. Live Codex/Claude runs
remain a separate explicit external gate.

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
