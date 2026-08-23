# Delivery roadmap and gates

Dates are phase labels, not excuses to widen the documented reuse boundary. A feature ships only when its gate passes.

## Overnight vertical slice

Sequence:

1. Freeze product promise, first user, v0 allowlist, refusal/no-store rules, and EffectIR v1.
2. Build native explicit `again run`, an ownership-checked instruction-only Codex skill, doctor scope reporting, and a true no-op production hook while effective workdir/TTY/shell/remote semantics are hidden. Retain exact-envelope, explicit-absolute-executable and opaque-handoff plumbing for experimental tests only.
3. Build deterministic workspace/request fingerprint, SQLite index, immutable blob store, exact result replay, and full-output retrieval.
4. Return exact full streams on every hit; add stats and human/machine-readable explanations. Keep delivery-ledger compaction disabled until Codex supplies a stable delivery receipt.
5. Run policy tables, no-op hook/envelope fixtures, explicit-run TTY behavior, mutation invalidation, state/path symlink, ownership, mode and hard-link checks, output-limit/nonempty-stderr admission, corruption, concurrency, crash, and non-zero-result tests.
6. Run `bench/direct_benchmark.py` for cold overhead, warm latency including the exact-executable probe child, wall time, mutation invalidation, resource observations, and full-stream equality with non-TTY streams.
7. Test personal-only and project-only Codex skill installs, record limitations, and commit only a green checkpoint.

Success gates:

- zero false hits in the adversarial fixture suite;
- every production hook fixture emits no automatic allow/rewrite decision;
- byte-perfect full stdout/stderr on every miss and hit, plus reliable `show` retrieval;
- explicit `again run` resolves only audited executables from the actual local tool-shell context;
- exact tool BLAKE3 and exact OS semantic profile match `strict-read-v0.5`; unknown updates fail closed;
- every unmodeled loader, sanitizer, locale, terminal, or timezone environment override in the documented denylist refuses admission;
- keys/proofs partition real/effective credentials, supplementary groups, supported macOS rlimits, and signal mask/dispositions;
- every served hit passes a fixed-argument exact-executable capability probe without rerunning requested argv;
- explicit TTY calls execute once uncached with inherited streams;
- explicit policy refusals never execute the command; callers rerun original argv unchanged;
- reusable results require exit zero, empty stderr, bounded complete captures, stable observations and shadow equality;
- p95 explicit-CLI warm hit under 100 ms on the development machine;
- warm speedup at least 3x on fixtures whose original duration is at least 500 ms;
- install and first explicit cached call under one minute, with no hook trust review.

Kill or narrow immediately if any known stale/incorrect result is served, the production hook emits an automatic allow/rewrite decision, a cache hit changes either output stream, or median eligible warm speedup is below 2x.

## Days 1–7: trusted local alpha

### Day 1 — reuse corpus

Expand to at least 1,000 deterministic/adversarial executions across Rust, Python, Go, TypeScript and shell repositories. Add property tests for parser and filesystem invalidation, `pwd -P`, `ls --color=never`, explicit `grep`/`rg` paths, `rg --no-ignore --sort=path`, recursive `.git` aliases, no-op hook envelopes, exact executable/OS profiles and unknown-profile refusal, ambient-input denylist coverage, runtime-context partitions, capability-probe failures, state-root placement and ownership/link/mode checks, configured ancestor owner/sticky rules, same-user/root state-parent races, bounded output, and empty-stderr admission. Publish every failure class as a regression fixture. Treat concurrent path mutation and transient global-resource changes as unresolved until stronger execution/snapshot boundaries exist.

### Day 2 — Linux trace boundary

Prototype rootless immutable/COW execution with enforced no-network policy and complete descendant tracking. Compare ptrace/seccomp/eBPF overhead and completeness. Tracer gaps remain execute-only.

### Day 3 — EffectIR validation

Record directories, absent paths, symlinks, metadata, executable/interpreter/library closure, environment digests, stdin, ordered effects, and completeness bitmap. Add replay preconditions and transactional staging.

### Day 4 — shadow validation

Shadow 100% of newly eligible hits; compare exact streams/status, canonical EffectIR and final filesystem root. Quarantine candidate and generalization class on mismatch. Add deterministic validation selection only after dependency completeness is demonstrated.

### Day 5 — real agent sessions

Capture opt-in local metrics on representative Codex tasks without collecting command text or output. Measure total task latency, explicit-prefix adoption, miss overhead, reuse rate, full-stream byte cost, uncached TTY executions, and behavioral failures.

### Day 6 — packaging and distribution

Normalized macOS/Linux releases, checksums/source SBOM, Homebrew tap, install script with signature verification, uninstall, upgrade, schema migration, bounded storage and GC. An installable artifact must still report unsupported and disable reuse unless its backend/profile is audited. Claim bit reproducibility only after an independent rebuild comparison.

### Day 7 — outside alpha

Ten real commands from at least five outside developers. Require seven to work without configuration, at least 3x median eligible warm speedup, zero semantic mismatches, and three explicit requests for CI/team sharing. If not, narrow the ICP/command profile before adding breadth.

Day-7 system gate: zero unexplained divergence in 100,000 eligible shadow comparisons, miss overhead below 15% for commands over one second, no host mutation after interrupted runs, and every unsupported effect explained.

## Days 8–30: team product

### Shared protocol

Define content-addressed manifest/blob APIs with policy/profile identity, signed provenance, quarantine and revocation. Clients validate every remote candidate and never execute a remote blob.

### Security and tenancy

End-to-end TLS, encrypted storage, tenant/repository namespaces, least-privilege credentials, ACLs, audit events, retention, deletion, quotas, rate limiting, secret-taint local-only policy, threat model, dependency/SBOM scanning and incident runbook.

### CI and remote execution

GitHub Action and generic CI client; equivalent immutable images; staged output restore; trusted-builder or two-producer admission; local fallback. Remote execution is introduced only after local trace/replay gates hold.

### Policy and analytics

Organization policy packs, signed versions, “why run/reuse” audit, compute/time savings receipts, regression health, cache poisoning alerts, GC/storage reports. No surveillance telemetry by default.

### Design partners and pricing evidence

Work with 5–10 agent-heavy polyglot teams. Validate a free local engine plus paid shared cache/CI/policy/provenance. Price hypotheses are tested against verified savings, not vanity command counts.

Day-30 gates:

- 100% rejection of unsigned, revoked, cross-tenant, cross-repository, policy-mismatched and image-mismatched fixtures;
- no validation mismatch served after discovery;
- cross-machine equality for 100 hermetic workloads;
- p95 local hit below 100 ms and shared hit faster than original execution;
- at least 30% median end-to-end wall-time reduction on consenting team sessions while preserving exact full streams;
- at least 20% useful cross-user hit rate for the chosen ICP;
- three design partners willing to pay for shared reuse or verified compute savings.

If cross-user hits remain below 10%, reuse evidence can still support local optimization, but the remote-cache business thesis must be reconsidered.

## How each stage compounds the moat

| Stage | Product asset | Compounding asset |
|---|---|---|
| v0 strict reads | explicit one-command wrapper, instruction skill, and clear refusal/rerun behavior | labeled admitted/refused command shapes, invalidation fixtures, output-repeat patterns |
| traced local alpha | broader useful work | real EffectIR traces, minimized divergences, tool/runtime compatibility, validation history |
| outside alpha | reproducible value | repository/language workload coverage and accepted policy generalizations |
| team cache | shared saved work | cross-machine equivalence graph, artifact provenance, organization-specific effect graph |
| remote execution | high-value acceleration | calibrated compute profiles, failure/poisoning corpus, verified savings history |

The moat is reuse-safety and compatibility evidence that improves conservative coverage. A blob store or opaque classifier alone is copyable.
