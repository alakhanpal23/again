# Delivery roadmap and gates

Dates are phase labels, not excuses to weaken the safety invariant. A feature ships only when its gate passes.

## Overnight vertical slice

Sequence:

1. Freeze product promise, first user, v0 allowlist, bypass rules, and EffectIR v1.
2. Build native CLI, Codex PreToolUse adapter, opaque call handoff, idempotent dry-run setup, and doctor.
3. Build deterministic workspace/request fingerprint, SQLite index, immutable blob store, exact result replay, and full-output retrieval.
4. Add same-session exact-output references, stats, and human/machine-readable explanations.
5. Run policy tables, hook-contract fixtures, mutation invalidation, symlink/path escape, corruption, concurrency, crash, and non-zero-result tests.
6. Benchmark cold overhead, warm latency, wall time, output bytes, and context-byte reduction on controlled fixtures.
7. Test an isolated Codex install/config, record limitations, commit and push only a green checkpoint.

Success gates:

- zero false hits in the adversarial fixture suite;
- all unsafe fixtures pass through without hook auto-allow;
- byte-perfect first delivery and reliable `show` recovery;
- compact references only after full same-session delivery;
- p95 hook classification under 10 ms and local hit under 100 ms on the development machine;
- warm speedup at least 3x on fixtures whose original duration is at least 500 ms;
- at least 50% duplicate output bytes removed in repeated-session fixtures;
- install/setup under one minute excluding the explicit Codex trust review.

Kill or narrow immediately if any stale/incorrect result is served, a rewrite changes an unsafe call’s approval behavior, exact output cannot be recovered, or median eligible warm speedup is below 2x.

## Days 1–7: trusted local alpha

### Day 1 — correctness corpus

Expand to at least 1,000 deterministic/adversarial executions across Rust, Python, Go, TypeScript and shell repositories. Add model-based/property tests for parser and filesystem invalidation. Publish every failure class as a regression fixture.

### Day 2 — Linux trace boundary

Prototype rootless immutable/COW execution with enforced no-network policy and complete descendant tracking. Compare ptrace/seccomp/eBPF overhead and completeness. Tracer gaps remain execute-only.

### Day 3 — EffectIR validation

Record directories, absent paths, symlinks, metadata, executable/interpreter/library closure, environment digests, stdin, ordered effects, and completeness bitmap. Add replay preconditions and transactional staging.

### Day 4 — shadow validation

Shadow 100% of newly eligible hits; compare exact streams/status, canonical EffectIR and final filesystem root. Quarantine candidate and generalization class on mismatch. Add deterministic validation selection only after dependency completeness is demonstrated.

### Day 5 — real agent sessions

Capture opt-in local metrics on representative Codex tasks without collecting command text or output. Measure total task latency, miss overhead, reuse rate, repeated output bytes, explicit full-output fetches, and behavioral failures.

### Day 6 — packaging and distribution

Reproducible macOS/Linux releases, checksums/SBOM, Homebrew tap, install script with signature verification, uninstall, upgrade, schema migration, bounded storage and GC.

### Day 7 — outside alpha

Ten real commands from at least five outside developers. Require seven to work without configuration, at least 3x median eligible warm speedup, zero semantic mismatches, and three explicit requests for CI/team sharing. If not, narrow the ICP/command profile before adding breadth.

Day-7 system gate: zero unexplained divergence in 100,000 eligible shadow comparisons, miss overhead below 15% for commands over one second, no host mutation after interrupted runs, and every unsupported effect explained.

## Days 8–30: team product

### Shared protocol

Define content-addressed manifest/blob APIs with policy/profile identity, signed provenance, quarantine and revocation. Clients validate every remote candidate and never execute a remote blob.

### Security and tenancy

End-to-end TLS, encrypted storage, tenant/repository namespaces, least-privilege tokens, ACLs, audit events, retention, deletion, quotas, rate limiting, secret-taint local-only policy, threat model, dependency/SBOM scanning and incident runbook.

### CI and remote execution

GitHub Action and generic CI client; equivalent immutable images; staged output restore; trusted-builder or two-producer admission; local fallback. Remote execution is introduced only after local trace/replay gates hold.

### Policy and analytics

Organization policy packs, signed versions, “why run/reuse” audit, compute/time/token savings receipts, regression health, cache poisoning alerts, GC/storage reports. No surveillance telemetry by default.

### Design partners and pricing evidence

Work with 5–10 agent-heavy polyglot teams. Validate a free local engine plus paid shared cache/CI/policy/provenance. Price hypotheses are tested against verified savings, not vanity command counts.

Day-30 gates:

- 100% rejection of unsigned, revoked, cross-tenant, cross-repository, policy-mismatched and image-mismatched fixtures;
- no validation mismatch served after discovery;
- cross-machine equality for 100 hermetic workloads;
- p95 local hit below 100 ms and shared hit faster than original execution;
- at least 30% median end-to-end wall-time reduction and 30% duplicate tool-output reduction on consenting team sessions;
- at least 20% useful cross-user hit rate for the chosen ICP;
- three design partners willing to pay for shared reuse or verified compute savings.

If cross-user hits remain below 10%, correctness data can still support local optimization, but the remote-cache business thesis must be reconsidered.

## How each stage compounds the moat

| Stage | Product asset | Compounding asset |
|---|---|---|
| v0 strict reads | instant setup and trustworthy fallback | labeled safe/unsafe command shapes, invalidation fixtures, output-repeat patterns |
| traced local alpha | broader useful work | real EffectIR traces, minimized divergences, tool/runtime compatibility, proof history |
| outside alpha | reproducible value | repository/language workload coverage and accepted policy generalizations |
| team cache | shared saved work | cross-machine equivalence graph, artifact provenance, organization-specific effect graph |
| remote execution | high-value acceleration | calibrated compute profiles, failure/poisoning corpus, verified savings history |

The moat is correctness and compatibility data that improves safe coverage. A blob store or opaque classifier alone is copyable.

