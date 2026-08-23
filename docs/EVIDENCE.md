# Evidence ledger

Every performance or safety claim must map to a reproducible command and retained raw result. “Pending” is not evidence.

| Claim | Metric | Gate | Current evidence |
|---|---|---:|---|
| Hook does not weaken unsafe calls | unsafe fixtures rewritten | 0 | 0 / 1,024 generated hostile shapes plus targeted matrix; pass |
| Eligible hit is correct | known false hits | 0 | 0 across current unit/integration corpus; corpus is not yet the 100,000-run alpha gate |
| Exact output is recoverable | retrieval equality | 100% | 1 / 1 benchmark recovery plus integration fixture; pass |
| Hook is imperceptible | p95 classification | <10 ms | 6.359 ms over 25 warm samples; pass |
| Local hit is fast | p95 lookup + compact output | <100 ms | 8.088 ms over 25 warm samples; pass |
| Useful work accelerates | median eligible warm speedup | >=3x | not applicable: native fixture is 3.995 ms; Again exec is 7.069 ms and therefore slower on this trivial command |
| Context shrinks | repeated output bytes omitted | >=50% | 99.992% on a 2,097,120-byte repeated result; pass |
| Trace-backed profile is trustworthy | unexplained differential mismatches | 0 / 100,000 | not implemented |
| Team protocol boundary holds | cross-tenant/policy/profile/image/producer bypass | 100% rejected | typed protocol and Ed25519 unit corpus pass; no service/API claim yet |

Benchmark raw JSON, machine metadata, commit SHA and scripts belong under `bench/results/`. Never replace a failing run; append a new one and explain the change.

## Retained runs

- [`2026-08-23-macos-arm64-v2.json`](../bench/results/2026-08-23-macos-arm64-v2.json): dirty-tree pre-checkpoint run of the complete hook path. Safety, recovery, hook-latency, hit-latency, invalidation, and output-reduction gates pass. The speed gate is correctly marked `not_applicable`; the native `cat` baseline is too small, and Again is slower on it. This run is retained rather than rewritten. A committed-source rerun must supersede its provenance before release.
- [`2026-08-23-macos-arm64-v3.json`](../bench/results/2026-08-23-macos-arm64-v3.json): clean commit `0421bad`, 25 warm samples. Hook p95 6.359 ms, exec p95 8.088 ms, end-to-end p95 14.110 ms, exact recovery/invalidation/unsafe-matrix checks pass, and duplicate-output reduction is 99.992%. Native `cat` remains faster; the speed gate is `not_applicable` because its 3.860 ms baseline is below 500 ms.
- [`2026-08-23-codex-e2e.json`](../bench/results/2026-08-23-codex-e2e.json): real Codex CLI 0.149.0 session under `workspace-write`. The global `PreToolUse` hook rewrote two separate `cat input.txt` calls to opaque `again exec` calls; the first returned exact bytes and the second returned a reversible compact reference. Repository-local state was writable. The fixture accidentally also retained the same project hook, so two identical handlers matched; this limitation is recorded and both temporary hooks were removed.
