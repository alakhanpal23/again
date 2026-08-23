# Evidence ledger

Every performance or safety claim must map to a reproducible command and retained raw result. “Pending” is not evidence.

| Claim | Metric | Gate | Current evidence |
|---|---|---:|---|
| Hook does not weaken unsafe calls | unsafe fixtures rewritten | 0 | 0 / 1,024 generated hostile shapes plus targeted matrix; pass |
| Eligible hit is correct | known false hits | 0 | 0 across current unit/integration corpus; corpus is not yet the 100,000-run alpha gate |
| Exact output is recoverable | retrieval equality | 100% | 1 / 1 benchmark recovery plus integration fixture; pass |
| Hook is imperceptible | p95 classification | <10 ms | 5.506 ms over 15 warm samples; pass |
| Local hit is fast | p95 lookup + compact output | <100 ms | 12.345 ms over 15 warm samples; pass |
| Useful work accelerates | median eligible warm speedup | >=3x | not applicable: native fixture is 3.995 ms; Again exec is 7.069 ms and therefore slower on this trivial command |
| Context shrinks | repeated output bytes omitted | >=50% | 99.992% on a 2,097,120-byte repeated result; pass |
| Trace-backed profile is trustworthy | unexplained differential mismatches | 0 / 100,000 | not implemented |
| Team boundary holds | cross-tenant/policy/image bypass | 100% rejected | not implemented |

Benchmark raw JSON, machine metadata, commit SHA and scripts belong under `bench/results/`. Never replace a failing run; append a new one and explain the change.

## Retained runs

- [`2026-08-23-macos-arm64-v2.json`](../bench/results/2026-08-23-macos-arm64-v2.json): dirty-tree pre-checkpoint run of the complete hook path. Safety, recovery, hook-latency, hit-latency, invalidation, and output-reduction gates pass. The speed gate is correctly marked `not_applicable`; the native `cat` baseline is too small, and Again is slower on it. This run is retained rather than rewritten. A committed-source rerun must supersede its provenance before release.
