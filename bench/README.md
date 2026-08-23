# Product benchmark

This is a reproducible local product benchmark, not a published performance
claim. It measures the whole Codex-facing path: hook classification, opaque
handoff, execution/validation, cache replay, compact response, and exact output
recovery.

Build a binary and write a new, retained result file:

```bash
cargo build --release
python3 bench/benchmark.py \
  --binary target/release/again \
  --iterations 15 \
  --json-out bench/results/local-$(date +%Y%m%d-%H%M%S).json
```

`--json-out` is optional; without it JSON is written to stdout. When present it
uses exclusive creation and refuses to overwrite an existing result. Retain the
raw JSON with the change being evaluated. It records:

- source commit and dirty state;
- binary path, `--version`, and SHA-256 digest;
- machine and Python metadata;
- raw samples plus p50/p95 for baseline, warm hook, warm execution, and full
  warm end-to-end latency;
- a cold result, `again show <id>` byte-for-byte recovery check, unsafe and
  unhandled no-rewrite matrix, and input-mutation invalidation check.

The fixture is a fresh temporary workspace containing a deterministic payload.
It uses a temporary Again state directory, so it neither reuses nor changes a
developer's normal cache.

## Gates

The output evaluates these explicit, observed gates:

| Gate | Pass condition |
| --- | --- |
| Hook | warm hook p95 `< 10 ms` |
| Hit | warm execution p95 `< 100 ms` |
| Context reduction | median duplicate output reduction `>= 50%` |
| Speed | evaluated only if baseline p50 is at least `500 ms`; then baseline p50 / warm hit p95 must be at least `3x` |

The speed gate is `not_applicable` below the 500 ms baseline threshold. Gate
status is a measurement outcome for the recorded environment, not a general
claim. The benchmark intentionally reports cold cost, distributions, raw
samples, safety checks, and failed gates rather than hiding them.

The no-rewrite matrix includes network, mutation, Git, unknown, shell-composed,
absolute-path, and stdin-dependent commands. It fails the run if the hook
rewrites any of them; it never executes those commands.

## Slow speed gate

Use a separate low-output scan fixture for the roadmap's speed gate:

```bash
python3 -B bench/slow_gate.py \
  --binary target/release/again \
  --size-mib 2048 \
  --json-out bench/results/YYYY-MM-DD-slow-gate.json
```

It creates a sparse file with one match at the end, measures native `grep`, the
full cold double-validation path, and warm hook-to-result latency. It then
changes an input byte while deliberately leaving grep's output unchanged; a
compact response at that point is a correctness failure. Speed passes only when
native p50 is at least 500 ms and native p50 divided by Again warm end-to-end
p95 is at least 3x.
