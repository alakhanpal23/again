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

Every existing JSON under `bench/results/` predates the current explicit-CLI
product contract and/or exercises the unsafe experimental hook. Those files are
retained unchanged as historical, superseded evidence; see
[`docs/EVIDENCE.md`](../docs/EVIDENCE.md).
