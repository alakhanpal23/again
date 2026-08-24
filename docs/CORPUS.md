# Generated differential corpus

Again includes a deterministic generated corpus for its deliberately narrow v0 policy and scoped-fingerprint model. This is repository-local test evidence. It is not outside-user, production, deployment, or field evidence.

## Reproduce it

The ordinary test suite runs a 10,000-case CI slice:

```sh
cargo test --offline --test generated_differential generated_differential_ci_slice -- --exact
```

Run the explicit 100,000-case corpus with:

```sh
cargo test --offline --test generated_differential generated_differential_100k -- --ignored --exact --nocapture
```

Both use seed `0xa6a120265eedc0de`. The generator uses complete 40-case blocks, so the full run contains exactly 40,000 eligible shapes and 60,000 non-eligible shapes. The CI slice contains 4,000 and 6,000 respectively.

The separate product-path corpus executes real `again run` processes rather
than only calling policy/fingerprint APIs:

```sh
cargo +1.88.0 build --release --locked
python3 -B bench/polyglot_reuse_corpus.py \
  --binary target/release/again \
  --cases-per-language 100 \
  --json-out bench/results/YYYY-MM-DD-polyglot-reuse.json
```

The retained [`2026-08-23-polyglot-reuse-v1.json`](../bench/results/2026-08-23-polyglot-reuse-v1.json)
passed 1,010 Again invocations across synthetic Rust, Python, Go, TypeScript,
and shell repositories. It made 505 native-command comparisons, required every
cold and warm result to match native status/stdout/stderr, observed 505 full
replays, and proved one mutation miss plus one new-epoch hit per repository.
The run also correctly reported zero estimated net milliseconds saved: these
roughly 2.2 ms native reads are below the useful-work threshold, while warm
Again p95 was 7.15 ms or less. This is correctness/compatibility evidence, not
a speed claim.

## Coverage

The 16 eligible categories cover the direct policy used by `again run` for `cat`, `head`, `tail`, `wc`, `ls --color=never`, `pwd -P`, `grep`, and `rg`, including safe flags, multiple content operands, identity-only access, directory listings, explicit files, and recursive trees. Every eligible `grep` and `rg` shape has at least one explicit path operand. Every eligible `rg` shape additionally includes both `--no-ignore` and `--sort=path`, including regular-file searches.

The 24 non-eligible categories cover shell composition, redirection, expansion, globs, newlines, network tools, mutating tools, escaping symlinks, parent and absolute input paths, `.again`, volatile Git logs, stdin, unsafe flags, `rg` missing either deterministic flag, an existing Again wrapper, unknown commands, parse errors, and TTY-dependent execution. Targeted tests separately cover `RIPGREP_CONFIG_PATH` and explicit recursive `.git` directories/symlink aliases.

Every generated command is classified twice and the decisions must match exactly. Eligible categories must produce `ExactReuse`; every other category must not. This is the explicit `again run` policy. Production Codex hooks are no-op regardless of this decision.

Four stratified representatives exercise scoped fingerprints:

- `pwd -P`: unrelated workspace content is ignored; a modeled environment change invalidates only the request.
- `cat selected.txt`: unrelated content is ignored; selected content invalidates.
- `rg --no-ignore --sort=path needle tree`: content outside the tree is ignored; tree membership invalidates.
- `ls --color=never listing`: content outside the listed directory is ignored; directory membership invalidates.

Each representative also requires two identical fingerprints before mutation. Where standard read-only system tools are available, six small command fixtures (`cat`, `head`, `tail`, `wc`, `ls --color=never`, and `pwd -P`) are executed twice with a fixed environment and their status, stdout, and stderr are compared exactly.

The product-path corpus rotates `cat`, `head`, `tail`, `wc`, and `grep` over
100 files in each language-shaped repository. It exercises exact executable/OS
admission, runtime-context binding, SQLite/CAS persistence, cold double
validation, the per-hit capability probe, full-stream presentation, stats, and
mutation invalidation. Its initial smoke run found that BSD `head -n 0` made the
old fixed capability probe fail on every warm `head` call; the probe now reads
one line from fixed null stdin and has a reviewed-host regression test covering
every audited Apple tool.

## Limitations

- Generated cases test the explicit `again run` policy and fingerprint APIs in-process. Bare executable names can be eligible there because the wrapper resolves and validates them in the actual local context. Targeted hook/process tests separately cover the production no-op behavior and dormant exact-envelope/explicit-absolute-executable guards.
- Generated classifications do not execute the `strict-read-v0.5` exact binary/OS verifier, exercise unknown-host refusal or the ambient-input denylist, bind real/effective credentials, groups, rlimits or signals, or exercise the per-hit exact-executable capability probe.
- The corpus covers the current audited narrow profile, not arbitrary shell semantics or arbitrary command caching.
- The two-run checks establish agreement only for the included local fixtures at test time. They do not establish general command determinism.
- This corpus does not simulate hostile kernel behavior, transient global-resource changes, concurrent filesystem mutation during or after sampling, same-user/root replacement after configured ancestor validation, other state-path races, macOS Seatbelt enforcement, remote/team caches, or outside-user workloads.
- Case count is not a general safety or equivalence guarantee; the value is deterministic regression breadth and reproducible differential checks.
- The five repositories contain representative language file extensions and
  deterministic bytes; Again does not parse those languages or cache their
  compilers/tests. The corpus therefore establishes narrow read-tool
  compatibility across layouts, not language-semantic support.
