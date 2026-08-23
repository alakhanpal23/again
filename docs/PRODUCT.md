# Product contract

## Exact promise

> Again makes a narrow, policy-admitted set of explicit local read-only commands fast while returning their exact full streams. Prefix the command with `again run --`; commands outside the policy are not cached.

This sentence is both the product pitch and the reuse boundary. “Policy-admitted” means only that a command matches the active versioned observation model and current checks; it is not a general safety or equivalence certification. Two executions printing the same bytes is not sufficient.

## Initial customer and job

The first customer is a technical individual using Codex locally on a repository where agent runs repeatedly search or inspect the same material and can invoke `again run -- <argv...>`. The initial job is narrower: remove repeated repository-read latency without asking the developer to declare a build graph.

The first economic buyer is the same developer. The later buyer is an engineering-platform leader paying to remove redundant agent/CI computation across a team while retaining provenance and policy control.

## Onboarding contract

The packaged target is:

```bash
brew install again
again setup --codex
# Start a new Codex session; it can now invoke:
again run -- rg --no-ignore --sort=path needle src
```

`again setup --codex` installs an instruction-only skill at `$HOME/.agents/skills/again` by default. `again setup --codex --project` instead installs `<repo>/.agents/skills/again`; scoped `--remove` reverses an unchanged owned install. The skill tells Codex when to use explicit `again run --` and to rerun an ineligible command unchanged outside Again. It does not install hooks. `again doctor` reports both skill scopes and duplicate installation.

Personal-scope local use requires no Again account, sign-in, API key, daemon, Docker, privileged helper, repository file, Codex hook installation, or telemetry.

On Unix, disposable local state defaults to `${TMPDIR}/again-<euid>/workspaces/<BLAKE3(canonical-workspace-path)>`, with private app-owned directory levels, so the first run never mutates the observed repository. `AGAIN_HOME` selects one exact persistent root; it must be absolute and outside the active workspace, and an existing root must already satisfy the owned-real-`0700` policy. Every canonical ancestor must be a real directory owned by the current uid or root, with sticky protection if group/world writable. Path checks and creation are still raceable by the same user or root.

Production automatic Codex hook rewriting is disabled: the normal hook returns before reading or parsing stdin and emits no allow decision. The hook contract does not expose effective TTY, workdir, shell/login, sandbox, remote `environment_id`, output ceiling, or delivery receipt, so transparent substitution cannot preserve the complete call. Strict current-envelope parsing, an explicit-absolute-executable guard, opaque handoff, and defensive runtime checks remain dormant/tested plumbing behind `--experimental-unsafe-rewrite`. That flag enables the path only for controlled differential tests; there, a hidden TTY or same-repository cwd difference runs the revalidated command once uncached with inherited streams, while a different repository/non-Git cwd or remote executable/state mismatch can fail. It must never be installed as a production hook.

Explicit `again run` is local/default-environment only. Because it starts inside the actual tool shell context, it sees the effective cwd, streams, environment and executable resolution. If any standard stream is a TTY, it performs a single audited execution with inherited streams and no cache read/write.

## v0 admission boundary

The macOS-compatible `strict-read-v0.5` slice admits only strictly parsed read-only `again run` invocations from a small allowlist and verifies executable identity. It may resolve a bare audited name such as `cat`, but admission requires the exact reviewed Apple-tool BLAKE3 and exact reviewed `SystemVersion.plist` BLAKE3. Codex-bundled `rg` requires its exact reviewed BLAKE3 and canonical bundle path shape under that OS profile. Codesign identifier/team fields are descriptive metadata, not strict signature or byte-integrity evidence. Unknown binary or OS updates fail closed. Linux and unknown macOS packages may install, but reuse remains disabled until an audited backend/profile exists; doctor reports audited or unsupported status. Dormant hook plumbing additionally requires `argv[0]` to be an explicit absolute audited executable, but no automatic hook invocation is currently admitted.

Again fingerprints the declared content/listing scope plus canonical workspace/cwd identity, executable bytes, plaintext-free domain-separated environment digests, platform, policy, and request before reuse. Cache keys and proofs also bind real/effective uid and gid, supplementary groups, supported macOS resource limits, and signal mask/dispositions/flags. V0 refuses any present `DYLD_*`, `LD_*`, `Malloc*`, `MALLOC_*`, sanitizer-options, `GCONV_PATH`, `LOCPATH`, `NLSPATH`, `PATH_LOCALE`, `TERMCAP`, `TERMINFO`/`TERMINFO_DIRS`, or `TZDIR` variable because its referenced external bytes are unmodeled. The observation is sampled and path-based, not an immutable snapshot; concurrent mutation, plan-to-use races, and transient global-resource changes remain. Environment digests do not classify secrets or protect low-entropy values from an attacker who can guess the complete fingerprint input.

Only `pwd -P` is admitted, and `ls` requires `--color=never`. Every `grep` and `rg` request requires an explicit path operand. Every `rg` request, including one naming only regular files, additionally requires both `--no-ignore` and `--sort=path`. `RIPGREP_CONFIG_PATH` disables reuse, and an explicit recursive `.git` directory or symlink alias to it is rejected. This intentionally trades hit rate for a smaller, testable observation boundary.

Each pre-execution policy failure below makes explicit `again run` return an error without executing the command. The caller must rerun the original argv unchanged outside Again:

- unknown executable, subcommand, or flag;
- shell composition, pipes, redirects, substitutions, globs, or multiline input;
- absolute input operands or path traversal outside the canonical workspace;
- network, DNS, sockets, IPC, device, credential, or home-directory access;
- filesystem mutation, Git mutation, package management, database access, or process signaling;
- time, randomness, stdin dependence, daemonization, or background work;
- any attempt to recursively wrap an Again command.

A policy-admitted command is executed once uncached instead of reused when any standard stream is a TTY. A cold non-TTY command can also finish without creating a reusable entry: non-zero exit, signal, nonempty stderr, a stdout/stderr capture above 16 MiB, changed inputs, shadow mismatch, or later incomplete evidence all force no-store. Cold stdout/stderr stream live, and once output has been successfully presented, subsequent cache bookkeeping failures preserve the child status. Each stored blob is capped at 16 MiB.

Linux trace-backed admission expands only behind a named capability profile. An observed effect becomes eligible only after an execution boundary can prevent or record all effects represented by that profile.

## Exact-output behavior

Again stores exact stdout and stderr as immutable blobs, and every cache hit currently returns both complete streams. Before replay, every served hit starts the exact audited executable with fixed cheap capability-probe arguments. This confirms point-in-time exec authority but does not rerun the requested argv, eliminate all process spawn, or prove the requested work would succeed under transient global resource pressure. Automatic output compaction is disabled because Codex hooks expose neither the effective output ceiling nor a delivery receipt, so Again cannot establish that a previous complete stream was delivered.

The repository still contains a context-keyed delivery ledger, `PreCompact`/`PostCompact` handlers, and a compact-reference representation. They are dormant future infrastructure and do not activate automatically. `again show` remains an explicit way to inspect stored exact bytes; it is not needed to reconstruct ordinary cache-hit output.

## Product stages

1. **Explicit local exact reads:** `again run`, conservative command parser, audited executable identity, scoped fingerprint, local SQLite/CAS, exact full-stream replay, explainability.
2. **Trace-backed local effects:** Linux rootless isolation, complete descendant/effect observation, COW execution, preconditioned effect replay, 100% initial shadow validation.
3. **Team reuse:** encrypted namespaced CAS, signed provenance, equivalent execution profiles, local verification, revocation, CI and policy.

## North-star and guardrails

North-star: measured end-to-end agent wait time eliminated on eligible repeated work.

Guardrails: known incorrect reuse count, shadow divergence count, miss overhead, explicit-CLI/cache-read-plus-probe latency, exact executable/OS/context-profile mismatches, exact full-stream equality, production-hook no-op violations, secret-tainted entry count, crash consistency, and user-visible refusal/no-store explanations.
