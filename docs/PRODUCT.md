# Product contract

## Exact promise

> Again is a repository-aware execution memory and tool-call control plane for coding agents. It skips only work proven redundant, executes uncertain work, and returns the smallest useful verified observation.

This sentence is both the product pitch and the reuse boundary. The stable explicit path makes a narrow, policy-admitted set of local read-only commands fast while returning exact full streams. The experimental MCP path currently controls only the built-in `repo.read` and `repo.search` tools. “Proven” means that the request and its declared repository, task, provider, schema, environment, authorization scope, and dependency observations satisfy a versioned deterministic policy; matching text or semantic similarity is never sufficient.

## Initial customer and job

The first customer is a technical individual using Codex or Claude locally on a repository where agents repeatedly search or inspect the same material. The initial job is to remove redundant repository-tool latency and repeated context without asking the developer to declare a build graph. The experimental gateway gives agents a shared exact execution memory; the explicit CLI remains the conservative stable path.

The first economic buyer is the same developer. The later buyer is an engineering-platform leader paying to remove redundant agent/CI computation across a team while retaining provenance and policy control.

## Onboarding contract

The packaged target is:

```bash
brew install again
again setup --codex
# Start a new Codex session; it can now invoke:
again run -- rg --no-ignore --sort=path needle src
# only if those exact complete bytes remain visible in this active context:
again reference -- rg --no-ignore --sort=path needle src
```

`again setup --codex` installs an instruction-only skill at `$HOME/.agents/skills/again` by default. `again setup --codex --project` instead installs `<repo>/.agents/skills/again`; scoped `--remove` reverses an unchanged owned install. The skill tells Codex when to use explicit `again run --`, when an explicit `again reference --` is context-safe, and to rerun an ineligible command unchanged outside Again. It does not install hooks. `again doctor` reports both skill scopes and duplicate installation.

Personal-scope local use requires no Again account, sign-in, API key, daemon, Docker, privileged helper, repository file, Codex hook installation, or telemetry.

The experimental MCP onboarding path is explicit and workspace-bound:

```bash
again mcp setup --client codex --workspace /canonical/repository
again mcp setup --client claude --workspace /canonical/repository
```

Both commands are dry runs unless `--install-owned-config ABSOLUTE_PATH` is supplied. The generated server argv contains the exact canonical repository path. Installation can create only a wholly Again-owned absent config plus its ownership record, or verify the exact owned pair; an unowned or conflicting file is never overwritten. The gateway uses bounded concurrent stdio, serializes complete responses, propagates cancellation to the matching physical attempt, and fails closed on malformed or oversized JSON-RPC.

Current gateway limits are part of the product truth: there is no general upstream MCP proxy, authenticated result-ID retrieval, automatic compact cross-agent delivery, semantic reuse, task-quality qualification, or production Linux command backend. Unknown or incomplete state executes normally. Mutating, network, credential, deployment, payment, and unknown tools are not reused.

The current retained product checkpoint is [`2026-08-27-agent-gateway-product-e2e-release-v3.json`](../bench/results/2026-08-27-agent-gateway-product-e2e-release-v3.json), bound to source `850e7c4398adc25ef1210ee4260e27b29aaeb753`, release-binary SHA-256 `e52e7540c3754038db3fbc87bc0039df1b6e983b124497d4f3559708c5a536f0`, and report-file SHA-256 `9b818771f830395d2b123e83437b290ea470b284bcef0f52ce1576edbd82ce08`. All eight exact scenarios passed through four actual Again MCP processes with 12 provider executions and zero false hits. Their exact event windows contain two exact reuse hits and one joined in-flight call, for three avoided provider executions. The canceled follower remains only a cancellation candidate.

The same release bytes passed the retained [onboarding smoke](../bench/results/2026-08-27-agent-gateway-onboarding-smoke-v2.json) and [quick chaos run](../bench/results/2026-08-27-agent-gateway-chaos-soak-v3.json). Onboarding exercised isolated Codex/Claude installation, owned reinstall/removal, unowned and symlink refusal, exact workspace binding, real MCP startup, both built-ins, mutation invalidation, and descendant cleanup without reading real user credentials or configuration. Chaos reconciled all eight product scenarios, 16 extra exact calls over two sessions, zero false hits, six absent owned process groups, unchanged open-descriptor count, and absent temporary state. These are local release-binary facts, not hostile-binary network-sandbox or general performance evidence.

The fresh [real-repository report](../bench/results/2026-08-27-agent-gateway-real-repository-partial-v2.json) passed explicit clean Rust, Python, and TypeScript repositories but remains a typed `non_pass` because the bounded offline search found no eligible local Go repository and the harness never clones or downloads one. The alpha-trial recorder freezes ten scenarios and can aggregate exactly five independent users and 50 attempts, but no outside-user report exists; local simulation is explicitly non-evidence. The [real-agent report](../bench/results/2026-08-27-agent-gateway-real-agent-dry-run-v2.json) validates explicit read-only Codex 0.150.1 and Claude 2.1.220 command templates, exact inspected runtime pins, isolated configuration roots, credential-by-environment handling, fixed paired tasks, output redaction, resumable journal rules, and evidence bounds. It is an offline plan: no agent, network, or paid model call ran. All 16 live paired runs remain manual and unexecuted, so no model-quality, end-to-end agent-latency, direct token-count, or task-outcome claim follows. Production has no authenticated MCP recipient issuer: schema-v10 receipts and grants are dormant, full results remain the only MCP presentation, and delivery-confirmed bytes/tokens saved are zero.

On Unix, disposable local state defaults to `${TMPDIR}/again-<euid>/workspaces/<BLAKE3(canonical-workspace-path)>`, with private app-owned directory levels, so the first run never mutates the observed repository. `AGAIN_HOME` selects one exact persistent root; it must be absolute and outside the active workspace, and an existing root must already satisfy the owned-real-`0700` policy. Every canonical ancestor must be a real directory owned by the current uid or root, with sticky protection if group/world writable. Path checks and creation are still raceable by the same user or root.

Production automatic Codex hook rewriting is disabled: the normal hook returns before reading or parsing stdin and emits no allow decision. Current hooks support `updatedInput` and expose the session `cwd`, but they do not expose an `exec_command` call's effective per-call workdir, effective TTY, shell/login, sandbox, remote `environment_id`, output ceiling, or delivery receipt. Transparent substitution therefore cannot preserve the complete call. Strict current-envelope parsing, an explicit-absolute-executable guard, opaque handoff, and defensive runtime checks remain dormant/tested plumbing behind `--experimental-unsafe-rewrite`. That flag enables the path only for controlled differential tests; there, a hidden TTY or same-repository cwd difference runs the revalidated command once uncached with inherited streams, while a different repository/non-Git cwd or remote executable/state mismatch can fail. It must never be installed as a production hook.

Explicit `again run` is local/default-environment only. Because it starts inside the actual tool shell context, it sees the effective cwd, streams, environment and executable resolution. If any standard stream is a TTY, it performs a single audited execution with inherited streams and no cache read/write.

The separately provisioned team-alpha command is `again team run --profile <absolute-private-profile> -- <bare argv...>`. It admits only portable `cat`/`head`/`tail`/`wc`/`grep`/`rg` forms, executes with exactly `LANG=C` and `LC_ALL=C`, and never builds a team key or contacts the service when any standard stream is a TTY. A remote hit is returned only after live request/runtime parity, fresh root-signed trust, revocation/allowlist checks, producer signature, ciphertext digest/size, AEAD authentication, and local privacy rescan. An authenticated exact-generation response is a miss only when no reusable candidate exists: absent/deleted, normally expired/not-yet-valid, or made unusable by current producer/record revocation or trust allowlists. Missing trust/blob state, quarantined or inconsistent metadata, generation changes, and malformed authenticated objects are hard failures rather than misses. Read-only misses and documented degraded transport paths execute locally once; corruption can never become a hit. See [`TEAM_ALPHA.md`](TEAM_ALPHA.md).

`again team inspect --profile <absolute-private-profile> --json -- <bare argv...>`
uses the same local admission to emit deterministic, secret-free request,
runtime, producer-public-key, and unsigned trust-requirement bindings. It does
not contact the service or execute the requested argv; it is an operator
bootstrap artifact, not a signed trust bundle or public onboarding flow.

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

Again stores exact stdout and stderr as immutable blobs, and every `again run` cache hit returns both complete streams. Before replay, every served hit starts the exact audited executable with fixed cheap capability-probe arguments. This confirms point-in-time exec authority but does not rerun the requested argv, eliminate all process spawn, or prove the requested work would succeed under transient global resource pressure.

`again reference -- <argv...>` is deliberately not transparent replay. It verifies the same live request, runtime, executable capability, stored proof, and both CAS blobs, then emits one bounded JSON reference containing the result id, status, BLAKE3 digests, and byte lengths. A miss never executes the requested command. The caller explicitly owns the context assertion: use a reference only when those complete bytes remain visible in the same active context, and use `again show <result-id>` or `again run` otherwise. The reference event records the actual positive byte difference between full streams and the reference; small outputs may save zero bytes.

Automatic output compaction is disabled because Codex hooks expose neither the effective output ceiling nor a delivery receipt, so Again cannot establish by itself that a previous complete stream was delivered.

The repository still contains a context-keyed delivery ledger and `PreCompact`/`PostCompact` handlers. They remain dormant future infrastructure and do not activate automatically. `again show` remains an explicit way to inspect stored exact bytes; it is not needed to reconstruct ordinary `again run` cache-hit output.

## Product stages

1. **Repository-aware agent gateway:** exact built-in repository reads/searches, concurrent in-flight joining, dependency-bound reuse, bounded MCP transport, explicit agent setup, and honest full-result delivery.
2. **Explicit local exact reads:** `again run`, conservative command parser, audited executable identity, scoped fingerprint, local SQLite/CAS, exact full-stream replay, explainability.
3. **Trace-backed local effects:** Linux rootless isolation, complete descendant/effect observation, COW execution, preconditioned effect replay, 100% initial shadow validation.
4. **Team reuse:** encrypted namespaced CAS, signed provenance, equivalent execution profiles, local verification, revocation, CI and policy.

## North-star and guardrails

North-star: measured end-to-end agent wait time eliminated on eligible repeated work.

Guardrails: known incorrect reuse count, shadow divergence count, miss overhead, explicit-CLI/cache-read-plus-probe latency, exact executable/OS/context-profile mismatches, exact full-stream equality, production-hook no-op violations, secret-tainted entry count, crash consistency, and user-visible refusal/no-store explanations.
