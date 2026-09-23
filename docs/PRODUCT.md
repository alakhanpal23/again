# Product contract

## Exact promise

> Again is a repository-aware execution memory and tool-call control plane for coding agents. It skips only work proven redundant, executes uncertain work, and returns the smallest useful verified observation.

This sentence is both the product pitch and the reuse boundary. The explicit path makes a narrow, policy-admitted set of local read-only commands fast while returning exact full streams. The default MCP path controls 13 built-in repository/Git intelligence tools and includes a crate-internal bounded transport for real upstream stdio providers. “Proven” means that the request and its declared repository, task, provider, schema, environment, authorization scope, executable, and dependency observations satisfy a versioned deterministic policy; matching text, provider annotations, or semantic similarity is never sufficient.

## Product outcome

> Again helps coding agents start with verified repository understanding, avoid
> repeating work, run only the validation that changed, and share exact
> execution knowledge across agents.

The product is optimized for lower time and lower total cost per successful
coding task, not for cache-hit percentage. The complete end-state user loop,
current implementation map, scorecard, and delivery order are frozen in
[the agent acceleration product](AGENT_ACCELERATION.md). That direction does
not upgrade an experimental subsystem or broaden any shipping claim below. The
profile-by-profile inventory of reads, code intelligence, validation, builds,
artifacts, mutations, and external actions is [the reuse surface](REUSE_SURFACE.md).
The latency-critical task experience and its proof gate are defined by the
[straight-to-code fast path](STRAIGHT_TO_CODE.md).

## Initial customer and job

The first customer is a technical individual using Codex or Claude locally on a repository where agents repeatedly search or inspect the same material. The initial job is to remove redundant repository-tool latency and repeated context without asking the developer to declare a build graph. The gateway gives agents a shared exact execution memory; the explicit CLI remains the conservative local path.

The first economic buyer is the same developer. The later buyer is an engineering-platform leader paying to remove redundant agent/CI computation across a team while retaining provenance and policy control.

## Onboarding contract

The packaged target is:

```bash
brew install again
again mcp setup --client codex --workspace "$(pwd -P)" --apply --with-skill
# Start a new Codex session; it can now invoke:
# Call the Again task.start MCP tool for a bounded shared edit brief.
# Or prepare verified source previews before a noninteractive Codex run:
again codex --workspace "$(pwd -P)" --task-id fix-calculator --task "Fix calculator addition" -- --ephemeral
# Claude Code print mode uses the same authenticated launch preparation:
again claude --workspace "$(pwd -P)" --task-id fix-calculator --task "Fix calculator addition" -- --output-format json
again run -- rg --no-ignore --sort=path needle src
# only if those exact complete bytes remain visible in this active context:
again reference -- rg --no-ignore --sort=path needle src
```

`--apply --with-skill` verifies the Codex MCP entry through the official client CLI and installs the instruction-only personal skill at `$HOME/.agents/skills/again` in one flow. `--inspect --with-skill` checks both. `again setup --codex --project` remains available for an explicitly project-scoped skill; scoped `--remove` reverses an unchanged owned install. The skill guides task start, shared context, verified repository tools, explicit `again run --`, and context-safe `again reference --`. It does not install hooks. `again doctor` reports both skill scopes and duplicate installation.

`again codex` starts or joins the authenticated workspace daemon, registers the exact durable task, and supplies up to two complete source previews and bounded current shared findings before calling `codex exec`. It preserves Codex's normal user configuration and approval policy, pins the Again MCP connection for this invocation, and forwards explicit Codex flags after `--`. An elected launcher holds and renews the leader lease for the process lifetime. A follower waits up to 30 seconds by default; if the leader exits, it claims the task and refreshes source and context before launching Codex. Use `--peer-wait-seconds 0` to launch a collaborating follower immediately, or set a bounded wait up to 300 seconds. A still-active peer is reported in the follower brief. Blocked dependencies and terminal tasks stop the launch. `again mcp brief --workspace <path> --task-id <id> --task <text>` prints a preview without claiming a lease for other launchers. Keep task text free of secrets. These commands require a daemon-enabled Unix build and an installed Codex CLI; this launch path has local diagnostic evidence but is not yet a qualified default workflow.

`again claude` uses the same brief, peer wait, and lease lifecycle for Claude Code's noninteractive print mode. It passes a workspace-bound Again MCP server through Claude Code's documented [`--mcp-config`](https://code.claude.com/docs/en/cli-reference) flag and forwards explicit Claude flags after `--`. The local release gate checks the generated arguments with a fake Claude executable; no Claude Code binary is installed on this host, so a live Claude task and token result remain unverified.

The explicit `again run` path requires no Again account, sign-in, API key, daemon, Docker, privileged helper, repository file, Codex hook installation, or telemetry. MCP context and prebrief use the authenticated local daemon.

The MCP onboarding path is explicit and workspace-bound:

```bash
again mcp setup --client codex --workspace /canonical/repository
again mcp setup --client claude --workspace /canonical/repository
```

Both commands are dry runs unless `--apply` is supplied. Apply uses the official client CLI, verifies the exact installed entry, and refuses a conflicting entry. The generated server argv contains the exact canonical repository path. The gateway uses bounded concurrent stdio, serializes complete responses, propagates cancellation to the matching physical attempt, and fails closed on malformed or oversized JSON-RPC.

Current gateway limits are part of the product truth: same-user daemon sessions have authenticated task-scoped full retrieval and write/flush-confirmed compact context delivery, but production or cross-user recipient issuance is absent. There is no CLI configuration path for arbitrary upstream MCP servers, semantic reuse, live task-quality qualification, or production Linux command backend. Unknown or incomplete state executes normally when doing so preserves the closed provider semantics; configuration that could make a nominally read-only Git query execute a filter or external diff command is instead refused before Git starts. External Git includes/ignore/attribute files and nested worktree/submodule state never authorize reuse. Mutating, freshness-bound, network, credential, communication, deployment, payment, and unknown tools are not reused; sensitive or unknown classes bypass storage entirely.

The retained [exact gateway checkpoint](../bench/results/2026-08-27-agent-gateway-product-e2e-release-v3.json) at `850e7c4398adc25ef1210ee4260e27b29aaeb753` passed eight scenarios through four actual Again MCP processes with 12 provider executions and zero false hits. Its exact event windows contain two exact reuse hits and one joined in-flight call, for three avoided provider executions. The newer [authenticated product lifecycle gate](../bench/results/2026-09-23-auth-product-e2e-indexed-validation-hint-v1.json) passed at `eb12c17fa027556e88ce6f56cf6c9a7cf1dbf2ba`, including two-client task/source sharing, invalidation, cancellation, corruption refusal, and lease recovery. These gates cover different scenario sets; neither proves a product-wide task-speed gain.

The [four-platform native beta matrix](../bench/results/2026-09-23-native-beta-matrix-56d9d3e-summary.json) passed at `56d9d3e4e2e1f0b349ab126d422a617b04dd1658`. Each daemon-enabled archive was installed, started, exercised through authenticated MCP, checked for its tool catalog and client setup plans, and removed. The archives are retained in [GitHub Actions run 35919913635](https://github.com/alakhanpal23/again/actions/runs/35919913635); no release has been published.

The same release bytes passed the retained [onboarding smoke](../bench/results/2026-08-27-agent-gateway-onboarding-smoke-v2.json) and [quick chaos run](../bench/results/2026-08-27-agent-gateway-chaos-soak-v3.json). Onboarding exercised isolated Codex/Claude installation, owned reinstall/removal, unowned and symlink refusal, exact workspace binding, real MCP startup, both built-ins, mutation invalidation, and descendant cleanup without reading real user credentials or configuration. Chaos reconciled all eight product scenarios, 16 extra exact calls over two sessions, zero false hits, six absent owned process groups, unchanged open-descriptor count, and absent temporary state. These are local release-binary facts, not hostile-binary network-sandbox or general performance evidence.

The earlier [real-repository report](../bench/results/2026-08-27-agent-gateway-real-repository-partial-v2.json) correctly remained a typed `non_pass` when no Go repository was supplied. The [four-language report](../bench/results/2026-08-28-agent-gateway-real-repository-four-language-private-release-v1.json) passes explicit clean Rust, Python, Go, and TypeScript repositories with zero false hits; the harness never clones, downloads, or executes source-repository code. Local live Codex edits now have retained paired events and usage on [calculator](../bench/results/2026-09-23-codex-pair-product-wrapper-guided-baseline-first-v1.json) and [running balance](../bench/results/2026-09-23-codex-running-balance-wrapper-baseline-first-v1.json), plus [two-agent runs in both orders](../bench/results/2026-09-23-codex-parallel-running-balance-baseline-first-v1.json). Those tasks passed their exact patch oracles and often reduced first-edit time, calls, and input tokens; parallel completion time was mixed. The original 16-run read-only real-agent harness remains unexecuted, and no representative editable cohort or metered total-cost qualification exists. A live Claude Code task remains unverified on this host. Production and cross-user MCP recipient issuance remain absent. The local daemon supports recipient-scoped retrieval and delivery-confirmed compact context, while the live input-token differences cannot yet be attributed specifically to compact delivery.

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

The macOS-compatible `strict-read-v0.5` slice admits only strictly parsed read-only `again run` invocations from a small allowlist and verifies executable identity. It may resolve a bare audited name such as `cat`, but admission requires the exact reviewed Apple-tool BLAKE3 and exact reviewed `SystemVersion.plist` BLAKE3 for either `macos-15.6.1-24G90-read-v0` or `macos-26.5-25F71-read-v0`. Codex `rg` requires an exact reviewed BLAKE3 and package path shape under that OS profile; the reviewed layouts are the original bundle and standalone Codex `0.150.1`. Codesign identifier/team fields are descriptive metadata, not strict signature or byte-integrity evidence. Unknown binary, layout, or OS updates fail closed. Linux and unknown macOS packages may install, but reuse remains disabled until an audited backend/profile exists; doctor reports audited or unsupported status. Dormant hook plumbing additionally requires `argv[0]` to be an explicit absolute audited executable, but no automatic hook invocation is currently admitted.

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

1. **Repository-aware agent gateway:** exact built-in repository/Git intelligence, concurrent in-flight joining, dependency-bound reuse, bounded MCP transport, explicit agent setup, and honest full-result delivery.
2. **Explicit local exact reads:** `again run`, conservative command parser, audited executable identity, scoped fingerprint, local SQLite/CAS, exact full-stream replay, explainability.
3. **Trace-backed local effects:** Linux rootless isolation, complete descendant/effect observation, COW execution, preconditioned effect replay, 100% initial shadow validation.
4. **Team reuse:** encrypted namespaced CAS, signed provenance, equivalent execution profiles, local verification, revocation, CI and policy.

## North-star and guardrails

North-star: measured end-to-end time and total cost eliminated per successful
coding task while preserving its fixed outcome rubric.

Guardrails: known incorrect reuse count, shadow divergence count, miss overhead, explicit-CLI/cache-read-plus-probe latency, exact executable/OS/context-profile mismatches, exact full-stream equality, production-hook no-op violations, secret-tainted entry count, crash consistency, and user-visible refusal/no-store explanations.
