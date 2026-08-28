# Again

Again is a repository-aware execution memory and tool-call control plane for coding agents. It skips only work proven redundant, executes uncertain work, and returns the smallest useful verified observation. The stable local engine currently applies that rule to a deliberately narrow set of explicit read-only commands; an experimental MCP gateway applies it to bounded repository and Git intelligence.

```bash
# Redirect all three standard streams so this terminal demonstration is non-TTY.
again run -- rg --no-ignore --sort=path -n "EffectIR" src \
  </dev/null > /tmp/again-first.out 2> /tmp/again-first.err
again run -- rg --no-ignore --sort=path -n "EffectIR" src \
  </dev/null > /tmp/again-second.out 2> /tmp/again-second.err
cmp /tmp/again-first.out /tmp/again-second.out
cmp /tmp/again-first.err /tmp/again-second.err
```

The second eligible invocation can be a cache hit and still returns the same complete streams. An agent that already has those complete bytes in its active context may instead explicitly request a compact, content-addressed proof with `again reference -- <same argv...>`; that command never executes on a miss. If any standard stream is a TTY, as in a normal interactive terminal invocation, `again run` instead executes the audited command once uncached with inherited streams. The current repository is an early conservative implementation; arbitrary commands are not safe to cache.

## Experimental agent gateway

`again mcp serve` exposes 13 bounded read-only tools over MCP stdio: `repo.read`, `repo.search`, `repo.list`, `repo.tree`, `repo.stat`, `repo.glob`, `repo.references`, `repo.manifest`, plus `git.status`, `git.diff`, `git.log`, `git.show`, and `git.blame`. Exact repository, task, provider, schema, environment, authorization-scope, dependency, and executable bindings control reuse. Concurrent identical calls can join one in-flight execution; later exact calls can reuse its verified result. Relevant repository changes invalidate it. Unknown state and every mutation, credential operation, communication, deployment, payment, or unknown tool bypasses storage and replay.

```bash
repo_root="$(pwd -P)"
again mcp setup --client codex --workspace "$repo_root"
# Review the printed command, then add it using the agent's own configuration flow.
```

Setup is a dry run by default and emits a command containing the exact canonical workspace. `--install-owned-config ABSOLUTE_PATH` may create a wholly Again-owned, previously absent configuration and ownership record; it never merges into or overwrites an existing user-managed file. A bounded real-upstream stdio transport and conservative universal tool policy now exist behind crate APIs, including process-tree cancellation and ephemeral credential borrowing, but arbitrary upstream registration is not exposed by the CLI. Semantic similarity creates no reuse authority, compact cross-agent delivery is disabled, and no Linux command-execution backend is exposed.

The schema-v10 release-binary checkpoint at source `850e7c4398adc25ef1210ee4260e27b29aaeb753` passed all eight bounded product scenarios through four real MCP stdio processes: concurrent execution/join, later exact reuse, relevant and proven-irrelevant mutations, follower and leader cancellation, real 30-second lease recovery after process death, and copied-CAS corruption refusal. It observed 12 provider executions and zero false hits. The scenario windows show three avoided provider executions: two exact reuses and one joined follower. Acquisition candidates are not counted as hits; promotion occurs only after proof consumption, result loading, and repository revalidation. See the [release E2E report](bench/results/2026-08-27-agent-gateway-product-e2e-release-v3.json), bound to release binary SHA-256 `e52e7540c3754038db3fbc87bc0039df1b6e983b124497d4f3559708c5a536f0` and file SHA-256 `9b818771f830395d2b123e83437b290ea470b284bcef0f52ce1576edbd82ce08`.

The same release bytes passed the [isolated onboarding smoke](bench/results/2026-08-27-agent-gateway-onboarding-smoke-v2.json) and [quick chaos checkpoint](bench/results/2026-08-27-agent-gateway-chaos-soak-v3.json). Chaos independently reconciled all eight scenarios, converged 16 exact calls from two sessions on one result, found zero false hits, and observed no owned process-group, descriptor, or temporary-state leak. A fresh [three-language real-repository run](bench/results/2026-08-27-agent-gateway-real-repository-partial-v2.json) passed Rust, Python, and TypeScript but is deliberately `non_pass` overall because the bounded offline search found no eligible local Go repository. The versioned alpha-trial verifier is ready, but no outside-user evidence exists; a local simulation cannot close that gate. The [real-agent report](bench/results/2026-08-27-agent-gateway-real-agent-dry-run-v2.json) is only an offline plan: no paid/model call ran and all 16 live paired runs remain. Schema v10 adds dormant receipt/grant storage without turning caller identity, write completion, result IDs, or content hashes into delivery authority. Production MCP still returns full results, so delivery-confirmed byte/token savings remain zero. None of these reports establishes model quality, hostile-binary network isolation, or production qualification.

## Product promise

On a validated cache hit for an eligible explicit `again run -- <argv...>` call, Again returns the stored successful stdout, stderr, and status without rerunning the requested argv. Every served hit first launches the exact audited executable once with fixed cheap capability-probe arguments; it therefore is not a zero-process-spawn path. Every `again run` hit returns the complete streams. A miss streams the first execution's output live; only a result that passes the initial admission checks is executed a second time before storage. Reusable admission requires exit status zero, empty stderr, identical validation runs, stable post-execution fingerprints, and stdout/stderr within the 16 MiB per-stream capture limit. Any local blob is also capped at 16 MiB. Once the child's output has been successfully presented, later validation, admission, or accounting failures preserve the child's status. This is faster for sufficiently expensive repeats; trivial utilities can still be slower because fingerprinting, the capability probe, and process startup have real costs. An ineligible explicit call errors without executing the command and tells the caller to rerun the original command unchanged.

`again reference -- <argv...>` is a separate, explicit token-reduction operation. It performs the same admission, fingerprint, runtime, executable-capability, stored-proof, and blob-integrity checks, then emits one deterministic JSON line containing the result id, stream BLAKE3 digests, byte lengths, and status. It never executes or stores the requested command: a miss exits with an error stating that no command ran. Use it only when the exact full result remains visible in the same active agent context; after compaction, across agents, or whenever the bytes are needed, use `again run` or `again show <result-id>`. Automatic compact references remain disabled.

Again never treats a matching command string or basename as sufficient. `again run -- cat ...` resolves and validates the executable from the wrapper's actual local context. Active policy `strict-read-v0.5` admits only the exact reviewed BLAKE3 of each Apple tool at its fixed system path plus the exact BLAKE3 of `/System/Library/CoreServices/SystemVersion.plist`. The Codex-bundled `rg` requires its exact canonical bundle path shape, reviewed binary BLAKE3, and the same OS profile. Codesign-reported identifier/team fields are checked only as descriptive publisher metadata; strict signature validity is not claimed, and the exact BLAKE3 is the byte-integrity boundary. The current semantic profiles are `macos-15.6.1-24G90-read-v0` and, for ripgrep, `codex-rg-15.2.0-e89fff89ac-arm64-read-v0`; any unreviewed OS or binary update fails closed. Packages may install on Linux or an unknown macOS profile, but reuse remains disabled until that platform/backend is audited; `again doctor` reports either the audited Apple profile or an unsupported code. The narrow command surface includes `cat`, `head`, `tail`, `wc`, `grep`, `ls --color=never`, only `pwd -P`, and `rg`. Every `grep` and `rg` invocation requires an explicit path operand. Every `rg` invocation, including an explicit regular-file search, also requires both `--no-ignore` and `--sort=path`; `RIPGREP_CONFIG_PATH` disables admission, and explicit recursive `.git` directories or aliases to them are rejected. Git commands, network access, writes, shell composition, time, randomness, unsupported paths, unknown flags, incomplete observation, and non-zero results are not cached as reusable results.

Cache keys and stored proofs also bind a macOS runtime-context digest: real/effective uid and gid, supplementary groups, supported soft/hard resource limits, and the current signal mask, dispositions, and flags. A changed context produces a miss rather than reusing a result from different inherited process semantics.

V0 refuses admission when the environment contains any `DYLD_*`, `LD_*`, `Malloc*`, `MALLOC_*`, `{ASAN,LSAN,MSAN,TSAN,UBSAN}_OPTIONS`, `GCONV_PATH`, `LOCPATH`, `NLSPATH`, `PATH_LOCALE`, `TERMCAP`, `TERMINFO`, `TERMINFO_DIRS`, or `TZDIR` variable. Those variables can redirect loaders, instrumentation, locale, terminal, or timezone lookups to external bytes outside the scoped fingerprint; hashing only their text would not bind those bytes.

Automatic Codex `PreToolUse` rewriting is disabled: the production hook returns before reading or parsing stdin and emits no allow decision. Current hooks can rewrite tool input and report the session `cwd`, but Bash input still contains only `tool_input.command`; an `exec_command` call's effective per-call `workdir`, TTY, shell/login, sandbox, remote `environment_id`, output ceiling, and delivery receipt are absent. Transparent substitution therefore cannot preserve all hidden semantics. The repository retains strict envelope parsing, an explicit-absolute-executable guard, opaque handoff, defensive runtime checks, `PreCompact`/`PostCompact` handlers, and a delivery ledger as dormant/test plumbing behind the explicit unsafe test flag. If that dormant wrapper is exercised directly, a hidden TTY or same-repository cwd difference executes the revalidated command once uncached with inherited streams; a different repository/non-Git cwd or remote executable/state mismatch can fail. None is an active acceleration or output-compaction path. Explicit `again run` is local/default-environment only and starts inside the tool shell's actual cwd, streams, and environment; if any stream is a TTY, the audited command executes once uncached with inherited streams.

Local v0 does not classify credentials or secret-tainted output. Admitted path operands and validation metadata may be persisted, and successful stdout/stderr may remain in the local CAS; the experimental opaque-hook path also persists raw command text and argv while a call is pending. Do not place credentials in eligible command arguments or use Again on secret-bearing output until secret classification ships. The undeployed remote service rejects records already marked secret-tainted, but it cannot infer that label for the local engine.

## First user

The beachhead is an individual Codex or Claude user working in a medium or large local repository where agents repeatedly read and search the same state. The experimental gateway removes duplicate provider calls without asking every agent to remember prior commands; the stable explicit path remains `again run --`, with `again reference --` available only when the complete bytes remain visible. Test/build reuse and transparent interception are later profiles and do not ship until their semantics are observable and their isolation/differential gates pass.

## Install during development

```bash
cargo install --path .
again setup --codex
# Optional experimental MCP gateway dry run for the current canonical repository:
again mcp setup --client codex --workspace "$(pwd -P)"
# Start a new Codex session, then Codex can use:
again run -- cat path/to/file
# For the same call only when its full bytes are still visible:
again reference -- cat path/to/file
```

`again setup --codex` installs a reversible instruction-only skill at `$HOME/.agents/skills/again` by default. Use `again setup --codex --project` for `<repo>/.agents/skills/again`, and use the same scope with `--remove` to remove files still matching Again's ownership record. Setup does not install or modify hooks. `again doctor` reports both skill scopes and warns when both are installed.

No Again account, OAuth flow, API key, daemon, Docker, root permission, task graph, hook installation, or telemetry is required for local mode. On Unix, disposable state defaults to `${TMPDIR}/again-<euid>/workspaces/<BLAKE3(canonical-workspace-path)>`, with app-owned directory levels at mode `0700`; the first run never mutates the workspace. `AGAIN_HOME` selects one exact persistent root and must be absolute and outside the active workspace. Its final component cannot be a symlink, and an existing root must already be an owned real directory with mode `0700`. Every canonical ancestor must be a real directory owned by the current uid or root; a group/world-writable ancestor must have the sticky bit. Fixed state files, directories, blobs, and the state-root `.gitignore` must satisfy the documented ownership, type, link-count, symlink, and private-mode checks; unsafe state causes an error. Resolution and creation remain pathname-based and can still be raced by the same user or root. This repository's checked-in `/.again` ignore is root-scoped legacy housekeeping; it neither places current state in the workspace nor ignores nested user directories.

An opt-in encrypted team-alpha path now exists for a manually provisioned private profile:

```bash
again team run --profile /absolute/private/profile.json -- wc -c README.md
again team inspect --profile /absolute/private/profile.json --json -- cat README.md
```

It supports a narrower portable `cat`/`head`/`tail`/`wc`/`grep`/`rg` subset, exact cleared locale environment, TTY bypass, profile-specific runtime attestation, signed fresh trust, encrypted manifests, immutable double capture, local privacy scanning, and verified remote plaintext. Every profile-controlled credential/checkpoint path must be external to the repository. The service is not deployed and there is no public profile/key bootstrap, so this is not yet a publicly usable team product. A bounded CI wrapper and composite action exist for credentials that an operator has already provisioned; they do not deploy or onboard the service. See [the team-alpha contract](docs/TEAM_ALPHA.md) and [CI boundary](docs/TEAM_CI.md).

The two-request `bundle_v1` Worker route, Rust client lifecycle, and a manual two-client public-CA HTTPS lifecycle are implemented and locally exercised. The protocol remains manually selectable only for controlled tests and is unshipped: the retained 100-repetition 50 ms benchmark misses the 40% gate at 16 MiB, an actual TCP reset does not cancel indefinitely pending readers, and the full matrix, direct proof of current Worker-isolate heap usage, 100,000-case stateful D1/R2 path, and a cross-layer post-decrypt revocation race are still absent. Provisioned alpha and CI examples therefore remain pinned to the five-request `legacy_v2` path. See [the bundle-v1 status and evidence](docs/TEAM_LOOKUP_BUNDLE_V1.md).

`team inspect` is the offline bootstrap view of the exact same admitted request
used by `team run`. It never constructs a remote client or executes the requested
argv. It emits deterministic, secret-free JSON containing the scoped request and
runtime digests, producer public identity, and unsigned trust requirements. It
requires a publisher profile so the real producer public key can be derived;
tokens, repository keys, signing secrets, paths, environment plaintext, times,
epochs, and signatures are never emitted. A first or stale runtime audit may run
the fixed system signature verifier, but never the requested command.

## Commands

```text
again run -- <argv...>    Run through the conservative local engine
again reference -- <argv...>
                          Verify an existing hit and emit a compact JSON reference; never execute on miss
again team run --profile <absolute-profile> -- <bare argv...>
                          Use the manually provisioned encrypted team alpha
again team inspect --profile <absolute-profile> --json -- <bare argv...>
                          Print its offline, unsigned trust bootstrap bindings
again mcp serve --workspace <canonical-repository>
                          Serve experimental bounded repository tools over MCP stdio
again mcp setup --client <codex|claude> --workspace <canonical-repository>
                          Print an ownership-checked, dry-run agent configuration
again setup --codex       Install the instruction-only personal Codex skill
again setup --codex --project
                          Install the skill in the current repository
again hook                Production no-op; unsafe parser requires a test flag
again exec --call <id>    Experimental opaque-call plumbing for hook tests
again explain [id]        Show a stored result or the latest recorded event
again show <result-id>    Retrieve exact stored stdout/stderr
again stats               Show local execution and replay counters
again doctor              Verify state, skill scopes, and safety capabilities
```

`again hook --experimental-unsafe-rewrite` exists only for controlled differential tests. It can change hidden Codex invocation semantics and must not be installed or used as a production integration.

`again explain <id>` reads a stored, non-quarantined result; without an id it reports only the latest event that was actually recorded. It does not reconstruct or invent an explanation for a refusal or failure that occurred before event persistence.

See [current status](docs/STATUS.md), [the product contract](docs/PRODUCT.md), [architecture](docs/ARCHITECTURE.md), [engineering decisions](docs/DECISIONS.md), [roadmap](docs/ROADMAP.md), [development workstreams](docs/DEVELOPMENT_WORKSTREAMS.md), and [security model](SECURITY.md).

## Open source and business

The current local policy engine, EffectIR schema, cache, validation, explainability, and Codex integration stay open source; the planned local tracer and effect-replay machinery will as well. The repository also contains an undeployed, locally tested shared-cache service and an opt-in CLI that recomputes request bindings, consumes root-signed fresh trust, and verifies/decrypts encrypted remote records for manually provisioned profiles. No authenticated public control plane provisions that state and no production endpoint exists. A future paid team product may provide managed shared cache, equivalent remote execution, policy and audit controls, application-layer confidentiality, provenance, analytics, support, and verified compute-savings reporting. Clients still validate every remote record locally.

## Status

Pre-alpha. Scoped validation is sampled and path-based; concurrent mutation after validation, transient global-resource changes around the capability probe, same-user/root pathname races, and unauthenticated same-user metadata-store writes remain outside the current boundary. Do not depend on Again for correctness-sensitive workloads until those limits are closed and the documented gates are green. Unknown means Again refuses the call; the caller must rerun the original unchanged.

## License

Apache-2.0.
