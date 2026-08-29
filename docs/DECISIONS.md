# Engineering decisions

This log records choices that affect Again's reuse boundary. A later optimization may replace a choice only with stronger evidence and a schema/profile version change.

## D-001 — Production hooks never rewrite automatically

The production Codex hook returns before reading or parsing stdin and emits no automatic `allow` or rewritten input, even for a command the direct policy could admit. Current `PreToolUse` reports the session `cwd` and supports `updatedInput`, but its Bash payload drops an `exec_command` call's effective per-call `workdir` and still hides TTY, shell/login, sandbox and remote-environment semantics. Transparent substitution therefore cannot be established from the session `cwd` plus `tool_input.command`. Explicit `again run -- <argv...>` is the production interface; an ineligible explicit call errors before execution, and the caller reruns the original argv unchanged outside Again.

## D-002 — Trust executable identity, not `PATH` names

The macOS `strict-read-v0.5` profile accepts exact Apple system paths only when each tool's BLAKE3 and one exact reviewed `SystemVersion.plist` BLAKE3 match. The reviewed Apple profiles are `macos-15.6.1-24G90-read-v0` and `macos-26.5-25F71-read-v0`; their tool digests and semantic identities remain separate. Codex ripgrep additionally requires an exact reviewed bundle or standalone-package path shape, exact binary BLAKE3, and the same OS profile. Codesign identifier/team output is descriptive provenance metadata rather than strict signature or byte-authentication evidence. Unknown tool, package-layout, or OS updates fail closed until a new profile is reviewed. Explicit `again run -- cat ...` resolves a bare name from the actual tool-shell context and then validates that identity. Dormant hook plumbing requires `argv[0]` to already be an explicit absolute audited path, but that guard does not enable automatic rewriting. Executable identity and semantic profile are bound into the request key and proof.

## D-003 — Every ripgrep request fixes ignore and output-order inputs

Ripgrep may read parent, repository, global, or configured files and may emit path-dependent ordering. V0 leaves those ambient sources unmodeled. Every `rg` request, including one whose current operands are regular files, therefore requires both `--no-ignore` and `--sort=path`; this also closes a file-to-directory race between classification and fingerprinting. Any `RIPGREP_CONFIG_PATH` disables admission. Explicit recursive `.git` directories and symlink aliases to them are rejected.

## D-004 — Scoped observations replace whole-repository hashing

Each admitted command produces an explicit access plan: content paths, recursive trees, directory listings, or identity only. This cuts fingerprint work and avoids invalidation from unrelated edits. `.again` and volatile Git log/lock namespaces cannot be named as admitted operands; explicit recursive `.git` roots and aliases are also rejected. These observations are sampled and pathname based, so they do not close concurrent mutation or plan-to-use races.

## D-005 — First admission requires exact double execution

A successful miss is run twice immediately. Stdout, stderr, exit status, and post-execution input fingerprint must agree exactly before storage. This catches common nondeterminism but is validation evidence, not a replacement for a complete execution profile.

## D-006 — Automatic output compaction is disabled

Every `again run` miss and hit returns byte-exact full stdout and stderr. Codex hooks expose neither the effective output ceiling nor a delivery receipt, so a `PreToolUse` handler cannot establish that a previous complete stream was delivered. Automatic compact-reference emission is therefore disabled. Production returns before parsing `PreCompact`/`PostCompact`; the unsafe experimental parser treats those events as state-free no-ops. The context-keyed delivery ledger and clearing primitives remain dormant infrastructure for a future hook contract with a stable delivery receipt.

The separate `again reference -- <argv...>` command is allowed because it changes output only after an explicit caller choice. It repeats live request/runtime/executable/proof/blob validation, never executes on a miss, and emits a bounded content-addressed JSON reference. The caller—not Again—asserts that the complete bytes remain visible in the same active context. `again show <id>` remains explicit retrieval for stored results, and stats count only the positive full-stream bytes actually omitted by the smaller reference.

## D-007 — Per-workspace state stays outside the workspace

Without `AGAIN_HOME`, Unix state is disposable and lives at `${TMPDIR}/again-<euid>/workspaces/<BLAKE3(canonical-workspace-path)>`, with app-owned levels at mode `0700`. Keeping it external prevents first-run state creation from changing observable repository listings and recursive searches. `AGAIN_HOME` selects one exact persistent root; it must be absolute and outside the active workspace, its final component cannot be a symlink, and an existing root must already be an owned real directory with mode `0700`. Its canonical ancestors must be real directories owned by the current uid or root; group/world-writable ancestors require sticky protection. Static database/blob symlinks, foreign ownership, hard-linked fixed files, and insecure modes are rejected; fixed files use mode `0600` and directories use their required private modes. These pathname checks do not prevent same-user/root concurrent replacement races, and SQLite rows are not authenticated against a same-user writer. The source tree's checked-in `/.again` ignore is deliberately root-scoped legacy housekeeping, not an instruction to place state there or ignore nested `.again` directories.

## D-008 — Seatbelt is a capability, not a shipped claim

Again can compile a deterministic macOS Seatbelt profile with exact executable and scoped read permissions plus write/network/device/credential denials. On the development machine, `sandbox-exec` is available outside Codex but nested application is rejected inside Codex's existing workspace sandbox. The Codex v0 path therefore relies only on audited read-only executable semantics; arbitrary-command reuse waits for an enforceable trace/isolation profile.

## D-009 — Performance gates include fingerprint overhead

A current product benchmark must measure explicit CLI startup, fingerprint, lookup, the per-hit exact-executable capability-probe process, and full-stream presentation. `bench/direct_benchmark.py` exercises that path with all standard streams non-TTY, exact cold/warm/mutation comparisons, and a 3x speed gate only where the native baseline is at least 500 ms. The retained `2026-08-23-direct-net-current-v3.json` working-tree run satisfies that conditional gate for its recorded binary, host and 2 GiB sparse-file `grep` fixture; `2026-08-23-direct-v1.json` remains the prior clean-commit timing/exactness result. Savings accounting reports only positive producer-duration minus measured replay-wall-time, never the gross producer duration. Neither run is a general speed claim. `bench/reference_benchmark.py` separately gates the explicit lookup-only reference against exact full retrieval, mutation, event/counter, byte-reduction, and latency checks; it measures bytes, not tokenizer or model tokens. `bench/benchmark.py` and `bench/slow_gate.py` deliberately exercise the unsafe experimental hook and are regression harnesses, not product evidence. Trivial commands and first-run double validation may be slower. Automatic hook rewriting or inferred output compaction is not a current gate. Failing and superseded measurements stay in the evidence ledger.

## D-010 — Codex onboarding is an owned instruction skill

`again setup --codex` installs only `SKILL.md` plus an ownership manifest under the personal `$HOME/.agents/skills/again` scope by default or `<repo>/.agents/skills/again` with `--project`. It never installs hooks. Reinstall and removal proceed only while managed bytes and ownership state are intact; unowned files, partial state, symlinked paths, or user edits fail closed. Doctor reports both scopes and flags simultaneous personal/project installation as duplicate instructions.

## D-011 — Concurrent results converge or quarantine atomically

Local result compare/insert runs under an immediate SQLite transaction. Identical writers converge on one result; a same-key output/status disagreement quarantines the record and emits evidence in the same transaction. Cleanup is bounded and may delete only old unreferenced tracked blobs, stale opaque calls, and expired telemetry—not results, deliveries, quarantine evidence, or referenced blobs.

## D-012 — Shared records use signed, producer-bound manifests

Remote manifests sign a manual length-prefixed canonical encoding with Ed25519. Tenant, repository, request, policy, execution profile, platform/image, blob, lifetime, privacy, key-id, and producer bindings are verified before acceptance. A key id cannot be silently rebound to different key material or a different producer. This secures the protocol object. The undeployed Worker and sealed Rust v2 client are now connected to an explicit, manually provisioned team-alpha CLI; this is not a deployed or production team-cache claim.

## D-013 — Scoped observations bind a filesystem-object epoch

Scoped file, directory-member, and executable metadata includes device, inode, and nanosecond ctime in addition to visible metadata and content where applicable. In tested non-concurrent cases this detects a byte-for-byte replacement with restored mtime against a different object epoch. A content mutation can therefore invalidate a listing-only request even when listing output would be unchanged. It does not close mutation between validation and use; an immutable snapshot or descriptor-relative boundary remains necessary for that race.

## D-014 — Hidden Codex context disables automatic rewriting

Codex exposes a session `cwd` to `PreToolUse`, but not the effective per-call workdir used by `exec_command`; it also omits effective TTY, shell/login, sandbox, remote `environment_id`, and output-cap settings. Production automatic rewriting is therefore a true no-op until an official envelope exposes the semantics needed for transparent substitution. Dormant plumbing accepts only the audited top-level shape and a `tool_input` object containing only `command`, requires an explicit absolute audited executable, uses an opaque handoff, and retains runtime mismatch defenses. It is reachable only through the conspicuously named `--experimental-unsafe-rewrite` flag for controlled differential tests and must not be installed. None of those partial checks upgrades the hidden hook context into an active reuse path. Explicit `again run` observes the actual local/default tool-shell context and remains the MVP.

## D-015 — The direct policy requires explicit, deterministic operands

Only `pwd -P` is admitted, and `ls` requires `--color=never`. Both `grep` and `rg` require at least one explicit path operand. Every `rg`, including regular-file searches, additionally requires `--no-ignore --sort=path`; configured ripgrep and explicit recursive `.git` roots or aliases are refused. This narrower surface avoids silently depending on logical `PWD`, terminal color policy, stdin, ignore configuration, traversal order, or volatile Git internals.

## D-016 — Cache admission is bounded and stderr-free

Cold stdout and stderr are streamed live while bounded copies are captured. A reusable result requires exit zero, empty stderr, complete captures no larger than 16 MiB per stream, stable post-execution observations, and exact shadow agreement; every stored blob is likewise capped at 16 MiB. Empty stderr avoids claiming to reproduce cross-stream interleaving that was never recorded. Once the first execution's output is successfully presented, later validation, storage, event, or accounting failures preserve the child's status rather than replacing it with a cache error.

## D-017 — Inherited process semantics partition reuse

The cache key and proof bind a `strict-read-v0.5` runtime-context digest containing real/effective uid and gid, supplementary groups, supported macOS soft/hard resource limits, and current signal mask/disposition/flag state. A served hit then starts the exact audited executable with fixed harmless arguments and suppressed streams to check current exec authority. This child-process probe does not rerun the requested argv; it also means a hit is not a zero-process-spawn operation.

## D-018 — Point-in-time checks leave global and pathname races

The exact-executable probe cannot establish that the requested work would succeed under the same transient global resource availability, and those resources can change after the probe. Filesystem sampling still has plan-to-use and concurrent-mutation races. Custom `AGAIN_HOME` ancestor validation/root creation also remains pathname based and can be redirected by same-user/root concurrent replacement after validation. These are documented boundaries, not certified equivalence.

## D-019 — External-byte environment overrides refuse reuse

Hashing an environment value does not bind files that the value makes a loader, sanitizer, locale converter, terminal database, or timezone implementation read. V0 therefore refuses admission when any `DYLD_*`, `LD_*`, `Malloc*`, `MALLOC_*`, `{ASAN,LSAN,MSAN,TSAN,UBSAN}_OPTIONS`, `GCONV_PATH`, `LOCPATH`, `NLSPATH`, `PATH_LOCALE`, `TERMCAP`, `TERMINFO`, `TERMINFO_DIRS`, or `TZDIR` name is present.

## D-020 — Installability does not imply an audited reuse profile

Release artifacts may install and expose diagnostics on Linux or an unknown macOS profile, but reusable execution remains disabled there. macOS success-path E2Es run only when the host's exact OS profile and all audited Apple-tool bytes match; unknown-profile refusal has separate fail-closed unit coverage. Doctor reports the audited Apple profile or an unsupported code.

## D-021 — Explain reports persisted facts only

`again explain <id>` reads a stored, non-quarantined result, and `again explain` reads the latest persisted execution event. It does not infer or synthesize a reason for calls that failed or were refused before event creation.

## D-022 — Team bundles stream only after an object-identity fence

The two-request team lookup keeps the 16 MiB ciphertext limit but may not materialize ciphertext-sized JavaScript buffers in the Worker. A successful upload binds the R2-returned version, ETag, R2-verified SHA-256, size, storage key, and random blob incarnation into D1. Lookup obtains conditional R2 body streams, checks that metadata, and then runs one final D1 query binding the same repository generation, manifest, trust head, blob incarnations, and R2 identities. Only after that fence may the response stream begin. This follows the 128 MiB-per-isolate Workers limit, which is shared across concurrent requests, while retaining client-side BLAKE3, AEAD, signed-manifest, local privacy, and post-decryption trust verification as the plaintext-release authority. Lowering the output limit merely to accommodate buffering would narrow the product without fixing the architecture.

## D-023 — The product unit is a successful coding task

Again optimizes time and total cost per successful coding task, not cache-hit
percentage. Repository orientation, tool execution, context delivery,
validation, and cross-agent knowledge are one acceleration loop. Evaluation
freezes the agent/model, repository snapshot, task, limits, and outcome rubric,
then measures task wall time, provider calls, provider-reported tokens,
validation compute, and total metered cost. A byte count, hit, skipped process,
or model-generated relevance score cannot alone establish task savings or reuse
authority. Unknown dependencies execute normally, and a task-level improvement
cannot compensate for an incorrect hit, stale fact, or weaker validation
outcome.
