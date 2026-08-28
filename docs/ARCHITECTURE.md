# Architecture

## Architectural rules

Again treats reuse as an authority transition, not a cache lookup. These rules
apply across the local, Linux trace-backed, and team paths:

1. **Unknown is not equivalent.** An unmodeled input, effect, platform, runtime,
   transport state, or cleanup result refuses or becomes execute-only.
2. **Bytes do not create authority.** Parsed JSON, decoded kernel frames,
   structurally valid EffectIR, digests, and test fixtures are evidence inputs;
   they cannot mint execution, candidate, promotion, or replay authority.
3. **Authority capabilities move linearly.** Stopped-task permits, exchange
   tokens, completion evidence, and hit permits are non-copyable and consumed
   by one next transition. A sealed immutable snapshot may be duplicated only
   through its private identity-preserving descriptor-clone path; every copy
   remains bound to the same manifest and identity.
4. **Execution and reuse are separate decisions.** A safely completed workload
   may return exact foreground output while remaining permanently ineligible for
   a candidate or hit.
5. **Cleanup is part of correctness.** Terminal reap, final `ECHILD`, signal and
   descriptor restoration, mount/branch cleanup, and durable publication are
   required evidence, not best-effort afterthoughts.
6. **Remote state cannot upgrade local safety.** A valid remote signature or
   ciphertext never compensates for a missing local execution profile,
   observation, precondition, or capability proof.
7. **Claims follow retained evidence.** Pure tests prove pure logic; a fixed
   diagnostic proves only its fixed transcript; product and performance claims
   require their distinct end-to-end gates.

## Current system map

| Plane | Current implementation | Missing authority/product step |
|---|---|---|
| Agent tool-call gateway | Experimental bounded MCP stdio server with canonical tool translation, descriptor-retained repository authority, 13 built-in repository/Git tools, SQLite/CAS coordination, post-proof exact reuse/in-flight joining, bounded queues, session cancellation, crash recovery, corruption quarantine, workspace-bound setup, a conservative universal tool policy, Git external-dependency/nested-control refusal and executable-configuration preflight, a bounded crate-internal real-upstream stdio transport, additive schema-v10 receipt/grant storage, verified shared-reasoning read models, a crate-internal write-and-flush-bound reasoning delivery composition, durable envelope-deduplicated metrics verification, release-binary product/onboarding/chaos evidence, a partial real-repository corpus, an outside-trial verifier, and an offline real-agent plan | CLI registration for allowlisted upstream providers, transport-authenticated recipient issuance, recipient-bound full retrieval and exact compact-presentation receipts on the public MCP path, deterministic semantic-candidate validation, a complete four-language real-repository corpus, five-user outside evidence, live Codex/Claude task-quality evaluation, and production qualification |
| Explicit local reads | Working macOS MVP with strict policy, exact executable/profile checks, SQLite/CAS, double-run admission, complete-stream replay, explicit references, and reversible Codex skill | audited multi-host profile registry, signed distribution, and outside-alpha evidence |
| Linux snapshots | Descriptor-stable enumeration, charged materialization, canonical workspace/runtime-tree publication, reopened-child binding, a descriptor-bound `.venv/bin/python` checkpoint, and a bounded two-publication structural runtime inventory exist internally | model complete loader search/cache/preload/hwcaps semantics, content-addressed snapshot identity, live connector composition, and `SnapshotProvider` |
| Linux isolation | Private-root, bounded scratch/procfs, descriptor scrub, credential normalization, capability elimination, authenticated child-only continuation, Landlock, terminal seccomp, and fixed ptrace diagnostics exist as hidden leaves; a command-free connector now consumes the real runtime checkpoint, attaches and reauthenticates both published roots, transfers the exact stopped child and its cleanup guard through `PTRACE_SEIZE`/`PTRACE_INTERRUPT` to an opaque supervisor owner, and preserves terminate/reap-before-drain cancellation | install and read back the workload filter on that same held child, add a fixed one-use command release, supervise the complete task tree, and deliver foreground results in a provisioned launch |
| Linux tracing | Strict decoders, trace-all filter, lifecycle recorder, branded pure supervisor planner, and a hidden fixed two-task kernel connector with options/filter witnesses, bounded private-range `clone3` capture, full reap, final `ECHILD`, and consuming cleanup exist | connector-wide fault injection, pinned 100/100 kernel evidence, semantic recorder, execute-only composition, and execution authority |
| Linux EffectIR/reuse | Canonical EffectIR v2, comparison, promotion, manifest, and wire/storage contracts have substantial pure coverage | live semantic trace construction, complete candidate finalization, shadow dispatcher, fresh hit validation, and replay |
| Team reuse | Encrypted v2 manifests, signed trust/provenance, strict Rust clients, Worker/D1/R2 boundary, team CLI, and CI wrapper exist for manual provisioning | deployed service, onboarding/control plane, production operations/security evidence, equivalent-profile cross-machine proof, and design-partner validation |

The status of each row is normative only through [STATUS.md](STATUS.md). The
phase ordering and exit gates are in [ROADMAP.md](ROADMAP.md).

## Experimental gateway authority chain

```text
MCP JSON-RPC frame
  -> bounded canonical GatewayToolCallV1
  -> descriptor-retained WorkspaceExecutionEpochV1
  -> repository/task/environment dependency binding
  -> store-issued exact candidate or in-flight lease
  -> one-use route proof consumption
  -> provider execution when proof is absent or stale
  -> exact result load and repository revalidation
  -> served-hit/join accounting only after those checks
  -> full bounded MCP result
```

The content address is identity, not authorization. The authorization scope is
bound into the request, and the current server does not expose retrieval by
result ID. AI or embedding systems may suggest work for deterministic checking
in a future layer, but cannot issue an exact-hit, join, replay, or delivery
permit.

Schema v10 adds new receipt, retrieval-grant, and compact-savings tables without
reinterpreting legacy rows. This is structural groundwork, not a production
delivery channel. Normal stdio sessions have unknown recipient identity, and
the authenticated recipient issuer and route remain test-only. Receipts
therefore cannot authorize retrieval or compact output, and compact
bytes/tokens/time remain zero and unclaimed. The phase-two commit failed the
all-target build in isolation; its later retrieval commit made the candidate
branch green but still supplied authenticated recipients only under `cfg(test)`.
Those response-bound types remain off main; production continues to send the
complete bounded MCP result.

## Target Linux authority chain

```text
AdmissionInput
  -> PytestAdmissionDraft                  lexical evidence only
  -> SealedSnapshot                        descriptor-backed snapshot authority
  -> PreparedPytest                        resolved invocation + sealed inputs
  -> PreparedExecutionSession              isolated branch, stdio, PID 1
  -> PreExecStoppedTask
     + InstalledFilterWitness
     + PtraceOptionsWitness
  -> KernelTracerSession                   only kernel connector can issue
  -> planner intents <-> exact kernel operations
     + semantic EffectIR recorder
  -> ConnectorExecutionOutcome
       |- CleanupIncompleteFailure         typed failure/report; stop
       |- ExecutedOnlyCleanupToken         immutable executed-only record; stop
       `- ExecutionCompletionToken
          + retained PreparedPytest
          -> candidate eligibility finalizer
          -> {immutable primary candidate, retained PreparedPytest}
          -> ShadowEnvelopeV2
          -> independent shadow candidate
  -> separate promotion comparison row
  -> freshly revalidated hit token
  -> exact replay / transactional effect commit
```

The chain may stop safely at refusal or execute-only, but no arrow may be
skipped. The intended ownership is:

- `ProfileAdmission::parse_lexical` produces only a draft. It cannot resolve
  selectors or create filesystem/execution authority.
- A concrete `SnapshotProvider` must consume the existing connector checkpoint
  only after source qualification, full workspace/runtime manifest construction,
  content-addressed durable publication, and descriptor capability binding.
- `finalize_against_snapshot` creates `PreparedPytest` by resolving the exact
  selectors and executable chain against the sealed snapshot.
- One private Linux execution connector temporarily consumes `PreparedPytest`,
  owns branch creation, namespaces, stdio, filters, tracee launch, kernel
  tracing, semantic recording, result capture, final root, and cleanup, then
  returns that same live capability with a candidate-capable outcome. There is
  no public generic sandbox/tracer trait that lets crate siblings substitute
  evidence or reconstruct prepared authority from paths or identity bytes.
- Exact installed-filter and ptrace-options witnesses unlock the currently pure
  supervisor planner. A decoded frame or synthetic token cannot unlock it.
- Every planner exchange is bound to the exact connector session, TID, stop
  generation, operation, and buffer shape. The connector confirms success only
  after the corresponding kernel call succeeds.
- A `clone3` stopped-memory read additionally requires proof that every traced
  task sharing the address space is stopped or absent, no untraced sibling can
  mutate it, and the range is not externally mutable/shared. Without that
  witness, the connector must not resume from the capture: it kills and drains
  the tree and fails closed. An execute-only record may describe the failure
  only after cleanup.
- `ExecutionCompletionToken` is non-`Clone`, non-serializable, and connector-
  issued only after no exchange or pending task relation remains, the lifecycle
  recorder completes, every task exits and is reaped, a later wait returns
  `ECHILD`, semantic and final-root state finalize, streams/status are complete,
  and signal/descriptor/mount/branch cleanup succeeds.
- `ExecutedOnlyCleanupToken` is issued only when the connector can prove the
  same full cleanup boundary for a safely completed or deliberately terminated
  non-candidate run. It can bind an immutable executed-only record but can never
  create a candidate. A cleanup-incomplete or fatal connector outcome mints no
  cleanup token and no candidate authority; any retained diagnostic must state
  that narrower evidence explicitly.
- `VerifiedExecutionRecordV2` must ultimately be constructible only through a
  private finalizer that consumes one of those connector outcomes. Its current
  structural binding surface is foundation code and must be narrowed before a
  concrete profile is connected.
- A verified primary finalizer must return the still-live `PreparedPytest`
  beside the immutable candidate so `ShadowEnvelopeV2` can consume the same
  sealed authority. The shadow may not recreate it from serializable identity
  or host paths.
- A candidate is immutable and grants no hit. Promotion stores a separate row
  referencing two distinct complete candidates with byte-equal semantic views.
- A promotion row or request key alone grants no replay. Fresh validation must
  reconstruct the observation closure, revalidate runtime/profile and blobs,
  enforce quarantine/revocation, and mint a one-use hit token.

The first honest Linux product milestone stops after an executed-only foreground
pytest run. Candidate, promotion, and replay authority remain later gates.

## Request path

```text
Codex/tool shell explicitly invokes `again run -- <argv...>` or
`again reference -- <argv...>`
  -> observe actual cwd, streams and local/default environment
  -> parse strict policy + verify executable identity and ambient-input policy
     -> unsafe/unknown: error without execution; caller reruns the original argv unchanged
     -> `run` with TTY streams: run the audited command once uncached with inherited streams
     -> eligible non-TTY call:
        -> fingerprint request + scoped resources + executable + environment digests
        -> local lookup
           -> miss + `run`: stream one execution live; if admission checks pass, shadow-execute and store exact blobs/record
           -> miss + `reference`: record a typed no-execution miss and fail
           -> hit: revalidate key/proof/blob bytes and run the fixed-argument exact-executable capability probe
              -> `run`: return exact full streams
              -> `reference`: return deterministic result id/status/stream digests and lengths
        -> persist disposition, timing, bytes, and reason

Production Codex hook
  -> return before reading/parsing stdin; emit nothing; mutate nothing

Experimental unsafe hook plumbing
  -> parse the exact audited PreToolUse / PreCompact / PostCompact shape
  -> exercise opaque handoff/runtime defenses only in controlled tests
```

The explicit CLI is the production path. It starts in the tool shell's effective context and may resolve a bare audited executable name itself. That makes cwd, TTY streams, environment and executable resolution available before the reuse decision. Again does not execute an ineligible explicit request. `again reference` is lookup-only: it never executes or stores the requested command, including on a miss.

`again setup --codex` installs a reversible instruction-only Codex skill, not hooks. The default personal path is `$HOME/.agents/skills/again`; `--project` selects `<repo>/.agents/skills/again`. The skill directs Codex to use `again run` only for the narrow surface and to rerun refused commands unchanged. It permits `again reference` only when the exact unchanged bytes remain visible in the same active context; compaction, another agent, or a need for the bytes requires full retrieval instead. Setup tracks its owned bytes, refuses indirect or user-modified state, and doctor reports personal/project skill status.

Automatic `PreToolUse` rewriting is disabled; the normal hook returns before reading or parsing stdin. Codex now supports `updatedInput` and exposes the session `cwd`, but Bash hooks still receive only `tool_input.command`: the effective per-call workdir for `exec_command`, effective TTY, shell/login, sandbox, remote `environment_id`, and output-cap controls remain absent. Even an absolute executable is therefore insufficient to establish transparent substitution. The dormant adapter rejects unknown envelope fields, requires `tool_input` to contain only `command`, requires an explicit absolute audited executable, and uses an opaque identifier rather than interpolating original shell text only when `--experimental-unsafe-rewrite` explicitly enables it for controlled differential tests. There, a hidden TTY or same-repository cwd difference runs the revalidated command once uncached with inherited streams, while a different repository/non-Git cwd or remote executable/state mismatch can fail. Those mechanisms are tested future infrastructure, not an active product or equivalence claim. The current engine is local/default-environment only.

## Components

- **Policy:** deterministic, versioned, deny-by-default parser with stable reason codes.
- **Codex skill:** instruction-only onboarding for explicit `again run` and caller-asserted `again reference`; it does not modify hooks or execute commands itself.
- **Experimental adapter:** dormant parser/handoff plumbing for the audited Codex `PreToolUse`, `PreCompact`, and `PostCompact` JSON shapes with unknown-field rejection. Production returns before stdin read/parse and emits nothing; only the explicit unsafe test flag reaches this adapter.
- **Executable verifier:** rejects PATH/basename spoofing. `strict-read-v0.5` accepts only each exact reviewed Apple system path and binary BLAKE3 under the exact `macos-15.6.1-24G90-read-v0` `SystemVersion.plist` BLAKE3. Ripgrep additionally requires the exact canonical Codex bundle path shape, exact binary BLAKE3, and `codex-rg-15.2.0-e89fff89ac-arm64-read-v0` profile. Codesign identifier/team fields are descriptive metadata only, not strict signature validity or the byte-authentication boundary. Unknown updates fail closed. Installation on Linux or unknown macOS does not enable reuse; doctor reports unsupported until a backend/profile is audited.
- **Fingerprinter:** samples canonical argv, admitted content/listing paths, executable, platform/profile, policy version, and plaintext-free domain-separated environment digests. It refuses any present loader/instrumentation/locale/terminal/timezone override in the `DYLD_*`, `LD_*`, `Malloc*`, `MALLOC_*`, sanitizer-option, `GCONV_PATH`, `LOCPATH`, `NLSPATH`, `PATH_LOCALE`, `TERMCAP`, `TERMINFO`/`TERMINFO_DIRS`, or `TZDIR` set because their referenced bytes are outside the scoped observation. A separate runtime-context digest binds real/effective uid/gid, the supplementary-group vector, macOS soft/hard `CPU`, `FSIZE`, `DATA`, `STACK`, `CORE`, `RSS`, `MEMLOCK`, `NPROC`, `NOFILE`, and `AS` limits, plus the signal mask and disposition/flag class through signal 31. Both the cache key and stored proof bind this digest. Filesystem observations remain path-based rather than immutable, and the environment digests are not a secret-classification or high-entropy confidentiality boundary.
- **Executor:** runs explicit argv from the actual local context, streams a cold execution live, and captures bounded exact bytes/status. Dormant hook plumbing can hand off an opaque stored call id. V0 admits only exit-zero results with empty stderr, complete stdout/stderr captures no larger than 16 MiB each, stable post-observations, and exact shadow agreement. It does not yet classify secret-bearing arguments or output.
- **Index:** private SQLite WAL metadata with immediate transactions for concurrent compare/insert and foreign keys. Every hit semantically revalidates the result row and stored validation record against recomputed inputs; the row still lacks a cryptographic binding against a malicious same-user writer.
- **CAS:** BLAKE3-addressed immutable blobs, capped at 16 MiB each and written by stage-and-rename; a digest mismatch is corruption, never a hit. Bounded lifecycle passes remove only old, tracked, unreferenced blobs and expired pending/telemetry rows.
- **Presenter:** exact full-stream `again run` replay, explicit full retrieval, and explicit verified `again reference` output. A reference contains only the result id, status, stream BLAKE3 digests, and byte lengths after the same live request/runtime/executable/proof/blob checks; on a miss it emits no requested output and runs nothing. The caller owns the assertion that the full bytes remain visible in the same active context. A context-keyed delivery ledger and clearing primitive remain dormant; automatic reference emission is disabled because hooks expose neither the effective output ceiling nor a delivery receipt. Once output presentation succeeds, later cache-admission or accounting errors preserve the already-produced status.
- **Validator:** mandatory request-key, runtime-context, exact executable/profile, validation-record, result-constraint, and blob-byte revalidation on hits; first-miss shadow comparison; same-key divergence quarantine; and explainability. Before serving a hit it launches the exact executable with fixed cheap arguments, null stdin, and suppressed output to verify point-in-time exec authority. This probe is a real child process, but it does not use the requested argv.

## EffectIR versions

The local explicit-read engine stores a smaller `V0Proof` JSON beside the result
row and CAS blobs. Its historical/general trace design was called EffectIR v1.
The frozen Linux pytest contract uses non-reinterpreting EffectIR v2 objects in
[LINUX_PYTEST_WIRE_V1.md](LINUX_PYTEST_WIRE_V1.md); its schemas and canonical
encoding have pure coverage, but a live semantic recorder does not yet exist.
The durable trace record separates these concerns:

- invocation identity: original and parsed request, cwd/workspace, stdin digest, policy/profile;
- platform identity: OS, architecture, kernel/runtime, executor and tracer versions;
- observed resources: file content/metadata, directory membership/order, symlink target, absent path, executable/library, environment value digest;
- result: exact stdout/stderr blob references, exit/signal, duration;
- effects: ordered filesystem operations with before/after preconditions when the traced profile supports them;
- proof: observation completeness, decision/reason, input root, policy hash, validation history;
- metrics and privacy: saved time/bytes, source session, shareability and secret-taint classification.

Schema versions are explicit. Unknown fields may be retained where the wire
contract permits, but an unknown semantic version is ineligible for reuse.

## Trace-backed reuse design target

The future trace-backed profile is designed to allow replay only when:

1. the original run occurred inside an execution boundary that blocks or records every observable input and effect expressible by `P`;
2. every recorded precondition still matches a snapshot used for replay/commit;
3. all effects are in the profile’s replayable subset;
4. applying the recorded result/effects is observationally equivalent to executing the request under `P`.

Local v0 does not satisfy this immutable-snapshot target. It combines scoped sampling with a deliberately small set of audited read-only tool semantics, then revalidates before a hit. Filesystem paths can still change after validation or between individual observations; same-user plan-to-use and concurrent-mutation races remain. The capability probe is also point-in-time: transient global resource availability may change immediately afterward or may be sufficient for the cheap probe while insufficient for the requested work. The optional macOS Seatbelt compiler can produce a deny-write/deny-network, scope-limited profile, but nested Seatbelt is not runtime-applicable inside Codex's existing sandbox on the current development machine. This is not the long-term dependency-discovery mechanism or a general equivalence guarantee.

## Long-term Linux execution profile

A rootless worker executes against an immutable input snapshot and COW workspace. Landlock/seccomp-style enforcement bounds filesystem/network/syscall capabilities; eBPF is an audit and performance signal rather than the sole enforcement boundary. A narrow supervisor records descendants, directory and negative dependencies, executable/library identity, environment, and ordered effects. Unsupported syscalls or lost trace events set `trace_complete=false` and permanently disqualify that record.

Replay first materializes into a fresh branch, verifies before-state hashes, and atomically commits only if the destination snapshot still matches. A crash exposes no partial effect.

## Local-state trust boundary

On Unix, disposable default state lives at `${TMPDIR}/again-<euid>/workspaces/<BLAKE3(canonical-workspace-path)>`. App-owned levels are private mode `0700`; state is deterministic per canonical workspace within that temporary namespace, but the OS may clear it. Keeping it external means a first run cannot change the workspace observed by `ls --color=never` or recursive searches. `AGAIN_HOME` selects one exact persistent root and must be absolute and external to the active workspace. Its final component cannot be a symlink, and every existing root must already be a current-user-owned real directory with mode `0700`. The configured root's canonical ancestor chain must contain only real directories owned by the current uid or root; any group/world-writable ancestor must have the sticky bit. The state opener also rejects static database/WAL/SHM, blob-directory/shard/file, and state-root `.gitignore` symlinks. Existing fixed files must be current-user-owned regular files, mode `0600`, and single-linked; fixed directories must be current-user-owned real directories with their required private modes. CAS bytes and row semantics are checked again on reads. Opens and creation remain pathname based, so same-user/root replacement between validation and use remains possible.

Those checks prevent common redirection and unsafe-preexisting-state cases but do not establish a hostile same-user/root boundary. Opens are still pathname based rather than descriptor-relative, so same-user or root processes can race validation and use. SQLite rows are not authenticated against another writer running as that user. The local filesystem namespace and database remain trusted inputs.

## Shared-cache trust boundary

The opt-in team-alpha CLI closes the first end-to-end client boundary for manually provisioned profiles. It preflights portable inputs, derives content observations, attaches an exact runtime/image authority from a short-lived full-audit checkpoint, obtains root-signed fresh repository trust, and accepts only verified/decrypted v2 plaintext. On a typed manifest miss, a configured producer captures twice from an owner-private immutable snapshot, scans the retained result, encrypts locally, uploads ciphertext first, and signs/publishes the manifest last. The same retained bytes are presented once even when a post-capture policy or transport step degrades. TTYs bypass before key/network work; non-hit paths never manufacture a hit and use an audited one-execution local fallback where availability policy permits.

Remote metadata is untrusted. The protocol uses deterministic length-prefixed manifest bytes and strict Ed25519 signatures whose key id is immutably bound to one producer. The team CLI derives namespace, request/input, policy/profile, platform/image, and runtime bindings from its live workspace and private profile; obtains root-signed, freshness-checked repository trust; and releases plaintext only after manifest, revocation, shareability, blob identity, ciphertext digest, AEAD, plaintext length/digest, and local privacy checks. Records explicitly marked secret-tainted remain local, but the local v0 engine does not yet infer that classification. Cross-machine reuse still requires equivalent execution profiles and trusted production or independent matching validation.

The undeployed Cloudflare Worker service enforces bearer permissions, tenant/repository namespaces, v2-only manifest storage, quotas, D1/R2 blob lifecycle, immutable producer-key bindings and revocation, signed-manifest admission, conflict quarantine, audit records, repository generations, and bounded reconciliation. Repository keys and plaintext streams stay client-side; the service stores ciphertext and signed encrypted-record metadata. The wired async Rust team client rejects plaintext production endpoints and redirects, uses bounded send/body and per-chunk stall deadlines, strictly parses bounded bodies, and verifies/decrypts records locally. Its unit-only HTTP constructor accepts numeric loopback addresses, disables proxies, and is absent from non-test builds.

Both lookup transports now exist in source. `legacy_v2` performs initial trust, manifest, two ciphertext, and final-trust GETs. `bundle_v1` replaces the first four with one length-framed streaming response, retains the post-decryption latest-trust GET, and is covered by the actual Worker route, strict Rust client, an 18-state Worker/reference matrix, and a manual two-client Quick Tunnel lifecycle. That is implementation evidence, not rollout authority: bundle v1 remains opt-in experimental and unshipped because its maximum-payload latency and pending-reader TCP-reset gates fail and the full local/live matrix, direct proof of current Worker-isolate heap usage, 100,000-case stateful D1/R2 corpus, and cross-layer post-decrypt race are missing. Profiles and signed trust remain manually provisioned, the service is undeployed, and the checked-in CI integration only consumes pre-provisioned state. These pieces are therefore an integration/security alpha rather than a public team product, and remote storage cannot upgrade an unsafe local execution profile into a safe one. See [the exact bundle status](TEAM_LOOKUP_BUNDLE_V1.md) and [retained evidence](EVIDENCE.md).
