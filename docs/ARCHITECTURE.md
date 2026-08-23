# Architecture

## Request path

```text
Codex/tool shell explicitly invokes `again run -- <argv...>`
  -> observe actual cwd, streams and local/default environment
  -> parse strict policy + verify executable identity and ambient-input policy
     -> unsafe/unknown: error without execution; caller reruns the original argv unchanged
     -> TTY streams: run the audited command once uncached with inherited streams
     -> eligible non-TTY call:
        -> fingerprint request + scoped resources + executable + environment digests
        -> local lookup
           -> miss: stream one execution live; if admission checks pass, shadow-execute and store exact blobs/record
           -> hit: revalidate key/proof/blob bytes, run fixed-argument exact-executable capability probe, return exact full streams
        -> persist disposition, timing, bytes, and reason

Production Codex hook
  -> return before reading/parsing stdin; emit nothing; mutate nothing

Experimental unsafe hook plumbing
  -> parse the exact audited PreToolUse / PreCompact / PostCompact shape
  -> exercise opaque handoff/runtime defenses only in controlled tests
```

The explicit CLI is the production path. It starts in the tool shell's effective context and may resolve a bare audited executable name itself. That makes cwd, TTY streams, environment and executable resolution available before the reuse decision. Again does not execute an ineligible explicit request.

`again setup --codex` installs a reversible instruction-only Codex skill, not hooks. The default personal path is `$HOME/.agents/skills/again`; `--project` selects `<repo>/.agents/skills/again`. The skill directs Codex to use the explicit CLI only for the narrow surface and to rerun refused commands unchanged. Setup tracks its owned bytes, refuses indirect or user-modified state, and doctor reports personal/project skill status.

Automatic `PreToolUse` rewriting is disabled; the normal hook returns before reading or parsing stdin. Codex hides effective TTY, workdir, shell/login, sandbox, remote `environment_id`, and output-cap controls, so even an absolute executable in `tool_input.command` is insufficient to establish transparent substitution. The dormant adapter rejects unknown envelope fields, requires `tool_input` to contain only `command`, requires an explicit absolute audited executable, and uses an opaque identifier rather than interpolating original shell text only when `--experimental-unsafe-rewrite` explicitly enables it for controlled differential tests. There, a hidden TTY or same-repository cwd difference runs the revalidated command once uncached with inherited streams, while a different repository/non-Git cwd or remote executable/state mismatch can fail. Those mechanisms are tested future infrastructure, not an active product or equivalence claim. The current engine is local/default-environment only.

## Components

- **Policy:** deterministic, versioned, deny-by-default parser with stable reason codes.
- **Codex skill:** instruction-only onboarding for explicit `again run`; it does not modify hooks or execute commands itself.
- **Experimental adapter:** dormant parser/handoff plumbing for the audited Codex `PreToolUse`, `PreCompact`, and `PostCompact` JSON shapes with unknown-field rejection. Production returns before stdin read/parse and emits nothing; only the explicit unsafe test flag reaches this adapter.
- **Executable verifier:** rejects PATH/basename spoofing. `strict-read-v0.5` accepts only each exact reviewed Apple system path and binary BLAKE3 under the exact `macos-15.6.1-24G90-read-v0` `SystemVersion.plist` BLAKE3. Ripgrep additionally requires the exact canonical Codex bundle path shape, exact binary BLAKE3, and `codex-rg-15.2.0-e89fff89ac-arm64-read-v0` profile. Codesign identifier/team fields are descriptive metadata only, not strict signature validity or the byte-authentication boundary. Unknown updates fail closed. Installation on Linux or unknown macOS does not enable reuse; doctor reports unsupported until a backend/profile is audited.
- **Fingerprinter:** samples canonical argv, admitted content/listing paths, executable, platform/profile, policy version, and plaintext-free domain-separated environment digests. It refuses any present loader/instrumentation/locale/terminal/timezone override in the `DYLD_*`, `LD_*`, `Malloc*`, `MALLOC_*`, sanitizer-option, `GCONV_PATH`, `LOCPATH`, `NLSPATH`, `PATH_LOCALE`, `TERMCAP`, `TERMINFO`/`TERMINFO_DIRS`, or `TZDIR` set because their referenced bytes are outside the scoped observation. A separate runtime-context digest binds real/effective uid/gid, the supplementary-group vector, macOS soft/hard `CPU`, `FSIZE`, `DATA`, `STACK`, `CORE`, `RSS`, `MEMLOCK`, `NPROC`, `NOFILE`, and `AS` limits, plus the signal mask and disposition/flag class through signal 31. Both the cache key and stored proof bind this digest. Filesystem observations remain path-based rather than immutable, and the environment digests are not a secret-classification or high-entropy confidentiality boundary.
- **Executor:** runs explicit argv from the actual local context, streams a cold execution live, and captures bounded exact bytes/status. Dormant hook plumbing can hand off an opaque stored call id. V0 admits only exit-zero results with empty stderr, complete stdout/stderr captures no larger than 16 MiB each, stable post-observations, and exact shadow agreement. It does not yet classify secret-bearing arguments or output.
- **Index:** private SQLite WAL metadata with immediate transactions for concurrent compare/insert and foreign keys. Every hit semantically revalidates the result row and stored validation record against recomputed inputs; the row still lacks a cryptographic binding against a malicious same-user writer.
- **CAS:** BLAKE3-addressed immutable blobs, capped at 16 MiB each and written by stage-and-rename; a digest mismatch is corruption, never a hit. Bounded lifecycle passes remove only old, tracked, unreferenced blobs and expired pending/telemetry rows.
- **Presenter:** exact full-stream replay and explicit full retrieval. A context-keyed delivery ledger, compact-reference representation, and clearing primitive exist but are not invoked by production hooks; automatic reference emission is disabled because hooks expose neither the effective output ceiling nor a delivery receipt. Once output presentation succeeds, later cache-admission or accounting errors preserve the already-produced status.
- **Validator:** mandatory request-key, runtime-context, exact executable/profile, validation-record, result-constraint, and blob-byte revalidation on hits; first-miss shadow comparison; same-key divergence quarantine; and explainability. Before serving a hit it launches the exact executable with fixed cheap arguments, null stdin, and suppressed output to verify point-in-time exec authority. This probe is a real child process, but it does not use the requested argv.

## EffectIR v1

EffectIR v1 is the typed, round-trip-tested target record for trace-backed execution. The v0 engine does not persist it yet; it currently stores a smaller `V0Proof` JSON beside the result row and CAS blobs. The target durable record separates these concerns:

- invocation identity: original and parsed request, cwd/workspace, stdin digest, policy/profile;
- platform identity: OS, architecture, kernel/runtime, executor and tracer versions;
- observed resources: file content/metadata, directory membership/order, symlink target, absent path, executable/library, environment value digest;
- result: exact stdout/stderr blob references, exit/signal, duration;
- effects: ordered filesystem operations with before/after preconditions when the traced profile supports them;
- proof: observation completeness, decision/reason, input root, policy hash, validation history;
- metrics and privacy: saved time/bytes, source session, shareability and secret-taint classification.

Schema versions are explicit. Unknown fields may be retained, but an unknown semantic version is ineligible for reuse.

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

The repository now contains a non-integrated Linux policy planner plus a disposable applicability probe, not an execution boundary. The planner compiles canonical file/tree scopes to candidate rootless Landlock ABI 3+ rules, never grants host-root directory reads merely for path traversal, and rejects immediate-directory-listing scopes because Landlock path-beneath would widen them to a subtree. ABI 3 is required only because it can mediate standalone truncation; it still does not mediate metadata observations such as `stat`/`access` or effects such as `chmod`/`setxattr`/`utime`. The fixed `/usr/bin/true` probe installs Landlock and a seccomp deny list that includes ordinary and batched socket calls plus the io_uring entry syscalls, but this is not a general no-network guarantee. No public API runs caller-supplied Linux commands. Inherited descriptors, runtime-directory breadth, complete network isolation, and plan-to-apply path races remain unresolved, so the engine does not use this work and it cannot make test/build replay safe.

## Local-state trust boundary

On Unix, disposable default state lives at `${TMPDIR}/again-<euid>/workspaces/<BLAKE3(canonical-workspace-path)>`. App-owned levels are private mode `0700`; state is deterministic per canonical workspace within that temporary namespace, but the OS may clear it. Keeping it external means a first run cannot change the workspace observed by `ls --color=never` or recursive searches. `AGAIN_HOME` selects one exact persistent root and must be absolute and external to the active workspace. Its final component cannot be a symlink, and every existing root must already be a current-user-owned real directory with mode `0700`. The configured root's canonical ancestor chain must contain only real directories owned by the current uid or root; any group/world-writable ancestor must have the sticky bit. The state opener also rejects static database/WAL/SHM, blob-directory/shard/file, and state-root `.gitignore` symlinks. Existing fixed files must be current-user-owned regular files, mode `0600`, and single-linked; fixed directories must be current-user-owned real directories with their required private modes. CAS bytes and row semantics are checked again on reads. Opens and creation remain pathname based, so same-user/root replacement between validation and use remains possible.

Those checks prevent common redirection and unsafe-preexisting-state cases but do not establish a hostile same-user/root boundary. Opens are still pathname based rather than descriptor-relative, so same-user or root processes can race validation and use. SQLite rows are not authenticated against another writer running as that user. The local filesystem namespace and database remain trusted inputs.

## Shared-cache trust boundary

Remote metadata is untrusted. The protocol uses deterministic length-prefixed manifest bytes and strict Ed25519 signatures whose key id is bound to one producer. The target consumer flow must recompute namespace, request/input, policy/profile, platform/image, revocation, shareability, and blob bindings before staging a candidate. The current standalone async client validates a strict manifest against bindings and trust/revocation state supplied by its caller and verifies requested blob bytes separately; it does not derive or authenticate that snapshot, orchestrate a complete candidate fetch, recheck live revocation, or stage anything for execution. Records explicitly marked secret-tainted remain local, but the current local engine does not produce that classification. Cross-machine reuse requires equivalent profiles and trusted production or independent matching validation.

An undeployed Cloudflare Worker prototype enforces bearer permissions, tenant/repository namespaces, quotas, D1 blob lifecycle, R2 content addressing, producer-key registration/revocation, signed-manifest admission, conflict quarantine, audit records, and bounded reconciliation. An async Rust HTTP client rejects plaintext production endpoints and redirects, uses one bounded send/body deadline plus per-chunk stall deadlines, strictly parses bounded bodies, verifies blobs, and invokes the concrete Ed25519 manifest path. Its unit-only HTTP constructor accepts numeric loopback addresses, disables proxies, and is absent from non-test builds. Neither service nor client is wired into the CLI. The service remains untrusted transport/storage, lacks application-layer encryption and production controls, and cannot upgrade an unsafe local execution profile into a safe one.
