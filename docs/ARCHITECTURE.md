# Architecture

## Request path

```text
Codex Bash call
  -> PreToolUse hook (strict classification only)
     -> unsafe/unknown: no hook decision; Codex runs the original call
     -> eligible: save opaque call, rewrite to `again exec --call <id>`
        -> verify executable identity and ambient-input policy
        -> fingerprint request + scoped resources + executable + environment digests
        -> local lookup
           -> miss: execute, validate admission, store exact blobs and record
           -> hit: revalidate key and blobs, return full or same-session reference
        -> persist disposition, timing, bytes, and reason
```

The hook never interpolates the original shell string into its replacement. It persists the request locally and passes an opaque identifier to the wrapper. Unsafe commands are not rewritten, preserving Codex’s normal approval and sandbox flow.

## Components

- **Policy:** deterministic, versioned, deny-by-default parser with stable reason codes.
- **Adapter:** reads official Codex hook JSON and emits only documented `PreToolUse` output.
- **Executable verifier:** rejects PATH/basename spoofing; v0 accepts exact Apple system paths or the signed Codex-bundled ripgrep identity.
- **Fingerprinter:** hashes canonical argv, only the admitted content/listing scopes, executable, platform/profile, policy version, and secret-safe environment digests.
- **Executor:** runs the opaque original request and captures exact bytes/status. v0 stores only successful read-only calls.
- **Index:** SQLite WAL metadata with immediate transactions for concurrent compare/insert and foreign keys.
- **CAS:** BLAKE3-addressed immutable blobs written by stage-and-rename; a digest mismatch is corruption, never a hit. Bounded lifecycle passes remove only old, tracked, unreferenced blobs and expired pending/telemetry rows.
- **Presenter:** session delivery ledger, compact exact-repeat references, and full retrieval.
- **Validator:** mandatory hit revalidation, shadow comparison, mismatch quarantine, and explainability.

## EffectIR v1

The durable record separates these concerns:

- invocation identity: original and parsed request, cwd/workspace, stdin digest, policy/profile;
- platform identity: OS, architecture, kernel/runtime, executor and tracer versions;
- observed resources: file content/metadata, directory membership/order, symlink target, absent path, executable/library, environment value digest;
- result: exact stdout/stderr blob references, exit/signal, duration;
- effects: ordered filesystem operations with before/after preconditions when the traced profile supports them;
- proof: observation completeness, decision/reason, input root, policy hash, validation history;
- metrics and privacy: saved time/bytes, source session, shareability and secret-taint classification.

Schema versions are explicit. Unknown fields may be retained, but an unknown semantic version is ineligible for reuse.

## Correctness invariant

For supported profile `P`, replay is allowed only when:

1. the original run occurred inside an execution boundary that blocks or records every observable input and effect expressible by `P`;
2. every recorded precondition still matches a snapshot used for replay/commit;
3. all effects are in the profile’s replayable subset;
4. applying the recorded result/effects is observationally equivalent to executing the request under `P`.

Scoped content hashing plus audited tool semantics is the temporary v0 proof for strict read-only tools. The optional macOS Seatbelt compiler can produce a deny-write/deny-network, scope-limited profile, but nested Seatbelt is not runtime-applicable inside Codex's existing sandbox on the current development machine; Again does not pretend otherwise. This is not the long-term dependency-discovery mechanism.

## Long-term Linux execution profile

A rootless worker executes against an immutable input snapshot and COW workspace. Landlock/seccomp-style enforcement bounds filesystem/network/syscall capabilities; eBPF is an audit and performance signal rather than the sole enforcement boundary. A narrow supervisor records descendants, directory and negative dependencies, executable/library identity, environment, and ordered effects. Unsupported syscalls or lost trace events set `trace_complete=false` and permanently disqualify that record.

Replay first materializes into a fresh branch, verifies before-state hashes, and atomically commits only if the destination snapshot still matches. A crash exposes no partial effect.

## Shared-cache trust boundary

Remote metadata is untrusted. The protocol uses deterministic length-prefixed manifest bytes and strict Ed25519 signatures whose key id is bound to one producer. A client verifies namespace, signature, policy/profile identity, platform image, blob digests, input preconditions, revocation state, and shareability before staging a candidate. Raw outputs marked secret-tainted remain local. Cross-machine reuse requires equivalent profiles and trusted production or independent matching validation. The service/client transport and storage enforcement are not implemented yet.
