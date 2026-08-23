# Engineering decisions

This log records choices that affect Again's correctness claim. A later optimization may replace a choice only with stronger evidence and a schema/profile version change.

## D-001 — Unknown commands remain untouched

The Codex hook emits no output for an unknown, unsafe, or incompletely modeled call. It never returns an `allow` decision merely to observe a command. This preserves Codex's original approval and sandbox path.

## D-002 — Trust executable identity, not `PATH` names

The macOS v0 profile accepts exact Apple system paths for its narrow read-only tools and an OpenAI-signed Codex-bundled ripgrep identity. A fake executable named `cat` or `rg` earlier in `PATH` is not rewritten. Executable bytes and the audited identity are part of the request proof.

## D-003 — Recursive ripgrep requires `--no-ignore`

Normal recursive ripgrep may read parent, repository, and global ignore files, including a configured file outside the workspace. V0 cannot claim a minimal input scope while leaving those inputs unmodeled. Recursive searches therefore require `--no-ignore`, and any `RIPGREP_CONFIG_PATH` disables admission. Explicit regular-file searches do not need this flag.

## D-004 — Scoped content proofs replace whole-repository hashing

Each admitted command produces an explicit access plan: content paths, recursive trees, directory listings, or identity only. This cuts proof work and avoids invalidation from unrelated edits. `.again` and volatile Git log/lock namespaces are excluded from hashing and cannot be named as admitted operands.

## D-005 — First admission requires exact double execution

A successful miss is run twice immediately. Stdout, stderr, exit status, and post-execution input fingerprint must agree exactly before storage. This catches common nondeterminism but is validation evidence, not a replacement for a complete execution profile.

## D-006 — Same-session compaction is reversible

The first delivery is byte-perfect. Only an exact cache hit already delivered in the same session may become a short reference. `again show <id>` and `AGAIN_FULL=1` recover the exact streams; no model-generated summary participates in correctness.

## D-007 — Repository-scoped, self-ignored local state

Without `AGAIN_HOME`, state lives under `<workspace>/.again` so a Codex workspace sandbox need not gain home-directory write access. The directory creates a self-ignoring `.gitignore` without modifying an existing user file. State and blobs use private Unix permissions.

## D-008 — Seatbelt is a capability, not a shipped claim

Again can compile a deterministic macOS Seatbelt profile with exact executable and scoped read permissions plus write/network/device/credential denials. On the development machine, `sandbox-exec` is available outside Codex but nested application is rejected inside Codex's existing workspace sandbox. The Codex v0 path therefore relies only on audited read-only executable semantics; arbitrary-command reuse waits for an enforceable trace/isolation profile.

## D-009 — Performance gates include proof overhead

Benchmarks measure hook, opaque handoff, fingerprint, lookup, and presentation. Trivial commands may be slower. The 3x speed gate is evaluated only where the native baseline is at least 500 ms; duplicate-output reduction remains valuable independently. Failing measurements stay in the evidence ledger.

