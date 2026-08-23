# Implementation status

This file distinguishes code that exists from roadmap intent. It is updated only from retained tests or benchmark evidence.

## Local vertical slice

| Capability | Status | Evidence / limitation |
|---|---|---|
| Codex `PreToolUse` adapter and idempotent setup | implemented | official event/output fixtures, merge/remove/dry-run tests; real isolated Codex run still required |
| Account-free repository-local state | implemented | SQLite/CAS under `.again`, private modes, self-ignore test |
| Strict parsing and mandatory bypass | implemented for narrow macOS v0 | 1,024-shape adversarial process corpus; Linux hook intentionally fails closed |
| Executable identity | implemented for macOS v0 | exact Apple paths; signed Codex-bundled ripgrep; fake-PATH test |
| Scoped request fingerprint | implemented | content, recursive tree, listing, identity, absent path, symlink, special-file and race tests |
| Verified digest memoization | implemented | dev/inode/mode/uid/gid/size/mtime/ctime tuple, SQLite v2, corruption/migration/inode/ctime tests |
| Local result CAS and quarantine | implemented | BLAKE3 blob validation, same-key divergence quarantine, SQLite WAL/FULL sync |
| First-run double validation | implemented | exact streams/status/post-input fingerprint; not a complete nondeterminism proof |
| Same-session output compaction and recovery | implemented | byte-perfect first delivery, compact repeat, `show`, `AGAIN_FULL` |
| Explain/stats/doctor | implemented baseline | richer per-resource explanations and GC reporting remain |
| macOS Seatbelt profile compiler | implemented, not active in Codex path | profile tests pass; nested application is rejected by Codex's existing sandbox on this machine |

Current local verification: 74 library tests, 1 generated-corpus integration test covering 1,024 hostile shapes, 5 engine integration tests, and 10 store/setup tests; strict all-target Clippy passes.

## Measured gates

The retained dirty-tree benchmark passes hook p95 (5.506 ms), local hit p95 (12.345 ms), exact recovery, mutation invalidation, unsafe no-rewrite, and duplicate-output reduction (99.992%). It does **not** demonstrate a speedup: the native 3.995 ms `cat` fixture is faster than Again. A workload with at least a 500 ms baseline is still required for the speed gate.

## Day 1–7 remaining

- Run the real isolated Codex hook flow and record sandbox/state behavior.
- Add a slow, low-output workload and multi-language repository corpus.
- Reach 100,000 differential shadow validations with zero unexplained mismatch.
- Implement an enforceable Linux trace/COW profile before test/build effect replay.
- Add bounded storage GC, reproducible signed releases, SBOM, install/uninstall, and outside alpha evidence.

## Day 8–30 foundation versus remaining product

Implemented foundation: versioned remote manifest types, deterministic signing bytes, complete namespace/request/policy/profile/platform/image/blob bindings, producer-key authorization, expiry/revocation/privacy rules, and fail-closed signature-verifier interface.

Not yet a team product: reviewed Ed25519 implementation, authenticated service, encrypted blob storage, tenancy enforcement at the API/storage layer, client upload/download, CI adapter, audit/analytics, rate limits/quotas/deletion, deployment, cross-machine equality corpus, and design-partner/payment evidence.

