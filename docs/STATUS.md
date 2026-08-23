# Implementation status

This file distinguishes code that exists from roadmap intent. It is updated only from retained tests or benchmark evidence.

## Local vertical slice

| Capability | Status | Evidence / limitation |
|---|---|---|
| Codex `PreToolUse` adapter and reversible setup | implemented | official event/output fixtures, byte-exact restore/fail-closed edit tests, duplicate-scope diagnostics, and one real isolated Codex 0.149.0 `workspace-write` run |
| Account-free repository-local state | implemented | SQLite/CAS under `.again`, private modes, self-ignore test |
| Strict parsing and mandatory bypass | implemented for narrow macOS v0 | 1,024-shape adversarial process corpus; Linux hook intentionally fails closed |
| Executable identity | implemented for macOS v0 | exact Apple paths; signed Codex-bundled ripgrep; fake-PATH test |
| Scoped request fingerprint | implemented | content, recursive tree, listing, identity, absent path, symlink, special-file and race tests |
| Verified digest memoization | implemented | dev/inode/mode/uid/gid/size/mtime/ctime tuple, SQLite v2, corruption/migration/inode/ctime tests |
| Local result CAS, lifecycle, and quarantine | implemented | BLAKE3 blob validation, bounded orphan/pending/event cleanup, atomic concurrent convergence/divergence tests, SQLite WAL/FULL sync |
| First-run double validation | implemented | exact streams/status/post-input fingerprint; not a complete nondeterminism proof |
| Same-session output compaction and recovery | implemented | byte-perfect first delivery, compact repeat, `show`, `AGAIN_FULL` |
| Explain/stats/doctor | implemented baseline | doctor reports both hook scopes and the actual audited-native/Seatbelt state; richer per-resource explanations and GC reporting remain |
| macOS Seatbelt profile compiler | implemented, not active in Codex path | profile tests pass; nested application is rejected by Codex's existing sandbox on this machine |

Current local verification: 89 library tests, 1 generated-corpus integration test covering 1,024 hostile shapes, 5 engine integration tests, and 10 store/setup tests (105 total); strict all-target Clippy passes.

## Measured gates

The retained clean-commit benchmark passes hook p95 (6.359 ms), local exec p95 (8.088 ms), exact recovery, mutation invalidation, unsafe no-rewrite, and duplicate-output reduction (99.992%). It does **not** demonstrate a speedup: the native 3.860 ms `cat` fixture is faster than Again. A workload with at least a 500 ms baseline is still required for the speed gate.

## Day 1–7 remaining

- Repeat the real Codex hook flow across clean global-only and project-only installs, subdirectories, and interrupted/long-running calls.
- Add a slow, low-output workload and multi-language repository corpus.
- Reach 100,000 differential shadow validations with zero unexplained mismatch.
- Implement an enforceable Linux trace/COW profile before test/build effect replay.
- Add reproducible signed releases, SBOM, packaged install/uninstall, and outside alpha evidence. Bounded local lifecycle cleanup is implemented.

## Day 8–30 foundation versus remaining product

Implemented foundation: versioned remote manifest types, deterministic signing bytes, complete namespace/request/policy/profile/platform/image/blob bindings, producer-key authorization, expiry/revocation/privacy rules, and strict Ed25519 signing/verification with immutable key-id ownership.

Not yet a team product: authenticated service, encrypted blob storage, tenancy enforcement at the API/storage layer, client upload/download, CI adapter, audit/analytics, rate limits/quotas/deletion, deployment, cross-machine equality corpus, and design-partner/payment evidence.
