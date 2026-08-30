# Implementation prompt pack

This execution pack turns Again's verified-reuse foundations into a useful
multi-agent product. Each prompt is for a fresh coding-agent terminal in its
own Git worktree. Terminals should produce reviewable commits and evidence,
not broad speculative rewrites.

The first product milestone is:

> Two local agents working in one repository share verified discoveries and
> in-flight work, automatically converge on one eligible command execution,
> and both observe precise invalidation after a relevant edit.

## Common preamble for every terminal

Paste this before the terminal-specific prompt.

```text
You are implementing one bounded workstream in the Again repository. Read
docs/ROADMAP.md, docs/STATUS.md, docs/ARCHITECTURE.md,
docs/AGENT_ACCELERATION.md, docs/STRAIGHT_TO_CODE.md, and
docs/REUSE_SURFACE.md before editing. Inspect the current implementation and
recent Git history; do not trust a roadmap claim without checking code.

Preserve Again's authority model:
- a digest, command string, path, model statement, or result ID alone never
  grants reuse, retrieval, freshness, or delivery authority;
- unknown or incomplete evidence executes normally when execution is safe;
- mutations, secrets, credentials, communication, deployment, payments,
  interactive programs, and unknown external effects never reuse output;
- agent-authored statements are suggestions until backed by verified sources;
- every served hit passes fresh profile-specific validation;
- execute-only records, shadow records, and promotions remain separate;
- no public API exposes a private capability by serializing an identifier;
- do not weaken an existing qualification contract to make a test pass.

Keep default features safe and experimental features empty by default. Do not
add network dependencies. Preserve unrelated user changes. Prefer focused
modules over making already-large files less maintainable. Add adversarial
tests for refusals, mutation races, stale state, corruption, authorization
mismatch, and lifecycle retirement where relevant.

Run at minimum:
  cargo fmt --all --check
  cargo clippy --locked --all-targets --all-features -- -D warnings
  cargo test --locked --all-features

If a platform-qualified test cannot run locally, run all portable and pure
tests, preserve the refusal, and state the exact external gate. Do not claim
hosted, Linux, deployment, or product qualification from local tests.

Before finishing, provide:
1. the outcome in product terms;
2. changed files and why;
3. tests and exact results;
4. safety properties preserved;
5. remaining blockers or integration dependencies;
6. one focused commit with a clear message.
```

## Worktree and integration order

Create every terminal from the same reviewed base commit in a separate
worktree. Do not run all prompts against one working directory.

```text
Wave 1: A substrate, B context ledger, C command-profile router
Wave 2: D task-start/coordinator, E code intelligence, F pytest execution
Wave 3: G paired integration and product gate
Wave 4: H encrypted team distribution
```

Wave 1 is accepted as one linear implementation chain:

```text
7f30412 Terminal C -> 8080788 Terminal B -> 45b0284 Terminal A
```

Do not rerun Terminals A, B, or C. Create Terminals D, E, and F from the
reviewed documentation checkpoint immediately above `45b0284`, so every Wave 2
worktree contains the same implementation and prompt pack. Terminal G owns
cross-workstream integration. Terminal H starts only after the local two-agent
gate is useful and stable.

## Terminal A — shared manifest and dependency graph

```text
Implement the verified shared substrate described by Roadmap Phase 1.

Primary ownership:
- src/workspace_authority.rs
- a new focused dependency/invalidation module if appropriate
- manifest-specific tests and benchmarks
- the smallest required repository-tool runtime integration

Study ObservedManifestV1 and commits 362094f and fcd8b18. Do not restore the
removed DependencyInvalidationIndexV1 unchanged: it indexed only a single
observation-key path and did not model complete dependency closure.

Deliver:
1. One live ObservedManifestV1 owned for the bounded lifetime of a workspace
   execution/MCP epoch, with no cloneable or serializable authority token.
2. Reuse of already-observed regular files, directory membership, absence,
   identities, trees, and Git dependencies across all eligible repository tools.
3. A bounded dependency graph mapping every observed dependency witness to
   dependent results, facts, validations, and artifacts, with reverse lookup.
4. Repository epoch advancement that atomically invalidates affected
   dependents while preserving proven-unaffected entries.
5. Hard limits for nodes, paths, edges, bytes, depth, fan-out, and invalidation
   work. Limit exhaustion fails closed.
6. Metrics distinguishing physical observations, node reuse, complete-result
   reuse, irrelevant-mutation preservation, and invalidation.
7. Cold, warm, relevant-mutation, irrelevant-mutation, and concurrent
   benchmarks over small, 1k-file, 10k-file, and large-byte fixtures.

Required adversarial cases:
- directory replacement and restore;
- symlink/special-file transitions;
- mutation during observation and validation;
- absent path becoming present and parent membership changes;
- dependency fan-out exhaustion and poisoned/incomplete epochs;
- two eligible operations sharing observations without expanding authority.

Acceptance:
- one epoch serves multiple eligible operations without duplicate traversal;
- relevant mutation invalidates every derived dependent;
- irrelevant mutation preserves the hit;
- no persisted manifest or copied digest independently grants a hit;
- exact output and zero-false-hit behavior remain unchanged.
```

## Terminal B — durable local Shared Context Ledger

```text
Implement the durable local Shared Context Ledger. Build on the existing typed
reasoning models and SQLite/CAS coordinator; do not create a second database or
a parallel generic memory framework.

Primary ownership:
- src/agent_gateway/context.rs
- src/store.rs schema migration and context storage APIs
- focused context-ledger tests

Deliver:
1. Versioned, bounded repository, workspace, task, agent, session, turn,
   connection, compaction-generation, and lifecycle-generation identities.
2. Append-only context events for verified fact admission, unverified
   suggestion, completed observation, in-flight work, failed approach, explicit
   unknown, result reference, invalidation, and retirement.
3. Provenance linking admitted facts to exact source observations and complete
   dependency sets. Facts without current verified sources are not current.
4. Idempotent admission and deterministic ordering. Duplicate envelopes do not
   duplicate facts or savings.
5. Durable reverse edges so dependency invalidation retires every derived
   fact/result reference without deleting audit history.
6. Bounded task-snapshot and ordered-delta-after-cursor queries.
7. In-flight leases with join/observe semantics, recovery, deadlines,
   cancellation, and same-user/workspace scoping.
8. Quotas and garbage collection retaining provenance required by live facts
   and delivery receipts.

Trust rules:
- exact built-in observations admit verified facts through typed adapters;
- agent prose is only a suggestion;
- model output is relevance metadata, never evidence;
- a result ID is not a retrieval capability;
- authorization mismatch returns an explicit unknown or refusal;
- invalidation is monotonic for the affected fact version.

Acceptance:
- two independent store handles observe the same task ledger;
- concurrent duplicate admissions converge;
- mutation invalidates all and only affected facts;
- stale recipient/lifecycle identities cannot receive deltas;
- corruption and partial migration fail closed;
- existing migrations and gateway coordination remain compatible.
```

## Terminal C — automatic universal command-memory router

```text
Implement the automatic universal command-memory control plane. It may observe
every eligible agent action, but must never become an arbitrary command cache
or arbitrary-command launcher.

Primary ownership:
- src/agent_gateway/protocol.rs
- src/agent_gateway/router.rs
- new profile-registry/adapter modules
- focused router and profile-contract tests

Build on UniversalToolPolicyV1, ToolCapabilityClassV1, and
UniversalGatewayDecisionV1.

Deliver:
1. A sealed profile registry with versioned identities and private adapters for
   canonicalization, dependency/effect planning, executable/runtime binding,
   coordination, CAS, quarantine, and accounting.
2. One automatic API classifying actions as exact read, deterministic command,
   freshness read, non-reusable read, mutation, credential, communication,
   deployment, payment, interactive, or unknown.
3. Safe decisions: reuse promoted result, join in-flight,
   execute-and-observe, passthrough without storage, or refuse dangerous
   invalid configuration.
4. A value model bypassing negative-value lookup/validation/materialization.
5. Lifecycle types enforcing execute-only -> candidate -> independent shadow
   -> promotion -> freshly validated hit.
6. Complete streams and recipient-safe compact presentation.
7. Route, miss, join, candidate, promotion, invalidation, quarantine, byte,
   and measured-time metrics.

Initially register only existing qualified read profiles. Add contract types
and non-authoritative placeholders for pytest, Rust, TypeScript, Python, Go,
and build profiles. Unsupported profiles execute normally.

Acceptance:
- every action receives a deterministic decision;
- unsafe/unknown classes cannot enter storage or reuse;
- profile metadata, command basename, model judgment, or output match alone
  cannot upgrade authority;
- interactive/watch/REPL/stdin-dependent calls pass through uncached;
- eligible concurrent calls join once;
- existing exact-read and public CLI behavior do not regress.
```

## Terminal D — task.start and same-user local coordinator

```text
Productize the Shared Context Ledger as the multi-agent task-start and context
delivery experience. Depend on accepted Terminal A and B commits.

Primary ownership:
- src/mcp_gateway.rs
- src/agent_gateway_runtime.rs
- src/agent_gateway_runtime/context_compiler.rs
- src/agent_gateway_service.rs and the daemon feature where required
- MCP/task-start integration tests

Deliver bounded public MCP operations, named consistently with the existing
namespace:
- task.start: authenticate workspace/task/recipient and return one edit brief;
- context.delta: ordered changes after an acknowledged cursor;
- context.publish: suggestions and typed work state, never unverified facts;
- context.retrieve: recipient-bound exact full-result retrieval;
- context.cancel/lifecycle retirement where required.

Implement a same-user local coordinator so multiple agent processes share one
repository/task ledger without weakening workspace identity. Reuse SQLite/CAS
and daemon foundations. A socket path, result ID, or serialized workspace token
must not become bearer authority.

The deterministic bounded task.start response includes:
- verified facts and exact sources;
- invalidated facts separated from current facts;
- unknowns, failed approaches, and in-flight/joinable work;
- recipient-bound result references;
- relevant files/symbols supplied by Terminal E;
- changed-only validation preview;
- no compulsory prose plan.

Delivery protocol:
- first delivery is complete and acknowledged only after write plus flush;
- references/deltas bind exact recipient, scope, session, turn, connection,
  compaction, and lifecycle identities;
- disconnect, cancellation, restart, compaction, partial write, cursor gap, or
  lifecycle change retires compact authority and falls back to full.

Acceptance:
- two real local MCP clients share task state;
- Agent B sees Agent A's verified observations and in-flight work;
- duplicate work joins or is identified;
- mutation creates an exact invalidation delta;
- stale/unauthorized recipients cannot retrieve or receive compact context;
- overflow uses continuation/retrieval, never silent truncation;
- savings count only after verified delivery receipts.
```

## Terminal E — bounded code intelligence and edit-brief relevance

```text
Implement deterministic bounded code intelligence for the task-start brief.
Depend on Terminal A's manifest and graph. Semantic ranking stays separate from
truth and reuse authority.

Primary ownership:
- new focused code-intelligence modules
- edit-brief candidate/ranking modules
- language fixtures and benchmarks
- avoid MCP wiring owned by Terminal D

Deliver:
1. Incremental bounded file, symbol, definition, reference, import/module, and
   test indexes for Rust, Python, TypeScript/JavaScript, and Go.
2. Index entries bound to exact observations and shared invalidation edges.
3. Deterministic task relevance from names, symbols, definitions, references,
   Git changes, and verified facts.
4. A purpose-specific edit-brief compiler smaller than the general brief.
5. Item, byte, file, depth, parse-time, and candidate limits with stable order
   and explicit incomplete/unknown markers.
6. An optional provider-neutral ranking interface with timeout and budget;
   model output can reorder candidates but cannot add authority or facts.

Use conservative extractors, not pretend compiler completeness. Unsupported or
ambiguous syntax remains an explicit unknown.

Acceptance:
- small tasks find expected edit neighborhoods in all four languages;
- mutations incrementally invalidate/rebuild affected entries;
- generated/vendor/large/binary files respect bounds and policy;
- identical inputs produce byte-identical briefs;
- optional-model failure falls back deterministically;
- every current item resolves to a live source locator.
```

## Terminal F — first real validation profile: pytest

```text
Complete the first useful validation profile without weakening the sealed
Linux pytest contract. Depend on Terminal C's profile interface. Reuse existing
EffectIR, isolation, trace, candidate, shadow, promotion, and replay types.

Primary ownership:
- src/linux_pytest.rs and src/linux_pytest/*
- profile-specific store integration behind the linux-pytest feature
- qualification tests and evidence tooling

Deliver in reviewable checkpoints:
1. A foreground execute-only orchestrator for exactly admitted
   `.venv/bin/python -I -m pytest <selector>` calls.
2. Same-child workload-filter installation/verification, fixed-command release,
   tree supervision, bounded streams, EffectIR, cancellation, and final reap.
3. Immutable execute-only storage with every reuse/candidate field false.
4. Complete dependency/effect closure and typed execute-only/refusal reasons.
5. Independent primary and shadow records.
6. Separate compare-and-swap promotion after exact comparison.
7. Fresh local validation before a promoted hit and exact output replay.
8. Quarantine on divergence, corruption, incomplete capture, profile/runtime
   drift, and relevant mutation.
9. An advisory changed-only planner; uncertainty runs the broader safe selector.

Acceptance:
- native, execute-only, primary, shadow, promoted hit, and mutation outcomes
  are exact for the frozen profile;
- no stage can be skipped or inferred from another record;
- cancellation kills and reaps the complete tree;
- relevant mutation invalidates and proven-irrelevant mutation preserves;
- portable hosts return typed non-qualification;
- provisioned native x86_64 evidence remains a separate gate.
```

## Terminal G — paired two-agent integration and product gate

```text
Integrate the accepted substrate, context ledger, task-start API, automatic
router, code intelligence, and first validation profile. Do not invent
replacement abstractions during integration; fix contract conflicts at their
owning layer.

Primary ownership:
- integration glue after component commits land
- end-to-end and benchmark harnesses
- setup/doctor/stats/explain surfaces
- docs/STATUS.md and retained local reports

Build this real two-client scenario:
1. Agent A starts a task and receives a cold edit brief.
2. Agent A searches/reads; verified observations are admitted.
3. Agent B starts the same task and receives those facts, sources, and A's
   in-flight state without repeating physical observations.
4. Both request one eligible validation; one execution occurs and the other
   joins or retrieves it.
5. Agent A edits a relevant dependency.
6. Derived facts and validation invalidate; both recipients receive a delta.
7. Validation executes again; an unrelated edit preserves eligible results.

Measure baseline versus Again in independent identical worktrees:
- time to first correct edit and validated completion;
- physical tool/provider calls and duplicate investigations/executions;
- context/full-result bytes after acknowledged delivery;
- validation avoided, miss overhead, false hits, quarantines, and correctness.

Add diagnostics:
- doctor reports coordinator/profile readiness and exact blockers;
- stats separates observed, joined, promoted, served, invalidated, and saved;
- explain says why an action executed, joined, reused, bypassed, or refused;
- setup enables local integration without unsafe hook claims.

Acceptance:
- repeated paired runs have zero false hits and the same correct task outcome;
- claims use measured timings/counts and delivery receipts;
- warm improvement does not hide cold cost;
- local platform and undeployed-service limitations remain explicit;
- docs claim only behavior exercised by retained evidence.
```

## Terminal H — encrypted cross-machine team memory

```text
Start only after Terminal G's local gate is useful and stable. Productize
encrypted team distribution without letting remote state mint local authority.

Primary ownership:
- service/*
- src/team*, src/remote.rs, trust and provisioning modules
- team operations/security/evidence tests

Deliver:
1. Self-service repository/profile/root/key/trust/credential/generation
   provisioning with no repository secrets.
2. Production TLS D1/R2 deployment steps. Never accept Cloudflare Terms or
   choose production resources automatically.
3. Encrypted signed distribution of observations, context events, validations,
   promotions, and artifacts with privacy namespaces.
4. Allowlists, revocation, trust epochs, expiry, quotas, deletion, audit,
   monitoring, backup/recovery, and key rotation.
5. Cross-machine profile-equivalence proofs.
6. Fresh local dependency/profile/trust verification before every remote hit.
7. Secret-taint scans before publication and after decryption.

Acceptance:
- remote state never upgrades missing local observation/profile/recipient/trust
  or freshness authority;
- revocation, generation, and deletion races fail closed;
- tampered manifests/blobs/receipts/trust bundles are rejected;
- reuse works only for explicitly equivalent profiles;
- staging deployment and rollback are exercised;
- production stays blocked until an authorized human provisions resources.
```

## Integration lead checklist

After every wave:

1. Review each diff and rebase it onto the accepted base.
2. Confirm explicit refusal paths remain intact.
3. Run formatting, strict all-feature Clippy, locked all-feature tests, product
   E2E, chaos/corruption tests, and applicable qualification harnesses.
4. Resolve duplicate types/storage paths before the next wave.
5. Keep `docs/STATUS.md` evidence-backed and `docs/ROADMAP.md` future-facing.
6. Retain reports with exact source and binary identities.
7. Keep remote deployment claims separate from the local product claim.
