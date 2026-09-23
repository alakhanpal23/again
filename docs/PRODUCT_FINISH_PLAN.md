# Product finish plan

This is the execution checklist for making Again a usable agent acceleration
product without relying on new-user recruitment. The unit of success is a
correct, validated coding task completed by Codex or Claude. Cache hits alone
are not success. `STATUS.md` records what has actually passed; this plan does
not grant reuse authority or supersede the closed profiles in `REUSE_SURFACE.md`.

## Release contract

A supported local installation must let two agent sessions in one repository:

1. start or join an exact durable task and receive a bounded current edit brief;
2. share verified source-backed discoveries and explicit unknowns;
3. avoid a redundant eligible repository read by a fresh exact hit or an
   in-flight join, while executing an unsafe or unproven action normally;
4. receive precise invalidation after a relevant edit and preserve verified
   unaffected results after an unrelated edit;
5. retrieve full results after a compact response, with recipient delivery
   scoped to the active connection and compaction generation; and
6. finish with the same accepted patch and required validation as the native
   agent workflow.

The default product must work with documented Codex and Claude installations.
The shell hook cannot transparently rewrite arbitrary calls until the client
supplies effective workdir, TTY, shell, sandbox, environment, and delivery
context. The supported entrance is the authenticated workspace MCP daemon;
`again run` remains the explicit audited local-command entrance. Never turn a
tool name, model statement, result ID, or digest into reuse authority.

## Work in dependency order

### 1. Make the product reachable

- Make one supported setup flow install and inspect the Again MCP entry and the
  agent instructions for each client. Verify the exact binary, workspace,
  protocol version, daemon readiness, and clean restart/upgrade behavior.
- Make task-start, context delta, retrieval, and the thirteen repository/Git
  tools discoverable in the actual agent session. Show bounded recovery advice
  if the daemon or client integration is unavailable.
- Exercise installation, removal, two simultaneous clients, restart, stale
  binary, conflicting configuration, cancellation, and noninteractive client
  approval modes in clean isolated homes.
- Move the production-binary product E2E harness onto authenticated task
  sessions. Its standalone `repo.*` scenarios still require stored result IDs,
  but standalone reads now execute directly by design. Start a task before
  testing exact reuse, shared facts, and retrieval; retain separate assertions
  that standalone cheap reads bypass storage. Bind the passing report to a
  clean source SHA and exact binary.
- The daemon-backed task harness now covers recipient-scoped cancellation,
  corrupt-result refusal and quarantine, and a killed daemon's lease expiry
  and recovery, alongside its shared-source and large-index scenarios. Its
  clean-source release-binary report is
  `bench/results/2026-09-23-auth-product-e2e-lifecycle-v2.json`. The beta
  aggregator now requires this report; qualify in-flight request
  cancellation separately. Keep the old standalone harness as historical
  evidence for scenarios it still covers uniquely.

**Exit evidence:** release-binary onboarding run for Codex and Claude; a real
agent can call `task.start` and a repository tool through the installed server.
No manual editing of agent configuration is needed.

### 2. Finish exact work avoidance

- Capture actual Codex/Claude traces and rank repeated read-only call shapes by
  elapsed time, frequency, bytes, and pre-edit contribution. Add an adapter
  only after specifying canonical request, complete dependency and executable
  observations, effects, limits, and post-hit validation.
- Wire the measured reuse-value decision into the live gateway. Bypass storage
  for cheap work whose lookup and fresh validation cost more than execution.
  Keep that decision separate from the proof needed to return a hit.
- Decouple verified task facts from cache hits. A direct built-in read should
  still be able to publish source-backed context and invalidate stale facts;
  the active-task cache can then refuse slow hit paths without losing shared
  context. The authenticated one-file and 1,000-file probes in `bench/results`
  currently show slower warm repository reuse despite fewer executions.
- Measure shared-manifest traversal, result lookup, join latency, cold miss
  overhead, relevant and irrelevant mutation cost, and response bytes on
  1k/10k-file and large-output fixtures. Optimize the dominant measured path.
- Remove the measured warm direct-call authority-check overhead with a shared
  invalidation generation or equivalent fast proof that remains correct across
  connections, restarts, and separate store handles. Preserve the cross-task
  recovery test and compare against execute-only on cheap calls.
- Keep mutations, credentials, communication, network freshness, interactive
  work, and unknown tools on the normal execution path. Add closed profiles for
  more deterministic actions only when complete observations are possible.

**Exit evidence:** exact streams and zero incorrect hits in adversarial and
four-language corpora; concurrent duplicates execute once; measured warm
latency wins without material cold-task regression. Every avoided execution
has a persisted proof and an `explain` reason.

### 3. Finish shared context and task behavior

- Derive current facts and source locators only from admitted built-in tool
  observations. Keep agent prose marked as suggestions, and expose source and
  dependency evidence in task-start and delta responses.
- Complete durable task revision, parent, dependency, claim, transition,
  retention, quota, and recovery behavior across processes. Update the roadmap
  where it still describes already-landed lifecycle work as future work.
- Test full-before-compact delivery, exact recipient retrieval, disconnect,
  cancellation, compaction, restart, relevant/irrelevant edits, corrupt store,
  quota exhaustion, and two agents publishing at the same time.
- Qualify the new source-recipe reobservation across every built-in repository
  and Git tool, relevant and irrelevant edits, daemon restart, quota limits,
  concurrent mutation, and large task ledgers. Task-start now returns an
  incomplete brief at the 256-source scan bound, and context delta withholds
  events at the same bound. The 257-source release-binary gate now covers both;
  qualify concurrent mutation and larger real task ledgers next.
  Retain atomic, scope-bound cross-task retirement.
- Keep task-start local and bounded. An unavailable index returns an explicit
  incomplete brief quickly; validation preview never declares a test skippable
  without a qualified execution profile.
- Preserve useful entry points when the source inventory exceeds the code
  index budget. The fast fallback can preview a small explicit task path;
  measure whether real agents use it to avoid reads and whether omitted
  candidates hurt accepted-edit quality on large repositories.
- Reduce the roughly two-second task-start index time on 1,000-file
  repositories without dropping useful candidates. A 150 ms synchronous
  budget returned zero candidates in the local control and was reverted;
  investigate bounded filename routing or background index publication with
  fresh source validation before using that cutoff.
- Qualify the opt-in named-file preview route against the full-index path on
  real accepted edits. It saves about two seconds on the local 1,000-file
  task-start diagnostic, but the broader candidate list is explicitly
  incomplete; retain the full-index route when no complete explicit preview
  was requested. The first live Codex pair on that fixture passed both edit
  oracles and reached the first edit in 15.0 seconds with Again versus 18.3
  seconds in the baseline, but finished in 60.4 versus 25.7 seconds and used
  260k versus 124k input tokens. The Again trace shows two failed follow-up
  calls and additional post-edit inspection. See
  `bench/results/2026-09-23-codex-1k-preview-pair-v1.json` and its raw JSONL
  events. The root-path and Git-status overflow defects from that trace have
  focused regression coverage. A clean-source repeat on the fixed binary
  removed both tool failures and passed the edit oracle, but still finished
  in 46.7 seconds versus 20.7 seconds baseline, with 204k versus 107k input
  tokens and zero exact hits. First edit was 19.1 versus 12.9 seconds. See
  `bench/results/2026-09-23-codex-1k-preview-pair-fixed-v1.json`. The agent
  read directory listings and README after editing to choose validation;
  task-start supplied an explicit source preview but no proven test selector.
  Measure the value of validation guidance and post-edit calls next.
  The bounded Python test-path candidate preview now fills the second preview
  slot when the task requests tests and a matching `tests/test_<stem>.py`
  exists. It is labeled unverified relevance and does not change the
  execute-required validation policy. In one further live Codex pair, Again
  used both previews, made zero follow-up repository calls, and finished in
  21.6 seconds versus 19.7 seconds baseline with 122k versus 99k input
  tokens. Both edits passed. See
  `bench/results/2026-09-23-codex-1k-test-preview-pair-v1.json` and raw events.
  This is still one unbalanced pair, and the task-level speed target remains
  unmet; run a balanced repeat-heavy cohort before treating the change as a
  reliable gain.

**Exit evidence:** the paired real-client flow satisfies all six release
contract steps. No stale fact is presented as current and no context reference
is usable by an unauthenticated or retired recipient.

### 4. Add changed-only validation behind separate profiles

- Finish the Linux pytest execute-only route on a provisioned, qualified
  kernel tuple: same-child filter installation, fixed command release, complete
  post-release task-tree supervision, streams, effects, and terminal cleanup.
- Only then build immutable candidates, independent shadows, promotion, and
  fresh dependency validation for hits. Add profile-specific Rust, TypeScript,
  Go, and Python checks in that order after each execute-only path is proven.
- Treat an unqualified host as execute-only or normal passthrough. Do not claim
  that a recognized command shape or the command-free Linux diagnostics can
  skip validation.

**Exit evidence:** changed tests execute, proven-unaffected tests reuse, and
status/streams/required effects match native runs; divergence quarantines the
candidate. Hosted and provisioned evidence is bound to exact source and binary.

### 5. Prove task-level benefit with existing users and controlled agents

- Run balanced baseline/Again editable pairs on identical repository snapshots
  with pinned Codex and Claude binaries, models, settings, permissions, time
  limits, and acceptance rubrics. Include cold, hot, mutated, parallel-agent,
  and compaction cohorts. Preserve raw events and provider-reported usage.
- Report first accepted edit, validated completion, redundant calls avoided,
  physical executions, validation processes, context bytes, tokens, and total
  metered cost. Count misses, refusals, stale candidates, and corruptions in
  the denominator. Use real agent sessions; the offline reference editor is
  only a harness check.
- Tune the expensive path that the paired traces identify, then rerun the
  frozen cohort. Do not tune only the showcase fixture.

**Exit evidence:** zero incorrect hits and no patch or validation regression;
the roadmap targets are met on the repeat-heavy cohort: 30% fewer redundant
repository/provider calls, 30% faster first accepted edit, 20% faster
validated completion, and 20% lower total metered task cost. If a target is
missed, publish the measured result and keep optimizing.

### 6. Release and operate

- Pass format, strict Clippy, locked tests, adversarial corpus, service tests,
  product E2E, four-language corpus, and the provisioned Linux gate on the
  exact candidate SHA. Retain artifacts and independently verify the release.
- Publish signed native packages with installer rollback tests. Run a clean
  install and the complete two-agent scenario using only release artifacts.
- Update `README.md`, `PRODUCT.md`, `STATUS.md`, `REUSE_SURFACE.md`, and
  `STRAIGHT_TO_CODE.md` from observed behavior; several current-state sections
  still describe earlier phases. Document current platform/profile limits.
- For the team path, deploy and qualify authenticated service operations,
  provisioning, revocation, quotas, deletion, recovery, abuse controls, and
  cross-machine exactness before calling it a managed team product.

**Exit evidence:** a reproducible release, a current operational runbook, and
one evidence index linking every public claim to an exact-SHA run. New-user
recruitment is outside this plan; existing-user and controlled-agent product
qualification remain required.
