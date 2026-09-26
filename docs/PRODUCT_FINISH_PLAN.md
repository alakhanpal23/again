# Product finish plan

This is the execution checklist for making Again a usable agent acceleration
product without relying on new-user recruitment. The unit of success is a
correct, validated coding task completed by Codex or Claude. Cache hits alone
are not success. `STATUS.md` records what has actually passed; this plan does
not grant reuse authority or supersede the closed profiles in `REUSE_SURFACE.md`.

The near-term release scope is now the [single-agent product plan](SINGLE_AGENT_PRODUCT_PLAN.md).
The two-agent contract below is a later extension; it is not a prerequisite
for proving that Again makes one agent faster and better.

## Near-term release contract

A supported local installation must let one agent:

1. start a task with a bounded, current repository brief;
2. inspect relevant knowledge retained from previous tasks, with source,
   freshness, and uncertainty visible;
3. produce a correct edit with less repeated investigation and context;
4. select and run required validation, reusing a result only with qualified
   proof; and
5. complete faster and at lower total cost than the same agent without Again
   on the frozen balanced task cohort.

The [single-agent product plan](SINGLE_AGENT_PRODUCT_PLAN.md) defines the
dependency order and gates for this contract.

## Later two-agent release contract

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
  aggregator now requires this report. The authenticated harness also covers
  an in-flight follower cancellation with one surviving leader execution;
  two clean-source release-binary runs at `110bf88` passed. Keep the old
  standalone harness as historical
  evidence for scenarios it still covers uniquely.

**Exit evidence:** release-binary onboarding run for Codex and Claude; a real
agent can call `task.start` and a repository tool through the installed server.
No manual editing of agent configuration is needed.

### 2. Finish exact work avoidance

The [hot-path architecture decision](HOT_PATH_ARCHITECTURE_DECISION.md) defines
the separate observation and work-avoidance lanes and the evidence required
before changing default routing.

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
  context. Task-bound `repo.stat` and `repo.read` of files up to 8 KiB now have
  this direct-observation path, with
  a separate durable origin that grants no cache or retrieval authority. The
  clean-source authenticated release-binary gate at `69d4ffd` passed peer
  visibility and edit invalidation. Extend the route to other built-ins only
  after a complete cheap observation is proven. The authenticated one-file
  and 1,000-file probes in `bench/results` still show slower warm repository
  reuse despite fewer executions.
- Measure shared-manifest traversal, result lookup, join latency, cold miss
  overhead, relevant and irrelevant mutation cost, and response bytes on
  1k/10k-file and large-output fixtures. The code index now uses a separate
  observed manifest over the same workspace epoch, so its witnesses do not
  add work to each repository/Git proof. The matched 1k-file release-binary
  trial reduced cold admission while retaining full-result references and
  source invalidation. Qualify this on clean source and additional workloads;
  remaining broad first-call scans are still expensive.
- Task-start's proven source-inventory overflow now routes broad repository
  tools with overflowing requested subtrees and Git status directly. Smaller
  subtrees retain in-flight joins. The 10k-file trial cut their multi-second
  first-call admission while retaining fresh provider execution. This route
  withholds a full-result ID for broad calls. Overflowing searches can now
  admit at most two file-backed matches as task facts, with source-recipe
  revalidation and relevant-edit retirement; absence and complete search
  output are still unknown. The clean-source release-binary lifecycle gate at
  `5c88120` passed peer delivery and retirement. Qualify real task outcomes,
  then add a complete cheap change signal before promising exact
  reuse for full broad results on large repositories.
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
  repositories without dropping useful candidates. A 512-file manifest batch
  brought the local release-binary median to 0.964 seconds from 2.220 seconds
  and removed the parse-time unknown while retaining 24 candidates. This still
  needs clean-source release and real-task validation. A 150 ms synchronous
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
  A reverse-order pair on the same fixture also passed both edit oracles but
  finished in 24.5 seconds with Again versus 22.0 seconds baseline, using
  150k versus 98k input tokens. Again made no repository follow-up calls, but
  its first test command used unavailable `python` before succeeding with
  `python3`. See
  `bench/results/2026-09-23-codex-1k-test-preview-reverse-v1.json`.
  These two opposing orders still show no task-level acceleration; move the
  controlled evaluation to repeat-heavy and parallel-agent tasks.
  Two current-binary Codex pairs after the index-batch change again passed
  both edit oracles and avoided follow-up repository reads, but reached the
  first edit later than baseline in both orders. A one-tool diagnostic MCP
  surface did not improve the result. Measure the content and model-turn cost
  of the task-start brief before changing production tool discovery, and run
  the repeat-heavy parallel cohort rather than extrapolating from this edit.
  `again mcp brief` uses a preview-only task start. `again codex` puts complete
  source previews and bounded current shared findings into the initial prompt,
  then holds and renews its elected leader lease for the Codex process. The
  agent's own MCP connection remains available, and an observed peer leader
  prompts an authenticated join before duplicated work.
  The first wrapper prompt induced a redundant `task.start` and regressed
  latency; the corrected prompt avoided that call in both live treatment
  orders and passed the edit oracle with faster first edit and completion on
  the same 1,000-file fixture. These remain local diagnostics. Run a balanced
  repeat-heavy parallel cohort and a live peer-leader handoff, including
  mutation between prebrief and first edit.
  A two-Codex committed-fixture diagnostic now covers both condition orders.
  The first follower implementation joined but sometimes spent another model
  turn and repeated inspections, so validated completion was mixed. Delaying
  an exact duplicate follower until the leader exited cut tokens by more than
  half in both local orders while preserving the accepted repair. The launcher
  now waits up to a bounded 30 seconds and refreshes its brief before taking
  over. A clean release-binary launcher gate verified a source mutation during
  the wait, and both treatment orders of the live two-agent fixture used the
  default wait with accepted repairs and lower input tokens. The launcher gate
  now also tests a leader outliving a one-second wait. Expand this beyond the
  one calculator fixture and keep independent subtasks parallel.
  `again claude` now uses the same launcher lifecycle with a per-invocation
  workspace MCP configuration in noninteractive print mode. Its release gate
  can verify argv and lease behavior with a fake executable, but a live Claude
  CLI is unavailable on the current host. Run the accepted-edit and token
  cohort on a host with an installed, authenticated Claude Code binary before
  claiming both supported clients meet the task-level targets.

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
