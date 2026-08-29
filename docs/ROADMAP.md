# Again product and delivery roadmap

This is the single roadmap for Again. It combines the product architecture,
reuse strategy, straight-to-code experience, delivery sequence, and release
gates. [STATUS.md](STATUS.md) remains the source of implementation truth and
[EVIDENCE.md](EVIDENCE.md) remains the source of measured claims. A roadmap
item is intent until those documents contain its passing evidence.

Historical Gate 0–6 names are retained below so release procedures, Linux
evidence, and older technical documents keep their original meaning.

## Product objective

> Again gives coding agents persistent, verified repository understanding and
> execution memory so they can move from task to correct code with less
> rediscovery, fewer tool calls, less context, and less repeated validation.

Again optimizes time and total cost per successful coding task. It is not a
generic command cache, a replacement coding agent, or an authority granted to
an LLM. Every repeated action is a reuse candidate; only a current
deterministic proof may turn it into a shortcut.

The target user outcome is:

> Again helps coding agents start with verified repository understanding, avoid
> repeating work, run only the validation that changed, and share exact
> execution knowledge across agents.

## Target user experience

```text
task arrives
  -> Again opens one current repository epoch
  -> Again registers the exact prompt as one durable task intent
  -> concurrent aliases join one leader instead of repeating orientation
  -> Again returns one bounded verified edit brief
  -> the agent inspects only unresolved details
  -> the agent makes the first correct edit
  -> Again invalidates affected knowledge
  -> uncertain or affected validation executes
  -> proven unaffected validation may reuse a promoted result
  -> findings, results, and artifacts become verified execution memory
  -> the next agent starts ahead
```

The task-start response is an edit brief, not a compulsory prose plan. It
contains current entry points, exact source locators, verified constraints,
invalidations, known failed approaches, explicit unknowns, and a proposed
validation set. It does not dump a full repository tree, repeat already
delivered output, or present model speculation as fact.

Exact prompt bytes within one repository, workspace, and authorization scope
resolve to one durable canonical task even when different agent clients supply
different external task IDs. Reusing an external ID for different prompt bytes
is refused. Similar prompts remain separate until an explicit deterministic
relationship is supplied; model similarity never grants task-convergence
authority.

## System architecture

```text
Codex / Claude / OpenCode / IDE / CI
                  |
          MCP and explicit CLI
                  |
   +--------------v----------------+
   | Agent acceleration gateway     |
   | task start | tool router       |
   | context delivery | validation  |
   | explanations | metrics         |
   +----------+------------+--------+
              |            |
       suggestions          | authority
              |            |
   +----------v----+  +----v--------------------+
   | Optional LLM  |  | Deterministic authority |
   | task intent   |  | repository epoch        |
   | relevance     |  | dependency/effect proof |
   | compression   |  | executable/toolchain    |
   +----------+----+  | policy/freshness/scope  |
              |       +------------+------------+
              +--------------------+
                                   |
                     +-------------v-------------+
                     | Verified execution memory |
                     | results | facts           |
                     | invalidations | failures  |
                     | candidates | promotions   |
                     | artifacts | receipts      |
                     | SQLite metadata + CAS     |
                     +-------------+-------------+
                                   |
                     +-------------v-------------+
                     | Execution providers       |
                     | repository/Git            |
                     | audited local reads       |
                     | isolated validation       |
                     | encrypted team service    |
                     +---------------------------+
```

The optional LLM interprets a task, ranks candidates, compresses verified
context, and suggests validation. It cannot declare a fact current, issue a
cache hit, skip a test, authorize artifact materialization, or upgrade remote
state. The deterministic authority layer owns those decisions.

## What the previous Again contributes

The new product is built on the working Again engine rather than replacing it.

| Existing subsystem | Current value | Role in the new product |
|---|---|---|
| Canonical tool-call gateway | Normalizes bounded MCP calls and provider identity | Common entrance for task-start, code intelligence, validation, and future providers |
| Fourteen local-alpha MCP tools | One deterministic task-start brief plus 13 exact repository/Git observations | Immediate agent orientation, source evidence, and reusable task context |
| Workspace execution epochs | Descriptor-retained repository authority | One current view shared by task-start and eligible tools |
| Scoped observation plans | Fingerprint only declared paths, trees, listings, identities, and Git state | Fine-grained invalidation instead of whole-repository cache eviction |
| Exact executable/profile checks | Bind reviewed executable and host semantics | Foundation for toolchain-specific validation profiles |
| SQLite coordination and CAS | Durable metadata, leases, events, and immutable streams | Shared execution memory for results, facts, validation, and artifacts |
| In-flight joining | Identical concurrent calls converge on one execution | Prevent duplicate work across simultaneous agents |
| Crash recovery and quarantine | Reclaims dead leases and refuses corrupt/divergent state | Required reliability boundary for all new reuse planes |
| Double-execution admission | Detects common nondeterminism before storing local reads | Early validation pattern; later test profiles use stronger shadow promotion |
| Digest memoization | Avoids rehashing unchanged filesystem objects | Core primitive for the shared manifest and incremental indexes |
| Exact `run`/`reference`/`show` | Reuse or retrieve narrow audited local command results | Explicit local compatibility path and exact-result delivery primitive |
| Universal tool policy | Separates exact reads, deterministic commands, freshness reads, mutations, credentials, communication, deployment, and payment | Prevents broader coverage from becoming unsafe generic caching |
| Typed reasoning context | Facts, invalidations, unknowns, observations, failures, suggestions, and delivery metrics | Data model for the task-start edit brief and cross-agent knowledge |
| Linux EffectIR foundations | Snapshot, isolation, trace, candidate, shadow, promotion, and replay contracts | Dependency authority for changed-only testing and later build reuse |
| Encrypted team foundation | Signed provenance, encrypted manifests, trust and revocation | Later cross-machine execution-memory distribution |

No new subsystem should rebuild storage, request canonicalization, coordination,
invalidation, delivery accounting, or corruption handling if the existing engine
can be safely generalized.

## Unified reuse architecture

Again uses multiple reuse planes on one control plane.

### Observation reuse

Repository reads, search, tree, stat, glob, manifests, and bounded Git
intelligence reuse exact results after fresh dependency validation. This is the
shipping beachhead.

### Knowledge reuse

Verified facts, completed investigations, failed approaches, explicit unknowns,
and invalidations are derived from exact observations. A fact carries source
references and repository, workspace, state, dependency, and authorization
bindings. A model-produced statement is a suggestion until admitted through
that deterministic path.

### Execution reuse

Tests, type checks, linters, and builds use profile-specific observers. The
first version of every profile is execute-only. Reuse requires a complete
immutable candidate, an independent shadow, a separate promotion record, and
fresh validation of the promoted dependency closure.

### Artifact reuse

Qualified build outputs become immutable content-addressed artifacts. Artifact
identity alone never authorizes materialization; the producing profile,
toolchain, configuration, environment, complete inputs, and destination/effect
contract must still match.

### Delivery reuse

An exact result or brief is delivered in full until the exact recipient,
session, turn, connection, compaction generation, and lifecycle authenticate
complete delivery. Only then may Again send a compact reference or delta.

### Team reuse

Encrypted remote storage distributes already qualified observations, results,
and artifacts across equivalent profiles. Remote signatures and ciphertext can
never compensate for missing local validation authority.

## Cache hierarchy

```text
L0  active in-flight work
    identical concurrent calls join one physical execution

L1  process-hot verified view
    current repository epoch, descriptor handles, prepared statements,
    current manifest nodes, and bounded indexes

L2  local durable execution memory
    SQLite metadata, immutable CAS streams/artifacts, facts, invalidations,
    candidates, promotions, receipts, and metrics

L3  optional local shared service
    multiple agent sessions share one same-user coordinator without weakening
    workspace or recipient identity

L4  encrypted team service
    cross-machine distribution with signatures, trust, revocation, privacy,
    profile equivalence, quotas, and local verification
```

Every layer may improve lookup latency. None may mint authority that the layer
below does not possess.

## Universal request lifecycle

```text
agent action
  -> canonical request and capability class
  -> profile-specific dependency/effect plan
  -> current repository/runtime observation
  -> exact candidate lookup
       |- active equivalent call -> join
       |- fresh promoted result  -> serve
       `- absent or uncertain    -> execute normally
  -> immutable result or execute-only record
  -> optional independent shadow
  -> separate promotion
  -> provenance and invalidation edges
  -> recipient-safe presentation
  -> task-level cost and quality accounting
```

Unknown reusable state falls back to normal execution where that execution is
safe. Dangerous executable configuration may require refusal. Mutations,
credentials, communication, deployment, payment, and unknown external effects
bypass result reuse.

## Reuse identity

A profile binds the relevant subset of:

- repository, workspace, and task identity;
- canonical provider/tool/request/arguments;
- repository paths, trees, Git state, and filesystem-object epochs;
- executable, interpreter, compiler, toolchain, and provider bytes;
- environment, runtime context, platform, and isolation profile;
- configuration, plugins, manifests, lockfiles, and generated inputs;
- observed dependency and effect closure;
- authorization and privacy scope;
- policy, schema, and profile versions;
- exact stdout, stderr, wait status, diagnostics, or artifact manifests.

A command string, basename, content digest, provider annotation, embedding
match, or LLM judgment is never sufficient by itself.

## Shared repository manifest and invalidation

The largest common cost is the fresh authoritative filesystem view. The target
implementation extends the existing workspace epoch, observation plans, and
digest memoization:

1. Open and retain bounded directory descriptors from one workspace epoch.
2. Build a sealed observed manifest containing only nodes required by current
   operations, not an unconditional whole-repository snapshot.
3. Reuse parent directory descriptors and verified unchanged-node digests
   across repository tools in the same epoch.
4. Record result-to-node and fact-to-result dependency edges.
5. On mutation, create a new epoch and revalidate changed nodes plus required
   ancestors.
6. Retire only results, facts, indexes, validations, and artifacts reachable
   from changed or uncertain dependencies.
7. Require a final fresh fence before serving a hit; an old sealed manifest
   cannot authorize a new epoch.

This accelerates both the previous exact-tool cache and the new task-start
brief. It requires no external account or hosted service.

## Optional LLM acceleration

Again supports three modes:

1. **Deterministic-only:** lexical/path/symbol indexes and verified facts; fully
   local and offline.
2. **Fast-model assisted:** a local or inexpensive hosted model interprets the
   task, ranks candidates, compresses context, and suggests validation.
3. **Coding-model integrated:** the primary coding model receives the verified
   brief and concentrates on design, editing, and debugging.

The task-start path must have a deterministic fallback. Optional model work has
a strict latency, token, privacy, and dollar budget; timeout or refusal returns
the verified local subset plus explicit unknowns. Model suggestions may be
memoized by model identity, prompt-template digest, parameters, and exact input
digest, but remain non-authoritative suggestions after reuse.

The intended economics are:

```text
deterministic code handles truth and reuse
  -> cheap model handles ranking and compression
  -> powerful model spends tokens on coding decisions
```

## Action-family coverage

| Action family | Target treatment |
|---|---|
| File content, metadata, search, tree, glob | Exact snapshot-bound observation reuse |
| Git status, diff, log, show, blame | Exact Git-state reuse with configuration/executable fences |
| Symbols, definitions, references, imports | Deterministic derived observations over fixed parser/server bytes |
| Repository/task facts and investigations | Source-bound knowledge reuse with explicit invalidation |
| Type checks, diagnostics, lint check mode | Profile-specific exact execution reuse |
| Pytest, Cargo tests, Go tests, Jest/Vitest | Changed-only execution and promoted-result reuse |
| Formatting checks | Check-only deterministic profile; write mode is mutation |
| Dependency/build graph queries | Manifest/lock/toolchain/configuration-bound observation reuse |
| Builds | Diagnostics first, then qualified immutable artifact reuse |
| Edits, renames, deletes, generated-source writes | Execute and invalidate; no ordinary replay |
| Installs and environment changes | Explicit state transition; no generic cache hit |
| Watchers, servers, REPLs, debuggers | Interactive passthrough |
| Credentials, communication, deployment, payment | Bypass reusable storage and never replay side effects |

The exhaustive profile inventory remains in [REUSE_SURFACE.md](REUSE_SURFACE.md).

## Product scorecard

The primary unit is a successful coding task. Paired evaluation freezes the
agent/model, repository snapshot, task, permissions, limits, and acceptance
rubric.

Primary measures:

- time to the first edit retained in the accepted patch;
- end-to-end time to a validated task result;
- pre-edit tool calls, provider executions, unique files, and bytes read;
- provider-reported input/output tokens;
- validation processes and compute time;
- total metered model, provider, and compute cost;
- accepted task and patch-quality outcome.

Guardrails:

- zero known incorrect hits and stale facts presented as current;
- no required-validation or patch-quality regression;
- every skipped execution has a consumable proof and explanation;
- cold, warm, miss, invalidation, compaction, corruption, cancellation, and
  recovery cases remain visible;
- trivial work bypasses Again when verification has negative value;
- optional model cost and latency are included rather than hidden.

Initial public product targets, not current claims:

- at least 30% median reduction in time to the first correct edit;
- at least 20% median reduction in end-to-end validated task time;
- at least 20% median reduction in total metered task cost;
- at least 30% redundant repository/provider calls avoided on the repeat-heavy
  beachhead cohort;
- zero incorrect hits across every qualifying paired run.

A showcase cohort may target 2x or greater acceleration, but it cannot replace
the diverse-repository product gate.

## Delivery sequence

Paste-ready workstream prompts, dependency ordering, ownership boundaries, and
acceptance gates for this sequence live in
[`IMPLEMENTATION_PROMPTS.md`](IMPLEMENTATION_PROMPTS.md). The first product
milestone is a paired local two-agent flow in which verified observations and
in-flight work are shared, an eligible command executes once, and a relevant
mutation invalidates both derived context and execution memory.

Current priority order after the local paired gate:

1. Make the same-user daemon and task-start flow installable and automatic for
   supported agent clients, with a clean upgrade/recovery path.
2. Run and retain pinned live-agent editable cohorts so the task-quality and
   acceleration claims are based on real Codex/Claude outcomes.
3. Add explicit task revision, parent/child, dependency, and completion records
   without silently merging semantically similar prompts.
4. Finish the qualified Linux pytest execution path, then admit changed-only
   reuse through the existing candidate/shadow/promotion contract.
5. Extend qualified validation to Rust, TypeScript, Go, and Python before
   materializing immutable build artifacts.
6. Productize encrypted cross-machine coordination only after the local
   installation, quality, and validation gates are stable.

### Phase 0 — retain the working exact-reuse foundation

Status: implemented local foundation; outside qualification remains open.

Preserve:

- default MCP repository/Git tools and explicit CLI behavior;
- exact output and request/dependency bindings;
- in-flight joins, leases, recovery, quarantine, and metrics;
- fail-closed executable/profile checks;
- empty-by-default experimental features;
- existing release, evidence, and security boundaries.

Exit:

- no regression in current product E2E, chaos, four-language, formatting,
  Clippy, test, packaging, and corruption gates;
- current benchmark artifacts are reproducible on the candidate binary; and
- every new layer uses rather than forks the existing execution-memory core.

### Phase 1 — universal hot reuse substrate

Goal: make the existing cache fast and general enough to support the edit brief
and later validation profiles.

Status: core implementation landed in Wave 1 through `45b0284`; the deterministic
paired product gate is implemented. Hosted and diverse-repository performance
qualification remain release work.

Work:

- add a sealed per-epoch observed manifest;
- reuse parent directory descriptors and unchanged-node digests;
- add dependency-to-result/fact invalidation indexes;
- introduce profile-private adapters around common canonicalization,
  coordination, CAS, quarantine, and accounting;
- add a value model that bypasses lookup for trivial negative-value work;
- benchmark cold/warm 1k, 10k, large-byte, mutation, and concurrent workloads.

Exit:

- exact bytes and zero-false-hit behavior remain unchanged;
- relevant mutation invalidates and proven-irrelevant mutation preserves hits;
- one repository epoch can serve multiple eligible operations without duplicate
  full traversal;
- benchmarked hot paths materially improve without hiding cold cost; and
- no persistent manifest becomes authority without a fresh epoch fence.

### Phase 2 — straight-to-code task start

Goal: replace broad agent orientation with one bounded verified edit brief.

Status: implemented locally through the durable ledger, same-user coordinator,
public task/context tools, bounded code-intelligence index, paired-client gate,
durable diagnostics, and an editable paired benchmark. Its offline oracle is
qualified; pinned live-agent task-quality evidence remains open.

The coordinator now persists exact agent-supplied prompts as unverified task
intent, resolves exact-prompt aliases onto one canonical task across daemon
restarts, refuses conflicting reuse of a task ID, automatically elects one
bounded task leader, exposes owner-authenticated lease renewal, and retires
leadership with the recipient lifecycle. Canonical tasks and aliases are both
bounded and corruption-checked on open.

Work:

- admit typed facts from exact built-in tool observations;
- implement bounded file-symbol, definition, and reference indexes;
- select deterministic task-relevant candidates;
- create a purpose-specific edit-brief compiler smaller than the internal
  general reasoning brief;
- expose one workspace-bound task-start MCP route;
- persist exact task intent and automatically converge duplicate starts;
- attach invalidations, unknowns, failed approaches, source locators,
  retrieval references, and validation preview;
- update agent setup so a task begins with one brief, not a forced prose plan.

Exit:

- every presented current fact resolves to live verified sources;
- invalid or contradictory sources fail closed or appear explicitly invalidated;
- the route is bounded and has a deterministic model-free fallback;
- cold and hot task-start latency, bytes, and tool-call displacement are
  measured; and
- no semantic ranking result grants current-fact or reuse authority.

### Phase 3 — optional LLM ranking and authenticated context delta

Goal: use models for relevance without paying repeatedly for rediscovery or
weakening truth.

Status: authenticated local recipient issuance, full retrieval, write/flush
receipts, compact delivery, deltas, and lifecycle retirement are implemented.
Optional model usage and provider-reported cost/token measurements remain open.

Work:

- add provider-neutral optional ranking/compression with strict budgets;
- bind model suggestions to model, template, parameters, and exact input;
- add transport-authenticated recipient issuance;
- expose recipient-bound full retrieval grants;
- record complete-response write/flush receipts;
- deliver compact references or deltas only within the same active,
  uncompacted recipient context;
- retire authority on disconnect, cancellation, restart, compaction, or
  lifecycle change.

Exit:

- model timeout/failure falls back without blocking the agent;
- full output remains available and exact;
- duplicate envelopes do not double-count savings;
- no bearer result ID grants retrieval;
- token/cost claims use provider-reported usage from paired runs; and
- sensitive task/context data remains local unless explicitly configured.

### Phase 4 — editable real-agent product gate

Goal: prove Again reduces planning and coding time, not merely tool latency.

Status: the bounded editable harness, exact patch oracle, collateral-mutation
refusal, balanced ordering, monotonic timing markers, durable-product-activity
check, and retained offline qualification are implemented. Live Codex/Claude
cohorts, diverse repositories, provider usage, patch rubrics, and outside-user
evidence remain open; no acceleration claim exists yet.

Work:

- extend the existing real-agent harness from read-only tasks to editable tasks
  in independent identical worktrees;
- retain monotonic task, first-tool, first-edit, accepted-edit, validation, and
  final-outcome markers;
- use fixed acceptance tests and patch-quality rubrics;
- run Codex and Claude baseline/Again pairs with treatment order balancing;
- report cold, hot, changed, compaction, model-assisted, and deterministic
  cohorts separately.

Exit:

- the initial public product targets above pass on diverse real repositories;
- no task outcome, validation, or patch-quality regression occurs;
- raw paired events and provider usage are retained; and
- outside-user evidence closes the applicable local-alpha gate.

### Phase 5 — changed-only pytest

Goal: execute uncertain tests and reuse only promoted unaffected results.

Work:

- complete one real `.venv/bin/python -I -m pytest <selector>` execute-only
  profile on qualified Linux;
- bind snapshot, interpreter/runtime closure, configuration/plugins,
  environment, descendants, reads, effects, streams, wait status, and cleanup;
- build immutable primary candidates;
- run independent shadows and store separate promotion rows;
- derive a validation plan from the observed dependency closure;
- freshly revalidate every proposed hit.

Exit:

- unsupported/incomplete observations remain execute-only;
- zero unexplained divergences in the frozen shadow corpus;
- no candidate exists without connector completion and cleanup evidence;
- affected tests execute and only proven-unaffected tests reuse; and
- exact status/stdout/stderr and required effects match the native outcome.

### Phase 6 — polyglot validation and build artifacts

Goal: extend the same private-profile machinery rather than creating ecosystem
specific caches.

Order:

1. Rust: Cargo check, exact tests, Clippy, and formatter check.
2. TypeScript/JavaScript: `tsc --noEmit`, Jest/Vitest, ESLint check.
3. Go: exact `go test`, vet, and build profiles.
4. Python: Ruff, mypy, and broader qualified test shapes.
5. Immutable build artifacts produced by the qualified profiles.

Exit for each profile:

- executable/toolchain/configuration/plugin/lock/generated-input and complete
  observed dependency bindings are closed;
- execute-only, candidate, shadow, promotion, invalidation, and hit tests pass;
- native and Again outcomes are exact for the admitted surface;
- miss overhead and artifact materialization cost are measured; and
- adding the profile does not expose a generic arbitrary-command launcher.

### Phase 7 — managed cross-agent and team execution memory

Goal: share verified observations, knowledge, validation, and artifacts across
agents and equivalent machines.

Work:

- productize local multi-session recipient identity and coordination;
- deploy the encrypted service behind production TLS;
- add self-service repository/profile/key/trust provisioning;
- enforce signed producers, revocation, privacy, generation lifecycle, quotas,
  audit, deletion, monitoring, backup, and recovery;
- prove cross-machine execution-profile equivalence;
- retain local verification before every remote hit;
- validate with design partners before broad availability.

Exit:

- no remote state upgrades missing local authority;
- cross-machine exactness and revocation races pass;
- secret-tainted data cannot be shared;
- production operations and independent security review close; and
- team task-level time/cost improvement passes the paired product gate.

## Historical gate compatibility

### Gate 0 — restore evidence authority

Historical meaning: make claims follow reproducible local or immutable hosted
evidence. This remains a permanent rule and is represented by Phase 0 and the
product scorecard.

### Gate 1 — distributable local alpha

Historical meaning: signed/installable local product plus outside-user exactness
and speed evidence. It now spans Phase 0 qualification and the outside-user
portion of Phase 4. The current local four-language pass does not substitute for
outside evidence.

### Gate 2 — kernel-backed supervisor tree proof

Historical meaning: the fixed command-free Linux supervisor transport proof.
Its retained evidence remains valid and narrow. It grants no pytest, profile,
execution, candidate, or reuse authority.

### Gate 3 — first execute-only pytest product slice

Historical meaning: one real pytest selector executes through the qualified
Linux profile while all candidate/shadow/promotion/reuse fields remain false.
This is the first half of Phase 5.

### Gate 4 — complete candidate construction

Historical meaning: a completed foreground execution becomes an immutable
candidate after complete semantic observation and cleanup. This is a Phase 5
subgate and still grants no hit.

### Gate 5 — shadow, promotion, and local pytest reuse

Historical meaning: independent primary/shadow agreement, separate promotion,
fresh validation, and exact local pytest reuse. This closes Phase 5.

### Gate 6 — managed team alpha

Historical meaning: deployed, provisioned, encrypted, signed, revocable,
equivalent-profile team reuse with operational evidence. It is Phase 7 and may
begin only after the relevant local-product and local-reuse gates pass.

## Release discipline

Every release candidate must:

- pass pinned formatting, strict Clippy, locked tests, packaging, service, and
  applicable 100,000-case differential gates;
- retain exact source, binary, environment, benchmark, and report identities;
- distinguish local observations, immutable hosted evidence, expected platform
  refusals, and unexecuted plans;
- preserve failing and superseded evidence instead of overwriting it;
- keep experimental commands behind empty-by-default features;
- report cold/miss overhead beside warm savings;
- make no token, cost, coding-quality, or cross-machine claim without the
  corresponding direct gate; and
- refuse release if documentation claims exceed [STATUS.md](STATUS.md) or
  [EVIDENCE.md](EVIDENCE.md).

## Working documents

- [PRODUCT.md](PRODUCT.md): shipping promise and current boundary.
- [AGENT_ACCELERATION.md](AGENT_ACCELERATION.md): complete user loop and product
  scorecard.
- [STRAIGHT_TO_CODE.md](STRAIGHT_TO_CODE.md): edit-brief fast path and editable
  task evaluation.
- [REUSE_SURFACE.md](REUSE_SURFACE.md): action-family and validation-profile
  inventory.
- [ARCHITECTURE.md](ARCHITECTURE.md): authority transitions and current/target
  component boundaries.
- [STATUS.md](STATUS.md): what is implemented.
- [EVIDENCE.md](EVIDENCE.md): what has been measured.
- [DEVELOPMENT_WORKSTREAMS.md](DEVELOPMENT_WORKSTREAMS.md): terminal ownership
  and merge discipline.
