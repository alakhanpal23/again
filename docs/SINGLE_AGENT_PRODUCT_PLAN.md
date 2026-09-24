# Single-agent product plan

## Goal and scope

Again should help one coding agent reach a correct, validated change faster and
at lower total cost than the same agent without Again. It should remain useful
on the first task in a repository and improve as it learns the repository.
Parallel coordination and cross-machine sharing are later extensions of the
same knowledge model, not requirements for this release.

## Default product decision (2026-09-24)

The supported user path should be `again codex` followed by ordinary Codex
shell and editor tools. The launcher supplies a small verified brief and
automatically observes completed work; Brain supplies source-current context
to a later task. The installed skill should not make every cheap read or search
an Again gateway call. Warm proof and lookup have been slower than direct
execution on several measured repository calls, and native shell is the
agent's normal workflow. Keep `again run`, `repo.*`, and `git.*` available for
explicit, measured cases with useful exact-result or shared-context value.

The next product gate should use a **frozen real-task cohort**, not another
single showcase repair. Before running it, pin at least three repositories,
their pre-fix commits, independent edit and test oracles, model/client version,
approval settings, task text, prior-Brain seeding, and a rate card. Include bug
fixes and feature edits, small and large repositories, cold and returning
tasks, and both treatment orders. Count prebrief and prior-observation setup
time in the corresponding user journey; report returning-task benefit
separately if that setup is amortized. Retain exact source/build binding,
raw event digests, accepted patches, agent-run required tests, elapsed time,
first edit, post-edit time, command executions, tokens, and cost. An incomplete
or failed task stays in the denominator. The release decision requires the
full cohort to meet the existing 20% median completion-time and cost targets,
with no accepted-outcome or required-validation regression and no material
cold-task or p95 regression.

The current two historical repair fixtures are diagnostic seeds for that
cohort, not sufficient repository diversity. Codex account usage blocked a
source-bound repeat on 2026-09-24; offline fixtures and scorecard checks can
be prepared while live runs are unavailable. The Linux pytest reuse profile
is not qualified on the stock hosted runner. Keep validation execute-required
and pursue reuse only after a positive provisioned-host input/effect proof and
a measured task-level benefit. If the frozen cohort misses a gate, rank time
and token cost by phase, change one default-path bottleneck, and rerun the
same frozen cohort. Remove a default feature that consistently raises total
completion time despite earlier first edits.

The first customer-visible loop is:

```text
task -> current repository brief -> focused investigation -> edit
     -> appropriate validation -> durable useful knowledge -> next task
```

The current launcher already supplies bounded verified source previews and a
task brief. Local Codex fixtures often reached the first edit sooner, while
end-to-end completion was mixed. Ordinary shell calls mostly bypass the Again
gateway, so current exact-result reuse does not cover the agent's normal work.
The plan below addresses those observed gaps before expanding cache profiles.

## What the repository brain should know

Persist a small, queryable knowledge base per canonical repository. Keep these
record types separate:

| Record | Example | Authority and lifetime |
| --- | --- | --- |
| Source fact | `balances` is defined in `src/running_balance.py` | Verified locator and content/dependency digest; retire on relevant edit. |
| Workflow fact | The project's accepted test command and its last observed result | Command provenance; recheck configuration and environment before advising or reusing. |
| Decision | Why a module or interface was chosen | Attributed to a document, commit, or user; a model summary is labeled as a suggestion. |
| Task history | Files changed, tests run, outcome, and unresolved questions | Durable event record; never implies that the next task has identical inputs. |
| Failed approach | An attempted command or fix and its observed failure | Exact scope and date; use as guidance, not a permanent prohibition. |

The brain should answer concrete questions: where to start, what is known,
what changed since a finding, which test is relevant, and what remains
uncertain. It should not store raw transcripts by default or turn semantic
similarity into permission to skip execution. Start with repository-local
knowledge. Add team or company-wide scope only after ownership, permissions,
redaction, retention, and cross-repository relevance are defined.

## Implementation sequence

### 0. Fix the scorecard and locate wasted work

- Freeze a balanced single-agent task set across small and large repositories,
  bug fixes and feature edits, and cold and returning sessions. Include tasks
  where the initial brief is misleading or incomplete.
- Retain structured traces of reads, searches, edits, tests, failures, wall
  time, input/output tokens, and accepted outcomes. Rank repeated work by
  *time and cost that could actually be avoided*, including proof overhead.
- Compare identical agent/model settings, repository snapshots, task prompts,
  and validation requirements with and without Again in both run orders.

**Gate:** an agreed baseline and task rubric exist before optimizing a new
cache or knowledge feature. First-edit speed alone is not a pass.

### 1. Observe the normal agent workflow

- Add a Codex client adapter to the existing launcher that consumes supported
  structured events while preserving child output, exit status, cancellation,
  and user configuration. Normalize completed file changes and tool calls into
  bounded task events. Do not interpret an unfinished or failed call as a fact.
- Classify observations: source-backed read, edit/invalidation, validation
  run, other command, and agent-authored claim. Redact credentials and avoid
  retaining full arbitrary command output. Add a user-visible way to inspect
  and clear retained knowledge.
- Prove event identity and the effective workspace. Treat native shell command
  output as unverified until an independent source observation can substantiate
  it. The adapter observes ordinary work; it does not transparently substitute
  arbitrary shell commands or replay side effects.
- Add Claude only after the Codex event path passes the same lifecycle and
  task-outcome gates; keep client-specific parsers outside the ledger.

**Gate:** one normal single-agent task produces an accurate event timeline
without extra agent tool calls or a material cold-task slowdown. Edits retire
affected findings even when the edit came from a native client tool.

### 2. Make repository knowledge useful at task start

- Admit narrow source-backed facts from verified observations into the existing
  store. Promote stable workflow facts only with explicit source or execution
  provenance. Store decisions and model summaries as attributed, unverified
  guidance until corroborated.
- Build a bounded brief from current code entry points, relevant prior facts,
  project conventions, test command evidence, recent relevant changes, and
  explicit unknowns. Rank by task relevance and evidence; show why each item
  appears and when it was last checked. Load full results on demand.
- Bootstrap conventions and decisions from repository documentation, package
  manifests, and explicitly supplied team notes. Preserve their author and
  source; repository text is evidence to summarize, not an instruction that
  can override the user's task. Show conflicting sources as a question to
  resolve instead of silently choosing one.
- Make indexing incremental and asynchronous where possible. Never block the
  first useful edit on a whole-repository scan. A missing or stale item becomes
  an explicit unknown and a targeted next inspection.
- Preserve knowledge across separate tasks in the same repository, with
  repository scope and freshness checks. Allow correction and retirement of
  wrong or obsolete knowledge.

**Gate:** returning tasks need fewer duplicate orientation reads and have the
same or better accepted outcome. Stale source facts are never presented as
current after a relevant edit, restart, or workspace switch.

### 3. Reduce repeated investigation in the active session

- Keep a small session memory of verified file regions, searches, results,
  attempted fixes, and unresolved questions. After compaction or a long task,
  return only relevant deltas and pointers to full results.
- Learn recoverable workflow hints from observed failures, such as an absent
  interpreter followed by a successful project test command. Recheck the
  environment before offering the hint on another task.
- Offer the agent a current result or targeted next step before it repeats an
  expensive investigation. Since post-call events arrive too late to stop that
  call, use the task brief, lifecycle update points, and explicit Again tools
  for prevention. Do not claim automatic native-shell interception until a
  client exposes the complete execution envelope and delivery receipt.
- Admit exact tool-result hits only for measured call shapes where the complete
  freshness proof costs less than execution. Preserve direct execution for
  cheap or uncertain calls. Record each *physical execution avoided* and the
  proof that allowed it.

**Gate:** measured repeated investigations and total context bytes fall on
returning tasks, with no incorrect hit or stale answer and no meaningful
regression on cold tasks.

### 4. Make validation targeted, then reusable

- Discover test commands and map changed code to candidate tests. Present
  selectors as suggestions until a real profile proves their coverage. Run
  affected or uncertain validation.
- Complete one execute-only validation profile and capture its actual input,
  environment, toolchain, and effect dependencies. Only then add immutable
  candidates, independent shadow comparison, promotion, and fresh proof for
  reusing an unchanged result.
- Show the agent what ran, what passed, what remains untested, and why a test
  was selected or safely reused. A previous green test message alone never
  authorizes a skip.

**Gate:** equal or better defect detection and accepted patches, fewer
unnecessary validation processes, and zero incorrectly skipped required tests.

### 5. Qualify and ship the single-agent workflow

- Run the frozen task cohort from clean release binaries on supported hosts.
  Report median and tail completion time, total metered cost per successful
  task, tool executions, validation processes, context bytes, and correctness.
- Attribute gains with ablations: brief only, observation plus brain, session
  memory, exact reuse, and validation selection/reuse. Remove a feature from
  the default path if its proof or delivery cost exceeds its measured benefit.
- Make setup, doctor, knowledge inspection/clear, failure recovery, and
  unsupported-client behavior straightforward. Publish only claims supported
  by the retained task and release evidence.

**Release gate:** target at least 20% lower paired median completion time and
20% lower total metered cost per successful task on the balanced cohort, with
no worse accepted-outcome rate or required validation, zero incorrect reuse,
and no material p95 or cold-task regression. Freeze the cohort, exact numeric
thresholds, and analysis method before the qualification run; do not select
them from its result.

## Work to defer

Defer parallel-agent leases and handoffs, cross-user company-wide sync, broad
shell interception, arbitrary command caching, and semantic cache hits as
primary product work. Maintain existing safe behavior, but spend new effort
on the single-agent gates above. Reconsider each deferred feature only when
single-agent evidence identifies a specific bottleneck it solves.
