# Straight-to-code fast path

## Objective

Again should minimize the time between a coding task arriving and the first
correct, useful edit. It should not encourage an agent to produce a longer plan
or read a generic repository summary before acting.

The fast path is:

```text
task
  -> one current repository epoch
  -> one bounded verified edit brief
  -> agent inspects only unresolved details
  -> first edit
  -> affected validation plan is already available
```

“First edit” alone is not a success metric. The edit must survive the fixed task
rubric and required validation. Again must optimize time to the first correct
edit and the final validated outcome together.

## Edit brief, not planning document

The task-start response should contain only information that helps the agent
edit or avoid a known mistake:

1. current changed-path and Git-state summary relevant to the task;
2. exact file and symbol locators most likely to be edit entry points;
3. current verified constraints and task/repository facts;
4. invalidated facts and explicit unknowns that require inspection;
5. verified failed approaches that should not be repeated;
6. the smallest proposed validation set, clearly distinguishing proven from
   execute-required work;
7. content-addressed retrieval references for details omitted from the brief.

It should not contain a generic architecture essay, a full tree, raw duplicate
tool output, speculative implementation steps, or a model-generated plan
presented as fact.

## Latency architecture

The synchronous task-start path must be local and deterministic:

- no model call;
- no network or hosted-service dependency;
- no package installation, build, or test execution;
- one descriptor-retained repository epoch;
- one fresh sealed observed manifest shared by eligible repository tools;
- content-addressed indexes derived from exact repository state;
- one store transaction for current facts, invalidations, and delivery state;
- bounded response bytes and bounded source references;
- no duplicate presentation of bytes already delivered to the authenticated
  recipient in the current uncompacted context.

Candidate relevance may come from lexical ranking, a local index, embeddings,
or a model, but ranking is not truth. Every fact included as current still needs
deterministic source and dependency validation. If ranking or enrichment is
slow, Again returns the verified subset plus explicit unknowns; it does not
hold the agent hostage to complete repository analysis.

Cold enrichment and deeper indexing may continue after the bounded response,
but their output becomes usable only through a later validated observation.
The hot path must never wait for optional enrichment.

## Work avoidance strategy

Again reduces pre-edit work in layers:

1. **Collapse round trips.** A task-start call replaces the common sequence of
   tree, manifest, search, file-read, Git-status, and repeated search calls.
2. **Reuse exact observations.** Current repository/Git calls and completed
   investigations are loaded from the shared execution memory when their
   dependencies still match.
3. **Deliver only the delta.** Previously delivered current facts are referenced
   after authenticated receipt; changed and newly relevant facts are delivered
   in full.
4. **Expose uncertainty early.** Unknown or invalidated areas are named so the
   agent investigates them directly instead of rereading everything.
5. **Prepare validation concurrently.** Dependency invalidation and the proposed
   validation set are computed from the same repository epoch; test execution
   does not block the first edit unless the agent explicitly requests it.
6. **Bypass negative-value reuse.** If fresh validation costs as much as or more
   than the work, execute the ordinary tool and avoid polluting the brief.

## Current implementation gap

The repository already contains most data-model foundations:

- typed repository-wide and task-specific facts;
- source references bound to repository, workspace, state, dependency, and
  authorization digests;
- invalidated facts, explicit unknowns, completed observations, in-flight work,
  failed approaches, and suggested calls;
- deterministic reasoning-brief compilation and exact recipient delivery
  acknowledgment internally;
- metrics for facts reused, investigations/provider calls avoided, context
  bytes, invalidations, and delivery-confirmed omitted bytes/tokens.

The current compiler is an internal general reasoning brief with a maximum of
64 items and 64 KiB. It is not task-ranked, has no public task-start MCP route,
does not admit facts automatically from shipping repository-tool results, and
cannot authenticate a production stdio recipient. Those are product gaps, not
current acceleration claims.

## Required implementation slices

1. **Fresh shared manifest:** let task-start and eligible repository tools share
   one immutable observation within a repository epoch while preserving fresh
   hit validation.
2. **Fact admission:** derive narrowly typed facts and source locators from exact
   built-in tool results. The admission path must reject secret-tainted,
   contradictory, oversized, or incompletely bound facts.
3. **Task relevance:** add deterministic bounded path/symbol/topic candidate
   selection. Semantic retrieval stays suggestion-only.
4. **Edit-brief compiler:** create a smaller purpose-specific presentation with
   explicit byte/item/source budgets and deterministic ordering.
5. **Task-start MCP route:** expose the brief through one workspace-bound call,
   initially returning full output.
6. **Authenticated delta delivery:** bind recipient/session/turn/connection and
   compaction lifecycle before compact or delta presentation.
7. **Validation preview:** attach affected/unknown validation work without
   claiming a test hit before the execution-profile gates close.
8. **Agent setup behavior:** instruct supported agents to request the brief once
   at task start, then move directly to inspection/editing rather than emitting
   a compulsory prose plan.

## Coding-task benchmark gate

The existing real-agent harness validates read-only task pairs. It cannot prove
faster coding or a faster first edit. The product gate requires editable paired
tasks in independent but identical worktrees.

Each baseline/Again pair freezes:

- agent client and exact model;
- repository snapshot and task text;
- tool permissions, sandbox, time, and token limits;
- clean configuration/context state;
- acceptance tests and patch-quality rubric.

The client event stream must retain monotonic markers for:

- task receipt;
- first repository/tool request;
- first attempted edit;
- first edit that is part of the final accepted patch;
- first required validation start and pass;
- final accepted outcome.

Primary comparison metrics:

- time to first correct edit;
- pre-edit tool calls, provider executions, unique files and bytes read;
- pre-edit reasoning/output tokens when reported by the provider;
- end-to-end validated task time;
- total tool, model, and validation compute cost;
- accepted task/patch outcome.

Guardrails:

- zero incorrect hits and stale facts;
- no reduction in required validation or patch quality;
- cold, warm, miss, invalidation, and compaction cases reported separately;
- first-edit improvement is rejected when the accepted outcome regresses;
- paired raw event evidence is retained; inferred token or cost savings are not
  substituted for provider-reported usage.

No “fastest,” “straight to code,” or coding-cost claim ships until this gate
shows a material improvement on diverse real repositories and tasks. The gate
exists to drive optimization, not to delay safe local experiments.
