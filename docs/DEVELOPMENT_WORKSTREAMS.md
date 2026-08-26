# Development workstreams and terminal ownership

This document defines how to develop Again with one primary writer and parallel
read-only agents. It exists to prevent conflicting edits, duplicated model
context, ambiguous evidence, and accidental expansion of a safety claim.

The product roadmap is [ROADMAP.md](ROADMAP.md); architectural authority is
[ARCHITECTURE.md](ARCHITECTURE.md); implementation truth is
[STATUS.md](STATUS.md).

## Default operating model

```text
Terminal A: Codex main writer
  -> commits one clean candidate SHA
       |-> Terminal B: test/correctness review
       |-> Terminal C: systems/security review
       `-> Terminal D: final milestone review (only when warranted)
  -> Terminal A verifies findings and, if needed, creates a new candidate commit
  -> CI evidence custodian verifies exact-SHA jobs/artifacts
  -> named human release authority alone may tag/publish
```

Parallelize independent reading and evaluation. Serialize edits in the main
worktree. A formal V2/V3 review is valid only for the exact clean committed SHA
it inspected. Pre-commit feedback is advisory and does not satisfy the ladder.

## Terminal assignments

| Terminal | Default model | Repository access | Primary responsibility | Explicitly forbidden |
|---|---|---|---|---|
| **A — control and main writer** | Codex GPT-5.6 Sol, `high`; use `xhigh`/`max` only for difficult authority, concurrency, or release work | sole writer in `/Users/arjun/again` | scope, architecture, implementation, adjacent tests/docs, targeted validation, integration, commits and pushes authorized by the user | editing while reviews of the candidate SHA are active; claiming CI/runtime evidence from local tests |
| **B — test and correctness reviewer** | OpenCode via `openrouter/deepseek/deepseek-v4-pro-0813` | read-only tracked source at frozen SHA; external build/state directories only | positive/negative behavior, failure precedence, regression fixtures, targeted tests, one full local suite per review round | editing tests/source, committing, pushing, writing repository state, duplicating the systems audit |
| **C — systems and security reviewer** | OpenCode via `openrouter/z-ai/glm-5.3` | read-only against frozen SHA | Rust ownership, unsafe/syscall ABI, signal/task cleanup, resource bounds, authority tokens, Linux/macOS divergence, threat boundaries | editing, broad style review, rerunning the full suite already owned by B |
| **D — final milestone reviewer** | OpenCode via `openrouter/anthropic/claude-opus-5` | read-only after B/C report | review `base..candidate` as one product change: architecture, user semantics, security claims, documentation accuracy, unrelated changes | routine per-commit use, implementation, release/tag actions |

For a large repository scan before the writer scopes a task, Terminal B may
temporarily use `openrouter/google/gemini-3.7-flash`. Unlisted premium models
are not part of the default workflow; the higher-priced final reviewer is
reserved for unusually high-value release audits.

The four OpenRouter IDs in this table were verified against the provider catalog
on 2026-08-25: [DeepSeek V4 Pro 0813](https://openrouter.ai/deepseek/deepseek-v4-pro-0813),
[GLM 5.3](https://openrouter.ai/z-ai/glm-5.3),
[Claude Opus 5](https://openrouter.ai/anthropic/claude-opus-5), and
[Gemini 3.7 Flash](https://openrouter.ai/google/gemini-3.7-flash). They are
operating defaults, not benchmark claims. In each OpenCode terminal, run
`/models` and select the full `openrouter/<publisher>/<model>` reference shown
above; if it is absent, check `opencode auth list` and the provider connection
before changing the documented ID.

OpenCode/OpenRouter usage is API-billed independently for every agent. Model
IDs and prices change; verify `/models` before updating these defaults. Free
endpoints are never required evidence gates.

## What each terminal does now

### Terminal A — current implementation focus

Terminal A first restores immutable CI evidence. It may then alternate coherent
writer rounds between two independent branches:

- Gate 1: productize the audited local profile and signed prerelease; and
- Gates 2–5: harden Linux authority, build the hidden kernel-backed supervisor,
  compose one execute-only pytest fixture, then add candidate, shadow,
  promotion, and hit authority in that order.

Managed team Gate 6 begins only after both Gate 1 and Gate 5 pass.

For the immediate Linux chain, Terminal A owns all changes that touch supervisor
state, connector permits, completion outcomes, stopped-memory/quiescence,
diagnostic dispatch, and the associated documentation. Those interfaces are too
tightly coupled for independent writers.

### Terminal B — routine review prompt

Terminal B receives the base SHA, candidate SHA, claimed behavior, changed
paths, and allowed commands. Its output is findings only:

```text
Review BASE..CANDIDATE for behavioral correctness and missing regression tests.
Do not edit. For each finding return severity, file:line, failure mechanism,
evidence, and the smallest required test. Run only the assigned test commands.
Omit repository summaries and successful-test logs.
```

For the kernel supervisor gate it focuses on stop-order independence, exact
buffer counts, unwritten-byte handling, failure injection, resume confirmation,
terminal reap/`ECHILD`, cleanup, and the unchanged legacy diagnostic.

### Terminal C — routine review prompt

```text
Review BASE..CANDIDATE as an adversarial systems boundary. Do not edit. Check
unsafe/syscall ABI, task and signal lifecycle, same-mm mutation, resource and
cleanup ownership, linear authority construction, platform cfg behavior, and
whether any pure or synthetic value can gain kernel/completeness/reuse authority.
Return evidence-backed findings only.
```

For `clone3`, it must distinguish multiple processes from multiple tasks sharing
one address space. A held calling-thread stop alone is not a quiescence proof.

### Terminal D — milestone review prompt

```text
Review BASE..CANDIDATE as one release-bound product change. Do not edit or rerun
expensive tests unless evidence is missing. Verify user-visible behavior,
architectural authority flow, nonclaims, security boundary, documentation,
scope discipline, and whether validation supports every claim. Return only
merge-blocking or materially important findings.
```

Use Terminal D after a roadmap gate or substantial milestone, not after every
small commit.

## Freeze and review protocol

At the start of a writer round, Terminal A records:

- base SHA and branch;
- clean/dirty status;
- exact objective and nonclaims;
- allowed files and frozen interfaces;
- targeted tests and required evidence; and
- the roadmap gate whose exit condition the change advances.

At the review boundary:

1. Terminal A commits a clean candidate and records its SHA. Untracked or
   unstaged candidate files are forbidden at this boundary. Pre-commit review
   may help the writer but is advisory because a patch digest does not reliably
   bind the full Git tree.
2. Terminals B and C review that same candidate concurrently and read-only.
3. Terminal B owns the one expensive local test suite. It sets external
   temporary build and application-state directories, records the candidate
   SHA before and after commands, and must leave tracked source and repository
   state unchanged. Terminal C performs static inspection and narrow targeted
   checks only.
4. Terminal A triages findings against source and tests. It does not accept a
   model vote as evidence.
5. Any edit creates a new candidate commit and invalidates affected reviews.
   Rerun only the reviews whose scope changed.
6. Terminal D reviews the final `base..candidate` only after B/C findings are
   resolved or explicitly documented.

The main writer never changes files while a reviewer is inspecting a supposedly
stable tree. This is the simplest way to prevent stale findings and repeated
context reads.

## Token and cost discipline

The lowest-token workflow that preserves independent review is one writer plus
two targeted read-only reviewers after a coherent milestone.

- Do not keep reviewers running while code changes continuously.
- Send `base`, `candidate`, `git diff --stat`, exact changed paths, the claim,
  and a role-specific checklist. Do not ask every agent to rediscover the entire
  roadmap.
- Ask for findings only. Successful paths and repository summaries are omitted.
- Run targeted tests during iteration; run one full local suite for the frozen
  candidate, not after every edit.
- Use Terminal D only for gate completion, major architecture changes, security
  boundary changes, or release candidates.
- Stop a reviewer after it has covered its assigned dimension. More agents are
  not automatically more confidence.
- If reviewers disagree, Terminal A reproduces the disputed behavior with code,
  kernel/API evidence, or a test. A third model is a tie-breaker, not proof.

Parallel agents reduce elapsed time but usually add their token use. Git
worktrees consume no model tokens themselves, but independent agents in those
worktrees reread context and run duplicate builds.

## When to use Git worktrees

Create worktrees only when two implementation tasks are genuinely independent:

- interfaces are frozen before either writer starts;
- owned files do not overlap;
- neither task changes shared enums, manifests, workflows, status, release
  notes, or authority constructors;
- each task has an independent acceptance test; and
- expected latency savings justify duplicated context, builds, and integration.

Good candidates later include a snapshot-manifest implementation and a semantic
recorder implementation after their shared interfaces are frozen. Supervisor
state plus its kernel connector, or code plus adjacent authority types, are not
independent.

The control terminal creates and records each worktree explicitly:

```sh
git worktree add ../again-wt-<task> -b work/<task> <frozen-base-sha>
```

Each worktree has one writer, one branch, disjoint files, and its own build
artifacts. The writer commits a clean branch and does not merge, rebase, push,
or edit another worktree. Terminal A integrates commits sequentially, resolves
all conflicts, reruns affected reviews, and alone updates shared documentation.

Do not create worktrees for read-only review, docs-only follow-up, ordinary test
execution, changes in the same Rust module, or patches small enough for one
writer.

## Validation ladder

| Level | Owner | Required result |
|---|---|---|
| **V0 Scope** | A | clean base, objective/nonclaims, allowed files, frozen interfaces, exact gate |
| **V1 Writer** | A | targeted unit/integration tests and `cargo fmt --check`; no broad claim |
| **V2 Correctness** | B | boundary/regression review and the one pinned full local suite for the frozen candidate, using external build/state directories |
| **V3 Systems** | C | unsafe/platform/lifecycle/cleanup/authority review; required live evidence identified separately from pure tests |
| **V4 Final local** | A | verify B's exact-SHA full-suite result; run pinned Rust 1.88 fmt, strict all-target/all-feature Clippy, explicit 100,000-case gate, and packaging syntax/rollback gates when relevant, without duplicating the full suite |
| **V5 Immutable CI** | evidence custodian | exact candidate SHA; every expected job actually starts and passes; service/team workflows pass when their path scopes change |
| **V6 Claim evidence** | evidence custodian | STATUS/EVIDENCE cite exact run, artifact, source hash, counts and limitations; product/performance claims have their separate retained results |
| **V7 Release** | named human | clean `origin/main`, green applicable gates, reviewed version/notes/tag, native matrix/SBOM/publish, downloaded-asset verification, install/upgrade/rollback/uninstall exercise |

Stock GitHub Ubuntu's expected namespace refusal and the fixed ptrace transport
are deliberately non-qualifying for Linux pytest execution. A green core CI run
does not subsume path-filtered Service CI or Team CI when those surfaces change.

## Evidence and release authority

An evidence custodian may be Terminal D or another read-only reviewer, but not
the writer for the same checkpoint. The custodian verifies:

- workflow `headSha` equals the candidate SHA;
- expected jobs have nonempty step lists and successful conclusions;
- canceled, skipped, zero-step, or billing-blocked jobs are not called green;
- expired or missing required artifacts do not rewrite a historically green
  job, but they invalidate any retained-artifact evidence gate;
- required artifacts exist, parse, and bind the documented source/platform; and
- the wording in STATUS does not widen the artifact's authority.

Only a named human is release authority. Tag pushes can trigger publication, so
an implementation agent must never create or push a release tag. Until repository
settings enforce protected tags, approval environments, and branch protection,
this process boundary is mandatory.

Release packaging authority is not Linux execution authority, trace-completeness
authority, or team-product authority. Each claim must pass its roadmap gate.
