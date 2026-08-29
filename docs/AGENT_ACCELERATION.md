# Agent acceleration product

## Product outcome

> Again helps coding agents start with verified repository understanding, avoid
> repeating work, run only the validation that changed, and share exact
> execution knowledge across agents.

The economic outcome is lower time and lower total cost per successful coding
task. Again does not try to cache every action. New work, changed work, and work
whose dependencies are uncertain must execute normally. Again removes only
work for which it can prove that the relevant repository, task, runtime,
authorization, executable, and dependency observations still apply.

This is the end-state product direction. It does not change the narrower
shipping claims in [PRODUCT.md](PRODUCT.md), [STATUS.md](STATUS.md), or
[EVIDENCE.md](EVIDENCE.md).

## The user experience

A coding task should eventually flow through one verified loop:

1. The agent begins with the current repository identity and change set, not a
   generic summary or a stale transcript.
2. Again returns a small orientation brief containing relevant files, symbols,
   previously verified facts, invalidated facts, and the evidence behind each
   item.
3. Repository and Git reads that are still exact are reused or joined instead
   of being repeated by every agent.
4. The agent edits normally. Again observes which declared dependencies changed
   and retires any fact or result whose proof no longer applies.
5. Again creates a validation plan from the changed dependency closure. Tests
   that might be affected execute; an unaffected result can be reused only
   after exact validation authority exists for that test profile.
6. Successful executions and useful findings become immutable candidates with
   provenance. A later agent receives the current verified delta instead of
   rediscovering the repository from scratch.

The agent remains free to inspect more context or run more validation. Again is
a control plane for verified shortcuts, not a replacement for agent reasoning.

## Four product accelerators

### 1. Verified orientation

The first response to a coding task should answer: what is relevant, what is
already known, what changed, and what is no longer trustworthy. Facts must be
typed, scoped to a repository or task, bound to source observations, and
invalidated deterministically. Embeddings or a model may nominate likely facts
and files; they cannot authorize their use as current truth.

The repository already contains typed reasoning facts, invalidated facts,
source references, bounded reasoning briefs, and deterministic compilation.
They are internal foundations. A public agent flow still needs trustworthy
task/recipient identity, fact admission from real tool results, and live task
quality evidence.

### 2. Exact tool-work reuse

Repeated repository and Git intelligence should converge on one provider
execution when its complete dependency binding is unchanged. This is the
shipping beachhead: the default MCP server exposes 13 bounded tools, joins
identical in-flight work, reuses exact verified results, and invalidates on
relevant repository changes.

The next performance work is to reduce the cost of the one required fresh
authority observation. A descriptor-oriented repository walker and a sealed,
immutable observed manifest should let multiple tools share one current view
without allowing an old manifest to create a hit. This is local engineering;
it requires no hosted service or account.

### 3. Changed-only validation

The product goal is not to skip tests by name or historical pass rate. It is to
observe the files, executables, environment, reads, and effects on which an
execution depended, then prove whether a later change can affect it. Until that
authority exists, a test runs.

The path is deliberately staged: execute-only isolated pytest, immutable
candidate construction, independent shadow comparison, promotion, and fresh
hit validation. The current Linux code is substantial foundation and
diagnostic evidence, but no user pytest command or test-reuse product ships
today.

### 4. Verified context and cost control

Once an exact result or reasoning brief has been delivered to a known recipient
in an uncompacted context, subsequent responses can refer to it rather than
resending the same bytes. After compaction, recipient change, disconnect, or
missing acknowledgment, full delivery is required again.

This lowers four different costs:

- model input caused by repeated repository orientation and duplicate output;
- provider/tool calls caused by repeated reads and investigations;
- local or remote compute caused by unaffected validation;
- developer wait time between task receipt and a correct result.

Today Again can measure exact provider calls avoided and explicit output bytes
omitted. The public MCP path has no authenticated recipient issuer, so it has
zero delivery-confirmed token savings. Model spend and task cost must not be
claimed until a live agent/API run records provider usage and comparable task
outcomes.

## Current product map

| Product layer | Available now | Next missing product step |
|---|---|---|
| Repository identity and observation | Descriptor-retained workspace epochs, dependency-bound built-in tools, exact invalidation | Share one sealed fresh manifest across eligible tools and measure cold/warm task impact |
| Tool execution memory | 13 default MCP repository/Git tools, exact hits, in-flight joins, recovery, quarantine | Outside-user evidence and reviewed upstream-provider configuration |
| Local exact command memory | Audited macOS read subset through `run`, `reference`, `show`, and local SQLite/CAS | Broader signed profile distribution without weakening fail-closed admission |
| Repository understanding | Internal typed facts, invalidations, source references, and reasoning-brief compiler | Admit facts from live verified observations and expose a bounded task-start brief |
| Context delivery | Internal authenticated receipt/grant composition and explicit same-context `reference` | Transport-authenticated recipient identity and public compact/delta delivery |
| Validation selection and reuse | EffectIR, snapshot, isolation, tracer, candidate, and promotion foundations | First real execute-only pytest slice, then shadow-backed reuse |
| Cross-agent/team knowledge | Local shared store and manually provisioned encrypted team foundation | Safe product onboarding, deployed service, and cross-machine equivalence evidence |
| Economics | Provider-call, result, byte, latency, and dormant token fields | Paired live-agent task measurements with quality and actual usage/cost |

## Product scorecard

The unit of success is a completed coding task, not a cache-hit percentage. A
paired evaluation should compare the same agent/model, repository snapshot,
task, limits, and outcome rubric with and without Again.

Primary measures:

- time from task receipt to the first useful edit;
- end-to-end wall time to a validated task result;
- repository/tool calls and provider executions per task;
- repository-context bytes and provider-reported input/output tokens per task;
- validation processes and compute time per task;
- total metered model, provider, and compute cost per successful task.

Quality and safety guardrails:

- task outcome and required validation must be unchanged or better;
- known incorrect hits and stale facts must remain zero;
- every skipped execution must have a consumable proof and explanation;
- shadow divergence, invalidation, corruption, cancellation, and cleanup must
  fail closed;
- miss overhead and first-task latency must be reported, not hidden by warm
  averages;
- trivial operations should bypass Again when verification costs more than the
  work it could save.

Initial product experiments should seek a material median reduction in both
end-to-end task time and metered cost while preserving the fixed outcome rubric.
Targets become release gates only after the baseline harness and raw evidence
format are frozen; they are not current performance claims.

## Delivery order

1. **Make the current gateway undeniable.** Complete outside-user evidence,
   keep zero-false-hit and recovery gates, and improve the authoritative
   repository traversal without broadening reuse.
2. **Ship verified task-start context.** Connect live tool results to typed fact
   admission and compile a bounded full orientation brief. Invalidated facts
   must remain visible as invalidated rather than silently disappearing.
3. **Prove compact and delta delivery.** Add transport-authenticated recipients,
   complete-response receipts, lifecycle/compaction retirement, and public
   retrieval grants before counting token savings.
4. **Measure real agents.** Run fixed paired Codex and Claude tasks, record task
   quality, tool calls, wall time, context bytes, provider usage, and actual
   cost. Optimize only from retained traces.
5. **Ship execute-only pytest.** Complete the first real Linux profile and use
   observed dependencies to produce a validation plan. It earns no reuse
   authority yet.
6. **Promote changed-only validation.** Construct immutable candidates, shadow
   them independently, promote exact agreements, and revalidate every hit.
7. **Share across agents and machines.** Productize encrypted team onboarding
   only after equivalent-profile, revocation, privacy, and cross-machine gates
   pass.

No external service is needed for steps 1, 2, or the local parts of step 3.
Paid agent APIs are useful only for the paired economic evaluation in step 4.
A hosted store becomes useful for cross-machine/team sharing in step 7; it does
not make local repository observation or exact validation intrinsically faster.
