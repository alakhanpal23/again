# Hot-path architecture decision

## Decision

Keep the authenticated workspace daemon, durable task ledger, exact-result
store, and proof rules. Change the synchronous gateway into two independent
planes:

1. **Observation and shared context.** A built-in read may publish a verified
   fact and source locator after its output and dependencies have been checked,
   whether or not the read is admitted as a reusable cache result. The ledger
   owns task visibility, source recipes, invalidation, and recipient delivery.
2. **Work avoidance.** A call may join an in-flight execution or serve stored
   bytes only after its full exact proof succeeds and the route is measured to
   save time. The result store owns canonical requests, leases, blobs, and hit
   evidence. A fact in the ledger is never by itself authority to skip a tool.

The gateway selects a lane before doing cache lookup or source-tree proof. The
first shipped direct observation lane covers task-bound `repo.stat` and
`repo.read` of files up to 8 KiB: it executes
the built-in provider, checks a second matching observation, and records a
source recipe and task fact. Its durable result has a separate `direct_observation`
origin and cannot satisfy a cache hit, join, or full-result reference. A warm
repeat still executes the provider and returns its fresh output. The
authenticated release-binary gate at `69d4ffd` passed two-client sharing,
unrelated-edit preservation, relevant-edit retirement, and this authority
separation. Larger task-bound reads still enter the exact-result path on
their first call.

The intended lanes are:

| Lane | When | Required behavior |
| --- | --- | --- |
| Direct | Cheap reads, unsafe or unknown effects, or proof at least as costly as execution | Execute provider. For an active task, separately admit a verified observation if its bounded proof is worthwhile; otherwise expose an explicit unknown. `repo.stat` and small `repo.read` currently perform a second observation before first fact admission. |
| Coalesced | Identical concurrent deterministic calls with complete observations | One leader executes; followers join only through a valid lease and fresh proof. |
| Exact | Expensive repeated deterministic calls with a cheaper complete freshness check | Return the stored result only after proof, blob validation, and recipient checks. |
| Brief | `task.start` and `context.delta` | Return a bounded verified subset promptly; optional indexing must not hold the response. |

There is no global promise that a repeat is a hit. The current broad
`repo.search` and `repo.tree` source-tree observation traverses the input tree;
it has the same order of work as provider execution. Those calls remain direct
until a complete change signal makes validation cheaper. A change journal or
generation may be used only if it detects edits from every relevant writer,
survives daemon restart or forces a scan, handles overflow and watcher loss,
and is bound to the workspace and source dependencies. On uncertainty, execute
and refresh instead of serving old bytes.

## Why this change is needed

The current gateway's first active-task repository call takes the cache
admission path so it can publish a source-backed fact. On the 1,000-file probe,
first-call admission was 0.13–0.41 seconds. Its warm direct path reruns the
provider and compares the fresh output; all 41 calls in each probe executed
physically. Warm search was 64.01 ms through Again versus 64.23 ms direct.
This protects correctness but provides essentially no work avoidance for that
shape. See `STATUS.md` and the retained `bench/results/*task-reuse-value*`
reports.

The underlying exact-reuse and context mechanisms are useful. The authenticated
release-binary gate proves two clients can share facts and collapse a concurrent
duplicate into one execution, with relevant invalidation and unrelated-source
preservation. The live 1,000-file Codex pairs accepted the same repair and
avoided follow-up repository calls after a task preview, yet Again still took
longer and used more input tokens. Those pairs are too small to assign all
model time to one component. They do rule out calling the present behavior a
general task-level acceleration win.

The integration boundary also matters: the daemon sees calls routed to its
MCP tools. Native shell/tool calls are outside its authority and cannot be
deduplicated transparently. Client setup and brief quality must reduce those
calls in real tasks; server-side caching alone cannot.

## Implementation order

1. Add a direct-observation admission API. The `repo.stat` and small-read paths are implemented;
   extend it only to shapes with cheap complete observation. It accepts the executed built-in
   response, canonical call, bounded dependency observation, and before/after
   workspace state. It persists a source-backed fact without first acquiring a
   cache lease. A changed source or incomplete observation withholds the fact.
   Keep result references only when full bytes are durably stored and scoped.
2. Split the current `execute` route into explicit policy and execution stages.
   The policy uses operation, task activity, proof cost, estimated provider
   cost, output bound, and availability of a complete cheap change signal. A
   direct call must not invoke `acquire_gateway_call` or `observe_gateway_route_proof_v1`.
3. Remove per-call warm-reference SQL only after a cross-connection and
   cross-process invalidation generation is proven. A generation mismatch
   falls back to durable lookup; restart, missed edits, store replacement, and
   overflow force conservative revalidation. Never treat an in-process value
   comparison as an exact cache hit.
4. Keep Git operations and any additional deterministic profile behind their
   own measured policy. Preserve effect classification, environment/executable
   observations, corruption quarantine, and full-result validation.
5. Improve the client path: installed Codex and Claude sessions should use one
   small `task.start` brief, then inspect unresolved details. Measure tool
   schema and brief token cost as well as tool latency. Do not add a preview
   merely because it removes a call if it worsens validated completion time.

## Acceptance gates

- **Correctness:** exact bytes and streams match direct execution; relevant
  edits, deletes, renames, Git changes, restart, watcher loss, and corruption
  refuse stale hits and retire stale facts. Unrelated edits preserve eligible
  facts. Two clients and separate store handles see the same authority.
- **Work avoided:** for every claimed hit or join, the release-binary trace
  records fewer physical provider executions and a durable explain reason.
  Direct observations are counted separately from cache hits.
- **Latency:** compare cold and warm direct, context-only, and exact lanes on
  one-file, 1,000-file, 10,000-file, and large-output fixtures. A lane ships by
  default only when it improves its eligible call shape without a material
  cold-task regression. Record p50/p95, bytes, tokens, and invalidation cost.
- **Task outcome:** balanced, pinned Codex and Claude cohorts include both
  treatment orders, repeat-heavy parallel tasks, and ordinary edit tasks.
  Require the same accepted patch and validation, lower median completion
  time and token cost, and zero incorrect hits. Report each workload separately;
  a synthetic hit rate does not substitute for a task outcome.

If the revised lanes pass tool-level gates but fail task-level cohorts, inspect
the MCP/client routing and brief presentation costs before changing the proof
store. A broader rewrite requires evidence that the daemon or durable proof
model itself is the bottleneck after those costs are isolated.
