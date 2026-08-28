# Delivery roadmap and product gates

This roadmap starts from the implementation described in [STATUS.md](STATUS.md).
Dates are planning labels, never evidence. A phase advances only when its exit
gate has a reproducible result and, where required, an immutable CI or retained
runtime artifact.

## Product objective

Again should eliminate repeated agent wait time and context without serving a
result whose inputs, execution profile, or effects are not proven equivalent.
The product definition is: “Again is a repository-aware execution memory and
tool-call control plane for coding agents. It skips only work proven redundant,
executes uncertain work, and returns the smallest useful verified observation.”
The product advances through four user-visible stages:

1. **Repository-aware agent gateway:** deduplicate exact repository tool calls
   across agent sessions and return bounded verified observations.
2. **Explicit local exact reads:** accelerate a deliberately narrow set of
   audited read-only commands while preserving complete streams.
3. **Trace-backed local pytest:** execute one frozen pytest invocation shape in
   an isolated Linux profile, then admit reuse only after complete observation
   and independent shadow agreement.
4. **Managed team reuse:** share encrypted, signed results only across equivalent
   repository and execution profiles with local verification.

The current product has an experimental stage-1 gateway and the narrower
stage-2 explicit CLI. Stage-3 snapshot, isolation, seccomp, ptrace, and wire
foundations exist, but no Linux pytest command can execute through the profile
and no Linux reuse authority exists. Stage 4 has a manually provisioned
client/service foundation, not a deployed product.

## Agent gateway fast track

The experimental local vertical slice now includes a real bounded MCP stdio
server, 13 built-in repository/Git intelligence tools, descriptor-retained repository authority,
exact dependency-bound reuse, SQLite/CAS coordination, in-flight joining,
cancellation, and explicit workspace-bound Codex/Claude setup. It remains
pre-alpha until these gates close:

The internal delivery composition now proves that one authenticated recipient
receives the canonical full reasoning brief before a compact reference can be
issued, and that write failure, reconnect, cancellation, compaction, or
lifecycle change clears that authority. Durable accounting revalidates the
exact result and response envelope and deduplicates retried receipts. This is
not yet a user-visible capability: the public stdio transport has no trusted
recipient issuer, so it continues to send full results and records zero
delivery-confirmed savings.

The built-in Git boundary now refuses reuse when local configuration imports
external files, and status/diff queries with nested worktree or submodule
control state execute without reuse. Configuration capable of launching a
filter, external diff/text-conversion command, or alternate-reference command
is rejected before the Git subprocess starts. This closes stale-result and
nominally-read-only command-launch gaps; broader Git configuration support must
arrive only with explicit dependency and executable authority.

1. Replace every caller-constructible routing observation with a store-issued,
   one-use proof whose lifecycle generation, dependency binding, and freshness
   are checked at consumption.
2. Add authenticated delivery receipts before counting bytes or execution time
   as saved. A content address must never act as a bearer authorization token.
3. Add full-result retrieval only through an authorization-scope and
   recipient-bound grant; then add compact references only after that exact
   recipient has received the full result in the current uncompacted context.
4. Keep semantic/AI routing suggestion-only until deterministic validation
   binds the complete state and a trusted validity interval.
5. Run the production binary with real Codex and Claude sessions on retained,
   network-controlled repository fixtures. Measure provider calls avoided,
   latency, bytes and estimated tokens omitted, false-hit count, task outcome,
   cancellation, restart recovery, and store corruption.
6. Expose reviewed configuration for the implemented bounded upstream MCP
   transport only after provider identity, executable drift, cancellation,
   credentials, and local policy are bound end to end. Side effects,
   credentials, communication, deployments, payments, and unknown tools must
   continue to bypass storage and reuse.

Current checkpoint: item 1 is closed for the built-in tools, and acquisition
events are only candidates; exact-hit and in-flight-join statistics are
promoted after one-use proof consumption, result loading, and repository
revalidation. Additive schema-v10 receipt/grant storage exists, but item 2
remains open because production stdio has no transport-authenticated recipient
issuer. No compact delivery, bytes, tokens, or time savings are claimed. The
phase-two response-bound commit failed its isolated all-target build. A later
retrieval commit made the combined branch green, but authenticated recipient
issuance remained test-only, so the production authority gate was still open.

The retained schema-v10 release-binary harness closes the deterministic portion
of item 5 with 8/8 scenarios, four real MCP processes, 12 provider executions,
three avoided executions (two exact hits and one joined call), and zero false
hits at source `850e7c4398adc25ef1210ee4260e27b29aaeb753`. The same binary passed the
isolated onboarding and quick chaos harnesses. Three explicit clean real
repositories passed, while the overall corpus correctly remains `non_pass`
until an eligible local Go repository is supplied. The ten-scenario alpha-trial
recorder exists, but zero outside users and zero of the required 50 attempts
have been recorded. The real-agent harness passed only its offline dry run
against Codex 0.150.1 and Claude 2.1.220; all 16 networked/paid paired runs
remain manual and unexecuted.

## Critical path

```text
                         restore immutable evidence
                             /              \
                            v                v
          distribute/validate local alpha   kernel two-task proof
                            |                -> execute-only pytest
                            |                -> complete candidates
                            |                -> shadow/promote/reuse
                            \                /
                             v              v
                         managed team alpha
```

After Gate 0, Gate 1 distribution and Gate 2 Linux-supervisor work are
independent branches. They may alternate implementation rounds, but only one
terminal owns repository edits at a time unless an explicitly isolated Git
worktree is assigned. Gate 6 requires both branches: Gate 1 and Gate 5. See
[DEVELOPMENT_WORKSTREAMS.md](DEVELOPMENT_WORKSTREAMS.md).

## Gate 0 — restore evidence authority

**Goal:** make the current source checkpoint eligible for engineering and
release claims.

Work:

- resolve the GitHub Actions account billing/spending-limit block;
- rerun macOS, Ubuntu, stock-rootless negative-lane, service, and applicable
  integration workflows on the exact commit being evaluated;
- retain raw artifacts and link the immutable runs from [STATUS.md](STATUS.md)
  and [EVIDENCE.md](EVIDENCE.md); and
- distinguish source failures, environment refusals, and zero-step CI
  infrastructure failures.

Exit gate:

- formatting, pinned Rust 1.88 strict all-target/all-feature Clippy, locked
  all-feature test suites, service tests, packaging tests, and the 100,000-case
  differential gate pass on their documented platforms; and
- every positive runtime claim names its exact source, platform, command, and
  retained artifact.

No later phase may treat a local pass or a zero-step CI failure as immutable
release evidence.

## Gate 1 — distributable local alpha

**Goal:** put the stage-1 product in outside users' hands before broadening its
semantic surface.

**Entry gate:** Gate 0.

Work:

1. Replace duplicated single-host constants with one versioned audited-profile
   registry shared by local executable verification and team runtime
   attestation.
2. Populate only profiles backed by exact host, OS, executable, and runtime
   evidence. Unknown profiles continue to fail closed.
3. Make `again doctor` report the selected profile, unsupported dimensions,
   skill scope, and safe next action without implying reuse authority.
4. Exercise real Codex sessions from workspace roots and subdirectories, with
   TTY/non-TTY streams, interruption, long-running calls, personal/project skill
   scopes, and automatic hooks remaining no-op.
5. Run the direct benchmark on real non-sparse Rust, Python, Go, and TypeScript
   repositories. Preserve exact streams and mutation invalidation.
6. Add reviewed keyless artifact signing/attestation and independently tested
   verification instructions around the existing native release workflow,
   checksums, source SBOM, installer, rollback, and uninstaller.
7. Publish a prerelease and provide a reviewed Homebrew or equivalent installation
   path that still refuses unsupported runtime profiles.

Current checkpoint: the real-repository validation harness for item 5 is
implemented, bounded, offline-only, and exercised by portable CI tests. It
requires explicit absolute paths to already-local Rust, Python, Go, and
TypeScript Git worktrees, pins the exact Again binary, copies only selected
tracked regular files, compares native/cold/warm streams and status exactly,
and proves mutation invalidation. A retained schema-v10 run passed Rust, Python,
and TypeScript with zero false hits but remains `non_pass` because the bounded
offline search found no eligible Go repository. The alpha-trial harness freezes
the required ten scenarios and exact five-user/50-attempt gate, while correctly
refusing local simulation as outside-user evidence. No outside attempt or
publisher-authenticated prerelease exists, so Gate 1 remains open.

Product outcome:

- an outside developer can install Again, run `again setup --codex`, inspect
  support with `again doctor`, use explicit `again run`/`again reference`, and
  remove the integration without hooks, accounts, daemons, or repository
  mutation.

Exit gate:

- five outside developers each attempt the same versioned 10-command corpus;
- at least 35 of the 50 attempts are policy-admitted and complete successfully
  without configuration after documented onboarding, with byte-identical cold
  and warm streams; safe refusals are reported separately and do not count as
  admitted successes;
- eligible repeats achieve at least 3x median warm speedup with byte-identical
  streams and zero known incorrect hits;
- unsupported hosts and tools fail closed with actionable explanations; and
- release artifacts have verified publisher authentication, not checksums alone.

Kill or narrow the stage-1 profile if any known stale result is served, a
production hook rewrites a command, a hit changes either stream, or the median
eligible warm speedup falls below 2x.

## Gate 2 — kernel-backed supervisor tree proof

**Goal:** connect the pure production tracer planner to the Linux kernel without
granting workload, Python, EffectIR, profile, execution, or reuse authority.

**Entry gate:** Gate 0. Gate 1 is an independent branch.

**Status:** closed for the fixed, command-free transport proof at source
`3d1fb201507a43b830d5ce341b2253957634016d`; this is not profile, execution, or
reuse qualification.

The first executable artifact is a hidden, fixed, no-command two-task probe. A
parent performs exact 88-byte `clone3(SIGCHLD)` and parent and child raw-exit.
The connector must:

- own the only private issuer for `TracerSupervisorStateV1`;
- prove exact ptrace options and exact installed-filter bytes before beginning;
- drive every planner intent through real `waitpid(-1, __WALL)`,
  `PTRACE_GETEVENTMSG`, `PTRACE_GET_SYSCALL_INFO`, bounded stopped-memory reads,
  and ordered `PTRACE_CONT`/`PTRACE_SYSCALL` operations;
- confirm a resume only after the exact ptrace operation returns success;
- before reading or resuming from `clone3` arguments, prove that every task
  sharing the address space is stopped or absent, no untraced sibling can
  mutate it, and the range is not externally mutable/shared; otherwise do not
  resume, kill and drain the tree, and fail closed;
- consume a completion boundary that requires no outstanding exchange, no
  pending birth/stop/resume, terminal reap for every task, connector-owned final
  `ECHILD`, preserved signal state, drained `SIGCHLD`, and completed cleanup; and
- emit only a fixed redacted diagnostic with every authority flag false.

Current checkpoint: that hidden connector and redacted CLI diagnostic are now
implemented, including exact option/filter readback, stopped private-range
capture, event/stop identity correlation before pidfd authority, full-tree
drain, final `ECHILD`, and consuming completion. A wait-returned stopped tracee
is retained for cleanup before event-message correlation, including on a
mismatch. Bounded proc/environment reads, bounded wait backoff, and typed
seccomp/process-memory refusals are also implemented. The connector now routes
run/cleanup waits, every ptrace exchange, stopped-memory reads, both resume
modes, PID/pidfd termination, and signal-state verification through private
test-only fault seams. Linux tests require each forward failure to preserve its
typed first error while the complete tree reaches final `ECHILD`; cleanup-path
faults retain the first cleanup errno and refuse completion. The completed
diagnostic redacts the observed parent-event-first or child-stop-first order.
Provisioned
[`run 32965300493`](https://github.com/alakhanpal23/again/actions/runs/32965300493)
passed 100/100 at the exact source checkpoint above on Linux x86_64 kernel
`6.8.0-134-generic`, with 99 parent-event-first and 1 child-stop-first sample.
The offline verifier accepted artifact `9605461989` with 302 members, archive
SHA-256
`43f3be33e9d92e28198ccab64deab1db6533c6a66c0ed7d1523f6fde4f371dfa`,
and member-manifest SHA-256
`4cb7287d6940b43a9720b10b82f90518b32abd319b3c9343df69c42ab20cf3ae`.
The ephemeral runner was evidence infrastructure only and need not remain
registered after the run.

The retained artifact must be verified offline before it is cited. The verifier
accepts the downloaded ZIP, the independently recorded source SHA, and the
independently recorded runner kernel release; it refuses ZIP prefixes, trailers,
comments, extra fields, gaps, special entries, type-loose JSON, raw/validated
drift, report drift, and any authority claim. Its canonical audit includes the
archive SHA-256, member-manifest SHA-256, source SHA, kernel release, exact member
and sample counts, and both observed delivery orders:

```sh
python3 -B scripts/verify_linux_supervisor_evidence.py ARTIFACT.zip \
  --expected-source-sha SOURCE_SHA \
  --expected-kernel-release KERNEL_RELEASE
```

Before wiring a candidate record, narrow the authority path so structurally
valid synthetic values cannot bind a reusable execution record. Completion
evidence must be linear, connector-issued, and consumed exactly once.

Exit gate:

- parent-event-first and child-stop-first kernel schedules both satisfy the same
  invariant summary;
- exact stopped-memory address, TID, stop generation, and 88-byte count are
  enforced; partial, long, unavailable, substituted, or dirty-tail reads never
  resume the task;
- every injected wait/ptrace/read/resume failure kills and reaps the complete
  tree, preserves signal state, drains `SIGCHLD`, leaks no tracked descriptor,
  and preserves the first typed error;
- 100/100 fixed samples pass on a pinned provisioned Linux runner whose tracer
  is outside seccomp, has `CAP_SYS_ADMIN` in the governing user namespace, and
  runs a kernel with `CONFIG_SECCOMP_FILTER` and `CONFIG_CHECKPOINT_RESTORE`, as
  required for `PTRACE_SECCOMP_GET_FILTER`;
- the preserved fixed single-task ptrace diagnostic and stock-Ubuntu negative
  namespace lane remain unchanged; and
- public Linux dispatch remains disabled.

## Gate 3 — first execute-only pytest product slice

**Goal:** safely execute one real pytest selector through the documented Linux
profile while making reuse impossible.

**Entry gate:** Gate 2.

The only invocation shape remains:

```text
again run -- .venv/bin/python -I -m pytest <selector> [<selector> ...]
```

Current checkpoint: a crate-private pure parser accepts only the exact inner
argv `.venv/bin/python -I -m pytest tests/test_smoke.py::test_smoke` and returns
a non-authoritative lexical wrapper around the existing Stage-0 selector. A
fixed two-file fixture and bounded Python oracle freeze the intended evidence
shape and refuse fixture drift, malformed JSON, stream mismatch, nonzero wait
status, incomplete cleanup/reap, nonzero candidate/shadow/promotion/replay
counts, or any authority claim. The oracle deliberately does not execute
pytest, dereference its qualified-tuple reference, or independently bind the
caller-reported binary/source hashes and cleanup booleans; even its consistent
outcome grants no pass, qualification, execution, or reuse authority. No CLI
or tracer path consumes this scaffold yet. A dedicated
connector transition can now consume the lexical proof while compiling the
four-view workspace tree, verify the fixed selector's regular-file type,
length, single-link manifest topology, and content digest before publication
escrow or rename, and return one opaque linear workspace-tree binding.

That binding can now be consumed with a second, independently published runtime
tree. The resulting structural inventory binds both publication roots, pins and
revalidates every selected object, distinguishes the root executable,
interpreter, and dependency-DSO ELF roles, and rejects `ET_EXEC` outside the
root. Its fixed six-directory lookup resolves the frozen `PT_INTERP` and ordered
`DT_NEEDED` graph under explicit node, depth, byte, lookup, descriptor, and
memory bounds. This is deliberately not a loader proof: loader cache, preload,
environment, `RPATH`/`RUNPATH`, glibc-hwcaps, virtual-environment, and pytest
semantics remain unmodeled. The native dual-publication test passed on hosted
Ubuntu at source commit `eec5d95edd2b01a94c3ac8bd76c2c5dc0f26f502` in
[CI run 33028269206](https://github.com/alakhanpal23/again/actions/runs/33028269206),
including complete fixed-directory lookup and refusal after a published runtime
mutation. The earlier local x86_64 QEMU timeout remains non-evidence, and this
structural result does not qualify the loader or authorize execution.

The runtime, stdio, and isolation owners now meet at one command-free connector
checkpoint. It requires and retains the two-publication structural inventory
before creating the concrete isolation-ready child, authenticates and splits
all pipe ownership, and retains bounded parent capture. After both roots are
attached and reauthenticated in the child's private mount namespace, a linear
handoff performs `PTRACE_SEIZE`, interrupts that exact single-task child,
requires the exact ptrace-event stop, and rechecks its task count, tracer,
`NoNewPrivs`, and pre-filter seccomp state before transferring the existing
cleanup guard to an opaque supervisor owner. Cancellation terminates and reaps
before EOF draining; uncertain reap closes without capture, and setup failures
retain their first error separately from cleanup completeness. A provisioned
x86_64 Linux run completed 100/100 attach, handoff, cancel, and terminal-reap
samples. This is a command-free ownership checkpoint, not execution evidence:
the connector exposes no resume, filter-install, release frame, command, PID,
descriptor, execution, candidate, replay, or reuse authority.

A separate live workload-seccomp diagnostic is also integrated. It installs and
reads back the exact 223-instruction cBPF program in one disposable single-task
child, retires the child identity on every terminal/ownership-loss path, and
returns only after kill, reap, final `ECHILD`, pending-signal continuity, and
signal restoration. Its result is intentionally a completed-probe record, not
a live installed-filter witness: the diagnostic child is already gone and can
never accept a command. The real isolation child can now enter a distinct
supervisor-held state, but supervisor cookie handling, same-child filter
installation/readback, fixed command release, complete post-release task-tree
supervision, and qualification against pinned Python remain future composition
work. No component grants execution, profile, candidate, replay, hit, or reuse
authority.

A separate bounded reference snapshot oracle records the fixed workspace
fixture and exact argv while marking source, binary, and qualified-tuple
provenance as caller-supplied and unverified. An offline verifier accepts only
the exact five-member future evidence archive and checks canonical ZIP layout,
schemas, hashes, streams, wait status, workspace stability, cleanup/reap
claims, execute-only counters, and false authority fields. A deterministic
offline packager reads exactly those five bounded inputs without following
links, writes and verifies a private `0600` staging archive, then publishes it
under the requested name with an atomic no-replace link. Publication and
cleanup ambiguity remain typed, and rejected bytes are never deliberately
published under the final name. These tools and their adversarial suites are
connected to hosted CI. They validate evidence shape and internal consistency
only: none executes pytest, verifies the producer's runtime observations,
qualifies a tuple, or grants product authority. There is no production
evidence producer yet, and the packager does not protect against a malicious
same-UID process that can race its output directory.

The first acceptance fixture should use exactly one selector, such as
`tests/test_smoke.py::test_smoke`. It must compose:

- two-phase lexical and snapshot-backed admission;
- descriptor-bound, manifest-reconciled, whole-inventory-revalidated
  workspace/runtime publications;
- rootless namespace PID 1, private root, scratch mounts, procfs, FD scrub,
  capability elimination, Landlock, and production workload seccomp;
- the kernel-backed supervisor and complete descendant cleanup;
- profile-owned stdin/stdout/stderr; and
- exact foreground stream and raw wait-status delivery.

Product outcome:

- admitted pytest runs execute in a disposable branch with no host network and
  no writable host-workspace view; malformed invocations refuse before Python
  starts; completed runs are always `Executed only` and cannot be shadowed,
  promoted, or replayed.

Exit gate:

- exact stdout, stderr, and wait status are delivered;
- the host workspace manifest is unchanged;
- network, descriptor, mount, namespace, task, and branch cleanup canaries pass;
- every descendant reaches terminal reap and final `ECHILD`;
- unsupported signals, restarts, syscalls, mappings, or nondeterministic inputs
  produce an explicit execute-only reason rather than a candidate; and
- the feature remains limited to exact qualified Linux tuples.

## Gate 4 — complete candidate construction

**Goal:** turn a foreground execution into an immutable candidate without yet
serving a cache hit.

**Entry gate:** Gate 3.

Work:

- implement the semantic syscall adapter and complete EffectIR v2 recorder;
- record executable/interpreter/library closure, descriptor-selected paths,
  file and directory observations, absent paths, symlinks, metadata, environment
  digests, stdin, ordered effects, task lifecycle, streams, and raw wait status;
- bind the canonical snapshot manifest and digest to the prepared invocation;
- broker or explicitly reject time, randomness, logical PID, sleep, asynchronous
  signal, scheduling, and externally mutable shared-memory surfaces;
- make every unsupported or incomplete trace permanently execute-only; and
- store candidates immutably without mutating them into promoted records.

Exit gate:

- the completeness bitmap is closed for every admitted candidate;
- no candidate can be created without connector completion evidence;
- canonical wire objects round-trip and differential tests cover malformed,
  reordered, substituted, over-limit, and unknown-version inputs; and
- crash or interruption exposes no partial committed effect or candidate.

## Gate 5 — shadow, promotion, and local pytest reuse

**Goal:** serve the first trace-backed pytest hit.

**Entry gate:** Gate 4.

Work:

1. Run the foreground and shadow in separate independently isolated invocations
   from the same immutable inputs.
2. Compare exact stdout, stderr, raw wait status, semantic EffectIR comparison
   view, completeness, runtime/profile identity, and final filesystem root.
3. On divergence, atomically quarantine only the exact v1 request-scoped class:
   profile digest, workspace identity, shape key, and request key. Effect shape
   remains analytics and grants no generalized quarantine authority.
4. Create a separate promotion row referencing two distinct immutable candidates;
   never mutate a candidate disposition.
5. Revalidate current inputs and all replay preconditions before serving a hit.
6. Start with 100% shadow validation and reduce it only after retained evidence
   demonstrates dependency completeness.

Product outcome:

- a later identical qualified pytest invocation with no replay-required
  workspace effects and an unchanged final workspace may return the promoted
  result without rerunning pytest while preserving complete streams and status.
  Filesystem-writing runs remain execute-only until transactional replay
  preconditions and effect commit pass a later gate.

Exit gate:

- zero unexplained divergences in 100,000 eligible shadow comparisons;
- zero known incorrect reuses and zero partial-effect commits;
- miss overhead below 15% for commands over one second;
- warm hit p95 below 100 ms and at least 3x speedup on eligible fixtures whose
  original duration is at least 500 ms; and
- every refusal, execute-only disposition, candidate, promotion, quarantine, and
  replay has a stable explanation and retained evidence.

## Gate 6 — managed team alpha

**Goal:** convert the existing manually provisioned encrypted team foundation
into a deployable, operable product without allowing remote state to upgrade an
unsafe local execution profile.

**Entry gates:** Gate 1 and Gate 5.

Work:

- deploy the Worker/D1/R2 service behind production TLS and pre-auth abuse
  controls;
- build account, tenant, repository, generation, profile, key, trust, rotation,
  revocation, retention, deletion, quota, and recovery workflows;
- prove production bucket and tenant isolation and obtain external security
  review;
- complete the cross-layer post-decrypt revocation race and stateful 100,000-case
  D1/R2 protocol corpus;
- keep `legacy_v2` as the default until `bundle_v1` passes the maximum-payload,
  pending-reader cancellation, heap, and full local/live matrix gates;
- prove cross-machine equality for equivalent execution profiles; and
- deliver CI integration using signed, immutable client artifacts rather than
  building secret-bearing code from an untrusted checkout.

Exit gate:

- 100% rejection of unsigned, revoked, stale-generation, cross-tenant,
  cross-repository, policy-mismatched, and profile-mismatched fixtures;
- cross-machine equality for at least 100 hermetic workloads;
- at least 30% median end-to-end wall-time reduction on consenting team sessions;
- at least 20% useful cross-user hit rate for the chosen customer profile; and
- three design partners are willing to pay for verified shared reuse or compute
  savings.

If useful cross-user hits remain below 10%, retain the remote evidence and local
optimization value but reconsider the shared-cache business thesis.

## Explicitly deferred

The following do not enter the critical path until their prerequisite gate is
green:

- arbitrary commands, arbitrary Python, pytest flags, interactive workloads,
  macOS trace-backed execution, or cross-platform semantic generalization;
- automatic Codex hook rewriting or automatic compact references without an
  effective per-call context and delivery receipt;
- remote execution before local trace/replay correctness;
- `bundle_v1` rollout before its existing failed gates pass;
- eBPF as a sole enforcement or completeness boundary;
- reuse of filesystem-writing pytest runs before transactional preconditions and
  effect commit are proven; and
- broad observability or surveillance telemetry. Metrics remain opt-in,
  content-free, and tied to explicit product gates.

## Compounding assets

| Stage | Product asset | Compounding evidence asset |
|---|---|---|
| Explicit local reads | simple exact wrapper and reversible onboarding | admitted/refused shapes, invalidation corpus, real repeat patterns |
| Kernel supervisor proof | real descendant transport and cleanup | kernel/profile compatibility and fault corpus |
| Execute-only pytest | safe useful Linux execution | traced unsupported surfaces and workload compatibility |
| Candidate + shadow | complete semantic records | minimized divergences and dependency closure |
| Local reuse | saved pytest execution | validation history and calibrated replay preconditions |
| Managed team reuse | shared verified savings | cross-machine equivalence, provenance, and organization-specific effect graphs |

The moat is conservative reuse authority backed by evidence. A blob store,
leaderboard score, or opaque classifier is not sufficient.
