# Delivery roadmap and product gates

This roadmap starts from the implementation described in [STATUS.md](STATUS.md).
Dates are planning labels, never evidence. A phase advances only when its exit
gate has a reproducible result and, where required, an immutable CI or retained
runtime artifact.

## Product objective

Again should eliminate repeated agent wait time without serving a result whose
inputs, execution profile, or effects are not proven equivalent. The product
advances through three user-visible stages:

1. **Explicit local exact reads:** accelerate a deliberately narrow set of
   audited read-only commands while preserving complete streams.
2. **Trace-backed local pytest:** execute one frozen pytest invocation shape in
   an isolated Linux profile, then admit reuse only after complete observation
   and independent shadow agreement.
3. **Managed team reuse:** share encrypted, signed results only across equivalent
   repository and execution profiles with local verification.

The current product is in stage 1. Stage-2 snapshot, isolation, seccomp, ptrace,
and wire foundations exist, but no Linux pytest command can execute through the
profile and no Linux reuse authority exists. Stage 3 has a manually provisioned
client/service foundation, not a deployed product.

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
outcome grants no pass, qualification, execution, or reuse authority. No CLI,
isolation, tracer, or stdio path consumes this scaffold yet. A dedicated
connector transition can now consume the lexical proof while compiling the
four-view workspace tree, verify the fixed selector's regular-file type,
length, single-link manifest topology, and content digest before publication
escrow or rename,
and return one opaque linear workspace-tree binding. Nothing calls that
transition yet; it covers neither the runtime tree nor executable resolution
and exposes no descriptor, execution, candidate, or reuse authority.

The first acceptance fixture should use exactly one selector, such as
`tests/test_smoke.py::test_smoke`. It must compose:

- two-phase lexical and snapshot-backed admission;
- connector-qualified immutable workspace/runtime snapshots;
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
