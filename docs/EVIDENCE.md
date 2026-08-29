# Evidence ledger

Every measured performance claim must map to a reproducible command and retained raw result. Test-status claims must map to a reproducible command and, before release, an immutable linked CI run. A local passing observation is labeled as such; “pending” is not evidence.

| Claim | Metric | Gate | Current evidence |
|---|---|---:|---|
| Again reduces completed coding-task time and cost | paired task outcome, time to first useful edit, end-to-end wall time, provider calls, provider-reported tokens, validation compute, and total metered cost | pending frozen task-level gate | no live paired agent run exists. The retained real-agent artifact is an offline plan; byte counts and avoided tool calls cannot establish model-token, dollar-cost, or task-quality savings |
| Verified task-start context avoids rediscovery | admitted/current facts, invalidated facts, investigations avoided, orientation tool calls, brief bytes, and unchanged task outcome | pending | typed facts, invalidations, evidence metrics, and deterministic brief compilation exist internally; no public task-start flow or live agent evaluation exists |
| Changed-only validation is exact | affected tests executed, unaffected tests served by a fresh promoted proof, false skips, and task outcome | pending | Linux pytest authority foundations and diagnostic gates exist, but no product pytest execution, dependency-derived validation plan, promoted test hit, or skipped test exists |
| Production Codex hook is a no-op | automatic allow/rewrite decisions | 0 | pinned Rust 1.88 process fixtures passed locally and in [Rust CI run 32664468230](https://github.com/alakhanpal23/again/actions/runs/32664468230) on macOS and Ubuntu for code commit `6b131bd` |
| Unknown host/tool profiles refuse reuse | successful reuse outside an audited profile | 0 | macOS success E2Es are guarded by a predicate covering the exact host OS and every audited Apple-tool BLAKE3; unknown-profile refusal passed in [Rust CI run 32664468230](https://github.com/alakhanpal23/again/actions/runs/32664468230) |
| Narrow v0 fixtures show no known incorrect reuse | known incorrect hits in executed fixtures | 0 | targeted engine and unit fixtures are local regression evidence; generated classifications are not cache-hit or general-equivalence evidence, and concurrent path mutation plus transient global-resource races remain outside the boundary |
| Exact stored output is retrievable | retrieval equality | 100% | process integration fixture passed locally and in [Rust CI run 32664468230](https://github.com/alakhanpal23/again/actions/runs/32664468230) |
| Every `again run` hit preserves full streams | warm stdout/stderr equality after executable probe | 100% | [`2026-08-23-direct-v1.json`](../bench/results/2026-08-23-direct-v1.json) records 15/15 byte-exact full-stream hits plus an exact cold run and mutation miss; explicitly requested `again reference` has a separate gate |
| Explicit reference omits only already-visible duplicate bytes | output-byte reduction with exact retrieval and no-execution misses | >=99% on the 1 MiB fixture | [`2026-08-23-reference-v2.json`](../bench/results/2026-08-23-reference-v2.json) passed 25/25 full hits and 25/25 bound references, exact `show`, cold/mutation no-execution misses, event/counter equality, and 99.9719% observed byte reduction; no tokenizer, model, or task-cost claim |
| Local hit is fast | p95 explicit-CLI startup + identity/context validation + capability-probe child + lookup + full-stream output | <100 ms | current working-tree retained run: 12.013 ms warm p95 on its recorded macOS arm64 host and fixture; the prior clean-commit run recorded 10.537 ms |
| Useful work accelerates | native p50 / explicit-run warm end-to-end p95 | >=3x when native p50 >=500 ms | current working-tree retained run: 49.442x, from 593.929 ms native p50 / 12.013 ms warm Again p95 on the recorded 2 GiB sparse-file `grep` fixture; all 15 hits reported 7,260 ms of positive net wall time saved |
| Trace-backed profile is trustworthy | unexplained differential mismatches | 0 / 100,000 | not implemented |
| Narrow policy classification is stable | classification violations | 0 / 100,000 | deterministic seed `0xa6a120265eedc0de`; [Rust CI run 32664468230](https://github.com/alakhanpal23/again/actions/runs/32664468230) passed 40,000 eligible and 60,000 non-eligible classifications, four fingerprint differentials and the available fixed two-run fixtures on macOS and Ubuntu. Classifications do not exercise executable/OS identity, runtime context, or hit probes |
| Narrow polyglot product path is exact | native status/stdout/stderr mismatches, stale mutation hits | 0 / 1,010 Again invocations | [`2026-08-23-polyglot-reuse-v1.json`](../bench/results/2026-08-23-polyglot-reuse-v1.json) passed 505 cold executions, 505 full replays, five mutation misses, and five new-epoch hits across Rust/Python/Go/TypeScript/shell-shaped repositories. Tiny native p50 values were about 2.2 ms and correctly produced zero estimated net savings; this is not language-semantic or speed evidence |
| Real-repository corpus is exact | native/cold/warm status or stream mismatches; stale mutation replay | pending | the bounded offline harness and portable adversarial tests are implemented and run in CI, but no retained report against explicit real Rust, Python, Go, and TypeScript repositories exists. Harness availability is not correctness or performance evidence |
| Fixed Linux supervisor transport closes Gate 2 | failed fixed samples or missing delivery order | 0 / 100; both orders required | provisioned [`Gate 2 run 32965300493`](https://github.com/alakhanpal23/again/actions/runs/32965300493) passed 100/100 at source `3d1fb201507a43b830d5ce341b2253957634016d` with 99 parent-event-first and 1 child-stop-first samples. Offline verification bound all 302 artifact members and the recorded archive/member-manifest hashes. This is command-free transport evidence only and grants no Python, profile, execution, or reuse authority |
| Gate 3 execute-only evidence shape is internally consistent | malformed fixture/snapshot/archive cases accepted | 0 in portable adversarial suites | fixed-fixture, reference-snapshot, and offline archive-verifier tests run in hosted CI. They execute no pytest workload and do not verify caller-reported runtime provenance, so they are diagnostic-contract tests rather than Gate 3 execution evidence |
| Selected team protocol/service scenarios hold locally | known boundary violations in tested namespace/auth/signature/wire/state-machine fixtures | 0 | typed protocol, concrete Ed25519, shared positive/negative wire-boundary, transport, and the earlier Worker boundary passed in [Service CI run 32664343315](https://github.com/alakhanpal23/again/actions/runs/32664343315). Current bundle, generation, lifecycle, and trust additions have broader local coverage but no immutable CI result linked here; this is not exhaustive, deployed, or external-review evidence |
| Bundle/reference protocol mapping is synthetically stable | disposition/byte mismatches | 0 / 100,000 | the deterministic [`lookup_bundle_state_matrix_protocol_parity_100k`](../src/team_pull/team_lookup_bundle_differential.rs) gate passes production bundle/reference response decoders and error mappers against a literal oracle. It creates synthetic responses in Rust; it does **not** execute the Worker or stateful D1/R2 transitions |
| Actual Worker bundle/reference states agree | mismatched outcome classes or hit bytes | 0 / 18 states | the enumerated [`service.spec.ts` state matrix](../service/test/service.spec.ts) executes the real Worker bundle and five-request routes against isolated D1/R2 bindings for hit, ordinary miss, corruption/trust, and generation states. This finite matrix is stateful; it is not the missing 100,000-case stateful path |
| Bundle request and overlap accounting is exact locally | request-count mismatch; failed four-way maximum-stream overlap | 0; 0 | [`2026-08-23-lookup-bundle-v1-50ms-matrix-v1.json`](../bench/results/2026-08-23-lookup-bundle-v1-50ms-matrix-v1.json) passes exact two-versus-five counts and proves four maximum-size responses overlap with eight live sources. Its Wrangler-process-tree RSS observation is not current isolate-heap proof |
| Bundle p95 clears the 50 ms per-size rollout gate | improvement over five-request reference at 0 B / 4 KiB / 1 MiB / 16 MiB | >=40% for every size | the same 100-repetition artifact records 59.41% / 59.61% / 52.17% / 1.208%; the maximum-size cell fails, so the overall gate fails and bundle v1 remains experimental/unshipped |
| Bundle HTTP disconnect cancels retained sources | cancelled sources after actual loopback TCP reset | 2 / 2 | [`2026-08-23-lookup-bundle-v1-finite-disconnect-v1.json`](../bench/results/2026-08-23-lookup-bundle-v1-finite-disconnect-v1.json) passes 2/2 finite-source cancellation in 62.5 ms, while the pending-source probe in the [50 ms matrix](../bench/results/2026-08-23-lookup-bundle-v1-50ms-matrix-v1.json) fails at 0/2 after 3.014 s. Direct body cancellation in unit tests is not an HTTP-disconnect substitute |
| Manual bundle client/service lifecycle works | required lifecycle checks | all retained checks true | [`2026-08-23-team-live-e2e-bundle-v1.json`](../bench/results/2026-08-23-team-live-e2e-bundle-v1.json) exercises two clients through production rustls and a public-CA Quick Tunnel into local Wrangler D1/R2: publish, exact hit, trust rotation, wrong-key/corruption quarantine, revocation, deletion/recreation, stale refusal, and republish/hit pass. It is a dirty-tree single-host manual run, not deployment, a full live matrix, or the cross-layer post-decrypt race |
| Team alpha has bounded CI integration | portable/mock and real-binary wrapper boundary failures | 0 in retained local run | [`2026-08-23-team-ci-boundary-v1.json`](../bench/results/2026-08-23-team-ci-boundary-v1.json) records the wrapper, composite action, hostile-environment checks, and a bounded offline/fallback production-wrapper run. It did not use a deployed endpoint or remote hit and does not provide public onboarding |
| Local result metadata corruption is fail-closed | semantic result/validation-record mismatch served | 0 | unit and process-level policy-version/record/digest tamper fixtures pass; same-user cryptographic authentication is not implemented |
| Local secret-taint classification | admitted secret-bearing arguments/outputs detected | required | not implemented; no credential-safety or automatic-shareability claim |

Benchmark raw JSON, machine metadata, commit SHA and scripts belong under `bench/results/`. The current product command is documented in [`bench/README.md`](../bench/README.md) and runs `bench/direct_benchmark.py` against a release binary with all standard streams non-TTY. The harness removes and records the forbidden ambient-input names before measuring. Never replace a failing run; append a new one and explain the change. Test procedures belong in versioned documentation/workflows, and release claims require a linked immutable CI result for the claimed commit.

## Retained runs

[`2026-08-23-direct-net-current-v3.json`](../bench/results/2026-08-23-direct-net-current-v3.json)
is the current dirty-working-tree product-path run after replay accounting was
changed from stored producer duration to positive net wall time saved. It used
the recorded Rust 1.88 release binary, exact full streams, five native
baselines, 15 warm hits, and the controlled same-output mutation over the 2 GiB
logical sparse-file fixture. Native p50 was 593.929 ms and warm Again p95 was
12.013 ms, yielding 49.442x. Every exactness and mutation gate passed, and the
15 hits recorded 7,260 ms of net savings after measured wrapper time. The JSON
retains the exact dirty entries, source commit, harness and binary hashes; it
is local working-tree evidence, not immutable release or clean-commit evidence.

[`2026-08-23-polyglot-reuse-v1.json`](../bench/results/2026-08-23-polyglot-reuse-v1.json)
is a dirty-tree product-path correctness run over five deterministic synthetic
repository layouts. It passed all 1,010 Again invocations with exact native
status/stdout/stderr, 505 full hits, five modeled mutation misses, five hits on
the new input epochs, zero bypasses/quarantines/compact replays, and zero
estimated net milliseconds saved. Warm p95 ranged from 7.00 to 7.15 ms while
native p50 was roughly 2.2 ms, explicitly demonstrating that trivial reads are
not the economic workload. The corpus found and caused repair of the audited
BSD `head` capability probe before this retained run.

[`2026-08-23-reference-v2.json`](../bench/results/2026-08-23-reference-v2.json)
is a dirty-tree release-binary run of the explicit lookup-only presentation.
For one stored 1 MiB output it passed 25 exact full hits, 25 references bound to
the same result and stream digests, exact `show` recovery, cold and mutated
reference misses with zero execution counters, and event/stat agreement. The
references emitted 7,375 bytes instead of 26,214,400 duplicate full-stream
bytes, omitting 26,207,025 bytes for 99.9719% observed reduction; reference p95
was 11.468 ms and full-hit p95 was 11.779 ms. The harness explicitly records
that hooks, Codex models and tokenizers were not exercised, so this is output-
byte and latency evidence only—not measured model tokens, inference cost, or
agent-task quality.

[`2026-08-23-reference-v1.json`](../bench/results/2026-08-23-reference-v1.json)
is the immediately preceding passing run retained rather than overwritten. Its
wire/correctness/byte results match v2; v2 supersedes its timing claim after the
CAS-corruption quarantine path and regression fixture were added.

[`2026-08-23-lookup-bundle-v1-50ms-matrix-v1.json`](../bench/results/2026-08-23-lookup-bundle-v1-50ms-matrix-v1.json)
is a local Wrangler/workerd protocol benchmark with an immutable synthetic
streaming Worker, not the production D1/R2 route. For 100 measured repetitions
plus two warmups per size at one 50 ms response-start delay, bundle/reference
p95 improvement was 59.41% at 0 B, 59.61% at 4 KiB, 52.17% at 1 MiB, and
1.208% at 16 MiB. Exact 2-vs-5 request counts, all response bytes/hashes, and
four-way maximum-response overlap passed. The 16 MiB cell fails the unchanged
40% gate. Its actual TCP-reset probe with an indefinitely pending first read
also fails: 0/2 sources were cancelled after 3.014 seconds and the response
remained active. The recorded process-tree RSS is explicitly not Worker-isolate
heap evidence.

[`2026-08-23-lookup-bundle-v1-finite-disconnect-v1.json`](../bench/results/2026-08-23-lookup-bundle-v1-finite-disconnect-v1.json)
separates the weaker finite-source case: after an actual loopback TCP reset,
2/2 sources settled as cancelled in 62.5 ms. This does not repair or supersede
the pending-reader failure.

[`2026-08-23-team-live-e2e-bundle-v1.json`](../bench/results/2026-08-23-team-live-e2e-bundle-v1.json)
is the manual implementation-lifecycle result for the actual Worker route and
Rust client. It used a public-CA Quick Tunnel to local Wrangler D1/R2 and passed
publisher miss/publication, independent-reader exact reuse, trust rotation,
wrong-key and R2-corruption quarantine, producer revocation, repository
deletion/recreation, stale-generation refusal, and new-generation
publication/reuse. The profile enforced the two-request ceiling; a separate
deterministic client test observes the exact two calls. The nine timing samples
are transport observations, not a production speed gate.

[`2026-08-23-team-ci-boundary-v1.json`](../bench/results/2026-08-23-team-ci-boundary-v1.json)
records local passing checks for the one-secret materializer, bounded wrapper,
composite action boundary, real binary, and a hostile environment. The endpoint
in the production-wrapper observation was deliberately nonexistent, so the
result proves bounded inspection/fallback behavior rather than a remote hit.
It is integration for manually provisioned state, not hosted onboarding.

Bundle v1 remains opt-in experimental and unshipped. Missing ship evidence is
the full four-size by four-latency local matrix plus live counterpart, direct
proof of current Worker-isolate heap usage for four maximum responses, a
100,000-case stateful D1/R2 bundle/reference path, and a cross-layer race that
rotates or revokes trust after authenticated decryption but before the client's
final trust fence.

[`2026-08-23-direct-v1.json`](../bench/results/2026-08-23-direct-v1.json) is the prior clean-commit product-path result for source commit `7a238d5`. It used the Rust 1.88 release binary, explicit non-TTY `again run`, exact full streams, five native baselines, 15 warm hits, and a controlled same-output input mutation across a 2 GiB logical sparse-file `grep` fixture on the recorded macOS arm64 host. Native p50 was 721.467 ms; warm Again p95 was 10.537 ms, yielding 68.473x. All correctness gates and the conditional 3x speed gate passed. Cold double validation cost 2,713.629 ms and the post-mutation miss cost 1,652.163 ms, so this result does not claim that first runs or trivial commands are faster. Page cache was not dropped, aggregate allocation was sparse, stdout was 144 bytes, and the result generalizes only to its recorded commit, binary, host, environment and fixture. Its scope fields explicitly record that hooks, models, compaction and token reduction were not exercised. Its historical replay-savings counter used the producer duration rather than the newer positive-net accounting, so only the timing and exactness measurements remain current claims.

The four legacy runs below are **historical and superseded**. They exercised automatic Codex hook rewriting and compact-reference delivery. Both are now disabled because hooks expose only session cwd rather than effective per-call workdir and still hide other invocation context, the output ceiling, and delivery confirmation. The files are retained without alteration for provenance and regression archaeology; none satisfies a current performance, hit-latency, output, or release gate.

- [`2026-08-23-macos-arm64-v2.json`](../bench/results/2026-08-23-macos-arm64-v2.json): dirty-tree pre-checkpoint run of the earlier compact-reference hook path. Its recorded safety, recovery, latency, invalidation, and output-reduction outcomes describe that historical implementation only. Native `cat` was faster and its speed gate was `not_applicable`.
- [`2026-08-23-macos-arm64-v3.json`](../bench/results/2026-08-23-macos-arm64-v3.json): clean commit `0421bad`, 25 warm samples of the earlier compact-reference implementation. It recorded hook p95 6.359 ms, exec p95 8.088 ms, end-to-end p95 14.110 ms, and 99.992% output reduction. Native `cat` remained faster; the speed gate was `not_applicable`.
- [`2026-08-23-codex-e2e.json`](../bench/results/2026-08-23-codex-e2e.json): Codex CLI 0.149.0 session in which a bare `cat input.txt` was transparently rewritten and a repeat produced a compact reference. Both behaviors are disabled: the production hook now emits no automatic decision and explicit `again run` returns full streams. The fixture also accidentally retained the same project hook, so two handlers matched.
- [`2026-08-23-slow-gate-v1.json`](../bench/results/2026-08-23-slow-gate-v1.json): clean commit `58188d5`, 2 GiB logical sparse-file `grep` with 32 output bytes. It recorded native p50 962.473 ms, warm end-to-end p95 23.675 ms (40.653x), hook p95 9.797 ms, and exec p95 7.096 ms while all 25 repeats were compact references. Its input mutation forced a miss and cold double validation cost 3,416.835 ms. These measurements do not establish current full-stream behavior or speed.

The generated corpus procedure and limitations are retained in [`CORPUS.md`](CORPUS.md). [Rust CI run 32664468230](https://github.com/alakhanpal23/again/actions/runs/32664468230) and [Service CI run 32664343315](https://github.com/alakhanpal23/again/actions/runs/32664343315) are immutable test-status evidence, not retained performance runs. Service evidence is Miniflare/Vitest evidence, not production Cloudflare behavior; see the [`service` README](../service/README.md) and [remote threat model](REMOTE_THREAT_MODEL.md).
