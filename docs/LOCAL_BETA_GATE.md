# Local beta product gate

The local beta is releasable only when one candidate commit has all five kinds
of retained evidence below. Unit tests, dry runs, synthetic agents, and a local
unsigned binary are useful qualification inputs, but none can substitute for a
missing release input.

| Evidence | Required scope |
|---|---|
| Product scenario | The ordered 12-step install-to-uninstall lifecycle |
| Chaos/soak | `beta` mode, 100 concurrent `mcp connect` clients, one automatic daemon, zero false hits or resource leaks |
| Native package smoke | Exactly one result for each macOS/Linux arm64/x86_64 target |
| Real-agent review | Outside-user paired Codex and Claude runs, direct metrics, independent patch review, zero incorrect hits and no quality regression |
| Release verification | Immutable exact tag, authenticated publisher, seven signed subjects plus seven Sigstore bundles |

[`bench/local_beta_gate.py`](../bench/local_beta_gate.py) is the final
fail-closed aggregator. It validates the evidence contracts, binds all reports
to one 40-character source commit, binds product/chaos/agent results to the same
binary SHA-256, and writes only compact digests and release decisions. It does
not create a tag, publish a release, run an agent, infer success from a local
fixture, or turn an absent report into a skip.

## Product scenario contract

The scenario report schema is `again.local-beta-product-scenario.v1`. Its
`steps` must contain these names in this exact order, and every step must be a
pass:

1. `isolated_install`
2. `client_setup`
3. `automatic_daemon_clients`
4. `task_alias_convergence`
5. `task_graph_readiness`
6. `context_exchange`
7. `leader_takeover`
8. `lifecycle_completion`
9. `daemon_restart_recovery`
10. `repository_mutations`
11. `quota_maintenance`
12. `upgrade_remove_uninstall`

The validator checks the product invariants, not only the step labels. Among
other things, it requires one canonical definition and leader for aliased task
starts; dependency waiting and readiness; a higher takeover generation with a
stale-leader refusal; immutable terminal history across restart; relevant-only
invalidation; maintenance-mode inspect/export/delete/prune/GC/doctor/stats;
private no-overwrite exports; zero automatic eviction; safe upgrade draining;
exact client removal; and uninstall.

The same report must retain the adversarial matrix. It requires 100 concurrent
clients, at least two repositories, a positive retained soak duration, all
transport/storage/graph/migration/hostile-input probes, and zero cross-scope
hits, duplicated completions, false hits, secret leaks, silent evictions, or
unauthorized retrievals.

Scenario diagnostics deliberately exclude prompt text, context, stdout,
stderr, result content, endpoint authority, configuration documents, and
credential values. Only digests, counts, typed outcomes, and non-sensitive
identifiers belong in retained evidence. Credential-shaped text is rejected
even under an otherwise permitted field.

## Chaos beta mode

The chaos harness retains its quick and soak modes and adds a release-only beta
mode:

```bash
python3 -B bench/agent_gateway_chaos_soak.py \
  --again-binary /absolute/path/to/again \
  --mode beta \
  --concurrency 100 \
  --duration 600 \
  --json-out /absolute/path/to/chaos-beta.json
```

Beta mode uses `again mcp connect` for all exact-probe sessions. The first
connection must lazily start the workspace daemon, the task lifecycle tools
must be advertised, all sessions must return one exact result identity, and an
authenticated daemon stop must make the endpoint unavailable. The harness
still performs transport corruption, partial-frame, duplicate-ID, saturation,
restart, store-corruption, cleanup, descriptor, CPU, RSS, and temporary-state
checks. A host resource refusal is a non-pass, not evidence for a smaller
matrix.

## Native and real-agent evidence

Each native report uses `again.local-beta-native-smoke.v1` and records one of
the four closed target names, source, archive and installed-binary digests, and
passing install, daemon, authenticated MCP, doctor, and uninstall checks. The
same report also proves connector-driven automatic startup, exact Codex and
Claude setup plans, and the closed task/context/repository tool catalog. The
archive and installed-binary digests must equal the corresponding signed
release subject. Duplicate targets do not fill a missing job.

The outside-user report uses `again.local-beta-real-agent-review.v1`. Codex and
Claude each need paired baseline/Again observations for first correct edit,
duplicate reads and investigations, tool calls, response bytes, input/output
tokens, cost, validated completion time, and patch quality. The report must
state that it is outside-user evidence rather than a deterministic-harness-only
result. Incorrect hits, stale or incorrect facts, and quality regressions must
all be zero, and patches must be independently reviewed.

## Final aggregation

After the final candidate has all retained inputs:

```bash
python3 -B bench/local_beta_gate.py \
  --scenario-evidence /absolute/path/to/product-scenario.json \
  --chaos-evidence /absolute/path/to/chaos-beta.json \
  --real-agent-evidence /absolute/path/to/real-agent-review.json \
  --release-evidence /absolute/path/to/release-verification.json \
  --native-evidence /absolute/path/to/aarch64-apple-darwin.json \
  --native-evidence /absolute/path/to/x86_64-apple-darwin.json \
  --native-evidence /absolute/path/to/aarch64-unknown-linux-gnu.json \
  --native-evidence /absolute/path/to/x86_64-unknown-linux-gnu.json \
  --output /absolute/new/path/local-beta-gate.json
```

Input files must be bounded regular non-symlink files and remain unchanged
while read. The output is created once with mode `0600` and is never
overwritten. Success records SHA-256 bindings to every input and explicitly
states that tag creation remains a human release-authority action.

## Wave 2 integration

Terminal D owns the scenario and gate contracts. After A+B+C are linearized,
D must connect the black-box scenario producer to the accepted public CLI/MCP
wire shapes and generate fresh evidence from the packaged candidate. Failures
in daemon, lifecycle/storage, or packaging behavior go back to the original
owner and are rebased forward. Until all five retained evidence classes pass,
the local beta release status remains **not qualified**.
