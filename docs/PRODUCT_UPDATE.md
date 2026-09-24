# Product update — 2026-09-24

## What is available

Again is a **local source-installed beta** for a single Codex agent on macOS or Linux. Its main workflow, `again codex`, prepares a short repository brief, launches Codex with its native tools, observes completed JSON events, and saves bounded run history in a local Brain. A later task can receive relevant earlier source observations only while their source bytes remain current. Test commands are suggested, then executed by the agent.

The daemon-enabled archive passed a [four-target native install and smoke matrix](../bench/results/2026-09-23-native-beta-matrix-56d9d3e-summary.json) on macOS arm64/x64 and Linux arm64/x64. That checks packaging and local startup; it is not a published release. As of this update, the [GitHub releases page](https://github.com/alakhanpal23/again/releases) has no release and the Homebrew installation shown as a target in the product contract is unavailable. Users should follow the [source install](../README.md#install-and-run). Production qualification is still open.

## What changed recently

- The default Codex path uses native shell and editor tools while Again supplies current orientation. This avoids sending every cheap read through a proof and lookup layer.
- Brain captures supported completed reads, searches, edits, tests, run outcomes, and token usage. It can verify bounded multi-file search hits and withholds source observations after edits.
- A returning task with a strongly relevant, current Brain source can bypass the full index build; a source-bound brief diagnostic took 12 ms versus roughly 2.4–2.6 seconds for earlier index-building runs. That measures brief construction on one fixture, not total task completion.
- The multi-file search capture fault that lost one completed Rust Brain run is fixed. A [source-bound replay](../bench/results/2026-09-24-codex-run-capture-d8fc30a/capture.json) retained the run and exact raw-event command and token counts; capture errors now surface to the caller.

## Outcome evidence

The [initial two-repository cohort](../bench/results/2026-09-24-real-repository-cohort-38c8bc7/summary.json) accepted 8/8 pairs, with median Again/baseline ratios of 0.801 for lifecycle time and 0.884 for API-equivalent cost. The frozen gate required both at or below 0.800, so it failed.

The [expanded four-repository cohort](../bench/results/2026-09-24-diverse-real-cohort-bb44f50/summary.json) accepted 14/16 pairs. On accepted pairs, median ratios were 0.849 for lifecycle time and 0.903 for API-equivalent cost. The predeclared gate required every pair accepted and both ratios at or below 0.800. It failed. A baseline repair failed its independent validation; an Again Rust repair passed validation but lost its Brain run under the earlier capture implementation. The later capture fix cannot retroactively change the frozen result. The [audit](../bench/results/2026-09-24-diverse-real-cohort-bb44f50/audit.json) verifies all 48 raw prior and repair traces.

These are diagnostics across four historical bugs, not proof of a general speed or cost improvement. API-equivalent cost is calculated from observed tokens at a frozen model rate card, not from invoices. Individual tasks improved and regressed; the accepted-only medians omit failed outcomes.

## Next release gate

1. Publish a tagged source-bound native beta only after the release workflow passes and the exact archive and installation instructions are verified. Until then, keep source install as the user path.
2. Run a frozen cohort of **at least 20 distinct tasks in eight repositories**, across languages and task types, cold and returning in both orders. Charge Brain preparation to returning tasks; retain raw event streams, source/binary identities, agent-run validation, and independent edit oracles.
3. Require every paired outcome to be correct, validated, and captured. Compare completion time, tool executions, input/output tokens, and API-equivalent cost on the full accepted set. Publish per-task distributions and regressions, not just median ratios.
4. Only describe Again as a proven faster or cheaper production tool after that quality and performance gate passes and release/operational support is in place.

Implementation detail and remaining work live in [STATUS.md](STATUS.md), [ARCHITECTURE.md](ARCHITECTURE.md), and the [single-agent product plan](SINGLE_AGENT_PRODUCT_PLAN.md).
