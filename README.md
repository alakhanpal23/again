# Again

**A repository Brain for one coding agent.** Again starts a task with a short, source-checked brief and carries useful investigation into later tasks. It observes completed Codex tool events, records bounded local history, and rechecks source bytes before presenting an earlier read or search as current. The agent keeps using its normal editor and shell tools and runs tests after changing code.

Again is an experimental local developer tool. The key question is whether the brief and Brain reduce **time and API-equivalent cost per correct, validated task** across real repositories. See [Qualification](#qualification) for the measured boundary.

## When to use it

Use Again when you work repeatedly in the same repository with Codex: bug fixes, small features, and follow-up tasks that tend to revisit the same files or test commands. The clearest opportunity is a returning task whose prior source investigation is still current. Again can also help a cold task by pointing to likely files and a project test command before the first edit.

```bash
cargo install --locked --path . --features daemon
cd /path/to/your/repository
again codex --workspace "$(pwd -P)" --task-id fix-issue-123 \
  --task "Fix issue 123 and run the relevant tests" -- --ephemeral
again brain show --workspace "$(pwd -P)"
```

The `--` separates Again options from Codex options. Use a distinct task ID for each task. The launcher requires the Codex CLI and your existing Codex authentication. It does not require a hosted Again service.

## What the agent receives

1. **Current task brief.** Again identifies likely source files and provides up to two bounded, digest-checked previews. A small preview may be complete; a large file gets a labelled excerpt and may require a wider read.
2. **Repository Brain.** A previous completed read, search, edit, or test can become a compact hint. Before reusing source content in the next brief, Again checks the current file bytes. An agent-authored finding remains a suggestion, not a verified source fact.
3. **Validation guidance.** Again can suggest a relevant project test command. The suggestion does not certify the edit; run validation for the new change.
4. **Observed outcome.** The launcher records completed command, edit, and test events plus a compact run and token summary locally. `again brain show` lets you inspect that history.

The normal `again codex` path does not intercept native shell calls or silently skip tests. Exact output reuse is available separately through `again run` for eligible commands with a fresh proof; cheap ordinary reads often cost less to execute directly.

## System design

```mermaid
flowchart LR
  U[Developer task] --> L[again codex launcher]
  L --> B[Task brief builder]
  R[Current repository files and manifests] --> B
  M[(Local Brain: SQLite metadata + content addressed bytes)] --> B
  B --> C[Codex with native tools]
  C --> E[Completed JSON tool events]
  E --> V[Bounded parser and source verification]
  V --> M
  C --> T[Edit and run tests]
  T --> E
  M --> N[Next task brief]
  R --> N
```

The local workspace daemon supplies task lifecycle and MCP context. The Brain stores bounded observations and recent run summaries. Source digests guard reuse of earlier file content; stale observations are withheld. Storage can help the agent avoid investigation, but it cannot prove that a test still passes after a new edit.

## Technology

| Layer | Implementation |
| --- | --- |
| CLI and local daemon | Rust 2024, minimum Rust 1.88; `clap`, `tokio`, JSON-RPC/MCP |
| Persistent state | Bundled SQLite via `rusqlite`, content addressed blobs, BLAKE3 digests |
| Agent integration | Codex CLI JSON event stream; optional repository-scoped `PostToolUse` hook for interactive sessions |
| Repository context | Bounded source previews, Git and manifest checks, source-checked Brain observations |
| Validation and benchmarks | Rust tests and Python 3 paired live-agent harnesses with independent edit oracles |

The optional MCP setup for interactive Codex is:

```bash
again mcp setup --client codex --workspace "$(pwd -P)" --apply --with-skill --with-brain-hook
```

Review and trust the project hook in Codex `/hooks` after installing it. The `again codex` launcher captures its own event stream without the hook. See [product contract](docs/PRODUCT.md) for command behavior and safety boundaries.

## Qualification

The [expanded frozen cohort](bench/diverse_real_cohort_v2.json) tested historical bugs in Packaging, Camelcase, Again, and Tomlkit across Python, JavaScript, and Rust. Each bug was run cold and returning in both baseline-first and Again-first order. Returning tasks included a **real prior agent investigation in both conditions**; its time and tokens were charged to the task lifecycle. The source-bound release binary and prompts were frozen at `bb44f50` before the run.

| Cohort | Planned pairs | Accepted pairs | Median Again / baseline time | Median API-equivalent cost | Frozen gate |
| --- | ---: | ---: | ---: | ---: | --- |
| [Initial two-repository run](bench/results/2026-09-24-real-repository-cohort-38c8bc7/summary.json) | 8 | 8 | 0.801 | 0.884 | Failed |
| [Expanded four-repository run](bench/results/2026-09-24-diverse-real-cohort-bb44f50/summary.json) | 16 | 14 | 0.849* | 0.903* | Failed |

\*The expanded medians include only the 14 accepted pairs and **cannot establish a speed or cost win**. One baseline Camelcase repair failed its test. One correct Again Rust repair passed its test but the launcher failed to retain the completed Brain run; a multi-file search exposed an overly strict run-summary bound, subsequently fixed and covered by a regression gate. The accepted Rust pairs also showed a time regression in one cold order and the returning order. The original gate required **every pair accepted** and both medians at or below **0.800**. Neither cohort met that gate. API-equivalent cost applies a frozen model rate card to observed tokens; it is not a Codex bill.

The most promising use case in this sample was the small Camelcase repair, where Again sped up both cold orders. Packaging gains were modest. Tomlkit cold runs were slower on the expanded repeat, while its returning runs were faster. Four bugs and 16 pairs remain too small and varied to prove a product-wide effect. See [implementation status](docs/STATUS.md) for the failure analysis and remaining qualification work.

Run the frozen evaluation from a clean checkout with a source-bound release binary:

```bash
cargo build --locked --release --features daemon
python3 bench/diverse_real_cohort_v2.py \
  --binary target/release/again \
  --output-dir /tmp/again-diverse-real-cohort
```

The retained reports include source and binary hashes, independent edit-oracle outcomes, agent-run test checks, prior-task usage, and raw Codex JSONL. Historical diagnostics outside this cohort do not upgrade the measured claim.

## Boundaries and project map

- Brain observations are local to the workspace. Previous reads are presented only while their source is current; command metadata can be incomplete for unrecognized shell forms.
- Again does not broadly cache the agent's native tools. Explicit command reuse and the MCP gateway have narrower proof and eligibility rules.
- Test suggestions require execution. Proof-based test skipping and broad cross-repository task acceleration remain open gates.

See [architecture](docs/ARCHITECTURE.md) for the full authority model, [status](docs/STATUS.md) for verified implementation, [evidence](docs/EVIDENCE.md) for retained results, and [product plan](docs/SINGLE_AGENT_PRODUCT_PLAN.md) for remaining work.

Apache-2.0 licensed.
