# Again

Again helps one coding agent start with a verified repository brief, carry useful source knowledge into later tasks, and avoid repeated investigation. Its local Again Brain records completed Codex activity and rechecks source bytes before presenting prior reads or edits as current.

![Again system design: a command is classified, its scoped observation and stored proof are verified, then the result is reused or executed](docs/system-design.svg)

*Pre-alpha: the single-agent workflow has local task evidence; broad production qualification and proof-based test reuse remain open.*

## Current product

- `again codex --workspace <path> --task-id <id> --task <text> -- [codex flags]` — launch Codex with bounded current source previews, relevant Brain history, and a validation suggestion. Completed tool calls and run usage are recorded locally.
- `again brain show|clear --workspace <path>` — inspect or clear bounded activity, source observations, test hints, and Codex run summaries. Brain history is guidance; tests still run.
- `again build-info` — show the Git revision and source-cleanliness embedded at build time for reproducible task evaluations.
- `again brain hook-setup --workspace <path>` — preview the repository-scoped Codex observer; add `--apply` to install it or `--remove` to restore an unchanged prior hook configuration. Completed interactive Bash calls and successful native patches can then update Brain without hand editing Codex settings.
- `again brain observe-codex-hook` — the observer's stdin adapter. It emits no hook output and never changes a tool call.

For interactive Codex sessions, add `--with-brain-hook` to the MCP setup
command, or run the standalone hook setup command in that repository. Again preserves unrelated
handlers and refuses to overwrite a hook file changed after installation.

The observer does not rewrite or skip a tool call. Codex hook coverage and
response shapes vary by tool; unrecognized responses contribute only command
metadata. [Hook contract](https://learn.chatgpt.com/docs/hooks).
- `again run -- <argv...>` — run a command through the conservative local engine; cache hits return stored stdout, stderr, and status without rerunning the requested command.
- `again reference -- <argv...>` — verify an existing hit and emit compact content-addressed JSON; a miss never executes the command.
- `again mcp connect --workspace <path>` — start or join the authenticated per-workspace daemon and proxy MCP over stdio. The daemon drains active sessions and retires after ten idle minutes.
- `again mcp setup --client codex|claude --workspace <path>` — print an exact dry-run plan. Add `--apply`, `--inspect`, or `--remove`; MCP changes use only the official client CLI and are verified afterward. For Codex, add `--with-skill` and `--with-brain-hook` to `--apply` or `--inspect` to manage the personal skill and project Brain observer in the same flow.
- `again mcp daemon status|stop --workspace <path>` — inspect or drain the local workspace daemon. New sessions fail with upgrade guidance when the executable or protocol differs.
- `again task list|inspect|export|delete|prune` — manage durable workspace tasks. Export creates a new private `0600` file; deletion requires `--yes`, and pruning requires an explicit `--dry-run` or `--apply`. Terminal history is retained until one of these explicit deletion operations succeeds.
- `again setup --codex` — install the instruction-only personal Codex skill.
- `again explain [id]` / `again show <id>` — inspect the latest decision or retrieve exact stored output.

## Product direction

Again's near-term goal is lower time and cost per correct, validated single-agent coding task. The Brain should keep repository knowledge current across tasks, while measured tool and run activity shows whether investigation was actually avoided. Proof-based test reuse and team sharing are later gates.

## Technical Foundation

- **EffectIR schema** + **13 repository/Git tools** for exact bounded observations
- **SQLite coordination + CAS** for durable metadata, leases, events, immutable streams
- **Strict executable/profile checks** (macOS `strict-read-v0.5`: reviewed Apple tool BLAKE3 + `SystemVersion.plist`)
- **Scoped observation plans** that fingerprint only declared paths, trees, listings, identities, and Git state
- **v0 universal tool policy** separating exact reads, deterministic commands, freshness reads, mutations, credentials, communication, deployment, payment

## Status

**Pre-alpha.** Scoped validation is sampled and path-based; concurrent mutation after validation, transient global-resource changes, same-user/root pathname races, and unauthenticated same-user metadata-store writes remain outside the current boundary.

**Do not depend on Again for correctness-sensitive workloads** until documented gates are green. Unknown means Again refuses the call; the caller must rerun the original unchanged.

**Evidence checkpoint:** See [current implementation status](docs/STATUS.md) and its retained single-agent cohorts, Brain ablations, and release-binary gates. Broad accepted-task, cost, and validation-reuse qualification remains open.

**100K-case gate:** Passed with stock-Linux lane retaining required typed non-qualifying capability result.

## Quickstart

```bash
cargo install --locked --path . --features daemon
again mcp setup --client codex --workspace "$(pwd -P)" --apply --with-skill --with-brain-hook
again codex --workspace "$(pwd -P)" --task-id fix-example --task "Fix the failing example and run its tests" -- --ephemeral
again brain show --workspace "$(pwd -P)"
```

## License

Apache-2.0.

## Roadmap

- [Agent acceleration](docs/AGENT_ACCELERATION.md) — complete user loop and product scorecard
- [Product contract](docs/PRODUCT.md) — shipping promise and current boundary
- [Straight-to-code](docs/STRAIGHT_TO_CODE.md) — edit-brief fast path and editable task evaluation
- [Reuse surface](docs/REUSE_SURFACE.md) — action-family and validation-profile inventory
- [Architecture](docs/ARCHITECTURE.md) — authority transitions and current/target component boundaries
- [Status](docs/STATUS.md) — what is implemented
- [Evidence](docs/EVIDENCE.md) — what has been measured
- [Development workstreams](docs/DEVELOPMENT_WORKSTREAMS.md) — terminal ownership and merge discipline
- [Product finish plan](docs/PRODUCT_FINISH_PLAN.md) — remaining integration, performance, qualification, and release gates
