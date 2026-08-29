# Again

Again is a repository-aware execution memory and tool-call control plane for coding agents. It skips only work proven redundant, executes uncertain work, and returns the smallest useful verified observation.

## Product

**Current (Default Product):**

- `again run -- <argv...>` — Run commands through a conservative local engine; cache hits return stored stdout/stderr/status without rerun
- `again reference -- <argv...>` — Verify existing hits and emit compact content-addressed JSON; never executes on miss
- `again mcp serve --workspace <path>` — Exposes 13 bounded read-only repository/Git tools over MCP stdio
- `again mcp setup --client codex|claude --workspace <path>` — Print ownership-checked, dry-run configuration
- `again setup --codex` — Install instruction-only personal Codex skill
- `again explain [id]` / `again show <id>` — Retrieve stored results or latest persisted event

**Product Direction:**

Again gives coding agents persistent, verified repository understanding and execution memory so they can move from task to correct code with less rediscovery, fewer tool calls, and less repeated validation.

**Target outcome:** Helping coding agents start with verified repository understanding, avoid repeating work, run only the validation that changed, and share exact execution knowledge across agents.

## Technical Foundation

- **EffectIR schema** + **13 repository/Git tools** for exact bounded observations
- **SQLite coordination + CAS** for durable metadata, leases, events, immutable streams
- **Strict executable/profile checks** (macOS `strict-read-v0.5`: reviewed Apple tool BLAKE3 + `SystemVersion.plist`)
- **Scoped observation plans** that fingerprint only declared paths, trees, listings, identities, and Git state
- **v0 universal tool policy** separating exact reads, deterministic commands, freshness reads, mutations, credentials, communication, deployment, payment

## Status

**Pre-alpha.** Scoped validation is sampled and path-based; concurrent mutation after validation, transient global-resource changes, same-user/root pathname races, and unauthenticated same-user metadata-store writes remain outside the current boundary.

**Do not depend on Again for correctness-sensitive workloads** until documented gates are green. Unknown means Again refuses the call; the caller must rerun the original unchanged.

**Evidence checkpoint:** Source commit `bd24946e613af656d35c6af653a6cf25adc8359d` passed exact-SHA hosted CI on 2026-08-27. Gates 1–2 retained; Gates 3+ open until outside-user evidence exists.

**100K-case gate:** Passed with stock-Linux lane retaining required typed non-qualifying capability result.

## Quickstart

```bash
cargo install --path .
again setup --codex
again mcp setup --client codex --workspace "$(pwd -P)"
again run -- cat path/to/file
```

## License

Apache-2.0.

## Roadmap

[agent acceleration](docs/AGENT_ACCELERATION.md) — complete user loop and product scorecard  
[product contract](docs/PRODUCT.md) — shipping promise and current boundary  
[straight-to-code](docs/STRAIGHT_TO_CODE.md) — edit-brief fast path and editable task evaluation  
[reuse surface](docs/REUSE_SURFACE.md) — action-family and validation-profile inventory  
[architecture](docs/ARCHITECTURE.md) — authority transitions and current/target component boundaries  
[status](docs/STATUS.md) — what is implemented  
[evidence](docs/EVIDENCE.md) — what has been measured  
[development workstreams](docs/DEVELOPMENT_WORKSTREAMS.md) — terminal ownership and merge discipline