# Again

Again is an open-source execution layer for coding-agent tool calls. It reuses a result only when it can prove the supported inputs are unchanged, and it replaces output that the same agent session has already seen with a short, reversible reference.

```text
$ again setup --codex
Codex hook installed. Review it once with /hooks.

$ again run -- rg --no-ignore -n "EffectIR" src
...full output...

$ again run -- rg --no-ignore -n "EffectIR" src
[again: exact repeat of result 01J...; 18,421 duplicate bytes omitted]
```

The current repository is an early correctness-first implementation. The example above is the target alpha experience, not a claim that arbitrary commands are safe to cache today.

## Product promise

For an eligible Codex shell call, Again returns the same successful result without re-executing it. This is faster for sufficiently expensive calls; trivial utilities can still be slower because proof and process startup have a real cost. Within one Codex session, byte-identical output already delivered in full may be represented by a compact result reference. If Again cannot prove its narrow safety conditions, the original call runs normally.

Again never treats a matching command string or basename as sufficient proof. The current macOS profile admits exact Apple system identities for narrowly parsed `cat`, `head`, `tail`, `wc`, `grep`, `ls`, and `pwd`, plus OpenAI-signed Codex-bundled `rg`. Recursive `rg` requires `--no-ignore` so parent/global ignore files are not hidden inputs. Git, network access, writes, shell composition, time, randomness, interactive input, credentials, unsupported paths, unknown flags, incomplete observation, and non-zero results bypass storage.

## First user

The beachhead is an individual Codex user working in a medium or large repository whose agent repeatedly reads and searches after small edits. The first release compacts and, where the avoided work exceeds proof overhead, accelerates provably read-only calls. Test/build reuse is a later trace-backed profile and does not ship until differential correctness gates pass.

## Install during development

```bash
cargo install --path .
again setup --codex
```

No Again account, OAuth flow, API key, daemon, Docker, root permission, task graph, or telemetry is required for local mode. Local state is private and repository-scoped under `.again` unless `AGAIN_HOME` is set. Codex requires one explicit review of a newly installed non-managed hook and trusts its exact hash; Again cannot safely bypass that platform control.

## Commands

```text
again setup --codex       Install or print the Codex PreToolUse hook
again run -- <argv...>    Run through the conservative local engine
again hook                Handle Codex PreToolUse JSON on stdin
again exec --call <id>    Execute an opaque call created by the hook
again explain [id]        Explain reuse or bypass in plain language
again show <result-id>    Retrieve exact stored stdout/stderr
again stats               Show local time and duplicate bytes saved
again doctor              Verify the install and safety capabilities
```

See [current status](docs/STATUS.md), [the product contract](docs/PRODUCT.md), [architecture](docs/ARCHITECTURE.md), [engineering decisions](docs/DECISIONS.md), [roadmap](docs/ROADMAP.md), and [security model](SECURITY.md).

## Open source and business

The local policy engine, tracer, EffectIR, cache, validation, explainability, and Codex integration stay open source. A future paid team product may provide encrypted shared cache, equivalent remote execution, policy and audit controls, provenance, analytics, support, and verified compute-savings reporting. Clients must still validate remote records locally.

## Status

Pre-alpha. Do not depend on Again for correctness-sensitive workloads until the documented gates are green. Unknown always means execute.

## License

Apache-2.0.
