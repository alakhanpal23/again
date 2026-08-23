# Product contract

## Exact promise

> Again makes repeated, certified-safe Codex shell calls fast and replaces byte-identical output the current session already saw with a compact, reversible reference. Uncertain calls run normally.

This sentence is both the product pitch and the correctness boundary. “Certified-safe” means the active Again policy has complete evidence for the supported observation model. It does not mean two executions happened to print the same bytes.

## Initial customer and job

The first customer is a technical individual using Codex locally on a repository where agent runs repeatedly search, inspect, test, lint, or build the same material. The initial job is narrower: remove repeated repository-read latency and duplicate tool-result tokens without changing prompts or asking the developer to declare a build graph.

The first economic buyer is the same developer. The later buyer is an engineering-platform leader paying to remove redundant agent/CI computation across a team while retaining provenance and policy control.

## Onboarding contract

The packaged target is:

```bash
brew install again && again setup --codex
```

Local use requires no Again account, sign-in, API key, daemon, Docker, privileged helper, repository file, or telemetry. `setup` is idempotent, preserves unrelated hooks, prints the exact change, and supports a dry run and removal. Codex itself requires the user to review a non-managed hook once through `/hooks`; setup must explain this instead of hiding it.

## v0 admission boundary

The macOS-compatible first slice admits only strictly parsed read-only invocations from a small allowlist and verifies the resolved executable identity. It fingerprints the minimal declared content/listing scope plus canonical workspace/cwd identity, executable bytes, secret-safe environment digests, platform, policy, and request before reuse. Recursive ripgrep is eligible only with `--no-ignore`; an external `RIPGREP_CONFIG_PATH` disables reuse. This intentionally trades hit rate for a falsifiable safety claim.

Every one of these forces pass-through or bypass-without-store:

- unknown executable, subcommand, or flag;
- shell composition, pipes, redirects, substitutions, globs, or multiline input;
- absolute paths or path traversal outside the canonical workspace;
- network, DNS, sockets, IPC, device, credential, or home-directory access;
- filesystem mutation, Git mutation, package management, database access, or process signaling;
- time, randomness, TTY/stdin dependence, daemonization, or background work;
- non-zero exit, signal, output above safety limits, unreadable/special input, or incomplete evidence (the audited read may execute, but no reusable entry is stored);
- any attempt to recursively wrap an Again command.

Linux trace-backed admission expands only behind a named capability profile. An observed effect is reusable only if kernel enforcement or a semisolate prevents all unrepresented effects.

## Token-reduction behavior

Again stores exact stdout and stderr as immutable blobs. The first time a result digest appears in a Codex session, the complete bytes are returned. A later cache hit in the same session may return:

```text
[again: exact repeat of result <id>; <n> duplicate bytes omitted; run `again show <id>` for full output]
```

The reference is allowed only for a successful byte-identical result with the same output digest. Session delivery state resets on compaction unless the adapter receives reliable compaction identity. No LLM summary participates in cache correctness. `AGAIN_FULL=1` and `again show` always recover the exact bytes.

## Product stages

1. **Local exact reads:** conservative command parser, audited executable identity, scoped fingerprint, local SQLite/CAS, compact same-session references, explainability.
2. **Trace-backed local effects:** Linux rootless isolation, complete descendant/effect observation, COW execution, preconditioned effect replay, 100% initial shadow validation.
3. **Team reuse:** encrypted namespaced CAS, signed provenance, equivalent execution profiles, local verification, revocation, CI and policy.

## North-star and guardrails

North-star: verified end-to-end agent wait time and duplicate tool-result bytes eliminated.

Guardrails: false reuse count, shadow divergence count, miss overhead, hook overhead, cache-read latency, full-output retrievability, secret-tainted entry count, crash consistency, and user-visible bypass explanations.
