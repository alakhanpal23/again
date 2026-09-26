# Coding-agent reuse surface

## Coverage principle

Again should capture every meaningfully reusable coding action, but it must not
equate repetition with reuse authority.

> Every repeated action is a reuse candidate. Only a current deterministic
> proof may turn that candidate into a shortcut.

For each action family, Again needs a versioned profile that answers:

1. What exact request did the agent make?
2. Which repository paths, trees, Git state, executables, toolchains,
   environment values, configuration, lockfiles, plugins, generated inputs, and
   external resources could affect it?
3. What effects can it produce?
4. Can those dependencies be observed completely before or during execution?
5. What must be revalidated immediately before serving a result?
6. Does reuse return an observation, an artifact, or transactional effects?

Storing a result does not authorize reuse. A reusable path requires canonical
request identity, complete dependency binding, immutable result bytes, an
effect boundary, and fresh validation. When any answer is incomplete, the
ordinary tool executes.

## Complete coding action inventory

| Action family | Representative actions | Desired treatment | Current Again state |
|---|---|---|---|
| File content and metadata | read, stat, list, tree, glob, manifest discovery | Exact observation-bound reuse and in-flight joining when a shared task needs durable source facts; direct execution when proof is slower | Ships through eight bounded `repo.*` MCP tools; standalone calls execute directly, and repeated same-task calls execute directly after one stored result if fresh provider output is identical; narrow audited CLI reads also ship |
| Repository search | text search, filename search, symbol-text references | Exact reuse bound to observed paths/trees and request limits when it has measured value | `repo.search`, `repo.glob`, and `repo.references` ship; standalone and identical repeated same-task calls execute directly, and `repo.references` is bounded textual intelligence, not semantic language-server authority |
| Git intelligence | status, diff, log, show, blame | Exact reuse after Git control state, source dependencies, configuration, and executable validation when it has measured value | Five bounded `git.*` tools ship; standalone large-index `git.status` executes directly, and repeated same-task large-index status executes directly after one stored result when fresh output matches; dangerous executable configuration is refused and unsupported external state cannot authorize hits |
| Task orientation | relevant files, architecture facts, previous findings, failed approaches, known unknowns | Reuse current typed facts; emit invalidated facts explicitly; deliver a bounded task-start delta | Same-user daemon exposes `task.start`, a bounded code edit brief, typed context, exact prompt convergence, and recipient-scoped deltas; real agent task-quality qualification remains open |
| Semantic code intelligence | symbols, definitions, references, call hierarchy, type/hover information | Deterministic derived observation bound to exact source, parser/server bytes, configuration, and dependency graph | No shipping semantic profile. Models or embeddings may nominate candidates only |
| Diagnostics | compiler diagnostics, type checks, lint check mode, static analysis | Reuse exact complete diagnostics only after toolchain/config/plugin/generated-input and dependency validation | Generic command shapes exist but always pass through without storage or reuse |
| Unit/integration tests | pytest, Cargo tests, Go tests, Jest, Vitest, framework-specific selectors | Execute uncertain/affected tests; reuse promoted exact results for proven-unaffected dependency closures | Linux pytest authority foundations exist; no product test execution or test hit ships |
| Formatting checks | `cargo fmt --all --check`, formatter check/diff modes | Deterministic check result with exact formatter/config/source binding | Exact Cargo syntax is recognized only for explanation and still passes through; write modes are mutations |
| Builds and compilation | Cargo check/build, TypeScript no-emit, Go build/test compilation, package builds | Reuse diagnostics and, later, content-addressed artifacts after complete source/toolchain/config/env/dependency proof | Backend descriptors and command classifiers exist; no command launcher or reusable build profile |
| Dependency/build graph queries | Cargo metadata, package scripts/graph, Go list, Python environment/package graph | Reuse deterministic graph observations with toolchain, manifest, lockfile, configuration, and environment bindings | Manifests can be discovered; ecosystem graph profiles do not ship |
| Generated artifacts | object files, incremental state, generated sources, bundles, coverage data | Share only immutable content-addressed artifacts produced by a qualified profile; never treat an artifact digest alone as authorization | Local CAS exists for exact result streams; general build-artifact reuse does not |
| Local deterministic utilities | read-only transforms and calculations whose complete inputs are declared | Exact or deterministic-coverage reuse when executable and all inputs are bound | Universal policy supports the class; default explicit CLI intentionally admits only a small audited read subset |
| External/fresh data | CI status, issue/PR metadata, package-registry metadata, web documentation | Revalidate through a trusted freshness validator; store only reviewed non-secret output | Protocol vocabulary exists, but freshness-bound reads execute and no external product connector is qualified |
| Edits and workspace mutations | patch, write, rename, delete, formatter write, snapshot update, code generation | Execute normally and invalidate dependent knowledge. Transactional effect replay is a later, much stronger profile | Correctly bypasses ordinary reuse; future EffectIR foundations do not authorize product replay |
| Environment mutations | install dependencies, update lockfiles, create environments, package add/update | Execute normally; capture resulting state only through an explicit qualified transition | Network/mutation shapes bypass storage and reuse |
| Interactive processes | watch mode, REPL, dev server, debugger, terminal UI | Never replay as a completed observation; optionally reuse immutable inputs or later diagnostics around it | Classified as passthrough |
| Credentials and private operations | login, token access, secret-manager calls | Bypass result storage unless a dedicated secret-safe contract exists | Universal policy requires bypass |
| Communication and external side effects | comments, messages, issues, commits pushed, PR creation, deployment, payment | Never replay the side effect. A separate freshness read may verify whether the desired postcondition already exists | Universal policy requires bypass |

## Shipping reusable tools

The default MCP product currently covers these exact bounded observations:

```text
repo.read          repo.search       repo.list
repo.tree          repo.stat         repo.glob
repo.references    repo.manifest

git.status         git.diff          git.log
git.show           git.blame
```

All other MCP providers and developer commands need an explicit product profile
before they may store or reuse results. Provider annotations, tool names, and a
command that looks read-only are untrusted hints.

## Validation profile ladder

Developer validation should expand through narrow independently qualified
profiles instead of one generic shell-command cache.

| Order | Profile | First useful slice | Required dependency authority |
|---:|---|---|---|
| 1 | Python pytest | One or more exact selectors through `.venv/bin/python -I -m pytest` | Python/runtime closure, selector files, imported files, config/plugins, environment, reads/effects, complete descendants |
| 2 | Rust checks | `cargo check`, exact test selectors, Clippy, and `cargo fmt --all --check` as separate profiles | Rust/Cargo/rustup identities, target/config, manifests/lockfile, build scripts, proc macros, environment, source and generated dependency closure |
| 3 | TypeScript/JavaScript checks | `tsc --noEmit`, exact Jest/Vitest selectors, ESLint check | Node/package-manager/tool identities, config/plugins, package/lock graph, module resolution, transforms, environment and read closure |
| 4 | Go checks | exact `go test` packages/selectors, `go vet`, build | Go binary/environment, module/work/sum files, replace directives, generated/cgo inputs, package and file dependency closure |
| 5 | Python static checks | Ruff check, mypy, type/lint profiles | Executables/venv, config/plugins/stubs, interpreter/package graph, source and import closure |
| 6 | Build artifacts | qualified compiler outputs from the profiles above | Everything required for the producing diagnostics plus immutable artifact manifests and safe materialization |

Each first version is execute-only. It records dependencies and exact outcomes
without skipping work. Reuse arrives only after immutable candidate creation,
an independent shadow agrees, a promotion row is committed, and the next call
freshly validates the promoted dependency closure.

## Code-intelligence ladder

Agents spend substantial time rediscovering code structure before they edit.
Again should add deterministic repository-local intelligence in this order:

1. file symbols and outline;
2. exact definition locations;
3. syntax-aware references;
4. imports and module/package dependency edges;
5. call/type hierarchy where the language engine can make it deterministic;
6. current diagnostics tied to a qualified validation profile.

The safest initial implementations use fixed parser or language-engine bytes,
bounded output, repository-local configuration, and explicit dependency
manifests. A semantic index can accelerate candidate selection but cannot make
its own possibly stale answer reusable.

## Universal reuse pipeline

Every reusable action should eventually enter the same control plane:

```text
agent tool/test request
  -> canonical request and capability class
  -> profile-specific dependency/effect observer
  -> exact candidate lookup or in-flight join
  -> fresh proof validation
       |- valid promoted proof -> return exact observation/artifact
       `- absent/uncertain     -> execute normally and observe
  -> immutable result/candidate
  -> optional independent shadow and promotion
  -> provenance, invalidation links, and task-level accounting
```

This lets Again broaden coverage without weakening its central rule. A file
read, language query, linter, test, and build can share storage, coordination,
delivery, and metrics while retaining separate dependency and effect profiles.

## Implementation priority

1. Preserve and optimize the 13 shipping repository/Git tools.
2. Connect their verified results to task-start facts and invalidation.
3. Add bounded symbols/definitions/references over a sealed fresh repository
   manifest so agents perform fewer exploratory reads.
4. Finish execute-only pytest and the trace-derived validation plan.
5. Generalize the candidate/shadow/promotion machinery behind profile-private
   adapters, then add Rust, TypeScript/JavaScript, Go, and Python check profiles.
6. Add authenticated recipient delivery so repeated facts/results consume less
   model context.
7. Add content-addressed build artifacts only after the corresponding command
   profile is qualified.
8. Share verified observations, validation results, and artifacts across agents
   locally, then across equivalent machines through the encrypted team path.

Coverage is measured by redundant work eliminated per successful coding task:
orientation calls, provider executions, validation processes, compute time,
context bytes, provider-reported tokens, and metered cost. The safety denominator
includes every attempted reuse, invalidation, refusal, and divergence—not only
successful hits.
