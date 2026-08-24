# Team alpha in CI

The repository includes a bounded wrapper and a reusable GitHub composite
action for the manually provisioned `again team run` alpha. One invocation
installs Rust `1.88.0`, builds Again with the committed lockfile, materializes
all required team state from one masked secret outside the active workspace,
validates the exact request offline with `again team inspect`, and then runs
that same argv through `again team run`.

This is integration plumbing, not hosted onboarding. It does not deploy the
Worker, publish a release, create trust, register a tenant, or provision the
server.

## The one-secret bundle

CI accepts one strict multiline JSON secret. It combines the path-independent
profile fields with the five files a publisher profile references:

```json
{
  "schema_version": 1,
  "namespace": "again.team-ci-bundle.v1",
  "profile": {
    "schema_version": 1,
    "namespace": "again.team-profile.v1",
    "endpoint_origin": "https://cache.example.com",
    "tenant_id": "acme",
    "repository_id": "repo-1",
    "generation_id": "0123456789abcdef0123456789abcdef",
    "pinned_root_key_id": "root-2026-08",
    "pinned_root_public_key_hex": "<64 lower-case hex characters>",
    "lookup_protocol": "legacy_v2",
    "lookup_budget": {
      "max_requests": 5,
      "max_response_bytes": 41943040,
      "total_timeout_ms": 30000
    },
    "publisher": {
      "publish_budget": {
        "max_requests": 4,
        "max_transfer_bytes": 41943040,
        "total_timeout_ms": 30000
      }
    }
  },
  "files": {
    "read_token": "ag1.<id>.<32-to-128-character-secret>",
    "repository_key": {
      "schema_version": 1,
      "namespace": "again.repository-encryption-key.v1",
      "key_id": "repository-key-1",
      "key_hex": "<64 lower-case hex characters>"
    },
    "sharing_policy": {
      "schema_version": 1,
      "namespace": "again.repository-sharing-policy.v1",
      "version": "ci-policy-v1",
      "include_prefixes": ["src"],
      "exclude_prefixes": [".env", ".git", "target"],
      "max_output_bytes": 1048576
    },
    "write_token": "ag1.<id>.<32-to-128-character-secret>",
    "producer_signing_key": {
      "schema_version": 1,
      "namespace": "again.producer-signing-key.v1",
      "key_id": "producer-key-1",
      "producer_id": "producer-1",
      "secret_key_hex": "<64 lower-case hex characters>"
    }
  }
}
```

Every object rejects missing and unknown fields. The profile and publisher
objects deliberately reject all file paths: the materializer injects canonical
paths beneath its fresh private directory. It writes the profile, tokens,
repository key, sharing policy, and producer key as distinct `0600` regular
files. It supplies distinct, initially absent trust and runtime checkpoint
paths beneath the same `0700` state directory. Duplicate object members and
the non-JSON `NaN`/`Infinity` constants are rejected at every nesting level.

The placeholders are not credentials and cannot produce a working bundle. An
operator must create the root, repository and producer keys, tokens, policy,
server-side tenant/repository/generation, and signed trust consistently. The
client remains the final schema and cryptographic validator.

## Generic CI from a trusted Again checkout

The generic wrapper is safe to call only from an immutable, reviewed Again
source checkout. It builds and runs the Rust source and bundle materializer
next to the wrapper. Never give the team secret to a wrapper, materializer, or
local `uses: ./.github/actions/team-run` path from a pull-request-controlled or
otherwise untrusted revision. A hostile checkout controls code that receives
the secret; file modes and environment clearing cannot repair that trust
mistake. When the repository being inspected is not the trusted Again source
itself, use the remote composite action pinned to a reviewed full commit SHA as
shown below.

Expose the complete bundle as a masked multiline secret named
`AGAIN_TEAM_CI_BUNDLE_JSON`, then invoke the wrapper with a literal `--` and
one argument per shell argv element:

```yaml
- name: Run one provisioned Again team request
  env:
    AGAIN_TEAM_CI_BUNDLE_JSON: ${{ secrets.AGAIN_TEAM_CI_BUNDLE_JSON }}
  run: ./scripts/again-team-ci.sh -- cat src/main.rs
```

Do not put the bundle in a command-line argument, interpolate it into `run:`,
enable shell tracing, or base64-encode it. Multiline CI secrets pass directly
through the environment; the wrapper copies the value to non-exported shell
state and clears the exported variable before Rustup, Cargo, build scripts,
Again, or the requested command starts. The bundle is capped at 64 KiB, while
each materialized file retains the client-side limit documented by the team
alpha.

The wrapper requires Bash, Python 3, Git (outside GitHub Actions), Rustup,
Cargo, and a Unix runner. It must start inside the repository whose request
will be inspected. `RUNNER_TEMP`, or `TMPDIR` when `RUNNER_TEMP` is absent,
must resolve to an existing location in which an owner-private directory can
be created outside that repository.

The delimiter and argument boundaries are security-relevant. This is valid:

```bash
./scripts/again-team-ci.sh -- rg --no-ignore --sort=path 'literal pattern' src
```

These are rejected before inspection:

```bash
./scripts/again-team-ci.sh rg pattern src
./scripts/again-team-ci.sh -- /usr/bin/rg pattern src
./scripts/again-team-ci.sh -- sh -c 'rg pattern src'
```

There is no `eval`, command-string parser, or shell fallback. The parser's
current bare executable subset is exactly `cat`, `head`, `tail`, `wc`, `grep`,
and `rg`; normal team-alpha argument, sharing-policy, exact executable, and
dynamic-dependency-closure restrictions still apply. A parsed name is not a
promise that the current sealed runtime has audited that tool.

## GitHub Actions

After checking out the repository to inspect, call the composite action as one
step. Pin the remote use to a reviewed full commit SHA; the placeholder below
is not a usable ref. Do not replace it with a mutable branch, tag, local action
path, or source from the consumer checkout:

```yaml
- name: Run one provisioned Again team request
  uses: alakhanpal23/again/.github/actions/team-run@<full-reviewed-commit-sha>
  with:
    bundle: ${{ secrets.AGAIN_TEAM_CI_BUNDLE_JSON }}
    argv: '["cat", "src/main.rs"]'
```

`argv` is a JSON string array, not a shell command. Each element becomes one
argument verbatim. The action rejects empty, malformed, non-string, oversized,
NUL-containing, and path-valued executable inputs, inserts the mandatory `--`,
and hands the array to the generic wrapper without shell evaluation.

The action intentionally does not cache or upload the built binary. GitHub
workflow permissions can remain `contents: read`, and checkout credentials
should not be persisted.

## Secret lifecycle and output

The wrapper creates a fresh `0700` directory with `mktemp`, verifies that it is
canonical, owner-held, and outside the active workspace, and uses exclusive,
no-follow creation for every materialized file. Symlinked, hard-linked,
incorrectly permissioned, oversized, empty, malformed, path-injecting, and
unknown-field bundles fail closed.

Exit and signal traps overwrite, truncate, and unlink every known materialized
file, including checkpoints created during the invocation, then remove the
private build directory. Physical erasure cannot be guaranteed on
copy-on-write filesystems, SSDs, snapshots, runner telemetry, after an
uncatchable `SIGKILL`, or after host loss; use an ephemeral encrypted runner
for that threat model.

The integration does not echo the bundle, include it in argv, export it to
build or child processes, or print the inspection document. Fixed progress
messages go to stderr. `team run` still presents the requested command's
stdout, stderr, and exit status by design, so the operator remains responsible
for choosing a policy-admitted command whose intended output is safe for CI
logs.

## Current limitations

- There is no public Again endpoint, hosted account flow, trust service, or
  profile/key/bootstrap generator. The checked-in Worker is not deployed.
  Creating a valid one-secret bundle is still a manual operator task.
- Offline inspection requires the publisher section and producer signing key
  so it can derive the real producer identity. It does not load bearer tokens
  or the repository key, contact the endpoint, or execute the requested argv,
  though a stale or absent runtime checkpoint can perform the fixed host audit.
- Reuse is limited to the exact reviewed macOS arm64 runtime/tool profile.
  Linux and unknown macOS runners fail closed; ordinary GitHub-hosted runner
  images should not be assumed compatible. A manually prepared self-hosted
  runner is the realistic alpha environment.
- Checkpoints are fresh and removed with each invocation. Runtime inspection
  therefore performs a full audit in each clean job, and accepted trust epochs
  do not provide anti-rollback memory across jobs. Durable cross-job monotonic
  state requires a separately reviewed persistent-runner design and is not
  claimed by this action.
- The one-secret bundle places all client credentials under the CI provider's
  secret and runner threat model. Same-user/root compromise, CI administrator
  access, logs produced by the requested command, and provider-side secret
  handling remain outside the local file protections.
- Use a fresh ephemeral runner and do not run untrusted code in an earlier step
  of the secret-bearing job. The action clears common Linux/macOS loader
  injection variables at the action boundary and launches Again from a minimal
  environment, but no user-space wrapper can undo code that already ran as the
  runner account or stop a hostile dynamic loader before its initial process
  starts. This is part of the same-user/runner-host exclusion, not a certified
  defense against a previously compromised job.
- The integration has deterministic clean-runner mock-boundary and static
  tests only. It is not a two-machine product E2E, production availability
  benchmark, external security review, or evidence that a public team product
  exists.
