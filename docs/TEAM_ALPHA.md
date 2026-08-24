# Encrypted team-cache alpha

The repository contains an opt-in, fresh-process team-cache CLI:

```bash
again team run --profile /absolute/private/profile.json -- wc -c README.md
```

This is an integration surface for a pre-provisioned alpha, not public
onboarding. There is no hosted Again endpoint, account flow, or profile
generator yet. The checked-in Worker remains undeployed. A bounded CI wrapper
and composite action can consume an operator-created one-secret bundle, but do
not provision any of those missing pieces; see [the CI boundary](TEAM_CI.md).

## Offline request and trust inspection

A provisioned producer can derive the exact bootstrap bindings without a
network request or target-command execution:

```bash
again team inspect --profile /absolute/private/profile.json --json -- cat README.md
```

Inspection runs the same strict profile and external-state checks, portable
preflight, executable inspection, slow-first/fast-checkpoint runtime
attestation, request construction, output-independent privacy gate, and strong
file-digest cache as `team run`. It then stops: it constructs no remote client,
does not load bearer tokens or the repository encryption key, and never runs
the requested argv. A missing or stale runtime checkpoint still performs the
fixed full host audit, which can invoke `/usr/bin/codesign`; that verifier is
not the requested command.

Successful stdout is one compact deterministic JSON object followed by a
newline. It contains only:

- endpoint/tenant/repository/generation scope;
- exact request, policy, classifier, execution-profile, platform, and image
  digests;
- producer id, key id, and public key; and
- an unsigned `trust_requirements` object containing the corresponding
  allowlists and active producer binding.

The document deliberately has no epoch, issue/expiry time, signature, bearer
token, repository key, signing secret, private key, local path, or environment
plaintext. `trust_requirements` is input for an offline root signer, not a
valid trust bundle. The operator must choose a monotonic epoch and fresh
bounded validity window, construct the canonical trust-bundle schema, sign it
with the pinned offline root, and provision it independently. Inspection
requires the profile's `publisher` section because deriving the real producer
public identity from the owner-private signing credential avoids a second,
weaker bootstrap descriptor. A request rejected by the sharing policy remains
local-only and produces no inspection document.

## Exact behavior

- The command must use a bare executable name and the mandatory `--`
  delimiter. The current portable subset is `cat`, `head`, `tail`, `wc`,
  `grep`, and `rg`; flags and explicit repository-relative operands are more
  restrictive than local v0, and `rg` requires `--no-ignore --sort=path`.
- The child receives a completely cleared environment containing exactly
  `LANG=C` and `LC_ALL=C`.
- Any TTY on stdin, stdout, or stderr causes a zero-lookup, zero-publication
  bypass. The audited command runs locally once with inherited streams.
- A non-TTY invocation first performs cheap argv/environment/path preflight.
  It then binds the request to the exact audited executable, macOS runtime,
  dyld, shared cache, immutable execution profile, sharing-policy digest, and
  content-derived repository observations.
- An absent or stale runtime checkpoint triggers the explicit full audit.
  A fresh checkpoint uses the fast verifier. Corrupt, unsafe, rolled-back, or
  mismatched checkpoints fail closed and are never silently replaced.
- Only a typed, authenticated no-reusable-manifest response is a cache miss.
  It covers absent/deleted candidates, normal candidate time invalidity, and
  candidates disabled by current producer/record revocation or trust
  allowlists. Quarantined/inconsistent metadata, missing expected trust/blob
  state, malformed objects, and generation changes remain hard failures. A hit is presented only
  after fresh root-signed trust verification, durable epoch acceptance,
  producer/revocation/allowlist checks, bounded ciphertext retrieval,
  signature verification, XChaCha20-Poly1305 authentication/decryption,
  request/runtime revalidation, and a local privacy rescan.
- The profile's strict 128-bit lower-case `generation_id` is included in the
  portable request key, root-signed trust scope/checkpoint, producer-signed
  encrypted manifest v2, and stream AEAD associated data. Every trust,
  manifest, and ciphertext request sends it as
  `X-Again-Repository-Generation` and requires the same response header.
  Recreating a repository ID therefore produces a different request key and
  rejects replayed trust, manifests, and ciphertext references from the old
  generation before plaintext can be released.
- A miss with publisher credentials captures two exact successful executions
  from an owner-private immutable snapshot, scans the retained bytes, encrypts
  them locally, uploads ciphertext blobs, and publishes the signed manifest
  last. The retained result is presented once even if privacy, encryption, or
  upload fails after capture.
- A read-only miss or a transport failure before capture executes the audited
  command locally once. Trust, binding, runtime, or manifest corruption can
  never become a hit; it produces a fixed local quarantine reason. Transient
  availability and read-only misses produce fixed bypass reasons. No fallback
  diagnostic text is appended to child stdout or stderr.

The command remains success-only for shared reuse: published/remote results
have exit code zero and empty stderr. A local fallback preserves the actual
child exit status and streams.

## Private profile shape

Every path below must be absolute, canonical, distinct, external to the active
workspace, current-user-owned, single-link, and mode `0600`. Checkpoint files
may initially be absent, but their common parent must already be an owned,
canonical `0700` directory. Again creates an owned `0700` `snapshots` child on
the first publication miss. The endpoint must be canonical HTTPS.

```json
{
  "schema_version": 1,
  "namespace": "again.team-profile.v1",
  "endpoint_origin": "https://cache.example.com",
  "tenant_id": "acme",
  "repository_id": "repo-1",
  "generation_id": "0123456789abcdef0123456789abcdef",
  "pinned_root_key_id": "root-2026-08",
  "pinned_root_public_key_hex": "<64 lower-case hex characters>",
  "read_token_file": "/private/again/acme/read.token",
  "repository_key_file": "/private/again/acme/repository-key.json",
  "sharing_policy_file": "/private/again/acme/sharing-policy.json",
  "checkpoint_file": "/private/again/acme/trust-checkpoint.json",
  "runtime_attestation_checkpoint_file": "/private/again/acme/runtime-checkpoint.json",
  "lookup_protocol": "legacy_v2",
  "lookup_budget": {
    "max_requests": 5,
    "max_response_bytes": 41943040,
    "total_timeout_ms": 30000
  },
  "publisher": {
    "write_token_file": "/private/again/acme/write.token",
    "producer_signing_key_file": "/private/again/acme/producer-key.json",
    "publish_budget": {
      "max_requests": 4,
      "max_transfer_bytes": 41943040,
      "total_timeout_ms": 30000
    }
  }
}
```

`lookup_protocol` is required and accepts exactly `legacy_v2` or `bundle_v1`.
There is no automatic value and no retry through the other protocol after a
miss or failure. `legacy_v2` requires `lookup_budget.max_requests` of at least
`5`: initial trust, manifest, stdout, stderr, and a final latest-trust
revocation fence. `bundle_v1` requires at least `2`: one bounded payload and a
mandatory post-decryption latest-trust fence. Both protocols retain the common
maximum of `8`. Invalid protocol names, legacy value `4`, and bundle value `1`
are rejected while loading the profile, before runtime audit or network I/O.

The Worker route, Rust client, and manual two-client `bundle_v1` lifecycle are
implemented. The profile value is retained so controlled evidence runs can
exercise that exact path, and it never downgrades when the route is absent or
corrupt. Bundle v1 remains opt-in experimental and unshipped. Operator and CI
examples remain pinned to `legacy_v2`; do not
provision `bundle_v1` outside controlled testing until the documented ship
gates pass. See [the bundle-v1 contract and evidence](TEAM_LOOKUP_BUNDLE_V1.md).

Omit `publisher` for a read-only client. Repository encryption keys, producer
keys, bearer tokens, root trust, trust bundles, and policy files must be
provisioned consistently by the operator; copying placeholders from this page
does not create a working team cache.

The team-alpha client, normal HTTP manifest routes, and D1 manifest boundary
are encrypted-schema-v2-only. They do not publish, look up, or retain manifest
schema v1 as a compatibility path. Incompatible pre-v2 data must be rejected
or handled by an explicit out-of-band migration; it cannot participate in the
repository-generation replay-safety claim.

## Current product gaps

There is no deployed service, public control plane, profile/key bootstrap,
credential-rotation UX, two-machine product E2E, production benchmark,
external security review, or design-partner evidence. The checked-in wrapper,
composite action, and workflow are CI integration for state that an operator
already provisioned manually, not public onboarding. Runtime portability is limited to the
exact reviewed macOS arm64 profile. The team CLI should be treated as a locally
tested alpha boundary, not a production availability or security claim.

Bundle v1 has more implementation evidence than shipped status. The actual
Worker route has an 18-state bundle/reference matrix, the Rust synthetic
protocol corpus passes 100,000 comparisons, and a retained manual public-CA
Quick Tunnel run covers publication, independent reuse, trust rotation,
corruption, revocation, and generation deletion/recreation. The 100,000 cases
are response/parser/mapping cases, not stateful D1/R2 operations. At 50 ms the
100-repetition improvements are 59.41%, 59.61%, 52.17%, and 1.208% for
0 B/4 KiB/1 MiB/16 MiB, so the 16 MiB 40% gate fails. An actual TCP reset
cancels 2/2 finite readers in 62.5 ms but 0/2 indefinitely pending readers after
3.014 seconds. The full 4x4 local plus live matrix, direct proof of current
Worker-isolate heap usage, 100,000-case stateful path, and cross-layer
post-decrypt revocation race remain missing. Exact artifacts are linked from
[the evidence ledger](EVIDENCE.md).

### Lifecycle behavior and deferred hardening

- During immutable capture, Again temporarily handles `SIGINT`, `SIGTERM`, and
  `SIGHUP` and forwards them immediately to the retained child process group.
  The group receives 250 milliseconds to exit and drain its pipes before
  `SIGKILL`; a second signal escalates immediately. Interruption suppresses the
  shadow run and local fallback, terminates the retained group, reaps its
  leader, and returns the shell-compatible `128 + signal` status. An interrupt
  before the first spawn retains no invented execution; one after a completed
  first run presents that run's exact streams once and overrides only its CLI
  exit status.
- On macOS the pre-exec descriptor scrub remains the fixed async-signal-safe
  close loop `3..65536`. Review of the public Apple SDK, Apple Libc/XNU
  sources, and the Rust `libc` surface found no supported `closefrom`,
  `close_range`, or `F_CLOSEM` primitive for this path. `RLIMIT_NOFILE` is not
  a safe substitute because lowering the limit does not close an already-open
  high descriptor. Descriptors numbered 65536 or higher therefore remain
  outside the claimed child-isolation boundary. Linux attempts `close_range`
  before the same fallback loop.
- Trust-checkpoint serialization uses an identity-revalidated exclusive
  `flock` acquired with nonblocking polls against one five-second monotonic
  deadline. Contention past that deadline fails closed and routes the operation
  away from remote reuse; a wedged local Again process cannot hang the command
  indefinitely.
- The local checkpoint, profile, credentials, runtime checkpoint, workspace,
  and event database are protected against other users by ownership and mode
  checks, not against the current UID or root. A same-user/root adversary is an
  accepted local-host threat exclusion for this alpha.
