# Remote cache threat model

This threat model covers the Worker in [`service/`](../service/README.md), its D1/R2 bindings, operator bootstrap, bearer tokens, producer keys, signed manifests, audit API, and scheduled reconciliation. It does not cover the account-free local runtime except at the boundary where the existing, not-yet-CLI-wired Rust client module can accept remote data.

Status labels used below:

- **Implemented; locally scenario-tested** means the repository contains the control and focused deterministic coverage. It does not imply a concurrency proof, injected provider-failure campaign, or external review.
- **Operational requirement** means a deployer must supply/configure it.
- **Remaining requirement** means the repository does not yet implement or validate it.

## Assets, actors, and trust boundaries

Protected assets are output blobs, signed manifest metadata, tenant/repository namespace integrity, bearer secrets, producer private keys, quota/accounting state, revocation state, and audit data.

Actors are tenant users, repository-scoped clients, producer/build identities, tenant administrators, service operators, Cloudflare/platform administrators, and unauthenticated Internet callers. A tenant, repository client, producer, or token may be malicious or compromised. D1 and R2 operations may fail independently, be retried, or be observed at different times.

The service trusts its deployed code, binding configuration, D1 schema, R2 namespace, and operator bootstrap. It does not trust request paths, bodies, bearer credentials merely because they are well-formed, producer claims without a registered key/signature, R2 objects without matching D1 state/metadata/bytes, or remote cache records at a consumer. Producer private keys and plaintext bearer secrets must never cross into service storage.

## Threats and controls

### Cross-tenant or cross-repository leakage

Threat: an authenticated client changes a route, digest, request key, or manifest field to read/write another tenant or repository; an R2 key collision exposes identical digests across namespaces.

Implemented; locally scenario-tested controls:

- Authentication derives tenant from the token row, never from request JSON.
- D1 reads and mutations qualify tenant and repository; repository existence is checked within the tenant.
- Repository-scoped tokens receive `404` outside their scope.
- Manifest tenant/repository/request bindings must equal token and route bindings before signature admission.
- R2 keys are `v1/{tenant}/{repository}/blake3/{digest}`.
- Tests place the same digest path under different tenants and require isolation.

Residual risk/requirements:

- Bootstrap mistakes, binding a token to the wrong tenant, or privileged D1/R2 access bypass application isolation.
- Token IDs are globally unique, not tenant-qualified.
- Production needs least-privilege Cloudflare IAM, separate environments/resources, configuration review, and tenant-isolation monitoring.

### Bearer-token exfiltration, replay, and redirects

Threat: a bearer appears in logs, URLs, shell history, crash reports, proxies, browser storage, or a redirect to another origin; a stolen token is replayed until expiry/revocation.

Implemented; locally scenario-tested controls:

- Tokens are accepted only in `Authorization: Bearer ag1.<id>.<secret>`.
- D1 stores SHA-256(secret), not the raw secret; comparison uses `crypto.subtle.timingSafeEqual` after a fixed-shape lookup.
- Expired and revoked tokens fail generically; permissions and optional repository scope reduce authority.
- API code emits no redirects and response caching is disabled.

Operational requirements:

- HTTPS only; clients must reject plaintext endpoints and must not forward `Authorization` across redirects or origin changes. Prefer redirect mode `error`.
- Redact authorization headers in edge, Worker, proxy, tracing, and support tooling. Deliver bootstrap secrets once through an approved secret channel.
- Use short expiries, least privilege, repository scoping where possible, and tested rotation/revocation procedures.

Residual risk: hashing at rest does not protect a live bearer or an offline low-entropy secret. Possession remains sufficient for API use. The Rust production constructor requires HTTPS and rejects redirects, but the configured endpoint, system proxy/CA policy, and DNS resolution remain deployment trust inputs; it does not pin an origin or reject HTTPS addresses that resolve to private or loopback space. Do not construct it from untrusted endpoint input.

### Cache poisoning and false provenance

Threat: an attacker uploads bytes under a false digest, submits a manifest under another request, claims another producer, races divergent results, references unavailable bytes, or uses secret/local-only output.

Implemented; locally scenario-tested controls:

- Blob PUT hashes bounded bytes with BLAKE3 and requires the URL digest to match.
- Ready reads and pending-object promotion fetch bounded R2 bytes and validate BLAKE3, size, and custom metadata; mismatch quarantines.
- Manifest parser rejects unknown/missing fields, invalid digests/sizes/lifetimes, future/expired values, `local_only`, `secret`, and `secret_tainted` records.
- Canonical manifest bytes bind tenant, repository, request, policy, execution profile, platform, image, blobs, producer, privacy, lifetime, and immutable key ID; Ed25519 is verified against the registered producer key.
- D1 triggers require referenced blobs to be ready and size-matched at manifest insertion.
- Exact repeats are idempotent; same-request or same-record divergence quarantines rather than selecting a winner.
- Revoked keys make dependent manifests unreadable immediately.
- Protocol identifiers reject whitespace, control characters, lone UTF-16 surrogates, and values longer than 256 UTF-8 bytes so JavaScript signing input matches Rust's Unicode-scalar/byte interpretation.

Residual risk/requirements:

- A compromised authorized producer can sign bad outputs. There is no independent two-producer quorum, trusted-build attestation, transparency log, or remote-execution proof.
- The existing async client module verifies strict bounded transfers/wire data, concrete Ed25519 signatures, supplied trust context, bindings, and blob bytes, but the CLI does not yet construct that context from recomputed local inputs and authenticated authorization/revocation state. `VerificationContext` has no authenticated envelope, source, freshness epoch, or tenant-policy version; stale or mis-scoped caller state can therefore accept a key/record that current policy would reject. That integration must obtain and freshness-check the snapshot through an authenticated channel, then fail closed to local execution.
- The service does not make arbitrary shell caching safe and never executes uploaded bytes.

### R2/D1 partial failure and reconciliation

Threat: D1 reserves quota without an R2 object, R2 is written before D1 promotion, promotion/deletion fails, or metadata and object bytes diverge.

Implemented; locally scenario-tested controls:

- Upload begins with a D1 `pending` reservation that counts against quota, then conditionally puts R2, validates the stored bytes and metadata, and promotes to `ready`.
- A failed upload preserves `pending` as a durable repair record rather than releasing accounted quota.
- Client retry repairs missing R2 for a pending/formerly-ready row.
- The due-work query is indexed. Cron processes at most 64 rows: valid pending objects become ready, invalid ones quarantine, deleting objects are retried and confirmed absent before D1 removal, and missing objects, incomplete deletes, and caught per-row exceptions receive exponential retry times so one due page does not continuously monopolize the queue.
- An administrator may cancel a pending reservation only after its one-hour upload lease expires. A one-hour D1 deletion tombstone remains after the initial R2 delete as a bounded late-writer mitigation before quota is released.
- Tests cover D1-pending/R2-valid recovery, R2 loss after ready, interrupted deletion, cancellation grace, missing-object page advancement, and overlapping scheduled invocations with one transition audit. They do not inject arbitrary R2/D1 exceptions or prove all interleavings.

Residual risk/requirements:

- Missing R2 for `pending` remains reserved until client repair or explicit post-lease administrator cancellation; there is no automatic abandonment policy.
- R2 objects with no D1 row are not enumerated or collected.
- The tombstone is time-based, not a generation fence. An abnormally delayed PUT can finish after final absence confirmation or tombstone expiry and leave an untracked R2 object.
- D1 state changes and security audit inserts are separate operations. Audit failure can occur after an authoritative mutation, so mutation-plus-audit atomicity/outbox semantics and fault injection remain required.
- Cron is configured every 15 minutes, not an immediate guarantee; repeated platform failure creates backlog.
- Production needs backlog/error alerts, reconciliation runbooks, review of the explicit stale-pending cancellation policy, and verified backup/restore behavior.

### Deletion races and retention

Threat: deleting a blob while a manifest begins referencing it creates a dangling manifest; interrupted deletion releases quota too early; concurrent retries resurrect state.

Implemented; locally scenario-tested controls:

- Blob transition to `deleting` is conditional on no non-deleted manifest reference.
- The manifest insert trigger independently requires both blobs still be `ready`, closing the check/insert race in D1.
- Pending cancellation requires administrator authority, an expired upload lease, and a deletion grace tombstone; quarantined remediation requires administrator authority.
- R2 absence is checked before D1 row removal; the D1 delete trigger then releases quota.
- Manifest deletion is soft state and must precede referenced blob deletion.

Residual risk/requirements:

- There is no tenant/repository deletion API or end-to-end erasure workflow.
- There is no automated retention for expired/deleted/quarantined manifests, conflicts, blobs, or audit events.
- Expired manifests, manifests signed by revoked keys, and quarantined manifests remain non-deleted references and can pin blobs even though normal GET no longer exposes them. Conflict quarantine has no administrative adjudication/recovery generation.
- A production design must define legal holds, grace periods, idempotent tenant deletion across D1/R2, deletion tombstones, retry monitoring, and proof/completion reporting.

### Producer-key compromise and revocation

Threat: key ID rebinding changes who can sign, a stolen private key poisons records, or revoked-key records remain reusable.

Implemented; locally scenario-tested controls:

- Key ID is immutably bound to tenant/repository, producer ID, and one Ed25519 public key.
- Identical active registration is idempotent; conflicting binding and reuse after revocation return conflict.
- Revocation is persisted and GET hides dependent manifests immediately.

Operational requirements:

- Generate and store private keys outside the service in an approved keystore; rotate to a new key ID; protect admin bearer tokens used for registration/revocation.
- Distribute current trusted key/producer and revocation state to consumers through an authenticated channel.

Residual risk: revocation cannot retract already downloaded data or identify when a key was first compromised. No automated key expiry, compromise attestation, or transparency history is implemented.

### Quota abuse and rate limiting

Threat: a tenant exhausts storage with pending blobs, a stolen token consumes D1/Worker capacity, or unauthenticated traffic forces token lookups/hash work.

Implemented; locally scenario-tested controls:

- D1 triggers atomically enforce tenant `quota_bytes`; `used_bytes` includes pending rows and changes with blob-row insertion/deletion.
- Separate D1 triggers meter row counts plus rounded manifest/audit JSON KiB against `metadata_quota_units`; repository statistics expose both quota classes. Metadata is released only when the metered row is physically deleted.
- Blob and JSON bodies are bounded; blob PUT requires a valid `Content-Length` and verifies streamed length.
- Each valid-secret token has a persisted fixed-minute limit of 600 requests before expiry, permission, and scope decisions, so rejected authenticated requests also consume its window. Old windows are deleted in bounded background/cron batches.

Residual risk/requirements:

- Rate limiting occurs after bearer parsing, D1 lookup, and secret hashing; invalid/unauthenticated traffic is not limited by this application counter.
- Limits are per token, not per source IP, tenant, repository, or global service capacity. Pending reservations hold quota until repair or explicit post-lease administrator cancellation.
- Soft-deleted and otherwise retained metadata continues to consume metadata quota. Retention/GC and an operator recovery path are not implemented.
- **Remaining requirement:** configure and test edge pre-authentication rate limiting/WAF rules, abuse detection, tenant-level request budgets, backlog limits, and alerts before public exposure.

### Audit privacy and observability

Threat: audit/log data leaks cache keys, command-derived identifiers, output bytes, credentials, or tenant activity; hashes are treated as anonymous.

Implemented; locally scenario-tested controls:

- Audit target identifiers are SHA-256 of a domain-separated tenant/repository/type/target tuple; tests assert output bytes and raw request keys are absent.
- API error responses expose stable codes/request IDs, while unexpected Worker logs record error names rather than request bodies.
- Audit access requires `audit` or `admin` and is tenant/repository scoped with bounded pages.

Residual risk/requirements:

- Actor/subject, action, outcome, timestamps, repository ID, selected numeric details, and activity volume remain sensitive metadata.
- Target hashes are pseudonymous, not anonymous; low-entropy identifiers may be guessed.
- Audit writes are not transactionally coupled to every authoritative mutation; a failed audit insert can leave changed state without the intended event.
- Wrangler currently enables observability with full head sampling. Production must define redaction, access control, regional handling, retention/deletion, sampling, and incident-review policy.

## Required work before production/team claims

The following remain explicit release blockers, not implied future controls:

1. Edge pre-authentication rate limiting and abuse protection, tested against invalid-token floods and body attacks.
2. Documented/enforced retention plus complete tenant/repository deletion across D1, R2, audit, conflicts, tokens, keys, and backups.
3. An authenticated operator control plane or reviewed provisioning automation for tenants, quotas, token issue/rotation/revocation, and incident response.
4. Orphan-R2 discovery plus per-key generation fencing/serialization for late writers, a reviewed automatic stale-pending policy if desired, reconciliation monitoring/alerts, and disaster-recovery exercises.
5. Transactional mutation-plus-audit outbox semantics, bounded audit retention, and binding-failure fault-injection tests.
6. Wire the existing strict Rust transport/verification module into the CLI; recompute its verification context from local inputs and obtain fresh trusted producer/revocation state through an authenticated channel before any fail-closed local reuse flow can be claimed.
7. Expired/revoked/quarantined manifest GC, blob unpinning, conflict adjudication/recovery, and metadata-quota recovery workflows.
8. Application-layer confidentiality decision and implementation if provider/TLS protections do not meet customer requirements.
9. Independent external security architecture review and penetration test, with remediation tracked before production exposure.
10. Deployment-specific IAM, environment separation, custom-domain/TLS, WAF, observability privacy, backups, and on-call runbooks.

Until those are complete, the accurate claim is: the repository contains a locally tested remote-cache service boundary and state-machine prototype, not a deployed or externally validated team product.
