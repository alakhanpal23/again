# Remote cache threat model

This threat model covers the Worker in [`service/`](../service/README.md), its D1/R2 bindings, operator bootstrap, bearer tokens, producer keys, signed manifests, audit API, scheduled reconciliation, and the manually provisioned `again team run` client boundary. It does not otherwise cover the account-free local runtime.

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
- R2 keys are `v1/{tenant}/{repository}/{generation}/blake3/{digest}`; a recreated human-readable repository ID receives a new random generation.
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
- The opt-in team-alpha CLI recomputes request/policy/execution-profile/platform/image bindings and obtains a root-signed, short-lived trust bundle carrying epoch, producer keys, revocations, and allowlists. The accepted epoch is durably checkpointed before manifest/blob retrieval. Runtime and request inputs are checked again after network I/O and immediately before decryption. Only a typed manifest 404 is a miss; signature, AEAD, trust, binding, rollback, and corruption failures cannot become hits. This remains manually provisioned alpha state rather than a public control plane.
- The service does not make arbitrary shell caching safe and never executes uploaded bytes.

### R2/D1 partial failure and reconciliation

Threat: D1 reserves quota without an R2 object, R2 is written before D1 promotion, promotion/deletion fails, or metadata and object bytes diverge.

Implemented; locally scenario-tested controls:

- Upload begins with a D1 `pending` reservation that counts against quota and a unique durable operation candidate bound to the exact repository generation, digest, and immutable blob incarnation. It then conditionally puts R2, validates stored bytes/metadata, and atomically promotes that incarnation to `ready`.
- A failed or genuinely ambiguous upload preserves `pending` plus its bounded operation candidate rather than releasing accounted quota or guessing that no late object can arrive. A definitely settled failed attempt retires only its own candidate.
- Client retry repairs missing R2 for the same pending incarnation; every replacement uses a new random incarnation and object identity.
- The due-work query is indexed. The hourly byte-reconciliation cron processes at most 16 rows: valid pending objects become ready, invalid ones quarantine, deleting objects are retried and confirmed absent before D1 removal, and missing objects, incomplete deletes, and caught per-row exceptions receive exponential retry times so one due page does not continuously monopolize the queue.
- An administrator may cancel a pending reservation only after its one-hour adoption window expires. The service deletes the exact current-generation incarnation, retains deleting state until absence is confirmed, and preserves unresolved operation candidates for later exact-object sweeping rather than relying on a finite late-writer timeout.
- Tests cover D1-pending/R2-valid recovery, R2 loss after ready, interrupted deletion, cancellation grace, missing-object page advancement, and overlapping scheduled invocations with one transition audit. They do not inject arbitrary R2/D1 exceptions or prove all interleavings.

Residual risk/requirements:

- Missing R2 for `pending` remains reserved until client repair or explicit post-adoption-window administrator cancellation; there is no timer-based automatic abandonment of ambiguous operations.
- Tenant-fair orphan-candidate sweeps delete an exact active-repository object only when no live row owns its incarnation. Completed repository receipts retain exact-generation graveyard work that repeatedly sweeps the deleted prefix, including very late Worker-owned writes after D1 finalization. Candidate counts are capped per tenant and repository and surfaced in stats; capacity recovery is an explicit operator action.
- Repository generations prevent an old object namespace or old DELETE retry from targeting a recreated repository. Every admitted normal repository mutation holds and renews a generation-scoped D1 write lease, and repository deletion waits for retained leases before listing R2 or erasing metadata. Final mutation statements either carry the live-generation predicate or are protected by D1 generation triggers. The lease expires after 15 minutes for liveness: an abnormally stalled upload can finish after expiry, but its durable exact-object candidate and the old-generation graveyard preserve cleanup work, while subsequent D1 promotion fails closed. An out-of-band R2/S3 writer bypasses both the D1 lease and operation-candidate protocol, so production still requires this Worker to be the bucket's sole writer.
- The encrypted team protocol also binds the exact generation end to end: it is hashed into the portable request key, signed by the trust root, persisted in the anti-rollback checkpoint scope, signed and AEAD-bound in manifest v2, checked against the live D1 repository, and carried in a mandatory request/response header for every normal repository-scoped route. A generation-A trust body, request key, manifest, or ciphertext reference cannot authorize generation B. Legacy manifest v1 lacks a signed generation and is explicitly outside this invariant.
- D1 state changes and security audit inserts are separate operations. Audit failure can occur after an authoritative mutation, so mutation-plus-audit atomicity/outbox semantics and fault injection remain required.
- Lightweight lifecycle work runs every 15 minutes and byte reconciliation runs hourly, not immediately; repeated platform failure creates backlog.
- Production needs backlog/error alerts, reconciliation runbooks, review of the explicit stale-pending cancellation policy, and verified backup/restore behavior.

### Deletion races and retention

Threat: deleting a blob while a manifest begins referencing it creates a dangling manifest; interrupted deletion releases quota too early; concurrent retries resurrect state.

Implemented; locally scenario-tested controls:

- Blob transition to `deleting` is conditional on no non-deleted manifest reference.
- The manifest insert trigger independently requires both blobs still be `ready`, closing the check/insert race in D1.
- Pending cancellation requires administrator authority, an expired adoption window, exact-incarnation deletion/absence confirmation, and retained unresolved-operation evidence; quarantined remediation requires administrator authority.
- R2 absence is checked before D1 row removal; the D1 delete trigger then releases quota.
- Manifest deletion is soft state and must precede referenced blob deletion.
- Repository DELETE requires the current generation ETag, atomically tombstones the repository, and creates an O(1), generation-scoped lifecycle job plus an independent idempotency receipt. A direct D1 tombstone invokes the same trigger.
- Every normal repository mutation acquires and renews a generation-scoped write lease before its potentially slow work and final state change; uploads retain the lease across R2 mutation. Deletion waits for retained leases, sweeps the exact generation prefix in pages of at most 1,000, resets an unusable cursor, restarts completed cursor passes, and requires two fresh empty listings separated by at least 60 seconds.
- D1 erasure is restartable and bounded to 256 rows per statement and eight chunks per leased job pass. Guarded finalization removes the repository only after every scoped child class is empty, then completes the old-generation receipt. Tests cover a blocked in-flight PUT, late objects before a cursor, large phased cleanup, direct tombstones, and generation-A deletion/recreation as generation B.
- Deleted and expired manifests are physically removed in bounded batches. Manifest transitions enqueue only their referenced blobs, and the atomic candidate decision retains a GC signal if the final reference disappears during processing.

Residual risk/requirements:

- There is no complete tenant-deletion workflow, backup erasure integration, legal-hold policy, or externally durable proof/completion report.
- Repository deletion cannot fence an out-of-band bucket principal, and its 15-minute write-lease expiry is a liveness tradeoff rather than a proof against an arbitrarily stalled admitted PUT. Such writes are isolated to the old generation but can become orphans after completion.
- Conflict rows and audit events do not have independent age-based retention, and conflict quarantine has no administrative adjudication/recovery workflow.
- Production still needs deletion-backlog monitoring, IAM-enforced sole-writer isolation, orphan discovery, fault injection against real D1/R2, legal-hold/grace policy, and tested backup/restore/erasure procedures.

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
- Limits are per token, not per source IP, tenant, repository, or global service capacity. Pending reservations hold quota until repair or explicit post-adoption-window administrator cancellation.
- Soft-deleted metadata consumes quota until bounded physical retention runs. Conflict and audit age-based retention and an operator quota-recovery workflow remain unimplemented.
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
2. Documented/enforced tenant deletion and backup erasure, legal-hold/grace policy, deletion proof/reporting, and production fault injection for the implemented repository lifecycle.
3. An authenticated operator control plane or reviewed provisioning automation for tenants, quotas, token issue/rotation/revocation, and incident response.
4. Production fault injection and monitoring for the implemented operation-candidate and generation-graveyard sweeps, IAM-enforced sole-writer isolation, documented candidate-capacity recovery, a reviewed stale-pending policy if desired, reconciliation alerts, and disaster-recovery exercises.
5. Transactional mutation-plus-audit outbox semantics, bounded audit retention, and binding-failure fault-injection tests.
6. A deployed cross-host design-partner lifecycle proving independent provisioning, reuse, trust rotation, revocation, corruption quarantine, and recovery under real service operations; the existing single-host public-CA tunnel run is not that evidence.
7. Conflict adjudication/recovery, age-based conflict/audit retention, and operator metadata-quota recovery workflows.
8. Repository-key rotation/recovery UX and a reviewed metadata-confidentiality policy; encrypted v2 protects stream plaintext, but tenant/repository identifiers, sizes, timing, and activity metadata remain visible to the service/platform.
9. Independent external security architecture review and penetration test, with remediation tracked before production exposure.
10. Deployment-specific IAM, environment separation, custom-domain/TLS, WAF, observability privacy, backups, and on-call runbooks.

Until those are complete, the accurate claim is: the repository contains a locally tested remote-cache service boundary and state-machine prototype, not a deployed or externally validated team product.
