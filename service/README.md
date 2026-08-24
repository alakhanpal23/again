# Again cache service

This directory contains the tested, undeployed Cloudflare Worker boundary for the manually provisioned encrypted Again team-cache alpha. It stores metadata in D1 and encrypted, content-addressed output bytes in R2. The opt-in `again team run` CLI implements the five-request `legacy_v2` flow and the two-request `bundle_v1` flow against these routes; account-free local Again remains independent of this service. Bundle v1 is implemented and manually selectable for controlled tests, but it is unshipped and excluded from current operator/CI examples. There is no public endpoint, control plane, profile generator, or self-service account flow, so deploying this Worker alone does not create a usable team product. The [checked-in CI integration](../docs/TEAM_CI.md) only consumes state an operator has already provisioned.

See the [remote threat model](../docs/REMOTE_THREAT_MODEL.md) before exposing the service.

## What is implemented and tested

- Bearer-token authentication with tenant, optional repository scope, expiry, revocation, and permissions.
- Tenant/repository-qualified D1 queries and tenant/repository/generation-prefixed R2 keys.
- Immutable BLAKE3-addressed ciphertext blobs, a 16 MiB per-blob limit, actual-byte verification before read/promotion, immutable random blob incarnations, and separate tenant blob-byte and metadata-unit quotas.
- Encrypted manifest schema v2 is the only HTTP and D1-admitted manifest schema. V2 manifests and root-signed trust bundles bind the exact 128-bit repository `generation_id`; recreated repositories cannot admit replayed trust, request keys, manifests, or ciphertext references from an earlier generation.
- Immutable producer-key registration and immediate manifest hiding after key revocation.
- Same-key manifest conflict quarantine instead of winner selection.
- Bounded per-token D1 rate windows, including authenticated requests rejected by authorization, privacy-reduced audit records, and repository statistics.
- Recovery state for interrupted blob upload/deletion, durable per-upload R2 orphan candidates, exact incarnation fences, and an hourly indexed reconciler with bounded, tenant-fair due work and per-row exception backoff.
- Random repository generations returned as ETags, generation-qualified R2 namespaces, and generation-scoped write leases that fence every admitted repository mutation from deletion/recreation. Blob uploads finish their bounded body read before acquiring the mutation lease, then renew it around hashing and R2 operations.
- Immediate, one-way repository deletion tombstones; O(1) lifecycle jobs and durable generation receipts; bounded, leased R2 prefix sweeping with durable cursors/backoff and two delayed fresh-empty confirmations; then phased, bounded D1 erasure before final quota release.
- Bounded, tenant-fair physical cleanup for deleted/expired manifests and an indexed candidate queue for newly unreferenced blobs. Completed-generation graveyard sweeps and active-repository orphan candidates cover late R2 writes without scanning another namespace.
- Absolute 30-second body deadlines, byte and chunk-count bounds, and body-before-mutation-lease admission for JSON and blob uploads.
- Operator-controlled tenant and per-repository hard caps for permanently ambiguous R2 operations, separate tenant/per-repository signed-trust security reserves, repository-partitioned audit retention, near-cap statistics, and bounded expired-write-lease cleanup.
- Exact generation/incarnation/state predicates around post-await mutations and releases. Producer, trust, blob, and manifest state transitions batch their authoritative audit evidence; repository tombstoning is the deliberate availability exception and records its durable deletion job even if the best-effort audit insert fails.
- A bounded `bundle_v1` lookup route that obtains both R2 body streams, rechecks the exact manifest/trust/blob-generation and immutable R2 identities in D1 after both R2 GETs return, and only then emits fixed framing and consumes the streams. The client still performs its mandatory post-decryption latest-trust GET.

These are implementation and automated-test claims, not deployment or outside-user evidence.

## Local development

Prerequisites:

- Node.js `>=22.20 <23`; CI fixes Node 22.20.0.
- npm 11.6.1, declared by `packageManager`, using the committed `package-lock.json`.
- A Cloudflare account and authenticated Wrangler session only for creating or operating remote D1/R2/Worker resources. Unit tests use local Vitest/Miniflare bindings and do not require deployment.
- A Workers Paid plan for production. The configured 15-minute lifecycle cron has the sub-hour cron CPU envelope, while the hourly byte-reconciliation cron uses the longer hourly-cron envelope. The design and batch constants assume the current Paid-plan limits described below.

From this directory:

```sh
npm ci
npm run cf-typegen
npm run typecheck
npm test
```

`npm run check` runs the same generation, typecheck, and test sequence. `npm run dev` starts Wrangler's development environment. Generated binding types are committed as `worker-configuration.d.ts`; regeneration must leave that file clean.

The test setup applies every migration in `migrations/` to isolated D1 state and uses an isolated R2 binding. The tests cover authentication and repository scoping; cross-tenant and cross-repository statistics/capacity isolation; blob integrity, incarnation ABA, quotas, interrupted concurrent uploads, durable orphan convergence, and exact mutation/audit coupling; generation preconditions and paused generation-A work across deletion/recreation for every route class; bounded body deadlines/fragmentation; write-lease ownership and global expiry cleanup; D1 deletion phases, R2 cursor restart, late objects, malicious out-of-prefix pages, and row-local failure isolation; tenant-fair manifest cleanup, blob GC, reconciliation, deletion, and graveyard work; producer identity/revocation, trust rotation/freshness/reserve isolation, encrypted-manifest v2 signatures/privacy/conflicts, v1 rejection, audit partitioning, scoped statistics, and migration behavior. Bundle coverage includes exact framing, source failure/cancellation, lazy maximum-size streams, post-R2 D1 fences, generation races, immutable R2 identities, and an actual 18-state bundle-versus-five-request route matrix. These are deterministic local scenarios; they are not a substitute for fault injection against a production Cloudflare account.

Retained evidence is intentionally split by scope. The [18-state matrix source](test/service.spec.ts) exercises the actual Worker with isolated D1/R2. The Rust [100,000-case parity gate](../src/team_pull/team_lookup_bundle_differential.rs) is synthetic protocol/parser/mapper coverage, not 100,000 stateful D1/R2 operations. The [manual two-client lifecycle result](../bench/results/2026-08-23-team-live-e2e-bundle-v1.json) uses production rustls through a public-CA Quick Tunnel into local Wrangler D1/R2, but it is not a deployment or full live performance matrix. See the [bundle rollout status](../docs/TEAM_LOOKUP_BUNDLE_V1.md).

## Deployment prerequisites and placeholders

`wrangler.jsonc` is a template, not deploy-ready production configuration:

- Replace D1 `database_id: "00000000-0000-0000-0000-000000000000"` with the created database ID.
- Confirm the D1 database name and R2 bucket name are unique and correct for the target account/environment.
- Decide whether to use a `workers.dev` hostname or add an explicit route/custom domain. No production route is currently declared.
- Keep both cron triggers. `*/15 * * * *` performs tenant-fair metadata retention, blob-GC admission, active-object orphan and completed-generation graveyard sweeps, repository deletion, expired-write-lease cleanup, and rate-window cleanup. `7 * * * *` performs byte-reading blob reconciliation separately so worst-case hashing never runs in the sub-hour cron.
- Review observability and log-retention settings. The template enables observability with full head sampling.
- Create separate resources/configuration per environment. Do not point development tests at production bindings.
- Make this Worker binding the **only write/delete principal** for the blob bucket. Do not retain independent S3 credentials, another Worker, dashboard automation, or lifecycle process that can write under `v1/<tenant>/<repository>/<generation>/`. Generation-qualified keys and Worker-held write leases fence this implementation's admitted uploads, but they cannot constrain an out-of-band principal.

The current bounds deliberately follow Cloudflare's current platform contracts:

- [D1 limits](https://developers.cloudflare.com/d1/platform/limits/) give an individual query and an entire `batch()` 30 seconds and recommend chunking large deletes. Repository metadata erasure uses 256-row deletes, two statements per batch, at most eight chunks per leased job pass, and at most four jobs per 15-minute invocation.
- The [R2 Workers API reference](https://developers.cloudflare.com/r2/api/workers/workers-api-reference/) caps list pages and multi-object deletes at 1,000 keys. Repository erasure never requests or deletes more than 1,000 keys per page.
- [R2 consistency](https://developers.cloudflare.com/r2/reference/consistency/) is strongly consistent for object writes, lists, and deletes. The deletion state machine still restarts completed cursor passes and requires two fresh empty listings to defend against application-level in-flight work.
- [Workers limits](https://developers.cloudflare.com/workers/platform/limits/) allow up to 10,000 subrequests on the Paid plan and document the 1,000 default internal-service limit retained here, plus different Cron Trigger CPU limits for intervals below one hour versus one hour or longer. Both cron paths stay well below 1,000 operations; the frequent cron avoids blob hashing, and the hourly cron reconciles at most 16 blob rows sequentially.

These numbers are release gates, not tuning suggestions. Re-check the linked official documentation before changing the plan, crons, page sizes, or batch constants.

A typical operator sequence is:

```sh
cd service
npm ci
npx wrangler d1 create again-cache
npx wrangler r2 bucket create again-cache-blobs
# Put the returned D1 ID and chosen resource names in an environment-specific config.
npx wrangler d1 migrations apply again-cache --remote
npm run cf-typegen
npm run typecheck
npm test
# Only after security/configuration review: npm run deploy
```

For a new installation, apply every migration before provisioning any tenant, token, or repository. Migration `0003_retention_lifecycle.sql` intentionally aborts if a pre-`0003` database already contains repositories; it does not attempt an unbounded generation backfill. A database that has already applied `0001` through `0003` may apply `0004_repository_generation_protocol.sql`: its preflight guard requires every stored trust head and encrypted-manifest-v2 body to contain the exact live repository generation, then installs atomic generation triggers. `0005_commit_freshness.sql` adds commit-time freshness fences. `0006_blob_incarnations.sql` upgrades existing blob rows to the explicit all-zero legacy incarnation, makes every replacement use a random immutable incarnation, disables new manifest-v1 rows, and adds bounded lifecycle/audit/trust reserves. `0007_r2_object_identities.sql` adds the immutable version/ETag/SHA-256 identity tuple required by the streaming bundle fence. Pre-v7 ready rows retain an all-null legacy tuple so they can be reconciled or deleted, but they are not bundle-eligible; every new transition to ready must carry the complete tuple. The migration tests exercise populated upgrades and incompatible-state refusal; no migration rewrites or re-signs cryptographic records. Back up and rehearse any upgrade on a copy first.

The repository does not supply production account IDs, routes, bootstrap credentials, tenant data, secrets, or a deployment pipeline. Its CI wrapper and composite action are client integration only, not service deployment or onboarding.

## Operator bootstrap and onboarding

There is no public tenant or token administration endpoint. Before an API client can onboard, an authorized operator must provision D1 rows out of band:

Tenant identifiers are permanent and non-reusable in this design. There is no tenant-delete/recreate API or tenant-generation fence; a future control plane must add an equivalent signed/authorization generation before it may recycle a tenant ID.

1. Insert a `tenants` row with reviewed `quota_bytes` and `metadata_quota_units` limits.
2. Generate a high-entropy token secret in a secret manager. Store only its lower-case SHA-256 digest in `auth_tokens`; deliver the raw secret once over an approved channel.
3. Set an explicit subject, expiry, permission set, and optional repository scope. Token IDs are globally unique in this schema.
4. Use an unscoped admin token to create the repository through the API, or provision the repository in the same controlled bootstrap transaction.
5. Provision the repository's pinned offline-root Ed25519 public key in `trust_root_keys`. Keep the root private key offline.
6. Register each producer's Ed25519 public key through the producer endpoint. The private key must remain on the producer/client.
7. Construct and publish a fresh root-signed trust bundle containing the exact tenant, repository, generation, endpoint, producer key, revocations, and allowed policy/profile/platform/image digests.

The bearer wire format is:

```text
ag1.<token-id>.<secret>
```

The secret is 32–128 URL-safe alphanumeric/underscore/hyphen characters. Valid permissions are `read`, `write`, `delete`, `audit`, and `admin`; `admin` satisfies every permission check. A repository-scoped token receives a generic `404` when it attempts another repository. Do not put raw secrets in migration files, Wrangler configuration, shell history, URLs, logs, or issue trackers.

After bootstrap, onboarding order is:

1. `POST /v1/repositories` with an admin token. Persist the returned `generation_id`/`ETag`; destructive repository deletion requires that exact generation, and every normal repository-scoped request must send it as `X-Again-Repository-Generation`.
2. Provision the offline root and publish the first fresh trust bundle.
3. `PUT /v1/repositories/{repository_id}/producers/{key_id}` with the producer ID and 32-byte Ed25519 public key as lower-case hex.
4. Upload encrypted stdout/stderr blobs by BLAKE3 digest.
5. Upload a canonical producer-signed encrypted manifest v2 that references ready ciphertext blobs and the current trust head.
6. Consumers fetch trust, manifest, and ciphertext, then independently validate every binding, signature, revocation, digest, and AEAD tag before releasing plaintext.

The opt-in `again team run --profile /absolute/private/profile.json -- <bare argv...>` path invokes the strict Rust transport for a manually provisioned profile. It performs output-independent admission before bearer/network/capture, recomputes request/runtime bindings, verifies initial and final fresh root-signed trust, checks revocations and producer signatures, authenticates/decrypts ciphertext locally, and revalidates request/runtime/clock before presenting a hit. On an eligible miss, a profile with publisher credentials performs immutable double capture, privacy scanning, encryption, blob upload, and manifest-last publication. `again team inspect` derives the same request and trust requirements without loading credentials, contacting the service, or executing the requested command. Both `legacy_v2` and `bundle_v1` are implemented without fallback between protocols, but bundle v1 remains opt-in experimental/unshipped and current operator/CI examples select `legacy_v2`. There is still no public profile/key/bootstrap UX or hosted deployment.

## API v1

All responses set `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. Errors are JSON with a bounded stable code in both the body and `X-Again-Error-Code`, plus a request ID. Except for health, send `Authorization: Bearer ag1.<id>.<secret>`. Every normal repository-scoped route requires the exact live `X-Again-Repository-Generation`; a missing value is `428`, a stale generation is `412`, and successful responses echo the generation. This transport precondition supplements the signed v2 generation binding. Repository creation and generation-qualified repository deletion are the lifecycle exceptions described below.

| Method and path | Permission | Tested behavior |
| --- | --- | --- |
| `GET /v1/health` | none | Returns service and schema health only; it does not check D1/R2 readiness. |
| `POST /v1/repositories` | unscoped `admin` | Body `{"repository_id":"…"}`; idempotently creates within the token tenant and returns a random 128-bit lower-case `generation_id` as both JSON and a quoted `ETag`. Repository-scoped credentials cannot create or recreate repositories. |
| `DELETE /v1/repositories/{repo}` | `admin` | Requires `If-Match: "<generation_id>"` (`428` if absent, `412` on a live-generation mismatch). Atomically tombstones that generation and returns `202`; retries return its durable deleting/deleted receipt and can never target a later generation reusing the same repository ID. Every normal route becomes `404` immediately while bounded cron work erases R2 and D1 state. |
| `PUT /v1/repositories/{repo}/producers/{key}` | `admin` | Body contains exactly `producer_id` and `public_key_hex`; an identical active binding is idempotent, rebinding/reuse after revocation conflicts. |
| `DELETE /v1/repositories/{repo}/producers/{key}` | `admin` | Irrevocably marks the key revoked; manifests signed by it stop reading immediately. |
| `PUT /v1/repositories/{repo}/trust-bundles/latest` | `admin` | Verifies a bounded, fresh offline-root-signed bundle for the exact generation and atomically advances its monotonic epoch, cumulative key/record revocations, active producer bindings, allowlists, and audit evidence. |
| `GET /v1/repositories/{repo}/trust-bundles/latest` | `read` | Re-verifies the stored signature and performs a final exact latest-head/root/generation/freshness fence before returning the bundle. Missing, expired, malformed, or root-disabled trust is a hard trust/state failure. |
| `PUT /v1/repositories/{repo}/blobs/{digest}` | `write` | Requires `application/octet-stream` and `Content-Length`; verifies bounded bytes against lower-case BLAKE3 path digest. |
| `GET /v1/repositories/{repo}/blobs/{digest}` or `HEAD /v1/repositories/{repo}/blobs/{digest}` | `read` | Serves only a D1-`ready` object whose bounded R2 bytes, size, digest, and metadata all match. Integrity failure quarantines it. |
| `DELETE /v1/repositories/{repo}/blobs/{digest}` | `delete` | Refuses referenced blobs. Old pending reservations and quarantined blobs require `admin`; deletion is resumable. |
| `PUT /v1/repositories/{repo}/manifests/{request_key}` | `write` | Accepts encrypted schema v2 only and validates exact generation/request bindings, lifetime/privacy, current trust allowlists/revocations, producer key, Ed25519 signature, and ready blob incarnations. Exact repeats are idempotent; divergence quarantines. |
| `GET /v1/repositories/{repo}/manifests/{request_key}` | `read` | Returns only a ready, time-valid v2 candidate authorized by the exact latest trust/producer/blob state. Only the authenticated ordinary no-reusable-candidate cases return typed `manifest_not_found`; corruption, missing trust/blob state, and generation changes stay hard failures. |
| `GET /v1/repositories/{repo}/lookup-bundles/{request_key}` | `read` | Experimental implemented route. Returns fixed `bundle_v1` framing with initial trust, manifest, and two validated R2 ciphertext streams only after the final exact D1 generation/manifest/trust/blob-identity fence. Ordinary no-candidate states match the manifest route's typed miss; corruption stays a hard failure. It remains manually selectable for controlled tests and unshipped. |
| `DELETE /v1/repositories/{repo}/manifests/{request_key}` | `delete` | Soft-deletes the manifest before its blobs may be deleted. |
| `GET /v1/repositories/{repo}/audit?limit=…&cursor=…` | `audit` | Returns a descending, tenant/repository-scoped page; limit is 1–100. |
| `GET /v1/repositories/{repo}/stats` | `audit` | Repository-scoped credentials receive repository-local object/state and trust/orphan-cap metrics only. Unscoped tenant credentials additionally receive tenant byte/metadata/cap usage and near-limit signals. Activity in repository B cannot change repository A's scoped response. |

Manifest schema v1 is retained only as an offline canonicalization test vector in older core tests. The service parser, PUT/GET routes, and D1 insert/update triggers reject it because v1 has no signed generation field. Team publication and reuse are encrypted-schema-v2-only.

## D1/R2 state machine

Blob upload intentionally writes D1 first:

```text
absent --reserve quota--> pending --verified R2 object--> ready
                              | invalid R2 bytes/metadata
                              v
                         quarantined

ready/quarantined --unreferenced delete request--> deleting
old pending --admin cancel + grace tombstone--------^
deleting --R2 delete confirmed--> D1 row removed and quota released
```

- `pending` is the durable quota reservation. Before each R2 PUT, the service creates a unique per-attempt orphan candidate bound to the exact generation, digest, and immutable blob incarnation. A handler removes only its own candidate after its PUT has definitely settled and the exact ready-row fence succeeds; genuinely ambiguous/crashed operations remain durable.
- A client retry can write/verify the same incarnation and atomically promote `pending` to `ready`, insert `blob.put` audit evidence, and complete that operation candidate. A transient post-PUT readback failure retires the settled attempt instead of leaking a candidate.
- At `7 * * * *`, reconciliation examines at most 16 indexed due `pending`/`deleting` rows. It promotes byte-verified R2 objects, quarantines invalid objects, completes deletions, and exponentially delays missing objects, incomplete deletes, and caught per-row exceptions so one due page does not continuously monopolize the queue.
- A missing R2 object remains `pending` and quota-reserved. After its one-hour upload lease expires, an administrator can cancel it; the service deletes any current generation-qualified R2 object, retains a one-hour `deleting` tombstone, and lets reconciliation release the row and quota after confirming absence.
- Tenant-fair orphan sweeps delete an exact active-repository object only when no live row owns its incarnation. Completed repository receipts rotate permanent exact-generation graveyard sweeps, so a very late generation write is still collected after D1 finalization. Neither path applies a finite unsafe tombstone TTL because Cloudflare documents no finite R2-await wall-clock bound.
- Tenant and per-repository orphan-candidate limits bound permanent ambiguity. Near-cap stats expose operator action; the supported recovery is a reviewed limit raise (within schema maxima) or a new isolated namespace, never timer-based deletion of an unresolved operation.
- Manifest insertion requires both referenced blob rows to remain `ready` inside the D1 insert transaction.
- Blob deletion first transitions D1 to `deleting`, refuses any non-deleted manifest reference, deletes R2, confirms absence, then deletes D1. Interrupted deletion remains resumable by request or cron.

Repository deletion uses a separate state machine:

```text
active --If-Match generation DELETE--> tombstoned (all normal routes hidden)
                              |
                 wait for admitted write leases
                              |
                              v
                 leased prefix pages (<=1,000 objects)
                    | partial failure
                    v
              durable cursor + exponential backoff
                              |
                              v
             fresh empty prefix --wait >=60s--> fresh empty prefix
                              |
                              v
           bounded D1 phases (<=256 rows per statement; <=8 chunks/lease)
                              |
                              v
       guarded finalization deletes the repository and completes its receipt
```

At most four repository deletions are leased per 15-minute invocation, selected tenant-fairly; a failure acquiring or processing one row is logged/deferred without suppressing later tenants. A completed cursor pass always restarts from the prefix beginning, so objects written lexicographically before an earlier cursor are not skipped. Every R2 page is bounded and every returned key is rechecked against the exact generation prefix before bulk delete. An upload admitted before the tombstone holds a generation-scoped D1 lease; deletion cannot list or finalize until that lease releases or expires, and a separate bounded cron removes expired leases even for active repositories. Two fresh empty listings separated by at least 60 seconds provide an additional observation before D1 erasure. D1 children, scoped tokens, trust state, and audit rows are then removed in restartable exact-generation phases; the final guarded batch deletes the repository and marks the independent generation receipt complete. Reusing the human-readable ID creates a new random generation, and a retry for the old receipt cannot tombstone it. Production must still isolate bucket writes to this Worker because no D1 lease can fence an independent R2/S3 principal.

## Token and signing-key lifecycle

Bearer tokens are opaque replayable credentials. D1 stores SHA-256(secret), expiry, optional revocation time, permissions, subject, tenant, and optional repository scope. The API has no token issue/rotate/revoke endpoint. Rotation is an operator action: create a new token ID/secret with a short overlap, migrate clients, then set the old row's `revoked_at`. Short expiries and least privilege are required because possession is sufficient for use.

Producer signing keys are different from bearer tokens. The service stores only an Ed25519 public key, immutably bound to tenant/repository/key ID and producer ID. Revocation is exposed through the API and immediately hides dependent manifests. A revoked key ID cannot be rebound; rotate to a new key ID. Revocation does not delete blobs or manifests, and it cannot undo data already downloaded by a client.

## Product boundary and non-claims

Local Again remains the default, account-free product: local policy, fingerprinting, execution validation, and `.again` storage do not require this service. The service introduces Cloudflare account/resource administration, bearer credentials, producer signing keys, tenant policy, and remote operational responsibility.

This repository does **not** claim:

- that arbitrary shell commands or arbitrary outputs are safe to share;
- production deployment, availability, disaster recovery, compliance, penetration testing, or external security review;
- public tenant/token/profile/key onboarding, credential rotation UX, or automatic tenant deletion;
- a shipped or production-enabled `bundle_v1` lookup endpoint. The route/client/manual lifecycle exist, but the experimental profile is excluded from current operator and CI examples, which use the five-request encrypted-manifest-v2 reference flow;
- finite-time reclamation of genuinely ambiguous R2 PUT tombstones. Permanent candidates are bounded by operator-controlled tenant and repository caps and require explicit capacity recovery;
- lossless, indefinite audit retention. Retention is a bounded repository/protected-class ring; authoritative producer/trust/blob/manifest transitions batch audit evidence, while repository tombstoning deliberately remains available if its best-effort audit insert fails;
- fencing against out-of-band R2/S3 writers; repository deletion is supportable only when this Worker is the bucket's sole writer;
- edge/WAF rate limiting before Worker/D1 authentication work;
- that a server-verified signature eliminates the need for consumer-side manifest, environment, policy/profile, platform/image, blob, revocation, and input validation;
- outside-user adoption, cross-team hit rates, or verified savings.
