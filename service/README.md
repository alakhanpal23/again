# Again cache service

This directory contains the tested Cloudflare Worker boundary for an experimental shared Again cache. It stores metadata in D1 and content-addressed output bytes in R2. It is not used by the account-free local Again runtime today. A strict Rust HTTP transport/verification module exists, but the CLI does not invoke it or construct its verification context; deploying this Worker therefore does not enable team reuse by itself.

See the [remote threat model](../docs/REMOTE_THREAT_MODEL.md) before exposing the service.

## What is implemented and tested

- Bearer-token authentication with tenant, optional repository scope, expiry, revocation, and permissions.
- Tenant/repository-qualified D1 queries and tenant/repository-prefixed R2 keys.
- Immutable BLAKE3-addressed blobs, a 16 MiB per-blob limit, actual-byte verification before read/promotion, and separate tenant blob-byte and metadata-unit quotas.
- Strict, signed manifest schema v1 with tenant, repository, request, policy, execution profile, platform, image, producer, key, privacy, lifetime, and blob bindings.
- Immutable producer-key registration and immediate manifest hiding after key revocation.
- Same-key manifest conflict quarantine instead of winner selection.
- Bounded per-token D1 rate windows, including authenticated requests rejected by authorization, privacy-reduced audit records, and repository statistics.
- Recovery state for interrupted blob upload/deletion, plus a scheduled reconciler with indexed due work and exception backoff.

These are implementation and automated-test claims, not deployment or outside-user evidence.

## Local development

Prerequisites:

- Node.js `>=22.20 <23`; CI fixes Node 22.20.0.
- npm 11.6.1, declared by `packageManager`, using the committed `package-lock.json`.
- A Cloudflare account and authenticated Wrangler session only for creating or operating remote D1/R2/Worker resources. Unit tests use local Vitest/Miniflare bindings and do not require deployment.

From this directory:

```sh
npm ci
npm run cf-typegen
npm run typecheck
npm test
```

`npm run check` runs the same generation, typecheck, and test sequence. `npm run dev` starts Wrangler's development environment. Generated binding types are committed as `worker-configuration.d.ts`; regeneration must leave that file clean.

The test setup applies `migrations/0001_initial.sql` to isolated D1 state and uses an isolated R2 binding. The tests cover authentication failures, repository scoping, cross-tenant isolation, blob integrity, blob and metadata quota accounting, partial-failure repair, deletion recovery, key immutability/revocation, manifest signature and privacy checks, conflict quarantine, audit redaction, statistics, identifier canonicalization, and the persisted token rate window. These are deterministic local scenarios; they are not a concurrency proof or injected Cloudflare outage test.

## Deployment prerequisites and placeholders

`wrangler.jsonc` is a template, not deploy-ready production configuration:

- Replace D1 `database_id: "00000000-0000-0000-0000-000000000000"` with the created database ID.
- Confirm the D1 database name and R2 bucket name are unique and correct for the target account/environment.
- Decide whether to use a `workers.dev` hostname or add an explicit route/custom domain. No production route is currently declared.
- Keep the 15-minute cron trigger if reconciliation is expected; without it, repair depends on client retries.
- Review observability and log-retention settings. The template enables observability with full head sampling.
- Create separate resources/configuration per environment. Do not point development tests at production bindings.

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

The repository does not supply production account IDs, routes, bootstrap credentials, tenant data, secrets, or a deployment pipeline.

## Operator bootstrap and onboarding

There is no public tenant or token administration endpoint. Before an API client can onboard, an authorized operator must provision D1 rows out of band:

1. Insert a `tenants` row with reviewed `quota_bytes` and `metadata_quota_units` limits.
2. Generate a high-entropy token secret in a secret manager. Store only its lower-case SHA-256 digest in `auth_tokens`; deliver the raw secret once over an approved channel.
3. Set an explicit subject, expiry, permission set, and optional repository scope. Token IDs are globally unique in this schema.
4. Use an unscoped admin token to create the repository through the API, or provision the repository in the same controlled bootstrap transaction.
5. Register each producer's Ed25519 public key through the producer endpoint. The private key must remain on the producer/client.

The bearer wire format is:

```text
ag1.<token-id>.<secret>
```

The secret is 32–128 URL-safe alphanumeric/underscore/hyphen characters. Valid permissions are `read`, `write`, `delete`, `audit`, and `admin`; `admin` satisfies every permission check. A repository-scoped token receives a generic `404` when it attempts another repository. Do not put raw secrets in migration files, Wrangler configuration, shell history, URLs, logs, or issue trackers.

After bootstrap, onboarding order is:

1. `POST /v1/repositories` with an admin token.
2. `PUT /v1/repositories/{repository_id}/producers/{key_id}` with the producer ID and 32-byte Ed25519 public key as lower-case hex.
3. Upload stdout/stderr blobs by BLAKE3 digest.
4. Upload a canonical, signed manifest that references ready blobs.
5. Consumers fetch the manifest and blobs, then independently validate all bindings and bytes before reuse.

The async Rust client module implements HTTPS-only, no-redirect transfer with one send/body deadline, per-chunk stall deadlines, strict bounded wire parsing, blob verification, and concrete Ed25519 candidate verification. The CLI does not invoke it, register producers, derive a verification context from recomputed local inputs, or authenticate/freshness-check trust and revocation state. An operator must not describe the service as integrated team caching until that wiring and fail-closed fallback are tested end to end.

## API v1

All responses set `Cache-Control: no-store` and `X-Content-Type-Options: nosniff`. Errors are JSON with a stable code and request ID. Except for health, send `Authorization: Bearer ag1.<id>.<secret>`.

| Method and path | Permission | Tested behavior |
| --- | --- | --- |
| `GET /v1/health` | none | Returns service and schema health only; it does not check D1/R2 readiness. |
| `POST /v1/repositories` | `admin` | Body `{"repository_id":"…"}`; idempotently creates within the token tenant/scope. |
| `PUT /v1/repositories/{repo}/producers/{key}` | `admin` | Body contains exactly `producer_id` and `public_key_hex`; an identical active binding is idempotent, rebinding/reuse after revocation conflicts. |
| `DELETE /v1/repositories/{repo}/producers/{key}` | `admin` | Irrevocably marks the key revoked; manifests signed by it stop reading immediately. |
| `PUT /v1/repositories/{repo}/blobs/{digest}` | `write` | Requires `application/octet-stream` and `Content-Length`; verifies bounded bytes against lower-case BLAKE3 path digest. |
| `GET /v1/repositories/{repo}/blobs/{digest}` or `HEAD /v1/repositories/{repo}/blobs/{digest}` | `read` | Serves only a D1-`ready` object whose bounded R2 bytes, size, digest, and metadata all match. Integrity failure quarantines it. |
| `DELETE /v1/repositories/{repo}/blobs/{digest}` | `delete` | Refuses referenced blobs. Old pending reservations and quarantined blobs require `admin`; deletion is resumable. |
| `PUT /v1/repositories/{repo}/manifests/{request_key}` | `write` | Validates strict schema, bindings, lifetime/privacy, producer key, Ed25519 signature, and ready blob references. Exact repeats are idempotent; divergence quarantines. |
| `GET /v1/repositories/{repo}/manifests/{request_key}` | `read` | Returns only ready, unexpired, not-future manifests signed by a non-revoked key. |
| `DELETE /v1/repositories/{repo}/manifests/{request_key}` | `delete` | Soft-deletes the manifest before its blobs may be deleted. |
| `GET /v1/repositories/{repo}/audit?limit=…&cursor=…` | `audit` | Returns a descending, tenant/repository-scoped page; limit is 1–100. |
| `GET /v1/repositories/{repo}/stats` | `audit` | Returns ready/pending/deleting/quarantined counts plus tenant blob-byte and metadata-unit quota usage. |

Manifest schema examples live in [`test/fixtures/manifest-v1.json`](test/fixtures/manifest-v1.json), with its canonical signing vector in [`manifest-v1-canonical.json`](test/fixtures/manifest-v1-canonical.json).

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

- `pending` is the durable reservation/outbox state. It counts against quota so an interrupted upload cannot create unaccounted storage.
- A client retry can write/verify R2 and promote `pending` to `ready`.
- Every 15 minutes, reconciliation examines at most 64 indexed due `pending`/`deleting` rows. It promotes byte-verified R2 objects, quarantines invalid objects, completes deletions, and exponentially delays missing objects, incomplete deletes, and caught per-row exceptions so one due page does not continuously monopolize the queue.
- A missing R2 object remains `pending` and quota-reserved. After its one-hour upload lease expires, an administrator can cancel it; the service deletes any current R2 object, retains a one-hour `deleting` tombstone as a bounded late-writer mitigation, and lets reconciliation release the row and quota after confirming absence. The tombstone is not a generation fence; an abnormally delayed write can still create an orphan after final confirmation.
- The reconciler does not enumerate untracked R2 objects, so an R2 object with no D1 row is not automatically collected.
- Manifest insertion requires both referenced blob rows to remain `ready` inside the D1 insert transaction.
- Blob deletion first transitions D1 to `deleting`, refuses any non-deleted manifest reference, deletes R2, confirms absence, then deletes D1. Interrupted deletion remains resumable by request or cron.

## Token and signing-key lifecycle

Bearer tokens are opaque replayable credentials. D1 stores SHA-256(secret), expiry, optional revocation time, permissions, subject, tenant, and optional repository scope. The API has no token issue/rotate/revoke endpoint. Rotation is an operator action: create a new token ID/secret with a short overlap, migrate clients, then set the old row's `revoked_at`. Short expiries and least privilege are required because possession is sufficient for use.

Producer signing keys are different from bearer tokens. The service stores only an Ed25519 public key, immutably bound to tenant/repository/key ID and producer ID. Revocation is exposed through the API and immediately hides dependent manifests. A revoked key ID cannot be rebound; rotate to a new key ID. Revocation does not delete blobs or manifests, and it cannot undo data already downloaded by a client.

## Product boundary and non-claims

Local Again remains the default, account-free product: local policy, fingerprinting, execution validation, and `.again` storage do not require this service. The service introduces Cloudflare account/resource administration, bearer credentials, producer signing keys, tenant policy, and remote operational responsibility.

This repository does **not** claim:

- that the Rust CLI is connected to this API;
- that arbitrary shell commands or arbitrary outputs are safe to share;
- end-to-end encryption from producer to consumer (TLS/provider controls are not application-layer encryption);
- production deployment, availability, disaster recovery, compliance, penetration testing, or external security review;
- automatic tenant deletion, retention enforcement, expired/revoked/quarantined-manifest garbage collection, conflict adjudication, or complete R2 orphan collection;
- atomic mutation-plus-audit transactions; an audit insertion can currently fail after an authoritative state transition;
- generation fencing against arbitrarily delayed R2 writers;
- edge/WAF rate limiting before Worker/D1 authentication work;
- that a server-verified signature eliminates the need for consumer-side manifest, environment, policy/profile, platform/image, blob, revocation, and input validation;
- outside-user adoption, cross-team hit rates, or verified savings.
