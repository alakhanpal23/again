import { ApiError, hexToBytes, nowSeconds, requireRouteIdentifier, sha256Hex } from "./util";

const TOKEN_PATTERN = /^ag1\.([A-Za-z0-9][A-Za-z0-9._:-]{0,63})\.([A-Za-z0-9_-]{32,128})$/;
const RATE_LIMIT_PER_MINUTE = 600;

export type Permission = "read" | "write" | "delete" | "audit" | "admin";

interface TokenRow {
  id: string;
  tenant_id: string;
  subject: string;
  secret_sha256: string;
  repository_scope: string | null;
  permissions: string;
  expires_at: number;
  revoked_at: number | null;
}

interface RateRow {
  request_count: number;
}

export interface AuthContext {
  tokenId: string;
  tenantId: string;
  subject: string;
  repositoryScope: string | null;
  permissions: ReadonlySet<string>;
}

export async function authenticate(
  request: Request,
  env: Env,
  ctx: ExecutionContext,
  repositoryId: string | null,
  permission: Permission,
): Promise<AuthContext> {
  const authorization = request.headers.get("authorization");
  if (authorization === null || !authorization.startsWith("Bearer ")) {
    throw unauthorized();
  }
  const match = TOKEN_PATTERN.exec(authorization.slice("Bearer ".length));
  if (match === null) throw unauthorized();
  const tokenId = match[1];
  const secret = match[2];
  if (tokenId === undefined || secret === undefined) throw unauthorized();

  const row = await env.DB.prepare(
    `SELECT id, tenant_id, subject, secret_sha256, repository_scope,
            permissions, expires_at, revoked_at
       FROM auth_tokens
      WHERE id = ?`,
  )
    .bind(tokenId)
    .first<TokenRow>();

  const suppliedHash = await sha256Hex(secret);
  const storedHash = /^[0-9a-f]{64}$/.test(row?.secret_sha256 ?? "")
    ? (row?.secret_sha256 ?? "0".repeat(64))
    : "0".repeat(64);
  const secretMatches = constantTimeHexEqual(storedHash, suppliedHash);
  if (row === null || !secretMatches) {
    throw unauthorized();
  }
  const now = nowSeconds();
  const requestCount = await enforceRateLimit(env.DB, row.id, now);
  if (requestCount === 1) {
    const staleBefore = now - 3600;
    ctx.waitUntil(
      env.DB.prepare(
        `DELETE FROM rate_windows
          WHERE rowid IN (
            SELECT rowid FROM rate_windows
             WHERE window_start < ?
             ORDER BY window_start
             LIMIT 100
          )`,
      )
        .bind(staleBefore)
        .run()
        .catch((error: unknown) => {
          console.warn(JSON.stringify({ event: "rate_window_cleanup_failed", error: errorName(error) }));
      }),
    );
  }

  if (row.revoked_at !== null || row.expires_at <= now) throw unauthorized();

  const permissions = new Set(row.permissions.split(",").filter((value) => value.length > 0));
  if (!permissions.has(permission) && !permissions.has("admin")) {
    throw new ApiError(403, "permission_denied", "token does not grant this operation");
  }
  if (repositoryId !== null) {
    requireRouteIdentifier(repositoryId, "repository_id");
    if (row.repository_scope !== null && row.repository_scope !== repositoryId) {
      throw new ApiError(404, "not_found", "resource not found");
    }
  }

  return {
    tokenId: row.id,
    tenantId: row.tenant_id,
    subject: row.subject,
    repositoryScope: row.repository_scope,
    permissions,
  };
}

async function enforceRateLimit(db: D1Database, tokenId: string, now: number): Promise<number> {
  const windowStart = now - (now % 60);
  const row = await db
    .prepare(
      `INSERT INTO rate_windows(token_id, window_start, request_count)
       VALUES (?, ?, 1)
       ON CONFLICT(token_id, window_start) DO UPDATE
          SET request_count = request_count + 1
        WHERE request_count < ?
       RETURNING request_count`,
    )
    .bind(tokenId, windowStart, RATE_LIMIT_PER_MINUTE)
    .first<RateRow>();
  if (row === null) {
    throw new ApiError(429, "rate_limited", "token request limit exceeded");
  }
  return row.request_count;
}

function constantTimeHexEqual(expected: string, supplied: string): boolean {
  if (expected.length !== 64 || supplied.length !== 64) return false;
  return crypto.subtle.timingSafeEqual(hexToBytes(expected), hexToBytes(supplied));
}

function unauthorized(): ApiError {
  return new ApiError(401, "unauthorized", "valid bearer token required");
}

function errorName(error: unknown): string {
  return error instanceof Error ? error.name : "UnknownError";
}
