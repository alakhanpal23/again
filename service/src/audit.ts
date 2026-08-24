import type { AuthContext } from "./auth";
import { sha256Hex } from "./util";

export type AuditDetail = string | number | boolean | null;

export async function auditStatement(
  db: D1Database,
  auth: AuthContext,
  repositoryId: string | null,
  action: string,
  targetType: string,
  targetId: string,
  outcome: string,
  details: Readonly<Record<string, AuditDetail>> = {},
): Promise<D1PreparedStatement> {
  const targetHash = await sha256Hex(
    `${auth.tenantId}\0${repositoryId ?? ""}\0${targetType}\0${targetId}`,
  );
  return db
    .prepare(
      `INSERT INTO audit_events(
         tenant_id, repository_id, actor, action, target_type,
         target_id_sha256, outcome, details_json, created_at
       ) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?)`,
    )
    .bind(
      auth.tenantId,
      repositoryId,
      auth.subject,
      action,
      targetType,
      targetHash,
      outcome,
      JSON.stringify(details),
      Math.floor(Date.now() / 1000),
    );
}

/**
 * Build an audit insert guarded by an exact live repository generation.
 * Callers batch it with their mutation; mutation-specific predicates are
 * still required where a zero-row state transition is a normal race.
 */
export async function generationGuardedAuditAfterMutationStatement(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  generationId: string,
  actor: string,
  action: string,
  targetType: string,
  targetId: string,
  outcome: string,
  details: Readonly<Record<string, AuditDetail>> = {},
): Promise<D1PreparedStatement> {
  const targetHash = await sha256Hex(
    `${tenantId}\0${repositoryId}\0${targetType}\0${targetId}`,
  );
  return db
    .prepare(
      `INSERT INTO audit_events(
         tenant_id, repository_id, actor, action, target_type,
         target_id_sha256, outcome, details_json, created_at
       )
       SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE EXISTS (
            SELECT 1 FROM repositories repository
             WHERE repository.tenant_id = ? AND repository.id = ?
               AND repository.generation_id = ?
               AND repository.deleted_at IS NULL
          )`,
    )
    .bind(
      tenantId,
      repositoryId,
      actor,
      action,
      targetType,
      targetHash,
      outcome,
      JSON.stringify(details),
      Math.floor(Date.now() / 1000),
      tenantId,
      repositoryId,
      generationId,
    );
}

/** Build a repository-scoped audit insert that can only target one live generation. */
export async function generationGuardedAuditStatement(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  generationId: string,
  actor: string,
  action: string,
  targetType: string,
  targetId: string,
  outcome: string,
  details: Readonly<Record<string, AuditDetail>> = {},
): Promise<D1PreparedStatement> {
  const targetHash = await sha256Hex(
    `${tenantId}\0${repositoryId}\0${targetType}\0${targetId}`,
  );
  return db
    .prepare(
      `INSERT INTO audit_events(
         tenant_id, repository_id, actor, action, target_type,
         target_id_sha256, outcome, details_json, created_at
       )
       SELECT ?, ?, ?, ?, ?, ?, ?, ?, ?
        WHERE EXISTS (
          SELECT 1 FROM repositories repository
           WHERE repository.tenant_id = ? AND repository.id = ?
             AND repository.generation_id = ?
             AND repository.deleted_at IS NULL
        )`,
    )
    .bind(
      tenantId,
      repositoryId,
      actor,
      action,
      targetType,
      targetHash,
      outcome,
      JSON.stringify(details),
      Math.floor(Date.now() / 1000),
      tenantId,
      repositoryId,
      generationId,
    );
}

/**
 * Build the repository-create audit fence. Repository creation is the only
 * repository mutation authorized before a generation exists, so it must also
 * revalidate the exact tenant-admin token inside the D1 transaction.
 */
export async function tenantAdminGenerationGuardedAuditStatement(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  generationId: string,
  tokenId: string,
  tokenSecretSha256: string,
  actor: string,
  outcome: string,
): Promise<D1PreparedStatement> {
  const targetHash = await sha256Hex(
    `${tenantId}\0${repositoryId}\0repository\0${repositoryId}`,
  );
  return db
    .prepare(
      `INSERT INTO audit_events(
         tenant_id, repository_id, actor, action, target_type,
         target_id_sha256, outcome, details_json, created_at
       )
       SELECT ?, ?, ?, 'repository.create', 'repository', ?, ?, '{}', ?
        WHERE EXISTS (
          SELECT 1 FROM repositories repository
           WHERE repository.tenant_id = ? AND repository.id = ?
             AND repository.generation_id = ? AND repository.deleted_at IS NULL
        )
          AND EXISTS (
            SELECT 1 FROM auth_tokens token
             WHERE token.id = ? AND token.tenant_id = ?
               AND token.secret_sha256 = ? AND token.subject = ?
               AND token.repository_scope IS NULL
               AND token.revoked_at IS NULL AND token.expires_at > unixepoch()
               AND instr(',' || token.permissions || ',', ',admin,') > 0
          )`,
    )
    .bind(
      tenantId,
      repositoryId,
      actor,
      targetHash,
      outcome,
      Math.floor(Date.now() / 1000),
      tenantId,
      repositoryId,
      generationId,
      tokenId,
      tenantId,
      tokenSecretSha256,
      actor,
    );
}

/** Build the one audit event allowed after an exact repository tombstone. */
export async function generationGuardedDeletionAuditStatement(
  db: D1Database,
  tenantId: string,
  repositoryId: string,
  generationId: string,
  actor: string,
  targetId: string,
): Promise<D1PreparedStatement> {
  const targetHash = await sha256Hex(
    `${tenantId}\0${repositoryId}\0repository\0${targetId}`,
  );
  return db
    .prepare(
      `INSERT INTO audit_events(
         tenant_id, repository_id, actor, action, target_type,
         target_id_sha256, outcome, details_json, created_at
       )
       SELECT ?, ?, ?, 'repository.delete', 'repository', ?, 'requested', '{}', ?
        WHERE EXISTS (
          SELECT 1 FROM repositories repository
           WHERE repository.tenant_id = ? AND repository.id = ?
             AND repository.generation_id = ?
             AND repository.deleted_at IS NOT NULL
        )
          AND EXISTS (
            SELECT 1 FROM repository_deletions deletion
             WHERE deletion.tenant_id = ? AND deletion.repository_id = ?
               AND deletion.generation_id = ? AND deletion.phase != 'finalize'
          )`,
    )
    .bind(
      tenantId,
      repositoryId,
      actor,
      targetHash,
      Math.floor(Date.now() / 1000),
      tenantId,
      repositoryId,
      generationId,
      tenantId,
      repositoryId,
      generationId,
    );
}
