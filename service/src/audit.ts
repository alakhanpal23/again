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
