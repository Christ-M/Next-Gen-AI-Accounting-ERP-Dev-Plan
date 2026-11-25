/**
 * Audit service — append-only security/event trail.
 *
 * Rules:
 *  - `audit()` NEVER throws (logging must not break business flows).
 *  - Metadata is JSON-serialized and length-clamped.
 *  - Reads are scoped: users see their own trail, admins see everything.
 */
import { db } from '@/lib/db';
import { clamp, sanitizeText } from '@/core/security/sanitizer';
import { withSqliteRetry, isUniqueViolation } from '@/lib/sqlite-retry';
import { appendChainedAudit } from '@/core/audit/audit-chain.service';

/** Canonical audit action keys (stable, greppable, type-safe). */
export const AUDIT_ACTIONS = {
  AUTH_REGISTER: 'AUTH_REGISTER',
  AUTH_REGISTER_ADMIN: 'AUTH_REGISTER_ADMIN',
  AUTH_LOGIN_SUCCESS: 'AUTH_LOGIN_SUCCESS',
  AUTH_LOGIN_FAILED: 'AUTH_LOGIN_FAILED',
  AUTH_ACCOUNT_LOCKED: 'AUTH_ACCOUNT_LOCKED',
  AUTH_LOGOUT: 'AUTH_LOGOUT',
  AUTH_TOKEN_REFRESH: 'AUTH_TOKEN_REFRESH',
  AUTH_TOKEN_REUSED: 'AUTH_TOKEN_REUSED',
  SESSION_REVOKED: 'SESSION_REVOKED',
  SESSIONS_REVOKED_ALL: 'SESSIONS_REVOKED_ALL',
  BOOTSTRAP_ADMIN_CREATED: 'BOOTSTRAP_ADMIN_CREATED',

  // Phase 2 — accounting events
  ACC_ACCOUNT_CREATED: 'ACC_ACCOUNT_CREATED',
  ACC_ACCOUNT_UPDATED: 'ACC_ACCOUNT_UPDATED',
  ACC_ACCOUNT_DELETED: 'ACC_ACCOUNT_DELETED',
  ACC_ENTRY_CREATED: 'ACC_ENTRY_CREATED',
  ACC_ENTRY_UPDATED: 'ACC_ENTRY_UPDATED',
  ACC_ENTRY_DELETED: 'ACC_ENTRY_DELETED',
  ACC_ENTRY_POSTED: 'ACC_ENTRY_POSTED',
  ACC_ENTRY_VOIDED: 'ACC_ENTRY_VOIDED',
  ACC_ENTRY_REVERSED: 'ACC_ENTRY_REVERSED',
  ACC_PERIOD_CREATED: 'ACC_PERIOD_CREATED',
  ACC_PERIOD_CLOSED: 'ACC_PERIOD_CLOSED',
  ACC_PERIOD_REOPENED: 'ACC_PERIOD_REOPENED',
  ACC_CURRENCY_ADDED: 'ACC_CURRENCY_ADDED',
  ACC_CURRENCY_UPDATED: 'ACC_CURRENCY_UPDATED',
  ACC_RATE_SET: 'ACC_RATE_SET',
  ACC_TAX_CREATED: 'ACC_TAX_CREATED',
  ACC_TAX_UPDATED: 'ACC_TAX_UPDATED',
  ACC_REVAL_RUN: 'ACC_REVAL_RUN',

  // Phase 3 — inventory events
  INV_PRODUCT_CREATED: 'INV_PRODUCT_CREATED',
  INV_PRODUCT_UPDATED: 'INV_PRODUCT_UPDATED',
  INV_PRODUCT_DELETED: 'INV_PRODUCT_DELETED',
  INV_CATEGORY_CREATED: 'INV_CATEGORY_CREATED',
  INV_UOM_CREATED: 'INV_UOM_CREATED',
  INV_WAREHOUSE_CREATED: 'INV_WAREHOUSE_CREATED',
  INV_WAREHOUSE_UPDATED: 'INV_WAREHOUSE_UPDATED',
  INV_MOVE_CREATED: 'INV_MOVE_CREATED',
  INV_MOVE_POSTED: 'INV_MOVE_POSTED',
  INV_MOVE_DELETED: 'INV_MOVE_DELETED',
  INV_MOVE_VOIDED: 'INV_MOVE_VOIDED',
  INV_COST_RECALCULATED: 'INV_COST_RECALCULATED',
  INV_COUNT_CREATED: 'INV_COUNT_CREATED',
  INV_COUNT_COMPLETED: 'INV_COUNT_COMPLETED',
  INV_COUNT_CANCELLED: 'INV_COUNT_CANCELLED',
  INV_FORECAST_GENERATED: 'INV_FORECAST_GENERATED',
  INV_SETTINGS_UPDATED: 'INV_SETTINGS_UPDATED',

  // Phase 4 — sales & purchasing events
  SALES_PARTY_CREATED: 'SALES_PARTY_CREATED',
  SALES_PARTY_UPDATED: 'SALES_PARTY_UPDATED',
  SALES_PARTY_DELETED: 'SALES_PARTY_DELETED',
  SALES_DOC_CREATED: 'SALES_DOC_CREATED',
  SALES_DOC_UPDATED: 'SALES_DOC_UPDATED',
  SALES_DOC_DELETED: 'SALES_DOC_DELETED',
  SALES_DOC_STATUS: 'SALES_DOC_STATUS',
  SALES_DOC_CONVERTED: 'SALES_DOC_CONVERTED',
  SALES_DOC_ISSUED: 'SALES_DOC_ISSUED',
  SALES_DOC_FULFILLED: 'SALES_DOC_FULFILLED',
  SALES_DOC_VOIDED: 'SALES_DOC_VOIDED',
  PURCH_DOC_CREATED: 'PURCH_DOC_CREATED',
  PURCH_DOC_UPDATED: 'PURCH_DOC_UPDATED',
  PURCH_DOC_DELETED: 'PURCH_DOC_DELETED',
  PURCH_DOC_CONFIRMED: 'PURCH_DOC_CONFIRMED',
  PURCH_DOC_RECEIVED: 'PURCH_DOC_RECEIVED',
  PURCH_DOC_ISSUED: 'PURCH_DOC_ISSUED',
  PURCH_DOC_VOIDED: 'PURCH_DOC_VOIDED',
  SALES_PAYMENT_RECORDED: 'SALES_PAYMENT_RECORDED',
  SALES_PAYMENT_VOIDED: 'SALES_PAYMENT_VOIDED',
  SALES_POS_CHECKOUT: 'SALES_POS_CHECKOUT',
  SALES_SETTINGS_UPDATED: 'SALES_SETTINGS_UPDATED',

  // Phase 5 — treasury events
  TRE_ACCOUNT_CREATED: 'TRE_ACCOUNT_CREATED',
  TRE_ACCOUNT_UPDATED: 'TRE_ACCOUNT_UPDATED',
  TRE_ACCOUNT_DELETED: 'TRE_ACCOUNT_DELETED',
  TRE_CHEQUE_CREATED: 'TRE_CHEQUE_CREATED',
  TRE_CHEQUE_ACTION: 'TRE_CHEQUE_ACTION',
  TRE_TRANSFER_CREATED: 'TRE_TRANSFER_CREATED',
  TRE_TRANSFER_VOIDED: 'TRE_TRANSFER_VOIDED',
  TRE_RECON_LINE_ADDED: 'TRE_RECON_LINE_ADDED',
  TRE_RECON_LINE_DELETED: 'TRE_RECON_LINE_DELETED',
  TRE_RECON_MATCHED: 'TRE_RECON_MATCHED',
  TRE_RECON_UNMATCHED: 'TRE_RECON_UNMATCHED',
  TRE_RECON_ADJUSTED: 'TRE_RECON_ADJUSTED',
  TRE_RECON_FEED_IMPORTED: 'TRE_RECON_FEED_IMPORTED',
  TRE_RECON_TX_CREATED: 'TRE_RECON_TX_CREATED',
  TRE_RECON_CLOSED: 'TRE_RECON_CLOSED',
  TRE_SETTINGS_UPDATED: 'TRE_SETTINGS_UPDATED',

  // Phase 6 — planning events (calendar, goals, budgets)
  PLAN_EVENT_CREATED: 'PLAN_EVENT_CREATED',
  PLAN_EVENT_UPDATED: 'PLAN_EVENT_UPDATED',
  PLAN_EVENT_DELETED: 'PLAN_EVENT_DELETED',
  PLAN_EVENT_STATUS: 'PLAN_EVENT_STATUS',
  PLAN_GOAL_CREATED: 'PLAN_GOAL_CREATED',
  PLAN_GOAL_UPDATED: 'PLAN_GOAL_UPDATED',
  PLAN_GOAL_DELETED: 'PLAN_GOAL_DELETED',
  PLAN_GOAL_CONTRIBUTION: 'PLAN_GOAL_CONTRIBUTION',
  PLAN_BUDGET_CREATED: 'PLAN_BUDGET_CREATED',
  PLAN_BUDGET_UPDATED: 'PLAN_BUDGET_UPDATED',
  PLAN_BUDGET_DELETED: 'PLAN_BUDGET_DELETED',
  PLAN_BUDGET_ACTIVATED: 'PLAN_BUDGET_ACTIVATED',
  PLAN_BUDGET_CLOSED: 'PLAN_BUDGET_CLOSED',
  PLAN_BUDGET_POLICY_CHANGED: 'PLAN_BUDGET_POLICY_CHANGED', // Phase 25 — guard policy {mode, tolerancePct}
  PLAN_BUDGET_REVISION_CREATED: 'PLAN_BUDGET_REVISION_CREATED', // Phase 25 — signed deltas on a committed budget
  PLAN_BUDGET_REVISION_APPROVED: 'PLAN_BUDGET_REVISION_APPROVED', // Phase 25
  PLAN_BUDGET_REVISION_REJECTED: 'PLAN_BUDGET_REVISION_REJECTED', // Phase 25
  PLAN_BUDGET_REVISION_APPLIED: 'PLAN_BUDGET_REVISION_APPLIED', // Phase 25 — budget lines mutated (evidence)
  PLAN_INSIGHTS_GENERATED: 'PLAN_INSIGHTS_GENERATED',

  // Phase 7 — reports & AI events
  AI_ANOMALY_SCAN: 'AI_ANOMALY_SCAN',
  AI_FORECAST_GENERATED: 'AI_FORECAST_GENERATED',
  AI_SUGGESTION_APPLIED: 'AI_SUGGESTION_APPLIED',
  AI_ASK_EXECUTED: 'AI_ASK_EXECUTED',

  // Phase 6 (v3) — financial AI hardening
  AI_WHATIF_SIMULATED: 'AI_WHATIF_SIMULATED',
  AI_SCENARIO_SAVED: 'AI_SCENARIO_SAVED',
  AI_SCENARIO_DELETED: 'AI_SCENARIO_DELETED',
  AI_ANOMALY_FEEDBACK: 'AI_ANOMALY_FEEDBACK',

  // Phase 7 (v3) — tax compliance events
  TAX_PROFILE_UPDATED: 'TAX_PROFILE_UPDATED',
  TAX_VAT_FILED: 'TAX_VAT_FILED',
  TAX_VAT_UNFILED: 'TAX_VAT_UNFILED',
  TAX_PERFORMANCE_CALC: 'TAX_PERFORMANCE_CALC',

  // Phase 20 — tax declaration package
  TAX_RETURN_CREATED: 'TAX_RETURN_CREATED',
  TAX_RETURN_FILED: 'TAX_RETURN_FILED',
  TAX_RETURN_PAID: 'TAX_RETURN_PAID',
  TAX_RETURN_UNFILED: 'TAX_RETURN_UNFILED',
  TAX_RETURN_DELETED: 'TAX_RETURN_DELETED',
  TAX_WITHHOLDING_CREATED: 'TAX_WITHHOLDING_CREATED',
  TAX_WITHHOLDING_REVERSED: 'TAX_WITHHOLDING_REVERSED',

  // Phase 8 — enterprise command center
  ADMIN_USER_CREATED: 'ADMIN_USER_CREATED',
  ADMIN_USER_UPDATED: 'ADMIN_USER_UPDATED',
  ADMIN_USER_DELETED: 'ADMIN_USER_DELETED',
  ADMIN_PASSWORD_RESET: 'ADMIN_PASSWORD_RESET',
  BACKUP_CREATED: 'BACKUP_CREATED',
  BACKUP_DELETED: 'BACKUP_DELETED',
  BACKUP_DOWNLOADED: 'BACKUP_DOWNLOADED',
  BACKUP_RESTORED: 'BACKUP_RESTORED',
  DATA_EXPORTED: 'DATA_EXPORTED',
  DATA_IMPORTED: 'DATA_IMPORTED',
  DIAGNOSTICS_RUN: 'DIAGNOSTICS_RUN',

  // Phase 8 (v3) — ops: webhooks, streaming, auto-backup
  WEBHOOK_CREATED: 'WEBHOOK_CREATED',
  WEBHOOK_UPDATED: 'WEBHOOK_UPDATED',
  WEBHOOK_DELETED: 'WEBHOOK_DELETED',
  WEBHOOK_TESTED: 'WEBHOOK_TESTED',
  WEBHOOK_RETRY_RUN: 'WEBHOOK_RETRY_RUN',
  STREAM_EXPORTED: 'STREAM_EXPORTED',
  STREAM_IMPORTED: 'STREAM_IMPORTED',
  BACKUP_SCHEDULE_UPDATED: 'BACKUP_SCHEDULE_UPDATED',

  // Phase 9 (v3) — two-factor auth & at-rest encryption
  AUTH_2FA_SETUP: 'AUTH_2FA_SETUP',
  AUTH_2FA_ENABLED: 'AUTH_2FA_ENABLED',
  AUTH_2FA_DISABLED: 'AUTH_2FA_DISABLED',
  AUTH_2FA_FAILED: 'AUTH_2FA_FAILED',
  AUTH_2FA_RECOVERY_USED: 'AUTH_2FA_RECOVERY_USED',
  AUTH_2FA_RECOVERY_REGENERATED: 'AUTH_2FA_RECOVERY_REGENERATED',
  SECURITY_SECRETS_MIGRATED: 'SECURITY_SECRETS_MIGRATED',

  // Phase 12 (v3) — automation & scheduler
  JOB_CREATED: 'JOB_CREATED',
  JOB_UPDATED: 'JOB_UPDATED',
  JOB_DELETED: 'JOB_DELETED',
  JOB_RUN_MANUAL: 'JOB_RUN_MANUAL',
  JOB_AUTO_DISABLED: 'JOB_AUTO_DISABLED',

  // Phase 13 (v3) — disaster recovery & business continuity
  DR_VERIFY: 'DR_VERIFY',
  DR_DRILL_RUN: 'DR_DRILL_RUN',

  // Phase 14 (v3) — external API-key platform
  API_KEY_CREATED: 'API_KEY_CREATED',
  API_KEY_UPDATED: 'API_KEY_UPDATED',
  API_KEY_REVOKED: 'API_KEY_REVOKED',
  API_KEY_DELETED: 'API_KEY_DELETED',

  // Phase 15 (v3) — BI builder & exports
  BI_EXPORT_RUN: 'BI_EXPORT_RUN',
  BI_REPORT_CREATED: 'BI_REPORT_CREATED',
  BI_REPORT_UPDATED: 'BI_REPORT_UPDATED',
  BI_REPORT_DELETED: 'BI_REPORT_DELETED',
  BI_REPORT_RUN: 'BI_REPORT_RUN',

  // Phase 16 (v3) — fixed assets & payroll
  ASSET_CATEGORY_CREATED: 'ASSET_CATEGORY_CREATED',
  ASSET_CATEGORY_UPDATED: 'ASSET_CATEGORY_UPDATED',
  ASSET_CATEGORY_DELETED: 'ASSET_CATEGORY_DELETED',
  ASSET_CREATED: 'ASSET_CREATED',
  ASSET_UPDATED: 'ASSET_UPDATED',
  ASSET_DELETED: 'ASSET_DELETED',
  ASSET_DISPOSED: 'ASSET_DISPOSED',
  DEPRECIATION_RUN: 'DEPRECIATION_RUN',
  PAYROLL_EMPLOYEE_CREATED: 'PAYROLL_EMPLOYEE_CREATED',
  PAYROLL_EMPLOYEE_UPDATED: 'PAYROLL_EMPLOYEE_UPDATED',
  PAYROLL_EMPLOYEE_DELETED: 'PAYROLL_EMPLOYEE_DELETED',
  PAYROLL_CONTRACT_CREATED: 'PAYROLL_CONTRACT_CREATED',
  PAYROLL_WORKLOG_SAVED: 'PAYROLL_WORKLOG_SAVED',
  PAYROLL_RUN_CREATED: 'PAYROLL_RUN_CREATED',
  PAYROLL_RUN_DELETED: 'PAYROLL_RUN_DELETED',
  PAYROLL_RUN_APPROVED: 'PAYROLL_RUN_APPROVED',
  PAYROLL_RUN_PAID: 'PAYROLL_RUN_PAID',
  PAYROLL_TAX_TABLE_UPDATED: 'PAYROLL_TAX_TABLE_UPDATED',

  // Phase 17 (v3) — HR & social insurance suite
  HR_LEAVE_CREATED: 'HR_LEAVE_CREATED',
  HR_LEAVE_UPDATED: 'HR_LEAVE_UPDATED',
  HR_LEAVE_APPROVED: 'HR_LEAVE_APPROVED',
  HR_LEAVE_REJECTED: 'HR_LEAVE_REJECTED',
  HR_LEAVE_CANCELLED: 'HR_LEAVE_CANCELLED',
  HR_ACCRUAL_CREATED: 'HR_ACCRUAL_CREATED',
  HR_ACCRUAL_DELETED: 'HR_ACCRUAL_DELETED',
  HR_ACCRUAL_APPROVED: 'HR_ACCRUAL_APPROVED',
  HR_BANK_FILE_EXPORTED: 'HR_BANK_FILE_EXPORTED',

  // Phase 18 (v3) — cost & profit centers
  CC_CENTER_CREATED: 'CC_CENTER_CREATED',
  CC_CENTER_UPDATED: 'CC_CENTER_UPDATED',
  CC_CENTER_DELETED: 'CC_CENTER_DELETED',
  CC_LINES_TAGGED: 'CC_LINES_TAGGED', // bulk tagging (incl. untag, center=null)
  CC_ALLOCATION_CREATED: 'CC_ALLOCATION_CREATED',
  CC_ALLOCATION_DELETED: 'CC_ALLOCATION_DELETED',
  CC_ALLOCATION_APPROVED: 'CC_ALLOCATION_APPROVED', // voucher number in metadata

  // Phase 19 (v3) — cash-flow statement
  CF_MAPPING_SET: 'CF_MAPPING_SET', // cash-flow classification override (account → activity)
  CF_MAPPING_DELETED: 'CF_MAPPING_DELETED', // classification override removed (default rules resume)

  // Phase 21 (v3) — financial close (چرخهٔ اختتامیه)
  CL_CLOSED: 'CL_CLOSED', // year-end close run completed (voucher numbers in metadata)
  CL_UNCLOSED: 'CL_UNCLOSED', // close reversal — books re-opened for the year

  // Phase 22 (v3) — attachments & document evidence (پیوست‌ها)
  ATTACHMENT_UPLOAD: 'ATTACHMENT_UPLOAD', // evidence bound to an entity (sha256/size in metadata)
  ATTACHMENT_DOWNLOAD: 'ATTACHMENT_DOWNLOAD', // payload retrieved (evidence-chain access log)
  ATTACHMENT_DELETED: 'ATTACHMENT_DELETED', // soft delete — audit chain stays complete

  // Phase 23 — approval workflow engine
  WF_RULE_CREATED: 'WF_RULE_CREATED', // threshold routing rule registered
  WF_RULE_UPDATED: 'WF_RULE_UPDATED', // rule/steps edited (history keeps snapshots)
  WF_RULE_DELETED: 'WF_RULE_DELETED', // soft delete — matching stops, history intact
  WF_REQUEST_SUBMITTED: 'WF_REQUEST_SUBMITTED', // entity submitted (manual or auto-gate)
  WF_STEP_APPROVED: 'WF_STEP_APPROVED', // one step cleared (seq + actor in metadata)
  WF_REQUEST_APPROVED: 'WF_REQUEST_APPROVED', // final step cleared — bound action executed
  WF_REQUEST_REJECTED: 'WF_REQUEST_REJECTED', // rejected at a step — entity untouched
  WF_REQUEST_CANCELLED: 'WF_REQUEST_CANCELLED', // cancelled by creator/admin

  // Phase 24 — BOM & manufacturing (مواد و تولید)
  MFG_BOM_CREATED: 'MFG_BOM_CREATED', // BOM registered (output × version + lines)
  MFG_BOM_UPDATED: 'MFG_BOM_UPDATED', // header/lines edited (locked once live orders exist)
  MFG_BOM_STATUS: 'MFG_BOM_STATUS', // archive/unarchive toggle
  MFG_BOM_DELETED: 'MFG_BOM_DELETED', // soft delete — completed-order evidence intact
  MFG_ORDER_CREATED: 'MFG_ORDER_CREATED', // DRAFT order over an ACTIVE BOM
  MFG_ORDER_RELEASED: 'MFG_ORDER_RELEASED', // availability soft-check passed
  MFG_ORDER_COMPLETED: 'MFG_ORDER_COMPLETED', // consumption + output + transformation voucher
  MFG_ORDER_CANCELLED: 'MFG_ORDER_CANCELLED', // DRAFT/RELEASED → CANCELLED
  MFG_ORDER_DELETED: 'MFG_ORDER_DELETED', // DRAFT-only structural delete

  // Phase 27 — data lifecycle & retention governance
  LIFECYCLE_POLICY_CHANGED: 'LIFECYCLE_POLICY_CHANGED', // retention rule {keepDays, enabled}
  LIFECYCLE_SWEPT: 'LIFECYCLE_SWEPT', // sweep executed (dry-run or commit) — totals evidence

  // Phase 28 — governed bulk import
  IMPORT_EXECUTED: 'IMPORT_EXECUTED', // dry-run uploaded + validated (row-level outcome evidence)
  IMPORT_COMMITTED: 'IMPORT_COMMITTED', // commit executed — created rows + digest evidence
} as const;

export type AuditAction = (typeof AUDIT_ACTIONS)[keyof typeof AUDIT_ACTIONS];
export type AuditSeverity = 'INFO' | 'WARNING' | 'CRITICAL';

export interface AuditEntry {
  userId?: string | null;
  action: AuditAction | string;
  severity?: AuditSeverity;
  entity?: string;
  entityId?: string;
  ipAddress?: string | null;
  userAgent?: string | null;
  metadata?: Record<string, unknown>;
}

/** Persist an audit event. Fire-and-forget safe. */
export async function audit(entry: AuditEntry): Promise<void> {
  try {
    let metadata: string | undefined;
    if (entry.metadata) {
      try {
        metadata = JSON.stringify(entry.metadata).slice(0, 1000);
      } catch {
        metadata = undefined;
      }
    }
    // Phase 30 — every entry is sealed into the SHA-256 hash chain
    // (audit-chain.service). The row is created with an explicit createdAt
    // so the timestamp is covered by the hash. Transient SQLite contention
    // (P1008/P2024/P2034) must not silently drop audit rows under concurrent
    // writes; bounded retry first — the retry re-reads the chain head, so a
    // UNIQUE(seq) race (P2002 — two writers read the same head concurrently)
    // resolves itself on the next attempt with a fresh seq + hash.
    await withSqliteRetry(
      () =>
        appendChainedAudit({
          userId: entry.userId ?? null,
          action: entry.action,
          severity: entry.severity ?? 'INFO',
          entity: entry.entity ? sanitizeText(entry.entity, 60) : null,
          entityId: entry.entityId ? sanitizeText(entry.entityId, 60) : null,
          ipAddress: entry.ipAddress ? clamp(entry.ipAddress, 64) : null,
          userAgent: entry.userAgent ? clamp(entry.userAgent, 300) : null,
          metadata: metadata ?? null,
          createdAt: new Date(),
        }),
      { attempts: 6, baseDelayMs: 60, retryOn: isUniqueViolation }
    );
  } catch (err) {
    // Never break the main flow because of audit failures.
    console.error('[audit] failed to persist entry:', err);
  }
}

export interface AuditQuery {
  /** 'own' → force userId filter; 'all' → admin-only scope, no filter */
  scope: 'own' | 'all';
  userId?: string;
  take?: number;
  cursorId?: string;
}

export async function listAuditLogs({ scope, userId, take = 20, cursorId }: AuditQuery) {
  const limit = Math.min(Math.max(take, 1), 100);
  return db.auditLog.findMany({
    where: scope === 'own' ? { userId } : undefined,
    orderBy: [{ createdAt: 'desc' }, { id: 'desc' }],
    take: limit,
    ...(cursorId ? { cursor: { id: cursorId }, skip: 1 } : {}),
    include: { user: { select: { id: true, fullName: true, email: true, role: true } } },
  });
}

export async function countAuditSince(since: Date, action?: string): Promise<number> {
  return db.auditLog.count({
    where: { createdAt: { gte: since }, ...(action ? { action } : {}) },
  });
}
