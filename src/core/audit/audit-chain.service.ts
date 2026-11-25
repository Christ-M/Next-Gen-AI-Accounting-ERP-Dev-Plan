/**
 * Phase 30 — Tamper-Evident Audit Ledger (دفتر حسابرسی ضد دستکاری).
 *
 * Every audit entry is sealed into a SHA-256 hash chain:
 *
 *   hash(n) = SHA-256( prevHash(n) ‖ '\u001f' ‖ canonical(row(n)) )
 *   prevHash(1) = GENESIS = '0' × 64
 *
 * `canonical(row)` is a deterministic serialization with a fixed field order
 * (see canonicalAuditRow) — the verifier recomputes it byte-for-byte from the
 * stored columns, so ANY mutation of an audited field (action, severity,
 * metadata, timestamps, …) breaks the chain at exactly that entry.
 *
 * Integrity invariants (machine-checked by tests/p36-audit-chain-e2e.mjs):
 *  1. seq is globally unique and gap-free over chained rows (UNIQUE index ⇒
 *     a racing append retried against the fresh head cannot duplicate it).
 *  2. hash(n) covers the full row content — recompute-and-compare is THE
 *     tamper detector (no trust in stored values).
 *  3. prevHash(n) === hash(n-1) — chain linkage.
 *  4. AuditCheckpoint seals pin the head at seal time: history sealed by a
 *     checkpoint cannot be rewritten without breaking the seal evidence.
 *
 * The chain is single-writer by construction (the `audit()` write throat) on
 * the single-instance SQLite runtime; the UNIQUE(seq) index plus the bounded
 * SQLite retry make even hypothetical cross-process races fail closed.
 */
import { createHash } from 'crypto';
import { db } from '@/lib/db';
import { withSqliteRetry } from '@/lib/sqlite-retry';

/** Genesis prev-hash: SHA-256 chain root marker (64 zeros). */
export const AUDIT_GENESIS_HASH = '0'.repeat(64);

/** Field separator inside the canonical payload (ASCII unit separator). */
const SEP = '\u001f';

/** NULL-field marker — collision-free: never appears in sanitized payloads. */
const NULL = '\u0002';

/** Algorithm tag stored on checkpoints (upgrade path for future formats). */
export const AUDIT_CHAIN_ALGORITHM = 'sha256-v1';

// ── canonical serialization ─────────────────────────────────────────────────

/**
 * Deterministic audit-row serialization. Fixed order:
 *   v1 ‖ action ‖ severity ‖ entity ‖ entityId ‖ userId ‖ ip ‖ ua ‖ metadata ‖ createdAtISO
 * NULL/undefined → the NULL marker; numbers render as decimal strings.
 * The stored `metadata` string is used verbatim (it is what the row holds).
 */
export function canonicalAuditRow(row: {
  action: string;
  severity: string;
  entity: string | null;
  entityId: string | null;
  userId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  metadata: string | null;
  createdAt: Date;
}): string {
  const f = (v: string | null | undefined) =>
    v === null || v === undefined || v === '' ? NULL : v;
  return [
    'audit-chain-v1',
    f(row.action),
    f(row.severity),
    f(row.entity),
    f(row.entityId),
    f(row.userId),
    f(row.ipAddress),
    f(row.userAgent),
    f(row.metadata),
    row.createdAt.toISOString(),
  ].join(SEP);
}

/** SHA-256 hex digest of one chained audit row. */
export function computeAuditRowHash(
  prevHash: string,
  row: Parameters<typeof canonicalAuditRow>[0],
): string {
  return createHash('sha256').update(prevHash + SEP + canonicalAuditRow(row)).digest('hex');
}

// ── append (the write side of the chain) ────────────────────────────────────

export interface ChainedAuditData {
  userId: string | null;
  action: string;
  severity: string;
  entity: string | null;
  entityId: string | null;
  ipAddress: string | null;
  userAgent: string | null;
  metadata: string | null;
  /** Explicit timestamp — hashed, so it must be decided BEFORE hashing. */
  createdAt: Date;
}

/**
 * Append one entry to the chain. Returns the created row.
 * Concurrency: reads the current head, appends seq = head.seq + 1. The
 * UNIQUE(seq) index makes double-append fail loudly; the caller's
 * withSqliteRetry re-reads the head and succeeds on the retry.
 */
export async function appendChainedAudit(data: ChainedAuditData) {
  const head = await db.auditLog.findFirst({
    where: { hash: { not: null } },
    orderBy: [{ seq: 'desc' }],
    select: { seq: true, hash: true },
  });
  const seq = (head?.seq ?? 0) + 1;
  const prevHash = head?.hash ?? AUDIT_GENESIS_HASH;
  const hash = computeAuditRowHash(prevHash, data);
  return db.auditLog.create({
    data: {
      userId: data.userId,
      action: data.action,
      severity: data.severity,
      entity: data.entity,
      entityId: data.entityId,
      ipAddress: data.ipAddress,
      userAgent: data.userAgent,
      metadata: data.metadata,
      createdAt: data.createdAt,
      seq,
      prevHash,
      hash,
    },
  });
}

// ── verification (the read side of the chain) ───────────────────────────

export interface ChainVerifyResult {
  ok: boolean;
  /** rows actually re-hashed during this verification */
  checked: number;
  headSeq: number | null;
  headHash: string | null;
  firstBrokenSeq: number | null;
  reason: string | null;
  coverage: { chained: number; total: number };
}

/**
 * Full chain walk: recompute every hash from the stored columns, check
 * linkage (prevHash === previous hash) and gap-free seq continuity.
 * Deterministic, read-only, no timing dependence (unlike latency probes).
 */
export async function verifyAuditChain(): Promise<ChainVerifyResult> {
  const [total, chained] = await Promise.all([
    db.auditLog.count(),
    db.auditLog.count({ where: { hash: { not: null } } }),
  ]);

  const rows = await db.auditLog.findMany({
    where: { hash: { not: null } },
    orderBy: [{ seq: 'asc' }],
    select: {
      seq: true,
      hash: true,
      prevHash: true,
      action: true,
      severity: true,
      entity: true,
      entityId: true,
      userId: true,
      ipAddress: true,
      userAgent: true,
      metadata: true,
      createdAt: true,
    },
  });

  const base: Omit<ChainVerifyResult, 'ok'> = {
    checked: rows.length,
    headSeq: rows.length ? (rows[rows.length - 1].seq ?? null) : null,
    headHash: rows.length ? (rows[rows.length - 1].hash ?? null) : null,
    firstBrokenSeq: null,
    reason: null,
    coverage: { chained, total },
  };

  if (rows.length === 0) {
    return { ...base, ok: true }; // empty chain is trivially intact
  }

  let prevHash = AUDIT_GENESIS_HASH;
  let prevSeq = 0;
  for (const row of rows) {
    if (row.prevHash !== prevHash) {
      return {
        ...base,
        ok: false,
        firstBrokenSeq: row.seq,
        reason: `linkage broken at seq=${row.seq} — prevHash does not match hash of seq=${prevSeq}`,
      };
    }
    if (row.seq !== prevSeq + 1) {
      return {
        ...base,
        ok: false,
        firstBrokenSeq: row.seq,
        reason: `gap: expected seq=${prevSeq + 1} but found seq=${row.seq}`,
      };
    }
    const expected = computeAuditRowHash(prevHash, row);
    if (expected !== row.hash) {
      return {
        ...base,
        ok: false,
        firstBrokenSeq: row.seq,
        reason: `hash mismatch at seq=${row.seq} — row content mutated after sealing (recomputed ${expected.slice(0, 12)}… ≠ stored ${String(row.hash).slice(0, 12)}…)`,
      };
    }
    prevHash = row.hash!;
    prevSeq = row.seq;
  }
  return { ...base, ok: true };
}

// ── one-time legacy backfill ────────────────────────────────────────────────

/**
 * Chain legacy rows (hash IS NULL) — created before Phase 30 — in their
 * chronological order, continuing the seq sequence. Idempotent: a completed
 * backfill is a no-op. Returns the number of rows newly chained.
 */
export async function backfillAuditChain(): Promise<{ backfilled: number }> {
  const head = await db.auditLog.findFirst({
    where: { hash: { not: null } },
    orderBy: [{ seq: 'desc' }],
    select: { seq: true, hash: true },
  });
  let seq = head?.seq ?? 0;
  let prevHash = head?.hash ?? AUDIT_GENESIS_HASH;

  // ordered oldest-first, id-stable; created explicitly (Phase 30) rows are
  // already chained — the where clause excludes them.
  const legacy = await db.auditLog.findMany({
    where: { hash: null },
    orderBy: [{ createdAt: 'asc' }, { id: 'asc' }],
    select: {
      id: true,
      action: true,
      severity: true,
      entity: true,
      entityId: true,
      userId: true,
      ipAddress: true,
      userAgent: true,
      metadata: true,
      createdAt: true,
    },
  });

  for (const row of legacy) {
    seq += 1;
    const hash = computeAuditRowHash(prevHash, row);
    await withSqliteRetry(
      () =>
        db.auditLog.update({
          where: { id: row.id },
          data: { seq, prevHash, hash },
        }),
      { attempts: 5, baseDelayMs: 80 },
    );
    prevHash = hash;
  }
  return { backfilled: legacy.length };
}

// ── checkpoints (cryptographic seals) ───────────────────────────────────

/**
 * Seal the current chain head. Refuses to seal a broken chain — the seal is
 * evidence, not decoration.
 */
export async function checkpointAuditChain(createdBy: string | null) {
  const verdict = await verifyAuditChain();
  if (!verdict.ok) {
    throw new Error(
      `refusing to seal a broken chain (seq=${verdict.firstBrokenSeq}): ${verdict.reason}`,
    );
  }
  if (verdict.headSeq === null || !verdict.headHash) {
    throw new Error('nothing to seal — the chain has no entries yet');
  }
  return db.auditCheckpoint.create({
    data: {
      seq: verdict.headSeq,
      hash: verdict.headHash,
      entriesCount: verdict.coverage.chained,
      algorithm: AUDIT_CHAIN_ALGORITHM,
      createdBy,
    },
  });
}

/** Verify the last checkpoint still pins an unbroken prefix of the chain. */
export async function verifyCheckpoints() {
  const checkpoints = await db.auditCheckpoint.findMany({ orderBy: [{ seq: 'asc' }] });
  const verdict = await verifyAuditChain();
  if (!verdict.ok) {
    return { ok: false, checked: checkpoints.length, reason: verdict.reason, firstBrokenSeq: verdict.firstBrokenSeq };
  }
  // every seal must sit ON the intact chain (seq + hash reachable)
  for (const cp of checkpoints) {
    const row = await db.auditLog.findFirst({ where: { seq: cp.seq }, select: { hash: true } });
    if (!row || row.hash !== cp.hash) {
      return {
        ok: false,
        checked: checkpoints.length,
        reason: `checkpoint seq=${cp.seq} no longer matches the chain head hash at that position — sealed history was rewritten`,
        firstBrokenSeq: cp.seq,
      };
    }
  }
  return { ok: true, checked: checkpoints.length, reason: null, firstBrokenSeq: null };
}

// ── status snapshot (Operations console) ────────────────────────────────

export interface ChainStatus {
  total: number;
  chained: number;
  unchained: number;
  headSeq: number | null;
  headHash: string | null;
  checkpoints: number;
  lastCheckpoint: { seq: number; hash: string; entriesCount: number; algorithm: string; createdAt: Date } | null;
  coveragePct: number;
}

export async function getAuditChainStatus(): Promise<ChainStatus> {
  const [total, chained, head, checkpoints, last] = await Promise.all([
    db.auditLog.count(),
    db.auditLog.count({ where: { hash: { not: null } } }),
    db.auditLog.findFirst({
      where: { hash: { not: null } },
      orderBy: [{ seq: 'desc' }],
      select: { seq: true, hash: true },
    }),
    db.auditCheckpoint.count(),
    db.auditCheckpoint.findFirst({ orderBy: [{ seq: 'desc' }] }),
  ]);
  return {
    total,
    chained,
    unchained: total - chained,
    headSeq: head?.seq ?? null,
    headHash: head?.hash ?? null,
    checkpoints,
    lastCheckpoint: last
      ? {
          seq: last.seq,
          hash: last.hash,
          entriesCount: last.entriesCount,
          algorithm: last.algorithm,
          createdAt: last.createdAt,
        }
      : null,
    coveragePct: total === 0 ? 100 : Math.round((chained / total) * 10000) / 100,
  };
}
