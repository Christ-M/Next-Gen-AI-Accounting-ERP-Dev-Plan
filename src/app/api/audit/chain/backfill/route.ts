/**
 * Phase 30 — POST /api/audit/chain/backfill — chain legacy audit rows (ADMIN only).
 *
 * One-time (idempotent) backfill that links pre-Phase-30 entries (hash IS
 * NULL) into the SHA-256 chain in their chronological order, continuing the
 * existing seq sequence. After success, coverage hits 100%.
 */
import { NextRequest } from 'next/server';
import {
  getClientIp,
  jsonError,
  jsonOk,
  rateLimit,
  RATE_LIMITS,
  requireAuth,
  toErrorResponse,
} from '../../../auth/helpers';
import { backfillAuditChain, getAuditChainStatus } from '@/core/audit/audit-chain.service';

export async function POST(req: NextRequest) {
  try {
    const ctx = await requireAuth(req);
    if (!ctx.permissions.includes('audit.view.all')) {
      return jsonError(403, 'FORBIDDEN');
    }
    const rl = rateLimit(`audit-chain-backfill:${getClientIp(req)}`, RATE_LIMITS.mutation.limit, RATE_LIMITS.mutation.windowMs);
    if (!rl.ok) return jsonError(429, 'RATE_LIMITED');

    const backfill = await backfillAuditChain();
    const chain = await getAuditChainStatus();
    return jsonOk({ backfill, chain }, 200);
  } catch (err) {
    return toErrorResponse(err);
  }
}
