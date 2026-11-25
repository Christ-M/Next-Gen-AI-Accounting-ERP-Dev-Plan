/**
 * Phase 30 — GET /api/audit/chain — audit hash-chain status (ADMIN only).
 * Live snapshot for the Operations console: head, coverage, checkpoints.
 * Read-only — verification runs on the dedicated /verify endpoint.
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
} from '../../auth/helpers';
import { getAuditChainStatus } from '@/core/audit/audit-chain.service';

export async function GET(req: NextRequest) {
  try {
    const ctx = await requireAuth(req);
    if (!ctx.permissions.includes('audit.view.all')) {
      return jsonError(403, 'FORBIDDEN');
    }
    const rl = rateLimit(`audit-chain:${getClientIp(req)}`, RATE_LIMITS.read.limit, RATE_LIMITS.read.windowMs);
    if (!rl.ok) return jsonError(429, 'RATE_LIMITED');

    const status = await getAuditChainStatus();
    return jsonOk({ chain: status });
  } catch (err) {
    return toErrorResponse(err);
  }
}
