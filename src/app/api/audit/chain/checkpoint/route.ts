/**
 * Phase 30 — POST /api/audit/chain/checkpoint — seal the audit chain (ADMIN only).
 *
 * Pins the current chain head (seq + hash + entries count) as an immutable
 * AuditCheckpoint evidence row. Refuses (409 SEAL_REFUSED) when verification
 * fails or the chain is empty — a seal is evidence, not decoration.
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
import { checkpointAuditChain } from '@/core/audit/audit-chain.service';

export async function POST(req: NextRequest) {
  try {
    const ctx = await requireAuth(req);
    if (!ctx.permissions.includes('audit.view.all')) {
      return jsonError(403, 'FORBIDDEN');
    }
    const rl = rateLimit(`audit-chain-seal:${getClientIp(req)}`, RATE_LIMITS.mutation.limit, RATE_LIMITS.mutation.windowMs);
    if (!rl.ok) return jsonError(429, 'RATE_LIMITED');

    try {
      const cp = await checkpointAuditChain(ctx.user.id);
      return jsonOk({ checkpoint: cp }, 201);
    } catch (sealErr) {
      // Broken chain or empty chain — surface the honest reason.
      return jsonError(409, 'SEAL_REFUSED', {
        detail: sealErr instanceof Error ? sealErr.message : String(sealErr),
      });
    }
  } catch (err) {
    return toErrorResponse(err);
  }
}
