/**
 * Phase 30 — GET /api/audit/chain/verify — tamper-evidence verification (ADMIN only).
 *
 * Re-walks the audit hash chain and recomputes every SHA-256 from the stored
 * columns: any mutation of an audited field (by whatever means — direct DB
 * access, restore tampering, migration bug) breaks the chain at exactly the
 * mutated seq. Also cross-checks every checkpoint seal against the chain.
 *
 * Query: ?full=1 → additionally returns the per-checkpoint seal verdicts.
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
import { verifyAuditChain, verifyCheckpoints } from '@/core/audit/audit-chain.service';

export async function GET(req: NextRequest) {
  try {
    const ctx = await requireAuth(req);
    if (!ctx.permissions.includes('audit.view.all')) {
      return jsonError(403, 'FORBIDDEN');
    }
    const rl = rateLimit(`audit-chain-verify:${getClientIp(req)}`, RATE_LIMITS.read.limit, RATE_LIMITS.read.windowMs);
    if (!rl.ok) return jsonError(429, 'RATE_LIMITED');

    const url = new URL(req.url);
    const full = url.searchParams.get('full') === '1';

    const result = await verifyAuditChain();
    const seals = full ? await verifyCheckpoints() : null;

    return jsonOk({
      verify: result,
      ...(seals ? { seals } : {}),
      verdict: result.ok && (seals ? seals.ok : true) ? 'INTACT' : 'BROKEN',
    });
  } catch (err) {
    return toErrorResponse(err);
  }
}
