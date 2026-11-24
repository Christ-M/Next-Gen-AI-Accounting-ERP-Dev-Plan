/**
 * GET /api/health — liveness probe + runtime telemetry (public).
 */
import { NextResponse } from 'next/server';
import { db } from '@/lib/db';
import { APP } from '@/core/config/app.config';
import { bootstrapOpsScheduler } from '@/lib/ops-scheduler';

export async function GET() {
  bootstrapOpsScheduler(); // idempotent — drives webhook retries + auto-backup
  const startedAt = Date.now();
  let dbOk = true;
  try {
    await db.$queryRaw`SELECT 1`;
  } catch {
    dbOk = false;
  }
  return NextResponse.json({
    ok: true,
    data: {
      status: dbOk ? 'operational' : 'degraded',
      database: dbOk ? 'connected' : 'unreachable',
      version: APP.version,
      uptimeSec: Math.floor(process.uptime()),
      latencyMs: Date.now() - startedAt,
      time: new Date().toISOString(),
    },
  });
}
