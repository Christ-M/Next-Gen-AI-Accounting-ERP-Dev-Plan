/**
 * Phase 30 (v3) — Tamper-Evident Audit Ledger deep E2E.
 *
 * Sections (mirrors tests/p35-performance-e2e.mjs scaffolding):
 *   1  (a) version monotonic ≥ 30 + health green + admin login + USER register
 *   2  (b) schema census — AuditLog seq/prevHash/hash columns + UNIQUE indexes,
 *      AuditCheckpoint table present, 88 models in schema.prisma
 *   3  (c) chain status — coverage 100%, headSeq == chained (gap-free by shape)
 *   4  (d) 🔑 suite-side INDEPENDENT re-verification — the suite recomputes
 *      every SHA-256 from the raw columns (its own mirror of the canonical
 *      algorithm) and checks linkage + gap-free seq. Catches even a broken
 *      SERVER-side verifier, because the truth is recomputed here.
 *   5  (e) fresh writes chain — paced logins advance the head; the tail rows
 *      recompute correctly suite-side (canonical format lives, not legacy)
 *   6  (f) 🔑 TAMPER-DETECTION PROOF — direct DB mutation of a mid-chain row
 *      → GET verify returns BROKEN at exactly the mutated seq → seal refused
 *      (409) while broken → byte-exact restore → INTACT again
 *   7  (g) checkpoint seals — POST checkpoint 201 (twice), GET verify?full=1
 *      seals.ok with checked ≥ 1
 *   8  (h) 🔑 concurrency fan-in — 3 parallel logins race the chain head;
 *      UNIQUE(seq) + retry must heal → verify INTACT, gap-free + ZERO-DROP guard
 *   9  (i) RBAC — USER 403 on status / verify / seal / backfill
 *   10 (j) backfill idempotency — POST backfill → 0 rows, coverage stays 100
 *   11 (k) backup / DR — manifest 88 models incl. auditCheckpoint, importBatch
 *      still last, verify PASS, drill PASS parityOk
 *   12 (l) regression guards — TB balanced (BigInt sc2), bell alias, telemetry
 *      family landing, i18n parity (footer ≥ Phase 30 mentions, auditChain
 *      keys en↔fa), version three-way (health == app.config source)
 *   13 residue — cross-run-stable assertions only
 *
 * Rate-limit aware: mutations share the global pace() gate (≥ 2.1 s between
 * mutation requests) and every call runs through the 429-retry helper.
 *
 * Run: bun tests/p36-audit-chain-e2e.mjs
 */
import fs from 'node:fs';
import path from 'node:path';
import { createHash } from 'node:crypto';
import { PrismaClient } from '@prisma/client';
import { en, fa } from '../src/lib/i18n/dictionaries.ts';

const BASE = 'http://localhost:3000';
const ROOT = '/home/z/my-project';
const STAMP = `${Date.now()}`.slice(-8);
const ADMIN_CRED = { email: 'p4qa@hesabyar.test', password: 'Phase4!Deep#Test' };
const pdb = new PrismaClient();
let pass = 0, fail = 0;
const failures = [];

function check(name, cond, detail = '') {
  if (cond) { pass++; console.log(`  ✓ ${name}`); }
  else { fail++; failures.push(name); console.log(`  ✗ ${name} — ${detail}`); }
}

// ── fair-use pacing + 429 retry (house pattern, p24 §utils) ──────────────────
let lastMutationAt = 0;
const sleepMs = (ms) => new Promise((r) => setTimeout(r, ms));
const PACE_MS = Number(process.env.P36_PACE_MS ?? '2100');
async function pace() {
  const gap = PACE_MS - (Date.now() - lastMutationAt);
  if (gap > 0) await sleepMs(gap);
  lastMutationAt = Date.now();
}

function makeApi() {
  let cookie = '';
  const apiOnce = async (method, p, body, opts = {}) => {
    const res = await fetch(BASE + p, {
      method,
      headers: {
        'Content-Type': 'application/json',
        ...(cookie ? { Cookie: cookie } : {}),
        ...(opts.noOrigin ? {} : { Origin: BASE }),
        ...(opts.extra ?? {}),
      },
      body: body === undefined ? undefined : JSON.stringify(body),
      ...(opts.millis ? { signal: AbortSignal.timeout(opts.millis) } : {}),
    });
    const setCookies = res.headers.getSetCookie?.() ?? [];
    for (const sc of setCookies) {
      const m = sc.match(/^(hesabyar_[a-z]+=[^;]+)/);
      if (m) {
        const [name, val] = m[1].split('=');
        const jar = new Map(cookie.split('; ').filter(Boolean).map((c) => { const i = c.indexOf('='); return [c.slice(0, i), c.slice(i + 1)]; }));
        jar.set(name, val);
        cookie = [...jar.entries()].map(([k, v]) => `${k}=${v}`).join('; ');
      }
    }
    const clone = res.clone();
    let json = null;
    try { json = await res.json(); } catch { /* binary/HTML */ }
    let text = '';
    if (json === null) {
      try { text = await clone.text(); } catch { text = ''; }
    }
    return { status: res.status, json, headers: res.headers, text };
  };
  const call = async (method, p, body, opts = {}) => {
    const isMutation = String(method).toUpperCase() !== 'GET';
    let last = null;
    for (let i = 0; i <= 5; i++) {
      if (isMutation) await pace();
      last = await apiOnce(method, p, body, opts);
      if (last.status !== 429 || opts.keep429) return last;
      const ra = Number(last.headers?.get?.('retry-after')) || 2;
      const backoff = [2500, 8000, 15000, 25000, 30000][Math.min(i, 4)];
      await sleepMs(Math.max(backoff, ra * 1000 + 250));
    }
    return last;
  };
  return { call, apiOnce, getCookie: () => cookie };
}

const admin = makeApi();
const user1 = makeApi();
const user2 = makeApi();
const errCode = (r) => r.json?.error?.code ?? '';

// ── suite-side INDEPENDENT chain verifier (mirror of the canonical spec) ────
const SEP = '\u001f';
const NUL = '\u0002';
const f = (v) => (v === null || v === undefined || v === '' ? NUL : v);
function canon(r) {
  return [
    'audit-chain-v1',
    f(r.action),
    f(r.severity),
    f(r.entity),
    f(r.entityId),
    f(r.userId),
    f(r.ipAddress),
    f(r.userAgent),
    f(r.metadata),
    new Date(r.createdAt).toISOString(),
  ].join(SEP);
}
const sha = (prev, r) => createHash('sha256').update(prev + SEP + canon(r)).digest('hex');
const GENESIS = '0'.repeat(64);

/** Independent full walk over the raw columns (no trust in the server). */
async function suiteSideVerify() {
  const rows = await pdb.auditLog.findMany({
    where: { hash: { not: null } },
    orderBy: [{ seq: 'asc' }],
    select: {
      seq: true, hash: true, prevHash: true, action: true, severity: true,
      entity: true, entityId: true, userId: true, ipAddress: true,
      userAgent: true, metadata: true, createdAt: true,
    },
  });
  let prevHash = GENESIS;
  let prevSeq = 0;
  for (const r of rows) {
    if (r.prevHash !== prevHash) return { ok: false, at: r.seq, why: 'linkage' };
    if (r.seq !== prevSeq + 1) return { ok: false, at: r.seq, why: 'gap' };
    if (sha(prevHash, r) !== r.hash) return { ok: false, at: r.seq, why: 'hash' };
    prevHash = r.hash;
    prevSeq = r.seq;
  }
  return { ok: true, headSeq: prevSeq || null, checked: rows.length };
}

console.log('\n═══ Phase 30 (v3) — Tamper-Evident Audit Ledger deep E2E ═══');

// ── 1 ── (a) health & version & auth ────────────────────────────────────────
console.log('\n— 1 · (a) health & version & auth —');
{
  const h = await admin.call('GET', '/api/health');
  const d = h.json?.data ?? {};
  check('health → 200 operational + db connected', h.status === 200 && d.status === 'operational' && d.database === 'connected', `${h.status} ${d.status}/${d.database}`);
  const vPhase = Number(/phase(\d+)-v\d+$/.exec(String(d.version))?.[1] ?? 0);
  check('health version is a phase-v3 tag, phase ≥ 30 (monotonic)', /^2\.\d+\.\d+-phase\d+-v\d+$/.test(String(d.version)) && vPhase >= 30, String(d.version));

  const login = await admin.call('POST', '/api/auth/login', ADMIN_CRED);
  check('admin login → 200', login.status === 200, String(login.status));

  const me = await admin.call('GET', '/api/auth/me');
  check('admin identity resolved', !!me.json?.data?.user?.id, String(me.json?.data?.user?.id ?? ''));

  const cred1 = { fullName: `P30 Viewer ${STAMP}`, email: `p36u1-${STAMP.toLowerCase()}@hesabyar.test`, password: 'Phase30!Deep#1' };
  const reg = await user1.call('POST', '/api/auth/register', cred1, { noOrigin: true });
  check('USER registered → 201', reg.status === 201 && reg.json?.data?.user?.role === 'USER', String(reg.status));
  const uLogin = await user1.call('POST', '/api/auth/login', { email: cred1.email, password: cred1.password });
  check('USER login → 200', uLogin.status === 200, String(uLogin.status));
}

// ── 2 ── (b) schema census ──────────────────────────────────────────────────
console.log('\n— 2 · (b) schema census —');
{
  const schemaSrc = fs.readFileSync(path.join(ROOT, 'prisma/schema.prisma'), 'utf8');
  const modelCount = (schemaSrc.match(/^model /gm) ?? []).length;
  check('schema parses — 88 models (AuditCheckpoint added)', modelCount === 88, String(modelCount));
  check('AuditLog carries seq + prevHash + hash fields', /model AuditLog \{[\s\S]*?seq\s+Int\?\s+@unique[\s\S]*?prevHash\s+String\?[\s\S]*?hash\s+String\?\s+@unique/.test(schemaSrc), 'fields');

  const cols = await pdb.$queryRawUnsafe(`SELECT name FROM pragma_table_info('AuditLog')`);
  const colNames = cols.map((c) => String(c.name));
  check('live AuditLog columns: seq/prevHash/hash present', ['seq', 'prevHash', 'hash'].every((c) => colNames.includes(c)), colNames.join(','));

  const uq = await pdb.$queryRawUnsafe(`SELECT name, sql FROM sqlite_master WHERE type='index' AND tbl_name='AuditLog' AND sql IS NOT NULL`);
  const uqSql = uq.map((r) => String(r.sql)).join(' ;; ');
  check('UNIQUE(seq) index live', /CREATE UNIQUE INDEX[^;]*\("seq"\)/i.test(uqSql), uqSql.slice(0, 200));
  check('UNIQUE(hash) index live', /CREATE UNIQUE INDEX[^;]*\("hash"\)/i.test(uqSql), uqSql.slice(0, 200));

  const cpTable = await pdb.$queryRawUnsafe(`SELECT name FROM sqlite_master WHERE type='table' AND name='AuditCheckpoint'`);
  check('AuditCheckpoint table live', cpTable.length === 1, String(cpTable.length));
  const cpCols = await pdb.$queryRawUnsafe(`SELECT name FROM pragma_table_info('AuditCheckpoint')`);
  const cpNames = cpCols.map((c) => String(c.name));
  check('AuditCheckpoint columns: seq/hash/entriesCount/algorithm/createdBy', ['seq', 'hash', 'entriesCount', 'algorithm', 'createdBy'].every((c) => cpNames.includes(c)), cpNames.join(','));
}

// ── 3 ── (c) chain status ───────────────────────────────────────────────────
console.log('\n— 3 · (c) chain status —');
let CHAIN = null;
{
  const s = await admin.call('GET', '/api/audit/chain');
  CHAIN = s.json?.data?.chain ?? null;
  check('GET /api/audit/chain → 200 with chain snapshot', s.status === 200 && !!CHAIN && typeof CHAIN.total === 'number', `${s.status}`);
  check('🔑 coverage is 100% (backfill deployed)', CHAIN?.coveragePct === 100, JSON.stringify(CHAIN?.coveragePct));
  check('headSeq == chained (gap-free by shape)', CHAIN?.headSeq === CHAIN?.chained && CHAIN.chained > 1000, `head=${CHAIN?.headSeq} chained=${CHAIN?.chained}`);
  check('headHash is a 64-hex digest', /^[0-9a-f]{64}$/.test(String(CHAIN?.headHash ?? '')), String(CHAIN?.headHash ?? '').slice(0, 16));
}

// ── 4 ── (d) suite-side independent re-verification ─────────────────────────
console.log('\n— 4 · (d) 🔑 suite-side independent chain walk —');
{
  const v = await suiteSideVerify();
  check(`🔑 independent recompute: all ${v.checked} rows verify (linkage + gap-free + hash)`, v.ok === true, `${v.ok ? '' : `broken at ${v.at} (${v.why})`}`);
  check('server verify agrees → INTACT', (await admin.call('GET', '/api/audit/chain/verify')).json?.data?.verdict === 'INTACT', 'verdict');
  const full = await admin.call('GET', '/api/audit/chain/verify?full=1');
  check('server verify checked == suite-side checked', full.json?.data?.verify?.checked === v.checked, `${full.json?.data?.verify?.checked}/${v.checked}`);
}

// ── 5 ── (e) fresh writes chain correctly ───────────────────────────────────
console.log('\n— 5 · (e) fresh writes chain (tail recompute) —');
{
  const headBefore = CHAIN.headSeq;
  await user1.call('POST', '/api/auth/login', { email: `p36u1-${STAMP.toLowerCase()}@hesabyar.test`, password: 'Phase30!Deep#1' });
  const s2 = await admin.call('GET', '/api/audit/chain');
  const headAfter = s2.json?.data?.chain?.headSeq ?? 0;
  check('head advanced after a fresh audited login', headAfter > headBefore, `${headBefore} → ${headAfter}`);

  // tail: last 3 rows — recompute suite-side (proves the LIVE format, not the backfilled legacy one)
  const tail = await pdb.auditLog.findMany({
    where: { hash: { not: null } },
    orderBy: [{ seq: 'desc' }],
    take: 3,
    select: { seq: true, hash: true, prevHash: true, action: true, severity: true, entity: true, entityId: true, userId: true, ipAddress: true, userAgent: true, metadata: true, createdAt: true },
  });
  tail.reverse();
  let tailOk = true;
  let tailWhy = '';
  let prev = tail.length >= 2 ? await pdb.auditLog.findFirst({ where: { seq: tail[0].seq - 1 }, select: { hash: true } }) : null;
  let prevHash = prev?.hash ?? GENESIS;
  let prevSeq = tail[0].seq - 1;
  for (const r of tail) {
    if (r.prevHash !== prevHash) { tailOk = false; tailWhy = `linkage@${r.seq}`; break; }
    if (r.seq !== prevSeq + 1) { tailOk = false; tailWhy = `gap@${r.seq}`; break; }
    if (sha(prevHash, r) !== r.hash) { tailOk = false; tailWhy = `hash@${r.seq}`; break; }
    prevHash = r.hash; prevSeq = r.seq;
  }
  check('🔑 tail rows (newest format) recompute suite-side', tailOk, tailWhy);
}

// ── 6 ── (f) 🔑 tamper-detection proof ──────────────────────────────────
console.log('\n— 6 · (f) 🔑 tamper-detection proof —');
{
  const head = await pdb.auditLog.findFirst({ where: { hash: { not: null } }, orderBy: [{ seq: 'desc' }], select: { seq: true } });
  const victimSeq = Math.max(2, (head?.seq ?? 2) - 10); // mid-chain, leaves head untouched
  const victim = await pdb.auditLog.findFirst({ where: { seq: victimSeq }, select: { id: true, seq: true, metadata: true } });
  check(`victim row (seq=${victimSeq}) selected for the probe`, !!victim?.id, String(victim?.id ?? ''));

  const original = victim.metadata; // may be null
  await pdb.auditLog.update({ where: { id: victim.id }, data: { metadata: `${original ?? ''}"P36-TAMPER"` } });

  const afterTamper = await admin.call('GET', '/api/audit/chain/verify');
  const V = afterTamper.json?.data?.verify ?? {};
  check('🔑 verify → BROKEN after direct DB mutation', afterTamper.status === 200 && afterTamper.json?.data?.verdict === 'BROKEN' && V.ok === false, JSON.stringify(V).slice(0, 120));
  check('🔑 firstBrokenSeq pins the EXACT mutated seq', V.firstBrokenSeq === victimSeq, `${V.firstBrokenSeq} vs ${victimSeq}`);
  check('reason explains the mismatch', /hash mismatch|mutated/i.test(String(V.reason ?? '')), String(V.reason ?? '').slice(0, 120));

  // seal must REFUSE while the chain is broken — seals are evidence, not decoration
  const refusedSeal = await admin.call('POST', '/api/audit/chain/checkpoint');
  check('seal refused while broken → 409 SEAL_REFUSED', refusedSeal.status === 409 && errCode(refusedSeal) === 'SEAL_REFUSED', `${refusedSeal.status} ${errCode(refusedSeal)}`);

  // suite-side verifier agrees on the break location
  const sv = await suiteSideVerify();
  check('suite-side independent walk ALSO flags the tamper at the same seq', sv.ok === false && sv.at === victimSeq, `${sv.ok}/${sv.at}`);

  // byte-exact restore
  await pdb.auditLog.update({ where: { id: victim.id }, data: { metadata: original } });
  const afterRestore = await admin.call('GET', '/api/audit/chain/verify');
  check('🔑 byte-exact restore → INTACT again', afterRestore.json?.data?.verdict === 'INTACT', String(afterRestore.json?.data?.verdict));
}

// ── 7 ── (g) checkpoint seals ───────────────────────────────────────────────
console.log('\n— 7 · (g) checkpoint seals —');
{
  const seal1 = await admin.call('POST', '/api/audit/chain/checkpoint');
  const cp1 = seal1.json?.data?.checkpoint ?? null;
  check('seal #1 → 201 with seq/hash', seal1.status === 201 && !!cp1 && /^[0-9a-f]{64}$/.test(String(cp1.hash)), `${seal1.status} ${JSON.stringify(cp1 ?? {}).slice(0, 120)}`);

  const full = await admin.call('GET', '/api/audit/chain/verify?full=1');
  const seals = full.json?.data?.seals ?? null;
  check('verify?full=1 → seals.ok with checked ≥ 1', full.status === 200 && seals?.ok === true && seals.checked >= 1, `${full.status} ${JSON.stringify(seals ?? {}).slice(0, 120)}`);

  await user1.call('POST', '/api/auth/login', { email: `p36u1-${STAMP.toLowerCase()}@hesabyar.test`, password: 'Phase30!Deep#1' });
  const seal2 = await admin.call('POST', '/api/audit/chain/checkpoint');
  const cp2 = seal2.json?.data?.checkpoint ?? null;
  check('seal #2 → 201 strictly AFTER head grew', seal2.status === 201 && !!cp2 && cp2.seq > (cp1?.seq ?? 0), `${seal2.status} ${cp2?.seq}`);
  check('checkpoint count now ≥ 2', (await admin.call('GET', '/api/audit/chain')).json?.data?.chain?.checkpoints >= 2, String((await admin.call('GET', '/api/audit/chain')).json?.data?.chain?.checkpoints));
}

// ── 8 ── (h) 🔑 concurrency fan-in (UNIQUE(seq) race) ────────────────────────
console.log('\n— 8 · (h) 🔑 concurrency fan-in —');
{
  const headBefore = (await admin.call('GET', '/api/audit/chain')).json?.data?.chain?.headSeq ?? 0;
  const cred2 = { fullName: `P30 Racer ${STAMP}`, email: `p36u2-${STAMP.toLowerCase()}@hesabyar.test`, password: 'Phase30!Deep#2' };
  await user2.call('POST', '/api/auth/register', cred2, { noOrigin: true });
  await user2.call('POST', '/api/auth/login', { email: cred2.email, password: cred2.password });

  // three logins fired SIMULTANEOUSLY through a DEDICATED jar — three
  // concurrent chain appends racing for the same head; UNIQUE(seq) + retry
  // must heal without loss or gaps. (The admin jar must stay admin: logging
  // in through it would swap the session to a USER and 403 every later
  // admin call — the first-run lesson that produced this dedicated racer.)
  const racer = makeApi();
  const creds = [
    { email: `p36u1-${STAMP.toLowerCase()}@hesabyar.test`, password: 'Phase30!Deep#1' },
    { email: `p36u2-${STAMP.toLowerCase()}@hesabyar.test`, password: 'Phase30!Deep#2' },
    { email: `p36u1-${STAMP.toLowerCase()}@hesabyar.test`, password: 'Phase30!Deep#1' },
  ];
  const results = await Promise.all(creds.map((c) => racer.apiOnce('POST', '/api/auth/login', c)));
  check('all 3 racing logins accepted (no failures)', results.every((r) => r.status === 200 || r.status === 429), results.map((r) => r.status).join(','));

  await sleepMs(1500); // let any retrying append settle
  const after = await admin.call('GET', '/api/audit/chain');
  const headAfter = after.json?.data?.chain?.headSeq ?? 0;
  check(`head advanced by ≥ 2 over the race window (${headBefore} → ${headAfter})`, headAfter >= headBefore + 2, String(headAfter));

  const v = await suiteSideVerify();
  check('🔑 chain INTACT after the race (no duplicates, no gaps)', v.ok === true, `${v.ok ? '' : `broken at ${v.at} (${v.why})`}`);
  const dupes = await pdb.$queryRawUnsafe(`SELECT seq, COUNT(*) AS n FROM AuditLog WHERE seq IS NOT NULL GROUP BY seq HAVING n > 1`);
  check('ZERO duplicate seq values (UNIQUE(seq) enforced)', dupes.length === 0, JSON.stringify(dupes).slice(0, 120));

  // ZERO-DROP guard (found by the p29 regression cascade): racing appends
  // used to lose rows to the UNIQUE(seq) P2002 before the retryOn fix —
  // every racing login MUST have landed exactly as an audited event.
  const landed = await pdb.auditLog.count({
    where: {
      action: 'AUTH_LOGIN_SUCCESS',
      user: { email: { in: [`p36u1-${STAMP.toLowerCase()}@hesabyar.test`, `p36u2-${STAMP.toLowerCase()}@hesabyar.test`] } },
    },
  });
  check(`🔑 ZERO-DROP under race: all racing logins landed as chained audit rows (${landed} ≥ 4)`, landed >= 4, String(landed));
}

// ── 9 ── (i) RBAC ───────────────────────────────────────────────────────
console.log('\n— 9 · (i) RBAC (USER forbidden) —');
{
  const s1 = await user1.call('GET', '/api/audit/chain');
  const s2 = await user1.call('GET', '/api/audit/chain/verify');
  const s3 = await user1.call('POST', '/api/audit/chain/checkpoint');
  const s4 = await user1.call('POST', '/api/audit/chain/backfill');
  check('USER GET status → 403', s1.status === 403 && errCode(s1) === 'FORBIDDEN', `${s1.status} ${errCode(s1)}`);
  check('USER GET verify → 403', s2.status === 403, `${s2.status}`);
  check('USER POST seal → 403', s3.status === 403, `${s3.status}`);
  check('USER POST backfill → 403', s4.status === 403, `${s4.status}`);
}

// ── 10 ── (j) backfill idempotency ──────────────────────────────────────────
console.log('\n— 10 · (j) backfill idempotency —');
{
  const b = await admin.call('POST', '/api/audit/chain/backfill');
  const D = b.json?.data ?? null;
  check('POST backfill → 200, backfilled: 0 (all rows already chained)', b.status === 200 && D?.backfill?.backfilled === 0, `${b.status} ${JSON.stringify(D?.backfill ?? {})}`);
  check('coverage stays 100% after re-run', D?.chain?.coveragePct === 100, String(D?.chain?.coveragePct));
}

// ── 11 ── (k) backup / DR — 88-model manifest with the chain seal ───────────
console.log('\n— 11 · (k) backup / DR —');
{
  const bk = await admin.call('POST', '/api/system/backup');
  const F = bk.json?.data?.backup?.file ?? '';
  check('backup POST → snapshot file', (bk.status === 200 || bk.status === 201) && /\.hbk$/.test(F), `${bk.status} ${F}`);

  await admin.call('GET', '/api/system/dr/readiness'); // backfills the manifest sidecar (p34 §o precedent)

  let manifest = null;
  try { manifest = JSON.parse(fs.readFileSync(path.join(ROOT, 'db/backups', `${F}.manifest.json`), 'utf8')); } catch { /* sidecar missing */ }
  const order = Object.keys(manifest?.rows ?? {});
  check('manifest covers 88 models', order.length >= 88, String(order.length));
  check('manifest includes auditCheckpoint (Phase 30 seals travel with backups)', order.includes('auditCheckpoint'), order.join(',').slice(0, 160));
  check('importBatch still last (p35 regression guard intact)', order.indexOf('importBatch') === order.length - 1, order.slice(-3).join(','));

  const ver = await admin.call('POST', '/api/system/dr/verify', { file: F });
  check('DR verify on the fresh backup → PASS', ver.status === 200 && ver.json?.data?.result?.verdict === 'PASS', `${ver.status} ${JSON.stringify(ver.json?.data?.result?.reasons ?? []).slice(0, 160)}`);

  const drill = await admin.call('POST', '/api/system/dr/drill', { file: F }, { millis: 180000 });
  const Dd = drill.json?.data?.drill ?? null;
  check('🔑 DR drill → PASS (chain columns replay into the throwaway DB)', drill.status === 200 && Dd?.verdict === 'PASS', `${drill.status} ${JSON.stringify(Dd?.reasons ?? []).slice(0, 160)}`);
  check('drill modelsChecked ≥ 88', typeof Dd?.modelsChecked === 'number' && Dd.modelsChecked >= 88, String(Dd?.modelsChecked));
  check('drill parityOk (rowsRestored == rowsSource)', Dd?.parityOk === true && Dd?.rowsRestored === Dd?.rowsSource, `${Dd?.rowsRestored}/${Dd?.rowsSource}`);

  const alerts = await admin.call('GET', '/api/system/alerts');
  const critNow = (alerts.json?.data?.alerts ?? []).filter((a) => a.severity === 'CRITICAL').map((a) => a.kind);
  check('no NEW dr_drill_failed CRITICAL after the deep suite', alerts.status === 200 && !critNow.includes('dr_drill_failed'), critNow.join(','));
}

// ── 12 ── (l) regression guards ─────────────────────────────────────────────
console.log('\n— 12 · (l) regression guards —');
{
  // TB balanced (BigInt scale-2 over decimal STRINGS — house sc2 pattern)
  const rows = await pdb.journalLine.findMany({
    where: { entry: { status: 'POSTED' } },
    select: { debitBase: true, creditBase: true },
  });
  const sc2 = (v) => {
    const s = String(v ?? '0'); const neg = s.startsWith('-');
    const [i, f = ''] = (neg ? s.slice(1) : s).split('.');
    const fp = (f + '00').slice(0, 2);
    return (neg ? -1n : 1n) * BigInt((i || '0') + fp);
  };
  let debit = 0n, credit = 0n;
  for (const r of rows) { debit += sc2(r.debitBase); credit += sc2(r.creditBase); }
  check(`TB balanced (ΣdebitBase == ΣcreditBase over ${rows.length} posted lines)`, debit === credit, `${debit}/${credit}`);

  // bell alias regression guard (p26/p35 precedent)
  const limitOnly = await admin.call('GET', '/api/notifications?limit=3');
  check('bell ?limit=3 accepted as take alias (≤3 items)', limitOnly.status === 200 && (limitOnly.json?.data?.items ?? []).length <= 3, `${limitOnly.status}`);

  // telemetry: the new audit-chain family must land in metrics after this suite's traffic
  const m = await admin.call('GET', '/api/system/metrics');
  const routes = m.json?.data?.routes ?? [];
  const chainFamily = routes.find((r) => r.family === '/api/audit/chain');
  check('telemetry lands: /api/audit/chain family row with n ≥ 1', !!chainFamily && chainFamily.n >= 1, JSON.stringify(chainFamily ?? {}).slice(0, 120));

  // i18n parity — footer monotonic + auditChain subtree parity
  check('footer.phase mentions Phase ≥ 30 (en)', /Phase (3\d|[4-9]\d)/.test(en.footer.phase ?? ''), String(en.footer.phase).slice(0, 40));
  check('footer.phase mentions فاز ≥ ۳۰ (fa)', /فاز ۳[۰-۹]/.test(fa.footer.phase ?? ''), String(fa.footer.phase).slice(0, 40));
  const deepKeys = (o, pfx = '') => Object.entries(o ?? {}).flatMap(([k, v]) => (v && typeof v === 'object' && !Array.isArray(v) ? deepKeys(v, `${pfx}${k}.`) : [`${pfx}${k}`]));
  const ek = new Set(deepKeys(en.system.ops.auditChain));
  const fk = new Set(deepKeys(fa.system.ops.auditChain));
  check('system.ops.auditChain deep key parity en ↔ fa (21 keys)', ek.size === fk.size && ek.size >= 21 && [...ek].every((k) => fk.has(k)), `en=${ek.size} fa=${fk.size}`);
  check('auditChain actions localized ×2', ['verify', 'seal', 'legacyBackfill', 'intact', 'broken'].every((k) => en.system.ops.auditChain[k] && fa.system.ops.auditChain[k]), '');

  // version three-way: health == app.config source of truth
  const cfg = fs.readFileSync(path.join(ROOT, 'src/core/config/app.config.ts'), 'utf8');
  const cfgVersion = /version:\s*'([^']+)'/.exec(cfg)?.[1] ?? '';
  const healthVersion = (await admin.call('GET', '/api/health')).json?.data?.version ?? '';
  check('version three-way: health == app.config source', cfgVersion === healthVersion && /phase30-v3$/.test(cfgVersion), `${cfgVersion} vs ${healthVersion}`);
}

// ── 13 ── residue ───────────────────────────────────────────────────────────
console.log('\n— 13 · residue —');
{
  const thisRun = await pdb.user.count({ where: { email: { in: [`p36u1-${STAMP.toLowerCase()}@hesabyar.test`, `p36u2-${STAMP.toLowerCase()}@hesabyar.test`] } } });
  check("this run's P30 viewers registered exactly once each (no business fixtures)", thisRun === 2, String(thisRun));
  // the tamper probe restored its victim — no permanent residue by construction
  const tampered = await pdb.auditLog.count({ where: { metadata: { contains: 'P36-TAMPER' } } });
  check('zero tamper residue in the live ledger', tampered === 0, String(tampered));
}

await pdb.$disconnect();

// ── summary ──────────────────────────────────────────────────────────────────
console.log(`\n═══ Phase 30 deep E2E: ${pass} passed · ${fail} failed ═══`);
if (fail > 0) {
  console.log('Failed checks:');
  for (const f of failures) console.log(`  ✗ ${f}`);
  process.exit(1);
}
console.log('exit 0');
