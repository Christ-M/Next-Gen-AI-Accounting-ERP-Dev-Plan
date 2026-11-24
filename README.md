# Hesabyar · حسابیار

**Advanced Accounting & ERP Platform — پلتفرم پیشرفته حسابداری و برنامه‌ریزی منابع سازمانی**

> **Version `2.29.0-phase29-v3`** · 87 Prisma models · 256 API routes · 34 deep-test suites · bilingual fa/en RTL UI

---

## Overview | نمای کلی

Hesabyar is a production-grade ERP platform delivered in 29 disciplined engineering phases. Every phase follows the same protocol: **full-detail implementation → deep automated testing → bug identification → immediate fix → delivery report**.

| Domain | Delivered capabilities |
| --- | --- |
| Accounting | Chart of accounts, journal entries, fiscal periods, multi-currency + revaluation, income statement / balance sheet / ledger / trial balance |
| Inventory | Products, UoM, warehouses, batches & serial units, stock counts, expiry, forecasting, traceability, FIFO/WAV valuation layers |
| Sales & Purchasing | Quote → Order → Invoice → Payment pipelines, POS, parties CRM, purchase receipts → bills → payments |
| Treasury | Accounts, cheque lifecycle, transfers, bank-feed import (CSV/MT940) + assisted reconciliation & matching engine |
| Planning | Budgets with revisions + guard (WARN/BLOCK), variance analytics, goals, calendar, AI insights |
| Payroll & HR | Contracts, work-logs, payroll runs (approve/pay), leaves, accruals, insurance list, bank file |
| Fixed Assets | Register, categories, depreciation schedules & runs, disposals, cardex |
| Manufacturing | BOMs, material availability, production orders (release/complete/cancel) with transformation vouchers |
| Tax & Compliance | VAT declarations & returns, withholding, income/salary tax, compliance overview |
| Closing | Period closing preview/execute/unlock with mirrored voucher evidence |
| Cost Centers | Pools, allocation approval, P&L, voucher tagging, cardex |
| Approvals | Configurable rules, request inbox, history, hard-freeze enforcement on gated entities |
| Documents | Governed attachments (upload/download/dedupe), voucher chips, deep links |
| Governance | Audit trail, notifications + webhooks (HMAC-signed, retries), lifecycle retention sweeps, archive batches |
| Import | Governed bulk import: dry-run validation → commit with digests, per-row isolation, once-only commits |
| BI & Reports | 21+ datasets, report builder (saved + run), cash-flow, KPIs, sales analytics, inventory valuation/aging, exports |
| Operations | Backup + schedule + restore, DR manifest (SHA-256 sidecar) + verify + non-destructive drills, jobs/scheduler, system metrics (route latency p50/p95/max), diagnostics, API keys, OpenAPI |
| AI | Ask, categorize, forecast, anomalies, what-if scenarios |

## Architecture | معماری

- **Frontend:** Next.js 16 (App Router) · React 19 · Tailwind CSS 4 · shadcn/ui (New York) · recharts · Framer Motion · next-themes dark/light · fa/en + RTL
- **Backend:** Next.js route handlers (256 endpoints) · TypeScript 5 strict · Zod contracts on every write · decimal.js canonical decimal **strings** (never binary floats)
- **Data:** Prisma + SQLite (87 models; every scalar FK column index-covered — SQLite does not auto-index FKs) · append-only audit trail · HSF1 encryption envelopes for secrets at rest
- **Realtime:** socket.io mini-service (`mini-services/realtime-service`, internal :3030) behind the gateway; the web app pushes events through a control plane (:3031)
- **Security:** JWT access (30 min) + rotating refresh tokens, TOTP 2FA + one-time recovery codes, per-route sliding-window rate limits (30/min mutations), OWASP headers (CSP, X-Frame-Options DENY, nosniff, Referrer-Policy, Permissions-Policy, COOP)
- **Reliability:** bounded SQLite contention retry, fair-rate 429 budgeting with retry-after headers, global mutation pacing

```
src/
  app/api/…            256 route handlers (accounting, sales, treasury, …, system, ext/v1)
  components/
    ui/                shadcn/ui primitives (New York)
    views/             feature consoles (accounting, treasury, hr, reports, system, …)
    layout/            app shell, sidebar, topbar, status footer
  core/                domain services per bounded context + security/ + money/ + config/
  lib/                 db client, i18n, stores (zustand), realtime client, write queue
prisma/                schema.prisma (87 models) + domain seeds
scripts/               ops tooling, per-phase repair/verify scripts
tests/                 34 deep-test suites (bun *.mjs) + UI verification screenshots
mini-services/         realtime socket.io service
docs/                  delivery log, test inventory, repo manifest
```

## Quality engineering | مهندسی کیفیت

- **34 deep-test suites** (`tests/p*-e2e.mjs`, ~17k LOC total) exercising the real HTTP surface with login sessions, rate-limit-aware pacing and 429-retry helpers. Serial regression of the ten most recent suites = **1,057 checks green** at Phase 29.
- **Machine-verified invariants:** trial balance always balanced (BigInt scale-2 sums), FK index coverage (zero gaps), DR manifest parity + non-destructive drill replay, i18n fa/en key parity, cross-run residue stability, EXPLAIN QUERY PLAN proofs on hot paths.
- **Tamper evidence roadmap:** append-only audit log (Phase 30 adds a SHA-256 hash chain + checkpoints).
- **Per-phase UI verification:** RTL fa / en / 390px mobile screenshots for every delivered feature.

## Deployment | استقرار

Multi-stage Bun + Next.js standalone image; compose stack runs `web` (:3000) + `realtime` (internal). SQLite database and auto-backups live on a bind-mounted `db/` volume. Health probe: `GET /api/health`. See `DEPLOY.md` for the full production runbook (secrets, reverse proxy, backup policy).

```bash
cp .env.production.example .env.production   # set JWT/REALTIME secrets
docker compose up -d --build
```

## Version contract | قرارداد نسخه

`APP.version` in `src/core/config/app.config.ts` is the single source of truth; it is surfaced verbatim by `GET /api/health` and the app status footer. The chain so far: `… → 2.25.0-phase25-v3 → 2.26.0 → 2.27.0 → 2.28.0 → 2.29.0-phase29-v3` (current).

## Repository mirror scope (important)

This GitHub repository is maintained through the GitHub **API** (the sandbox has no git-push credential). Scope of what is mirrored:

- Mirrored: all configuration/deploy files, `prisma/schema.prisma`, domain/config source files, docs (this README, delivery log, test inventory, full repo manifest).
- Local-only (documented in `docs/REPO-MANIFEST-*.txt`, which lists **all 917 tracked paths**): the complete `src/**` tree beyond the mirrored core files (mirroring progresses phase by phase), binary evidence PNGs under `tests/`, the SQLite database `db/custom.db`, and `.env` (never mirrored — secrets).

Each delivery phase pushes its new/changed text files here as a separate commit.
