# Hesabyar — Delivery Log | گزارش تحویل فازها

29 delivery phases, one protocol: **implement (full detail) → deep test → identify & fix bugs → deliver report → propose next phase**.

> Suite naming: from Phase 25 onward the deep-test suite for Phase *N* is `tests/p{N+6}-*.mjs` (p31=Phase 25 … p35=Phase 29). Earlier suites predate that convention; the table lists the suite that carries each delivery's evidence.

| Phase | Delivery | Deep-test evidence |
| --- | --- | --- |
| 1 | Platform bootstrap: Next.js 16 app shell, auth foundation (JWT access + rotating refresh, bcrypt), design system | — |
| 2 | Accounting core hardening: accounts, journal entries, fiscal periods, decimal-string money contract | `tests/p2-accounting-hardening.mjs` |
| 3 | Inventory hardening: products, warehouses, moves, valuation | `tests/p3-inventory-hardening.mjs` |
| 4 | Sales/CRM pipelines end-to-end (quote→order→invoice→payment, purchases) | `tests/p4-e2e.mjs` |
| 5 | Treasury core: accounts, cheque lifecycle, transfers, reconciliation | `tests/p5-e2e.mjs` (+cleanup) |
| 6 | Planning core: budgets, goals, calendar | `tests/p6-e2e.mjs` |
| 7–8 | Webhooks platform (HMAC signing, deliveries, retries), test endpoint fixes | exercised by p14/p15 suites |
| 9 | Realtime (socket.io mini-service) + full UI golden path across all modules + registration/security flows | `tests/p9-e2e.mjs`, `tests/p9-realtime-ws.mjs`, `tests/p9-final-cleanup.mjs` |
| 10 | Bank feed import (CSV/MT940) + dedupe + ETag patch | `tests/p10-bankfeed-e2e.mjs` |
| 11 | AI what-if scenarios + baseline | `tests/p11-ai-whatif-e2e.mjs` |
| 12 | Polish pass (suite scripts, i18n) | `scripts/p12/run-suite.sh` |
| 13 | Compliance module (VAT/income/salary) + backup restore verification | `tests/p13-compliance-e2e.mjs` |
| 14 | Operations console (jobs, webhooks, diagnostics, golden patches) | `tests/p14-ops-e2e.mjs` |
| 15 | Advanced security: TOTP 2FA + recovery codes + MFA challenge + at-rest encryption envelopes | `tests/p15-security-e2e.mjs` |
| 16 | Module expansion (assets/payroll tabs groundwork), i18n parity tooling | `tests/p16-phase10-e2e.mjs` |
| 17 | Production readiness: standalone build, Docker, health probes | `tests/p17-prodreadiness-e2e.mjs` |
| 18 | Automation scheduler: jobs, runs, ops scheduler bootstrap | `tests/p18-automation-scheduler-e2e.mjs` |
| 19 | DR/BCP: SHA-256 manifest sidecar, verify + non-destructive drills | `tests/p19-dr-bcp-e2e.mjs` |
| 20 | API platform: API keys, OpenAPI catalog, ext/v1 | `tests/p20-api-platform-e2e.mjs` |
| 21 | BI + report builder + exports | `tests/p21-bi-export-e2e.mjs` |
| 22 | Fixed assets + payroll | `tests/p22-assets-payroll-e2e.mjs` |
| 23 | HR + insurance + bank file | `tests/p23-hr-insurance-e2e.mjs` |
| 24 | Cost centers + tagging + P&L | `tests/p24-costcenters-e2e.mjs` |
| 25 | Cash-flow engine (+v3 variance verification pass) — `2.25.0-phase25-v3` | `tests/p25-cashflow-e2e.mjs` |
| 26 | Enterprise hardening sweep: soft-deleted account code release (partial unique index), notification bell `limit` alias, 7-suite regression — `2.26.0-phase26-v3` | `tests/p32-harden-e2e.mjs` |
| 27 | Data lifecycle & retention governance (policies, sweeps, archive batches) — `2.27.0-phase27-v3` | `tests/p33-lifecycle-e2e.mjs` |
| 28 | Governed bulk import (dry-run→commit digests, per-row isolation, once-only commits) — `2.28.0-phase28-v3` | `tests/p34-import-e2e.mjs` |
| 29 | Performance & scale sweep: FK index coverage (34 new indexes, zero audit gaps), route-latency telemetry (p50/p95/max + error counters in `/api/system/metrics`), Operations console latency table — `2.29.0-phase29-v3` | `tests/p35-performance-e2e.mjs` |

## Verified regression baseline (end of Phase 29)

Serial re-run, all green: p25=112, p26=71, p27=145, p28=89, p29=117, p30=115, p31=119, p32=41, p33=93, p34=97 → **999 checks**, plus p35=**58** → **1,057 total**, exit 0. Lint + typecheck clean.

## Next

- **Phase 30 — Tamper-Evident Audit Ledger** (SHA-256 hash chain over the append-only audit log, checkpoints, machine-verified integrity + tamper-detection proof), version target `2.30.0-phase30-v3`, suite `tests/p36-audit-chain-e2e.mjs`.
