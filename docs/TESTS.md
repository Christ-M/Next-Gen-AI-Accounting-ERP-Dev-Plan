# Hesabyar — Deep-Test Suite Inventory | فهرست مجموعه‌های تست عمیق

All suites run against the live dev server (`bun tests/p<id>-<name>.mjs`, dev on :3000) and use shared discipline: authenticated sessions, per-route fair-rate budgets with 429-aware retry (retries do not burn the budget), global mutation pacing (~2.1s), empty-code selectors to minimize blind probing, watermark assertions for window-independent fan-out checks, and cross-run residue self-healing.

## Verified pass counts (Phase 29 serial regression, exit 0)

| Suite | Scope | Checks |
| --- | --- | --- |
| `p25-cashflow-e2e.mjs` | Cash-flow engine + mappings | 112 |
| `p26-tax-e2e.mjs` | VAT declarations/returns, withholding | 71 |
| `p27-closing-e2e.mjs` | Period closing preview/execute/unlock | 145 |
| `p28-attachments-e2e.mjs` | Governed attachments + voucher chips | 89 |
| `p29-approvals-e2e.mjs` | Approval rules/requests/hard-freeze | 117 |
| `p30-manufacturing-e2e.mjs` | BOMs + production orders | 115 |
| `p31-budget-variance-e2e.mjs` | Budget guard WARN/BLOCK + variance analytics | 119 |
| `p32-harden-e2e.mjs` | Soft-delete code release + bell alias | 41 |
| `p33-lifecycle-e2e.mjs` | Retention policies + sweeps | 93 |
| `p34-import-e2e.mjs` | Governed bulk import dry-run→commit | 97 |
| `p35-performance-e2e.mjs` | FK coverage audit + EXPLAIN QUERY PLAN + latency telemetry | 58 |
| **Total** | | **1,057** |

## Older suites (all green at their delivery; still part of the full regression pool)

| Suite | Scope |
| --- | --- |
| `p2-accounting-hardening.mjs` | Accounting core invariants |
| `p3-inventory-hardening.mjs` | Inventory invariants |
| `p4-e2e.mjs` | Sales pipelines |
| `p5-e2e.mjs` / `p5-cleanup.mjs` | Treasury core + residue cleanup |
| `p6-e2e.mjs` | Planning core |
| `p9-e2e.mjs` / `p9-realtime-ws.mjs` / `p9-final-cleanup.mjs` | Registration/auth flows, websocket realtime, golden path + cleanup |
| `p10-bankfeed-e2e.mjs` | Bank feed import (CSV/MT940) |
| `p11-ai-whatif-e2e.mjs` | AI what-if scenarios |
| `p13-compliance-e2e.mjs` | Compliance module + restore verification |
| `p14-ops-e2e.mjs` | Operations console |
| `p15-security-e2e.mjs` | TOTP 2FA, recovery codes, MFA challenge, encryption envelopes |
| `p16-phase10-e2e.mjs` | Module expansion groundwork |
| `p17-prodreadiness-e2e.mjs` | Standalone build + probes |
| `p18-automation-scheduler-e2e.mjs` | Jobs/scheduler |
| `p19-dr-bcp-e2e.mjs` | DR manifest verify + drills |
| `p20-api-platform-e2e.mjs` | API keys, OpenAPI, ext/v1 |
| `p21-bi-export-e2e.mjs` | BI datasets + builder + exports |
| `p22-assets-payroll-e2e.mjs` | Assets + payroll |
| `p23-hr-insurance-e2e.mjs` | HR + insurance |
| `p24-costcenters-e2e.mjs` | Cost centers + tagging |

~17,300 lines of test code total. Every delivered feature also carries RTL fa / en / 390px mobile browser-verification screenshots in `tests/` (binary evidence — local-only in the GitHub mirror, listed in `docs/REPO-MANIFEST-*.txt`).
