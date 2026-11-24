# ============================================================================
# HESABIYAR — Production image (multi-stage, bun + Next.js standalone)
#
# Stage 1 (deps)  : install dependencies with a frozen lockfile
# Stage 2 (build) : prisma generate + next build (output: "standalone")
# Stage 3 (run)   : slim runtime with only the standalone server + assets
# ============================================================================

# ---------------------------------------------------------------- deps ------
FROM oven/bun:1 AS deps
WORKDIR /app

COPY package.json bun.lock ./
RUN bun install --frozen-lockfile

# --------------------------------------------------------------- build ------
FROM oven/bun:1 AS build
WORKDIR /app

COPY --from=deps /app/node_modules ./node_modules
COPY . .

# Prisma client generation (no DB connection needed — dummy URL silences the
# client constructor in case any module evaluates it during the build).
ENV NODE_ENV=production
ENV DATABASE_URL=file:/tmp/build.db
RUN bun run db:generate

# `next build` with output:"standalone" + copies .next/static and public/
# into .next/standalone (see package.json "build" script).
RUN bun run build

# ------------------------------------------------------------- runtime ------
FROM oven/bun:1-slim AS runtime
WORKDIR /app

ENV NODE_ENV=production \
    PORT=3000 \
    HOSTNAME=0.0.0.0 \
    DATABASE_URL=file:/app/db/custom.db

# Standalone server (already contains .next/static + public via build script);
# copied again explicitly so the image stays correct even if the script changes.
COPY --from=build /app/.next/standalone ./
COPY --from=build /app/.next/static ./.next/static
COPY --from=build /app/public ./public

# Prisma schema/SQL for migrate-deploy workflows and the generated client
# engine (defensive: standalone tracing does not always capture the engine).
COPY --from=build /app/prisma ./prisma
COPY --from=deps /app/node_modules/.prisma ./node_modules/.prisma
COPY --from=deps /app/node_modules/@prisma ./node_modules/@prisma

# SQLite database + auto-backups live here (bind-mounted in compose).
RUN mkdir -p /app/db
VOLUME ["/app/db"]

EXPOSE 3000

# Phase 11 (v3) — container-level liveness probe wired to the platform probe.
# (bun-slim runtime ships bun, not node — use `bun -e` for the probe.)
HEALTHCHECK --interval=30s --timeout=5s --start-period=20s --retries=3 \
  CMD bun -e "fetch('http://127.0.0.1:3000/api/health').then(r=>process.exit(r.ok?0:1)).catch(()=>process.exit(1))" || exit 1

CMD ["bun", ".next/standalone/server.js"]
