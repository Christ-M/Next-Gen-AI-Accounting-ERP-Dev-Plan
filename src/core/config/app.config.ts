/**
 * Central application configuration — single source of truth.
 * Values here are consumed by both the API layer and (where non-sensitive)
 * the client UI. Secrets never live in this file; they come from process.env.
 */

export const APP = {
  name: 'Hesabyar',
  nameFa: 'حسابیار',
  taglineEn: 'Advanced Accounting Platform',
  taglineFa: 'پلتفرم حسابداری پیشرفته',
  /** Bumped per delivery phase — surfaced in the footer + /api/health */
  version: '2.29.0-phase29-v3',
} as const;

export const AUTH = {
  accessTokenCookie: 'hesabyar_at',
  refreshTokenCookie: 'hesabyar_rt',

  /** Access token (JWT) lifetime: 30 minutes */
  accessTtlSeconds: 60 * 30,
  /** Refresh token (opaque, rotating) lifetime: 7 days */
  refreshTtlSeconds: 60 * 60 * 24 * 7,
  /** Refresh token lifetime when "remember me" is checked: 30 days */
  refreshTtlRememberSeconds: 60 * 60 * 24 * 30,

  bcryptRounds: 12,
  maxFailedLogins: 5,
  /** Account lockout window after too many failed logins */
  lockoutMinutes: 15,
} as const;

/**
 * Sliding-window rate limits (per key, usually ip:route).
 * In-memory is intentional for the single-instance sandbox; the interface is
 * swappable for a Redis-backed store without touching call sites.
 */
export const RATE_LIMITS = {
  register: { limit: 5, windowMs: 10 * 60 * 1000 },
  login: { limit: 10, windowMs: 10 * 60 * 1000 },
  refresh: { limit: 40, windowMs: 10 * 60 * 1000 },
  read: { limit: 120, windowMs: 60 * 1000 },
  mutation: { limit: 30, windowMs: 60 * 1000 },
} as const;

/**
 * NOTE: environment secret resolution (`requireEnv`) lives in
 * `./env.server` — server-only (node built-ins). It is deliberately NOT
 * re-exported here so this module stays safe for client bundles.
 */
