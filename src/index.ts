/**
 * BangAuth — public library surface.
 *
 * v0.1 ships and is exercised primarily as a standalone Hono service
 * (see `src/server.ts` and the Dockerfile). This barrel exposes the
 * **pure engine pieces** so callers who want to:
 *   - issue / verify their own tokens
 *   - sign their own JWTs with monthly-rotating HMAC keys
 *   - generate or verify TOTP secrets
 *   - mint or check recovery codes
 *   - enforce a domain allowlist
 * can do so without standing up the server.
 *
 * The full "drop in as middleware" usage (`createBangAuth(config)`
 * returning Hono route handlers) is a v0.2 deliverable; until then,
 * `npx tsx src/server.ts` or `docker run bangauth` is the supported
 * shape.
 *
 * @module bangauth
 */

// ─── Token engine (the monthly-rotating SHA-256 design) ──────────────────
export {
  generateToken,
  verifyToken,
  currentMonth,
  isMonthValid,
} from './token.js';

// ─── JWT signing & verification ─────────────────────────────────────────
// (Same module — the JWT path lives alongside the access-code path
// because they share the monthly-rotation discipline.)

// ─── TOTP / authenticator-app flow ──────────────────────────────────────
export {
  generateSecret,
  buildQrUri,
  verifyTOTP,
} from './totp.js';

// ─── MFA session brute-force protection ─────────────────────────────────
export {
  generateMfaSession,
  verifyMfaSession,
  MAX_MFA_ATTEMPTS,
} from './mfa-session.js';

// ─── Recovery codes (XXXX-XXXX, ambiguous chars removed) ────────────────
export {
  generateRecoveryCodes,
  hashRecoveryCode,
  verifyRecoveryCode,
} from './recovery.js';

// ─── Domain allowlist ───────────────────────────────────────────────────
export { isDomainAllowed } from './domain.js';

// ─── Identity derivation ────────────────────────────────────────────────
export { deriveTwinId } from './twin-id.js';

// ─── Types ──────────────────────────────────────────────────────────────
export type * from './types.js';
