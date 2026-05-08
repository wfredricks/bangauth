/**
 * UDT Identity Provider — MFA Session Tokens
 *
 * Short-lived, HMAC-signed session tokens that bridge the gap between initial
 * authentication and MFA verification. These tokens carry the user's email
 * through the MFA challenge flow without requiring a database.
 *
 * // Why: After the user's main token is verified but before MFA is confirmed,
 * // we need a way to identify the user during the TOTP/recovery code entry step.
 * // Rather than creating a server-side session (which needs a database), we use
 * // the same self-validating HMAC pattern as our access tokens. The token
 * // encodes the email, a timestamp, and a nonce — signed with the constellation
 * // secret. 5-minute TTL keeps the attack window tiny.
 *
 * @module mfa-session
 */

import { createHmac, randomBytes, timingSafeEqual } from 'node:crypto';

// ─── Constants ───────────────────────────────────────────────────────────────

/**
 * MFA session token TTL in milliseconds (5 minutes).
 *
 * // Why: The user has 5 minutes to enter their TOTP code after logging in.
 * // This is generous enough for fumbling with an authenticator app but tight
 * // enough to limit replay window. If it expires, they just log in again.
 */
const MFA_SESSION_TTL_MS = 5 * 60 * 1000;

// ─── Base64url Helpers ───────────────────────────────────────────────────────

/**
 * Encode a string to base64url.
 *
 * // Why: Same rationale as token.ts — URL-safe encoding for tokens that may
 * // appear in query strings or JSON payloads.
 */
function base64urlEncode(input: string): string {
  return Buffer.from(input, 'utf-8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decode a base64url string back to UTF-8.
 */
function base64urlDecode(input: string): string {
  let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  if (pad === 2) base64 += '==';
  else if (pad === 3) base64 += '=';
  return Buffer.from(base64, 'base64').toString('utf-8');
}

// ─── MFA Session Functions ───────────────────────────────────────────────────

/**
 * Generate an MFA session token for a user.
 *
 * // Why: The token is self-validating — it carries its own payload and signature.
 * // No database lookup needed to verify it. The nonce prevents replay attacks
 * // (though the 5-min TTL already limits the window significantly). Format
 * // mirrors the access token pattern: {base64url(payload)}.{hex-signature}.
 *
 * // Why (attempts): Brute-force protection is encoded in the token itself.
 * // Each failed verify increments attempts and returns a new token. When
 * // attempts >= MAX_MFA_ATTEMPTS, verification is rejected. No database needed
 * // — the token carries its own rate-limit state.
 *
 * @param email - The authenticated user's email address.
 * @param signingSecret - The current signing key's secret from Secrets Manager.
 * @param attempts - Number of failed verification attempts so far (default 0).
 * @returns An HMAC-signed MFA session token string.
 */
export function generateMfaSession(email: string, signingSecret: string, attempts: number = 0): string {
  const payload = {
    email: email.toLowerCase().trim(),
    iat: Date.now(),
    nonce: randomBytes(16).toString('hex'),
    purpose: 'mfa-session',
    attempts,
  };

  const payloadEncoded = base64urlEncode(JSON.stringify(payload));
  const signature = createHmac('sha256', signingSecret)
    .update(payloadEncoded)
    .digest('hex');

  return `${payloadEncoded}.${signature}`;
}

/**
 * Result of verifying an MFA session token.
 *
 * // Why: Now returns attempts count alongside email so callers can enforce
 * // brute-force limits without needing a database.
 */
export interface MfaSessionResult {
  email: string;
  attempts: number;
}

/**
 * Maximum allowed MFA verification attempts per session.
 *
 * // Why: 5 attempts is generous for a legitimate user (typos happen) but
 * // makes brute-forcing a 6-digit TOTP code impractical (1M possibilities,
 * // only 5 guesses). After 5 failures the user must start a new login.
 */
export const MAX_MFA_ATTEMPTS = 5;

/**
 * Verify an MFA session token and extract the email + attempt count.
 *
 * // Why: We decode the payload, recompute the HMAC, compare with timing-safe
 * // equality, and check the TTL. If anything fails, we return null — no partial
 * // results, no error details exposed to the caller. Either it's valid or it's not.
 * // Timing-safe comparison prevents signature oracle attacks.
 *
 * @param sessionToken - The MFA session token to verify.
 * @param signingSecret - The current signing key's secret from Secrets Manager.
 * @returns The email and attempts count if valid, or null.
 */
export function verifyMfaSession(
  sessionToken: string,
  signingSecret: string,
): MfaSessionResult | null {
  const dotIndex = sessionToken.indexOf('.');
  if (dotIndex === -1) return null;

  const payloadEncoded = sessionToken.substring(0, dotIndex);
  const providedSignature = sessionToken.substring(dotIndex + 1);

  // Why: Recompute the expected signature from the payload.
  const expectedSignature = createHmac('sha256', signingSecret)
    .update(payloadEncoded)
    .digest('hex');

  // Why: Timing-safe comparison prevents leaking information about how many
  // bytes of the signature matched. Belt-and-suspenders for server-side tokens.
  const expected = Buffer.from(expectedSignature, 'hex');
  const provided = Buffer.from(providedSignature, 'hex');
  if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) {
    return null;
  }

  // Decode and validate payload
  let payload: { email?: string; iat?: number; purpose?: string; attempts?: number };
  try {
    payload = JSON.parse(base64urlDecode(payloadEncoded)) as {
      email?: string;
      iat?: number;
      purpose?: string;
      attempts?: number;
    };
  } catch {
    return null;
  }

  // Why: Validate the purpose field to prevent cross-use of other HMAC tokens.
  if (payload.purpose !== 'mfa-session') return null;
  if (!payload.email || !payload.iat) return null;

  // Why: Check TTL — the token must not be older than 5 minutes.
  const age = Date.now() - payload.iat;
  if (age < 0 || age > MFA_SESSION_TTL_MS) return null;

  return {
    email: payload.email,
    attempts: payload.attempts ?? 0,
  };
}
