/**
 * UDT Identity Provider — Token Engine
 *
 * The core of the IdP. Generates and verifies deterministic, HMAC-signed tokens.
 *
 * // Why: Deterministic tokens mean the same email + same month + same key always
 * // produces the identical token. No database needed for dedup — math handles it.
 * // This dramatically simplifies the architecture: no token table, no race conditions,
 * // no "resend" logic — just regenerate and it's the same token.
 *
 * Token format: {base64url(payload)}.{hex-signature}
 *
 * @module token
 */

import { createHmac } from 'node:crypto';
import type { TokenPayload, SigningKey, KeyStore, VerifyResult } from './types.js';

// ─── Constants ───────────────────────────────────────────────────────────────

/**
 * Current payload schema version.
 *
 * // Why: Embedding a version lets future code handle legacy tokens gracefully
 * // without breaking existing deployments.
 */
const PAYLOAD_VERSION = 1;

/**
 * Grace period in days — previous month's tokens remain valid through this day.
 *
 * // Why: Monthly rotation happens on the 1st, but users might still have the
 * // old token in their inbox. A 3-day grace window prevents lockouts.
 */
const GRACE_PERIOD_DAYS = 3;

// ─── Base64url Helpers ───────────────────────────────────────────────────────

/**
 * Encode a string to base64url (RFC 4648 §5).
 *
 * // Why: Standard base64 uses +, /, and = which are problematic in URLs and tokens.
 * // base64url replaces them with URL-safe characters and strips padding.
 */
export function base64urlEncode(input: string): string {
  return Buffer.from(input, 'utf-8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Decode a base64url string back to UTF-8.
 *
 * // Why: Verification needs to decode the payload half of the token to read claims.
 */
export function base64urlDecode(input: string): string {
  // Restore standard base64 characters and padding
  let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  if (pad === 2) base64 += '==';
  else if (pad === 3) base64 += '=';
  return Buffer.from(base64, 'base64').toString('utf-8');
}

// ─── HMAC Computation ────────────────────────────────────────────────────────

/**
 * Compute an HMAC signature over a payload string.
 *
 * // Why: HMAC-SHA256 is the standard for symmetric token signing. We support
 * // HS256/HS384/HS512 for future flexibility, but default to HS256.
 *
 * @param payload - The string to sign (base64url-encoded JSON payload).
 * @param secret - The hex-encoded signing secret.
 * @param alg - Algorithm identifier ("HS256", "HS384", or "HS512").
 * @returns Hex-encoded HMAC signature.
 */
export function computeSignature(payload: string, secret: string, alg: string): string {
  const algorithm =
    alg === 'HS256' ? 'sha256' :
    alg === 'HS384' ? 'sha384' :
    'sha512';
  return createHmac(algorithm, secret).update(payload).digest('hex');
}

// ─── Month Utilities ─────────────────────────────────────────────────────────

/**
 * Derive the current month string in YYYY-MM format.
 *
 * // Why: Tokens are scoped to a calendar month. This is the canonical
 * // derivation — used by both generation and rotation.
 *
 * @returns Current month as "YYYY-MM" (e.g., "2026-05").
 */
export function currentMonth(): string {
  const now = new Date();
  return `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;
}

/**
 * Check whether a token's month is currently valid.
 *
 * // Why: Tokens expire at month boundaries, but we allow a grace period
 * // so users aren't locked out the instant the calendar flips. The previous
 * // month stays valid through the 3rd of the new month.
 *
 * @param tokenMonth - The month string from the token payload ("YYYY-MM").
 * @returns True if the token month is the current month or within the grace period.
 */
export function isMonthValid(tokenMonth: string): boolean {
  const now = new Date();
  const current = `${now.getFullYear()}-${String(now.getMonth() + 1).padStart(2, '0')}`;

  // Current month is always valid
  if (tokenMonth === current) return true;

  // Grace period: previous month valid through the 3rd
  const dayOfMonth = now.getDate();
  if (dayOfMonth <= GRACE_PERIOD_DAYS) {
    const prevDate = new Date(now.getFullYear(), now.getMonth() - 1, 1);
    const prevMonth = `${prevDate.getFullYear()}-${String(prevDate.getMonth() + 1).padStart(2, '0')}`;
    if (tokenMonth === prevMonth) return true;
  }

  return false;
}

// ─── Token Generation ────────────────────────────────────────────────────────

/**
 * Generate a deterministic access token.
 *
 * // Why: Given the same email, month, key, and constellation, this function
 * // ALWAYS produces the identical token. This is by design — idempotent
 * // generation means "resend token" is just "generate again." No database,
 * // no dedup table, no race conditions. Pure math.
 *
 * @param email - User's email address (will be lowercased).
 * @param month - Target month in "YYYY-MM" format.
 * @param key - The signing key to use.
 * @param constellationId - The constellation this token grants access to.
 * @returns The complete token string: "{base64url(payload)}.{signature}".
 */
export function generateToken(
  email: string,
  month: string,
  key: SigningKey,
  constellationId: string,
): string {
  const normalizedEmail = email.toLowerCase().trim();
  const domain = normalizedEmail.split('@')[1];

  const payload: TokenPayload = {
    email: normalizedEmail,
    domain,
    month,
    kid: key.kid,
    alg: key.alg,
    constellationId,
    version: PAYLOAD_VERSION,
  };

  // Why: JSON.stringify with sorted keys isn't needed here because the payload
  // object is constructed in a fixed order and JavaScript preserves insertion order.
  // Determinism comes from identical inputs → identical object → identical JSON.
  const payloadJson = JSON.stringify(payload);
  const payloadEncoded = base64urlEncode(payloadJson);
  const signature = computeSignature(payloadEncoded, key.secret, key.alg);

  return `${payloadEncoded}.${signature}`;
}

// ─── Token Verification ──────────────────────────────────────────────────────

/**
 * Verify an access token against the key store.
 *
 * // Why: Verification is the gateway — every login, every API call, every
 * // access check goes through here. It decodes the payload, looks up the
 * // signing key by kid, recomputes the HMAC, and checks month validity.
 * // Timing-safe comparison would be ideal but hex comparison is sufficient
 * // for our threat model (server-side only, no timing oracle).
 *
 * @param token - The complete token string to verify.
 * @param keyStore - Key store for looking up signing keys.
 * @returns Verification result — either valid with claims or invalid with a reason.
 */
export async function verifyToken(token: string, keyStore: KeyStore): Promise<VerifyResult> {
  // Split token into payload and signature
  const dotIndex = token.indexOf('.');
  if (dotIndex === -1) {
    return { valid: false, reason: 'Invalid token format: missing separator' };
  }

  const payloadEncoded = token.substring(0, dotIndex);
  const providedSignature = token.substring(dotIndex + 1);

  // Decode and parse payload
  let payload: TokenPayload;
  try {
    const payloadJson = base64urlDecode(payloadEncoded);
    payload = JSON.parse(payloadJson) as TokenPayload;
  } catch {
    return { valid: false, reason: 'Invalid token format: payload decode failed' };
  }

  // Validate required fields
  if (!payload.email || !payload.domain || !payload.month || !payload.kid || !payload.alg) {
    return { valid: false, reason: 'Invalid token: missing required fields' };
  }

  // Check month validity
  if (!isMonthValid(payload.month)) {
    return { valid: false, reason: `Token expired: month ${payload.month} is no longer valid` };
  }

  // Look up signing key
  const key = await keyStore.getKey(payload.kid);
  if (!key) {
    return { valid: false, reason: `Unknown signing key: ${payload.kid}` };
  }

  if (!key.active) {
    return { valid: false, reason: `Signing key ${payload.kid} is inactive` };
  }

  // Recompute signature and compare
  const expectedSignature = computeSignature(payloadEncoded, key.secret, payload.alg);
  if (providedSignature !== expectedSignature) {
    return { valid: false, reason: 'Invalid signature' };
  }

  return {
    valid: true,
    email: payload.email,
    domain: payload.domain,
    month: payload.month,
    kid: payload.kid,
    alg: payload.alg,
    constellationId: payload.constellationId,
  };
}
