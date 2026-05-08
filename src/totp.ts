/**
 * UDT Identity Provider — TOTP Engine
 *
 * Pure functions for generating and verifying Time-based One-Time Passwords
 * (RFC 6238) using HMAC-SHA1 with 6-digit codes and 30-second time steps.
 *
 * // Why: TOTP is the industry standard for second-factor authentication.
 * // Every authenticator app (Google Authenticator, Authy, 1Password, etc.)
 * // speaks the same protocol. By implementing it ourselves with node:crypto,
 * // we avoid external dependencies and keep the Lambda bundle small.
 *
 * @module totp
 */

import { createHmac, randomBytes } from 'node:crypto';

// ─── Constants ───────────────────────────────────────────────────────────────

/**
 * TOTP time step in seconds (RFC 6238 default).
 *
 * // Why: 30 seconds is the universal default. Every authenticator app assumes
 * // this unless told otherwise. Changing it would break compatibility.
 */
const TIME_STEP = 30;

/**
 * Number of digits in the generated TOTP code.
 *
 * // Why: 6 digits provides 1-in-a-million odds of a random guess, which is
 * // the standard balance between security and usability for TOTP.
 */
const CODE_DIGITS = 6;

/**
 * Default verification window — check ±1 time step.
 *
 * // Why: Clock skew between the server and the user's authenticator app is
 * // inevitable. ±1 window means we accept codes from 30 seconds ago to 30
 * // seconds in the future. This covers reasonable drift without being too lax.
 */
const DEFAULT_WINDOW = 1;

// ─── Base32 Encoding/Decoding ────────────────────────────────────────────────

/**
 * RFC 4648 Base32 alphabet.
 *
 * // Why: TOTP secrets are conventionally encoded in base32 because it's
 * // case-insensitive and avoids confusing characters. The otpauth:// URI
 * // spec requires base32 encoding of the secret.
 */
const BASE32_ALPHABET = 'ABCDEFGHIJKLMNOPQRSTUVWXYZ234567';

/**
 * Encode a Buffer to a base32 string.
 *
 * // Why: Inline implementation avoids adding a dependency for ~20 lines of code.
 * // Base32 encodes 5 bits per character, so 20 bytes → 32 characters.
 *
 * @param buffer - The raw bytes to encode.
 * @returns Base32-encoded string (uppercase, no padding).
 */
export function base32Encode(buffer: Buffer): string {
  let bits = 0;
  let value = 0;
  let result = '';

  for (const byte of buffer) {
    value = (value << 8) | byte;
    bits += 8;

    while (bits >= 5) {
      bits -= 5;
      result += BASE32_ALPHABET[(value >>> bits) & 0x1f];
    }
  }

  // Why: Flush remaining bits (if any) by left-shifting to fill a 5-bit group.
  if (bits > 0) {
    result += BASE32_ALPHABET[(value << (5 - bits)) & 0x1f];
  }

  return result;
}

/**
 * Decode a base32 string back to a Buffer.
 *
 * // Why: Verification needs the raw bytes of the secret to compute the HMAC.
 * // The secret is stored as base32, so we decode it before use.
 *
 * @param encoded - Base32-encoded string (case-insensitive).
 * @returns Raw bytes as a Buffer.
 */
export function base32Decode(encoded: string): Buffer {
  const upper = encoded.toUpperCase().replace(/=+$/, '');
  let bits = 0;
  let value = 0;
  const bytes: number[] = [];

  for (const char of upper) {
    const idx = BASE32_ALPHABET.indexOf(char);
    if (idx === -1) continue; // Why: Skip invalid characters gracefully.
    value = (value << 5) | idx;
    bits += 5;

    if (bits >= 8) {
      bits -= 8;
      bytes.push((value >>> bits) & 0xff);
    }
  }

  return Buffer.from(bytes);
}

// ─── TOTP Functions ──────────────────────────────────────────────────────────

/**
 * Generate a random TOTP secret.
 *
 * // Why: 160 bits (20 bytes) is the recommended minimum for HMAC-SHA1 keys
 * // per RFC 4226. This produces a 32-character base32 string that fits
 * // neatly in authenticator apps and QR codes.
 *
 * @returns Base32-encoded secret string (32 characters).
 */
export function generateSecret(): string {
  // Why: 20 bytes = 160 bits, matching the HMAC-SHA1 block size.
  const bytes = randomBytes(20);
  return base32Encode(bytes);
}

/**
 * Build an otpauth:// URI for QR code generation.
 *
 * // Why: The otpauth:// URI is the standard way to provision TOTP secrets
 * // into authenticator apps. Scanning a QR code of this URI auto-configures
 * // the app with the correct secret, issuer, and parameters.
 *
 * @param email - User's email address (used as the account label).
 * @param secret - Base32-encoded TOTP secret.
 * @param issuer - The service name shown in the authenticator app.
 * @returns The otpauth:// URI string.
 */
export function buildQrUri(email: string, secret: string, issuer: string): string {
  // Why: Both the label and query parameter use the issuer for clarity.
  // The label format "Issuer:email" is the recommended convention.
  const label = `${encodeURIComponent(issuer)}:${encodeURIComponent(email)}`;
  const params = new URLSearchParams({
    secret,
    issuer,
    digits: String(CODE_DIGITS),
    period: String(TIME_STEP),
  });
  return `otpauth://totp/${label}?${params.toString()}`;
}

/**
 * Generate a TOTP code for a given secret and time.
 *
 * // Why: This is the core TOTP algorithm from RFC 6238. We compute an HMAC-SHA1
 * // over the time counter (floor(time / 30)), extract a 4-byte dynamic offset,
 * // and truncate to a 6-digit code. This is what the authenticator app does too —
 * // if both sides have the same secret and roughly the same time, they produce
 * // the same code.
 *
 * @param secret - Base32-encoded TOTP secret.
 * @param time - Unix timestamp in seconds (defaults to now).
 * @returns 6-digit TOTP code as a zero-padded string.
 */
export function generateTOTP(secret: string, time?: number): string {
  const now = time ?? Math.floor(Date.now() / 1000);
  const counter = Math.floor(now / TIME_STEP);

  // Why: The counter must be an 8-byte big-endian integer per RFC 4226.
  // JavaScript can't natively write 64-bit integers to buffers, so we
  // split into two 32-bit writes.
  const counterBuffer = Buffer.alloc(8);
  counterBuffer.writeUInt32BE(Math.floor(counter / 0x100000000), 0);
  counterBuffer.writeUInt32BE(counter >>> 0, 4);

  // Why: HMAC-SHA1 is specified by RFC 6238 for TOTP. While SHA1 alone is
  // weak for collision resistance, HMAC-SHA1 remains cryptographically sound
  // for this purpose. Using SHA256 would break authenticator app compatibility.
  const keyBytes = base32Decode(secret);
  const hmac = createHmac('sha1', keyBytes).update(counterBuffer).digest();

  // Why: Dynamic truncation — the last nibble of the HMAC selects the offset
  // for extracting a 4-byte code. This is the DT() function from RFC 4226.
  const offset = hmac[hmac.length - 1] & 0x0f;
  const binary =
    ((hmac[offset] & 0x7f) << 24) |
    ((hmac[offset + 1] & 0xff) << 16) |
    ((hmac[offset + 2] & 0xff) << 8) |
    (hmac[offset + 3] & 0xff);

  const code = binary % 10 ** CODE_DIGITS;
  return String(code).padStart(CODE_DIGITS, '0');
}

/**
 * Verify a TOTP code against a secret with a configurable time window.
 *
 * // Why: We check the code against the current time step plus a window of
 * // adjacent steps. This handles clock skew between the server and the
 * // user's authenticator app. ±1 window (the default) covers most real-world
 * // drift — a 90-second total acceptance window.
 *
 * @param secret - Base32-encoded TOTP secret.
 * @param code - The 6-digit code to verify.
 * @param window - Number of time steps to check in each direction (default: 1).
 * @returns True if the code is valid for any step in the window.
 */
export function verifyTOTP(secret: string, code: string, window: number = DEFAULT_WINDOW): boolean {
  const now = Math.floor(Date.now() / 1000);

  // Why: Check the current step and adjacent steps within the window.
  // For window=1, we check times at -30s, 0s, and +30s — three checks total.
  for (let i = -window; i <= window; i++) {
    const stepTime = now + i * TIME_STEP;
    if (generateTOTP(secret, stepTime) === code) {
      return true;
    }
  }

  return false;
}
