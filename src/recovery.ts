/**
 * UDT Identity Provider — Recovery Code Management
 *
 * Generates, hashes, and verifies backup recovery codes for MFA. These are
 * the "break glass" codes that let a user regain access if they lose their
 * authenticator device.
 *
 * // Why: TOTP is great until your phone dies, gets lost, or factory resets.
 * // Recovery codes are the safety net — one-time-use codes printed or saved
 * // somewhere safe. We store only SHA256 hashes (never plaintext) so even
 * // a Secrets Manager breach doesn't expose usable codes.
 *
 * @module recovery
 */

import { createHash, randomBytes } from 'node:crypto';
import type { RecoveryCodeEntry } from './types.js';

// ─── Constants ───────────────────────────────────────────────────────────────

/**
 * Unambiguous character set for recovery codes.
 *
 * // Why: We exclude 0/O, 1/I/L to prevent user confusion when reading codes
 * // from paper or a screenshot. Nobody wants to guess whether that's a zero
 * // or the letter O when they've already lost their phone.
 */
const RECOVERY_CHARS = 'ABCDEFGHJKMNPQRSTUVWXYZ23456789';

/**
 * Default number of recovery codes to generate.
 *
 * // Why: 10 codes is the industry standard (Google, GitHub, etc.). It's enough
 * // to cover multiple device-loss events without being overwhelming to store.
 */
const DEFAULT_CODE_COUNT = 10;

/**
 * Length of each half of a recovery code.
 *
 * // Why: XXXX-XXXX format (4+4) gives 30^8 ≈ 656 billion combinations,
 * // which is more than sufficient for one-time-use backup codes.
 */
const HALF_LENGTH = 4;

// ─── Recovery Code Functions ─────────────────────────────────────────────────

/**
 * Generate a single random recovery code in XXXX-XXXX format.
 *
 * // Why: Each character is independently selected from the unambiguous alphabet
 * // using cryptographically secure random bytes. The hyphen improves readability.
 *
 * @returns A recovery code string like "ABCD-EF23".
 */
function generateSingleCode(): string {
  const bytes = randomBytes(HALF_LENGTH * 2);
  let first = '';
  let second = '';

  for (let i = 0; i < HALF_LENGTH; i++) {
    first += RECOVERY_CHARS[bytes[i] % RECOVERY_CHARS.length];
    second += RECOVERY_CHARS[bytes[HALF_LENGTH + i] % RECOVERY_CHARS.length];
  }

  return `${first}-${second}`;
}

/**
 * Generate a batch of recovery codes.
 *
 * // Why: Recovery codes are generated once during MFA enrollment and shown
 * // to the user exactly once. After that, only their SHA256 hashes are stored.
 * // The user must save them — we can't show them again.
 *
 * @param count - Number of codes to generate (default: 10).
 * @returns Array of recovery code strings in XXXX-XXXX format.
 */
export function generateRecoveryCodes(count: number = DEFAULT_CODE_COUNT): string[] {
  const codes: string[] = [];
  const seen = new Set<string>();

  // Why: Dedup check prevents the astronomically unlikely but non-zero chance
  // of generating duplicate codes in the same batch.
  while (codes.length < count) {
    const code = generateSingleCode();
    if (!seen.has(code)) {
      seen.add(code);
      codes.push(code);
    }
  }

  return codes;
}

/**
 * Hash a recovery code for secure storage.
 *
 * // Why: We NEVER store recovery codes in plaintext. SHA256 is sufficient here
 * // because recovery codes have high entropy (30^8 ≈ 2^39) — they're not
 * // passwords that might be reused or guessable. A rainbow table attack is
 * // impractical against this keyspace.
 *
 * @param code - The plaintext recovery code (case-insensitive, hyphen-optional).
 * @returns SHA256 hex hash of the normalized code.
 */
export function hashRecoveryCode(code: string): string {
  // Why: Normalize before hashing so "abcd-ef23" matches "ABCDEF23".
  // Users might type codes in lowercase or forget the hyphen.
  const normalized = code.toUpperCase().replace(/-/g, '');
  return createHash('sha256').update(normalized).digest('hex');
}

/**
 * Verify a recovery code against stored hashes and return the matching index.
 *
 * // Why: We need the index so the caller can mark that specific code as "used."
 * // Recovery codes are one-time-use — once verified, it must be consumed so it
 * // can't be replayed.
 *
 * @param code - The plaintext recovery code to verify.
 * @param hashedCodes - Array of stored recovery code entries with hashes and used flags.
 * @returns The index of the matching code, or -1 if no match (or code already used).
 */
export function verifyRecoveryCode(code: string, hashedCodes: RecoveryCodeEntry[]): number {
  const hash = hashRecoveryCode(code);

  for (let i = 0; i < hashedCodes.length; i++) {
    const entry = hashedCodes[i];
    // Why: Skip already-used codes — they can't be replayed.
    if (entry.used) continue;
    if (entry.hash === hash) return i;
  }

  return -1;
}
