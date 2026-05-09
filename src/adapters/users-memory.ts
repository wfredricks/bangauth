/**
 * BangAuth — In-Memory User Store Adapter
 *
 * Stores user state (access codes, MFA enrollments) in memory. No persistence —
 * everything resets on container restart. Perfect for dev/demo/constellation MVP.
 *
 * // Why: For a standalone HTTP service with no external database, we need
 * // somewhere to store access codes (email-based auth) and MFA enrollments.
 * // In-memory is fine for MVP — codes expire in 5 minutes, MFA can be re-enrolled.
 *
 * @module adapters/users-memory
 */

import type { MfaEnrollment } from '../types.js';

/**
 * Access code entry — stores the code and expiration timestamp.
 */
interface AccessCodeEntry {
  code: string;
  expiresAt: number; // Unix timestamp (ms)
}

/**
 * In-memory user store — keyed by email address (lowercased).
 */
export class MemoryUserStore {
  private accessCodes: Map<string, AccessCodeEntry> = new Map();
  private mfaEnrollments: Map<string, MfaEnrollment> = new Map();

  /**
   * Store an access code for an email address.
   *
   * // Why: When a user requests a code, we generate a 6-digit code and store
   * // it here with a 5-minute expiration. The code is sent via email (or printed
   * // to console), and the user submits it back to /auth/verify-code.
   *
   * @param email - User's email address.
   * @param code - The 6-digit access code.
   * @param ttlMs - Time-to-live in milliseconds (default: 5 minutes).
   */
  async storeAccessCode(email: string, code: string, ttlMs: number = 5 * 60 * 1000): Promise<void> {
    const normalizedEmail = email.toLowerCase().trim();
    const expiresAt = Date.now() + ttlMs;
    this.accessCodes.set(normalizedEmail, { code, expiresAt });
    console.log(`💾 Stored access code for ${normalizedEmail} (expires in ${ttlMs / 1000}s)`);
  }

  /**
   * Verify an access code for an email address.
   *
   * // Why: The user submits the code they received. We check if it matches
   * // and hasn't expired. If valid, we remove it (one-time use).
   *
   * @param email - User's email address.
   * @param code - The code to verify.
   * @returns True if the code is valid and not expired.
   */
  async verifyAccessCode(email: string, code: string): Promise<boolean> {
    const normalizedEmail = email.toLowerCase().trim();
    const entry = this.accessCodes.get(normalizedEmail);

    if (!entry) {
      console.log(`❌ No access code found for ${normalizedEmail}`);
      return false;
    }

    if (Date.now() > entry.expiresAt) {
      console.log(`⏰ Access code expired for ${normalizedEmail}`);
      this.accessCodes.delete(normalizedEmail);
      return false;
    }

    if (entry.code !== code) {
      console.log(`❌ Invalid access code for ${normalizedEmail}`);
      return false;
    }

    // Valid code — remove it (one-time use)
    this.accessCodes.delete(normalizedEmail);
    console.log(`✅ Access code verified for ${normalizedEmail}`);
    return true;
  }

  /**
   * Get MFA enrollment for an email address.
   *
   * // Why: Called during login to check if MFA is required, and during
   * // MFA verification to get the TOTP secret and recovery hashes.
   */
  async getMfaEnrollment(email: string): Promise<MfaEnrollment | null> {
    const normalizedEmail = email.toLowerCase().trim();
    return this.mfaEnrollments.get(normalizedEmail) ?? null;
  }

  /**
   * Save MFA enrollment for an email address.
   *
   * // Why: Stores TOTP secret and recovery code hashes. In production, this
   * // would go to Secrets Manager. In memory mode, it's just a Map.
   */
  async saveMfaEnrollment(email: string, data: MfaEnrollment): Promise<void> {
    const normalizedEmail = email.toLowerCase().trim();
    this.mfaEnrollments.set(normalizedEmail, data);
    console.log(`💾 Saved MFA enrollment for ${normalizedEmail} (status: ${data.status})`);
  }

  /**
   * Delete MFA enrollment for an email address.
   *
   * // Why: Used during MFA reset — removes the enrollment entirely.
   */
  async deleteMfaEnrollment(email: string): Promise<void> {
    const normalizedEmail = email.toLowerCase().trim();
    this.mfaEnrollments.delete(normalizedEmail);
    console.log(`🗑️  Deleted MFA enrollment for ${normalizedEmail}`);
  }

  /**
   * Clean up expired access codes.
   *
   * // Why: Without cleanup, the Map grows unbounded. Run this periodically
   * // to remove expired codes.
   */
  cleanupExpiredCodes(): void {
    const now = Date.now();
    let cleaned = 0;

    for (const [email, entry] of this.accessCodes.entries()) {
      if (now > entry.expiresAt) {
        this.accessCodes.delete(email);
        cleaned++;
      }
    }

    if (cleaned > 0) {
      console.log(`🧹 Cleaned up ${cleaned} expired access codes`);
    }
  }
}
