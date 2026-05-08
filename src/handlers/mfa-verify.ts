/**
 * UDT Identity Provider — MFA Verification Handler
 *
 * POST /idp/mfa/verify
 *
 * Verifies a TOTP code or recovery code against a user's MFA enrollment.
 * Also handles enrollment confirmation — if the enrollment is "pending,"
 * a valid TOTP code activates it and generates recovery codes.
 *
 * // Why: This is the second step of the MFA login flow. After the user's
 * // access token is verified and an MFA session token is issued, they submit
 * // their 6-digit TOTP code (or a recovery code) here. The handler validates
 * // the code and returns the final authentication result. For first-time
 * // enrollment confirmation, it also activates MFA and returns recovery codes.
 *
 * @module handlers/mfa-verify
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { createKeyStore } from '../config.js';
import { verifyMfaSession, generateMfaSession, MAX_MFA_ATTEMPTS } from '../mfa-session.js';
import { verifyTOTP } from '../totp.js';
import { generateRecoveryCodes, hashRecoveryCode, verifyRecoveryCode } from '../recovery.js';
import { getMfaEnrollment, saveMfaEnrollment } from '../mfa-store.js';
import { deriveTwinId } from '../twin-id.js';
import type { ApiResponse } from '../types.js';

// ─── Constants ───────────────────────────────────────────────────────────────

/**
 * Regex for a 6-digit TOTP code.
 *
 * // Why: Distinguishes TOTP codes from recovery codes at input time.
 * // TOTP = exactly 6 digits. Recovery = XXXX-XXXX alphanumeric.
 */
const TOTP_CODE_PATTERN = /^\d{6}$/;

/**
 * Regex for a recovery code in XXXX-XXXX format.
 *
 * // Why: Recovery codes use unambiguous uppercase alphanumerics with a hyphen.
 * // We accept lowercase input for usability.
 */
const RECOVERY_CODE_PATTERN = /^[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$/;

// Why: Reuse key store across warm invocations.
const keyStore = createKeyStore();

// ─── Handler ─────────────────────────────────────────────────────────────────

/**
 * Build a JSON API response with standard headers.
 */
function jsonResponse(statusCode: number, body: Record<string, unknown>): ApiResponse {
  return {
    statusCode,
    headers: {
      'Content-Type': 'application/json',
      'Access-Control-Allow-Origin': '*',
      'Access-Control-Allow-Headers': 'Content-Type',
    },
    body: JSON.stringify(body),
  };
}

/**
 * Lambda handler for POST /idp/mfa/verify.
 *
 * // Why: The MFA session token (from login) carries the user's email.
 * // We verify it, load their enrollment, then check the submitted code.
 * // Three paths:
 * //   1. TOTP code + active enrollment → verify TOTP → return success
 * //   2. Recovery code + active enrollment → verify + mark used → return success
 * //   3. TOTP code + pending enrollment → verify TOTP → activate + generate recovery codes
 *
 * @param event - API Gateway proxy event with JSON body containing { mfaSessionToken, code }.
 * @returns API Gateway proxy result with verification status.
 */
export async function handler(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  try {
    // Parse request body
    if (!event.body) {
      return jsonResponse(400, { error: 'Request body is required' });
    }

    let body: { mfaSessionToken?: string; code?: string };
    try {
      body = JSON.parse(event.body) as { mfaSessionToken?: string; code?: string };
    } catch {
      return jsonResponse(400, { error: 'Invalid JSON in request body' });
    }

    const { mfaSessionToken, code } = body;
    if (!mfaSessionToken || !code) {
      return jsonResponse(400, { error: 'mfaSessionToken and code are required' });
    }

    // Verify MFA session token
    // Why: Use signing key secret instead of constellationId for HMAC — the signing
    // key is a 256-bit random secret vs constellationId which is a short guessable string.
    const currentKey = await keyStore.getCurrentKey();
    const sessionResult = verifyMfaSession(mfaSessionToken, currentKey.secret);
    if (!sessionResult) {
      return jsonResponse(401, {
        mfaVerified: false,
        reason: 'Invalid or expired MFA session',
      });
    }

    const { email, attempts } = sessionResult;

    // Why: Brute-force protection — reject after MAX_MFA_ATTEMPTS failed attempts.
    // The attempt count is encoded in the self-validating session token, so no
    // database is needed. Each failed verify returns a new token with attempts + 1.
    if (attempts >= MAX_MFA_ATTEMPTS) {
      return jsonResponse(429, {
        mfaVerified: false,
        reason: 'too-many-attempts',
      });
    }

    // Load enrollment
    const enrollment = await getMfaEnrollment(email);
    if (!enrollment) {
      return jsonResponse(404, {
        mfaVerified: false,
        reason: 'No MFA enrollment found',
      });
    }

    const twinId = deriveTwinId(email);

    // Determine code type and verify
    if (TOTP_CODE_PATTERN.test(code)) {
      // Why: TOTP code path — verify against the stored secret.
      const valid = verifyTOTP(enrollment.totpSecret, code);
      if (!valid) {
        // Why: Issue a new session token with incremented attempt count.
        // The client must use this new token for the next verification attempt.
        const newSessionToken = generateMfaSession(email, currentKey.secret, attempts + 1);
        return jsonResponse(401, {
          mfaVerified: false,
          reason: 'Invalid TOTP code',
          mfaSessionToken: newSessionToken,
        });
      }

      // Check if this is enrollment confirmation (pending → active)
      if (enrollment.status === 'pending') {
        // Why: The user just scanned the QR code and entered a valid TOTP code
        // for the first time. Activate the enrollment and generate recovery codes.
        // Recovery codes are shown exactly once — the client must display them.
        const recoveryCodes = generateRecoveryCodes();
        const recoveryCodeHashes = recoveryCodes.map((c) => ({
          hash: hashRecoveryCode(c),
          used: false,
        }));

        await saveMfaEnrollment(email, {
          ...enrollment,
          status: 'active',
          recoveryCodeHashes,
        });

        console.log(`MFA enrollment activated for ${email}`);

        return jsonResponse(200, {
          mfaVerified: true,
          email,
          twinId,
          enrollmentActivated: true,
          recoveryCodes,
        });
      }

      // Active enrollment — standard TOTP verification
      console.log(`MFA verification successful for ${email}`);

      return jsonResponse(200, {
        mfaVerified: true,
        email,
        twinId,
      });
    } else if (RECOVERY_CODE_PATTERN.test(code)) {
      // Why: Recovery code path — check against stored hashes and mark used.
      // Recovery codes only work on active enrollments (not pending).
      if (enrollment.status !== 'active') {
        return jsonResponse(400, {
          mfaVerified: false,
          reason: 'Cannot use recovery codes during enrollment',
        });
      }

      const matchedIndex = verifyRecoveryCode(code, enrollment.recoveryCodeHashes);
      if (matchedIndex === -1) {
        // Why: Same brute-force protection for recovery codes.
        const newSessionToken = generateMfaSession(email, currentKey.secret, attempts + 1);
        return jsonResponse(401, {
          mfaVerified: false,
          reason: 'Invalid or already used recovery code',
          mfaSessionToken: newSessionToken,
        });
      }

      // Mark the recovery code as used
      // Why: One-time-use — prevent replay attacks with the same code.
      enrollment.recoveryCodeHashes[matchedIndex].used = true;
      enrollment.recoveryCodeHashes[matchedIndex].usedAt = new Date().toISOString();
      await saveMfaEnrollment(email, enrollment);

      const remaining = enrollment.recoveryCodeHashes.filter((c) => !c.used).length;
      console.log(`MFA recovery code used for ${email} (${remaining} remaining)`);

      return jsonResponse(200, {
        mfaVerified: true,
        email,
        twinId,
        recoveryCodesRemaining: remaining,
      });
    } else {
      return jsonResponse(400, {
        mfaVerified: false,
        reason: 'Invalid code format — expected 6-digit TOTP code or XXXX-XXXX recovery code',
      });
    }
  } catch (err: unknown) {
    console.error('mfa-verify handler error:', err);
    return jsonResponse(500, { error: 'Internal server error' });
  }
}
