/**
 * UDT Identity Provider — MFA Enrollment Handler
 *
 * POST /idp/mfa/enroll
 *
 * Initiates TOTP MFA enrollment for an authenticated user. Generates a TOTP
 * secret, builds a QR URI for authenticator app scanning, and stores the
 * enrollment as "pending" until the user confirms with their first valid code.
 *
 * // Why: MFA enrollment is a two-step process: (1) this endpoint generates
 * // the secret and QR code, (2) the user scans the QR, enters the code shown
 * // by their authenticator app, and POST /idp/mfa/verify confirms it. The
 * // "pending" status prevents half-configured MFA from blocking login.
 *
 * @module handlers/mfa-enroll
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { loadConfig, createKeyStore } from '../config.js';
import { verifyToken } from '../token.js';
import { generateSecret, buildQrUri } from '../totp.js';
import { getMfaEnrollment, saveMfaEnrollment } from '../mfa-store.js';
import type { ApiResponse } from '../types.js';

// Why: Reuse key store across warm invocations.
const keyStore = createKeyStore();

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
 * Lambda handler for POST /idp/mfa/enroll.
 *
 * // Why: Only authenticated users can enroll in MFA. The access token proves
 * // identity; we then generate a fresh TOTP secret and return it along with
 * // a QR URI. The client renders the QR code for the user to scan with their
 * // authenticator app. The enrollment stays "pending" until confirmed.
 *
 * @param event - API Gateway proxy event with JSON body containing { token }.
 * @returns API Gateway proxy result with QR URI and secret, or error.
 */
export async function handler(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  try {
    // Parse request body
    if (!event.body) {
      return jsonResponse(400, { error: 'Request body is required' });
    }

    let body: { token?: string };
    try {
      body = JSON.parse(event.body) as { token?: string };
    } catch {
      return jsonResponse(400, { error: 'Invalid JSON in request body' });
    }

    const token = body.token?.trim();
    if (!token) {
      return jsonResponse(400, { error: 'Token is required' });
    }

    // Verify the access token
    const result = await verifyToken(token, keyStore);
    if (!result.valid) {
      return jsonResponse(401, { error: 'Invalid or expired token', reason: result.reason });
    }

    const config = await loadConfig();

    // Check if already enrolled and active
    // Why: Prevent re-enrollment when MFA is already active. The user must
    // reset MFA first if they want to change their authenticator.
    const existing = await getMfaEnrollment(result.email);
    if (existing && existing.status === 'active') {
      return jsonResponse(409, { error: 'MFA already enrolled' });
    }

    // Generate TOTP secret and QR URI
    const secret = generateSecret();
    const qrUri = buildQrUri(result.email, secret, config.mfaIssuer);

    // Store as pending enrollment
    // Why: "pending" status means the user has the QR code but hasn't confirmed
    // it works yet. Login won't enforce MFA until status is "active."
    await saveMfaEnrollment(result.email, {
      totpSecret: secret,
      recoveryCodeHashes: [],
      enrolledAt: new Date().toISOString(),
      status: 'pending',
    });

    console.log(`MFA enrollment initiated for ${result.email}`);

    return jsonResponse(200, {
      qrUri,
      secret,
      status: 'pending',
    });
  } catch (err: unknown) {
    console.error('mfa-enroll handler error:', err);
    return jsonResponse(500, { error: 'Internal server error' });
  }
}
