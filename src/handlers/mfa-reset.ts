/**
 * UDT Identity Provider — MFA Reset Handler
 *
 * Handles three MFA reset flows:
 * - POST /idp/mfa/reset-request  — User-initiated: sends reset email
 * - POST /idp/mfa/reset-confirm  — User clicks email link to confirm reset
 * - POST /admin/reset-mfa        — Admin-initiated: immediate reset
 *
 * // Why: Users lose phones, factory-reset devices, and run out of recovery codes.
 * // Self-service reset via email is safe because email IS the identity anchor —
 * // if you can receive email, you own the identity. Admin reset is the nuclear
 * // option for support escalations.
 *
 * @module handlers/mfa-reset
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { createHmac, timingSafeEqual } from 'node:crypto';
import { loadConfig, createKeyStore } from '../config.js';
import { verifyToken } from '../token.js';
import { isDomainAllowed } from '../domain.js';
import { deleteMfaEnrollment } from '../mfa-store.js';
import { sendMfaResetEmail } from '../email.js';
import type { ApiResponse } from '../types.js';

// ─── Constants ───────────────────────────────────────────────────────────────

/**
 * Reset token TTL in milliseconds (15 minutes).
 *
 * // Why: Short enough to limit attack window if the email is intercepted,
 * // long enough for a user to check their email and click the link.
 */
const RESET_TOKEN_TTL_MS = 15 * 60 * 1000;

// Why: Reuse key store across warm invocations.
const keyStore = createKeyStore();

// ─── Helpers ─────────────────────────────────────────────────────────────────

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
 * Base64url encode a string.
 */
function base64urlEncode(input: string): string {
  return Buffer.from(input, 'utf-8')
    .toString('base64')
    .replace(/\+/g, '-')
    .replace(/\//g, '_')
    .replace(/=+$/, '');
}

/**
 * Base64url decode a string.
 */
function base64urlDecode(input: string): string {
  let base64 = input.replace(/-/g, '+').replace(/_/g, '/');
  const pad = base64.length % 4;
  if (pad === 2) base64 += '==';
  else if (pad === 3) base64 += '=';
  return Buffer.from(base64, 'base64').toString('utf-8');
}

/**
 * Generate an HMAC-signed reset token.
 *
 * // Why: Same self-validating pattern as access tokens and MFA session tokens.
 * // The token carries the email and timestamp, signed with the constellation secret.
 * // No database needed — verification recomputes the HMAC.
 *
 * @param email - User's email address.
 * @param secret - The constellation's HMAC signing secret.
 * @returns HMAC-signed reset token string.
 */
function generateResetToken(email: string, secret: string): string {
  const payload = {
    email: email.toLowerCase().trim(),
    iat: Date.now(),
    purpose: 'mfa-reset',
  };
  const payloadEncoded = base64urlEncode(JSON.stringify(payload));
  const signature = createHmac('sha256', secret).update(payloadEncoded).digest('hex');
  return `${payloadEncoded}.${signature}`;
}

/**
 * Verify an HMAC-signed reset token and extract the email.
 *
 * // Why: Validate HMAC integrity, check TTL, and verify purpose field
 * // to prevent cross-use with other HMAC tokens in the system.
 *
 * @param resetToken - The token to verify.
 * @param secret - The constellation's HMAC signing secret.
 * @returns The email address if valid, or null.
 */
function verifyResetToken(resetToken: string, secret: string): string | null {
  const dotIndex = resetToken.indexOf('.');
  if (dotIndex === -1) return null;

  const payloadEncoded = resetToken.substring(0, dotIndex);
  const providedSignature = resetToken.substring(dotIndex + 1);

  const expectedSignature = createHmac('sha256', secret)
    .update(payloadEncoded)
    .digest('hex');

  // Why: Timing-safe comparison prevents signature oracle attacks.
  const expected = Buffer.from(expectedSignature, 'hex');
  const provided = Buffer.from(providedSignature, 'hex');
  if (expected.length !== provided.length || !timingSafeEqual(expected, provided)) {
    return null;
  }

  let payload: { email?: string; iat?: number; purpose?: string };
  try {
    payload = JSON.parse(base64urlDecode(payloadEncoded)) as {
      email?: string;
      iat?: number;
      purpose?: string;
    };
  } catch {
    return null;
  }

  if (payload.purpose !== 'mfa-reset') return null;
  if (!payload.email || !payload.iat) return null;

  const age = Date.now() - payload.iat;
  if (age < 0 || age > RESET_TOKEN_TTL_MS) return null;

  return payload.email;
}

// ─── Handlers ────────────────────────────────────────────────────────────────

/**
 * Handle POST /idp/mfa/reset-request.
 *
 * // Why: User-initiated reset. They provide their valid access token,
 * // we generate a time-limited reset link and send it to their email.
 * // This proves they still control the email address.
 *
 * @param event - API Gateway proxy event with JSON body containing { token }.
 * @returns API Gateway proxy result.
 */
export async function handleResetRequest(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  try {
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

    const result = await verifyToken(token, keyStore);
    if (!result.valid) {
      return jsonResponse(401, { error: 'Invalid or expired token', reason: result.reason });
    }

    const config = await loadConfig();

    // Generate reset token and send email
    // Why: Use signing key secret instead of constellationId for HMAC strength.
    const currentKey = await keyStore.getCurrentKey();
    const resetToken = generateResetToken(result.email, currentKey.secret);
    const resetUrl = `${config.loginUrl}?mfaReset=${encodeURIComponent(resetToken)}`;

    await sendMfaResetEmail({
      to: result.email,
      resetUrl,
      constellationName: config.constellationId,
      fromAddress: config.sesFromAddress,
      fromName: config.sesFromName,
    });

    console.log(`MFA reset email sent to ${result.email}`);

    return jsonResponse(200, { status: 'sent' });
  } catch (err: unknown) {
    console.error('mfa-reset-request handler error:', err);
    return jsonResponse(500, { error: 'Internal server error' });
  }
}

/**
 * Handle POST /idp/mfa/reset-confirm.
 *
 * // Why: The user clicked the reset link in their email. We verify the
 * // HMAC-signed token, check TTL, and delete their MFA enrollment.
 * // They can then re-enroll from scratch.
 *
 * @param event - API Gateway proxy event with JSON body containing { resetToken }.
 * @returns API Gateway proxy result.
 */
export async function handleResetConfirm(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  try {
    if (!event.body) {
      return jsonResponse(400, { error: 'Request body is required' });
    }

    let body: { resetToken?: string };
    try {
      body = JSON.parse(event.body) as { resetToken?: string };
    } catch {
      return jsonResponse(400, { error: 'Invalid JSON in request body' });
    }

    const resetToken = body.resetToken?.trim();
    if (!resetToken) {
      return jsonResponse(400, { error: 'resetToken is required' });
    }

    // Why: Use signing key secret for HMAC verification (matches generation).
    const currentKey = await keyStore.getCurrentKey();
    const email = verifyResetToken(resetToken, currentKey.secret);
    if (!email) {
      return jsonResponse(401, { error: 'Invalid or expired reset token' });
    }

    await deleteMfaEnrollment(email);
    console.log(`MFA enrollment reset for ${email}`);

    return jsonResponse(200, { status: 'reset' });
  } catch (err: unknown) {
    console.error('mfa-reset-confirm handler error:', err);
    return jsonResponse(500, { error: 'Internal server error' });
  }
}

/**
 * Handle POST /admin/reset-mfa.
 *
 * // Why: Admin-initiated reset for support escalations when the user
 * // can't perform self-service reset. REQUIRES a valid IdP access token
 * // from an authorized domain. Without authentication, anyone who discovers
 * // this endpoint could reset any user's MFA — a critical security flaw.
 *
 * @param event - API Gateway proxy event with JSON body containing { token, email }.
 * @returns API Gateway proxy result.
 */
export async function handleAdminReset(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  try {
    if (!event.body) {
      return jsonResponse(400, { error: 'Request body is required' });
    }

    let body: { token?: string; email?: string };
    try {
      body = JSON.parse(event.body) as { token?: string; email?: string };
    } catch {
      return jsonResponse(400, { error: 'Invalid JSON in request body' });
    }

    // Why: Require a valid access token to authenticate the admin.
    // This prevents unauthenticated MFA resets — the original code accepted
    // just { email } with no authentication, meaning anyone who knew the
    // endpoint could reset any user's MFA.
    const token = body.token?.trim();
    if (!token) {
      return jsonResponse(400, { error: 'Token is required for admin operations' });
    }

    const result = await verifyToken(token, keyStore);
    if (!result.valid) {
      return jsonResponse(401, { error: 'Invalid or expired token', reason: result.reason });
    }

    // Why: Verify the admin's domain is still authorized.
    const config = await loadConfig();
    if (!isDomainAllowed(result.email, config.allowedDomains)) {
      return jsonResponse(403, { error: 'Email domain is not authorized for admin operations' });
    }

    const email = body.email?.trim().toLowerCase();
    if (!email) {
      return jsonResponse(400, { error: 'Email is required' });
    }

    await deleteMfaEnrollment(email);
    console.log(`MFA enrollment admin-reset for ${email} by ${result.email}`);

    return jsonResponse(200, { status: 'reset' });
  } catch (err: unknown) {
    console.error('mfa-admin-reset handler error:', err);
    return jsonResponse(500, { error: 'Internal server error' });
  }
}

/**
 * Lambda handler — routes based on the resource path in the API Gateway event.
 *
 * // Why: A single Lambda handles all three MFA reset paths. API Gateway
 * // routes different paths to the same Lambda; we switch on the resource
 * // path to dispatch to the right handler function. This keeps deployment
 * // simple while maintaining clean separation of concerns in the code.
 *
 * @param event - API Gateway proxy event.
 * @returns API Gateway proxy result.
 */
export async function handler(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  const path = event.path || event.resource || '';

  if (path.endsWith('/reset-request')) {
    return handleResetRequest(event);
  } else if (path.endsWith('/reset-confirm')) {
    return handleResetConfirm(event);
  } else if (path.endsWith('/reset-mfa')) {
    return handleAdminReset(event);
  }

  return jsonResponse(404, { error: `Unknown path: ${path}` });
}
