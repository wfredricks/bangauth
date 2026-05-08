/**
 * UDT Identity Provider — Request Token Handler
 *
 * POST /idp/request-token
 *
 * Generates a deterministic access token for a validated email address and
 * delivers it via SES. This is the entry point for the authentication flow:
 * user provides email → IdP validates domain → generates token → sends email.
 *
 * // Why: Passwordless authentication via email tokens. The user proves identity
 * // by demonstrating access to their email inbox. No passwords to manage,
 * // no credentials to leak, no reset flows to build.
 *
 * @module handlers/request-token
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { loadConfig, createKeyStore } from '../config.js';
import { isDomainAllowed } from '../domain.js';
import { generateToken, currentMonth } from '../token.js';
import { sendTokenEmail, sendRejectionEmail } from '../email.js';
import type { ApiResponse } from '../types.js';

// Why: Reuse key store across warm invocations — it has its own internal cache.
const keyStore = createKeyStore();

/**
 * Build a JSON API response with standard headers.
 *
 * // Why: Consistent response shape across all handlers. CORS headers
 * // are included because API Gateway might not add them automatically
 * // depending on the integration type.
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
 * Validate that a string looks like a plausible email address.
 *
 * // Why: Basic format check prevents obvious garbage from hitting SSM/SES.
 * // This isn't RFC 5322 compliant — it's a sanity check, not a validator.
 * // The real validation is "can they receive email at this address?"
 */
function isValidEmail(email: string): boolean {
  return /^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email);
}

/**
 * Compute the "valid through" date string for the token email.
 *
 * // Why: Users need to know when their token expires. The token is valid
 * // through the end of the current month plus a 3-day grace period.
 * // We format it as a human-readable date like "June 3, 2026".
 */
function computeValidThrough(): string {
  const now = new Date();
  // Token is valid through the 3rd of next month (grace period)
  const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 3);
  const monthNames = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December',
  ];
  return `${monthNames[nextMonth.getMonth()]} ${nextMonth.getDate()}, ${nextMonth.getFullYear()}`;
}

/**
 * Lambda handler for POST /idp/request-token.
 *
 * // Why: This is the "front door" of the IdP. A user submits their email,
 * // we validate it, generate their monthly token, and email it to them.
 * // The token is deterministic, so requesting multiple times in the same
 * // month just re-sends the same token — no duplication, no confusion.
 *
 * @param event - API Gateway proxy event with JSON body containing { email }.
 * @returns API Gateway proxy result with status message.
 */
export async function handler(
  event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  try {
    // Parse request body
    if (!event.body) {
      return jsonResponse(400, { error: 'Request body is required' });
    }

    let body: { email?: string };
    try {
      body = JSON.parse(event.body) as { email?: string };
    } catch {
      return jsonResponse(400, { error: 'Invalid JSON in request body' });
    }

    const email = body.email?.toLowerCase().trim();
    if (!email) {
      return jsonResponse(400, { error: 'Email is required' });
    }

    if (!isValidEmail(email)) {
      return jsonResponse(400, { error: 'Invalid email format' });
    }

    // Load config and validate domain
    const config = await loadConfig();

    if (!isDomainAllowed(email, config.allowedDomains)) {
      // Why: Send a helpful rejection email so the user knows what to do.
      // Don't just show an error page — they might not understand why.
      // Point them to auth-support@udt-credence.ai for manual vetting.
      try {
        await sendRejectionEmail({
          to: email,
          fromAddress: config.sesFromAddress,
          fromName: config.sesFromName,
          constellationName: config.constellationId,
        });
      } catch (emailErr) {
        // Why: If we can't send the rejection email (e.g., SES sandbox limits),
        // still return the API error. The email is a courtesy, not a requirement.
        console.warn('Failed to send rejection email:', emailErr);
      }

      return jsonResponse(403, {
        error: 'Email domain is not authorized for this constellation. A message has been sent to your email with instructions.',
      });
    }

    // Generate deterministic token
    const key = await keyStore.getCurrentKey();
    const month = currentMonth();
    const token = generateToken(email, month, key, config.constellationId);

    // Send via email
    const validThrough = computeValidThrough();
    await sendTokenEmail({
      to: email,
      token,
      constellationName: config.constellationId,
      loginUrl: config.loginUrl,
      validThrough,
      fromAddress: config.sesFromAddress,
      fromName: config.sesFromName,
    });

    console.log(`Token sent to ${email} for month ${month}`);

    return jsonResponse(200, {
      status: 'sent',
      message: 'Check your email',
    });
  } catch (err: unknown) {
    console.error('request-token handler error:', err);
    return jsonResponse(500, {
      error: 'Internal server error',
    });
  }
}
