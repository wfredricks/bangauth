/**
 * UDT Identity Provider — Login Handler
 *
 * POST /idp/login
 *
 * Verifies a token and returns authentication status + twin status.
 * Does NOT provision twins — that's the SPA's job via POST /idp/provision.
 *
 * // Why: Login must be fast (< 100ms). The old design called the Animator's
 * // /admin/provision which takes 10-60 seconds (Fargate task spawn). Decoupling
 * // login from provisioning means the user sees instant authentication, then
 * // the SPA handles twin readiness with a spinner and async polling.
 *
 * @module handlers/login
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { loadConfig, createKeyStore } from '../config.js';
import { verifyToken } from '../token.js';
import { isDomainAllowed } from '../domain.js';
import { deriveTwinId } from '../twin-id.js';
import { getMfaEnrollment } from '../mfa-store.js';
import { generateMfaSession } from '../mfa-session.js';
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
 * Check twin status via the Animator service (lightweight, no provisioning).
 *
 * // Why: Login just needs to know IF the twin exists and its current status.
 * // It does NOT spawn twins. The SPA calls POST /idp/provision separately
 * // if the twin doesn't exist. This keeps login fast (< 100ms).
 *
 * @param animatorUrl - Base URL of the Animator service.
 * @param twinId - The deterministic twin ID.
 * @returns Twin status or 'not_found'.
 */
async function checkTwinStatus(
  animatorUrl: string,
  twinId: string,
): Promise<string> {
  try {
    const controller = new AbortController();
    const timeout = setTimeout(() => controller.abort(), 3_000);

    const response = await fetch(`${animatorUrl}/admin/twins`, {
      signal: controller.signal,
    });
    clearTimeout(timeout);

    if (!response.ok) return 'unknown';

    const data = (await response.json()) as { twins: Array<{ twinId: string; status: string }> };
    const twin = data.twins.find((t) => t.twinId === twinId);
    return twin?.status ?? 'not_found';
  } catch {
    // Why: If Animator is unreachable, we still authenticate the user.
    // Twin status is best-effort — the SPA will handle provisioning.
    return 'unknown';
  }
}

/**
 * Lambda handler for POST /idp/login.
 *
 * // Why: This is where the rubber meets the road. A user pastes their token,
 * // we verify it cryptographically, check the domain is still allowed,
 * // derive their twinId, and provision their Digital Twin. If everything
 * // checks out, they're in.
 *
 * @param event - API Gateway proxy event with JSON body containing { token }.
 * @returns API Gateway proxy result with authentication status.
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

    // Verify token
    const result = await verifyToken(token, keyStore);

    if (!result.valid) {
      return jsonResponse(401, {
        authenticated: false,
        reason: result.reason,
      });
    }

    // Double-check domain is still allowed (could have been removed since token was issued)
    // Why: Belt-and-suspenders. The token was generated when the domain was allowed,
    // but an admin might have revoked access since then. Check again at login time.
    const config = await loadConfig();

    if (!isDomainAllowed(result.email, config.allowedDomains)) {
      return jsonResponse(403, {
        authenticated: false,
        reason: 'Email domain is no longer authorized',
      });
    }

    // ── MFA Check ──────────────────────────────────────────────────────────
    // Why: After verifying the access token, check if the user has MFA enrolled
    // or if the policy requires enrollment. If MFA is active, we return an
    // mfaSessionToken instead of completing login — the client must then call
    // POST /idp/mfa/verify with the TOTP code to finish authentication.
    const mfaEnrollment = await getMfaEnrollment(result.email);

    if (mfaEnrollment && mfaEnrollment.status === 'active') {
      // Why: User has active MFA — generate a short-lived session token
      // that carries their email through the TOTP verification step.
      // Use the signing key's secret (256-bit random) instead of constellationId
      // (short guessable string like "dla-piee") for HMAC integrity.
      const currentKey = await keyStore.getCurrentKey();
      const mfaSessionToken = generateMfaSession(result.email, currentKey.secret);
      return jsonResponse(200, {
        authenticated: true,
        mfaRequired: true,
        mfaChallenge: 'totp',
        mfaSessionToken,
      });
    }

    if (!mfaEnrollment && config.mfaPolicy === 'required') {
      // Why: Policy says MFA is mandatory but user hasn't enrolled yet.
      // Tell the client to redirect to the enrollment flow.
      return jsonResponse(200, {
        authenticated: true,
        mfaRequired: true,
        mfaChallenge: 'enroll',
      });
    }

    // No MFA required — check twin status (but don't provision)
    // Why: Login is authentication only. Provisioning is a separate concern
    // handled by the SPA via POST /idp/provision. This keeps login < 100ms.

    const twinId = deriveTwinId(result.email);
    const twinStatus = await checkTwinStatus(config.animatorUrl, twinId);

    console.log(`Login successful: ${result.email} → ${twinId} (twin: ${twinStatus})`);

    return jsonResponse(200, {
      authenticated: true,
      email: result.email,
      twinId,
      twinStatus,
      // Why: Tell the SPA what to do next based on twin status:
      // - "alive": redirect to chat immediately
      // - "not_found": call POST /idp/provision, then poll
      // - "starting"/"spawning"/"provisioning": poll until alive
      // - "unknown": Animator unreachable, try provision anyway
    });
  } catch (err: unknown) {
    console.error('login handler error:', err);
    return jsonResponse(500, {
      error: 'Internal server error',
    });
  }
}
