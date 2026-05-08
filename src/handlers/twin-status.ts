/**
 * UDT Identity Provider — Twin Status Handler
 *
 * POST /idp/twin-status
 *
 * Check the current status of a user's twin. Called by the SPA to poll
 * twin readiness after provisioning is kicked off.
 *
 * // Why: The SPA needs a lightweight way to check if the twin is alive
 * // without re-running the full login flow. This endpoint verifies the
 * // token (fast) and queries the Animator for twin status.
 *
 * @module handlers/twin-status
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { loadConfig, createKeyStore } from '../config.js';
import { verifyToken } from '../token.js';
import { deriveTwinId } from '../twin-id.js';
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
 * Lambda handler for POST /idp/twin-status.
 *
 * // Why: POST not GET because the token is in the body (not a query param
 * // that would show up in logs/referer headers). Lightweight check — just
 * // verify token + query Animator /admin/twins.
 *
 * Input: { token: string }
 * Output: { twinId, status } where status is "alive"|"starting"|"spawning"|"not_found"|"unknown"
 */
export async function handler(
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
      return jsonResponse(400, { error: 'Invalid JSON' });
    }

    const token = body.token?.trim();
    if (!token) {
      return jsonResponse(400, { error: 'Token is required' });
    }

    const result = await verifyToken(token, keyStore);
    if (!result.valid) {
      return jsonResponse(401, { error: 'Invalid token' });
    }

    const twinId = deriveTwinId(result.email);
    const config = await loadConfig();

    // Why: Quick query to Animator with a tight timeout. This is called
    // by the SPA every 5 seconds during provisioning — must be fast.
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 3_000);

      const response = await fetch(`${config.animatorUrl}/admin/twins`, {
        signal: controller.signal,
      });
      clearTimeout(timeout);

      if (!response.ok) {
        return jsonResponse(200, { twinId, status: 'unknown' });
      }

      const data = (await response.json()) as { twins: Array<{ twinId: string; status: string }> };
      const twin = data.twins.find((t) => t.twinId === twinId);

      return jsonResponse(200, {
        twinId,
        status: twin?.status ?? 'not_found',
      });
    } catch {
      return jsonResponse(200, { twinId, status: 'unknown' });
    }
  } catch (err: unknown) {
    console.error('twin-status handler error:', err);
    return jsonResponse(500, { error: 'Internal server error' });
  }
}
