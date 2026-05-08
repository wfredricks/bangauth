/**
 * UDT Identity Provider — Keys Handler
 *
 * GET /idp/keys
 *
 * Returns the list of active signing keys with public metadata only.
 * No secret material is ever exposed through this endpoint.
 *
 * // Why: Transparency about which keys are active helps with debugging
 * // and monitoring. If a token fails verification, operators can check
 * // whether the key it references is still in the active set. This is
 * // analogous to a JWKS endpoint in OAuth2, but simpler.
 *
 * @module handlers/keys
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { createKeyStore } from '../config.js';
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
      // Why: Keys endpoint can be cached by clients for a short time.
      // 60 seconds is aggressive enough to catch rotation quickly.
      'Cache-Control': 'public, max-age=60',
    },
    body: JSON.stringify(body),
  };
}

/**
 * Lambda handler for GET /idp/keys.
 *
 * // Why: Public endpoint — no authentication required. This is intentional:
 * // knowing which key IDs exist and when they expire is not sensitive.
 * // The secrets (HMAC keys) are NEVER included in the response.
 *
 * @param _event - API Gateway proxy event (unused — no input needed).
 * @returns API Gateway proxy result with list of active key metadata.
 */
export async function handler(
  _event: APIGatewayProxyEvent,
): Promise<APIGatewayProxyResult> {
  try {
    const activeKeys = await keyStore.listActiveKeys();

    return jsonResponse(200, {
      keys: activeKeys,
      count: activeKeys.length,
    });
  } catch (err: unknown) {
    console.error('keys handler error:', err);
    return jsonResponse(500, {
      error: 'Internal server error',
    });
  }
}
