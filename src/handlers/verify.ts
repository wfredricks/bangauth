/**
 * UDT Identity Provider — Verify Handler
 *
 * POST /idp/verify
 *
 * Standalone token verification endpoint. Returns token claims without
 * triggering twin provisioning. Useful for downstream services that need
 * to validate a token without the full login flow.
 *
 * // Why: Not every token check should provision a twin. The Animator might
 * // call this endpoint to verify an incoming request's token without
 * // creating a circular provisioning loop. API middleware, edge functions,
 * // and health checks all need verify without side effects.
 *
 * @module handlers/verify
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { createKeyStore } from '../config.js';
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
 * Lambda handler for POST /idp/verify.
 *
 * // Why: Pure verification — no side effects, no provisioning, no email sending.
 * // Takes a token, returns whether it's valid and what claims it contains.
 * // This is the building block for authorization middleware in other services.
 *
 * @param event - API Gateway proxy event with JSON body containing { token }.
 * @returns API Gateway proxy result with verification status and claims.
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
        verified: false,
        reason: result.reason,
      });
    }

    // Why: Include the derived twinId in the response so downstream services
    // don't need to recompute it. One source of truth for ID derivation.
    const twinId = deriveTwinId(result.email);

    return jsonResponse(200, {
      verified: true,
      email: result.email,
      domain: result.domain,
      twinId,
      month: result.month,
      kid: result.kid,
      alg: result.alg,
      constellationId: result.constellationId,
    });
  } catch (err: unknown) {
    console.error('verify handler error:', err);
    return jsonResponse(500, {
      error: 'Internal server error',
    });
  }
}
