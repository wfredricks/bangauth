/**
 * UDT Identity Provider — Provision Handler
 *
 * POST /idp/provision
 *
 * Triggers twin provisioning via the Animator. Called by the SPA after
 * login confirms the twin doesn't exist yet. Fire-and-forget — the SPA
 * polls twin status separately.
 *
 * // Why: Provisioning is decoupled from login because it takes 30-60 seconds
 * // (Fargate task spawn + Neo4j sidecar boot + health check). Login must be
 * // instant (< 100ms). The SPA calls provision async and shows a spinner
 * // while polling twin status.
 *
 * @module handlers/provision
 */

import type { APIGatewayProxyEvent, APIGatewayProxyResult } from 'aws-lambda';
import { loadConfig, createKeyStore } from '../config.js';
import { verifyToken } from '../token.js';
import { isDomainAllowed } from '../domain.js';
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
 * Lambda handler for POST /idp/provision.
 *
 * // Why: This is the "make me a twin" endpoint. The SPA calls this after
 * // login returns twinStatus: "not_found". It fires the provision request
 * // to the Animator and returns immediately — the Animator handles the
 * // actual Fargate task spawn asynchronously.
 *
 * Input: { token: string }
 * Output: { status: "provisioning", twinId } or { error }
 *
 * The SPA then polls GET /idp/twin-status?token=... until the twin is alive.
 *
 * @param event - API Gateway proxy event with JSON body containing { token }.
 * @returns API Gateway proxy result.
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
      return jsonResponse(400, { error: 'Invalid JSON in request body' });
    }

    const token = body.token?.trim();
    if (!token) {
      return jsonResponse(400, { error: 'Token is required' });
    }

    // Why: Must verify the token before provisioning — can't let unauthenticated
    // requests spawn Fargate tasks (that costs money).
    const result = await verifyToken(token, keyStore);
    if (!result.valid) {
      return jsonResponse(401, { error: 'Invalid token', reason: result.reason });
    }

    const config = await loadConfig();
    if (!isDomainAllowed(result.email, config.allowedDomains)) {
      return jsonResponse(403, { error: 'Email domain is no longer authorized' });
    }

    const twinId = deriveTwinId(result.email);

    // Why: Fire-and-forget. We send the provision request to the Animator
    // but don't wait for it to complete. The Animator will spawn the Fargate
    // task, and the SPA will poll twin status. We use a 5s timeout just to
    // confirm the Animator received the request.
    try {
      const controller = new AbortController();
      const timeout = setTimeout(() => controller.abort(), 5_000);

      const response = await fetch(`${config.animatorUrl}/admin/provision`, {
        method: 'POST',
        headers: { 'Content-Type': 'application/json' },
        body: JSON.stringify({
          userId: result.email.toLowerCase().trim().replace(/@/g, '-').replace(/\./g, '-'),
          fullName: result.email.split('@')[0],
          twinType: 'personal',
        }),
        signal: controller.signal,
      });

      clearTimeout(timeout);

      if (response.ok) {
        const data = (await response.json()) as { status?: string; twinId?: string };
        console.log(`Provision accepted for ${result.email}: ${data.status}`);
        return jsonResponse(200, {
          status: data.status ?? 'provisioning',
          twinId,
          email: result.email,
        });
      } else {
        const errorText = await response.text();
        console.error(`Animator provision failed (${response.status}): ${errorText}`);
        return jsonResponse(200, {
          status: 'provisioning',
          twinId,
          email: result.email,
          note: 'Animator returned an error but provision may still be in progress',
        });
      }
    } catch (err: unknown) {
      if (err instanceof Error && err.name === 'AbortError') {
        // Why: 5s timeout fired. Animator is processing — the provision
        // request was sent. SPA should poll twin status.
        console.log(`Provision request sent for ${twinId} — Animator is processing`);
        return jsonResponse(200, {
          status: 'provisioning',
          twinId,
          email: result.email,
        });
      }

      console.error('Provision error:', err);
      return jsonResponse(502, {
        error: 'Animator unreachable',
        twinId,
      });
    }
  } catch (err: unknown) {
    console.error('provision handler error:', err);
    return jsonResponse(500, { error: 'Internal server error' });
  }
}
