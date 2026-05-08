/**
 * UDT Identity Provider — Key Rotation Handler
 *
 * EventBridge-triggered handler that runs on the 1st of each month.
 * Generates a new signing key, stores it, updates the active key pointer,
 * and re-issues tokens to all active twins.
 *
 * // Why: Monthly key rotation limits the blast radius of a compromised key.
 * // If a key leaks, it's only valid for the current month (plus 3-day grace).
 * // Automatic rotation means operators don't have to remember to do it —
 * // and automatic re-issuance means users don't have to re-request tokens.
 *
 * @module handlers/rotate
 */

import { randomBytes } from 'node:crypto';
import {
  SecretsManagerClient,
  CreateSecretCommand,
} from '@aws-sdk/client-secrets-manager';
import { SSMClient, PutParameterCommand } from '@aws-sdk/client-ssm';
import { loadConfig } from '../config.js';
import { generateToken } from '../token.js';
import { sendTokenEmail } from '../email.js';
import type { SigningKey } from '../types.js';

// Why: Module-level clients for Lambda reuse.
const secretsManager = new SecretsManagerClient({});
const ssm = new SSMClient({});

/**
 * Compute the month string for the current date.
 *
 * // Why: Duplicated from token.ts intentionally — the rotation handler
 * // should not depend on the token module's currentMonth() because it
 * // might need to generate keys for arbitrary months in the future.
 */
function getMonthString(date: Date = new Date()): string {
  return `${date.getFullYear()}-${String(date.getMonth() + 1).padStart(2, '0')}`;
}

/**
 * Compute the "valid through" date string for the token email.
 *
 * // Why: Same logic as request-token handler but for the rotated month.
 */
function computeValidThrough(): string {
  const now = new Date();
  const nextMonth = new Date(now.getFullYear(), now.getMonth() + 1, 3);
  const monthNames = [
    'January', 'February', 'March', 'April', 'May', 'June',
    'July', 'August', 'September', 'October', 'November', 'December',
  ];
  return `${monthNames[nextMonth.getMonth()]} ${nextMonth.getDate()}, ${nextMonth.getFullYear()}`;
}

/**
 * Generate a new signing key for the given month.
 *
 * // Why: 256-bit random secret provides 128-bit security level with HMAC-SHA256.
 * // That's well beyond brute-force feasibility for our threat model.
 *
 * @param month - The month this key covers (e.g., "2026-06").
 * @returns A new SigningKey with a random secret.
 */
function createSigningKey(month: string): SigningKey {
  const kid = `k-${month}`;
  const now = new Date();
  // Key expires on the 4th of the following month (covers the 3-day grace period)
  const [yearStr, monthStr] = month.split('-');
  const monthNum = parseInt(monthStr, 10);
  const year = parseInt(yearStr, 10);
  const expiresAt = new Date(year, monthNum, 4).toISOString(); // monthNum is 0-indexed +1, so this is next month

  return {
    kid,
    alg: 'HS256',
    secret: randomBytes(32).toString('hex'),
    createdAt: now.toISOString(),
    expiresAt,
    active: true,
  };
}

/**
 * Fetch active twins from the Animator service.
 *
 * // Why: We need the list of active twins to re-issue tokens after rotation.
 * // The Animator is the source of truth for twin lifecycle — we ask it
 * // "who's active?" and re-issue tokens for each one.
 *
 * @param animatorUrl - Base URL of the Animator service.
 * @returns Array of twin objects with email addresses.
 */
async function fetchActiveTwins(
  animatorUrl: string,
): Promise<Array<{ userId: string; email?: string }>> {
  try {
    const response = await fetch(`${animatorUrl}/admin/twins`, {
      method: 'GET',
      headers: { 'Content-Type': 'application/json' },
    });

    if (!response.ok) {
      console.error(`Animator /admin/twins returned ${response.status}`);
      return [];
    }

    const data = (await response.json()) as {
      twins?: Array<{ userId: string; email?: string }>;
    };
    return data.twins ?? [];
  } catch (err: unknown) {
    console.error('Failed to fetch active twins:', err);
    return [];
  }
}

/**
 * Lambda handler for EventBridge monthly rotation.
 *
 * // Why: This is the "cron job" of the IdP. Every month:
 * //   1. Create a new signing key
 * //   2. Store it in Secrets Manager
 * //   3. Update the active key pointer in SSM
 * //   4. Re-issue tokens to all active twins
 * //   5. Log a summary
 * //
 * // If step 4 partially fails (some emails bounce), that's OK — users can
 * // always request a new token manually via /idp/request-token.
 *
 * @param _event - EventBridge scheduled event (unused — we derive month from current date).
 */
export async function handler(
  _event: unknown,
): Promise<void> {
  const month = getMonthString();
  const kid = `k-${month}`;

  console.log(`Starting key rotation for month ${month}`);

  // Step 1: Generate new signing key
  const newKey = createSigningKey(month);

  // Step 2: Store in Secrets Manager
  try {
    await secretsManager.send(
      new CreateSecretCommand({
        Name: `/udt/idp/keys/${kid}`,
        Description: `UDT IdP signing key for ${month}`,
        SecretString: JSON.stringify(newKey),
      }),
    );
    console.log(`Created secret /udt/idp/keys/${kid}`);
  } catch (err: unknown) {
    // Why: If the secret already exists, it might be a re-run of the same month.
    // Log and continue — the key is already there.
    if (err instanceof Error && err.name === 'ResourceExistsException') {
      console.warn(`Secret /udt/idp/keys/${kid} already exists — skipping creation`);
    } else {
      throw err;
    }
  }

  // Step 3: Update SSM current key pointer
  await ssm.send(
    new PutParameterCommand({
      Name: '/udt/idp/currentKid',
      Value: kid,
      Type: 'String',
      Overwrite: true,
    }),
  );
  console.log(`Updated /udt/idp/currentKid to ${kid}`);

  // Step 4: Re-issue tokens to active twins
  const config = await loadConfig();
  const twins = await fetchActiveTwins(config.animatorUrl);
  const validThrough = computeValidThrough();

  let sent = 0;
  let failed = 0;

  for (const twin of twins) {
    if (!twin.email) {
      console.log(`Skipping twin ${twin.userId} — no email address`);
      continue;
    }

    try {
      const token = generateToken(twin.email, month, newKey, config.constellationId);

      await sendTokenEmail({
        to: twin.email,
        token,
        constellationName: config.constellationId,
        loginUrl: config.loginUrl,
        validThrough,
        fromAddress: config.sesFromAddress,
        fromName: config.sesFromName,
      });

      sent++;
    } catch (err: unknown) {
      console.error(`Failed to send token to ${twin.email}:`, err);
      failed++;
    }
  }

  // Step 5: Log rotation summary
  console.log(JSON.stringify({
    event: 'key_rotation_complete',
    month,
    kid,
    totalTwins: twins.length,
    tokensSent: sent,
    tokensFailed: failed,
  }));
}
