/**
 * UDT Identity Provider — MFA Enrollment Store
 *
 * Manages MFA enrollment data in AWS Secrets Manager. Each user's TOTP secret
 * and recovery code hashes are stored as a single secret, keyed by the SHA256
 * hash of their email address.
 *
 * // Why: We reuse Secrets Manager (already our key store) rather than adding
 * // a database. MFA enrollment data is security-sensitive (TOTP secrets are
 * // equivalent to passwords) so Secrets Manager's encryption-at-rest and
 * // access logging are exactly what we need. The email hash in the path
 * // prevents PII leakage in CloudTrail logs.
 *
 * @module mfa-store
 */

import { createHash } from 'node:crypto';
import {
  SecretsManagerClient,
  GetSecretValueCommand,
  CreateSecretCommand,
  UpdateSecretCommand,
  DeleteSecretCommand,
} from '@aws-sdk/client-secrets-manager';
import type { MfaEnrollment } from './types.js';
import { ssmPrefix } from './config.js';

// Why: Module-level singleton — reused across warm Lambda invocations.
const secrets = new SecretsManagerClient({});

// ─── Helpers ─────────────────────────────────────────────────────────────────

/**
 * Derive the Secrets Manager path for a user's MFA enrollment.
 *
 * // Why: We hash the email to avoid storing PII in the secret name itself.
 * // Secret names appear in CloudTrail, billing dashboards, and console listings —
 * // hashing keeps the email private while still being deterministic.
 *
 * @param email - User's email address.
 * @returns The Secrets Manager secret name for this user's MFA data.
 */
function mfaSecretPath(email: string): string {
  const emailHash = createHash('sha256')
    .update(email.toLowerCase().trim())
    .digest('hex');
  return `${ssmPrefix()}mfa/${emailHash}`;
}

// ─── Store Functions ─────────────────────────────────────────────────────────

/**
 * Retrieve a user's MFA enrollment from Secrets Manager.
 *
 * // Why: Called during login (to check if MFA is required) and during
 * // verification (to get the TOTP secret and recovery hashes). Returns null
 * // if the user has never enrolled — callers use this to branch into
 * // enrollment vs. verification flows.
 *
 * @param email - User's email address.
 * @returns The MFA enrollment data, or null if not enrolled.
 */
export async function getMfaEnrollment(email: string): Promise<MfaEnrollment | null> {
  try {
    const result = await secrets.send(
      new GetSecretValueCommand({ SecretId: mfaSecretPath(email) }),
    );
    if (!result.SecretString) return null;
    return JSON.parse(result.SecretString) as MfaEnrollment;
  } catch (err: unknown) {
    // Why: ResourceNotFoundException means the user has never enrolled.
    // That's a normal condition, not an error.
    if (err instanceof Error && err.name === 'ResourceNotFoundException') {
      return null;
    }
    throw err;
  }
}

/**
 * Save (create or update) a user's MFA enrollment in Secrets Manager.
 *
 * // Why: We try CreateSecret first, fall back to UpdateSecret if it already exists.
 * // This handles both initial enrollment and subsequent updates (e.g., activating
 * // a pending enrollment, regenerating recovery codes).
 *
 * @param email - User's email address.
 * @param data - The MFA enrollment data to store.
 */
export async function saveMfaEnrollment(email: string, data: MfaEnrollment): Promise<void> {
  const secretId = mfaSecretPath(email);
  const secretString = JSON.stringify(data);

  try {
    await secrets.send(
      new CreateSecretCommand({
        Name: secretId,
        SecretString: secretString,
        Description: 'UDT IdP MFA enrollment data',
      }),
    );
  } catch (err: unknown) {
    // Why: ResourceExistsException means we're updating an existing enrollment.
    // Fall through to UpdateSecret.
    if (err instanceof Error && err.name === 'ResourceExistsException') {
      await secrets.send(
        new UpdateSecretCommand({
          SecretId: secretId,
          SecretString: secretString,
        }),
      );
      return;
    }
    throw err;
  }
}

/**
 * Delete a user's MFA enrollment from Secrets Manager.
 *
 * // Why: Used during MFA reset — removes the enrollment entirely so the user
 * // can re-enroll from scratch. ForceDeleteWithoutRecovery skips the 7-day
 * // recovery window because MFA data should be gone immediately when reset.
 *
 * @param email - User's email address.
 */
export async function deleteMfaEnrollment(email: string): Promise<void> {
  try {
    await secrets.send(
      new DeleteSecretCommand({
        SecretId: mfaSecretPath(email),
        ForceDeleteWithoutRecovery: true,
      }),
    );
  } catch (err: unknown) {
    // Why: If the secret doesn't exist, the delete is a no-op. The user
    // might be resetting MFA that was already reset, or never enrolled.
    if (err instanceof Error && err.name === 'ResourceNotFoundException') {
      return;
    }
    throw err;
  }
}
