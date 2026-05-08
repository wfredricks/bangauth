/**
 * UDT Identity Provider — Configuration Loader
 *
 * Loads IdP configuration from AWS SSM Parameter Store and signing keys from
 * AWS Secrets Manager. Both are cached in module-level variables with a
 * 5-minute TTL to minimize AWS API calls during warm Lambda invocations.
 *
 * // Why: Lambda cold starts hit SSM/Secrets Manager once, then warm invocations
 * // reuse cached values. This keeps latency low (~1ms for cached reads vs ~50ms
 * // for SSM) and costs down (SSM charges per API call). The 5-minute cache means
 * // config changes propagate within 5 minutes without redeployment.
 *
 * @module config
 */

import { SSMClient, GetParameterCommand } from '@aws-sdk/client-ssm';
import {
  SecretsManagerClient,
  GetSecretValueCommand,
  ListSecretsCommand,
} from '@aws-sdk/client-secrets-manager';
import type { IdPConfig, SigningKey, SigningKeyInfo, KeyStore } from './types.js';

// ─── AWS Clients ─────────────────────────────────────────────────────────────

// Why: Clients are module-level singletons — Lambda reuses them across invocations.
// This avoids re-establishing connections on every request.
const ssm = new SSMClient({});
const secrets = new SecretsManagerClient({});

// ─── Cache Infrastructure ────────────────────────────────────────────────────

/**
 * Cache TTL in milliseconds (5 minutes).
 *
 * // Why: 5 minutes balances freshness with cost. Config changes are rare
 * // (domain list updates, constellation changes) and a 5-minute delay is
 * // acceptable. For emergencies, redeploy the Lambda to force a cold start.
 */
const CACHE_TTL_MS = 5 * 60 * 1000;

/** Cached IdP configuration. */
let cachedConfig: IdPConfig | null = null;
/** Timestamp when config cache was last populated. */
let configCachedAt = 0;

/** Cached current key ID. */
let cachedCurrentKid: string | null = null;
/** Timestamp when current kid cache was last populated. */
let kidCachedAt = 0;

/** Cached signing keys by kid. */
const keyCache = new Map<string, { key: SigningKey; cachedAt: number }>();

// ─── SSM Helpers ─────────────────────────────────────────────────────────────

/**
 * Read a single SSM parameter value.
 *
 * // Why: Thin wrapper that handles the AWS SDK ceremony. Each SSM parameter
 * // is a simple string — we parse/split as needed at the caller level.
 *
 * @param path - The SSM parameter path (e.g., "/udt/idp/allowedDomains").
 * @returns The parameter value string.
 * @throws If the parameter doesn't exist or can't be read.
 */
async function getParam(path: string): Promise<string> {
  const result = await ssm.send(
    new GetParameterCommand({ Name: path, WithDecryption: true }),
  );
  const value = result.Parameter?.Value;
  if (!value) {
    throw new Error(`SSM parameter not found or empty: ${path}`);
  }
  return value;
}

// ─── Config Loader ───────────────────────────────────────────────────────────

/**
 * Load the IdP configuration from SSM Parameter Store.
 *
 * // Why: All runtime config lives in SSM so operators can change behavior
 * // (add domains, update URLs) without redeploying code. The cache prevents
 * // hitting SSM on every single request.
 *
 * @returns The current IdP configuration (may be cached).
 */
export async function loadConfig(): Promise<IdPConfig> {
  const now = Date.now();
  if (cachedConfig && now - configCachedAt < CACHE_TTL_MS) {
    return cachedConfig;
  }

  // Why: Parallel fetch — all parameters are independent, so we grab them
  // concurrently to minimize cold-start latency. MFA params use safe defaults
  // so existing deployments work without adding new SSM parameters.
  const [
    allowedDomainsRaw,
    constellationId,
    animatorUrl,
    sesFromAddress,
    sesFromName,
    loginUrl,
    mfaPolicy,
    mfaIssuer,
  ] = await Promise.all([
    getParam('/udt/idp/allowedDomains'),
    getParam('/udt/idp/constellationId'),
    getParam('/udt/idp/animatorUrl'),
    getParam('/udt/idp/ses/fromAddress'),
    getParam('/udt/idp/ses/fromName'),
    getParam('/udt/idp/loginUrl'),
    getParam('/udt/idp/mfaPolicy').catch(() => 'optional'),
    getParam('/udt/idp/mfaIssuer').catch(() => ''),
  ]);

  // Why: Default mfaIssuer to constellationId if not explicitly set.
  // Most deployments won't bother setting a separate issuer name.
  const resolvedMfaIssuer = mfaIssuer || constellationId;

  cachedConfig = {
    allowedDomains: allowedDomainsRaw.split(',').map((d) => d.trim()).filter(Boolean),
    constellationId,
    animatorUrl,
    sesFromAddress,
    sesFromName,
    loginUrl,
    mfaPolicy: mfaPolicy as 'required' | 'optional' | 'off',
    mfaIssuer: resolvedMfaIssuer,
  };
  configCachedAt = now;

  return cachedConfig;
}

// ─── Key Store Implementation ────────────────────────────────────────────────

/**
 * Read a signing key from Secrets Manager by kid.
 *
 * // Why: Each key is stored as a separate secret so that rotation can create
 * // a new secret without touching the old one. Keys are cached individually
 * // because verification looks up by kid (from the token), not by "current."
 *
 * @param kid - The key ID (e.g., "k-2026-05").
 * @returns The signing key, or null if not found.
 */
async function fetchKey(kid: string): Promise<SigningKey | null> {
  const now = Date.now();
  const cached = keyCache.get(kid);
  if (cached && now - cached.cachedAt < CACHE_TTL_MS) {
    return cached.key;
  }

  try {
    const result = await secrets.send(
      new GetSecretValueCommand({ SecretId: `/udt/idp/keys/${kid}` }),
    );
    if (!result.SecretString) return null;

    const key = JSON.parse(result.SecretString) as SigningKey;
    keyCache.set(kid, { key, cachedAt: now });
    return key;
  } catch (err: unknown) {
    // Why: ResourceNotFoundException means the key doesn't exist yet
    // (e.g., looking up next month's key before rotation). That's not an error,
    // it's just "not found."
    if (err instanceof Error && err.name === 'ResourceNotFoundException') {
      return null;
    }
    throw err;
  }
}

/**
 * Get the current key ID from SSM.
 *
 * // Why: The "current" key is a pointer in SSM, not hardcoded. This lets
 * // the rotation handler atomically switch which key is used for new tokens
 * // by updating a single SSM parameter.
 *
 * @returns The current key ID (e.g., "k-2026-05").
 */
async function getCurrentKid(): Promise<string> {
  const now = Date.now();
  if (cachedCurrentKid && now - kidCachedAt < CACHE_TTL_MS) {
    return cachedCurrentKid;
  }

  cachedCurrentKid = await getParam('/udt/idp/currentKid');
  kidCachedAt = now;
  return cachedCurrentKid;
}

/**
 * Create a KeyStore instance backed by AWS Secrets Manager.
 *
 * // Why: The KeyStore interface decouples handlers from AWS specifics.
 * // Tests inject a mock store; production uses this factory.
 *
 * @returns A KeyStore implementation that reads from Secrets Manager.
 */
export function createKeyStore(): KeyStore {
  return {
    async getKey(kid: string): Promise<SigningKey | null> {
      return fetchKey(kid);
    },

    async getCurrentKey(): Promise<SigningKey> {
      const kid = await getCurrentKid();
      const key = await fetchKey(kid);
      if (!key) {
        throw new Error(`Current signing key not found: ${kid}`);
      }
      return key;
    },

    async listActiveKeys(): Promise<SigningKeyInfo[]> {
      // Why: List secrets matching our prefix, then fetch each to check active status.
      // This is called rarely (GET /idp/keys) so the extra API calls are acceptable.
      const listResult = await secrets.send(
        new ListSecretsCommand({
          Filters: [{ Key: 'name', Values: ['/udt/idp/keys/'] }],
        }),
      );

      const activeKeys: SigningKeyInfo[] = [];
      const secretNames = listResult.SecretList?.map((s) => s.Name).filter(Boolean) ?? [];

      for (const name of secretNames) {
        // Extract kid from secret name: "/udt/idp/keys/k-2026-05" → "k-2026-05"
        const kid = name!.split('/').pop()!;
        const key = await fetchKey(kid);
        if (key?.active) {
          activeKeys.push({
            kid: key.kid,
            alg: key.alg,
            expiresAt: key.expiresAt,
          });
        }
      }

      return activeKeys;
    },
  };
}

/**
 * Clear all caches. Useful for testing and forced refresh.
 *
 * // Why: Tests need deterministic behavior without stale cache state.
 * // Also useful if an operator needs to force a config reload.
 */
export function clearCache(): void {
  cachedConfig = null;
  configCachedAt = 0;
  cachedCurrentKid = null;
  kidCachedAt = 0;
  keyCache.clear();
}
