/**
 * BangAuth — In-Memory Key Store Adapter
 *
 * Generates signing keys on boot and stores them in memory. No persistence —
 * every restart generates new keys. Perfect for dev/demo/constellation MVP.
 *
 * // Why: For a containerized constellation, we don't need persistent keys.
 * // Each container generates its own keys on boot. Tokens are short-lived
 * // (session-scoped), so restart = new keys is acceptable. This removes the
 * // dependency on AWS Secrets Manager for the standalone HTTP service.
 *
 * @module adapters/keys-memory
 */

import { randomBytes } from 'node:crypto';
import type { SigningKey, SigningKeyInfo, KeyStore } from '../types.js';

/**
 * In-memory key store — generates keys on construction, stores in RAM.
 */
export class MemoryKeyStore implements KeyStore {
  private keys: Map<string, SigningKey> = new Map();
  private currentKid: string;

  constructor() {
    // Why: Generate a single key on boot. kid format: k-{timestamp}
    // so each restart gets a unique kid. Algorithm: HS256 (HMAC-SHA256).
    this.currentKid = `k-${Date.now()}`;
    const key = this.generateKey(this.currentKid);
    this.keys.set(this.currentKid, key);

    console.log(`🔑 Generated signing key: ${this.currentKid}`);
  }

  /**
   * Generate a new signing key.
   *
   * // Why: 256-bit random secret (32 bytes) for HMAC-SHA256. The key is
   * // hex-encoded for easy storage and transmission. Expiration is set to
   * // 30 days out — in practice, container restart cycles keys more frequently.
   */
  private generateKey(kid: string): SigningKey {
    const secret = randomBytes(32).toString('hex'); // 256 bits
    const now = new Date();
    const expiresAt = new Date(now.getTime() + 30 * 24 * 60 * 60 * 1000); // 30 days

    return {
      kid,
      alg: 'HS256',
      secret,
      createdAt: now.toISOString(),
      expiresAt: expiresAt.toISOString(),
      active: true,
    };
  }

  /**
   * Get a specific key by kid.
   */
  async getKey(kid: string): Promise<SigningKey | null> {
    return this.keys.get(kid) ?? null;
  }

  /**
   * Get the current active signing key.
   */
  async getCurrentKey(): Promise<SigningKey> {
    const key = this.keys.get(this.currentKid);
    if (!key) {
      throw new Error(`Current signing key not found: ${this.currentKid}`);
    }
    return key;
  }

  /**
   * List all active keys (returns public metadata only).
   */
  async listActiveKeys(): Promise<SigningKeyInfo[]> {
    const activeKeys: SigningKeyInfo[] = [];
    for (const key of this.keys.values()) {
      if (key.active) {
        activeKeys.push({
          kid: key.kid,
          alg: key.alg,
          expiresAt: key.expiresAt,
        });
      }
    }
    return activeKeys;
  }
}
