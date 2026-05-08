/**
 * Memory Key Store — in-memory signing key store for testing.
 *
 * Why: Tests need a KeyStore without AWS Secrets Manager.
 * This adapter holds keys in memory — same interface, no cloud dependency.
 */

import type { SigningKey, KeyStore, SigningKeyInfo } from '../types.js';
import { createHmac, randomBytes } from 'crypto';

/**
 * Create a test signing key.
 */
export function createTestKey(kid?: string): SigningKey {
  return {
    kid: kid || `k-test-${Date.now()}`,
    alg: 'HS256',
    secret: randomBytes(32).toString('hex'),
    createdAt: new Date().toISOString(),
    expiresAt: new Date(Date.now() + 365 * 86400000).toISOString(),
    active: true,
  };
}

/**
 * In-memory key store for testing.
 */
export class MemoryKeyStore implements KeyStore {
  private keys = new Map<string, SigningKey>();
  private currentKid: string;

  constructor(initialKey?: SigningKey) {
    const key = initialKey || createTestKey('k-test');
    this.keys.set(key.kid, key);
    this.currentKid = key.kid;
  }

  async getKey(kid: string): Promise<SigningKey | null> {
    return this.keys.get(kid) || null;
  }

  async getCurrentKey(): Promise<SigningKey> {
    const key = this.keys.get(this.currentKid);
    if (!key) throw new Error(`Current key not found: ${this.currentKid}`);
    return key;
  }

  async listActiveKeys(): Promise<SigningKeyInfo[]> {
    return Array.from(this.keys.values())
      .filter(k => k.active)
      .map(k => ({ kid: k.kid, alg: k.alg, expiresAt: k.expiresAt }));
  }

  /** Add a key (test helper) */
  addKey(key: SigningKey): void {
    this.keys.set(key.kid, key);
  }

  /** Set current key (test helper) */
  setCurrentKid(kid: string): void {
    this.currentKid = kid;
  }
}

/**
 * Create a memory key store with a default test key.
 */
export function createMemoryKeyStore(): { store: MemoryKeyStore; key: SigningKey } {
  const key = createTestKey('k-test');
  const store = new MemoryKeyStore(key);
  return { store, key };
}
