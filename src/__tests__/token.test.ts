/**
 * Token Engine Tests — core auth logic
 */

import { describe, it, expect } from 'vitest';
import {
  base64urlEncode,
  base64urlDecode,
  computeSignature,
  currentMonth,
  isMonthValid,
  generateToken,
  verifyToken,
} from '../token.js';
import { createTestKey, MemoryKeyStore } from '../adapters/memory-key-store.js';

describe('Token Engine', () => {

  describe('base64url encoding', () => {
    it('encodes and decodes roundtrip', () => {
      const original = 'hello world! special chars: +/=';
      const encoded = base64urlEncode(original);
      const decoded = base64urlDecode(encoded);
      expect(decoded).toBe(original);
    });

    it('produces URL-safe output', () => {
      const encoded = base64urlEncode('test+data/with=padding');
      expect(encoded).not.toContain('+');
      expect(encoded).not.toContain('/');
      expect(encoded).not.toContain('=');
    });
  });

  describe('HMAC signature', () => {
    it('produces consistent signatures', () => {
      const sig1 = computeSignature('payload', 'secret', 'HS256');
      const sig2 = computeSignature('payload', 'secret', 'HS256');
      expect(sig1).toBe(sig2);
    });

    it('different payloads produce different signatures', () => {
      const sig1 = computeSignature('payload1', 'secret', 'HS256');
      const sig2 = computeSignature('payload2', 'secret', 'HS256');
      expect(sig1).not.toBe(sig2);
    });

    it('different secrets produce different signatures', () => {
      const sig1 = computeSignature('payload', 'secret1', 'HS256');
      const sig2 = computeSignature('payload', 'secret2', 'HS256');
      expect(sig1).not.toBe(sig2);
    });
  });

  describe('month rotation', () => {
    it('currentMonth returns YYYY-MM format', () => {
      const month = currentMonth();
      expect(month).toMatch(/^\d{4}-\d{2}$/);
    });

    it('current month is valid', () => {
      expect(isMonthValid(currentMonth())).toBe(true);
    });

    it('future month is invalid', () => {
      expect(isMonthValid('2099-12')).toBe(false);
    });
  });

  describe('token generation + verification', () => {
    const key = createTestKey('k-test-token');
    const keyStore = new MemoryKeyStore(key);
    const month = currentMonth();
    const constellationId = 'test-constellation';

    it('generates a token that can be verified', async () => {
      const token = generateToken('alice@test.com', month, key, constellationId);
      expect(token).toBeDefined();
      expect(token.length).toBeGreaterThan(10);

      const result = await verifyToken(token, keyStore);
      expect(result.valid).toBe(true);
      expect(result.email).toBe('alice@test.com');
    });

    it('rejects tampered tokens', async () => {
      const token = generateToken('alice@test.com', month, key, constellationId);
      const tampered = token.slice(0, -5) + 'XXXXX';
      const result = await verifyToken(tampered, keyStore);
      expect(result.valid).toBe(false);
    });

    it('rejects tokens with wrong key store', async () => {
      const token = generateToken('alice@test.com', month, key, constellationId);
      const otherKey = createTestKey('k-other');
      const otherStore = new MemoryKeyStore(otherKey);
      const result = await verifyToken(token, otherStore);
      expect(result.valid).toBe(false);
    });

    it('tokens are deterministic for same email + month + key', () => {
      const t1 = generateToken('alice@test.com', month, key, constellationId);
      const t2 = generateToken('alice@test.com', month, key, constellationId);
      expect(t1).toBe(t2);
    });

    it('different emails produce different tokens', () => {
      const t1 = generateToken('alice@test.com', month, key, constellationId);
      const t2 = generateToken('bob@test.com', month, key, constellationId);
      expect(t1).not.toBe(t2);
    });
  });
});
