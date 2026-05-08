/**
 * Token Engine Tests — core auth logic
 *
 * Tests the pure functions: HMAC signing, base64url encoding,
 * token generation, verification, month rotation.
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
    const secret = 'test-secret-key-at-least-32-chars-long!!';

    it('generates a token that can be verified', () => {
      const token = generateToken('alice@test.com', secret);
      expect(token).toBeDefined();
      expect(token.length).toBeGreaterThan(10);

      const result = verifyToken(token, secret);
      expect(result.valid).toBe(true);
      expect(result.email).toBe('alice@test.com');
    });

    it('rejects tampered tokens', () => {
      const token = generateToken('alice@test.com', secret);
      const tampered = token.slice(0, -5) + 'XXXXX';
      const result = verifyToken(tampered, secret);
      expect(result.valid).toBe(false);
    });

    it('rejects tokens with wrong secret', () => {
      const token = generateToken('alice@test.com', secret);
      const result = verifyToken(token, 'wrong-secret-key-also-32-chars!!');
      expect(result.valid).toBe(false);
    });

    it('tokens are deterministic for same email + month', () => {
      const t1 = generateToken('alice@test.com', secret);
      const t2 = generateToken('alice@test.com', secret);
      expect(t1).toBe(t2);
    });

    it('different emails produce different tokens', () => {
      const t1 = generateToken('alice@test.com', secret);
      const t2 = generateToken('bob@test.com', secret);
      expect(t1).not.toBe(t2);
    });
  });
});
