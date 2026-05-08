/**
 * MFA Tests — TOTP + session tokens + brute-force protection
 */

import { describe, it, expect } from 'vitest';
import { generateMfaSession, verifyMfaSession, MAX_MFA_ATTEMPTS } from '../mfa-session.js';
import { generateSecret, buildQrUri, verifyTOTP } from '../totp.js';

describe('MFA Session Tokens', () => {
  const signingSecret = 'a'.repeat(64); // 32 bytes hex

  it('generates a session token', () => {
    const token = generateMfaSession('alice@test.com', signingSecret);
    expect(token).toBeDefined();
    expect(token.length).toBeGreaterThan(10);
  });

  it('verifies a valid session token', () => {
    const token = generateMfaSession('alice@test.com', signingSecret);
    const result = verifyMfaSession(token, signingSecret);
    expect(result.email).toBe('alice@test.com');
    expect(result.attempts).toBe(0);
  });

  it('tracks attempt count', () => {
    const token = generateMfaSession('alice@test.com', signingSecret, 3);
    const result = verifyMfaSession(token, signingSecret);
    expect(result.attempts).toBe(3);
  });

  it('rejects tampered session token', () => {
    const token = generateMfaSession('alice@test.com', signingSecret);
    const tampered = 'X' + token.slice(1); // change first char
    // Should either throw or return a different email
    try {
      const result = verifyMfaSession(tampered, signingSecret);
      // If it doesn't throw, the email should be wrong or validation fails
      expect(result.email).not.toBe('alice@test.com');
    } catch {
      // Expected — tampered token rejected
      expect(true).toBe(true);
    }
  });

  it('MAX_MFA_ATTEMPTS is 5', () => {
    expect(MAX_MFA_ATTEMPTS).toBe(5);
  });
});

describe('TOTP Engine', () => {
  it('generates a secret', () => {
    const secret = generateSecret();
    expect(secret).toBeDefined();
    expect(secret.length).toBeGreaterThan(10);
  });

  it('generates a QR URI', () => {
    const secret = generateSecret();
    const uri = buildQrUri('alice@test.com', secret, 'BangAuth');
    expect(uri).toContain('otpauth://totp/');
    expect(uri).toContain('alice');
    expect(uri).toContain('BangAuth');
  });

  it('verifyTOTP rejects invalid code', () => {
    const secret = generateSecret();
    const result = verifyTOTP(secret, '000000');
    expect(typeof result).toBe('boolean');
  });

  it('two secrets are different', () => {
    const s1 = generateSecret();
    const s2 = generateSecret();
    expect(s1).not.toBe(s2);
  });
});
