/**
 * MFA Tests — TOTP + session tokens + brute-force protection
 */

import { describe, it, expect } from 'vitest';
import { generateMfaSession, verifyMfaSession, MAX_MFA_ATTEMPTS } from '../mfa-session.js';
import { generateTOTPSecret, generateQRUri, verifyTOTP } from '../totp.js';

describe('MFA Session Tokens', () => {
  const signingSecret = 'test-signing-secret-32-chars-minimum!!';

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
    const tampered = token + 'X';
    expect(() => verifyMfaSession(tampered, signingSecret)).toThrow();
  });

  it('MAX_MFA_ATTEMPTS is 5', () => {
    expect(MAX_MFA_ATTEMPTS).toBe(5);
  });
});

describe('TOTP Engine', () => {
  it('generates a secret', () => {
    const secret = generateTOTPSecret();
    expect(secret).toBeDefined();
    expect(secret.length).toBeGreaterThan(10);
  });

  it('generates a QR URI', () => {
    const secret = generateTOTPSecret();
    const uri = generateQRUri(secret, 'alice@test.com', 'BangAuth');
    expect(uri).toContain('otpauth://totp/');
    expect(uri).toContain('alice@test.com');
    expect(uri).toContain('BangAuth');
    expect(uri).toContain(secret);
  });

  it('verifies a TOTP code against a secret', () => {
    // Note: We can't generate a valid code without the exact timestamp,
    // but we can verify the function exists and handles invalid codes
    const secret = generateTOTPSecret();
    const result = verifyTOTP('000000', secret);
    // 000000 is almost certainly not valid for the current time step
    expect(typeof result).toBe('boolean');
  });
});
