/**
 * Recovery Code Tests
 */

import { describe, it, expect } from 'vitest';
import { generateRecoveryCodes, hashRecoveryCode, verifyRecoveryCode } from '../recovery.js';

describe('Recovery Codes', () => {
  it('generates the requested number of codes', () => {
    const codes = generateRecoveryCodes(8);
    expect(codes).toHaveLength(8);
  });

  it('generates unique codes', () => {
    const codes = generateRecoveryCodes(10);
    const unique = new Set(codes);
    expect(unique.size).toBe(10);
  });

  it('codes are readable format (groups of 4)', () => {
    const codes = generateRecoveryCodes(1);
    // Recovery codes should be formatted for easy reading
    expect(codes[0].length).toBeGreaterThan(5);
  });

  it('hash is deterministic', () => {
    const h1 = hashRecoveryCode('ABCD-EFGH');
    const h2 = hashRecoveryCode('ABCD-EFGH');
    expect(h1).toBe(h2);
  });

  it('different codes produce different hashes', () => {
    const h1 = hashRecoveryCode('ABCD-EFGH');
    const h2 = hashRecoveryCode('IJKL-MNOP');
    expect(h1).not.toBe(h2);
  });

  it('verifyRecoveryCode finds matching code', () => {
    const codes = generateRecoveryCodes(5);
    const hashed = codes.map((code, i) => ({
      hash: hashRecoveryCode(code),
      used: false,
      usedAt: null,
      index: i,
    }));

    const matchIndex = verifyRecoveryCode(codes[2], hashed);
    expect(matchIndex).toBe(2);
  });

  it('verifyRecoveryCode returns -1 for no match', () => {
    const hashed = [{
      hash: hashRecoveryCode('REAL-CODE'),
      used: false,
      usedAt: null,
      index: 0,
    }];

    const matchIndex = verifyRecoveryCode('FAKE-CODE', hashed);
    expect(matchIndex).toBe(-1);
  });
});
