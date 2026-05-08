/**
 * Domain Allowlist Tests
 */

import { describe, it, expect } from 'vitest';
import { isDomainAllowed } from '../domain.js';

describe('Domain Allowlist', () => {
  const domains = ['credence.ai', 'test.com', 'gov.mil'];

  it('allows email from approved domain', () => {
    expect(isDomainAllowed('bill@credence.ai', domains)).toBe(true);
  });

  it('rejects email from unapproved domain', () => {
    expect(isDomainAllowed('hacker@evil.com', domains)).toBe(false);
  });

  it('is case-insensitive', () => {
    expect(isDomainAllowed('bill@CREDENCE.AI', domains)).toBe(true);
  });

  it('rejects empty email', () => {
    expect(isDomainAllowed('', domains)).toBe(false);
  });

  it('rejects email without @', () => {
    expect(isDomainAllowed('notanemail', domains)).toBe(false);
  });

  it('allows .mil domain', () => {
    expect(isDomainAllowed('soldier@gov.mil', domains)).toBe(true);
  });
});
