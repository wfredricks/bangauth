/**
 * Email Builder Tests
 */

import { describe, it, expect } from 'vitest';
import { buildTokenEmail } from '../email.js';

describe('Email Builder', () => {
  it('builds email with token link', () => {
    const email = buildTokenEmail({
      to: 'alice@test.com',
      token: 'abc123',
      loginUrl: 'https://myapp.com/login',
      fromName: 'My App',
    });

    expect(email.to).toBe('alice@test.com');
    expect(email.subject).toBeDefined();
    expect(email.html).toContain('abc123');
    expect(email.html).toContain('https://myapp.com/login');
  });

  it('includes the from name', () => {
    const email = buildTokenEmail({
      to: 'alice@test.com',
      token: 'abc123',
      loginUrl: 'https://myapp.com/login',
      fromName: 'BangAuth',
    });

    expect(email.html).toContain('BangAuth');
  });
});
