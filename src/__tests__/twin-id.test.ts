/**
 * Twin ID Derivation Tests
 */

import { describe, it, expect } from 'vitest';
import { deriveTwinId } from '../twin-id.js';

describe('Twin ID Derivation', () => {
  it('derives twin ID from email', () => {
    const id = deriveTwinId('bill@credence.ai');
    expect(id).toBeDefined();
    expect(id.length).toBeGreaterThan(0);
  });

  it('same email produces same ID', () => {
    const id1 = deriveTwinId('bill@credence.ai');
    const id2 = deriveTwinId('bill@credence.ai');
    expect(id1).toBe(id2);
  });

  it('different emails produce different IDs', () => {
    const id1 = deriveTwinId('bill@credence.ai');
    const id2 = deriveTwinId('alice@credence.ai');
    expect(id1).not.toBe(id2);
  });

  it('includes twin type suffix', () => {
    const id = deriveTwinId('bill@credence.ai', 'personal');
    expect(id).toContain('personal');
  });

  it('default type is personal', () => {
    const id = deriveTwinId('bill@credence.ai');
    expect(id).toContain('personal');
  });
});
