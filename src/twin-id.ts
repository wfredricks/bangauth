/**
 * UDT Identity Provider — Twin ID Derivation
 *
 * // Why: Every user in the UDT system needs a stable, deterministic identifier.
 * // Rather than generating random UUIDs (which require a database to track),
 * // we derive the twinId directly from the email address. Same email always
 * // produces the same twinId. No lookup table needed.
 *
 * @module twin-id
 */

/**
 * Derive a deterministic twinId from an email address.
 *
 * // Why: The twinId is the user's identity anchor across the entire UDT system.
 * // It must be:
 * //   1. Deterministic — same email → same twinId, always
 * //   2. Human-readable — you can eyeball it and know who it is
 * //   3. URL-safe — no special characters that break routing
 * //   4. Lowercase — prevents case-sensitivity bugs
 *
 * Transformation rules:
 * - Lowercase the entire email
 * - Replace `@` with `-`
 * - Replace `.` with `-`
 * - Append `-{twinType}`
 *
 * @param email - The user's email address.
 * @param twinType - The type of twin (defaults to "personal").
 * @returns The derived twinId string.
 *
 * @example
 * ```typescript
 * deriveTwinId('wfredricks@credence-llc.com');
 * // → "wfredricks-credence-llc-com-personal"
 *
 * deriveTwinId('chen.maria@dla.mil');
 * // → "chen-maria-dla-mil-personal"
 *
 * deriveTwinId('admin@example.org', 'service');
 * // → "admin-example-org-service"
 * ```
 */
export function deriveTwinId(email: string, twinType: string = 'personal'): string {
  // Why: Normalize first, transform second. Lowercasing before replacement
  // ensures consistent output regardless of input casing.
  const normalized = email.toLowerCase().trim();

  // Why: Replace @ and . with hyphens to create a flat, URL-safe identifier.
  // The order doesn't matter since both become the same character.
  const base = normalized
    .replace(/@/g, '-')
    .replace(/\./g, '-');

  return `${base}-${twinType}`;
}
