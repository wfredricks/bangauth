/**
 * UDT Identity Provider — Domain Allowlist Checker
 *
 * // Why: Not everyone can request a token. The IdP gates access at the domain
 * // level — only emails from approved organizations get through. This is the
 * // first line of defense before any token generation happens.
 *
 * @module domain
 */

/**
 * Check whether an email's domain is in the allowlist.
 *
 * // Why: Domain-level gating is simpler and more maintainable than per-user
 * // allowlists. When a new organization onboards, we add their domain to SSM.
 * // The wildcard "*" exists for development/demo scenarios where any domain is OK.
 *
 * @param email - The email address to check.
 * @param allowedDomains - List of allowed domains (case-insensitive). Use "*" to allow all.
 * @returns True if the email's domain is in the allowlist.
 *
 * @example
 * ```typescript
 * isDomainAllowed('chen.maria@dla.mil', ['dla.mil', 'credence-llc.com']); // true
 * isDomainAllowed('random@gmail.com', ['dla.mil']);                        // false
 * isDomainAllowed('anyone@anything.com', ['*']);                           // true
 * ```
 */
export function isDomainAllowed(email: string, allowedDomains: string[]): boolean {
  // Why: Wildcard short-circuit — if "*" alone is in the list, everything passes.
  // This is intentional for dev/demo environments.
  if (allowedDomains.includes('*')) return true;

  const atIndex = email.lastIndexOf('@');
  if (atIndex === -1) return false;

  const domain = email.substring(atIndex + 1).toLowerCase().trim();
  if (!domain) return false;

  // Why: Support three matching patterns:
  //   1. Exact match: "credence-llc.com" matches only credence-llc.com
  //   2. Suffix wildcard: "*.mil" matches anything ending in .mil (dla.mil, navy.mil, etc.)
  //   3. Contains wildcard: "*credence*" matches any domain containing "credence"
  //   4. Full wildcard: "*" matches everything (handled above)
  // This lets Bill say "anyone with .mil or 'credence' in their email gets access."
  const normalizedAllowed = allowedDomains.map((d) => d.toLowerCase().trim());

  for (const pattern of normalizedAllowed) {
    // Contains pattern: *substring* (stars on both sides)
    if (pattern.startsWith('*') && pattern.endsWith('*') && pattern.length > 2) {
      const substring = pattern.slice(1, -1);
      if (domain.includes(substring)) return true;
      continue;
    }

    // Suffix pattern: *.mil (star + dot + TLD)
    if (pattern.startsWith('*.')) {
      const suffix = pattern.slice(1); // ".mil"
      if (domain.endsWith(suffix) || domain === suffix.slice(1)) return true;
      continue;
    }

    // Exact match
    if (domain === pattern) return true;
  }

  return false;
}
