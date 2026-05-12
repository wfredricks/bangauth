/**
 * UDT Identity Provider — Shared Type Definitions
 *
 * // Why: Central type definitions keep all handlers and modules aligned on
 * // a single contract. No duplication, no drift.
 *
 * @module types
 */

// ─── Token Types ─────────────────────────────────────────────────────────────

/**
 * The payload embedded inside every UDT access token.
 *
 * // Why: Deterministic tokens need a fixed, JSON-serializable payload so
 * // that identical inputs always produce identical base64url output.
 */
export interface TokenPayload {
  /** User's email address — the identity anchor. */
  email: string;
  /** Domain portion of the email (e.g., "dla.mil"). */
  domain: string;
  /** Year-month the token is valid for (e.g., "2026-05"). */
  month: string;
  /** Key ID used to sign this token (e.g., "k-2026-05"). */
  kid: string;
  /** HMAC algorithm (e.g., "HS256"). */
  alg: string;
  /** Constellation this token grants access to (e.g., "dla-piee"). */
  constellationId: string;
  /** Payload schema version — allows future evolution. */
  version: number;
}

/**
 * A signing key used to generate and verify tokens.
 *
 * // Why: Keys rotate monthly. Each key has a lifecycle (created → active → expired)
 * // and the kid lets us look up the right key during verification without trying them all.
 */
export interface SigningKey {
  /** Key ID — convention: "k-YYYY-MM" (e.g., "k-2026-05"). */
  kid: string;
  /** HMAC algorithm (e.g., "HS256", "HS384", "HS512"). */
  alg: string;
  /** 256-bit hex secret — NEVER exposed outside the IdP. */
  secret: string;
  /** ISO 8601 timestamp when this key was created. */
  createdAt: string;
  /** ISO 8601 timestamp when this key expires. */
  expiresAt: string;
  /** Whether this key is currently active for signing/verification. */
  active: boolean;
}

/**
 * Public metadata about a signing key — safe to expose via the /keys endpoint.
 *
 * // Why: Consumers need to know which keys exist and their lifetimes,
 * // but must NEVER see the secret material.
 */
export interface SigningKeyInfo {
  /** Key ID. */
  kid: string;
  /** HMAC algorithm. */
  alg: string;
  /** ISO 8601 expiration timestamp. */
  expiresAt: string;
}

// ─── Verification Result ─────────────────────────────────────────────────────

/**
 * Result of token verification — either valid with decoded claims or invalid with a reason.
 *
 * // Why: Discriminated union makes it impossible to accidentally access claims
 * // on an invalid token — TypeScript enforces the check.
 */
export type VerifyResult =
  | {
      valid: true;
      email: string;
      domain: string;
      month: string;
      kid: string;
      alg: string;
      constellationId: string;
    }
  | {
      valid: false;
      reason: string;
    };

// ─── Configuration ───────────────────────────────────────────────────────────

/**
 * IdP configuration loaded from SSM Parameter Store.
 *
 * // Why: All runtime configuration lives in SSM so we can change behavior
 * // without redeploying Lambda code. The 5-minute cache keeps costs down.
 */
export interface IdPConfig {
  /** Domains allowed to request tokens (e.g., ["acme.com", "partner.org"]). */
  allowedDomains: string[];
  /** Constellation identifier (e.g., "dla-piee"). */
  constellationId: string;
  /** Animator service URL for twin provisioning. */
  animatorUrl: string;
  /** SES sender address (e.g., "identity@acme.com"). */
  sesFromAddress: string;
  /** SES sender display name (e.g., "DLA PIEE Digital Twin"). */
  sesFromName: string;
  /** Login page URL included in token emails. */
  loginUrl: string;
  /** MFA enforcement policy: "required" (all users), "optional" (user choice), "off" (disabled). */
  mfaPolicy: 'required' | 'optional' | 'off';
  /** Issuer name shown in authenticator apps (e.g., "DLA PIEE Digital Twin"). */
  mfaIssuer: string;
  /**
   * Support mailbox shown to users whose domain is rejected. Operators
   * configure this per deployment (typically via `BANGAUTH_SUPPORT_EMAIL`).
   * Empty string omits the contact line.
   */
  supportEmail: string;
}

// ─── Key Store ───────────────────────────────────────────────────────────────

/**
 * Abstraction over Secrets Manager for signing key access.
 *
 * // Why: Handlers don't care where keys come from — they call the store.
 * // This also makes testing trivial (inject a mock store).
 */
export interface KeyStore {
  /** Retrieve a specific key by its ID. Returns null if not found. */
  getKey(kid: string): Promise<SigningKey | null>;
  /** Get the current active signing key (for new token generation). */
  getCurrentKey(): Promise<SigningKey>;
  /** List all active keys with public metadata only (no secrets). */
  listActiveKeys(): Promise<SigningKeyInfo[]>;
}

// ─── Lambda Event Helpers ────────────────────────────────────────────────────

/**
 * Standard JSON response shape for all IdP endpoints.
 *
 * // Why: Consistent response format across all handlers simplifies
 * // client-side parsing and error handling.
 */
export interface ApiResponse {
  statusCode: number;
  headers: Record<string, string>;
  body: string;
}

/**
 * Parameters for the SES email sender.
 *
 * // Why: Explicit parameter object prevents positional argument confusion
 * // and makes the email sender self-documenting.
 */
/**
 * Parameters for sending a rejection email to an unauthorized user.
 * // Why: When someone tries to request a token but their domain isn't allowed,
 * // we send a helpful email pointing them to a deployment-specific support
 * // address (configured by the operator).
 */
export interface SendRejectionEmailParams {
  /** Recipient email address. */
  to: string;
  /** SES sender address. */
  fromAddress: string;
  /** SES sender display name. */
  fromName: string;
  /** Human-readable constellation name. */
  constellationName: string;
  /**
   * Support mailbox the rejection email points the user at for manual
   * vetting. Operators set this per deployment (e.g. via the
   * `BANGAUTH_SUPPORT_EMAIL` environment variable).
   */
  supportEmail: string;
}

// ─── MFA Types ───────────────────────────────────────────────────────────────

/**
 * A user's MFA enrollment data stored in Secrets Manager.
 *
 * // Why: This is the complete MFA state for a user — their TOTP secret,
 * // recovery code hashes, enrollment timestamp, and status. Stored as a single
 * // JSON blob in Secrets Manager, keyed by SHA256(email).
 */
export interface MfaEnrollment {
  /** Base32-encoded TOTP secret (32 chars = 160 bits). */
  totpSecret: string;
  /** Hashed recovery codes with usage tracking. */
  recoveryCodeHashes: RecoveryCodeEntry[];
  /** ISO 8601 timestamp when enrollment was initiated. */
  enrolledAt: string;
  /** Enrollment status: "pending" until first TOTP code is confirmed, then "active". */
  status: 'pending' | 'active';
}

/**
 * A single recovery code entry with hash and usage state.
 *
 * // Why: We store only the SHA256 hash (never plaintext) so even a Secrets
 * // Manager breach doesn't expose usable codes. The used/usedAt fields let
 * // us track consumption and provide audit logs.
 */
export interface RecoveryCodeEntry {
  /** SHA256 hex hash of the normalized recovery code. */
  hash: string;
  /** Whether this code has been consumed. */
  used: boolean;
  /** ISO 8601 timestamp when this code was used (undefined if unused). */
  usedAt?: string;
}

/**
 * Payload inside an MFA session token.
 *
 * // Why: Explicit type for the HMAC-signed payload ensures consistent
 * // serialization between generation and verification.
 */
export interface MfaSessionPayload {
  /** User's email address. */
  email: string;
  /** Issued-at timestamp (milliseconds since epoch). */
  iat: number;
  /** Random nonce to prevent replay. */
  nonce: string;
  /** Token purpose — prevents cross-use with other HMAC tokens. */
  purpose: 'mfa-session';
}

/**
 * Parameters for sending an MFA reset email.
 *
 * // Why: Explicit parameter object prevents positional argument confusion
 * // and makes the email sender self-documenting.
 */
export interface SendResetEmailParams {
  /** Recipient email address. */
  to: string;
  /** The HMAC-signed reset link URL. */
  resetUrl: string;
  /** Human-readable constellation name. */
  constellationName: string;
  /** SES sender address. */
  fromAddress: string;
  /** SES sender display name. */
  fromName: string;
}

export interface SendTokenEmailParams {
  /** Recipient email address. */
  to: string;
  /** The generated access token. */
  token: string;
  /** Human-readable constellation name for the email subject/body. */
  constellationName: string;
  /** Login URL to include in the email. */
  loginUrl: string;
  /** Human-readable validity end date (e.g., "June 3, 2026"). */
  validThrough: string;
  /** SES sender address. */
  fromAddress: string;
  /** SES sender display name. */
  fromName: string;
}
