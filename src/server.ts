/**
 * BangAuth — Standalone HTTP Server
 *
 * Hono-based HTTP service that runs BangAuth as a containerized microservice.
 * Replaces AWS Lambda handlers with HTTP endpoints. Uses in-memory adapters
 * for MVP (console email, memory key store, memory user store).
 *
 * // Why: This transforms BangAuth from a Lambda-based IdP into a standalone
 * // service that can run anywhere — Docker, Kubernetes, bare metal, localhost.
 * // Perfect for constellation deployments where we want auth as a sidecar.
 *
 * @module server
 */

import { Hono } from 'hono';
import { cors } from 'hono/cors';
import { randomBytes } from 'node:crypto';
import { ConsoleEmailAdapter } from './adapters/email-console.js';
import { MemoryKeyStore } from './adapters/keys-memory.js';
import { MemoryUserStore } from './adapters/users-memory.js';
import { NatsPublisher } from './adapters/nats-publisher.js';
import { buildLoginPage } from './login-page.js';
import { isDomainAllowed } from './domain.js';
import { generateToken, verifyToken, currentMonth } from './token.js';
import { deriveTwinId } from './twin-id.js';
import { generateSecret, buildQrUri, verifyTOTP } from './totp.js';
import { generateMfaSession, verifyMfaSession, MAX_MFA_ATTEMPTS } from './mfa-session.js';
import { generateRecoveryCodes, hashRecoveryCode, verifyRecoveryCode } from './recovery.js';

// ─── Configuration ───────────────────────────────────────────────────────────

interface Config {
  appName: string;
  appId: string;
  allowedDomains: string[];
  mfaPolicy: 'required' | 'optional' | 'off';
  mfaIssuer: string;
  port: number;
  natsUrl?: string;
}

/**
 * Load configuration from environment variables.
 *
 * // Why: For the MVP, we use env vars. Later, we can add YAML config support.
 */
function loadConfig(): Config {
  return {
    appName: process.env.BANGAUTH_APP_NAME || 'BangAuth',
    appId: process.env.BANGAUTH_APP_ID || 'credence-twin-standard',
    allowedDomains: (process.env.BANGAUTH_ALLOWED_DOMAINS || '*').split(',').map(d => d.trim()),
    mfaPolicy: (process.env.BANGAUTH_MFA_POLICY || 'off') as 'required' | 'optional' | 'off',
    mfaIssuer: process.env.BANGAUTH_MFA_ISSUER || process.env.BANGAUTH_APP_NAME || 'BangAuth',
    port: parseInt(process.env.BANGAUTH_PORT || '3000', 10),
    natsUrl: process.env.NATS_URL,
  };
}

// ─── Initialize Adapters ─────────────────────────────────────────────────────

const config = loadConfig();
const emailAdapter = new ConsoleEmailAdapter();
const keyStore = new MemoryKeyStore();
const userStore = new MemoryUserStore();
const natsPublisher = new NatsPublisher(config.natsUrl);

console.log('🚀 BangAuth HTTP Service');
console.log(`   App: ${config.appName} (${config.appId})`);
console.log(`   Allowed domains: ${config.allowedDomains.join(', ')}`);
console.log(`   MFA policy: ${config.mfaPolicy}`);
console.log(`   Port: ${config.port}`);
console.log(`   NATS: ${config.natsUrl || 'disabled'}`);

// ─── Periodic Cleanup ────────────────────────────────────────────────────────

// Clean up expired access codes every minute
setInterval(() => {
  userStore.cleanupExpiredCodes();
}, 60_000);

// ─── Hono App ────────────────────────────────────────────────────────────────

const app = new Hono();

// CORS middleware — allow all origins for MVP
app.use('*', cors());

// ─── Health Check ────────────────────────────────────────────────────────────

/**
 * GET /health — Health check endpoint.
 */
app.get('/health', (c) => {
  return c.json({ status: 'ok', service: 'bangauth', timestamp: new Date().toISOString() });
});

// ─── Login Page ──────────────────────────────────────────────────────────────

/**
 * GET /auth/login — Serve the login page HTML.
 */
app.get('/auth/login', (c) => {
  const apiBaseUrl = process.env.BANGAUTH_API_BASE_URL || `http://localhost:${config.port}`;
  const redirectUrl = process.env.BANGAUTH_REDIRECT_URL || '/';
  const html = buildLoginPage(config.appName, apiBaseUrl, redirectUrl);
  return c.html(html);
});

// ─── Request Access Code ─────────────────────────────────────────────────────

/**
 * POST /auth/request-code — Request an access code via email.
 *
 * Body: { email: string }
 * Response: { status: 'sent' } or { error: string }
 */
app.post('/auth/request-code', async (c) => {
  try {
    const body = await c.req.json<{ email?: string }>();
    const email = body.email?.toLowerCase().trim();

    if (!email || !/^[^\s@]+@[^\s@]+\.[^\s@]+$/.test(email)) {
      return c.json({ error: 'Invalid email address' }, 400);
    }

    // Check if domain is allowed
    if (!isDomainAllowed(email, config.allowedDomains)) {
      // Send rejection email (prints to console in dev mode)
      await emailAdapter.sendRejectionEmail({
        to: email,
        fromAddress: 'noreply@bangauth.dev',
        fromName: config.appName,
        constellationName: config.appName,
        supportEmail: process.env.BANGAUTH_SUPPORT_EMAIL || '',
      });
      return c.json({ error: 'Email domain not authorized' }, 403);
    }

    // Generate a 6-digit access code
    // Why: In dev mode, use a fixed code for fast iteration. In production, generate random.
    const devMode = process.env.NODE_ENV !== 'production' || process.env.BANGAUTH_DEV_CODE;
    const code = devMode ? (process.env.BANGAUTH_DEV_CODE || '123456') : String(parseInt(randomBytes(3).toString('hex'), 16) % 1000000).padStart(6, '0');

    // Store the code in memory
    await userStore.storeAccessCode(email, code, 5 * 60 * 1000); // 5 minutes

    // Send the code via email (prints to console in dev mode)
    const key = await keyStore.getCurrentKey();
    const month = currentMonth();
    const token = generateToken(email, month, key, config.appId);

    await emailAdapter.sendTokenEmail({
      to: email,
      token: code, // Send the code, not the JWT (for simplicity in MVP)
      constellationName: config.appName,
      loginUrl: `http://localhost:${config.port}/auth/login`,
      validThrough: 'end of session',
      fromAddress: 'noreply@bangauth.dev',
      fromName: config.appName,
    });

    return c.json({ status: 'sent', message: 'Check your email for the access code' });
  } catch (err) {
    console.error('request-code error:', err);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// ─── Verify Access Code ──────────────────────────────────────────────────────

/**
 * POST /auth/verify-code — Verify an access code and return JWT.
 *
 * Body: { email: string, code: string }
 * Response: { authenticated: true, email, twinId, jwt? } or { authenticated: false, error }
 */
app.post('/auth/verify-code', async (c) => {
  try {
    const body = await c.req.json<{ email?: string; code?: string }>();
    const email = body.email?.toLowerCase().trim();
    const code = body.code?.trim();

    if (!email || !code) {
      return c.json({ authenticated: false, error: 'Email and code are required' }, 400);
    }

    // Verify the access code
    const valid = await userStore.verifyAccessCode(email, code);
    if (!valid) {
      return c.json({ authenticated: false, error: 'Invalid or expired code' }, 401);
    }

    // Check if MFA is required
    const mfaEnrollment = await userStore.getMfaEnrollment(email);

    if (mfaEnrollment && mfaEnrollment.status === 'active') {
      // MFA is active — generate session token
      const key = await keyStore.getCurrentKey();
      const mfaSessionToken = generateMfaSession(email, key.secret);
      return c.json({
        authenticated: true,
        mfaRequired: true,
        mfaChallenge: 'totp',
        mfaSessionToken,
      });
    }

    if (!mfaEnrollment && config.mfaPolicy === 'required') {
      // MFA is required but not enrolled — redirect to enrollment
      return c.json({
        authenticated: true,
        mfaRequired: true,
        mfaChallenge: 'enroll',
      });
    }

    // No MFA required — generate JWT and publish event
    const key = await keyStore.getCurrentKey();
    const month = currentMonth();
    const jwt = generateToken(email, month, key, config.appId);
    const twinId = deriveTwinId(email);

    // Publish user.authenticated event to NATS
    await natsPublisher.publishUserAuthenticated({
      userId: email,
      email,
      twinId,
      timestamp: new Date().toISOString(),
      mfaUsed: false,
    });

    return c.json({
      authenticated: true,
      email,
      twinId,
      jwt,
    });
  } catch (err) {
    console.error('verify-code error:', err);
    return c.json({ authenticated: false, error: 'Internal server error' }, 500);
  }
});

// ─── MFA Enrollment ──────────────────────────────────────────────────────────

/**
 * POST /auth/mfa/enroll — Enroll in MFA (returns QR code data).
 *
 * Body: { email: string }
 * Response: { qrUri, secret, status: 'pending' } or { error }
 */
app.post('/auth/mfa/enroll', async (c) => {
  try {
    const body = await c.req.json<{ email?: string }>();
    const email = body.email?.toLowerCase().trim();

    if (!email) {
      return c.json({ error: 'Email is required' }, 400);
    }

    // Check if already enrolled
    const existing = await userStore.getMfaEnrollment(email);
    if (existing && existing.status === 'active') {
      return c.json({ error: 'MFA already enrolled' }, 409);
    }

    // Generate TOTP secret and QR URI
    const secret = generateSecret();
    const qrUri = buildQrUri(email, secret, config.mfaIssuer);

    // Store as pending enrollment
    await userStore.saveMfaEnrollment(email, {
      totpSecret: secret,
      recoveryCodeHashes: [],
      enrolledAt: new Date().toISOString(),
      status: 'pending',
    });

    return c.json({ qrUri, secret, status: 'pending' });
  } catch (err) {
    console.error('mfa-enroll error:', err);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// ─── MFA Verification ────────────────────────────────────────────────────────

/**
 * POST /auth/mfa/verify — Verify MFA TOTP code.
 *
 * Body: { mfaSessionToken: string, code: string }
 * Response: { mfaVerified: true, email, twinId, jwt? } or { mfaVerified: false, reason }
 */
app.post('/auth/mfa/verify', async (c) => {
  try {
    const body = await c.req.json<{ mfaSessionToken?: string; code?: string }>();
    const { mfaSessionToken, code } = body;

    if (!mfaSessionToken || !code) {
      return c.json({ mfaVerified: false, reason: 'mfaSessionToken and code are required' }, 400);
    }

    // Verify MFA session token
    const key = await keyStore.getCurrentKey();
    const sessionResult = verifyMfaSession(mfaSessionToken, key.secret);
    if (!sessionResult) {
      return c.json({ mfaVerified: false, reason: 'Invalid or expired MFA session' }, 401);
    }

    const { email, attempts } = sessionResult;

    // Check brute-force limit
    if (attempts >= MAX_MFA_ATTEMPTS) {
      return c.json({ mfaVerified: false, reason: 'too-many-attempts' }, 429);
    }

    // Load enrollment
    const enrollment = await userStore.getMfaEnrollment(email);
    if (!enrollment) {
      return c.json({ mfaVerified: false, reason: 'No MFA enrollment found' }, 404);
    }

    const twinId = deriveTwinId(email);

    // Check if this is a TOTP code or recovery code
    if (/^\d{6}$/.test(code)) {
      // TOTP code
      const valid = verifyTOTP(enrollment.totpSecret, code);
      if (!valid) {
        const newSessionToken = generateMfaSession(email, key.secret, attempts + 1);
        return c.json({
          mfaVerified: false,
          reason: 'Invalid TOTP code',
          mfaSessionToken: newSessionToken,
        }, 401);
      }

      // Check if this is enrollment confirmation (pending → active)
      if (enrollment.status === 'pending') {
        const recoveryCodes = generateRecoveryCodes();
        const recoveryCodeHashes = recoveryCodes.map(rc => ({
          hash: hashRecoveryCode(rc),
          used: false,
        }));

        await userStore.saveMfaEnrollment(email, {
          ...enrollment,
          status: 'active',
          recoveryCodeHashes,
        });

        console.log(`✅ MFA enrollment activated for ${email}`);

        return c.json({
          mfaVerified: true,
          email,
          twinId,
          enrollmentActivated: true,
          recoveryCodes,
        });
      }

      // Active enrollment — standard TOTP verification
      const month = currentMonth();
      const jwt = generateToken(email, month, key, config.appId);

      // Publish user.authenticated event
      await natsPublisher.publishUserAuthenticated({
        userId: email,
        email,
        twinId,
        timestamp: new Date().toISOString(),
        mfaUsed: true,
      });

      return c.json({ mfaVerified: true, email, twinId, jwt });
    } else if (/^[A-Za-z0-9]{4}-[A-Za-z0-9]{4}$/.test(code)) {
      // Recovery code
      if (enrollment.status !== 'active') {
        return c.json({ mfaVerified: false, reason: 'Cannot use recovery codes during enrollment' }, 400);
      }

      const matchedIndex = verifyRecoveryCode(code, enrollment.recoveryCodeHashes);
      if (matchedIndex === -1) {
        const newSessionToken = generateMfaSession(email, key.secret, attempts + 1);
        return c.json({
          mfaVerified: false,
          reason: 'Invalid or already used recovery code',
          mfaSessionToken: newSessionToken,
        }, 401);
      }

      // Mark the recovery code as used
      enrollment.recoveryCodeHashes[matchedIndex].used = true;
      enrollment.recoveryCodeHashes[matchedIndex].usedAt = new Date().toISOString();
      await userStore.saveMfaEnrollment(email, enrollment);

      const remaining = enrollment.recoveryCodeHashes.filter(rc => !rc.used).length;
      const month = currentMonth();
      const jwt = generateToken(email, month, key, config.appId);

      // Publish user.authenticated event
      await natsPublisher.publishUserAuthenticated({
        userId: email,
        email,
        twinId,
        timestamp: new Date().toISOString(),
        mfaUsed: true,
      });

      return c.json({ mfaVerified: true, email, twinId, jwt, recoveryCodesRemaining: remaining });
    } else {
      return c.json({
        mfaVerified: false,
        reason: 'Invalid code format — expected 6-digit TOTP code or XXXX-XXXX recovery code',
      }, 400);
    }
  } catch (err) {
    console.error('mfa-verify error:', err);
    return c.json({ mfaVerified: false, reason: 'Internal server error' }, 500);
  }
});

// ─── JWKS Endpoint (Public Keys) ─────────────────────────────────────────────

/**
 * GET /auth/.well-known/jwks.json — Public keys for JWT verification.
 *
 * // Why: Downstream services need to verify JWTs without calling back to the
 * // auth service. They fetch this endpoint once and cache the keys.
 */
app.get('/auth/.well-known/jwks.json', async (c) => {
  try {
    const activeKeys = await keyStore.listActiveKeys();

    // Note: For HMAC (HS256), we don't actually expose the secret.
    // This endpoint would be more useful for RSA/ECDSA. For now, return metadata.
    const keys = activeKeys.map(key => ({
      kid: key.kid,
      alg: key.alg,
      use: 'sig',
      expiresAt: key.expiresAt,
    }));

    return c.json({ keys });
  } catch (err) {
    console.error('jwks error:', err);
    return c.json({ error: 'Internal server error' }, 500);
  }
});

// ─── Catch-All ───────────────────────────────────────────────────────────────

app.get('/', (c) => {
  return c.redirect('/auth/login');
});

app.notFound((c) => {
  return c.json({ error: 'Not found' }, 404);
});

// ─── Start Server ────────────────────────────────────────────────────────────

const port = config.port;

console.log(`\n🌐 Server starting on http://localhost:${port}`);
console.log(`   Login page: http://localhost:${port}/auth/login`);
console.log(`   Health check: http://localhost:${port}/health\n`);

// Graceful shutdown
process.on('SIGINT', async () => {
  console.log('\n🛑 Shutting down gracefully...');
  await natsPublisher.close();
  process.exit(0);
});

process.on('SIGTERM', async () => {
  console.log('\n🛑 Shutting down gracefully...');
  await natsPublisher.close();
  process.exit(0);
});

// Why: Start HTTP server using @hono/node-server for Node.js/tsx compatibility
import { serve } from '@hono/node-server';

serve({ fetch: app.fetch, port }, (info) => {
  console.log(`✅ BangAuth listening on http://localhost:${info.port}\n`);
});
