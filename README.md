# BangAuth 💥

**Passwordless authentication you can own. Bang, you're in!**

Email → access code → MFA → JWT. No passwords. No Cognito. No Auth0. No vendor lock-in. A single Hono service you run yourself.

## Why It's Different

**The access code IS the password — and the password expires every month, by construction.**

Most auth systems store password hashes and accept whatever the user typed as long as it matches. BangAuth doesn't store a password hash for the user at all. Instead, the per-user access code is `SHA-256(email + "YYYY-MM" + secret)`. On every login, BangAuth re-derives the expected code from the *current month* and compares. That has three concrete consequences:

1. **No password database to breach.** There's nothing to dump. Even a full server compromise leaks the signing key, not user passwords.
2. **Stolen codes self-expire at the month boundary** — with a 3-day grace period across the calendar flip so users aren't locked out at midnight on the 1st.
3. **The same property holds for JWT signing keys.** They rotate monthly on the same schedule. A leaked key compromises ≤ 1 month of issued tokens, not the system's history.

This is the design AWS Cognito and Auth0 *could* have shipped and chose not to, because vendor revenue depends on stickiness. BangAuth chose simplicity instead.

## How It Works

```
1. User enters email         → POST /auth/login
2. Access code emailed       → SHA-256(email + monthly salt)
3. User clicks link or       → POST /auth/verify
   enters code
4. MFA (if enabled)          → POST /auth/mfa/verify (TOTP)
5. JWT issued                → authenticated ✅
```

Codes rotate monthly by design — no password database to breach, no tokens to steal. The code IS the password, and it expires every month.

## Quick Start

BangAuth is a standalone Hono service you run as a sidecar to your app and call over HTTP. The MVP ships as a container:

```bash
# Clone and run with sensible defaults (console email adapter, in-memory key store)
git clone https://github.com/wfredricks/bangauth
cd bangauth
npm install
BANGAUTH_APP_NAME="My App" \
BANGAUTH_ALLOWED_DOMAINS="mycompany.com,partner.org" \
  npm start
# BangAuth is now listening on :3000
```

```bash
# Or build the image and run as a sidecar in your compose stack
docker build -t bangauth .
docker run -p 3000:3000 \
  -e BANGAUTH_ALLOWED_DOMAINS="mycompany.com" \
  bangauth
```

```typescript
// From your application code, call BangAuth's endpoints:
await fetch('http://bangauth:3000/auth/login', {
  method: 'POST',
  headers: { 'content-type': 'application/json' },
  body: JSON.stringify({ email: 'alice@mycompany.com' }),
});
// User receives an email with a magic link.
// On callback, POST to /auth/verify, then /auth/mfa/verify if MFA is enrolled.
// You get a signed JWT; mount your own middleware to verify it.
```

> **About "embed it like middleware."** The README's earlier drafts promised an
> in-process Hono middleware import (`import { createBangAuth } from 'bangauth'`).
> That's the right shape for a future v0.2 release — the engine is pure functions
> already — but the v0.1 line ships and is tested as a standalone service. Use it
> over HTTP for now.

## Features

**Authentication**
- 📧 Email-based login — no passwords, ever
- 🔄 Monthly code rotation — SHA-256 with YYYY-MM salt
- 🔐 MFA support — TOTP (Google Authenticator, Authy)
- 🎫 JWT tokens — signed with rotating HMAC keys
- 🛡️ Brute-force protection — max 5 MFA attempts per session
- 🔑 Recovery codes — 10 single-use backup codes (XXXX-XXXX, ambiguous chars removed)

**Adapters (plug in your infrastructure)**
- Email: SES | SMTP | SendGrid | Console (dev)
- Key storage: AWS Secrets Manager | Environment variables | File | Memory (testing)
- Config: AWS SSM | YAML file | Environment variables

**Security**
- NIST 800-53 aligned — AC-2, AC-3, IA-2, IA-5, SC-13
- Key rotation — monthly, automated via cron/EventBridge
- Audit trail — every auth event emitted to event bus
- No password storage — nothing to breach
- Domain allowlist — only approved organizations

## Configuration

```yaml
# bangauth.yaml

app:
  id: my-app
  name: My Application
  loginUrl: https://myapp.com/login

auth:
  allowedDomains:
    - mycompany.com
    - partner.org
  codeRotation: monthly
  tokenTTL: 86400              # 24 hours

mfa:
  policy: optional             # required | optional | off
  issuer: My Application       # Shown in authenticator app
  maxAttempts: 5

email:
  provider: ses                # ses | smtp | sendgrid | console
  fromAddress: auth@myapp.com
  fromName: My App Auth

keys:
  provider: secrets-manager    # secrets-manager | env | file | memory
  secretPath: /myapp/auth/keys
  algorithm: HS256
```

## Why BangAuth?

| | BangAuth | Auth0 | Cognito | Roll Your Own |
|---|---|---|---|---|
| **Vendor lock-in** | None | High | AWS-only | None |
| **Passwords** | None (email codes) | Yes | Yes | Probably |
| **MFA** | Built-in | Add-on | Config hell | You build it |
| **Self-hosted** | Yes | No | AWS-only | Yes |
| **FedRAMP-ready** | You own it | Their ATO | Their ATO | Your problem |
| **Cost** | Free + infra | $$$$/month | Usage-based | Engineering time |
| **Time to integrate** | 5 minutes | Hours | Days | Weeks |

## The Flow (detailed)

### 1. Login Request
```
POST /auth/login
{ "email": "alice@mycompany.com" }

→ Check domain allowlist
→ Generate code: SHA-256(email + YYYYMM + secret)
→ Send email with link: loginUrl?token=<code>
→ Response: { "message": "Check your email" }
```

### 2. Verify Code
```
POST /auth/verify
{ "token": "<code from email>" }

→ Recompute: SHA-256(email + YYYYMM + secret)
→ Compare with submitted code
→ If MFA enrolled: return mfaSessionToken
→ If no MFA: issue JWT immediately
```

### 3. MFA Verify (if enabled)
```
POST /auth/mfa/verify
{ "mfaSessionToken": "<from step 2>", "code": "123456" }

→ Verify TOTP code against enrolled secret
→ Check attempt count (max 5)
→ Issue JWT
```

### 4. Authenticated!
```
GET /api/anything
Authorization: Bearer <jwt>

→ Verify JWT signature
→ Check expiry
→ Extract user identity
→ Proceed ✅
```

## Testing

```bash
npm test
```

43 tests covering:
- Token engine (generation, verification, rotation)
- Domain allowlist
- Recovery codes
- MFA sessions (brute-force protection)
- TOTP (enrollment, QR generation)
- Email templates

All tests run with in-memory adapters — no AWS, no network, instant.

## Deployment

### Docker (the default path)

The `Dockerfile` at the repo root builds a self-contained image that runs the Hono server on port 3000. This is how BangAuth ships and how it's exercised in the Twin Constellation today.

```bash
docker build -t bangauth .
docker run -p 3000:3000 -e BANGAUTH_ALLOWED_DOMAINS="..." bangauth
```

Environment variables BangAuth recognises:

| Variable | Default | Purpose |
|---|---|---|
| `BANGAUTH_APP_NAME` | `BangAuth` | Shown in emails and the login page |
| `BANGAUTH_APP_ID` | `credence-twin-standard` | Token audience identifier |
| `BANGAUTH_ALLOWED_DOMAINS` | `*` | Comma-separated allowlist (e.g. `*.mil,gmail.com`) |
| `BANGAUTH_MFA_POLICY` | `optional` | `required` / `optional` / `off` |
| `BANGAUTH_MFA_ISSUER` | `BangAuth` | TOTP issuer label shown in authenticator apps |
| `BANGAUTH_PORT` | `3000` | HTTP listen port |
| `BANGAUTH_NATS_URL` | (unset) | If set, audit events publish to NATS |

### AWS (CDK) — experimental

The `cdk/` directory holds an in-progress CDK stack that deploys BangAuth as Lambda functions behind API Gateway with SES and Secrets Manager. It is *not* the recommended path today — use the Docker image until the CDK stack catches up to the latest server surface.

## Architecture

```
┌─────────────────────────────────────────────┐
│              Your Application                │
│     calls BangAuth over HTTP / fetch          │
└────────────────────────┬─────────────────────┘
                          │ HTTP (JSON)
                          ▼
┌─────────────────────────────────────────────┐
│             BangAuth Server                  │
│  Hono routes · Login · Verify · MFA · JWT     │
│    │ Pure functions (token, totp, recovery)   │
├─────────────────────────────────────────────┤
│              Adapter Layer                   │
│   Email    │   Keys     │   Users             │
│  SES/SMTP  │  SM/Env    │  Memory/Persistent  │
│  Console   │  Memory    │                     │
└───────────────────────────────────────────────┘
```

Pure auth logic on top of pluggable adapters. The core engine (`token.ts`, `totp.ts`, `recovery.ts`, `domain.ts`, `mfa-session.ts`) is pure functions, no I/O. The Hono server is the I/O shell. The adapters bridge to your infrastructure choices. **That separation is what makes the v0.2 "embed as library" path tractable** — the engine is already library-shaped; only the server wrapper needs replacing with an in-process middleware.

## Part of the PolyGraph Ecosystem

- [**PolyGraph**](https://github.com/wfredricks/polygraph) — own your database
- [**PolyGraph Viz**](https://github.com/wfredricks/polygraph-viz) — see your data
- **BangAuth** — own your identity

## License

Apache 2.0 — use it, modify it, own it.

---

*No passwords. No vendor lock-in. No excuses. Bang, you're in! 💥*
