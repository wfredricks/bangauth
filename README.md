# BangAuth 💥

**Passwordless authentication you can own. Bang, you're in!**

Email → access code → MFA → JWT. No passwords. No Cognito. No Auth0. No vendor lock-in. One `npm install`.

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

```bash
npm install bangauth
```

```typescript
import { createBangAuth } from 'bangauth';

const auth = await createBangAuth('./bangauth.yaml');

// Mount on any Hono app
app.post('/auth/login', auth.handlers.login);
app.post('/auth/verify', auth.handlers.verify);
app.post('/auth/mfa/enroll', auth.handlers.mfaEnroll);
app.post('/auth/mfa/verify', auth.handlers.mfaVerify);

// Protect your routes
app.use('/api/*', auth.middleware);

// That's it. Bang! 💥
```

## Features

**Authentication**
- 📧 Email-based login — no passwords, ever
- 🔄 Monthly code rotation — SHA-256 with YYYY-MM salt
- 🔐 MFA support — TOTP (Google Authenticator, Authy)
- 🎫 JWT tokens — signed with rotating HMAC keys
- 🛡️ Brute-force protection — max 5 MFA attempts per session
- 🔑 Recovery codes — 8 single-use backup codes

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

## CDK Deployment (AWS)

```bash
cd cdk
npm install
npx cdk deploy
```

Deploys: 11 Lambda functions, API Gateway, SES, Secrets Manager, SSM, S3 + CloudFront for SPA, EventBridge for key rotation.

## Architecture

```
┌─────────────────────────────────────────────┐
│              Your Application                │
├─────────────────────────────────────────────┤
│              BangAuth Middleware              │
│  Login · Verify · MFA · JWT · Audit Trail   │
├─────────────────────────────────────────────┤
│              Adapter Layer                   │
│   Email    │   Keys     │   Config           │
│  SES/SMTP  │  SM/Env    │  SSM/YAML          │
└─────────────────────────────────────────────┘
```

Pure auth logic on top. Pluggable adapters on bottom. Your infrastructure, your choice.

## Part of the PolyGraph Ecosystem

- [**PolyGraph**](https://github.com/wfredricks/polygraph) — own your database
- [**PolyGraph Viz**](https://github.com/wfredricks/polygraph-viz) — see your data
- **BangAuth** — own your identity

## License

Apache 2.0 — use it, modify it, own it.

---

*No passwords. No vendor lock-in. No excuses. Bang, you're in! 💥*
