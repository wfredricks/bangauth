# BangAuth Extraction Plan — Externalize the Peculiars

**Goal:** Extract the IdP into a generic open-source package. All deployment-specific
values go into a YAML config file. The code becomes reusable on any project.

---

## Peculiars to Externalize

### From config.ts (SSM Parameter Paths)

| Current (hardcoded SSM path) | YAML config key | Description |
|------------------------------|-----------------|-------------|
| `/udt/idp/allowedDomains` | `auth.allowedDomains` | Allowed email domains |
| `/udt/idp/constellationId` | `auth.appId` | Application/constellation identifier |
| `/udt/idp/animatorUrl` | `auth.callbackUrl` | URL to notify on auth success |
| `/udt/idp/ses/fromAddress` | `email.fromAddress` | Sender email address |
| `/udt/idp/ses/fromName` | `email.fromName` | Sender display name |
| `/udt/idp/loginUrl` | `auth.loginUrl` | Login page URL |
| `/udt/idp/mfaPolicy` | `mfa.policy` | required \| optional \| off |
| `/udt/idp/mfaIssuer` | `mfa.issuer` | TOTP issuer name (shown in authenticator) |
| `/udt/idp/currentKid` | `keys.currentKid` | Current signing key identifier |
| `/udt/idp/keys/{kid}` | `keys.secretPath` | Secret storage path pattern |

### From CDK stack

| Current (hardcoded) | YAML config key | Description |
|---------------------|-----------------|-------------|
| `udt-credence.ai` | `deployment.domain` | Custom domain |
| `twinsmith.ai` | `email.sesDomain` | SES domain for inbound email |
| `us-east-1` | `deployment.region` | AWS region |
| `230152865130` | (derived from AWS auth) | AWS account ID |

---

## BangAuth Config File (bangauth.yaml)

```yaml
# bangauth.yaml — drop this next to your app

app:
  id: my-app                    # Application identifier
  name: My Application          # Display name
  loginUrl: https://myapp.com/login

auth:
  allowedDomains:
    - mycompany.com
    - partner.org
  codeRotation: monthly         # SHA-256 salt rotation period
  tokenTTL: 86400               # JWT TTL in seconds (24h)

mfa:
  policy: optional              # required | optional | off
  issuer: My Application        # Shown in authenticator app
  maxAttempts: 5                # Brute-force protection

email:
  provider: ses                 # ses | smtp | sendgrid | console
  fromAddress: auth@myapp.com
  fromName: My App Auth
  # SES-specific:
  sesDomain: myapp.com
  # SMTP-specific:
  # smtpHost: smtp.gmail.com
  # smtpPort: 587

keys:
  provider: secrets-manager     # secrets-manager | env | file
  secretPath: /myapp/auth/keys  # Pattern for key storage
  rotationSchedule: monthly     # cron: first of month
  algorithm: HS256

deployment:
  region: us-east-1
  domain: myapp.com             # Custom domain (optional)
```

---

## Adapter Pattern (same as PolyGraph)

```
bangauth/
  src/
    core/
      auth.ts          — login, verify, token generation (PURE)
      mfa.ts           — TOTP enroll, verify, brute-force (PURE)
      codes.ts         — SHA-256 code generation + rotation (PURE)
      tokens.ts        — JWT sign, verify, refresh (PURE)
    adapters/
      email/
        ses.ts         — AWS SES adapter
        smtp.ts        — Generic SMTP adapter
        sendgrid.ts    — SendGrid adapter
        console.ts     — Dev: print to console
      keys/
        secrets-manager.ts  — AWS Secrets Manager
        env.ts              — Environment variables
        file.ts             — Local file (dev)
        memory.ts           — In-memory (testing)
      config/
        ssm.ts         — AWS SSM Parameter Store
        yaml.ts        — YAML file loader
        env.ts         — Environment variables
    handlers/
      login.ts         — POST /auth/login
      verify.ts        — POST /auth/verify
      mfa-enroll.ts    — POST /auth/mfa/enroll
      mfa-verify.ts    — POST /auth/mfa/verify
      rotate.ts        — Key rotation handler
    middleware/
      hono.ts          — Hono auth middleware
      express.ts       — Express auth middleware
    config.ts          — Loads from YAML → adapter → cached config
    index.ts           — Public API
  bangauth.yaml        — Example config
  README.md
```

---

## The Extraction Steps

1. Create `artifacts/bangauth/` repo
2. Copy IdP source files, strip SSM paths → adapter calls
3. Write YAML config loader (same pattern as birthright-loader)
4. Write adapter interfaces (email, keys, config)
5. Implement adapters (SES, SMTP, console; Secrets Manager, env, file)
6. Write bangauth.yaml example
7. Tests against memory adapters
8. README with "Quick Start" (3 lines to add auth to any Hono app)

---

## Usage After Extraction

```typescript
import { createBangAuth } from 'bangauth';

const auth = await createBangAuth('./bangauth.yaml');

// Mount on any Hono app
app.post('/auth/login', auth.handlers.login);
app.post('/auth/verify', auth.handlers.verify);
app.post('/auth/mfa/enroll', auth.handlers.mfaEnroll);
app.post('/auth/mfa/verify', auth.handlers.mfaVerify);
app.use('/api/*', auth.middleware);  // Protect routes

// That's it. Bang, you're in! 💥
```

---

*"No Cognito. No Auth0. No vendor lock-in. Just YAML and `npm install bangauth`."*
