# UDT Identity Provider (IdP)

Serverless Identity Provider for the User Digital Twin platform. Manages passwordless authentication via deterministic, HMAC-signed monthly tokens delivered by email.

## Architecture

```
User → POST /idp/request-token (email) → SES → User's inbox
User → POST /idp/login (token) → Verify → Provision twin → Session
Service → POST /idp/verify (token) → Claims
Ops → GET /idp/keys → Active key registry
EventBridge → rotate handler → Monthly key rotation + token re-issuance
```

### Key Design Decisions

1. **Deterministic tokens** — Same email + same month + same key = identical token. No database needed.
2. **Monthly rotation** — Keys rotate on the 1st, with a 3-day grace period for the previous month.
3. **Domain-gated access** — Only approved email domains can request tokens.
4. **ESM Lambda on Node 20** — Native ES modules, esbuild bundling, AWS SDK externalized.
5. **No framework** — Raw Lambda handlers. No Express, no Middy. Simple.

## Token Format

```
{base64url(JSON.stringify(payload))}.{hmac-sha256-hex-signature}
```

Payload contains: email, domain, month, kid, alg, constellationId, version.

## Project Structure

```
src/
├── token.ts              # Core token engine (generate, verify, HMAC)
├── domain.ts             # Domain allowlist checking
├── twin-id.ts            # Deterministic twinId derivation
├── config.ts             # SSM + Secrets Manager config loader (5-min cache)
├── email.ts              # SES email sender + HTML template
├── types.ts              # Shared TypeScript interfaces
└── handlers/
    ├── request-token.ts  # POST /idp/request-token
    ├── login.ts          # POST /idp/login
    ├── verify.ts         # POST /idp/verify
    ├── keys.ts           # GET /idp/keys
    └── rotate.ts         # EventBridge monthly rotation
```

## AWS Dependencies

| Service | Purpose |
|---------|---------|
| SSM Parameter Store | Runtime config (domains, URLs, current key ID) |
| Secrets Manager | Signing key storage |
| SES | Token email delivery |
| Lambda | Handler execution |
| API Gateway | HTTP routing |
| EventBridge | Monthly rotation schedule |

### SSM Parameters

| Path | Example Value |
|------|---------------|
| `/udt/idp/allowedDomains` | `dla.mil,credence-llc.com` |
| `/udt/idp/constellationId` | `dla-piee` |
| `/udt/idp/animatorUrl` | `http://10.0.1.193:3200` |
| `/udt/idp/ses/fromAddress` | `identity@udt-credence.ai` |
| `/udt/idp/ses/fromName` | `DLA PIEE Digital Twin` |
| `/udt/idp/loginUrl` | `https://udt-credence.ai/login` |
| `/udt/idp/currentKid` | `k-2026-05` |

### Secrets Manager

Each signing key stored at `/udt/idp/keys/{kid}` as JSON:

```json
{
  "kid": "k-2026-05",
  "alg": "HS256",
  "secret": "a1b2c3...hex...",
  "createdAt": "2026-05-01T00:00:00.000Z",
  "expiresAt": "2026-06-04T00:00:00.000Z",
  "active": true
}
```

## Development

```bash
# Install dependencies
npm install

# Build (esbuild bundles each handler independently)
npm run build

# Run tests
npm test

# Watch mode
npm run test:watch
```

## Deployment

Manual deployment via AWS CLI or console. Each handler in `dist/` is a self-contained ESM bundle ready for Lambda (Node 20 runtime).

Lambda handler mappings:
- `request-token.handler` → POST /idp/request-token
- `login.handler` → POST /idp/login
- `verify.handler` → POST /idp/verify
- `keys.handler` → GET /idp/keys
- `rotate.handler` → EventBridge schedule (monthly)

## Auth Flow

```
1. User submits email to /idp/request-token
2. IdP validates domain → generates deterministic token → emails it
3. User receives email with token
4. User submits token to /idp/login
5. IdP verifies token → provisions twin via Animator → returns session info
```

Requesting a token multiple times in the same month sends the same token — deterministic generation means no dedup logic needed.
