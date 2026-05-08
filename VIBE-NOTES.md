# IdP Vibe Build Notes

**Date:** 2026-05-02
**Approach:** Vibe-first — build manually, take notes, then codify into CDK

---

## Resources Created

### SES Domain Identity
- Domain: `udt-credence.ai`
- Status: PENDING (needs DKIM CNAME records in DNS)
- DKIM Tokens (add as CNAME records to udt-credence.ai hosted zone):
  - `32sarnm6giysxu6sqy65xoeknkipuvmc._domainkey.udt-credence.ai` → `32sarnm6giysxu6sqy65xoeknkipuvmc.dkim.amazonses.com`
  - `hxalq76e25m55adusfyjzi23g443knoh._domainkey.udt-credence.ai` → `hxalq76e25m55adusfyjzi23g443knoh.dkim.amazonses.com`
  - `wvko5r5yggdqtuakfst4yfr7h4fa4qvz._domainkey.udt-credence.ai` → `wvko5r5yggdqtuakfst4yfr7h4fa4qvz.dkim.amazonses.com`
- NOTE: DNS hosted zone is in Credence AWS account, not Bill's. Need to add these CNAME records there.
- Until verified, can use `wcfredricks@gmail.com` as sender for testing (already verified).

### Secrets Manager
- `/udt/idp/keys/k-2026-05` — signing key (HS256, 256-bit, expires 2026-06-04)
  - ARN: `arn:aws:secretsmanager:us-east-1:230152865130:secret:/udt/idp/keys/k-2026-05-KMmwsv`
- `/udt/idp/mfa/{sha256(email)}` — per-user TOTP enrollment (created dynamically)

### SSM Parameter Store
- `/udt/idp/allowedDomains` = `*.mil,*credence*,gmail.com`
- `/udt/idp/constellationId` = `dla-piee`
- `/udt/idp/animatorUrl` = `http://{public-ip}:3200` (changes on ECS redeploy!)
- `/udt/idp/ses/fromAddress` = `wcfredricks@gmail.com` (temp until udt-credence.ai verified)
- `/udt/idp/ses/fromName` = `UDT Digital Twin`
- `/udt/idp/loginUrl` = `https://udt-credence.ai/login`
- `/udt/idp/currentKid` = `k-2026-05`
- `/udt/idp/mfaPolicy` = `optional`
- `/udt/idp/mfaIssuer` = `DLA PIEE`

### IAM Role
- `udt-idp-lambda-role`
- Policies: AWSLambdaBasicExecutionRole, idp-permissions (SSM, Secrets Manager, SES)

### Lambda Functions (8)
- `udt-idp-request-token` (256MB, 30s)
- `udt-idp-login` (256MB, 90s)
- `udt-idp-verify` (256MB, 30s)
- `udt-idp-keys` (256MB, 30s)
- `udt-idp-rotate` (512MB, 300s)
- `udt-idp-mfa-enroll` (256MB, 30s)
- `udt-idp-mfa-verify` (256MB, 30s)
- `udt-idp-mfa-reset` (256MB, 30s)

### API Gateway
- API ID: `1r0hhe5l5d`
- Type: HTTP API
- Endpoint: `https://1r0hhe5l5d.execute-api.us-east-1.amazonaws.com`
- Stage: $default (auto-deploy)
- CORS: AllowOrigins *, AllowMethods GET/POST/OPTIONS
- Routes (9):
  - `POST /idp/request-token`
  - `POST /idp/login`
  - `POST /idp/verify`
  - `GET /idp/keys`
  - `POST /idp/mfa/enroll`
  - `POST /idp/mfa/verify`
  - `POST /idp/mfa/reset-request`
  - `POST /idp/mfa/reset-confirm`
  - `POST /admin/reset-mfa`

### EventBridge Schedule
- NOT YET CREATED — monthly rotation Lambda exists but needs EventBridge rule
- TODO: `aws events put-rule --schedule-expression 'cron(0 0 1 * ? *)'`

---

## Decisions Made During Build

1. **Lambda NOT in VPC** — Animator reached via public IP. VPC Lambda needs NAT Gateway for SSM/SES, which costs $30/mo. Not worth it for dev.
2. **Login Lambda 90s timeout** — Animator provision waits up to 60s. But API Gateway has 30s hard limit. Fixed with 10s AbortController on provision fetch — returns "provisioning" status if Animator is slow.
3. **animatorUrl uses public IP** — changes on every ECS redeploy. Need to update SSM param. TODO: use ALB DNS name instead.
4. **SES From address** — using `wcfredricks@gmail.com` until `udt-credence.ai` DKIM verified.
5. **Domain matching** — supports `*.mil` (suffix), `*credence*` (contains), exact match, and `*` (all).
6. **Login link in email** — token embedded in URL: `?token=...`. User clicks, logs in. Can bookmark for the month.
7. **Rejection email** — unauthorized domains get a helpful email pointing to `auth-support@udt-credence.ai`.

## Issues Encountered

1. Keys Lambda: `ListSecrets` permission missing — fixed by adding to IAM policy with `Resource: *`
2. Login Lambda VPC: couldn't reach SSM/SES without NAT Gateway — removed VPC, use public IP
3. VPC removal took ~2 minutes to propagate — Lambda returned ServiceUnavailable during transition
4. API Gateway 30s integration timeout — can't wait for Animator's 60s provision. Fixed with AbortController.

## What Worked Well

1. esbuild bundling — 8 handlers in 15ms, 3-16KB each
2. Self-validating HMAC pattern — same approach for access tokens, MFA session tokens, reset links
3. SSM + Secrets Manager — config and keys separate, proper access control
4. Deterministic tokens — idempotent by math, no database dedup needed
5. Vibe-first approach — got it working in ~2 hours, all decisions documented for CDK conversion

