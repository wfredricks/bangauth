# cdk/ — AWS deployment (placeholder)

A generic CDK stack that deploys BangAuth to AWS as Lambda functions
behind API Gateway, with SES for email, Secrets Manager for signing
keys, and EventBridge for monthly rotation, is **not yet shipped** as
part of this repo.

For v0.1.x, the supported deployment path is the `Dockerfile` at the
repo root — BangAuth runs as a standalone Hono service on whatever
host you choose.

If you need to deploy to AWS today, the building blocks are:

- One Lambda per handler in `src/handlers/`
- API Gateway routes mapped to those Lambdas
- SES domain identity for the sender address (verify DKIM)
- Secrets Manager entries under your `BANGAUTH_SSM_PREFIX` for the
  signing keys (one per month, e.g. `${prefix}keys/k-2026-05`)
- SSM Parameter Store entries under the same prefix for config
- EventBridge schedule `cron(0 0 1 * ? *)` to invoke the rotate
  handler on the 1st of each month

A reference (UDT-specific) version of the stack lives on the
`legacy/cdk-udt-deployment` branch for reference. It is not generic
enough to ship on `main` and was extracted there pending a rewrite.
