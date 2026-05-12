# Changelog

All notable changes to BangAuth are documented here. Format follows
[Keep a Changelog](https://keepachangelog.com/en/1.1.0/); the project
follows [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [0.1.1] — 2026-05-12

First release under the workspace's `PUBLISHING.md` discipline: source
of truth is this repo, versions are bumped per change, consumers
install by tag.

### Added

- **`src/index.ts` library barrel.** Exposes the pure engine pieces
  (`generateToken`, `verifyToken`, `currentMonth`, `isMonthValid`,
  TOTP helpers, MFA-session helpers, recovery-code helpers,
  `isDomainAllowed`, `deriveTwinId`) so callers who want to use the
  primitives without standing up the Hono server can. The server
  remains the supported v0.1 path; the library surface is what makes
  the v0.2 "embed as Hono middleware" deliverable tractable.
- **`LICENSE`** file (Apache 2.0). The README had always claimed
  Apache 2.0 but no LICENSE file existed; fixed.
- **`CHANGELOG.md`** (this file).
- **`package.json`** now declares `main`, `module`, `types`,
  `exports`, `files`, a `prepare` script that builds before install
  (so `npm install github:wfredricks/bangauth#v0.1.1` actually
  produces a usable package — lesson from PolyGraph v0.1.1 → v0.1.2),
  and `prepublishOnly` for registry publishes.
- **`tsconfig.json`** now sets `ignoreDeprecations: "6.0"` (silences
  a downstream `baseUrl` deprecation warning in TS 6.x) and
  `types: ["node"]` (needed for `Buffer` references in the MFA
  session module to type-check during the dts build).

### Changed

- **README.md** rewritten in places to match what the code actually
  does:
  - **New "Why It's Different" section** promotes the monthly-rotating
    salt design (the access code IS the password, and it expires
    every month by construction) from a one-line footnote to the
    headline argument. This is the novel idea most readers will come
    for; it deserves the lead.
  - **Quick Start** rewritten to reflect reality. The v0.1 line is a
    standalone Hono service (`npm start` or Docker run), not the
    in-process `createBangAuth(config)` middleware the earlier README
    promised. The middleware path is acknowledged as a v0.2 deliverable
    with a clear note.
  - **Deployment** section: Docker is the default path. The CDK stack
    in `cdk/` is acknowledged as experimental and not the recommended
    deployment today.
  - **Architecture** diagram redrawn to show the actual HTTP boundary
    between consumer and BangAuth, and to name the pure-functions /
    I/O-shell split that makes the v0.2 embed path tractable.
  - **Recovery codes** description corrected to "10 single-use" (the
    code generates 10; README had said 8).

### Fixed

- The build script (`tsup src/index.ts`) was pointing at a file that
  didn't exist; `src/index.ts` now exists and the build succeeds.

### Notes

- 43/43 tests pass. The library barrel only re-exports existing
  modules, so no new test coverage is required for it; the modules
  it exports were already pinned by `src/__tests__/`.
- The README's earlier claim of `npm install bangauth` was aspirational.
  v0.1.1 is consumable via `github:wfredricks/bangauth#v0.1.1`.
  Registry publish (`npm publish`) is deferred until the v0.2 library
  surface is stable.

## [0.1.0] — 2026-05 (initial implementation)

- Hono server with login / verify / MFA-enroll / MFA-verify / recovery
  endpoints.
- Monthly-rotating access codes (`SHA-256(email + YYYY-MM + secret)`)
  with a 3-day grace period across month boundaries.
- Monthly-rotating HMAC signing keys for JWT issuance.
- TOTP enrollment with QR URI generation and brute-force protection
  on the verification path (max 5 attempts per session).
- 10 single-use recovery codes per user (XXXX-XXXX format, ambiguous
  characters removed).
- Pluggable email / key-store / user-store adapters.
- Dockerfile and `bangauth.yaml` for containerized deployment.
- 43 tests covering the token engine, domain allowlist, recovery
  codes, MFA sessions, TOTP, and email templates.
