# Release readiness

This is a development review of the 0.2 Cloudflare beta, not an independent security audit. The service is deployed and configuration is present. Real Google authentication and Play Console requests remain unverified.

## Verified by automated tests

- Standalone token encryption binds ciphertext to the authenticated tenant.
- Standalone OAuth state expires and is single-use.
- Edit ownership is checked by tenant and package.
- Publishing requires dedicated authorization in the standalone backend and is unavailable in the hosted beta.
- Release input validation checks staged rollout fractions and rejects injected path segments.
- HTTP access requires authentication; MCP tool discovery filters write/publish tools.
- Cloudflare setup pages fail closed when Google configuration is missing.
- OAuth discovery and unauthenticated MCP challenges work in the Workers runtime.
- A simulated Google-backed agent flow exercises registration, consent, PKCE, identity-token verification, encrypted storage, tool listing, a review read, and disconnect.

## Required before inviting public users

- [ ] Complete real Google sign-in with the deployed redirect URI and a permitted test user.
- [ ] Confirm Google Play Android Developer API is enabled and a known package is accessible.
- [ ] Read real reviews, including pagination and permission-denied behavior.
- [ ] Verify Google access-token refresh, agent refresh, revoked Google grants, and expired agent grants. The current automated flow does not exercise every refresh/error path.
- [ ] Test actual MCP clients, including requested scopes, client registration, browser consent, token refresh, and reconnect behavior.
- [ ] Test a signed AAB on an internal testing app, upload interruptions, accurate Content-Length, and the 90 MiB limit.
- [ ] Test store listing edits, release track replacement, expired edits, validation errors, and discard behavior.
- [ ] Test negative authorization cases beyond the current suite: cross-browser consent replay, wrong nonce/audience, refresh reuse, and read-only tokens attempting writes.
- [ ] Confirm Google's applicable consent branding, privacy, domain, production-audience, and scope-verification requirements. Configuration presence is not verification approval.
- [ ] Review privacy/support contact details, retention, backups, account deletion, and a private security-reporting channel.
- [ ] Rotate credentials shared during setup and replace the deployed secret values. Do not rotate the database encryption key casually.

## Reliability and security work

- **Ambiguous writes:** review replies and other external writes do not yet have durable idempotency and reconciliation. A network timeout or audit-storage failure can follow a successful Google action. Inspect the external state before retrying.
- **Authorization lifecycle:** disconnect blocks subsequent requests, but does not recall in-flight requests. Exercise concurrent refresh/reconnect/disconnect races before a broad launch.
- **Uploads:** the current service streams a single upload of at most 90 MiB. Resumable or larger uploads need a separate design and tests.
- **Account scope:** isolation is per verified Google user, not per organization. Package allowlists, team roles, and a dedicated settings UI are not implemented.
- **Rate limits:** IP/account rate limits are not a strict global usage or cost budget. Establish operational budgets and abuse monitoring before public registration.
- **Operations:** configure monitoring, alerts, backup/restore drills, audit integrity, encryption-key migration, and a repeatable deployment/rollback procedure.
- **CI:** `npm run check` is reproducible locally; automated GitHub checks and automatic deployment are not configured.
- **Publishing:** remains disabled. Enabling public release commits requires a separate review and, if promised by the product, a real per-action human approval mechanism bound to the exact staged change.

## Review changes

The README now describes the current Cloudflare deployment rather than mixing it with the Node starter. Legacy documentation is preserved separately. The package version matches the hosted 0.2 code, and `npm run check` builds and runs both suites without silently skipping the Worker tests.
