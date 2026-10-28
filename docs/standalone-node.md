## Standalone Node starter (0.1)

An initial multi-user connector with remote MCP and REST interfaces to the Google Play Developer API. Node.js 24+, JavaScript, Express, the official MCP TypeScript SDK, and Google's OAuth client library.

**Status: development starter, not a launched service.** Local automated tests use mocks; no live Play account or release has been tested. Configure the identity provider and Google OAuth project, finish the launch items below, and test against an internal testing app before inviting users.

## Supported operations

| Operation | Access scope | Effect |
| --- | --- | --- |
| Read reviews | `play:read` | Reads reviews for a known package |
| Reply to a review | `play:write` | Immediately posts a public reply |
| Create an edit | `play:write` | Opens an unpublished Google Play edit |
| Read listings and tracks | `play:read` | Reads within an edit created by this connection |
| Update text listing | `play:write` | Stages title and descriptions |
| Upload AAB | `play:write` | Binary REST upload to an owned edit, up to 150 MiB |
| Update track | `play:write` | Stages the complete release list for that track |
| Validate / discard edit | `play:write` | Validates or deletes staged changes |
| Commit edit | `play:publish` | Validates, then submits changes to Google Play |

MCP exposes `bundle_upload_instructions`, which gives an authenticated REST upload endpoint. Binary bytes are not sent through MCP JSON. An agent needs an HTTP/file capability to upload its build. Screenshot uploads, financial reports, subscriptions, app creation, and Play Console declarations are outside this starter.

Compatibility means clients supporting the SDK's Streamable HTTP MCP protocol versions, or agents capable of calling REST with bearer authentication. This does not guarantee that every agent product supports remote MCP, this authorization flow, or binary uploads. No client-specific integration has been tested yet.

## Authorization architecture

1. Your authorization server authenticates developers and issues connector JWT access tokens. They must have the configured issuer, audience, subject, expiry, issued-at time, and a space-separated `scope` claim. Only RS256 and ES256 are accepted.
2. The connector advertises OAuth protected resource metadata at `/.well-known/oauth-protected-resource/mcp`. The configured authorization server must supply MCP-compatible OAuth discovery, authorization code flow with PKCE, client onboarding/registration, refresh, consent, and resource/audience binding. These functions are deliberately delegated; this repository does not implement an authorization server.
3. Your signed-in web frontend sends `POST /connect` using a connector token with `play:connect`. The response sets a browser-bound, HttpOnly state cookie and returns `authorizationUrl`. Navigate that same browser to the returned URL.
4. Google returns to `/google/callback`. The connector checks the state cookie, consumes single-use state, exchanges the Google authorization code with PKCE, and encrypts the resulting tokens for that tenant.
5. Agents call `/mcp` or `/api/tools/:name` with connector access tokens. Google tokens stay on the server and are never returned to agents.

Tenant keys derive from the verified issuer and subject. Token encryption uses AES-256-GCM with the tenant key as authenticated data. Edits are checked against tenant and package before use. The Google user must independently hold the relevant permissions in Play Console.

The Google scope is `https://www.googleapis.com/auth/androidpublisher`; the connector's read/write/publish scopes provide its own finer permission controls. Do not mistake connector read scopes for a read-only Google grant.

Publishing is disabled by default. Setting `ENABLE_PUBLISH=true` is insufficient by itself: the calling token must also have `play:publish`. This is an authorization gate, **not a human approval interface**. Keep that scope out of general agent grants. A separate human approval workflow is a launch item if your product promises per-action approval. Review replies already have an immediate external effect.

## Run locally

```powershell
npm ci
Copy-Item .env.example .env
# Fill in your own configuration; do not commit .env.
npm test
npm start
```

Generate `TOKEN_ENCRYPTION_KEY` using the command in `.env.example`. Use a secrets manager for deployed credentials. Keep the key separate from the database and backups.

In Google Cloud, enable the Google Play Developer API and create a web OAuth client. Configure its exact redirect URI as `PUBLIC_URL/google/callback`. Configure consent branding, domains, scopes, and test users; complete whatever verification Google requires for your selected audience and scopes before public rollout. Developers connect a Google identity that has access to their apps in Play Console. They provide package names; this starter does not discover every app in their account.

Use an external OAuth authorization server configured to issue tokens for `AUTH_AUDIENCE`. For remote MCP, that audience should identify `PUBLIC_URL/mcp`. Set its issuer and JWKS URI in `.env`. Never use Google's access token as the connector bearer token.

The server binds to loopback. For public hosting, put an HTTPS gateway on the same host in front of it. Keep one application process and persistent SQLite storage for this starter; migrations to a shared database and distributed rate limiting are needed before horizontal scaling. The current rate limiter keys on the direct peer address, so a proxy may share a single quota across users. Configure trusted proxies and per-tenant limits before a public launch; do not blindly trust forwarded headers.

## REST example

Call `POST /api/tools/create_edit` with `Authorization: Bearer <connector-token>`, `Content-Type: application/json`, and:

```json
{"packageName":"com.example.app"}
```

Then upload AAB bytes to `POST /api/bundles/com.example.app/EDIT_ID` with the same connector authorization and `Content-Type: application/octet-stream`. Use returned version codes with `update_track`, validate with `validate_edit`, then use a separately authorized `commit_edit` call. Store-listing changes use the same edit flow. Track updates replace the track's release list, so read the current track first.

Generic tool calls use `POST /api/tools/TOOL_NAME`; request bodies follow the Zod schemas in `src/tools.js`. MCP clients discover the same schemas through `tools/list` at `/mcp`.

`DELETE /connection` requires `play:connect`. It attempts Google revocation, then removes local credentials, pending states, and owned edit records. It reports whether Google revocation succeeded. In-flight operations cannot be recalled. Uncommitted Google edits may remain until they expire.

## Before public launch

- Implement the signed-in onboarding page and client connection instructions against your chosen identity provider. Test discovery, consent, access-token audiences, token refresh, client registration, and expired grants with actual agent clients.
- Implement per-action human approvals if required, bound to immutable payloads and edit revisions. Do not use an agent-controlled boolean as proof of approval.
- Add organization membership, package allowlists, reconnection identity confirmation, and an account settings page. Currently isolation is per authenticated user, not per organization.
- Replace the buffered 150 MiB upload endpoint with resumable, quota-controlled streaming for larger builds; test disconnects and Google processing timeouts. Do not retry commits or replies automatically after ambiguous network failures; inspect Play Console first.
- Add per-tenant quotas, distributed controls if scaling, encrypted backups, retention/deletion jobs, key rotation, and operational alerts. SQLite and Google token refresh concurrency require review before multiple workers.
- Add durable idempotency/reconciliation for external writes. The current audit records operation outcomes without storing review contents or tokens; it is not a tamper-proof audit service.
- Finish privacy policy, terms, Google OAuth verification requirements, and a security review. Review the single broad Google scope and consent messaging.
- Test listing changes, bundle signing/version codes, tracks, staged rollouts, edits that expire, rejected permissions, revocation, and managed publishing against real test apps. Google review and managed-publishing settings affect when committed changes become live.

## Reference documentation

- [Google Play API setup](https://developers.google.com/android-publisher/getting_started)
- [Google OAuth web server flow](https://developers.google.com/identity/protocols/oauth2/web-server)
- [Google Play API methods](https://developers.google.com/android-publisher/api-ref/rest)
- [Commit an edit](https://developers.google.com/android-publisher/api-ref/rest/v3/edits/commit)
- [MCP authorization](https://modelcontextprotocol.io/docs/tutorials/security/authorization)
- [MCP SDK server documentation](https://ts.sdk.modelcontextprotocol.io/server)
