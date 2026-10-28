# Google Play Console MCP

Connect MCP-compatible agents to Google Play Console through a hosted Cloudflare Worker. The service provides Google sign-in, per-agent consent, scoped access, review tools, store listing edits, streaming build uploads, and release preparation.

**Status: deployed developer beta. Google credentials are configured, but real Google sign-in and live Play Console operations have not yet been validated. Publishing is disabled.** Passing automated tests is not a production-readiness or security certification.

## Hosted service

| Address | Purpose |
| --- | --- |
| [Service homepage](https://play-console-mcp.taimweromita505.workers.dev/) | Connection instructions and beta status |
| `https://play-console-mcp.taimweromita505.workers.dev/mcp` | Remote MCP endpoint to add to an agent |
| [Health status](https://play-console-mcp.taimweromita505.workers.dev/health) | Configuration presence and live-validation status |
| [Data and privacy](https://play-console-mcp.taimweromita505.workers.dev/privacy) | Beta data-handling notice |

`googleConfigured: true` means the required configuration is present. It does not prove that Google accepts the credentials, that the consent configuration is correct, or that the account has app permissions.

## Connect an agent

1. Add the remote MCP endpoint above in a client supporting Streamable HTTP, OAuth authorization codes with S256 PKCE, and either dynamic client registration or Client ID Metadata Documents.
2. Request `play:read` for the first test. Add other scopes only when needed.
3. Review the client name, redirect destination, and permissions on the consent page. Continue with Google using an account with access to your app in Play Console.
4. Ask the agent to list reviews for a known package name, such as `com.example.app`.

If Google's OAuth app is in testing mode, the account must be included in its test-user list. The Google Play Android Developer API must be enabled in the operator's Cloud project. Each developer uses the operator's OAuth app; they do not create their own Google Cloud project for this service.

This service does not discover every app in an account. Users supply package names. Compatibility has not yet been tested against individual agent products. Agents need an HTTP/file-upload capability in addition to MCP to send build bytes.

## Permissions and tools

| Scope | Capabilities | Effect |
| --- | --- | --- |
| `play:read` | `list_reviews`, `get_tracks`, `get_listings` | Read reviews or inspect an existing edit owned by this connection |
| `play:write` | `reply_review` | Immediately posts a public review reply |
| `play:write` | `create_edit`, `update_listing`, `update_track`, `validate_edit`, `discard_edit` | Creates, modifies, validates, or discards unpublished edits |
| `play:write` | `bundle_upload_instructions` and binary REST upload | Uploads an AAB into an owned edit; maximum 90 MiB |
| `play:manage` | `DELETE /mcp/api/connection` | Attempts Google revocation and removes the account's local connection |
| `offline_access` | Agent session refresh | Requests continued access according to the OAuth grant lifetime |

Reading staged listings or tracks requires an edit previously created with `play:write`. Track updates replace the staged release list: inspect the existing track first. Text listings are supported; screenshots, graphics, app creation, financial reports, and subscription management are not included.

`commit_edit` is **not exposed by the hosted service**. Setting `ENABLE_PUBLISH=true` does not enable it in this beta; the Worker intentionally excludes publishing. Per-agent consent is not per-action human approval. Review replies already have an immediate external effect.

The connector uses Google's broad `https://www.googleapis.com/auth/androidpublisher` permission, alongside `openid email` for sign-in. Connector scopes provide the finer read/write/manage controls; Google does not receive a read-only scope just because an agent requests `play:read`.

## Architecture

- **Worker:** `src/cloudflare/worker.ts`; configuration in `wrangler.jsonc`.
- **OAuth:** Cloudflare's official Workers OAuth Provider handles discovery, registration, PKCE, agent tokens, and refresh. Google authenticates the developer. Agent credentials and Google tokens are separate.
- **D1:** Encrypted Google tokens, tenant-owned edits, and audit records. Identity comes from Google's verified `sub` claim. Google ID tokens are checked for issuer, audience, signature, expiry, and nonce.
- **KV:** A dedicated namespace holds OAuth state and grants. The provider library handles grant and credential protection.
- **Uploads:** Streamed directly to Google using fixed-length streams. No R2 bucket is required for the current 90 MiB upload flow.
- **Limits:** Cloudflare rate limits apply by IP and authenticated account. They are not a global billing cap or an exact distributed quota.
- **Retention:** A daily scheduled job deletes audit records older than 30 days. D1 backups and provider retention need separate operator policies.

Disconnect removes Google tokens and owned edit records. Old grants are rejected through a connection-revision check after a normal disconnect and reconnect. An already-running Google request cannot be recalled. OAuth grant records may remain until expiry or separate revocation; disconnect does not promise to erase Cloudflare logs or backups.

## REST API

The hosted REST API accepts the same connector bearer token as MCP, bound to the canonical `/mcp` resource. Never send a Google access token as the connector token.

| Method and path | Request |
| --- | --- |
| `POST /mcp/api/tools/TOOL_NAME` | JSON matching the tool schema in `src/tools.js` |
| `POST /mcp/api/bundles/PACKAGE_NAME/EDIT_ID` | AAB bytes; `Content-Type: application/octet-stream`; accurate `Content-Length`; at most 90 MiB |
| `DELETE /mcp/api/connection` | No body; requires `play:manage` |

For a read-only first test, call `list_reviews` with:

```json
{"packageName":"com.example.app","maxResults":20}
```

For release preparation, create an edit, upload the signed AAB, inspect the track, stage the complete release list, and validate the edit. The hosted beta cannot commit it. Do not retry review replies or other writes blindly after a timeout: their outcome can be ambiguous.

## Develop and verify

Use Node.js 24 or later:

```sh
npm ci
npm run check
```

`check` runs the standalone tests, generates Cloudflare runtime types, type-checks the Worker, builds its bundle, and runs the Workers integration tests. Run `npm test` for the standalone suite only. Worker tests require the generated bundle and deliberately do not silently skip when it is missing.

The automated suites currently contain ten tests. They cover tenant-bound token encryption, single-use OAuth state, edit ownership, publishing gates, rollout validation, HTTP/MCP permissions, and a full simulated Google-backed OAuth flow in workerd. The simulated flow includes agent registration, consent, ID-token verification, token exchange, tool discovery, review reads, encrypted D1 storage, and account disconnect. It does not contact a real Play account.

For local Workers development, use ignored local secret configuration and run `npm run cf:dev`. A development OAuth client, local `PUBLIC_URL`, and the exact local Google callback URI must be configured together. Production callback settings are not automatically valid for localhost.

## Deploy to your own Cloudflare account

The checked-in account, database, namespace IDs, and hostname belong to this deployment. Replace them before deploying a fork.

1. Create your Worker, a D1 database, and a dedicated OAuth KV namespace. Update their identifiers and `PUBLIC_URL` in `wrangler.jsonc`.
2. Enable Google Play Android Developer API and create a Google OAuth **Web application** client.
3. Configure the Google redirect URI to exactly `PUBLIC_URL/google/callback`. For the deployment above it is:

   ```text
   https://play-console-mcp.taimweromita505.workers.dev/google/callback
   ```

4. Add the Worker secrets `GOOGLE_CLIENT_ID`, `GOOGLE_CLIENT_SECRET`, and `TOKEN_ENCRYPTION_KEY`. Generate the encryption key from 32 cryptographically random bytes encoded as base64. Use dashboard secret entry or interactive `wrangler secret put NAME`; do not pass secret values in command arguments.
5. Apply the schema and deploy:

   ```sh
   npx wrangler d1 migrations apply play-console-mcp-db --remote
   npm run check
   npm run cf:deploy
   ```

6. Verify the homepage and `/health`. Unauthenticated `/mcp` requests should return `401` with a protected-resource metadata challenge. Test a real Google account and actual agent client before inviting others.

Keep the encryption key stable. Changing it without migrating existing records makes stored Google tokens unreadable. Google credentials are stored in Cloudflare secrets, not the repository. A deployment and a GitHub push are separate operations; pushing code does not automatically deploy it.

## Remaining launch work

See [release readiness](docs/release-readiness.md) for the specific validation and operational gaps. A real sign-in test, Google Play read and write tests, token-refresh and revocation tests, actual client compatibility, applicable Google verification, and an operator security review are still outstanding. Automated CI is not configured yet. No general public launch is claimed.

The older Express/SQLite implementation uses different endpoints, authentication requirements, and a 150 MiB buffered upload limit. Its instructions are isolated in [the standalone Node guide](docs/standalone-node.md); they do not describe the hosted Cloudflare service.

## References

- [Google Play API setup](https://developers.google.com/android-publisher/getting_started)
- [Google OAuth web-server flow](https://developers.google.com/identity/protocols/oauth2/web-server)
- [Cloudflare MCP authorization](https://developers.cloudflare.com/agents/model-context-protocol/protocol/authorization/)
- [Cloudflare MCP security](https://developers.cloudflare.com/agents/model-context-protocol/guides/securing-mcp-server/)
- [MCP authorization](https://modelcontextprotocol.io/docs/tutorials/security/authorization)
