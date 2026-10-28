import { OAuthProvider, AuthorizationError, type OAuthHelpers, authorizationErrorRedirect } from '@cloudflare/workers-oauth-provider';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { WebStandardStreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/webStandardStreamableHttp.js';
import { z } from 'zod';
import { Buffer } from 'node:buffer';
import { tools, execute, editArgs } from '../tools.js';
import { D1Store } from './store';
import { cloudPlay, exchangeCode, limitedJson, PLAY_SCOPE } from './google';
import { escape, home, layout, privacy } from './pages';

type AppEnv = Env & { OAUTH_PROVIDER?: OAuthHelpers };
const propsSchema = z.object({ tenant: z.string().min(1), revision: z.string().uuid() });
const supportedScopes = ['play:read', 'play:write', 'play:manage', 'offline_access'];
const descriptions: Record<string, string> = {
  'play:read': 'Read app reviews and staged store listings and tracks.',
  'play:write': 'Post public review replies, upload builds, and stage listing and release changes. Replies take effect immediately.',
  'play:manage': 'Disconnect this Google Play connection and remove its stored credentials.',
  'offline_access': 'Keep the agent connected using refresh tokens until access expires or is revoked.'
};
const ready = (env: Env) => Boolean(env.GOOGLE_CLIENT_ID && env.GOOGLE_CLIENT_SECRET && env.TOKEN_ENCRYPTION_KEY);
const html = (body: string, headers: HeadersInit = {}, status = 200) => {
  const h = new Headers(headers);
  h.set('Content-Type', 'text/html; charset=utf-8');
  return new Response(body, { status, headers: h });
};
const json = (body: unknown, status = 200) => Response.json(body, { status });
const storeFor = (env: Env) => new D1Store(env.DB, env.TOKEN_ENCRYPTION_KEY);

async function authorize(request: Request, env: AppEnv) {
  const oauth = env.OAUTH_PROVIDER;
  if (!oauth) throw new Error('Authorization configuration unavailable');
  if (!ready(env)) return html(layout('Setup pending', `<h1>Google connection setup is pending.</h1><p>The service is online. The operator must configure its Google OAuth client before developers can connect.</p><p>The callback address is:</p><pre><code>${escape(env.PUBLIC_URL)}/google/callback</code></pre>`), {}, 503);
  if (request.method === 'GET') {
    const authRequest = await oauth.parseAuthRequest(request);
    if (authRequest.codeChallengeMethod !== 'S256' || !authRequest.codeChallenge) return html(layout('Cannot connect', '<h1>PKCE is required.</h1><p>Use an MCP client that supports authorization with S256 PKCE.</p>'), {}, 400);
    const details = await oauth.describeConsent(authRequest);
    const consent = await oauth.beginConsent(authRequest);
    // Chromium applies form-action to the POST's redirect chain as well as its
    // first destination. Allow only Google and this validated client's origin.
    const clientOrigin = new URL(authRequest.redirectUri).origin;
    consent.headers.set('Content-Security-Policy', `default-src 'none'; style-src 'unsafe-inline'; form-action 'self' https://accounts.google.com ${clientOrigin}; frame-ancestors 'none'; base-uri 'none'`);
    const scopeList = details.scope.map(scope => `<label><input type="checkbox" name="scope" value="${escape(scope)}" checked> <strong>${escape(scope)}</strong><br>${escape(descriptions[scope] ?? scope)}</label>`).join('');
    return html(layout('Authorize your agent', `<span class="tag">Permission request</span><h1>Connect ${escape(details.clientName)}?</h1><p>${details.clientDomain ? `Client domain: <strong>${escape(details.clientDomain)}</strong>.` : 'This client registered itself. Its displayed name is not verified.'} Authorization returns to <strong>${escape(details.redirectHost)}</strong>.</p>${details.redirectIsLoopback ? '<p class="notice">This connects to an app on your computer. Continue only if you started this connection.</p>' : ''}<p>Choose the permissions to grant. You will then sign in with Google and approve Google Play access.</p><form method="post" action="/authorize"><input type="hidden" name="handle" value="${escape(consent.handle)}"><section>${scopeList}</section><p>Publishing is disabled during this beta.</p><button name="decision" value="approve">Continue with Google</button> <button class="secondary" name="decision" value="deny">Cancel</button></form>`), consent.headers);
  }
  if (request.method !== 'POST') return json({ error: 'method_not_allowed' }, 405);
  if (Number(request.headers.get('Content-Length') || 0) > 8192) return json({ error: 'Request too large' }, 413);
  const body = await limitedText(request, 8192);
  const form = new URLSearchParams(body);
  const handle = form.get('handle') ?? '';
  if (form.get('decision') !== 'approve') {
    const result = await oauth.denyConsent(request, handle);
    return new Response(null, { status: 302, headers: result.headers });
  }
  const scope = form.getAll('scope');
  const approved = await oauth.approveConsent(request, handle, { scope });
  const verifier = crypto.randomUUID() + crypto.randomUUID();
  const nonce = crypto.randomUUID();
  const challenge = Buffer.from(await crypto.subtle.digest('SHA-256', new TextEncoder().encode(verifier))).toString('base64url');
  const upstream = await oauth.beginUpstream(approved.request, { data: { verifier, nonce }, headers: approved.headers });
  const google = new URL('https://accounts.google.com/o/oauth2/v2/auth');
  for (const [key, value] of Object.entries({ client_id: env.GOOGLE_CLIENT_ID, redirect_uri: `${env.PUBLIC_URL}/google/callback`, response_type: 'code', scope: `openid email ${PLAY_SCOPE}`, access_type: 'offline', prompt: 'consent select_account', state: upstream.state, nonce, code_challenge: challenge, code_challenge_method: 'S256' })) google.searchParams.set(key, value);
  upstream.headers.set('Location', google.href);
  return new Response(null, { status: 302, headers: upstream.headers });
}

async function callback(request: Request, env: AppEnv) {
  if (!env.OAUTH_PROVIDER || !ready(env)) return json({ error: 'Google connection setup pending' }, 503);
  const oauth = env.OAUTH_PROVIDER;
  const original = await oauth.finishUpstream<{ verifier: string; nonce: string }>(request);
  const query = new URL(request.url).searchParams;
  if (query.has('error')) {
    original.headers.set('Location', authorizationErrorRedirect(original.request, 'access_denied'));
    return new Response(null, { status: 302, headers: original.headers });
  }
  const code = z.string().min(1).max(4096).parse(query.get('code'));
  const google = await exchangeCode(env, code, original.data.verifier, original.data.nonce);
  const store = storeFor(env);
  const previous = await store.credentials(google.tenant);
  const refreshToken = google.tokens.refresh_token ?? previous?.tokens.refresh_token;
  if (!refreshToken) throw new Error('Google offline access unavailable; reconnect and approve access');
  const revision = previous?.revision ?? crypto.randomUUID();
  await store.saveCredentials(google.tenant, { ...google.tokens, refresh_token: refreshToken }, revision);
  const completed = await oauth.completeAuthorization({ request: original.request, userId: google.tenant, metadata: {}, scope: original.request.scope, props: { tenant: google.tenant, revision } });
  await store.audit(google.tenant, 'connect', '', 'success');
  original.headers.set('Location', completed.redirectTo);
  return new Response(null, { status: 302, headers: original.headers });
}

async function limitedText(request: Request, limit: number) {
  const reader = request.body?.getReader();
  if (!reader) return '';
  const decoder = new TextDecoder();
  let length = 0, result = '';
  while (true) {
    const { done, value } = await reader.read();
    if (done) return result + decoder.decode();
    length += value.byteLength;
    if (length > limit) { await reader.cancel(); throw new Error('Request too large'); }
    result += decoder.decode(value, { stream: true });
  }
}

const ApiHandler = {
  async fetch(request: Request, env: AppEnv, ctx: ExecutionContext) {
    const authContext = ctx as ExecutionContext & { props?: unknown; auth?: { scope: string[] } };
    const props = propsSchema.parse(authContext.props);
    const scopes = new Set(authContext.auth?.scope ?? []);
    const limited = await env.REQUEST_LIMITER.limit({ key: `user:${props.tenant}` });
    if (!limited.success) return json({ error: 'rate_limited' }, 429);
    const store = storeFor(env);
    await store.requireConnection(props.tenant, props.revision);
    const play = cloudPlay(env, store, props.tenant, props.revision);
    const path = new URL(request.url).pathname;
    const invoke = (name: string, input: unknown) => execute(name, input, { scopes }, play, false);
    if (path === '/mcp') {
      const server = new McpServer({ name: 'google-play-console', version: '0.2.0' });
      for (const [name, tool] of Object.entries(tools)) {
        if (!scopes.has(tool.scope) || tool.scope === 'play:publish') continue;
        server.registerTool(name, { description: tool.description, inputSchema: tool.schema.shape, annotations: { readOnlyHint: tool.scope === 'play:read', destructiveHint: tool.scope !== 'play:read', openWorldHint: true } }, async (input: unknown) => {
          try { return { content: [{ type: 'text' as const, text: JSON.stringify(await invoke(name, input)) }] }; }
          catch (error) { return { isError: true, content: [{ type: 'text' as const, text: publicError(error) }] }; }
        });
      }
      if (scopes.has('play:write')) server.registerTool('bundle_upload_instructions', { description: 'Get the authenticated binary upload endpoint. Requires HTTP and file-upload capabilities. Maximum 90 MiB per upload.', inputSchema: editArgs }, async input => {
        try {
          await store.requireEdit(props.tenant, input.packageName, input.editId);
          return { content: [{ type: 'text' as const, text: JSON.stringify({ method: 'POST', url: `${env.PUBLIC_URL}/mcp/api/bundles/${input.packageName}/${input.editId}`, contentType: 'application/octet-stream', authorization: 'Use the connector bearer token. Never send a Google token.', maxBytes: 90 * 1024 * 1024 }) }] };
        } catch (error) { return { isError: true, content: [{ type: 'text' as const, text: publicError(error) }] }; }
      });
      const transport = new WebStandardStreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true, maxRequestBodySize: 1024 * 1024 });
      try { await server.connect(transport); return await transport.handleRequest(request); }
      finally { await server.close(); }
    }
    if (path === '/mcp/api/connection' && request.method === 'DELETE') {
      if (!scopes.has('play:manage')) return json({ error: 'insufficient_scope', scope: 'play:manage' }, 403);
      const current = await store.credentials(props.tenant);
      let googleRevoked = false;
      if (current?.tokens.refresh_token) {
        try { const response = await fetch('https://oauth2.googleapis.com/revoke', { method: 'POST', body: new URLSearchParams({ token: current.tokens.refresh_token }), signal: AbortSignal.timeout(15000) }); googleRevoked = response.ok; await response.body?.cancel(); } catch { /* Still remove local access. */ }
      }
      await store.disconnect(props.tenant);
      await store.audit(props.tenant, 'disconnect', '', 'success');
      return json({ disconnected: true, googleRevoked });
    }
    const tool = /^\/mcp\/api\/tools\/([a-z_]+)$/.exec(path);
    if (tool && request.method === 'POST') {
      const input: unknown = JSON.parse(await limitedText(request, 1024 * 1024));
      try { return json(await invoke(tool[1], input)); } catch (error) { return json({ error: publicError(error) }, 400); }
    }
    const upload = /^\/mcp\/api\/bundles\/([^/]+)\/([^/]+)$/.exec(path);
    if (upload && request.method === 'POST') {
      if (!scopes.has('play:write')) return json({ error: 'insufficient_scope', scope: 'play:write' }, 403);
      const args = z.object(editArgs).parse({ packageName: upload[1], editId: upload[2] });
      const length = Number(request.headers.get('Content-Length'));
      if (!Number.isSafeInteger(length) || length < 1 || length > 90 * 1024 * 1024) return json({ error: 'AAB uploads require Content-Length between 1 byte and 90 MiB' }, 413);
      if (request.headers.get('Content-Type') !== 'application/octet-stream' || !request.body) return json({ error: 'Send AAB bytes with application/octet-stream' }, 400);
      try {
        const result = await play.upload(args.packageName, args.editId, request.body, length);
        await store.audit(props.tenant, 'upload_bundle', args.packageName, 'success');
        return json(result);
      } catch (error) { await store.audit(props.tenant, 'upload_bundle', args.packageName, 'failure'); return json({ error: publicError(error) }, 400); }
    }
    return json({ error: 'not_found' }, 404);
  }
} satisfies ExportedHandler<AppEnv>;

const PublicHandler: ExportedHandler<AppEnv> = {
  async fetch(request, env) {
    const path = new URL(request.url).pathname;
    if (path === '/' && request.method === 'GET') return html(home(env.PUBLIC_URL, ready(env)));
    if (path === '/privacy' && request.method === 'GET') return html(privacy());
    if (path === '/health' && request.method === 'GET') return json({ service: 'play-console-mcp', version: '0.2.0', status: ready(env) ? 'awaiting_live_validation' : 'setup_required', googleConfigured: ready(env), publishingEnabled: false, redirectUri: `${env.PUBLIC_URL}/google/callback` });
    if (path === '/authorize') return authorize(request, env);
    if (path === '/google/callback' && request.method === 'GET') return callback(request, env);
    return json({ error: 'not_found' }, 404);
  }
};

function publicError(error: unknown) {
  if (error instanceof z.ZodError) return 'Invalid arguments';
  const message = error instanceof Error ? error.message : '';
  if (/^(Google |Offline |Connection |Edit |Missing scope:|Publishing |Unknown tool|Response too large)/.test(message)) return message;
  return 'Request failed. Check your connection and try again.';
}

export default {
  async fetch(request: Request, env: Env, ctx: ExecutionContext) {
    const origin = request.headers.get('Origin');
    const path = new URL(request.url).pathname;
    // OAuth token endpoints can be used by browser MCP clients; cookies are only accepted on same-origin forms.
    if (origin && origin !== env.PUBLIC_URL && (path === '/authorize' || path === '/google/callback')) return json({ error: 'Origin not allowed' }, 403);
    const limit = await env.REQUEST_LIMITER.limit({ key: `ip:${request.headers.get('CF-Connecting-IP') ?? 'unknown'}` });
    if (!limit.success) return json({ error: 'rate_limited' }, 429);
    const provider = new OAuthProvider<AppEnv>({
      apiRoute: '/mcp', apiHandler: ApiHandler, defaultHandler: PublicHandler,
      authorizeEndpoint: '/authorize', tokenEndpoint: '/oauth/token', clientRegistrationEndpoint: '/oauth/register',
      scopesSupported: supportedScopes, requiredScopes: ['play:read'], clientIdMetadataDocumentEnabled: true,
      resourceMetadata: { resource: `${env.PUBLIC_URL}/mcp`, authorization_servers: [env.PUBLIC_URL] },
      accessTokenTTL: 3600, refreshTokenTTL: 2592000, clientRegistrationTTL: 2592000
    });
    let response: Response;
    try { response = await provider.fetch(request, env, ctx); }
    catch (error) {
      if (error instanceof AuthorizationError) {
        response = html(layout('Connection failed', '<h1>This connection could not be completed.</h1><p>Restart authorization from your agent. The request may be invalid, expired, or opened in a different browser.</p>'), {}, 400);
      } else { response = json({ error: publicError(error) }, 400); }
    }
    const result = new Response(response.body, response);
    result.headers.set('Cache-Control', 'no-store');
    // HTML POST navigation under no-referrer sends Origin: null. Keep the
    // consent form's real same-origin header without leaking referrers to Google.
    result.headers.set('Referrer-Policy', path === '/authorize' && request.method === 'GET' ? 'same-origin' : 'no-referrer');
    result.headers.set('X-Content-Type-Options', 'nosniff');
    result.headers.set('X-Frame-Options', 'DENY');
    if (result.headers.get('Content-Type')?.includes('text/html') && !result.headers.has('Content-Security-Policy')) result.headers.set('Content-Security-Policy', "default-src 'none'; style-src 'unsafe-inline'; form-action 'self'; frame-ancestors 'none'; base-uri 'none'");
    return result;
  },
  async scheduled(_event: ScheduledController, env: Env) {
    await env.DB.prepare('DELETE FROM audit WHERE time < ?').bind(Date.now() - 30 * 86400000).run();
  }
};
