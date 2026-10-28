import express from 'express';
import { rateLimit } from 'express-rate-limit';
import { createRemoteJWKSet, jwtVerify } from 'jose';
import { McpServer } from '@modelcontextprotocol/sdk/server/mcp.js';
import { StreamableHTTPServerTransport } from '@modelcontextprotocol/sdk/server/streamableHttp.js';
import { mkdirSync } from 'node:fs';
import { dirname } from 'node:path';
import { pathToFileURL } from 'node:url';
import { Store, tenantId } from './store.js';
import { oauth, scope, playClient } from './google.js';
import { tools, execute, editArgs } from './tools.js';
import { z } from 'zod';

export function authenticator(config) {
  const jwks = createRemoteJWKSet(new URL(config.AUTH_JWKS_URI));
  return async (header) => {
    if (!header?.startsWith('Bearer ')) throw new Error('Bearer token required');
    const { payload } = await jwtVerify(header.slice(7), jwks, { issuer: config.AUTH_ISSUER, audience: config.AUTH_AUDIENCE, algorithms: ['RS256', 'ES256'], requiredClaims: ['sub', 'exp', 'iat'] });
    return { tenant: tenantId(payload.iss, payload.sub), scopes: new Set(typeof payload.scope === 'string' ? payload.scope.split(' ') : []) };
  };
}

export function createApp(config, store, authenticate = authenticator(config), factory = playClient) {
  const app = express();
  app.disable('x-powered-by');
  app.use((req, res, next) => {
    res.set({ 'Cache-Control': 'no-store', 'X-Content-Type-Options': 'nosniff', 'Referrer-Policy': 'no-referrer' });
    if (req.headers.origin && req.headers.origin !== config.PUBLIC_URL) return res.status(403).json({ error: 'Origin not allowed' });
    next();
  });
  app.use(rateLimit({ windowMs: 60000, limit: 120, standardHeaders: 'draft-8', legacyHeaders: false }));
  app.get('/health', (_req, res) => res.json({ status: 'ok', version: '0.1.0' }));
  const metadata = { resource: `${config.PUBLIC_URL}/mcp`, authorization_servers: [config.AUTH_ISSUER], scopes_supported: ['play:connect', 'play:read', 'play:write', 'play:publish'], bearer_methods_supported: ['header'] };
  app.get(['/.well-known/oauth-protected-resource', '/.well-known/oauth-protected-resource/mcp'], (_req, res) => res.json(metadata));

  app.get('/google/callback', async (req, res) => {
    try {
      const state = z.string().min(20).max(200).parse(req.query.state);
      const cookie = req.headers.cookie?.split(';').map(v => v.trim()).find(v => v.startsWith('play_connect='))?.slice(13);
      if (cookie !== state) throw new Error('Connection browser mismatch');
      const connection = store.consumeState(state);
      res.clearCookie('play_connect', { path: '/google/callback' });
      const code = z.string().min(1).max(4096).parse(req.query.code);
      const client = oauth(config);
      const { tokens } = await client.getToken({ code, codeVerifier: connection.verifier });
      if (!tokens.refresh_token || !tokens.scope?.split(' ').includes(scope)) throw new Error('Google did not grant offline Play access');
      store.saveCredentials(connection.tenant, tokens);
      store.audit(connection.tenant, 'connect', '', 'success');
      res.type('text/plain').send('Google Play connected. You can return to your agent.');
    } catch { res.status(400).type('text/plain').send('Connection failed or expired. Start a new connection.'); }
  });

  app.use(async (req, res, next) => {
    try { req.principal = await authenticate(req.headers.authorization); next(); }
    catch {
      res.set('WWW-Authenticate', `Bearer resource_metadata="${config.PUBLIC_URL}/.well-known/oauth-protected-resource/mcp"`);
      res.status(401).json({ error: 'invalid_token' });
    }
  });
  app.post('/connect', async (req, res) => {
    if (!req.principal.scopes.has('play:connect')) return res.status(403).json({ error: 'Missing scope: play:connect' });
    const client = oauth(config);
    const { codeVerifier, codeChallenge } = await client.generateCodeVerifierAsync();
    const state = store.newState(req.principal.tenant, codeVerifier);
    res.cookie('play_connect', state, { httpOnly: true, sameSite: 'lax', secure: config.PUBLIC_URL.startsWith('https:'), maxAge: 600000, path: '/google/callback' });
    const authorizationUrl = client.generateAuthUrl({ scope: [scope], access_type: 'offline', prompt: 'consent select_account', state, code_challenge: codeChallenge, code_challenge_method: 'S256' });
    res.json({ authorizationUrl });
  });
  app.delete('/connection', async (req, res) => {
    if (!req.principal.scopes.has('play:connect')) return res.status(403).json({ error: 'Missing scope: play:connect' });
    const credentials = store.credentials(req.principal.tenant);
    let revoked = false;
    try {
      if (credentials?.refresh_token) { await oauth(config).revokeToken(credentials.refresh_token); revoked = true; }
    } catch { /* Local removal still takes effect if Google is unavailable. */ }
    store.disconnect(req.principal.tenant);
    store.audit(req.principal.tenant, 'disconnect', '', 'success');
    res.json({ disconnected: true, googleRevoked: revoked });
  });
  const invoke = (req, name, args) => execute(name, args, req.principal, factory(config, store, req.principal.tenant), config.ENABLE_PUBLISH === 'true');
  app.post('/api/tools/:name', express.json({ limit: '1mb' }), async (req, res) => {
    try { res.json(await invoke(req, req.params.name, req.body)); }
    catch (e) { res.status(400).json({ error: publicError(e) }); }
  });
  app.post('/api/bundles/:packageName/:editId', express.raw({ type: 'application/octet-stream', limit: '150mb' }), async (req, res) => {
    if (!req.principal.scopes.has('play:write')) return res.status(403).json({ error: 'Missing scope: play:write' });
    try {
      const args = z.object(editArgs).parse(req.params);
      store.requireEdit(req.principal.tenant, args.packageName, args.editId);
      if (!Buffer.isBuffer(req.body) || !req.body.length) throw new Error('Expected AAB binary with application/octet-stream');
      const result = await factory(config, store, req.principal.tenant).upload(args.packageName, args.editId, req.body);
      store.audit(req.principal.tenant, 'upload_bundle', args.packageName, 'success');
      res.json(result);
    } catch (e) {
      store.audit(req.principal.tenant, 'upload_bundle', '', 'failure');
      res.status(400).json({ error: publicError(e) });
    }
  });
  app.post('/mcp', express.json({ limit: '1mb' }), async (req, res) => {
    const server = new McpServer({ name: 'google-play-console', version: '0.1.0' });
    for (const [name, tool] of Object.entries(tools)) {
      if (!req.principal.scopes.has(tool.scope) || (tool.scope === 'play:publish' && config.ENABLE_PUBLISH !== 'true')) continue;
      server.registerTool(name, { description: tool.description, inputSchema: tool.schema.shape, annotations: { readOnlyHint: tool.scope === 'play:read', destructiveHint: tool.scope !== 'play:read', openWorldHint: true } }, async args => {
        try { return { content: [{ type: 'text', text: JSON.stringify(await invoke(req, name, args)) }] }; }
        catch (e) { return { isError: true, content: [{ type: 'text', text: publicError(e) }] }; }
      });
    }
    server.registerTool('bundle_upload_instructions', { description: 'Get the authenticated binary upload endpoint. Use an HTTP-capable client to POST AAB bytes; no download from arbitrary URLs is supported.', inputSchema: editArgs }, async args => {
      if (!req.principal.scopes.has('play:write')) return { isError: true, content: [{ type: 'text', text: 'Missing scope: play:write' }] };
      try {
        store.requireEdit(req.principal.tenant, args.packageName, args.editId);
        return { content: [{ type: 'text', text: JSON.stringify({ method: 'POST', url: `${config.PUBLIC_URL}/api/bundles/${args.packageName}/${args.editId}`, contentType: 'application/octet-stream', authorization: 'Use your connector bearer token; never a Google token.', limitBytes: 150 * 1024 * 1024 }) }] };
      } catch (e) { return { isError: true, content: [{ type: 'text', text: publicError(e) }] }; }
    });
    const transport = new StreamableHTTPServerTransport({ sessionIdGenerator: undefined, enableJsonResponse: true });
    res.on('close', () => { void transport.close(); void server.close(); });
    try { await server.connect(transport); await transport.handleRequest(req, res, req.body); }
    catch { if (!res.headersSent) res.status(500).json({ error: 'MCP request failed' }); }
  });
  app.all('/mcp', (_req, res) => res.status(405).set('Allow', 'POST').end());
  app.use((_req, res) => res.status(404).json({ error: 'Not found' }));
  app.use((error, _req, res, _next) => res.status(error.status === 413 ? 413 : 400).json({ error: 'Invalid request' }));
  return app;
}

function publicError(error) {
  if (error instanceof z.ZodError) return 'Invalid arguments: ' + error.issues.map(i => `${i.path.join('.')}: ${i.message}`).join('; ');
  if (error.response || error.config) return `Google Play request failed (HTTP ${error.response?.status ?? 'unavailable'}). Check app permissions, edit state, and Play Console.`;
  return error.message || 'Request failed';
}

if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const config = { ...process.env };
  for (const key of ['PUBLIC_URL', 'AUTH_ISSUER', 'AUTH_JWKS_URI', 'AUTH_AUDIENCE', 'GOOGLE_CLIENT_ID', 'GOOGLE_CLIENT_SECRET', 'TOKEN_ENCRYPTION_KEY']) if (!config[key]) throw new Error(`Missing ${key}`);
  config.PUBLIC_URL = config.PUBLIC_URL.replace(/\/$/, '');
  for (const key of ['PUBLIC_URL', 'AUTH_ISSUER', 'AUTH_JWKS_URI']) {
    const url = new URL(config[key]);
    if (url.protocol !== 'https:' && !(key === 'PUBLIC_URL' && url.protocol === 'http:' && ['localhost', '127.0.0.1'].includes(url.hostname))) throw new Error(`${key} must use HTTPS`);
  }
  const path = config.DATABASE_PATH || './data/connector.sqlite';
  mkdirSync(dirname(path), { recursive: true });
  const store = new Store(path, config.TOKEN_ENCRYPTION_KEY);
  const app = createApp(config, store);
  app.listen(Number(config.PORT || 3000), '127.0.0.1', () => console.log('Play connector listening behind your HTTPS gateway'));
}
