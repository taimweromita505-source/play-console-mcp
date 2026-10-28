import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomBytes, createHash } from 'node:crypto';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';

const base = 'https://connector.test';
const playScope = 'https://www.googleapis.com/auth/androidpublisher';
const config = {
  modules: true, scriptPath: 'dist/worker.js', compatibilityDate: '2026-10-28',
  compatibilityFlags: ['nodejs_compat', 'global_fetch_strictly_public'],
  kvNamespaces: ['OAUTH_KV'], d1Databases: ['DB'],
  ratelimits: { REQUEST_LIMITER: { namespace_id: '21801', simple: { limit: 60, period: 60 } } }
};

test('Workers runtime serves setup status and protects the MCP endpoint', async () => {
  const mf = new Miniflare(convertV4MiniflareOptions({ ...config, bindings: { PUBLIC_URL: base, ENABLE_PUBLISH: 'false' } }));
  try {
    const health = await mf.dispatchFetch(`${base}/health`);
    assert.equal(health.status, 200, await health.clone().text());
    assert.equal((await health.json()).googleConfigured, false);
    const mcp = await mf.dispatchFetch(`${base}/mcp`, { method: 'POST' });
    assert.equal(mcp.status, 401);
    assert.match(mcp.headers.get('www-authenticate'), /resource_metadata/);
    const metadata = await mf.dispatchFetch(`${base}/.well-known/oauth-protected-resource/mcp`);
    assert.equal(metadata.status, 200);
    assert.equal((await metadata.json()).resource, `${base}/mcp`);
    assert.equal((await mf.dispatchFetch(`${base}/authorize`)).status, 503);
  } finally { await mf.dispose(); }
});

test('Workers runtime completes Google-backed agent OAuth and enforces tenant disconnect', async () => {
  const { publicKey, privateKey } = await generateKeyPair('RS256');
  const jwk = { ...await exportJWK(publicKey), kid: 'test-key', use: 'sig', alg: 'RS256' };
  let nonce = '';
  const mf = new Miniflare(convertV4MiniflareOptions({ ...config,
    bindings: { PUBLIC_URL: base, ENABLE_PUBLISH: 'false', GOOGLE_CLIENT_ID: 'test-client', GOOGLE_CLIENT_SECRET: 'test-secret', TOKEN_ENCRYPTION_KEY: randomBytes(32).toString('base64') },
    outboundService: async request => {
      const url = new URL(request.url);
      if (url.href === 'https://oauth2.googleapis.com/token') {
        const idToken = await new SignJWT({ nonce, email: 'test@example.test' }).setProtectedHeader({ alg: 'RS256', kid: 'test-key' }).setIssuer('https://accounts.google.com').setAudience('test-client').setSubject('google-user-one').setIssuedAt().setExpirationTime('5m').sign(privateKey);
        return Response.json({ access_token: 'mock-google-access', refresh_token: 'mock-google-refresh', expires_in: 3600, scope: `openid email ${playScope}`, id_token: idToken });
      }
      if (url.href === 'https://www.googleapis.com/oauth2/v3/certs') return Response.json({ keys: [jwk] });
      if (url.pathname.endsWith('/reviews')) return Response.json({ reviews: [{ reviewId: 'mock-review', authorName: 'Example' }] });
      if (url.href === 'https://oauth2.googleapis.com/revoke') return new Response('', { status: 200 });
      return new Response('Unexpected mock request', { status: 502 });
    }
  }));
  try {
    const db = await mf.getD1Database('DB');
    await db.exec(readFileSync('migrations/0001_connector.sql', 'utf8').replace(/\n/g, ' '));
    const registered = await mf.dispatchFetch(`${base}/oauth/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ client_name: 'Integration test agent', redirect_uris: ['http://127.0.0.1:3210/callback'], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none' }) });
    assert.equal(registered.status, 201, await registered.clone().text());
    const client = await registered.json();
    const verifier = randomBytes(32).toString('base64url');
    const authorize = new URL(`${base}/authorize`);
    for (const [key, value] of Object.entries({ client_id: client.client_id, redirect_uri: 'http://127.0.0.1:3210/callback', response_type: 'code', scope: 'play:read play:write play:manage offline_access', state: 'agent-state', code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', resource: `${base}/mcp` })) authorize.searchParams.set(key, value);
    const consent = await mf.dispatchFetch(authorize.href);
    assert.equal(consent.status, 200);
    const page = await consent.text();
    assert.match(page, /Integration test agent/);
    const handle = /name="handle" value="([^"]+)"/.exec(page)[1];
    const cookie = response => response.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');
    const form = new URLSearchParams({ handle, decision: 'approve' });
    for (const scope of ['play:read', 'play:write', 'play:manage', 'offline_access']) form.append('scope', scope);
    const approved = await mf.dispatchFetch(`${base}/authorize`, { method: 'POST', redirect: 'manual', headers: { Cookie: cookie(consent), Origin: base, 'Content-Type': 'application/x-www-form-urlencoded' }, body: form.toString() });
    assert.equal(approved.status, 302);
    const google = new URL(approved.headers.get('location'));
    assert.equal(google.origin, 'https://accounts.google.com');
    nonce = google.searchParams.get('nonce');
    const callback = new URL(`${base}/google/callback`);
    callback.searchParams.set('state', google.searchParams.get('state'));
    callback.searchParams.set('code', 'mock-google-code');
    const callbackResult = await mf.dispatchFetch(callback.href, { redirect: 'manual', headers: { Cookie: cookie(approved) } });
    assert.equal(callbackResult.status, 302, await callbackResult.clone().text());
    const redirect = new URL(callbackResult.headers.get('location'));
    assert.equal(redirect.searchParams.get('state'), 'agent-state');
    const token = await mf.dispatchFetch(`${base}/oauth/token`, { method: 'POST', headers: { 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ grant_type: 'authorization_code', client_id: client.client_id, redirect_uri: 'http://127.0.0.1:3210/callback', code: redirect.searchParams.get('code'), code_verifier: verifier, resource: `${base}/mcp` }).toString() });
    assert.equal(token.status, 200, await token.clone().text());
    const credentials = await token.json();
    const headers = { Authorization: `Bearer ${credentials.access_token}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' };
    const listed = await mf.dispatchFetch(`${base}/mcp`, { method: 'POST', headers, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) });
    assert.equal(listed.status, 200);
    const catalog = await listed.json();
    assert.ok(catalog.result.tools.some(tool => tool.name === 'reply_review'));
    assert.ok(!catalog.result.tools.some(tool => tool.name === 'commit_edit'));
    const reviews = await mf.dispatchFetch(`${base}/mcp/api/tools/list_reviews`, { method: 'POST', headers, body: JSON.stringify({ packageName: 'com.example.app' }) });
    assert.equal(reviews.status, 200, await reviews.clone().text());
    assert.equal((await reviews.json()).reviews[0].reviewId, 'mock-review');
    const stored = await db.prepare('SELECT secret FROM credentials').first();
    assert.ok(!stored.secret.includes('mock-google-refresh'));
    const disconnected = await mf.dispatchFetch(`${base}/mcp/api/connection`, { method: 'DELETE', headers });
    assert.equal(disconnected.status, 200);
    assert.equal((await disconnected.json()).disconnected, true);
    assert.equal(await db.prepare('SELECT 1 FROM credentials').first(), null);
    const blocked = await mf.dispatchFetch(`${base}/mcp/api/tools/list_reviews`, { method: 'POST', headers, body: JSON.stringify({ packageName: 'com.example.app' }) });
    assert.equal(blocked.status, 400);
  } finally { await mf.dispose(); }
});
