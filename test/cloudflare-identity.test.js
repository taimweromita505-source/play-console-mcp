import test from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { randomBytes, createHash } from 'node:crypto';
import { Miniflare, convertV4MiniflareOptions } from 'miniflare';
import { generateKeyPair, exportJWK, SignJWT } from 'jose';

const base = 'https://connector.test';
const playScope = 'https://www.googleapis.com/auth/androidpublisher';
const cookies = response => response.headers.getSetCookie().map(value => value.split(';')[0]).join('; ');

for (const failure of ['wrong nonce', 'wrong audience', 'wrong issuer', 'expired identity', 'missing Play scope']) {
  test(`Google sign-in rejects ${failure} before saving credentials`, async () => {
    const { publicKey, privateKey } = await generateKeyPair('RS256');
    const jwk = { ...await exportJWK(publicKey), kid: 'identity-test', alg: 'RS256', use: 'sig' };
    let nonce = '';
    const mf = new Miniflare(convertV4MiniflareOptions({
      modules: true, scriptPath: 'dist/worker.js', compatibilityDate: '2026-10-28', compatibilityFlags: ['nodejs_compat', 'global_fetch_strictly_public'],
      kvNamespaces: ['OAUTH_KV'], d1Databases: ['DB'],
      ratelimits: { REQUEST_LIMITER: { namespace_id: '21801', simple: { limit: 60, period: 60 } } },
      bindings: { PUBLIC_URL: base, ENABLE_PUBLISH: 'false', GOOGLE_CLIENT_ID: 'identity-client', GOOGLE_CLIENT_SECRET: 'identity-secret', TOKEN_ENCRYPTION_KEY: randomBytes(32).toString('base64') },
      outboundService: async request => {
        if (request.url === 'https://www.googleapis.com/oauth2/v3/certs') return Response.json({ keys: [jwk] });
        if (request.url === 'https://oauth2.googleapis.com/token') {
          const token = await new SignJWT({ nonce: failure === 'wrong nonce' ? 'not-the-request-nonce' : nonce })
            .setProtectedHeader({ alg: 'RS256', kid: 'identity-test' })
            .setIssuer(failure === 'wrong issuer' ? 'https://untrusted.example' : 'https://accounts.google.com')
            .setAudience(failure === 'wrong audience' ? 'different-client' : 'identity-client')
            .setSubject('identity-test-user').setIssuedAt()
            .setExpirationTime(failure === 'expired identity' ? Math.floor(Date.now() / 1000) - 60 : Math.floor(Date.now() / 1000) + 300).sign(privateKey);
          return Response.json({ access_token: 'identity-test-access', refresh_token: 'identity-test-refresh', expires_in: 3600, scope: failure === 'missing Play scope' ? 'openid email' : `openid email ${playScope}`, id_token: token });
        }
        throw new Error('Unexpected outbound request in rejected-identity test');
      }
    }));
    try {
      const db = await mf.getD1Database('DB');
      await db.exec(readFileSync('migrations/0001_connector.sql', 'utf8').replace(/\n/g, ' '));
      const registration = await mf.dispatchFetch(`${base}/oauth/register`, { method: 'POST', headers: { 'Content-Type': 'application/json' }, body: JSON.stringify({ client_name: 'Identity rejection test', redirect_uris: ['http://127.0.0.1:3210/callback'], grant_types: ['authorization_code'], response_types: ['code'], token_endpoint_auth_method: 'none' }) });
      assert.equal(registration.status, 201);
      const client = await registration.json();
      const verifier = randomBytes(32).toString('base64url');
      const url = new URL(`${base}/authorize`);
      for (const [key, value] of Object.entries({ client_id: client.client_id, redirect_uri: 'http://127.0.0.1:3210/callback', response_type: 'code', scope: 'play:read', state: 'identity-test-state', code_challenge: createHash('sha256').update(verifier).digest('base64url'), code_challenge_method: 'S256', resource: `${base}/mcp` })) url.searchParams.set(key, value);
      const consent = await mf.dispatchFetch(url.href);
      assert.equal(consent.status, 200);
      const handle = /name="handle" value="([^"]+)"/.exec(await consent.text())[1];
      const approved = await mf.dispatchFetch(`${base}/authorize`, { method: 'POST', redirect: 'manual', headers: { Cookie: cookies(consent), Origin: base, 'Content-Type': 'application/x-www-form-urlencoded' }, body: new URLSearchParams({ handle, decision: 'approve', scope: 'play:read' }).toString() });
      assert.equal(approved.status, 302);
      const google = new URL(approved.headers.get('location'));
      nonce = google.searchParams.get('nonce');
      const callback = new URL(`${base}/google/callback`);
      callback.searchParams.set('state', google.searchParams.get('state'));
      callback.searchParams.set('code', 'identity-test-code');
      const rejected = await mf.dispatchFetch(callback.href, { redirect: 'manual', headers: { Cookie: cookies(approved) } });
      assert.equal(rejected.status, 400);
      assert.equal(rejected.headers.get('location'), null);
      assert.equal((await db.prepare('SELECT COUNT(*) AS total FROM credentials').first()).total, 0);
    } finally { await mf.dispose(); }
  });
}
