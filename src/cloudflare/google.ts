import { createRemoteJWKSet, jwtVerify } from 'jose';
import { z } from 'zod';
import { D1Store, type GoogleTokens } from './store';

export const PLAY_SCOPE = 'https://www.googleapis.com/auth/androidpublisher';
const tokensSchema = z.object({ access_token: z.string(), refresh_token: z.string().optional(), expires_in: z.number(), scope: z.string().optional(), id_token: z.string().optional() });

export async function limitedJson(response: Response, limit = 2 * 1024 * 1024): Promise<unknown> {
  if (!response.body) throw new Error('Empty upstream response');
  const reader = response.body.getReader();
  const chunks: Uint8Array[] = [];
  let length = 0;
  while (true) {
    const { done, value } = await reader.read();
    if (done) break;
    length += value.byteLength;
    if (length > limit) { await reader.cancel(); throw new Error('Response too large'); }
    chunks.push(value);
  }
  const body = new Uint8Array(length);
  let offset = 0;
  for (const chunk of chunks) { body.set(chunk, offset); offset += chunk.length; }
  return JSON.parse(new TextDecoder().decode(body));
}

async function exchange(env: Env, parameters: Record<string, string>) {
  const response = await fetch('https://oauth2.googleapis.com/token', {
    method: 'POST', body: new URLSearchParams({ client_id: env.GOOGLE_CLIENT_ID, client_secret: env.GOOGLE_CLIENT_SECRET, ...parameters }),
    signal: AbortSignal.timeout(20000)
  });
  if (!response.ok) {
    await response.body?.cancel();
    throw new Error(`Google authorization failed (${response.status}); reconnect your account`);
  }
  return tokensSchema.parse(await limitedJson(response, 65536));
}

export async function exchangeCode(env: Env, code: string, verifier: string, nonce: string) {
  const result = await exchange(env, { grant_type: 'authorization_code', code, code_verifier: verifier, redirect_uri: `${env.PUBLIC_URL}/google/callback` });
  if (!result.id_token) throw new Error('Google did not return an identity token');
  const { payload } = await jwtVerify(result.id_token, createRemoteJWKSet(new URL('https://www.googleapis.com/oauth2/v3/certs')), {
    issuer: ['https://accounts.google.com', 'accounts.google.com'], audience: env.GOOGLE_CLIENT_ID, algorithms: ['RS256'], requiredClaims: ['sub', 'exp', 'iat', 'nonce']
  });
  if (payload.nonce !== nonce || !payload.sub) throw new Error('Google identity verification failed');
  if (!result.scope?.split(' ').includes(PLAY_SCOPE)) throw new Error('Google Play access was not granted');
  return { tenant: payload.sub, tokens: { access_token: result.access_token, refresh_token: result.refresh_token, scope: result.scope, expires_at: Date.now() + result.expires_in * 1000 } };
}

export function cloudPlay(env: Env, store: D1Store, tenant: string, revision: string) {
  const accessToken = async () => {
    const current = await store.requireConnection(tenant, revision);
    if (current.tokens.expires_at > Date.now() + 60000) return current.tokens.access_token;
    if (!current.tokens.refresh_token) throw new Error('Offline access unavailable; reconnect Google Play');
    const result = await exchange(env, { grant_type: 'refresh_token', refresh_token: current.tokens.refresh_token });
    const tokens: GoogleTokens = { ...current.tokens, access_token: result.access_token, refresh_token: result.refresh_token ?? current.tokens.refresh_token, expires_at: Date.now() + result.expires_in * 1000 };
    await store.updateCredentials(tenant, tokens, revision);
    return tokens.access_token;
  };
  const request = async (url: string, method: string, body?: BodyInit | null, contentType?: string) => {
    const headers = new Headers({ Authorization: `Bearer ${await accessToken()}` });
    if (contentType) headers.set('Content-Type', contentType);
    const response = await fetch(url, { method, headers, body, signal: AbortSignal.timeout(240000) });
    if (!response.ok) { await response.body?.cancel(); throw new Error(`Google Play request failed (${response.status}); check app permissions and edit state`); }
    if (response.status === 204 || method === 'DELETE') { await response.body?.cancel(); return {}; }
    return limitedJson(response);
  };
  return {
    tenant, store,
    async call(packageName: string, path: string, method = 'GET', data?: unknown, query: Record<string, string | number | undefined> = {}) {
      const url = new URL(`https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${encodeURIComponent(packageName)}${path}`);
      for (const [key, value] of Object.entries(query)) if (value !== undefined) url.searchParams.set(key, String(value));
      return request(url.href, method, data === undefined ? undefined : JSON.stringify(data), data === undefined ? undefined : 'application/json');
    },
    async upload(packageName: string, editId: string, body: ReadableStream, length: number) {
      await store.requireEdit(tenant, packageName, editId);
      const fixed = new FixedLengthStream(length);
      const [result] = await Promise.all([
        request(`https://androidpublisher.googleapis.com/upload/androidpublisher/v3/applications/${encodeURIComponent(packageName)}/edits/${encodeURIComponent(editId)}/bundles?uploadType=media`, 'POST', fixed.readable, 'application/octet-stream'),
        body.pipeTo(fixed.writable)
      ]);
      return result;
    }
  };
}
