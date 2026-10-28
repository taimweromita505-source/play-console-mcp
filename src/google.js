import { OAuth2Client } from 'google-auth-library';

export const scope = 'https://www.googleapis.com/auth/androidpublisher';
export function oauth(config) {
  return new OAuth2Client(config.GOOGLE_CLIENT_ID, config.GOOGLE_CLIENT_SECRET, `${config.PUBLIC_URL}/google/callback`);
}

export function playClient(config, store, tenant) {
  const credentials = store.credentials(tenant);
  if (!credentials) throw new Error('Connect a Google Play account first');
  const auth = oauth(config);
  auth.setCredentials(credentials);
  auth.on('tokens', tokens => {
    // Merge only into the same connection; a disconnect must not resurrect tokens.
    const current = store.credentials(tenant);
    if (current) store.saveCredentials(tenant, { ...current, ...tokens });
  });
  const request = async (url, method, data, headers) => {
    const response = await auth.request({ url, method, data, headers, timeout: 300000, retry: false });
    return response.data ?? {};
  };
  return {
    tenant, store,
    call(packageName, path, method = 'GET', data, query = {}) {
      const url = new URL(`https://androidpublisher.googleapis.com/androidpublisher/v3/applications/${encodeURIComponent(packageName)}${path}`);
      for (const [key, value] of Object.entries(query)) if (value !== undefined) url.searchParams.set(key, String(value));
      return request(url.href, method, data);
    },
    upload(packageName, editId, bytes) {
      return request(`https://androidpublisher.googleapis.com/upload/androidpublisher/v3/applications/${encodeURIComponent(packageName)}/edits/${encodeURIComponent(editId)}/bundles?uploadType=media`, 'POST', bytes, { 'Content-Type': 'application/octet-stream' });
    }
  };
}
