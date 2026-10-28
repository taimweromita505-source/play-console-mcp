import { createServer } from 'node:http';
import { randomBytes } from 'node:crypto';
import { mkdir, writeFile } from 'node:fs/promises';
import { dirname } from 'node:path';
import { Client } from '@modelcontextprotocol/sdk/client/index.js';
import { auth } from '@modelcontextprotocol/sdk/client/auth.js';
import { StreamableHTTPClientTransport } from '@modelcontextprotocol/sdk/client/streamableHttp.js';

const base = 'https://play-console-mcp.taimweromita505.workers.dev';
const resource = `${base}/mcp`;
const port = 18876;
const redirect = `http://127.0.0.1:${port}/oauth/callback`;
const packageName = process.argv[2];
const reportPath = process.argv[3] ?? 'work/live-readiness-result.json';
if (!/^[A-Za-z][A-Za-z0-9_]*(\.[A-Za-z][A-Za-z0-9_]*)+$/.test(packageName ?? '')) throw new Error('Supply an Android package name');
const state = randomBytes(32).toString('base64url');
let clientInfo, savedTokens, verifier, discovery, authorizationUrl, activeClient;
let running = false;
const report = { packageName, startedAt: new Date().toISOString(), status: 'starting', checks: [], errors: [] };
const record = (name, passed, detail) => report.checks.push({ name, passed, ...(detail === undefined ? {} : { detail }) });
const saveReport = async () => { await mkdir(dirname(reportPath), { recursive: true }); await writeFile(reportPath, JSON.stringify(report, null, 2) + '\n'); };
const provider = {
  redirectUrl: redirect,
  clientMetadata: { client_name: 'Play Console read-only readiness check', redirect_uris: [redirect], grant_types: ['authorization_code', 'refresh_token'], response_types: ['code'], token_endpoint_auth_method: 'none', scope: 'play:read offline_access' },
  state: () => state,
  clientInformation: () => clientInfo,
  saveClientInformation: value => { clientInfo = value; },
  tokens: () => savedTokens,
  saveTokens: value => { savedTokens = value; },
  saveCodeVerifier: value => { verifier = value; },
  codeVerifier: () => verifier,
  saveDiscoveryState: value => { discovery = value; },
  discoveryState: () => discovery,
  redirectToAuthorization: url => { authorizationUrl = url; },
  invalidateCredentials: scope => {
    if (scope === 'all' || scope === 'tokens') savedTokens = undefined;
    if (scope === 'all' || scope === 'client') clientInfo = undefined;
    if (scope === 'all' || scope === 'verifier') verifier = undefined;
    if (scope === 'all' || scope === 'discovery') discovery = undefined;
  }
};

async function revokeTestGrant() {
  if (!savedTokens || !clientInfo) return;
  const response = await fetch(`${base}/oauth/token`, { method: 'POST', body: new URLSearchParams({ token: savedTokens.refresh_token ?? savedTokens.access_token, token_type_hint: savedTokens.refresh_token ? 'refresh_token' : 'access_token', client_id: clientInfo.client_id }), signal: AbortSignal.timeout(20000) });
  record('Test grant revocation', response.ok, `HTTP ${response.status}`);
  await response.body?.cancel();
  if (response.ok) {
    const denied = await fetch(resource, { method: 'POST', headers: { Authorization: `Bearer ${savedTokens.access_token}`, 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }, body: JSON.stringify({ jsonrpc: '2.0', id: 9, method: 'tools/list', params: {} }), signal: AbortSignal.timeout(20000) });
    record('Revoked access token rejected', denied.status === 401, `HTTP ${denied.status}`);
    await denied.body?.cancel();
  }
  savedTokens = undefined;
}

async function runChecks(code) {
  report.status = 'running';
  const transport = new StreamableHTTPClientTransport(new URL(resource), { authProvider: provider });
  try {
    await transport.finishAuth(code);
    record('Real Google-backed OAuth exchange', Boolean(savedTokens?.access_token));
    activeClient = new Client({ name: 'play-console-live-readiness', version: '0.2.0' });
    await activeClient.connect(transport);
    record('Official MCP SDK initialization', true);
    const catalog = await activeClient.listTools();
    const names = catalog.tools.map(tool => tool.name);
    record('Read-only MCP tool discovery', names.includes('list_reviews') && !names.includes('reply_review'), names);
    record('Publishing unavailable', !names.includes('commit_edit'));
    const reviews = await activeClient.callTool({ name: 'list_reviews', arguments: { packageName, maxResults: 1 } });
    let content;
    try { content = JSON.parse(reviews.content?.find(item => item.type === 'text')?.text ?? '{}'); } catch { content = {}; }
    if (reviews.isError) record('Live Habit Coach review read', false, reviews.content?.filter(item => item.type === 'text').map(item => item.text).join(' ').slice(0, 500));
    else record('Live Habit Coach review read', true, { returned: Array.isArray(content.reviews) ? content.reviews.length : 0, nextPageAvailable: Boolean(content.tokenPagination?.nextPageToken) });
    if (!reviews.isError && content.tokenPagination?.nextPageToken) {
      const page = await activeClient.callTool({ name: 'list_reviews', arguments: { packageName, maxResults: 1, token: content.tokenPagination.nextPageToken } });
      record('Live review pagination', !page.isError);
    }
    const headers = { Authorization: `Bearer ${savedTokens.access_token}`, 'Content-Type': 'application/json' };
    // Empty arguments cannot identify a real review or produce a valid reply even if validation is broken.
    const write = await fetch(`${resource}/api/tools/reply_review`, { method: 'POST', headers, body: '{}', signal: AbortSignal.timeout(20000) });
    const writeResult = await write.json();
    record('Read-only REST token denies write scope', /Missing scope: play:write/.test(writeResult.error ?? ''), `HTTP ${write.status}`);
    const missing = await activeClient.callTool({ name: 'list_reviews', arguments: { packageName: 'com.example.playconsolereadinessmissing', maxResults: 1 } });
    record('Unknown or inaccessible app rejected', Boolean(missing.isError));
    const before = savedTokens.access_token;
    const refresh = await auth(provider, { serverUrl: resource, scope: 'play:read offline_access' });
    record('Agent refresh token exchange', refresh === 'AUTHORIZED' && Boolean(savedTokens?.access_token) && savedTokens.access_token !== before);
    await activeClient.close(); activeClient = undefined;
    const refreshedClient = new Client({ name: 'play-console-live-readiness-refreshed', version: '0.2.0' });
    activeClient = refreshedClient;
    await refreshedClient.connect(new StreamableHTTPClientTransport(new URL(resource), { authProvider: provider }));
    await refreshedClient.listTools();
    record('Refreshed agent token works', true);
  } catch (error) {
    report.errors.push(error instanceof Error ? error.message.slice(0, 500) : 'Readiness check failed');
  } finally {
    try { await activeClient?.close(); } catch {}
    try { await revokeTestGrant(); } catch { report.errors.push('Could not confirm test grant revocation'); }
    report.status = report.errors.length || report.checks.some(check => !check.passed) ? 'needs_attention' : 'passed';
    report.finishedAt = new Date().toISOString();
    await saveReport();
    console.log(JSON.stringify(report));
  }
}

const server = createServer(async (request, response) => {
  const url = new URL(request.url, `http://127.0.0.1:${port}`);
  response.setHeader('Cache-Control', 'no-store');
  response.setHeader('Referrer-Policy', 'no-referrer');
  response.setHeader('Content-Type', 'text/plain; charset=utf-8');
  if (url.pathname === '/start') {
    if (!authorizationUrl) { response.writeHead(503); response.end('Preparing authorization.'); return; }
    response.writeHead(302, { Location: authorizationUrl.href }); response.end(); return;
  }
  if (url.pathname === '/status') { response.setHeader('Content-Type', 'application/json'); response.end(JSON.stringify(report)); return; }
  if (url.pathname !== '/oauth/callback') { response.writeHead(404); response.end('Not found'); return; }
  if (running || url.searchParams.get('state') !== state || url.searchParams.get('iss') !== base) { response.writeHead(400); response.end('Invalid or already-used callback.'); return; }
  if (url.searchParams.has('error') || !url.searchParams.get('code')) {
    report.status = 'authorization_failed';
    report.errors.push(url.searchParams.get('error') ?? 'Missing authorization code');
    await saveReport(); response.writeHead(400); response.end('Authorization failed. Return to the chat for details.'); return;
  }
  running = true;
  response.end('Sign-in completed. The read-only checks are running. Return to the chat for results.');
  await runChecks(url.searchParams.get('code'));
  server.close();
});
await new Promise(resolve => server.listen(port, '127.0.0.1', resolve));
try {
  const result = await auth(provider, { serverUrl: resource, scope: 'play:read offline_access' });
  report.status = result === 'REDIRECT' ? 'waiting_for_user_authorization' : 'authorized';
  record('Live OAuth discovery and client registration', Boolean(clientInfo?.client_id));
  await saveReport();
  console.log(JSON.stringify({ status: report.status, startUrl: `http://127.0.0.1:${port}/start`, packageName }));
} catch (error) {
  report.status = 'setup_failed'; report.errors.push(error instanceof Error ? error.message.slice(0, 500) : 'Setup failed');
  await saveReport(); console.log(JSON.stringify(report)); server.close();
}
const timer = setTimeout(async () => { await activeClient?.close(); await revokeTestGrant(); server.close(); }, 30 * 60 * 1000);
timer.unref();
