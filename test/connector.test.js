import test from 'node:test';
import assert from 'node:assert/strict';
import { randomBytes } from 'node:crypto';
import { Store, tenantId } from '../src/store.js';
import { tools, execute } from '../src/tools.js';
import { createApp } from '../src/server.js';

const fresh = () => new Store(':memory:', randomBytes(32).toString('base64'));

test('credential encryption binds ciphertext to the authenticated tenant', () => {
  const store = fresh();
  store.saveCredentials('alice', { refresh_token: 'secret' });
  assert.equal(store.credentials('alice').refresh_token, 'secret');
  assert.equal(store.credentials('bob'), null);
  const row = store.db.prepare('SELECT secret FROM credentials').get();
  assert.ok(!row.secret.includes('secret'));
  assert.throws(() => store.open('bob', row.secret));
  store.db.close();
});

test('OAuth state is single-use and expired state fails', () => {
  const store = fresh();
  const state = store.newState('alice', 'verifier');
  assert.deepEqual(store.consumeState(state), { tenant: 'alice', verifier: 'verifier' });
  assert.throws(() => store.consumeState(state));
  const expired = store.newState('alice', 'verifier');
  store.db.prepare('UPDATE states SET expires=0 WHERE state=?').run(expired);
  assert.throws(() => store.consumeState(expired));
  store.db.close();
});

test('tenant identity includes the issuer and has no delimiter collision', () => {
  assert.notEqual(tenantId('one', 'alice'), tenantId('two', 'alice'));
  assert.notEqual(tenantId('a:b', 'c'), tenantId('a', 'b:c'));
});

test('an edit cannot be accessed through another tenant or package', () => {
  const store = fresh();
  store.rememberEdit('alice', 'com.example.app', '123');
  store.requireEdit('alice', 'com.example.app', '123');
  assert.throws(() => store.requireEdit('bob', 'com.example.app', '123'));
  assert.throws(() => store.requireEdit('alice', 'com.example.other', '123'));
  store.disconnect('alice');
  assert.throws(() => store.requireEdit('alice', 'com.example.app', '123'));
  store.db.close();
});

test('publishing requires both a dedicated scope and operator enablement', async () => {
  const play = { tenant: 'alice', store: fresh(), call: () => { throw new Error('Must not call Google'); } };
  const args = { packageName: 'com.example.app', editId: '123' };
  await assert.rejects(execute('commit_edit', args, { scopes: new Set(['play:write']) }, play, true), /Missing scope/);
  await assert.rejects(execute('commit_edit', args, { scopes: new Set(['play:publish']) }, play), /disabled/);
  play.store.db.close();
});

test('commit validates first and never silently cancels an existing review', async () => {
  const store = fresh();
  store.rememberEdit('alice', 'com.example.app', '123');
  const calls = [];
  const play = { tenant: 'alice', store, call: async (...args) => { calls.push(args); return { id: '123' }; } };
  await execute('commit_edit', { packageName: 'com.example.app', editId: '123' }, { scopes: new Set(['play:publish']) }, play, true);
  assert.ok(calls[0][1].endsWith(':validate'));
  assert.ok(calls[1][1].endsWith(':commit'));
  assert.equal(calls[1][4].changesInReviewBehavior, 'ERROR_IF_IN_REVIEW');
  assert.throws(() => store.requireEdit('alice', 'com.example.app', '123'));
  store.db.close();
});

test('track validation enforces staged rollout fractions and rejects path injection', () => {
  assert.equal(tools.update_track.schema.safeParse({ packageName: 'com.example.app', editId: '1', track: 'production', releases: [{ versionCodes: ['42'], status: 'inProgress' }] }).success, false);
  assert.equal(tools.get_tracks.schema.safeParse({ packageName: 'com.example.app', editId: '../other' }).success, false);
});

test('HTTP rejects unauthenticated and cross-origin clients; MCP advertises permitted tools', async () => {
  const store = fresh();
  const config = { PUBLIC_URL: 'http://localhost:3000', AUTH_ISSUER: 'https://issuer.example', ENABLE_PUBLISH: 'false' };
  const authenticate = async header => {
    if (header !== 'Bearer test') throw new Error('bad token');
    return { tenant: 'alice', scopes: new Set(['play:read']) };
  };
  const app = createApp(config, store, authenticate);
  const server = app.listen(0, '127.0.0.1');
  await new Promise(resolve => server.once('listening', resolve));
  const base = `http://127.0.0.1:${server.address().port}`;
  try {
    const unauth = await fetch(`${base}/mcp`, { method: 'POST' });
    assert.equal(unauth.status, 401);
    assert.ok(unauth.headers.get('www-authenticate').includes('resource_metadata'));
    assert.equal((await fetch(`${base}/health`, { headers: { Origin: 'https://evil.example' } })).status, 403);
    const response = await fetch(`${base}/mcp`, { method: 'POST', headers: { Authorization: 'Bearer test', 'Content-Type': 'application/json', Accept: 'application/json, text/event-stream' }, body: JSON.stringify({ jsonrpc: '2.0', id: 1, method: 'tools/list', params: {} }) });
    assert.equal(response.status, 200);
    const body = await response.json();
    assert.ok(body.result.tools.some(t => t.name === 'list_reviews'));
    assert.ok(!body.result.tools.some(t => t.name === 'commit_edit'));
    assert.ok(!body.result.tools.some(t => t.name === 'reply_review'));
  } finally { await new Promise(resolve => server.close(resolve)); store.db.close(); }
});
