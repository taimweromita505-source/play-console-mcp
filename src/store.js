import { DatabaseSync } from 'node:sqlite';
import { createCipheriv, createDecipheriv, randomBytes, createHash } from 'node:crypto';

export function tenantId(issuer, subject) {
  if (!issuer || !subject) throw new Error('Missing authenticated identity');
  return createHash('sha256').update(JSON.stringify([issuer, subject])).digest('hex');
}

export class Store {
  constructor(path, key) {
    this.key = Buffer.from(key, 'base64');
    if (this.key.length !== 32) throw new Error('TOKEN_ENCRYPTION_KEY must contain 32 random bytes');
    this.db = new DatabaseSync(path);
    this.db.exec(`PRAGMA journal_mode=WAL;
      CREATE TABLE IF NOT EXISTS credentials(tenant TEXT PRIMARY KEY, secret TEXT NOT NULL);
      CREATE TABLE IF NOT EXISTS states(state TEXT PRIMARY KEY, tenant TEXT NOT NULL, verifier TEXT NOT NULL, expires INTEGER NOT NULL);
      CREATE TABLE IF NOT EXISTS edits(tenant TEXT NOT NULL, package TEXT NOT NULL, edit TEXT NOT NULL, PRIMARY KEY(tenant,package,edit));
      CREATE TABLE IF NOT EXISTS audit(id INTEGER PRIMARY KEY, time INTEGER, tenant TEXT, action TEXT, package TEXT, outcome TEXT);`);
  }
  seal(tenant, value) {
    const iv = randomBytes(12);
    const cipher = createCipheriv('aes-256-gcm', this.key, iv);
    cipher.setAAD(Buffer.from(tenant));
    const data = Buffer.concat([cipher.update(JSON.stringify(value)), cipher.final()]);
    return Buffer.concat([iv, cipher.getAuthTag(), data]).toString('base64');
  }
  open(tenant, value) {
    const data = Buffer.from(value, 'base64');
    const cipher = createDecipheriv('aes-256-gcm', this.key, data.subarray(0, 12));
    cipher.setAAD(Buffer.from(tenant));
    cipher.setAuthTag(data.subarray(12, 28));
    return JSON.parse(Buffer.concat([cipher.update(data.subarray(28)), cipher.final()]).toString());
  }
  credentials(tenant) {
    const row = this.db.prepare('SELECT secret FROM credentials WHERE tenant=?').get(tenant);
    return row ? this.open(tenant, row.secret) : null;
  }
  saveCredentials(tenant, credentials) {
    this.db.prepare('INSERT OR REPLACE INTO credentials VALUES(?,?)').run(tenant, this.seal(tenant, credentials));
  }
  disconnect(tenant) {
    this.db.prepare('DELETE FROM credentials WHERE tenant=?').run(tenant);
    this.db.prepare('DELETE FROM edits WHERE tenant=?').run(tenant);
    this.db.prepare('DELETE FROM states WHERE tenant=?').run(tenant);
  }
  newState(tenant, verifier) {
    const state = randomBytes(32).toString('base64url');
    this.db.prepare('DELETE FROM states WHERE expires<?').run(Date.now());
    this.db.prepare('INSERT INTO states VALUES(?,?,?,?)').run(state, tenant, this.seal(tenant, verifier), Date.now() + 600000);
    return state;
  }
  consumeState(state) {
    const row = this.db.prepare('DELETE FROM states WHERE state=? RETURNING *').get(state);
    if (!row || row.expires < Date.now()) throw new Error('Invalid or expired connection state');
    return { tenant: row.tenant, verifier: this.open(row.tenant, row.verifier) };
  }
  rememberEdit(tenant, pkg, edit) {
    this.db.prepare('INSERT OR IGNORE INTO edits VALUES(?,?,?)').run(tenant, pkg, edit);
  }
  requireEdit(tenant, pkg, edit) {
    if (!this.db.prepare('SELECT 1 FROM edits WHERE tenant=? AND package=? AND edit=?').get(tenant, pkg, edit)) {
      throw new Error('Edit does not belong to this connection');
    }
  }
  forgetEdit(tenant, pkg, edit) {
    this.db.prepare('DELETE FROM edits WHERE tenant=? AND package=? AND edit=?').run(tenant, pkg, edit);
  }
  audit(tenant, action, pkg, outcome) {
    this.db.prepare('INSERT INTO audit(time,tenant,action,package,outcome) VALUES(?,?,?,?,?)').run(Date.now(), tenant, action, pkg, outcome);
  }
}
