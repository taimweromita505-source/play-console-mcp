export interface GoogleTokens {
  access_token: string;
  refresh_token?: string;
  expires_at: number;
  scope?: string;
}

const encode = (bytes: Uint8Array) => btoa(String.fromCharCode(...bytes));
const decode = (value: string) => Uint8Array.from(atob(value), c => c.charCodeAt(0));

export class D1Store {
  constructor(private db: D1Database, private key: string) {}

  private encryptionKey() {
    const bytes = decode(this.key);
    if (bytes.length !== 32) throw new Error('Invalid encryption key configuration');
    return crypto.subtle.importKey('raw', bytes, 'AES-GCM', false, ['encrypt', 'decrypt']);
  }

  async seal(tenant: string, value: GoogleTokens) {
    const iv = crypto.getRandomValues(new Uint8Array(12));
    const ciphertext = await crypto.subtle.encrypt({ name: 'AES-GCM', iv, additionalData: new TextEncoder().encode(tenant) }, await this.encryptionKey(), new TextEncoder().encode(JSON.stringify(value)));
    return JSON.stringify({ iv: encode(iv), data: encode(new Uint8Array(ciphertext)) });
  }

  async credentials(tenant: string) {
    const row = await this.db.prepare('SELECT secret,revision FROM credentials WHERE tenant=?').bind(tenant).first<{ secret: string; revision: string }>();
    if (!row) return null;
    const sealed: { iv: string; data: string } = JSON.parse(row.secret);
    const plaintext = await crypto.subtle.decrypt({ name: 'AES-GCM', iv: decode(sealed.iv), additionalData: new TextEncoder().encode(tenant) }, await this.encryptionKey(), decode(sealed.data));
    return { tokens: JSON.parse(new TextDecoder().decode(plaintext)) as GoogleTokens, revision: row.revision };
  }

  async saveCredentials(tenant: string, tokens: GoogleTokens, revision: string) {
    await this.db.prepare('INSERT INTO credentials(tenant,secret,revision) VALUES(?,?,?) ON CONFLICT(tenant) DO UPDATE SET secret=excluded.secret,revision=excluded.revision').bind(tenant, await this.seal(tenant, tokens), revision).run();
  }

  async updateCredentials(tenant: string, tokens: GoogleTokens, revision: string) {
    const result = await this.db.prepare('UPDATE credentials SET secret=? WHERE tenant=? AND revision=?').bind(await this.seal(tenant, tokens), tenant, revision).run();
    if (result.meta.changes !== 1) throw new Error('Connection changed; authorize again');
  }

  async requireConnection(tenant: string, revision: string) {
    const credentials = await this.credentials(tenant);
    if (!credentials || credentials.revision !== revision) throw new Error('Google Play connection removed; authorize again');
    return credentials;
  }

  async rememberEdit(tenant: string, pkg: string, edit: string) {
    await this.db.prepare('INSERT OR IGNORE INTO edits(tenant,package,edit) VALUES(?,?,?)').bind(tenant, pkg, edit).run();
  }

  async requireEdit(tenant: string, pkg: string, edit: string) {
    if (!await this.db.prepare('SELECT 1 FROM edits WHERE tenant=? AND package=? AND edit=?').bind(tenant, pkg, edit).first()) throw new Error('Edit does not belong to this connection');
  }

  async forgetEdit(tenant: string, pkg: string, edit: string) {
    await this.db.prepare('DELETE FROM edits WHERE tenant=? AND package=? AND edit=?').bind(tenant, pkg, edit).run();
  }

  async disconnect(tenant: string) {
    await this.db.batch([
      this.db.prepare('DELETE FROM credentials WHERE tenant=?').bind(tenant),
      this.db.prepare('DELETE FROM edits WHERE tenant=?').bind(tenant)
    ]);
  }

  async audit(tenant: string, action: string, pkg: string, outcome: string) {
    await this.db.prepare('INSERT INTO audit(time,tenant,action,package,outcome) VALUES(?,?,?,?,?)').bind(Date.now(), tenant, action, pkg, outcome).run();
  }
}
