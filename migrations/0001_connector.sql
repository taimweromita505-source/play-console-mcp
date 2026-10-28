CREATE TABLE IF NOT EXISTS credentials (
  tenant TEXT PRIMARY KEY,
  secret TEXT NOT NULL,
  revision TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS edits (
  tenant TEXT NOT NULL,
  package TEXT NOT NULL,
  edit TEXT NOT NULL,
  PRIMARY KEY(tenant, package, edit)
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY,
  time INTEGER NOT NULL,
  tenant TEXT NOT NULL,
  action TEXT NOT NULL,
  package TEXT NOT NULL,
  outcome TEXT NOT NULL
);
CREATE INDEX IF NOT EXISTS audit_tenant_time ON audit(tenant, time);
