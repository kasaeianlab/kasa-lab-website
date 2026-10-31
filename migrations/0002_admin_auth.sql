CREATE TABLE IF NOT EXISTS admin_login_codes (
  id TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  code_hash TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  attempts INTEGER NOT NULL DEFAULT 0,
  consumed_at INTEGER,
  created_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_admin_login_codes_email ON admin_login_codes(email);
CREATE TABLE IF NOT EXISTS admin_sessions (
  session_hash TEXT PRIMARY KEY,
  email TEXT NOT NULL,
  expires_at INTEGER NOT NULL,
  created_at INTEGER NOT NULL,
  last_seen_at INTEGER NOT NULL
);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_email ON admin_sessions(email);
CREATE INDEX IF NOT EXISTS idx_admin_sessions_expiry ON admin_sessions(expires_at);
CREATE TABLE IF NOT EXISTS admin_auth_rate_limits (
  rate_key TEXT PRIMARY KEY,
  request_count INTEGER NOT NULL DEFAULT 0,
  window_started_at INTEGER NOT NULL
);
