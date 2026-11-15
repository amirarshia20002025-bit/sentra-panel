-- SENTRA Panel — D1 schema (all timestamps are ms epoch; 0 means "never/unset")

CREATE TABLE IF NOT EXISTS users (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  token TEXT UNIQUE NOT NULL,          -- subscription link secret token
  uuid TEXT UNIQUE,                    -- VLESS uuid
  password TEXT,                       -- Trojan password
  enabled INTEGER NOT NULL DEFAULT 1,  -- soft kill switch per user
  quota_bytes INTEGER NOT NULL DEFAULT 0,   -- 0 = unlimited
  used_bytes INTEGER NOT NULL DEFAULT 0,
  quota_requests INTEGER NOT NULL DEFAULT 0, -- 0 = unlimited
  used_requests INTEGER NOT NULL DEFAULT 0,
  ip_limit INTEGER NOT NULL DEFAULT 0,       -- 0 = unlimited (best-effort on edge)
  start_on_first_connect INTEGER NOT NULL DEFAULT 0, -- defer expiry until first use
  duration_days INTEGER NOT NULL DEFAULT 0,          -- days granted from first connect
  started_at INTEGER,
  expires_at INTEGER,                        -- ms epoch; 0 = never
  reset_period TEXT NOT NULL DEFAULT 'never',-- never | daily | weekly | monthly
  last_reset_at INTEGER,
  isp_tag TEXT DEFAULT '',                   -- optional per-user ISP hint
  note TEXT DEFAULT '',
  created_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS sessions (
  token TEXT PRIMARY KEY,
  data TEXT NOT NULL,
  expires_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS traffic_daily (
  user_id INTEGER NOT NULL,
  day TEXT NOT NULL,              -- YYYY-MM-DD (UTC)
  up INTEGER NOT NULL DEFAULT 0,
  down INTEGER NOT NULL DEFAULT 0,
  PRIMARY KEY (user_id, day)
);

CREATE TABLE IF NOT EXISTS scan_cache (
  ip TEXT PRIMARY KEY,
  ok INTEGER NOT NULL,
  latency INTEGER NOT NULL,       -- ms (0 = failed)
  updated_at INTEGER NOT NULL
);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  at INTEGER NOT NULL,
  actor TEXT NOT NULL,            -- 'admin' | 'bot' | 'system'
  action TEXT NOT NULL,
  detail TEXT DEFAULT ''
);

CREATE INDEX IF NOT EXISTS idx_users_enabled ON users (enabled);
CREATE INDEX IF NOT EXISTS idx_sessions_exp ON sessions (expires_at);
CREATE INDEX IF NOT EXISTS idx_traffic_day ON traffic_daily (day);
