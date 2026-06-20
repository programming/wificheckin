CREATE TABLE workers (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  first_name TEXT NOT NULL,
  last_name TEXT NOT NULL,
  token TEXT NOT NULL UNIQUE,
  active INTEGER DEFAULT 1,
  created_at DATETIME DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE checkins (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  worker_id INTEGER NOT NULL,
  ip_address TEXT,
  fingerprint_hash TEXT,
  flagged INTEGER DEFAULT 0,
  flag_reason TEXT,
  timestamp DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(worker_id) REFERENCES workers(id)
);

CREATE TABLE fingerprints (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  worker_id INTEGER NOT NULL UNIQUE,
  fingerprint_json TEXT NOT NULL,
  captured_at DATETIME DEFAULT CURRENT_TIMESTAMP,
  FOREIGN KEY(worker_id) REFERENCES workers(id)
);

CREATE TABLE admin_login_attempts (
  ip_address TEXT PRIMARY KEY,
  fail_count INTEGER DEFAULT 0,
  locked_until DATETIME
);

CREATE INDEX idx_checkins_worker_time ON checkins(worker_id, timestamp);
