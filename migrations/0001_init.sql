-- Migration number: 0001 	 2025-08-23T18:41:22.858Z
CREATE TABLE IF NOT EXISTS users (
  id TEXT PRIMARY KEY,           -- your OAuth subject (github/google sub)
  email TEXT
);

CREATE TABLE IF NOT EXISTS applications (
  user_id TEXT NOT NULL,
  job_id  TEXT NOT NULL,
  applied INTEGER NOT NULL,      -- 0/1
  updated_at INTEGER NOT NULL DEFAULT (unixepoch()),
  PRIMARY KEY (user_id, job_id),
  FOREIGN KEY (user_id) REFERENCES users(id)
);
