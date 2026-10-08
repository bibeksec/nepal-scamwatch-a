CREATE TABLE IF NOT EXISTS reports (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  case_id TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  category TEXT NOT NULL,
  platform TEXT NOT NULL,
  identifier TEXT,
  description TEXT NOT NULL,
  risk TEXT NOT NULL DEFAULT 'Medium',
  status TEXT NOT NULL DEFAULT 'pending',
  evidence_key TEXT,
  evidence_type TEXT,
  ip_hash TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);

CREATE INDEX IF NOT EXISTS idx_reports_status ON reports(status);
CREATE INDEX IF NOT EXISTS idx_reports_category ON reports(category);
CREATE INDEX IF NOT EXISTS idx_reports_created ON reports(created_at);
CREATE INDEX IF NOT EXISTS idx_reports_iphash ON reports(ip_hash, created_at);
