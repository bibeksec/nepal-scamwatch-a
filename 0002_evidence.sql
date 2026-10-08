CREATE TABLE IF NOT EXISTS evidence (
  key TEXT PRIMARY KEY,
  content_type TEXT NOT NULL,
  data TEXT NOT NULL,
  created_at TEXT NOT NULL
);
