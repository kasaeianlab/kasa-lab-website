
PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS projects (
  id TEXT PRIMARY KEY,
  tracking_hash TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  email TEXT NOT NULL,
  organization TEXT,
  organization_type TEXT NOT NULL,
  country TEXT,
  service_type TEXT NOT NULL,
  project_title TEXT NOT NULL,
  description TEXT NOT NULL,
  expected_deliverables TEXT,
  timeline TEXT,
  budget_range TEXT,
  status TEXT NOT NULL DEFAULT 'Submitted',
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  notification_status TEXT NOT NULL DEFAULT 'pending'
);

CREATE TABLE IF NOT EXISTS project_files (
  id TEXT PRIMARY KEY,
  project_id TEXT NOT NULL,
  storage_key TEXT NOT NULL UNIQUE,
  original_name TEXT NOT NULL,
  content_type TEXT NOT NULL,
  size_bytes INTEGER NOT NULL,
  uploaded_at TEXT NOT NULL,
  FOREIGN KEY (project_id) REFERENCES projects(id)
    ON DELETE CASCADE
);

CREATE TABLE IF NOT EXISTS submission_rate_limits (
  ip_hash TEXT PRIMARY KEY,
  window_started_at INTEGER NOT NULL,
  request_count INTEGER NOT NULL DEFAULT 1
);

CREATE INDEX IF NOT EXISTS idx_projects_created_at
  ON projects(created_at);

CREATE INDEX IF NOT EXISTS idx_projects_status
  ON projects(status);

CREATE INDEX IF NOT EXISTS idx_project_files_project_id
  ON project_files(project_id);
