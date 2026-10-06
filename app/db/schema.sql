PRAGMA foreign_keys = ON;

CREATE TABLE IF NOT EXISTS assets (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  asset_tag TEXT NOT NULL UNIQUE,
  name TEXT NOT NULL,
  asset_type TEXT,
  business_unit TEXT,
  owner TEXT,
  criticality TEXT NOT NULL CHECK (criticality IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  internet_exposed INTEGER NOT NULL DEFAULT 0,
  data_classification TEXT,
  environment TEXT,
  status TEXT NOT NULL DEFAULT 'ACTIVE',
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS employees (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  employee_code TEXT NOT NULL UNIQUE,
  department TEXT,
  role TEXT,
  privilege_level TEXT,
  mfa_enabled INTEGER NOT NULL DEFAULT 0,
  account_status TEXT,
  last_login_days INTEGER,
  training_status TEXT
);

CREATE TABLE IF NOT EXISTS vulnerabilities (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  cve_id TEXT NOT NULL,
  asset_id INTEGER NOT NULL REFERENCES assets(id),
  title TEXT,
  severity TEXT NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  cvss_score REAL NOT NULL CHECK (cvss_score BETWEEN 0 AND 10),
  exploitability TEXT,
  known_exploited INTEGER NOT NULL DEFAULT 0,
  status TEXT NOT NULL CHECK (status IN ('OPEN','IN_PROGRESS','RESOLVED','ACCEPTED')),
  discovered_at TEXT,
  due_date TEXT,
  resolved_at TEXT,
  source TEXT,
  risk_score REAL,
  UNIQUE (cve_id, asset_id)
);

CREATE TABLE IF NOT EXISTS incidents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  incident_code TEXT NOT NULL UNIQUE,
  title TEXT,
  severity TEXT NOT NULL CHECK (severity IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  status TEXT NOT NULL,
  category TEXT,
  detected_at TEXT,
  resolved_at TEXT,
  affected_asset_id INTEGER REFERENCES assets(id),
  description TEXT,
  technique_ids TEXT
);

CREATE TABLE IF NOT EXISTS frameworks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL UNIQUE,
  version TEXT,
  description TEXT,
  source_reference TEXT
);

CREATE TABLE IF NOT EXISTS controls (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  control_code TEXT NOT NULL,
  framework_id INTEGER NOT NULL REFERENCES frameworks(id),
  title TEXT NOT NULL,
  description TEXT,
  category TEXT,
  implementation_status TEXT NOT NULL DEFAULT 'NOT_IMPLEMENTED'
    CHECK (implementation_status IN ('IMPLEMENTED','PARTIAL','NOT_IMPLEMENTED','NOT_APPLICABLE')),
  effectiveness REAL NOT NULL DEFAULT 0 CHECK (effectiveness BETWEEN 0 AND 1),
  owner TEXT,
  UNIQUE (framework_id, control_code)
);

CREATE TABLE IF NOT EXISTS risks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  risk_code TEXT NOT NULL UNIQUE,
  title TEXT NOT NULL,
  description TEXT,
  category TEXT,
  asset_id INTEGER REFERENCES assets(id),
  likelihood INTEGER NOT NULL CHECK (likelihood BETWEEN 1 AND 5),
  impact INTEGER NOT NULL CHECK (impact BETWEEN 1 AND 5),
  inherent_score REAL NOT NULL,
  control_effectiveness REAL NOT NULL DEFAULT 0 CHECK (control_effectiveness BETWEEN 0 AND 1),
  residual_score REAL NOT NULL,
  risk_level TEXT NOT NULL CHECK (risk_level IN ('LOW','MEDIUM','HIGH','CRITICAL')),
  owner TEXT,
  status TEXT NOT NULL DEFAULT 'IDENTIFIED'
    CHECK (status IN ('IDENTIFIED','ASSESSMENT','TREATMENT','MITIGATION','VALIDATION','ACCEPTED','CLOSED')),
  treatment TEXT CHECK (treatment IN ('MITIGATE','TRANSFER','AVOID','ACCEPT')),
  approval_status TEXT NOT NULL DEFAULT 'NOT_REQUIRED'
    CHECK (approval_status IN ('NOT_REQUIRED','PENDING','APPROVED','REJECTED')),
  due_date TEXT,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP,
  updated_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS risk_controls (
  risk_id INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
  control_id INTEGER NOT NULL REFERENCES controls(id) ON DELETE CASCADE,
  PRIMARY KEY (risk_id, control_id)
);

CREATE TABLE IF NOT EXISTS control_mappings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_type TEXT NOT NULL,
  source_id INTEGER NOT NULL,
  framework_id INTEGER NOT NULL REFERENCES frameworks(id),
  control_id INTEGER REFERENCES controls(id),
  external_ref TEXT,
  mapping_reason TEXT,
  confidence REAL CHECK (confidence BETWEEN 0 AND 1),
  origin TEXT NOT NULL DEFAULT 'CURATED' CHECK (origin IN ('CURATED','AI_SUGGESTED')),
  review_state TEXT NOT NULL DEFAULT 'APPROVED' CHECK (review_state IN ('PENDING','APPROVED','REJECTED')),
  ai_interaction_id INTEGER
);

CREATE TABLE IF NOT EXISTS evidence (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  control_id INTEGER NOT NULL REFERENCES controls(id),
  evidence_type TEXT,
  title TEXT,
  location TEXT,
  status TEXT NOT NULL CHECK (status IN ('PRESENT','MISSING','EXPIRED','NEEDS_REVIEW')),
  collected_at TEXT,
  expiry_date TEXT,
  owner TEXT
);

CREATE TABLE IF NOT EXISTS vendors (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor_code TEXT NOT NULL UNIQUE,
  vendor_name TEXT NOT NULL,
  service_category TEXT,
  criticality TEXT,
  data_access TEXT,
  inherent_risk REAL,
  residual_risk REAL,
  assessment_status TEXT,
  last_assessed TEXT,
  next_review TEXT
);

CREATE TABLE IF NOT EXISTS vendor_findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  vendor_id INTEGER NOT NULL REFERENCES vendors(id),
  finding TEXT NOT NULL,
  severity TEXT,
  status TEXT,
  due_date TEXT
);

CREATE TABLE IF NOT EXISTS remediation_actions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  risk_id INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
  action TEXT NOT NULL,
  owner TEXT,
  priority TEXT,
  due_date TEXT,
  status TEXT NOT NULL DEFAULT 'OPEN',
  completed_at TEXT,
  effectiveness_gain REAL NOT NULL DEFAULT 0.1 CHECK (effectiveness_gain BETWEEN 0 AND 1)
);

CREATE TABLE IF NOT EXISTS audit_findings (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  finding_code TEXT NOT NULL UNIQUE,
  title TEXT,
  source TEXT,
  severity TEXT,
  status TEXT,
  owner TEXT,
  due_date TEXT
);

CREATE TABLE IF NOT EXISTS risk_history (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  risk_id INTEGER NOT NULL REFERENCES risks(id) ON DELETE CASCADE,
  score REAL NOT NULL,
  risk_level TEXT NOT NULL,
  recorded_at TEXT NOT NULL,
  reason TEXT
);

CREATE TABLE IF NOT EXISTS risk_config (
  key TEXT PRIMARY KEY,
  value REAL NOT NULL,
  description TEXT
);

CREATE TABLE IF NOT EXISTS source_registry (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_name TEXT NOT NULL UNIQUE,
  publisher TEXT,
  source_type TEXT NOT NULL CHECK (source_type IN ('PUBLIC','SYNTHETIC')),
  official_url TEXT,
  acquisition_method TEXT,
  license_notes TEXT,
  retrieval_timestamp TEXT,
  dataset_version TEXT,
  checksum TEXT,
  record_count INTEGER DEFAULT 0,
  last_successful_run TEXT,
  status TEXT NOT NULL DEFAULT 'NEVER_RUN',
  from_cache INTEGER NOT NULL DEFAULT 0,
  last_error TEXT
);

CREATE TABLE IF NOT EXISTS data_sources (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_name TEXT NOT NULL UNIQUE,
  source_type TEXT,
  file_name TEXT,
  ingestion_status TEXT,
  last_run TEXT
);

CREATE TABLE IF NOT EXISTS etl_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source_id INTEGER REFERENCES data_sources(id),
  source_name TEXT,
  source_version TEXT,
  source_checksum TEXT,
  retrieval_timestamp TEXT,
  started_at TEXT NOT NULL,
  completed_at TEXT,
  records_read INTEGER DEFAULT 0,
  records_valid INTEGER DEFAULT 0,
  records_rejected INTEGER DEFAULT 0,
  records_loaded INTEGER DEFAULT 0,
  duplicates_removed INTEGER DEFAULT 0,
  quality_score REAL,
  status TEXT NOT NULL DEFAULT 'RUNNING',
  error_message TEXT
);

CREATE TABLE IF NOT EXISTS etl_rejections (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  etl_run_id INTEGER NOT NULL REFERENCES etl_runs(id),
  source_row INTEGER,
  reason TEXT NOT NULL,
  raw_payload TEXT
);

CREATE TABLE IF NOT EXISTS cve_catalog (
  cve_id TEXT PRIMARY KEY,
  description TEXT,
  published_at TEXT,
  last_modified_at TEXT,
  cvss_version TEXT,
  cvss_score REAL,
  cvss_vector TEXT,
  severity TEXT,
  cwe TEXT,
  affected_products TEXT,
  reference_urls TEXT,
  in_kev INTEGER NOT NULL DEFAULT 0
);

CREATE TABLE IF NOT EXISTS kev_entries (
  cve_id TEXT PRIMARY KEY,
  vendor_project TEXT,
  product TEXT,
  vulnerability_name TEXT,
  date_added TEXT,
  due_date TEXT,
  known_ransomware_use TEXT,
  notes TEXT,
  required_action TEXT
);

CREATE TABLE IF NOT EXISTS attack_techniques (
  technique_id TEXT PRIMARY KEY,
  name TEXT NOT NULL,
  tactics TEXT,
  description TEXT,
  platforms TEXT,
  version TEXT
);

CREATE TABLE IF NOT EXISTS ai_interactions (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  task TEXT,
  user_query TEXT,
  sanitized_query TEXT,
  model TEXT,
  prompt_version TEXT,
  retrieval_ids TEXT,
  retrieval_count INTEGER DEFAULT 0,
  response TEXT,
  grounding_score REAL,
  guardrail_status TEXT,
  output_validation TEXT,
  requires_approval INTEGER NOT NULL DEFAULT 0,
  created_at TEXT DEFAULT CURRENT_TIMESTAMP
);

CREATE TABLE IF NOT EXISTS ai_eval_runs (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  eval_suite TEXT,
  model TEXT,
  prompt_version TEXT,
  mode TEXT,
  started_at TEXT,
  completed_at TEXT,
  total_cases INTEGER DEFAULT 0,
  passed_cases INTEGER DEFAULT 0,
  score REAL,
  category_scores TEXT,
  is_baseline INTEGER NOT NULL DEFAULT 0,
  status TEXT
);

CREATE TABLE IF NOT EXISTS ai_eval_cases (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  eval_run_id INTEGER NOT NULL REFERENCES ai_eval_runs(id),
  case_code TEXT,
  category TEXT,
  input TEXT,
  expected_behavior TEXT,
  actual_output TEXT,
  score REAL,
  passed INTEGER,
  failure_reason TEXT
);

CREATE TABLE IF NOT EXISTS ai_approvals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ai_interaction_id INTEGER NOT NULL REFERENCES ai_interactions(id),
  reviewer TEXT,
  decision TEXT NOT NULL CHECK (decision IN ('APPROVED','REJECTED')),
  comments TEXT,
  decided_at TEXT
);

CREATE TABLE IF NOT EXISTS documents (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  title TEXT NOT NULL,
  source_type TEXT,
  framework TEXT,
  version TEXT,
  checksum TEXT,
  status TEXT,
  trusted INTEGER NOT NULL DEFAULT 1,
  ingested_at TEXT
);

CREATE TABLE IF NOT EXISTS document_chunks (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  document_id INTEGER NOT NULL REFERENCES documents(id) ON DELETE CASCADE,
  chunk_index INTEGER NOT NULL,
  section TEXT,
  content TEXT NOT NULL,
  metadata_json TEXT
);

CREATE INDEX IF NOT EXISTS idx_vuln_cve ON vulnerabilities(cve_id);
CREATE INDEX IF NOT EXISTS idx_vuln_sev ON vulnerabilities(severity);
CREATE INDEX IF NOT EXISTS idx_vuln_status ON vulnerabilities(status);
CREATE INDEX IF NOT EXISTS idx_risks_level ON risks(risk_level);
CREATE INDEX IF NOT EXISTS idx_risks_status ON risks(status);
CREATE INDEX IF NOT EXISTS idx_risks_owner ON risks(owner);
CREATE INDEX IF NOT EXISTS idx_risks_resid ON risks(residual_score);
CREATE INDEX IF NOT EXISTS idx_controls_fw ON controls(framework_id);
CREATE INDEX IF NOT EXISTS idx_evidence_ctrl ON evidence(control_id);
CREATE INDEX IF NOT EXISTS idx_inc_sev ON incidents(severity);
CREATE INDEX IF NOT EXISTS idx_vendors_resid ON vendors(residual_risk);
CREATE INDEX IF NOT EXISTS idx_etl_started ON etl_runs(started_at);
CREATE INDEX IF NOT EXISTS idx_eval_cat ON ai_eval_cases(category);

CREATE TABLE IF NOT EXISTS audit_log (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  actor TEXT,
  action TEXT NOT NULL,
  entity TEXT,
  entity_id TEXT,
  detail TEXT
);

CREATE TABLE IF NOT EXISTS analyses (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  kind TEXT NOT NULL CHECK (kind IN ('logs','incident')),
  source_name TEXT,
  created_at TEXT NOT NULL,
  event_count INTEGER DEFAULT 0,
  finding_count INTEGER DEFAULT 0,
  severity TEXT,
  score REAL,
  result_json TEXT NOT NULL
);

CREATE TABLE IF NOT EXISTS signals (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  source TEXT NOT NULL,
  kind TEXT NOT NULL,
  ts TEXT NOT NULL,
  ingested_at TEXT NOT NULL,
  severity TEXT NOT NULL CHECK (severity IN ('INFO','LOW','MEDIUM','HIGH','CRITICAL')),
  host TEXT,
  asset_id INTEGER REFERENCES assets(id),
  user TEXT,
  src_ip TEXT,
  title TEXT NOT NULL,
  description TEXT,
  technique_ids TEXT,
  cve_id TEXT,
  raw TEXT,
  status TEXT NOT NULL DEFAULT 'NEW' CHECK (status IN ('NEW','CORRELATED','IGNORED')),
  incident_id INTEGER REFERENCES incidents(id),
  scenario_id INTEGER,
  simulated INTEGER NOT NULL DEFAULT 1
);
CREATE INDEX IF NOT EXISTS idx_signals_ts ON signals(ts);
CREATE INDEX IF NOT EXISTS idx_signals_status ON signals(status);
CREATE INDEX IF NOT EXISTS idx_signals_incident ON signals(incident_id);

CREATE TABLE IF NOT EXISTS sim_scenarios (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  name TEXT NOT NULL,
  target TEXT,
  started_at TEXT NOT NULL,
  steps INTEGER NOT NULL,
  incident_id INTEGER REFERENCES incidents(id),
  detected_at TEXT
);

CREATE TABLE IF NOT EXISTS sim_metrics (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  ts TEXT NOT NULL,
  events INTEGER NOT NULL,
  rejected INTEGER NOT NULL,
  open_incidents INTEGER NOT NULL,
  open_vulns INTEGER NOT NULL,
  kev_open INTEGER NOT NULL,
  by_source TEXT
);
