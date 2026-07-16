-- SecVault database schema
-- Every statement uses CREATE TABLE IF NOT EXISTS / IF NOT EXISTS — safe to re-run on every update.
-- NEVER use DROP TABLE here — destructive and irreversible in production.

CREATE EXTENSION IF NOT EXISTS pgcrypto;

-- ─────────────────────────────────────────
-- SETTINGS
-- ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS settings (
  key TEXT PRIMARY KEY,
  value TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- ─────────────────────────────────────────
-- DEVICE MANAGEMENT
-- ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS devices (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  name TEXT NOT NULL,
  vendor TEXT NOT NULL DEFAULT 'forcepoint',
  mgmt_method TEXT NOT NULL DEFAULT 'smc', -- 'api' | 'ssh' | 'smc' | 'file'
  mgmt_ip TEXT,
  smc_host TEXT,
  smc_port INTEGER DEFAULT 8082,
  allow_self_signed_ssl BOOLEAN NOT NULL DEFAULT true,
  site TEXT,
  asset_criticality TEXT NOT NULL DEFAULT 'medium', -- 'low' | 'medium' | 'high' | 'critical'
  active BOOLEAN NOT NULL DEFAULT true,
  last_connectivity_ok BOOLEAN,
  last_connectivity_checked_at TIMESTAMPTZ,
  last_collected_at TIMESTAMPTZ,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE TABLE IF NOT EXISTS device_versions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  version_string TEXT NOT NULL,
  version_tuple JSONB NOT NULL,
  build TEXT,
  model TEXT,
  collected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

-- Tier 1 multi-vendor support: generic management port (API vendors default to
-- 443, SSH vendors to 22, applied in the adapter when NULL). smc_port remains
-- Forcepoint-specific. ADD COLUMN IF NOT EXISTS is idempotent — safe to re-run.
ALTER TABLE devices ADD COLUMN IF NOT EXISTS mgmt_port INTEGER;

CREATE INDEX IF NOT EXISTS idx_device_versions_device_id ON device_versions(device_id);
CREATE INDEX IF NOT EXISTS idx_device_versions_collected_at ON device_versions(collected_at);

CREATE TABLE IF NOT EXISTS device_credentials (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  credential_type TEXT NOT NULL, -- 'ssh' | 'rest_api' | 'smc_api'
  encrypted_data TEXT NOT NULL,
  iv TEXT NOT NULL,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_credentials_device_id ON device_credentials(device_id);

-- ─────────────────────────────────────────
-- CONFIG
-- ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS device_configs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  config_raw TEXT,
  config_parsed JSONB,
  collected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_device_configs_device_id ON device_configs(device_id);
CREATE INDEX IF NOT EXISTS idx_device_configs_collected_at ON device_configs(collected_at);

-- ─────────────────────────────────────────
-- FIREWALL RULES
-- ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS firewall_rules (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  rule_name TEXT,
  rule_id_vendor TEXT,
  sequence_number INTEGER,
  enabled BOOLEAN NOT NULL DEFAULT true,
  action TEXT, -- 'allow' | 'deny' | 'drop' | 'reject'
  src_zones JSONB,
  dst_zones JSONB,
  src_addresses JSONB,
  dst_addresses JSONB,
  services JSONB,
  applications JSONB,
  schedule TEXT,
  expiry_date TIMESTAMPTZ,
  log_enabled BOOLEAN NOT NULL DEFAULT true,
  nat_enabled BOOLEAN NOT NULL DEFAULT false,
  comment TEXT,
  tags JSONB,
  hit_count BIGINT NOT NULL DEFAULT 0,
  last_hit_at TIMESTAMPTZ,
  bytes_transferred BIGINT NOT NULL DEFAULT 0,
  collected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  raw_rule JSONB
);

CREATE INDEX IF NOT EXISTS idx_firewall_rules_device_id ON firewall_rules(device_id);
CREATE INDEX IF NOT EXISTS idx_firewall_rules_device_seq ON firewall_rules(device_id, sequence_number);

-- Structured diffs between consecutive device_configs snapshots (Phase 6).
CREATE TABLE IF NOT EXISTS config_diffs (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  diff JSONB NOT NULL, -- { added: [{path,value}], removed: [{path,value}], modified: [{path,old,new}] }
  change_summary TEXT,
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  acknowledged_at TIMESTAMPTZ,
  acknowledged_by TEXT
);

CREATE INDEX IF NOT EXISTS idx_config_diffs_device_id ON config_diffs(device_id);
CREATE INDEX IF NOT EXISTS idx_config_diffs_detected_at ON config_diffs(detected_at);

-- Labeled config snapshots kept for restore/download (Phase 6).
-- 'auto' backups are only written when a config change is detected, to avoid
-- duplicating every unchanged daily pull.
CREATE TABLE IF NOT EXISTS config_backups (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  config_raw TEXT,
  label TEXT NOT NULL DEFAULT 'auto', -- 'auto' | 'manual' | 'pre-change'
  backed_up_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_config_backups_device_id ON config_backups(device_id);

-- ─────────────────────────────────────────
-- RULE ANALYSIS (Phase 5)
-- ─────────────────────────────────────────

-- Rule hygiene findings, rewritten per device on each analysis run.
-- rule_id cascades from firewall_rules, which is itself DELETE+reinserted on
-- every rule pull — findings for a device are therefore always regenerated
-- immediately after each pull (engine-worker ordering guarantees this).
CREATE TABLE IF NOT EXISTS rule_analysis_results (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  rule_id UUID NOT NULL REFERENCES firewall_rules(id) ON DELETE CASCADE,
  finding_type TEXT NOT NULL, -- 'unused' | 'shadow' | 'redundant' | 'any_any' | 'risky_service' | 'reorder_candidate' | 'expiring_soon' | 'log_disabled' | 'overly_permissive'
  severity TEXT NOT NULL DEFAULT 'info', -- 'critical' | 'high' | 'medium' | 'info'
  detail TEXT,
  affected_rule_ids JSONB NOT NULL DEFAULT '[]'::jsonb, -- e.g. for shadow: the rule(s) doing the shadowing
  remediation TEXT,
  analyzed_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_rar_device_id ON rule_analysis_results(device_id);
CREATE INDEX IF NOT EXISTS idx_rar_finding_type ON rule_analysis_results(finding_type);
CREATE INDEX IF NOT EXISTS idx_rar_severity ON rule_analysis_results(severity);

-- Operator acknowledge/dismiss tracking for Phase 5 rule-hygiene findings
-- (Rule Analysis Dashboard Phase 2 -- Cleanup/Optimization/Reorder tabs).
--
-- Deliberately NOT keyed on rule_analysis_results.id or firewall_rules.id:
-- BOTH are fully DELETE+reinserted on every pull (rule_analysis_results on
-- every analysis run, firewall_rules on every collect -- see
-- lib/adapters/index.js's collectAndStore, which runs on a 24h schedule), so
-- either UUID would be a brand-new random value after the very next
-- scheduled collect. An acknowledgement keyed that way would silently vanish
-- on the next pull, defeating the entire point of a table meant to survive
-- across pulls. Keyed instead on rule_id_vendor, the vendor-native rule
-- identifier (firewall_rules.rule_id_vendor -- e.g. the PAN-OS rule name, the
-- Fortinet policy ID) which stays stable across recollects as long as the
-- rule itself isn't renamed/recreated on the device. rule_id_vendor is
-- nullable on firewall_rules for a handful of already-degraded/unparseable
-- rule shapes across adapters -- acknowledgement is simply unavailable for
-- those rows (the UI omits the control rather than accepting an ambiguous
-- NULL-keyed row, since Postgres UNIQUE treats multiple NULLs as distinct).
CREATE TABLE IF NOT EXISTS finding_acknowledgements (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  rule_id_vendor TEXT NOT NULL,
  finding_type TEXT NOT NULL,
  status TEXT NOT NULL DEFAULT 'new', -- 'new' | 'acknowledged' | 'dismissed' | 'actioned'
  note TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (device_id, rule_id_vendor, finding_type)
);

CREATE INDEX IF NOT EXISTS idx_fa_device_id ON finding_acknowledgements(device_id);

-- ─────────────────────────────────────────
-- CVE / ADVISORY
-- ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS advisories (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  cve_id TEXT NOT NULL UNIQUE,
  vendor TEXT NOT NULL,
  title TEXT,
  description TEXT,
  cvss_score NUMERIC(3, 1),
  cvss_vector TEXT,
  kev_listed BOOLEAN NOT NULL DEFAULT false,
  kev_date TIMESTAMPTZ,
  published_at TIMESTAMPTZ,
  affected_version_ranges JSONB NOT NULL DEFAULT '[]'::jsonb,
  fixed_in_versions JSONB NOT NULL DEFAULT '[]'::jsonb,
  advisory_url TEXT,
  raw_data JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_advisories_vendor ON advisories(vendor);
CREATE INDEX IF NOT EXISTS idx_advisories_kev_listed ON advisories(kev_listed);
CREATE INDEX IF NOT EXISTS idx_advisories_cvss_score ON advisories(cvss_score);
CREATE INDEX IF NOT EXISTS idx_advisories_published_at ON advisories(published_at);

-- Applicability predicates — curated data, not code. Empty until Phase 6 builds the
-- predicate evaluator; device_cve_assessments.config_applies defaults to 'unknown'
-- (tri-state, NOT 'no') whenever no row exists here for an advisory.
CREATE TABLE IF NOT EXISTS advisory_conditions (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  advisory_id UUID NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
  vendor TEXT NOT NULL,
  condition_description TEXT,
  predicate_type TEXT, -- 'config_key_exists' | 'config_value_equals' | 'config_value_matches' | 'feature_enabled' | 'port_exposed' | 'admin_access_from_zone'
  predicate_config JSONB,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_advisory_conditions_advisory_id ON advisory_conditions(advisory_id);

CREATE TABLE IF NOT EXISTS device_cve_assessments (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  advisory_id UUID NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
  version_affected BOOLEAN NOT NULL DEFAULT false,
  config_applies VARCHAR(10) NOT NULL DEFAULT 'unknown', -- 'yes' | 'no' | 'unknown'
  kev_listed BOOLEAN NOT NULL DEFAULT false,
  log_hit BOOLEAN NOT NULL DEFAULT false,
  priority_band VARCHAR(20) NOT NULL DEFAULT 'monitor', -- 'patch_now' | 'scheduled' | 'monitor'
  fixed_in TEXT,
  is_fixed_recommended BOOLEAN NOT NULL DEFAULT false,
  assessed_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  next_check_at TIMESTAMPTZ,
  UNIQUE (device_id, advisory_id)
);

CREATE INDEX IF NOT EXISTS idx_dca_device_id ON device_cve_assessments(device_id);
CREATE INDEX IF NOT EXISTS idx_dca_advisory_id ON device_cve_assessments(advisory_id);
CREATE INDEX IF NOT EXISTS idx_dca_priority_band ON device_cve_assessments(priority_band);

-- ─────────────────────────────────────────
-- VENDOR RECOMMENDED RELEASES
-- ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS vendor_recommended_releases (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  vendor TEXT NOT NULL,
  product_line TEXT,
  version TEXT NOT NULL,
  version_tuple JSONB NOT NULL,
  is_recommended BOOLEAN NOT NULL DEFAULT false,
  is_stable BOOLEAN NOT NULL DEFAULT false,
  as_of_date DATE,
  notes TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_vrr_vendor ON vendor_recommended_releases(vendor);

-- ─────────────────────────────────────────
-- FEED SYNC LOG
-- ─────────────────────────────────────────

CREATE TABLE IF NOT EXISTS feed_sync_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  feed_name TEXT NOT NULL, -- 'nvd' | 'kev'
  status TEXT NOT NULL, -- 'success' | 'error' | 'partial'
  inserted INTEGER NOT NULL DEFAULT 0,
  updated INTEGER NOT NULL DEFAULT 0,
  errors JSONB,
  duration_ms INTEGER,
  started_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  finished_at TIMESTAMPTZ
);

CREATE INDEX IF NOT EXISTS idx_feed_sync_log_feed_name ON feed_sync_log(feed_name);
CREATE INDEX IF NOT EXISTS idx_feed_sync_log_started_at ON feed_sync_log(started_at);

-- Readonly diagnostic roles + per-table grants are NOT created here.
-- Creating a ROLE requires CREATEROLE/superuser privilege, which secvault_user
-- (the account this file normally runs as, via lib/migrate.js) does not have —
-- see lib/schema-grants.sql, which is applied separately with elevated
-- privileges and is allowed to fail without aborting table creation.
