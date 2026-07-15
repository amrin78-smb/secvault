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

-- ─────────────────────────────────────────
-- READONLY GRANTS
-- Per-table GRANT SELECT only — NEVER GRANT SELECT ON ALL TABLES.
-- device_credentials is intentionally excluded from both readonly roles.
-- Roles are created idempotently; grants are safe to re-run.
-- ─────────────────────────────────────────

DO $$
BEGIN
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'claude_readonly') THEN
    CREATE ROLE claude_readonly LOGIN PASSWORD 'ClaudeRead@2026!';
  END IF;
  IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = 'nocvault_readonly') THEN
    CREATE ROLE nocvault_readonly LOGIN PASSWORD 'ClaudeRead@2026!';
  END IF;
END
$$;

GRANT SELECT ON TABLE settings TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE devices TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE device_versions TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE device_configs TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE firewall_rules TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE advisories TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE advisory_conditions TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE device_cve_assessments TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE vendor_recommended_releases TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE feed_sync_log TO claude_readonly, nocvault_readonly;
-- Exception: device_credentials — NEVER grant to these users
