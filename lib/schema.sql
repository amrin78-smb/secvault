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

-- ⛔ Added 2026-07-19, found in a follow-up bug sweep: Fortinet SSH and Palo
-- Alto SSH both successfully parse a serial number out of the device
-- (parseSystemStatus()'s `serial` field / sshParser's system-info `serial`
-- field respectively) and then getVersion()'s own return object dropped it
-- before it ever reached collectAndStore()'s INSERT — there was no column
-- to put it in anyway. `ADD COLUMN IF NOT EXISTS` (not part of the CREATE
-- TABLE above, which only applies on first creation) so this lands on an
-- already-deployed table too.
ALTER TABLE device_versions ADD COLUMN IF NOT EXISTS serial TEXT;

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

-- ⛔ Added 2026-07-19, found in a follow-up bug sweep: setCredential()'s
-- DELETE+INSERT transaction is atomic for a SINGLE request, but nothing
-- ever prevented two CONCURRENT setCredential() calls for the same
-- (device_id, credential_type) — e.g. a double-submit of the credential
-- rotation form — from each independently deleting-then-inserting and
-- leaving two rows behind, with getCredential()'s `ORDER BY created_at DESC
-- LIMIT 1` silently picking one by timestamp with no DB-enforced guarantee.
-- Dedupe (keep only the newest row per pair, matching what getCredential()
-- would already have picked) BEFORE adding the constraint, so this is safe
-- to run on a production database that may have accumulated a duplicate —
-- claude_readonly/nocvault_readonly cannot read this table (correctly) so
-- this could not be verified clean ahead of time; both statements are
-- idempotent, safe to re-run on every update.
DELETE FROM device_credentials a USING device_credentials b
WHERE a.device_id = b.device_id
  AND a.credential_type = b.credential_type
  AND a.created_at < b.created_at;

DO $$
BEGIN
  IF NOT EXISTS (
    SELECT 1 FROM pg_constraint WHERE conname = 'device_credentials_device_id_credential_type_key'
  ) THEN
    ALTER TABLE device_credentials
      ADD CONSTRAINT device_credentials_device_id_credential_type_key
      UNIQUE (device_id, credential_type);
  END IF;
END $$;

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

-- Fleet Alerts/Events page: same ack pattern as finding_acknowledgements above,
-- but for device_cve_assessments rows (which have no ack column of their own).
-- Keyed on (device_id, advisory_id) -- NOT device_cve_assessments.id -- because
-- although that table is upserted (ON CONFLICT DO UPDATE, not delete+reinsert,
-- see versionMatcher.js), the natural key is what versionMatcher already
-- upserts on, so keying the ack the same way keeps both tables joinable on
-- the same pair reliably regardless of internal id churn.
CREATE TABLE IF NOT EXISTS cve_assessment_acknowledgements (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  advisory_id UUID NOT NULL REFERENCES advisories(id) ON DELETE CASCADE,
  status TEXT NOT NULL DEFAULT 'new', -- 'new' | 'acknowledged' | 'dismissed' | 'actioned'
  note TEXT,
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  UNIQUE (device_id, advisory_id)
);

CREATE INDEX IF NOT EXISTS idx_caa_device_id ON cve_assessment_acknowledgements(device_id);

-- Phase 7: Compliance engine. Curated check library (audit_checks) + per-device
-- results (audit_findings), reusing lib/engines/applicability.js's predicate
-- evaluator (predicate_config is the SAME shape as advisory_conditions.predicate_config
-- -- config_key_exists/config_value_equals/config_value_matches/feature_enabled/
-- port_exposed/admin_access_from_zone -- evaluated against device_configs.config_parsed).
--
-- `standards` is a TEXT[], not a single TEXT column, even though the compliance
-- spec otherwise describes one check having one "standard" -- because the same
-- spec's own mapping table ("logging checks -> PCI_DSS, ISO_27001", "access
-- control checks -> PCI_DSS, CIS_V8, ISO_27001, NIST") requires ONE check to
-- score against MULTIPLE standards simultaneously (a single "admin access not
-- from WAN" check must count toward CIS_V8 AND ISO_27001 AND PCI_DSS AND NIST's
-- separate pass/fail percentages). A single-value column cannot represent that
-- many-to-many relationship; a plain array avoids a join table for what is
-- small, rarely-changing curated data (same tradeoff this schema already makes
-- for affected_version_ranges/fixed_in_versions as JSONB rather than child
-- tables).
CREATE TABLE IF NOT EXISTS audit_checks (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  check_id TEXT NOT NULL UNIQUE, -- stable slug, e.g. 'fortinet-ssl-vpn-not-internet-exposed'
  name TEXT NOT NULL,
  description TEXT,
  standards TEXT[] NOT NULL, -- subset of 'PCI_DSS' | 'ISO_27001' | 'CIS_V8' | 'NIST' | 'SANS' | 'CUSTOM'
  vendor TEXT, -- NULL = applies to all vendors; else a specific devices.vendor slug
  severity TEXT NOT NULL DEFAULT 'medium', -- 'critical' | 'high' | 'medium' | 'low' | 'info'
  predicate_config JSONB NOT NULL, -- {predicate_type, ...} -- same evaluator as advisory_conditions
  -- predicate_type: 'rule_scan' is a SECOND, distinct kind of check (added
  -- alongside the rule-evidence drill-down UI), evaluated by
  -- lib/engines/configAuditor.js directly against rule_analysis_results
  -- (NOT applicability.js's evaluatePredicate(), which only ever sees
  -- device_configs.config_parsed and has no concept of "for every rule").
  -- Its predicate_config shape is {predicate_type: 'rule_scan', finding_types:
  -- [...]} -- no pass_when, since every rule_scan check's polarity is fixed
  -- ("zero matching rules" always means pass): vendor:null, since
  -- firewall_rules/rule_analysis_results are already vendor-normalized.
  remediation_guidance TEXT,
  created_at TIMESTAMPTZ NOT NULL DEFAULT now(),
  updated_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_checks_vendor ON audit_checks(vendor);
CREATE INDEX IF NOT EXISTS idx_audit_checks_standards ON audit_checks USING GIN(standards);

-- Unlike rule_analysis_results/firewall_rules, audit_checks is curated library
-- data seeded once (lib/auditChecksSeed.js) and only changes when a human adds
-- a check -- it is NOT rewritten per device per pull. A stable UUID FK is
-- therefore safe here (contrast finding_acknowledgements' deliberate natural-key
-- design, which exists specifically because ITS parent rows churn every pull).
--
-- audit_findings itself DOES follow the rule_analysis_results lifecycle: DELETE
-- + reinsert per device on every compliance run (scheduled, after every config
-- pull; or on-demand). No ack/dismiss table for findings -- out of scope here,
-- unlike Phase 5's findings; add one later the same way finding_acknowledgements
-- was added if operators need it.
CREATE TABLE IF NOT EXISTS audit_findings (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  check_id UUID NOT NULL REFERENCES audit_checks(id) ON DELETE CASCADE,
  status TEXT NOT NULL, -- 'pass' | 'fail' | 'warning' | 'na'
  detail TEXT,
  -- Rule-level evidence for predicate_type: 'rule_scan' checks (added
  -- alongside the rule-evidence drill-down UI) -- the firewall_rules.id
  -- values that caused a 'fail'. NULL for every config-predicate check (the
  -- original kind, evaluated against device_configs.config_parsed, which has
  -- no single-rule evidence to point at) and for a rule_scan check that
  -- passed (nothing to show). Deliberately NOT a FK array (Postgres has no
  -- native FK-on-array-element) -- firewall_rules is fully DELETE+reinserted
  -- on every pull, so a stale id here simply resolves to zero rows on the
  -- next JOIN rather than violating a constraint; audit_findings itself is
  -- also fully DELETE+reinserted on every compliance run, so staleness here
  -- never outlives the next run either way.
  matched_rule_ids UUID[],
  detected_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_audit_findings_device_id ON audit_findings(device_id);
CREATE INDEX IF NOT EXISTS idx_audit_findings_check_id ON audit_findings(check_id);
CREATE INDEX IF NOT EXISTS idx_audit_findings_status ON audit_findings(status);

-- Rule Analysis Dashboard Phase 4: risk-score trend + operator audit trail.

-- One row per completed rule-analysis run (both scheduled collects and manual
-- "Run Analysis" clicks -- both paths go through runAnalysisForDevice(), which
-- is the single place this is snapshotted). score/band are stored together
-- (computed once from lib/engines/riskScore.js's computeRiskScore()) rather
-- than storing score alone and re-deriving band on read.
CREATE TABLE IF NOT EXISTS device_risk_history (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  score INTEGER NOT NULL,
  band TEXT NOT NULL, -- 'low' | 'medium' | 'high' | 'critical'
  recorded_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_drh_device_id ON device_risk_history(device_id);
CREATE INDEX IF NOT EXISTS idx_drh_recorded_at ON device_risk_history(recorded_at);

-- VPN active-session count snapshots (added 2026-07-19). A coarse,
-- polling-based substitute for real VPN usage telemetry (the "how many
-- concurrent VPN users over time" question genuinely needs syslog ingestion
-- -- see CLAUDE.md's Phase 8 notes -- this is a bounded, no-log-ingestion-
-- required approximation: periodically ask the device how many VPN sessions
-- are active RIGHT NOW, timestamp it, done). Only vendors whose adapter
-- implements getVpnSessionSummary() are ever polled -- see
-- services/engine-worker.js's runVpnSessionPoll(). A row is only ever
-- inserted on a SUCCESSFUL poll (a failed/unsupported poll writes nothing,
-- same "don't record a confident-looking zero for a failure" discipline as
-- everywhere else in this app) so active_session_count is NOT NULL.
-- `raw` keeps the adapter's raw parsed response for future debugging /
-- extending which fields get surfaced, without a schema change.
--
-- No retention/cleanup job exists for this table yet (accepted simplification
-- -- at a realistic 30-minute poll interval this is ~17.5k rows/device/year,
-- not a near-term scaling concern; a real retention policy is a documented
-- follow-up, not built now, same spirit as LOG_RETENTION_HOT_DAYS/WARM_DAYS
-- existing today for the not-yet-built Phase 8 firewall_logs table).
CREATE TABLE IF NOT EXISTS vpn_session_snapshots (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  device_id UUID NOT NULL REFERENCES devices(id) ON DELETE CASCADE,
  active_session_count INTEGER NOT NULL,
  raw JSONB,
  sampled_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_vss_device_id ON vpn_session_snapshots(device_id);
CREATE INDEX IF NOT EXISTS idx_vss_sampled_at ON vpn_session_snapshots(sampled_at);

-- Operator-action audit trail (NOT a general app log -- scheduled/background
-- jobs already have C:\Apps\SecVault\logs\engine.log for that). Populated
-- only at HTTP route call-sites representing a meaningful in-app action
-- (run-analysis, acknowledge-finding, acknowledge-config-diff), via
-- lib/activityLog.js. device_id is nullable: every call-site today is
-- device-scoped, but a future non-device action (e.g. a settings change)
-- should not be forced to fabricate one.
CREATE TABLE IF NOT EXISTS activity_log (
  id UUID PRIMARY KEY DEFAULT gen_random_uuid(),
  actor TEXT NOT NULL DEFAULT 'unknown',
  action TEXT NOT NULL,
  device_id UUID REFERENCES devices(id) ON DELETE CASCADE,
  detail TEXT,
  occurred_at TIMESTAMPTZ NOT NULL DEFAULT now()
);

CREATE INDEX IF NOT EXISTS idx_al_device_id ON activity_log(device_id);
CREATE INDEX IF NOT EXISTS idx_al_occurred_at ON activity_log(occurred_at);

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
