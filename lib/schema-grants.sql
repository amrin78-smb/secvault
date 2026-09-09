-- Readonly diagnostic roles + per-table grants.
-- Per-table GRANT SELECT only — NEVER GRANT SELECT ON ALL TABLES.
-- device_credentials is intentionally excluded from both readonly roles.
--
-- IMPORTANT: CREATE ROLE requires CREATEROLE or superuser privilege.
-- secvault_user (the account lib/migrate.js normally connects as) has neither —
-- it only received `GRANT ALL PRIVILEGES ON DATABASE secvault` at install time.
-- This file must be applied by a superuser (e.g. `psql -U postgres`), separately
-- from lib/schema.sql, and its failure must never block application startup —
-- see the best-effort handling in lib/migrate.js.

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

-- settings stores the local admin's bcrypt hash under key='admin_password_hash'
-- (app/api/settings/route.js). A blanket table grant would let claude_readonly/
-- nocvault_readonly read it directly via SQL, bypassing the API's own
-- HIDDEN_KEYS filter entirely (that filter only applies to the HTTP GET
-- handler, never to raw SQL access) -- found in a full-app audit (2026-07-16).
-- CLAUDE.md's own rule is that device_credentials is the sole table these
-- roles never see in full; settings holding an equivalent secret needed the
-- same treatment. Grant a view excluding that one row instead of the table.
-- REVOKE is required, not just omitting the old GRANT line below -- this file
-- is re-run on every update (see Update-SecVault.ps1), and REVOKE is the only
-- statement that undoes a privilege a PREVIOUS run already granted on a
-- live database; simply removing a GRANT line here does not retroactively
-- revoke it.
REVOKE SELECT ON TABLE settings FROM claude_readonly, nocvault_readonly;

CREATE OR REPLACE VIEW settings_readonly AS
  SELECT key, value, updated_at FROM settings WHERE key <> 'admin_password_hash';

GRANT SELECT ON settings_readonly TO claude_readonly, nocvault_readonly;
-- ⛔ A whole-TABLE grant covers columns added later, so
-- devices.last_cve_assessed_at (added 2026-09-09) needs no entry of its own —
-- checked, not assumed. This only holds because `devices` is granted as a
-- table; the column-list/VIEW grants above (settings_readonly, users_readonly)
-- do NOT auto-extend, and a new secret-bearing column there must be added to
-- the view definition explicitly or it silently stays hidden/exposed wrongly.
GRANT SELECT ON TABLE devices TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE device_versions TO claude_readonly, nocvault_readonly;
-- Same whole-table reasoning for device_configs.first_collected_at /
-- observation_count / content_hash (added 2026-09-09): all three are covered by
-- the table grant below. None is secret-bearing -- the hash is taken over
-- config_raw/config_parsed, which these roles can already read in full and which
-- every adapter has already redacted before storage.
GRANT SELECT ON TABLE device_configs TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE firewall_rules TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE network_objects TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE device_interfaces TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE device_routes TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE nat_rules TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE zone_classifications TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE object_analysis_results TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE advisories TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE advisory_conditions TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE device_cve_assessments TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE vendor_recommended_releases TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE feed_sync_log TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE config_diffs TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE config_backups TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE rule_analysis_results TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE finding_acknowledgements TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE cve_assessment_acknowledgements TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE audit_checks TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE audit_findings TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE device_risk_history TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE fleet_dashboard_snapshots TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE device_connectivity_history TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE activity_log TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE vpn_session_snapshots TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE vpn_active_sessions TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE vpn_ipsec_tunnels TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE snmp_metric_snapshots TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE notification_dispatch_log TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE compliance_report_log TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE device_licenses TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE device_ha_status TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE device_disk_usage TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE device_content_versions TO claude_readonly, nocvault_readonly;

-- users carries password_hash — same secret-bearing-column treatment as
-- settings.admin_password_hash above (a view excluding it, never a bare
-- table grant). REVOKE first for the same "this file re-runs on every
-- update" reason as settings above.
REVOKE SELECT ON TABLE users FROM claude_readonly, nocvault_readonly;

CREATE OR REPLACE VIEW users_readonly AS
  SELECT id, username, role, created_at, updated_at FROM users;

GRANT SELECT ON users_readonly TO claude_readonly, nocvault_readonly;
-- Exception: device_credentials — NEVER grant to these users
-- Exception: credential_profiles — holds encrypted secret material (the
-- same encrypted_data/iv shape as device_credentials), NEVER grant to
-- these users. No readonly view either, unlike settings/users above —
-- the whole row is credential-adjacent, there is no "safe subset" column
-- to expose (its own `username` column is non-secret but not worth a
-- view for on its own).
-- Exception: notification_channels — same encrypted_data/iv shape as
-- credential_profiles (webhook URL / SMTP password), NEVER grant to these
-- users. notification_dispatch_log holds no secrets and is granted above.

-- Phase 8 syslog tables (added 2026-09-08). Firewall log CONTENT can be
-- sensitive (internal addressing, usernames in some log types), but it holds
-- no stored credentials, so the standard readonly diagnostic grant applies --
-- same treatment as firewall_rules and device_configs.
GRANT SELECT ON TABLE syslog_events TO claude_readonly;
GRANT SELECT ON TABLE syslog_events TO nocvault_readonly;
GRANT SELECT ON TABLE syslog_rollup_hourly TO claude_readonly;
GRANT SELECT ON TABLE syslog_rollup_hourly TO nocvault_readonly;
GRANT SELECT ON TABLE syslog_rule_hits_hourly TO claude_readonly;
GRANT SELECT ON TABLE syslog_rule_hits_hourly TO nocvault_readonly;
GRANT SELECT ON TABLE syslog_ingest_stats TO claude_readonly;
GRANT SELECT ON TABLE syslog_ingest_stats TO nocvault_readonly;
GRANT SELECT ON TABLE syslog_talker_hourly TO claude_readonly;
GRANT SELECT ON TABLE syslog_talker_hourly TO nocvault_readonly;
GRANT SELECT ON TABLE syslog_app_hourly TO claude_readonly;
GRANT SELECT ON TABLE syslog_app_hourly TO nocvault_readonly;
GRANT SELECT ON TABLE syslog_blocked_dst_hourly TO claude_readonly;
GRANT SELECT ON TABLE syslog_device_inbound_hourly TO claude_readonly;
GRANT SELECT ON TABLE syslog_blocked_dst_hourly TO nocvault_readonly;
GRANT SELECT ON TABLE syslog_device_inbound_hourly TO nocvault_readonly;
GRANT SELECT ON TABLE syslog_country_hourly TO claude_readonly;
GRANT SELECT ON TABLE syslog_country_hourly TO nocvault_readonly;
GRANT SELECT ON TABLE syslog_user_hourly TO claude_readonly;
GRANT SELECT ON TABLE syslog_user_hourly TO nocvault_readonly;
GRANT SELECT ON TABLE syslog_urlcat_hourly TO claude_readonly;
GRANT SELECT ON TABLE syslog_urlcat_hourly TO nocvault_readonly;

-- Phase 8c syslog discovery (2026-09-09). No secret material: observed identity
-- and operator decisions only, the same sensitivity class as `devices`.
GRANT SELECT ON TABLE discovered_devices TO claude_readonly;
GRANT SELECT ON TABLE discovered_devices TO nocvault_readonly;
GRANT SELECT ON TABLE device_syslog_sources TO claude_readonly;
GRANT SELECT ON TABLE device_syslog_sources TO nocvault_readonly;
GRANT SELECT ON TABLE syslog_vpn_auth_hourly TO claude_readonly;
GRANT SELECT ON TABLE syslog_vpn_auth_hourly TO nocvault_readonly;

-- Saved views (2026-09-09, UI redesign Phase 3). No secret material: a view
-- name and a URL query string. user_id is a reference, not credential data.
GRANT SELECT ON TABLE saved_views TO claude_readonly;
GRANT SELECT ON TABLE saved_views TO nocvault_readonly;

-- Hourly threat aggregates (2026-09-09). Counts only, no message text.
GRANT SELECT ON TABLE syslog_threat_hourly TO claude_readonly;
GRANT SELECT ON TABLE syslog_threat_hourly TO nocvault_readonly;

-- Rule change requests (v2.93.0). Operator workflow data, no secret material.
GRANT SELECT ON TABLE rule_change_requests TO claude_readonly;
GRANT SELECT ON TABLE rule_change_requests TO nocvault_readonly;
GRANT SELECT ON TABLE rule_change_request_items TO claude_readonly;
GRANT SELECT ON TABLE rule_change_request_items TO nocvault_readonly;
