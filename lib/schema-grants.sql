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
--
-- ── Readonly password: PER INSTALL, never hardcoded (2026-10-16) ─────────
-- This file used to carry a hardcoded `PASSWORD` literal, so every
-- SecVault installation in the field was created with the SAME password, and
-- that password was in this git repository. CertVault had already solved this
-- and its own schema-grants.sql names SecVault as the app that had not; this is
-- that mechanism ported across, deliberately unchanged in shape so the two
-- cannot drift.
--
--   $env:PGPASSWORD = <postgres superuser password>           # never on argv
--   $env:SECVAULT_READONLY_PASSWORD = <generated password>    # install only
--   psql -U postgres -d secvault -f lib\schema-grants.sql
--
--   Alternative: -v readonly_password=<pw> wins over the env var.
--   ⛔ that puts the password on the process command line; prefer the env var.
--   Needs psql >= 15 (\getenv, \if :{?var}); the bundled PostgreSQL 16 has it.
--
-- ⛔ IT IS USED ONLY WHEN A ROLE IS CREATED. An operator's later
-- `ALTER ROLE ... PASSWORD` therefore survives every update, and an UPDATE need
-- not supply it at all (the roles already exist, so nothing reads it).
--
-- ⛔ NO PASSWORD SUPPLIED AND THE ROLE IS ABSENT => CREATED `NOLOGIN`, WITH A
-- WARNING. It fails CLOSED. Falling back to a default here would reinstate the
-- exact defect this replaces, and these roles are diagnostic-only -- nothing in
-- the application reads them, so a NOLOGIN role breaks nothing.
--
-- ⛔ THE ROLES ARE CLUSTER-WIDE AND SHARED WITH SIBLING SUITE APPS. If
-- claude_readonly already exists because NetVault or CertVault created it, this
-- file does NOT change its password -- so an installer must not claim to have
-- set one (CertVault staging, 2026-09-29: the roles pre-existed and the printed
-- password had never been applied).
--
-- What still bounds these roles, unchanged:
--   * SELECT-only, granted PER TABLE -- never GRANT ... ON ALL -- with
--     device_credentials, credential_profiles, notification_channels and
--     user_mfa excluded, as are the admin/user password hashes (via the
--     settings_readonly and users_readonly views below). The encrypted secrets
--     are genuinely not reachable through these roles.
--   * A default pg_hba.conf admits only 127.0.0.1/32 and ::1/128. ⛔ That is an
--     accident of the DEFAULT, not a control this file asserts: anyone who
--     widens pg_hba.conf exposes both roles with it.

-- Take the password into a session setting first: psql variables do NOT
-- interpolate inside a DO $$ ... $$ body, so it is parked in a custom GUC and
-- read back with current_setting(). Cleared again at the end of this file.
-- ⛔ Wrapped in a comparison so psql prints t/f, NOT the password itself
-- (set_config RETURNS the new value, and installer output is routinely logged).
\if :{?readonly_password}
\else
\getenv readonly_password SECVAULT_READONLY_PASSWORD
\endif

-- ⛔ psql interpolates :'readonly_password' INTO the statement text, so with
-- log_statement='all' or log_min_duration_statement=0 the password would land in
-- the PostgreSQL SERVER LOG. From here through the DO block below (the only code
-- that reads it; an ERROR there would quote its EXECUTE text -- CREATE ROLE ...
-- PASSWORD -- as CONTEXT) logging is suppressed. All four are SUSET and this
-- file runs as the superuser; they are RESET immediately afterwards.
SET log_statement = 'none';
SET log_min_duration_statement = -1;
SET log_min_error_statement = panic;
SET log_min_messages = panic;
\if :{?readonly_password}
SELECT set_config('secvault.ro_pw', :'readonly_password', false) <> '' AS readonly_password_supplied;
\else
SELECT set_config('secvault.ro_pw', '', false) <> '' AS readonly_password_supplied;
\endif

DO $$
DECLARE
  pw TEXT := current_setting('secvault.ro_pw', true);
  r  TEXT;
BEGIN
  FOREACH r IN ARRAY ARRAY['claude_readonly', 'nocvault_readonly'] LOOP
    IF NOT EXISTS (SELECT 1 FROM pg_roles WHERE rolname = r) THEN
      IF coalesce(pw, '') <> '' THEN
        -- %L quotes the literal safely; DDL cannot take a bind parameter.
        EXECUTE pg_catalog.format('CREATE ROLE %I LOGIN PASSWORD %L', r, pw);
      ELSE
        EXECUTE pg_catalog.format('CREATE ROLE %I NOLOGIN', r);
        RAISE WARNING 'role % created NOLOGIN: no readonly password supplied (ALTER ROLE % LOGIN PASSWORD ... to enable)', r, r;
      END IF;
    END IF;
  END LOOP;
END
$$;
-- End of the password span: server logging back to its configured defaults.
RESET log_min_messages;
RESET log_min_error_statement;
RESET log_min_duration_statement;
RESET log_statement;

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
  SELECT key, value, updated_at FROM settings
   WHERE key NOT IN ('admin_password_hash', 'product_license_key');

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
-- Holds a reason, an owner and an expiry. No secret, so readable like every
-- other finding table.
GRANT SELECT ON TABLE compliance_exceptions TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE device_risk_history TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE fleet_dashboard_snapshots TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE device_connectivity_history TO claude_readonly, nocvault_readonly;
GRANT SELECT ON TABLE activity_log TO claude_readonly, nocvault_readonly;
-- One-shot data-backfill ledger (v2.116.0). Holds no device data and no secrets:
-- a backfill name, a revision and a completion time. Readable so an operator can
-- answer "did that repair actually run here, and when?" without a superuser.
GRANT SELECT ON TABLE data_backfills TO claude_readonly, nocvault_readonly;
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
-- ldap_role_mappings holds no secret: a group DN is not sensitive, and which
-- group maps to which role is exactly what a diagnostic query is for.
GRANT SELECT ON TABLE ldap_role_mappings TO claude_readonly;
GRANT SELECT ON TABLE ldap_role_mappings TO nocvault_readonly;

-- Hourly threat aggregates (2026-09-09). Counts only, no message text.
GRANT SELECT ON TABLE syslog_threat_hourly TO claude_readonly;
GRANT SELECT ON TABLE syslog_threat_hourly TO nocvault_readonly;

-- Rule change requests (v2.93.0). Operator workflow data, no secret material.
GRANT SELECT ON TABLE rule_change_requests TO claude_readonly;
GRANT SELECT ON TABLE rule_change_requests TO nocvault_readonly;
GRANT SELECT ON TABLE rule_change_request_items TO claude_readonly;
GRANT SELECT ON TABLE rule_change_request_items TO nocvault_readonly;

GRANT SELECT ON TABLE background_jobs TO claude_readonly;
GRANT SELECT ON TABLE background_jobs TO nocvault_readonly;

GRANT SELECT ON TABLE vpn_sessions TO claude_readonly;
GRANT SELECT ON TABLE vpn_sessions TO nocvault_readonly;

-- EPSS enrichment columns on `advisories` (2026-09-10, lib/feeds/epss.js).
-- No secret material: a public exploitation probability, its percentile, the
-- model version and two timestamps. `advisories` is already granted above; a
-- table-level GRANT SELECT covers columns added later, but these are re-granted
-- explicitly and idempotently so this file stays the single readable answer to
-- "who can read what", per CLAUDE.md's per-table (never ON ALL TABLES) rule.
GRANT SELECT ON TABLE advisories TO claude_readonly;
GRANT SELECT ON TABLE advisories TO nocvault_readonly;

-- Segmentation intent (v2.113.0). Declared policy only, no secrets.
GRANT SELECT ON TABLE segmentation_intents TO claude_readonly;
GRANT SELECT ON TABLE segmentation_intents TO nocvault_readonly;

-- Application-centric view (v2.124.0). Declared intent only — application
-- names, business owners, and the address/port tuples an application is
-- expected to use. No secret material: nothing here is a credential, and the
-- addresses are the operator's own declarations rather than anything read off
-- a device. Same treatment as segmentation_intents above.
GRANT SELECT ON TABLE applications TO claude_readonly;
GRANT SELECT ON TABLE applications TO nocvault_readonly;
GRANT SELECT ON TABLE application_flows TO claude_readonly;
GRANT SELECT ON TABLE application_flows TO nocvault_readonly;

-- Cloud application catalogue (v2.125.0). Published, public address space from
-- Microsoft/AWS/Google/Cloudflare — nothing here is customer data and nothing
-- is a secret. It is only in the database at all so the product works without
-- reaching the internet on every page view.
GRANT SELECT ON TABLE cloud_app_ranges TO claude_readonly;
GRANT SELECT ON TABLE cloud_app_ranges TO nocvault_readonly;

-- Per-user device scoping (v2.168.0). Holds no secret — a user id, a device id
-- and who granted it — but it IS the authorisation boundary, so it is granted
-- read-only for diagnostics exactly like every other table here and never
-- written by anything but the app.
GRANT SELECT ON TABLE user_device_scopes TO claude_readonly;
GRANT SELECT ON TABLE user_device_scopes TO nocvault_readonly;

-- ⛔ Drop the readonly password out of the session. It was set with
-- is_local=false so it would survive to the DO block above; without this it
-- would stay readable via current_setting() for the rest of the connection.
SELECT set_config('secvault.ro_pw', '', false) = '' AS readonly_password_cleared;
