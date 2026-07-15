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
