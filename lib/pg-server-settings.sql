-- lib/pg-server-settings.sql
--
-- PostgreSQL SERVER-level settings that SecVault depends on for diagnosis.
--
-- ⛔ RUN AS THE postgres SUPERUSER, not secvault_user. ALTER SYSTEM is a
-- superuser-only operation, which is exactly why this is a separate file from
-- lib/schema.sql (run as secvault_user by lib/migrate.js) — the same two-file,
-- two-privilege-level split CLAUDE.md already documents for schema-grants.sql.
-- Both installer scripts apply this best-effort on every run; it must never be
-- merged back into schema.sql.
--
-- Every statement here is idempotent: ALTER SYSTEM SET overwrites its own
-- previous value in postgresql.auto.conf, so re-running changes nothing.

-- ─────────────────────────────────────────────────────────────────────────────
-- log_lock_waits
--
-- ⛔ ADDED 2026-09-12 BECAUSE ITS ABSENCE COST A DIAGNOSIS. The collector
-- dropped 324,875 syslog datagrams across two incidents (2026-09-09 16:15 and
-- 2026-09-12 08:02). The flush immediately before each one reported a batch_ms
-- of 290,208 and 228,298 while storing barely 2,000 rows — it was starved, not
-- busy — and PostgreSQL had NOTHING to say about it, because log_lock_waits was
-- off. The cause was eventually found by correlating the collector's own log
-- against ingest stats, which worked but should not have been necessary.
--
-- It only logs a wait that exceeds deadlock_timeout (1s here), so on a healthy
-- server it is silent. That is the point: a line in this log is always worth
-- reading, so it will not be tuned out as noise.
ALTER SYSTEM SET log_lock_waits = on;

-- ⛔ Takes effect without a restart — log_lock_waits is SIGHUP-level. Do NOT
-- replace this with a service restart: restarting PostgreSQL drops every live
-- connection including the collector's, and the collector's in-memory buffer
-- is exactly what we are trying to stop losing.
SELECT pg_reload_conf();
