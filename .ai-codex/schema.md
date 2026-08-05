# SecVault Database Schema — Lookup Index

Source of truth: `lib/schema.sql` (CREATE TABLE IF NOT EXISTS bodies) + `lib/migrate.js` (JS-level
migrations for columns/constraints/indexes that CREATE TABLE IF NOT EXISTS can't retroactively add to
an already-deployed table) + `lib/schema-grants.sql` (readonly roles, applied separately as superuser).
PostgreSQL 16. All PKs are `UUID DEFAULT gen_random_uuid()` except `settings` (TEXT key-value PK).
No `SERIAL` anywhere — a deliberate choice, see "Known schema debt" below.

36 tables total (this count was stale at 28 before 2026-08-02 — several prior features' tables were
never reflected here; corrected while adding this session's 3 new tables). Dense format per table:
```
col_name          TYPE  CONSTRAINTS                    -- notes / FK target
```

---

## Core / device management

### settings
```
key               TEXT PK
value             TEXT
updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
```
Key-value store. `key='admin_password_hash'` holds the bcrypt hash — secret-bearing, see Privilege notes.

### users
```
id                UUID PK DEFAULT gen_random_uuid()
username          TEXT NOT NULL UNIQUE
password_hash     TEXT NOT NULL
role              TEXT NOT NULL DEFAULT 'viewer'        -- 'admin' | 'viewer', no CHECK constraint (app-validated)
created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
```
RBAC identity table, replaces legacy `settings.admin_username`/`admin_password_hash` pair.
`password_hash` is secret-bearing, see Privilege notes.

### devices
```
id                     UUID PK DEFAULT gen_random_uuid()
name                   TEXT NOT NULL
vendor                 TEXT NOT NULL DEFAULT 'forcepoint'
mgmt_method            TEXT NOT NULL DEFAULT 'smc'       -- 'api' | 'ssh' | 'smc' | 'file' (comment lists 'file' — not seen used anywhere in CLAUDE.md's vendor table)
mgmt_ip                TEXT
mgmt_port              INTEGER                            -- ALTER'd in; NULL = per-adapter default (443 api/22 ssh/8082 smc)
smc_host               TEXT
smc_port               INTEGER DEFAULT 8082
allow_self_signed_ssl  BOOLEAN NOT NULL DEFAULT true
site                   TEXT
asset_criticality      TEXT NOT NULL DEFAULT 'medium'    -- 'low'|'medium'|'high'|'critical'
active                 BOOLEAN NOT NULL DEFAULT true
last_connectivity_ok        BOOLEAN
last_connectivity_checked_at TIMESTAMPTZ
last_collected_at      TIMESTAMPTZ
snmp_enabled           BOOLEAN NOT NULL DEFAULT false    -- ALTER'd in (SNMP Phase 1)
snmp_host              TEXT                               -- ALTER'd in; REQUIRED override for forcepoint (smc_host is the SMC, not the engine)
snmp_port              INTEGER NOT NULL DEFAULT 161       -- ALTER'd in
created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
```
No indexes beyond PK.

### device_versions
```
id                UUID PK DEFAULT gen_random_uuid()
device_id         UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
version_string    TEXT NOT NULL
version_tuple     JSONB NOT NULL
build             TEXT
model             TEXT
serial            TEXT                                    -- ALTER'd in 2026-07-19 (Fortinet/Palo Alto SSH parse it, was dropped before storage)
hostname          TEXT                                    -- ALTER'd in 2026-07-23 (device's own reported hostname, distinct from devices.name)
collected_at      TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_device_versions_device_id(device_id)`, `idx_device_versions_collected_at(collected_at)`.
One row per collect (history, not upsert) — "latest" = `ORDER BY collected_at DESC LIMIT 1`.

### device_credentials  ⛔ EXCLUDED from readonly roles (no view either)
```
id                UUID PK DEFAULT gen_random_uuid()
device_id         UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
credential_type   TEXT NOT NULL                          -- 'ssh' | 'rest_api' | 'smc_api' | 'snmp'
encrypted_data    TEXT NOT NULL                            -- AES-256-GCM, credStore.js
iv                TEXT NOT NULL
created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
UNIQUE (device_id, credential_type)                        -- added via DO $$ block, dedup DELETE run first
```
Indexes: `idx_device_credentials_device_id(device_id)`.
`setCredential()` is `INSERT ... ON CONFLICT (device_id, credential_type) DO UPDATE` — atomic under concurrency.

### credential_profiles  ⛔ EXCLUDED from readonly roles (no view either)
```
id                UUID PK DEFAULT gen_random_uuid()
name              TEXT NOT NULL UNIQUE
credential_type   TEXT NOT NULL                           -- 'ssh' | 'rest_api' | 'smc_api' | 'snmp'
username          TEXT                                     -- unencrypted, display-only, NULL for api-key-only profiles
encrypted_data    TEXT NOT NULL
iv                TEXT NOT NULL
created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
```
**No FK to devices/device_credentials** — deliberate. Applying a profile COPIES plaintext into the
target device's `device_credentials` row at that moment (one-time stamp, not a live reference).
credential_type-scoped, NOT vendor-scoped (shared plaintext parsers across vendors sharing a type).

---

## **Config-snapshot tables**

### device_configs
```
id                UUID PK DEFAULT gen_random_uuid()
device_id         UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
config_raw        TEXT                                     -- REDACTED before storage (secrets stripped)
config_parsed     JSONB
collected_at      TIMESTAMPTZ NOT NULL DEFAULT now()
is_baseline       BOOLEAN NOT NULL DEFAULT false           -- added 2026-08-03
```
Indexes: `idx_device_configs_device_id`, `idx_device_configs_collected_at`, and
`idx_device_configs_one_baseline_per_device` — a **partial unique index**
(`ON device_configs(device_id) WHERE is_baseline`) making "at most one baseline per device" a real
DB guarantee rather than app logic (same technique as `idx_compliance_report_log_period_success`).
Setting a baseline must therefore CLEAR the previous one before setting the new one, or the index
rejects the write.
One row per collect (history). "Latest" via `getLatestConfigParsed()` (applicability.js), which
normalizes vendor-specific root shapes (Palo Alto `.tree`, `devices.entry.deviceconfig`) before use.
`is_baseline` marks an operator-designated known-good snapshot; drift ("latest vs baseline") is a
genuinely different question from `config_diffs` ("latest vs previous pull"), because a
consecutive-pull comparison target may itself already be drifted. Drift is computed ON READ from
this flag, not stored — see `pages.md`'s device changes page.
⚠️ Baseline flags a `device_configs` row and NOT a `config_backups` row, because only this table
carries `config_parsed`; `config_backups` stores raw text that would need vendor-specific
re-parsing to diff.

### config_diffs
```
id                   UUID PK DEFAULT gen_random_uuid()
device_id            UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
diff                 JSONB NOT NULL                        -- {added:[{path,value}], removed:[...], modified:[{path,old,new}]}
change_summary       TEXT                                   -- cached one-liner, sanitized (path/value length caps, secret redaction)
detected_at          TIMESTAMPTZ NOT NULL DEFAULT now()
acknowledged_at      TIMESTAMPTZ
acknowledged_by      TEXT                                    -- derived from real session (actor), not client-supplied
acknowledged_note    TEXT                                    -- ALTER'd in 2026-07-20
```
Indexes: `idx_config_diffs_device_id`, `idx_config_diffs_detected_at`.
Secret redaction (`SECRET_PATH_PATTERN`/`deepRedactSecrets()`) + volatile-noise filtering
(`MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR`) applied in `configDiff.js`, both at write time AND via a
retroactive migrate-time cleanup (`cleanupVolatileConfigDiffs`).

### config_backups
```
id                UUID PK DEFAULT gen_random_uuid()
device_id         UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
config_raw        TEXT                                      -- REDACTED (copied verbatim from device_configs)
label             TEXT NOT NULL DEFAULT 'auto'              -- 'auto' | 'manual' | 'pre-change'
backed_up_at      TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_config_backups_device_id`. 'auto' backups only written when a diff is detected.
**Redacted → not restore-to-device capable, diff/audit/reference only.**

---

## Firewall rules / rule-hygiene analysis

### firewall_rules
```
id                UUID PK DEFAULT gen_random_uuid()
device_id         UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
rule_name         TEXT
rule_id_vendor    TEXT                                      -- vendor-native id, nullable, stable across recollects (unlike id)
sequence_number   INTEGER
enabled           BOOLEAN NOT NULL DEFAULT true
action            TEXT                                       -- 'allow'|'deny'|'drop'|'reject' (comment; code also treats 'block' as deny-family)
src_zones         JSONB
dst_zones         JSONB
src_addresses     JSONB
dst_addresses     JSONB
services          JSONB
applications      JSONB
schedule          TEXT
expiry_date       TIMESTAMPTZ
log_enabled       BOOLEAN NOT NULL DEFAULT true
nat_enabled       BOOLEAN NOT NULL DEFAULT false
comment           TEXT
tags              JSONB
hit_count         BIGINT NOT NULL DEFAULT 0
last_hit_at       TIMESTAMPTZ                                -- NEVER populated by any adapter (dead column, ruleAnalysis.js's `unused` check simplified past it 2026-07-19)
bytes_transferred BIGINT NOT NULL DEFAULT 0
collected_at      TIMESTAMPTZ NOT NULL DEFAULT now()
raw_rule          JSONB
vdom              TEXT                                       -- NULL except Fortinet (added 2026-07-30, both transports). See ruleAnalysis.js's isStrictlyEarlier().
```
Indexes: `idx_firewall_rules_device_id`, `idx_firewall_rules_device_seq(device_id, sequence_number)`.
**FULLY DELETE+reinserted on every collect (every 24h by default)** — every downstream table keying
on `firewall_rules.id` inherits this churn (see rule_analysis_results/object_analysis_results below).

### zone_classifications
```
id                UUID PK DEFAULT gen_random_uuid()
device_id         UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
zone_name         TEXT NOT NULL                             -- normalized (lowercase, trimmed) by the writer
role              TEXT NOT NULL                              -- 'internal' | 'external' | 'dmz'
created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
UNIQUE (device_id, zone_name)
```
Indexes: `idx_zone_classifications_device_id` — **created only in `migrate.js`, deliberately NOT in
schema.sql** (a bare CREATE INDEX there broke every upgrading server 2026-07-22 by running before an
upgrading table had `device_id` — see Known schema debt). Operator-supplied only, never auto-inferred;
"no row" = unclassified, never assumed. **PER-DEVICE as of 2026-07-22** — was global (`zone_name TEXT
UNIQUE`, no device_id) for a few hours the same day it first shipped, rebuilt after being reported
unusable (real zone names are per-device VPN/tunnel identifiers, not shared role names).

### network_objects
```
id                UUID PK DEFAULT gen_random_uuid()
device_id         UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
object_type       TEXT NOT NULL                             -- 'address' | 'address_group' | 'service' | 'service_group'
name              TEXT NOT NULL
value             TEXT                                        -- leaf objects only (CIDR/range/fqdn/proto:port); NULL for groups
members           JSONB                                       -- groups only: JSON array of member name strings; NULL for leaf
collected_at      TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_network_objects_device_id`, `idx_network_objects_type(object_type)`.
Optional per-adapter (`getObjects()`) — Sangfor deliberately unimplemented (returns empty catalog).
DELETE+reinsert per device per pull, same lifecycle as `firewall_rules`. No VDOM column (Fortinet:
same-named object across VDOMs collapses to whichever collected last — accepted, documented gap).

### device_interfaces
```
id                UUID PK DEFAULT gen_random_uuid()
device_id         UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
interface_name    TEXT NOT NULL
ip_address        TEXT                                        -- CIDR, e.g. "10.1.1.1/24" -- the interface's OWN address+mask
zone              TEXT
vdom              TEXT                                        -- NULL except Fortinet, same convention as firewall_rules.vdom
enabled           BOOLEAN NOT NULL DEFAULT true
collected_at      TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_device_interfaces_device_id`. Added 2026-08-02 for `lib/engines/topology.js`'s
multi-hop path simulation. Live-snapshot (DELETE+reinsert per pull), optional per-adapter
(`getInterfaces()`) — Phase 1: paloalto/fortinet only, SSH transport only.

### device_routes
```
id                UUID PK DEFAULT gen_random_uuid()
device_id         UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
destination_cidr  TEXT NOT NULL
next_hop_ip       TEXT                                        -- NULL means directly-connected/local -- topology.js's resolveRoute() treats this as "path ends here successfully", never collapse to a real IP
interface_name    TEXT
protocol          TEXT                                        -- 'connected' | 'static' | 'ospf' | 'bgp' | 'rip' | 'other'
metric            INTEGER
vdom              TEXT
collected_at      TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_device_routes_device_id`. Same lifecycle/scope as `device_interfaces`
(`getRoutingTable()`). Host (`/32`, PAN-OS flag `H`) routes are deliberately excluded by the Palo
Alto parser — a route to an interface's own address adds no path-decision value and would
wrongly out-rank real routes as the most-specific longest-prefix match.

### nat_rules
```
id                       UUID PK DEFAULT gen_random_uuid()
device_id                UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
sequence_number          INTEGER
enabled                  BOOLEAN NOT NULL DEFAULT true
nat_type                 TEXT NOT NULL                        -- 'source' | 'destination' | 'static'
original_src_addresses   JSONB
original_dst_addresses   JSONB
original_services        JSONB
translated_src_addresses JSONB
translated_dst_addresses JSONB
translated_services      JSONB
collected_at             TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_nat_rules_device_id`. `original_*`/`translated_*` columns use the EXACT SAME shape as
`firewall_rules.src_addresses` etc (JSONB array of literal IPs or object names) — deliberate, so
`lib/engines/objectResolver.js`'s `resolveAddressField()`/`matchesAddress()` work UNCHANGED against
these rows, zero new address-matching logic for NAT. `firewall_rules.nat_enabled` has ALWAYS been a
hardcoded schema default (`DEFAULT false`, never vendor-derived) until this table — real NAT data.
Optional per-adapter (`getNatRules()`) — implemented for both Palo Alto (separate ordered NAT
rulebase) and Fortinet (added 2026-08-02, derived from per-policy `nat enable` + VIP objects — see
`lib.md`'s `topology.js` entry for the SD-WAN-interface `natUnresolved` case).

---

### device_licenses
```
id           UUID PK DEFAULT gen_random_uuid()
device_id    UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
feature      TEXT NOT NULL                          -- 'Threat Prevention', 'Premium', 'Standard', ...
description  TEXT
serial       TEXT
issued_at    DATE
expires_at   DATE                                   -- see tri-state note below
expires_raw  TEXT                                   -- the vendor's own string, verbatim
expired      BOOLEAN                                -- the DEVICE's own verdict; NULL = not reported
authcode     TEXT
raw          JSONB
collected_at TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_device_licenses_device_id`, `idx_device_licenses_expires_at`. Added 2026-08-03.
Latest-snapshot (DELETE+reinsert per device, same lifecycle as `device_interfaces`), 1-to-many —
a real PA-440 reports ~11 entitlements including the SUPPORT contract ('Premium' = 24x7
advance-replacement, 'Standard' = 10x5), which is the fleet renewal-planning input.
⛔ **`expires_at` is TRI-STATE with `expires_raw`**: non-null date = real expiry; NULL +
`expires_raw='Never'` = genuinely perpetual; NULL + any other raw = the vendor string did not parse
and expiry is UNKNOWN. Never collapse the last two — `lib/engines/deviceHealth.js`'s
`licenseStatus()` depends on the distinction, and treating an unparsed expiry as "fine" is exactly
how a support contract lapses unnoticed. Optional per-adapter (`getLicenses()`), Palo Alto both
transports only.

### device_ha_status
```
id                        UUID PK DEFAULT gen_random_uuid()
device_id                 UUID NOT NULL UNIQUE — FK -> devices(id) ON DELETE CASCADE
enabled                   BOOLEAN NOT NULL
mode                      TEXT                     -- 'Active-Passive'
group_id                  TEXT
local_state               TEXT                     -- 'active' | 'passive' | vendor string
peer_state                TEXT
peer_mgmt_ip              TEXT                     -- bare IP, mask stripped
peer_serial               TEXT
peer_connection_status    TEXT                     -- 'up' | 'down' | ...
config_sync_state         TEXT                     -- 'synchronized' | ...
last_nonfunctional_reason TEXT                     -- fault reasons ONLY (see note)
version_compat_ok         BOOLEAN                  -- tri-state, see note
version_compat            JSONB                    -- per-component Match/Mismatch map
raw                       JSONB
collected_at              TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_device_ha_status_device_id`. Added 2026-08-03. **UNIQUE(device_id) — exactly one row
per device, written via UPSERT** (not DELETE+reinsert like its siblings). A standalone device gets
`enabled=false` stored, so "standalone" is a positively-collected fact rather than being
indistinguishable from "never collected" — the adapter returns `null` (and nothing is written) only
when the command could not run at all.
⛔ `version_compat_ok` is TRI-STATE: `true` = every component the device compared reported Match;
`false` = at least one Mismatch; `NULL` = the device reported no compatibility block at all. Never
default NULL to true.
⛔ `last_nonfunctional_reason` holds only GENUINE fault reasons (live: `'Link down'`). PAN-OS also
reports `Last suspended state reason: User requested` — a deliberate admin action on an otherwise
healthy pair — which the parser deliberately keeps OUT of this column (it goes to `raw`) so it can
never read as a fault. Live fleet: 6 of 11 Palo Altos are Active-Passive pairs.

### device_disk_usage
```
id           UUID PK DEFAULT gen_random_uuid()
device_id    UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
filesystem   TEXT NOT NULL                          -- '/dev/mmcblk0p8'
mounted_on   TEXT                                   -- '/opt/panlogs'
size_raw     TEXT                                   -- '22G' — the device's own human string
used_raw     TEXT
avail_raw    TEXT
use_percent  INTEGER                                -- 0-100, NULL when unparseable
collected_at TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_device_disk_usage_device_id`. Added 2026-08-03. Latest-snapshot, 1-to-many (7-9
filesystems per device). Sizes are deliberately NOT parsed to bytes: `df -h`'s rounded units would
make a byte figure falsely precise, while `use_percent` — which is what the UI bands on — is
already exact. Sourced from the management API/CLI (`show system disk-space`), NOT SNMP, so it
carries none of `snmp_metric_snapshots`' `lowConfidence` caveat.

### device_content_versions
```
id           UUID PK DEFAULT gen_random_uuid()
device_id    UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
component    TEXT NOT NULL   -- 'app'|'av'|'threat'|'wildfire'|'url_filtering'|'device_dictionary'
version      TEXT
released_at  TIMESTAMPTZ     -- NULL when the device reports none/unparseable
raw          JSONB
collected_at TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_device_content_versions_device_id`. Added 2026-08-03. **No extra device command is
issued** — these come from the `show system info` response `getVersion()` already fetches, via
`getVersion()`'s new `contentVersions` return field. Previously these landed only as opaque keys
inside `device_configs.config_parsed.system_info` and were never queryable. `url_filtering` has a
version but no release-date field on PAN-OS; its `released_at` stays NULL rather than being
inferred from the date-looking version string.

---

## **Rule-analysis / finding tables**

### rule_analysis_results
```
id                UUID PK DEFAULT gen_random_uuid()
device_id         UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
rule_id           UUID NOT NULL — FK -> firewall_rules(id) ON DELETE CASCADE
finding_type      TEXT NOT NULL   -- 'unused'|'shadow'|'redundant'|'correlation'|'generalization'|'any_any'|
                                   -- 'risky_service'|'reorder_candidate'|'expiring_soon'|'log_disabled'|
                                   -- 'overly_permissive'|'external_exposure'  (12 types)
severity          TEXT NOT NULL DEFAULT 'info'               -- 'critical'|'high'|'medium'|'info'
detail            TEXT
affected_rule_ids JSONB NOT NULL DEFAULT '[]'::jsonb          -- NOT a real FK array (Postgres has none) — names OTHER rule ids
remediation       TEXT
analyzed_at       TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_rar_device_id`, `idx_rar_finding_type`, `idx_rar_severity`.
DELETE+reinsert per device per analysis run (inside a transaction, `pg_advisory_xact_lock` guarded
against concurrent runs for the same device). `rule_id` cascades from `firewall_rules`, which itself
rewrites every 24h — analysis always reruns immediately after, so this stays consistent.

### finding_acknowledgements
```
id                UUID PK DEFAULT gen_random_uuid()
device_id         UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
rule_id_vendor    TEXT NOT NULL                              -- NOT firewall_rules.id — see below
finding_type      TEXT NOT NULL
status            TEXT NOT NULL DEFAULT 'new'                -- 'new'|'acknowledged'|'dismissed'|'actioned'
note              TEXT
updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
UNIQUE (device_id, rule_id_vendor, finding_type)
```
Indexes: `idx_fa_device_id`.
**Deliberately keyed on `rule_id_vendor` (vendor-native id), NOT `firewall_rules.id`/
`rule_analysis_results.id`** — both are fully DELETE+reinserted every pull/run, so a UUID FK would
silently lose every ack on the next scheduled collect. Rows with NULL `rule_id_vendor` (degraded/
unparseable rules on some adapters) simply have no ack UI — Postgres treats multiple NULLs as distinct
under UNIQUE, so this can't be relied on anyway.

### object_analysis_results
```
id                  UUID PK DEFAULT gen_random_uuid()
device_id           UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
object_id           UUID NOT NULL — FK -> network_objects(id) ON DELETE CASCADE
finding_type        TEXT NOT NULL                            -- 'unused' | 'duplicate'
detail              TEXT
related_object_ids  JSONB NOT NULL DEFAULT '[]'::jsonb         -- 'duplicate': other object id(s) sharing the same value; not a real FK array
analyzed_at         TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_oar_device_id`, `idx_oar_finding_type`. Mirrors `rule_analysis_results`' lifecycle exactly.

### audit_findings (compliance — Phase 7)
```
id                UUID PK DEFAULT gen_random_uuid()
device_id         UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
check_id          UUID NOT NULL — FK -> audit_checks(id) ON DELETE CASCADE
status            TEXT NOT NULL                              -- 'pass' | 'fail' | 'warning' | 'na'
detail            TEXT
matched_rule_ids  UUID[]                                       -- ALTER'd in 2026-07-18 (see Known schema debt); rule_scan checks only, NULL otherwise; not FK-on-array-element
detected_at       TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_audit_findings_device_id`, `idx_audit_findings_check_id`, `idx_audit_findings_status`.
DELETE+reinsert per device per compliance run (scheduled after config pull, or on-demand). Unlike
`rule_analysis_results.rule_id`, `check_id` FK is safe as a stable UUID — `audit_checks` is curated
library data, not rewritten per pull.

### audit_checks (compliance check library — curated, not per-device)
```
id                     UUID PK DEFAULT gen_random_uuid()
check_id               TEXT NOT NULL UNIQUE                   -- stable slug e.g. 'fortinet-ssl-vpn-not-internet-exposed'
name                   TEXT NOT NULL
description            TEXT
standards              TEXT[] NOT NULL                         -- subset of 'PCI_DSS'|'ISO_27001'|'CIS_V8'|'NIST'|'SANS'|'CUSTOM'
vendor                 TEXT                                     -- NULL = all vendors
severity               TEXT NOT NULL DEFAULT 'medium'          -- 'critical'|'high'|'medium'|'low'|'info'
predicate_config       JSONB NOT NULL                           -- {predicate_type, ...}; predicate_type='rule_scan' is evaluated by configAuditor.js directly against rule_analysis_results, not applicability.js
remediation_guidance   TEXT
created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
updated_at             TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_audit_checks_vendor`, `idx_audit_checks_standards` (GIN on `standards`).
Seeded via `lib/auditChecksSeed.js`'s `seedAuditChecks()`, called UNGUARDED from `migrate.js` `main()`
(a seed failure fails the whole migrate run loudly — unlike every other best-effort migration below it).

---

## **CVE / advisory tables**

### advisories
```
id                       UUID PK DEFAULT gen_random_uuid()
cve_id                   TEXT NOT NULL UNIQUE
vendor                   TEXT NOT NULL                        -- ownership guard: cross-vendor cve_id collisions keep whichever vendor ingested first
title                    TEXT
description              TEXT
cvss_score               NUMERIC(3,1)
cvss_vector              TEXT
kev_listed               BOOLEAN NOT NULL DEFAULT false
kev_date                 TIMESTAMPTZ
published_at             TIMESTAMPTZ
affected_version_ranges  JSONB NOT NULL DEFAULT '[]'::jsonb     -- vendor-owned column, CASE-guarded on upsert
fixed_in_versions        JSONB NOT NULL DEFAULT '[]'::jsonb     -- vendor-owned column, CASE-guarded on upsert
advisory_url             TEXT
raw_data                 JSONB
cwe_ids                  TEXT[]                                 -- ALTER'd in (Dashboard Rebuild); CWE ids e.g. 'CWE-78'
vulnerability_category   TEXT                                    -- ALTER'd in; derived coarse category (RCE/PRIV_ESC/INFO_DISCLOSURE/DOS/Other)
created_at               TIMESTAMPTZ NOT NULL DEFAULT now()
updated_at               TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_advisories_vendor`, `idx_advisories_kev_listed`, `idx_advisories_cvss_score`,
`idx_advisories_published_at`, `idx_advisories_vulnerability_category`.
⚠️ Comment drift: no CHECK/comment on `vendor`, but note the 2026-07-19 fix made EVERY non-neutral
column (not just title/ranges) vendor-ownership-guarded via `CASE WHEN advisories.vendor = EXCLUDED.vendor`.

### advisory_conditions
```
id                     UUID PK DEFAULT gen_random_uuid()
advisory_id            UUID NOT NULL — FK -> advisories(id) ON DELETE CASCADE
vendor                 TEXT NOT NULL
condition_description  TEXT
predicate_type         TEXT       -- 'config_key_exists'|'config_value_equals'|'config_value_matches'|'feature_enabled'|'port_exposed'|'admin_access_from_zone'
predicate_config       JSONB
created_at             TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_advisory_conditions_advisory_id`. Curated data (admin UI CRUD), not code — no
`config_applies` tri-state row here for an advisory means `'unknown'`, never `'no'`.

### device_cve_assessments
```
id                    UUID PK DEFAULT gen_random_uuid()
device_id             UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
advisory_id           UUID NOT NULL — FK -> advisories(id) ON DELETE CASCADE
version_affected      BOOLEAN NOT NULL DEFAULT false
config_applies        VARCHAR(10) NOT NULL DEFAULT 'unknown'    -- 'yes'|'no'|'unknown'
kev_listed             BOOLEAN NOT NULL DEFAULT false
log_hit                BOOLEAN NOT NULL DEFAULT false
priority_band          VARCHAR(20) NOT NULL DEFAULT 'monitor'    -- 'patch_now'|'scheduled'|'monitor'
fixed_in                TEXT
is_fixed_recommended   BOOLEAN NOT NULL DEFAULT false
assessed_at            TIMESTAMPTZ NOT NULL DEFAULT now()
next_check_at          TIMESTAMPTZ
UNIQUE (device_id, advisory_id)
```
Indexes: `idx_dca_device_id`, `idx_dca_advisory_id`, `idx_dca_priority_band`.
UPSERT (`ON CONFLICT DO UPDATE`), not delete+reinsert — write phase wrapped in
`pg_advisory_xact_lock(hashtext(device_id))` to prevent concurrent-run staleness resurrecting a
patched CVE (3 independent call sites can race: Assess Now, scheduled sync, config-change re-match).
No ack column of its own — see `cve_assessment_acknowledgements` below.

### cve_assessment_acknowledgements
```
id                UUID PK DEFAULT gen_random_uuid()
device_id         UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
advisory_id       UUID NOT NULL — FK -> advisories(id) ON DELETE CASCADE
status            TEXT NOT NULL DEFAULT 'new'                  -- 'new'|'acknowledged'|'dismissed'|'actioned'
note              TEXT
updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
UNIQUE (device_id, advisory_id)
```
Indexes: `idx_caa_device_id`. Mirrors `finding_acknowledgements` but keyed on real FK pair (safe here
since `device_cve_assessments` UPSERTs on the identical `(device_id, advisory_id)` natural key rather
than delete+reinsert).

### vendor_recommended_releases
```
id                UUID PK DEFAULT gen_random_uuid()
vendor            TEXT NOT NULL
product_line      TEXT
version           TEXT NOT NULL
version_tuple     JSONB NOT NULL
is_recommended    BOOLEAN NOT NULL DEFAULT false
is_stable         BOOLEAN NOT NULL DEFAULT false
as_of_date        DATE
notes             TEXT
created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_vrr_vendor`. Manually-maintained curated table (no adapter/feed writes here).

---

## Fleet dashboard / trend / monitoring / audit-trail tables

### device_risk_history
```
id                UUID PK DEFAULT gen_random_uuid()
device_id         UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
score             INTEGER NOT NULL
band              TEXT NOT NULL                               -- 'low'|'medium'|'high'|'critical'
recorded_at       TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_drh_device_id`, `idx_drh_recorded_at`. Snapshotted from inside
`runAnalysisForDevice()` (covers both scheduled collect and manual "Run Analysis").

### fleet_dashboard_snapshots
`device_connectivity_history` — append-only fleet reachability log (added 2026-08-05, v2.54.0): device_id, reachable, latency_ms, source ('test'|'collect'|'metrics'), message, checked_at. ⛔ Replaces nothing — `devices.last_connectivity_ok` remains, but it is a SINGLE value overwritten in place and written only by the manual test button, so it carries no history. ⛔ No new device load: rows come only from work that already contacted the device. Retention via the daily [snapshot-retention] job (SNMP_VPN_RETENTION_DAYS). Readonly grants present. Written by `lib/engines/connectivityHistory.js`.
`fleet_dashboard_snapshots` gained headline columns in v2.53.0 (device_count, devices_online, rules_total, rules_enabled, patch_now_count, high_risk_count, security_score) — all NULLABLE with NO default, added via ALTER TABLE ... ADD COLUMN IF NOT EXISTS; a 0 default would render as a confident "0 devices yesterday" delta.
```
id                          UUID PK DEFAULT gen_random_uuid()
snapshot_date               DATE NOT NULL UNIQUE
cve_critical                INTEGER NOT NULL DEFAULT 0
cve_high                    INTEGER NOT NULL DEFAULT 0
cve_medium                  INTEGER NOT NULL DEFAULT 0
cve_low                     INTEGER NOT NULL DEFAULT 0
compliance_overall_score    INTEGER                             -- nullable; null = nothing measurable, never coerced to 0
compliance_by_standard      JSONB NOT NULL DEFAULT '{}'::jsonb    -- {STANDARD_KEY: scorePct|null}
recorded_at                 TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_fds_snapshot_date`. One row/calendar day, `ON CONFLICT (snapshot_date) DO UPDATE`
(idempotent same-day reruns). Populated by daily engine-worker cron job (`10 0 * * *`).

### vpn_session_snapshots
```
id                      UUID PK DEFAULT gen_random_uuid()
device_id               UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
active_session_count    INTEGER NOT NULL                        -- only successful polls insert a row
raw                     JSONB
sampled_at              TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_vss_device_id`, `idx_vss_sampled_at`. Daily `[snapshot-retention]` cron job (`30 0 * * *`,
`runSnapshotRetentionJob()` in `services/engine-worker.js`) deletes rows older than
`SNMP_VPN_RETENTION_DAYS` (default 180d).

### vpn_active_sessions
```
id                UUID PK DEFAULT gen_random_uuid()
device_id         UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
username          TEXT
tunnel_type       TEXT
source_ip         TEXT
assigned_ip       TEXT
login_time        TEXT        -- device's raw string, not parsed to timestamptz (per-vendor tz fragility)
duration_seconds  BIGINT
bytes_in          BIGINT
bytes_out         BIGINT
client            TEXT
gateway           TEXT
raw               JSONB
collected_at      TIMESTAMPTZ NOT NULL DEFAULT now()
```
Index: `idx_vas_device_id`. LIVE per-user snapshot (one row per connected VPN user), DELETE+reinsert per successful poll — NO history, no retention. Added 2026-07-31. The per-user detail the management-plane commands already return (Palo Alto `show global-protect-gateway current-user`, Fortinet `get vpn ssl monitor`, Cisco ASA `show vpn-sessiondb anyconnect`), NOT syslog. Written by `lib/engines/vpnSessions.js` `storeVpnSessions()` from `getVpnSessionSummary().sessions`. GRANT SELECT to both readonly roles (no secrets — session metadata).

### vpn_ipsec_tunnels
```
id           UUID PK DEFAULT gen_random_uuid()
device_id    UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
name         TEXT
peer         TEXT
status       TEXT        -- normalized 'up'/'down' where derivable, else raw
ike_version  TEXT        -- 'IKEv1'/'IKEv2'/null
bytes_in     BIGINT
bytes_out    BIGINT
raw          JSONB
collected_at TIMESTAMPTZ NOT NULL DEFAULT now()
```
Index: `idx_vit_device_id`. LIVE IPSec site-to-site tunnel snapshot (DELETE+reinsert per successful poll, no history). Added 2026-07-31. From the NEW optional adapter method `getVpnTunnels()`: Palo Alto `show vpn ipsec-sa`, Fortinet `diagnose vpn tunnel list` / `/api/v2/monitor/vpn/ipsec`, Cisco ASA `show vpn-sessiondb l2l`. Written by `lib/engines/vpnTunnels.js` `storeVpnTunnels()`. GRANT SELECT to both readonly roles.

### snmp_metric_snapshots
```
id                UUID PK DEFAULT gen_random_uuid()
device_id         UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
cpu_percent       NUMERIC(5,2)                                  -- nullable, unlike vpn's NOT NULL — partial polls keep what they got
memory_percent    NUMERIC(5,2)
session_count     INTEGER
uptime_seconds    BIGINT
raw               JSONB
sampled_at        TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_sms_device_id`, `idx_sms_sampled_at`. All six Tier-1 vendors implement `getSnmpMetrics`
(generic MIB-II/HOST-RESOURCES-MIB only, no vendor MIB) — see `.ai-codex/connectors.md`'s per-vendor
entries for confidence-level caveats. Same daily `[snapshot-retention]` cron job as
`vpn_session_snapshots` above (`30 0 * * *`), deletes rows older than `SNMP_VPN_RETENTION_DAYS`
(default 180d).

### activity_log
```
id                UUID PK DEFAULT gen_random_uuid()
actor             TEXT NOT NULL DEFAULT 'unknown'
action            TEXT NOT NULL
device_id         UUID — FK -> devices(id) ON DELETE CASCADE     -- nullable: not every action is device-scoped
detail            TEXT
occurred_at       TIMESTAMPTZ NOT NULL DEFAULT now()
```
Indexes: `idx_al_device_id`, `idx_al_occurred_at`. NOT a general app log — only HTTP-route-triggered
operator actions via `lib/activityLog.js`'s `logActivity()` (never throws).

### feed_sync_log
```
id                UUID PK DEFAULT gen_random_uuid()
feed_name         TEXT NOT NULL              -- comment says 'nvd'|'kev' ONLY — STALE, see CLAUDE.md contradictions below
status            TEXT NOT NULL              -- 'success'|'error'|'partial'
inserted          INTEGER NOT NULL DEFAULT 0
updated           INTEGER NOT NULL DEFAULT 0
errors            JSONB
duration_ms       INTEGER
started_at        TIMESTAMPTZ NOT NULL DEFAULT now()
finished_at       TIMESTAMPTZ
```
Indexes: `idx_feed_sync_log_feed_name`, `idx_feed_sync_log_started_at`.

### notification_channels  ⛔ EXCLUDED from readonly roles (no view either)
```
id                UUID PK DEFAULT gen_random_uuid()
name              TEXT NOT NULL UNIQUE
channel_type      TEXT NOT NULL                           -- 'slack_webhook' | 'teams_webhook' | 'email' | 'generic_webhook'
enabled           BOOLEAN NOT NULL DEFAULT true
alert_types       TEXT[] NOT NULL DEFAULT ARRAY['patch_now_cve','compliance_critical','config_diff']
config            JSONB NOT NULL DEFAULT '{}'::jsonb      -- non-secret target info (email host/port/from/to); {} for webhook types
encrypted_data    TEXT NOT NULL                            -- webhook URL, or SMTP password for email
iv                TEXT NOT NULL
last_success_at   TIMESTAMPTZ
last_error        TEXT
last_error_at     TIMESTAMPTZ
created_at        TIMESTAMPTZ NOT NULL DEFAULT now()
updated_at        TIMESTAMPTZ NOT NULL DEFAULT now()
```
Added 2026-08-01. Mirrors `credential_profiles` above (not device-scoped, same encrypted_data/iv
shape via `credStore.js`'s exported `encrypt`/`decrypt`). `alert_types` is a routing filter (array,
not a join table — same tradeoff `audit_checks.standards` makes). `last_success_at`/`last_error`/
`last_error_at` are populated by `lib/notificationChannels.js`'s `recordChannelSuccess`/
`recordChannelError` on every dispatch attempt (see `notification_dispatch_log` below) — a silently-
failing channel would defeat this feature's purpose, so failures are visible, not just logged.

### notification_dispatch_log
```
id                UUID PK DEFAULT gen_random_uuid()
alert_type        TEXT NOT NULL              -- 'patch_now_cve' | 'compliance_critical' | 'config_diff'
natural_key       TEXT NOT NULL              -- 'device_id:advisory_id' | 'device_id:check_id' | config_diffs.id
device_id         UUID NOT NULL — FK -> devices(id) ON DELETE CASCADE
dispatched_at     TIMESTAMPTZ NOT NULL DEFAULT now()
cleared_at        TIMESTAMPTZ                -- NULL = currently open + already notified; set = eligible to re-notify
```
Added 2026-08-01. Indexes: `idx_ndl_device_id`, `idx_ndl_alert_type_cleared`. `UNIQUE(alert_type,
natural_key)`. Dedup ledger for `lib/engines/notificationDispatch.js`'s poll job. `cleared_at` (rows
are never deleted) is the load-bearing design choice here: a plain one-time row would permanently
suppress a genuine re-occurrence (a compliance check failing, getting fixed, then failing again) —
see that file's own header comment for the full reconcile-then-claim algorithm. `natural_key`'s
shape differs per alert_type specifically because each source table has different churn semantics:
`device_cve_assessments` is upserted in place, `audit_findings` is fully DELETE+reinserted every
compliance run (`check_id` is the only stable identity across that churn), `config_diffs` is
append-only (its own `id` is already stable).

### compliance_report_log
```
id                UUID PK DEFAULT gen_random_uuid()
period            TEXT NOT NULL              -- 'YYYY-MM'
status            TEXT NOT NULL              -- 'success' | 'error'
recipient_count   INTEGER NOT NULL DEFAULT 0
error             TEXT
started_at        TIMESTAMPTZ NOT NULL DEFAULT now()
finished_at       TIMESTAMPTZ
```
Added 2026-08-02. Indexes: `idx_compliance_report_log_period` (plain), plus a **partial unique
index** `idx_compliance_report_log_period_success` on `(period) WHERE status='success'` — the
load-bearing constraint, not the plain index. Only one `'success'` row can ever exist per
calendar month, but unlimited `'error'` rows can accumulate — a transient SMTP failure must be
retryable within the same month, never a permanent block, but a real DB constraint is required
(not just an app-level check) because `runComplianceReportJob()` runs both on its monthly cron
tick AND once immediately at every `SecVault-Engine` startup, and the service restarts on every
deploy. Written by `lib/engines/complianceReport.js`'s `dispatchMonthlyReport()` — the single
shared code path both the scheduled job and `POST /api/compliance/report/generate` call, so
`status='success'` requires at least one `notification_channels` row to have actually received
the report (if every matching channel's send fails, this logs `'error'` with
`recipient_count=0` instead, specifically so the unique index doesn't block a same-month retry).

---

## Known schema debt

- **`CREATE TABLE IF NOT EXISTS` is a no-op on an existing table — it never adds a column.** This
  codebase has been bitten by this repeatedly and now treats it as a standing discipline, not a
  one-time fix: every column added to an already-shipped table needs a companion
  `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` (schema.sql keeps both the CREATE TABLE body version AND
  the ALTER, for fresh installs vs. upgrades respectively). Confirmed past incidents still visible in
  the current schema.sql comments: `audit_findings.matched_rule_ids` (2026-07-18, crashed the
  per-device Compliance page on every already-deployed server), `device_versions.serial` (2026-07-19),
  `advisories.cwe_ids`/`vulnerability_category`, `config_diffs.acknowledged_note`,
  `devices.mgmt_port`/`snmp_enabled`/`snmp_host`/`snmp_port`. This is a live, ongoing risk for any
  future column addition, not fully-closed history.
- **A companion `CREATE INDEX`/constraint change for a column added to an EXISTING table must live in
  the JS migration, not schema.sql.** `zone_classifications` is the concrete incident: a bare
  `CREATE INDEX ... (device_id)` in schema.sql ran (via `runSchema()`) BEFORE `migrate.js`'s
  `migrateZoneClassificationsToPerDevice()` ever got a chance to add that column to an
  already-deployed table — aborted the ENTIRE `runSchema()` call (not just this one table) on every
  server that had installed the table's original global shape. Fixed by moving the index creation into
  the JS migration itself, sequenced after the `ALTER TABLE ADD COLUMN`. `zone_classifications` also
  carries a second, narrower incident: an earlier revision of the same migration function checked for
  the wrong auto-generated UNIQUE-constraint name (`zone_classifications_device_zone_key` instead of
  Postgres's real default, `zone_classifications_device_id_zone_name_key`), leaving a redundant,
  wrongly-named duplicate constraint on any server that installed during roughly a 23-minute window —
  `migrate.js` now `DROP CONSTRAINT IF EXISTS`s both names defensively.
- **`zone_classifications` global → per-device migration history.** Shipped global (`zone_name TEXT
  UNIQUE`) first, found unusable within hours (real fleet zone names are per-device VPN/tunnel
  identifiers, not shared role names — a flat fleet-wide list mixed every device's zones with no way
  to tell which firewall each belonged to), rebuilt per-device the same day. Any pre-existing
  global-scoped row is unconditionally discarded (`device_id IS NULL` rows deleted) rather than
  migrated — there's no way to attribute a legacy zone_name row to a specific device, and every row on
  the one deployment checked was still "Unclassified" at the time.
- **`firewall_rules.vdom` fixed 2026-07-30; `network_objects` still has the identical gap, not
  fixed.** `ruleAnalysis.js`'s shadow/redundant/correlation/generalization/reorder_candidate analysis
  now partitions by `(device_id, vdom)` via `isStrictlyEarlier()`, closing the false-positive-
  across-Fortinet-VDOMs bug. `network_objects` has no `vdom` column and no equivalent engine fix — a
  same-named object collected from two different VDOMs on the same device still silently collapses
  to whichever was inserted last. Real, separate, still-open debt — fixing it needs both a schema
  change AND fixing whatever downstream name-based object resolution (`objectUsage.js`,
  `reachabilityMatrix.js`) currently assumes one name = one object per device.
- **`finding_acknowledgements` is keyed on `(device_id, rule_id_vendor, finding_type)`, a natural key,
  not a UUID FK to `firewall_rules.id`/`rule_analysis_results.id`.** Deliberate: both parent tables are
  fully DELETE+reinserted on every pull/run (`firewall_rules` every 24h collect, `rule_analysis_results`
  every analysis run) — a UUID FK would silently orphan/lose every acknowledgement on the very next
  scheduled collect. Rows with `rule_id_vendor IS NULL` (a handful of degraded/unparseable rule shapes
  across adapters) simply can't be acknowledged — the UI omits the control rather than accept an
  ambiguous NULL-keyed row (Postgres UNIQUE treats multiple NULLs as distinct, so it wouldn't even
  enforce uniqueness there anyway).
- **`credential_profiles` has no FK to `devices`/`device_credentials`, by design.** Applying a profile
  COPIES its decrypted plaintext into the target device's own `device_credentials` row at that moment —
  a one-time stamp, not a live reference. Renaming/rotating/deleting a profile afterward never touches
  any device that already used it. Worth knowing before assuming a rename would cascade anywhere — it
  won't, on purpose.
- **Several JSONB "id array" columns are not real foreign keys** (Postgres has no FK-on-array-element):
  `rule_analysis_results.affected_rule_ids`, `object_analysis_results.related_object_ids`,
  `audit_findings.matched_rule_ids`. Safe in practice only because every table these reference into is
  itself fully DELETE+reinserted on the same cadence, so a stale id just resolves to zero rows on the
  next JOIN rather than a dangling/broken reference — this safety property would NOT hold if any of
  these referenced tables' rewrite lifecycle ever changed to incremental upsert.
- **No enum/CHECK constraints anywhere on the many text "enum-like" columns** (`devices.vendor`,
  `mgmt_method`, `asset_criticality`; `users.role`; `firewall_rules.action`;
  `rule_analysis_results.finding_type`/`severity`; `audit_findings.status`;
  `finding_acknowledgements.status`; `device_cve_assessments.config_applies`/`priority_band`;
  `credential_profiles`/`device_credentials.credential_type`, etc.) — every one is validated in
  application code only, by deliberate, stated convention. A hand-edited or buggy-migration row can
  silently carry an unrecognized value with the DB raising nothing.
- **SERIAL vs UUID was never a SecVault problem** — every table uses `UUID DEFAULT gen_random_uuid()`
  PKs from the start (the one exception, `settings.key TEXT PK`, is a deliberate key-value design, not
  an oversight). CLAUDE.md references this as a NetVault schema-debt issue this codebase intentionally
  avoided repeating — not itself current SecVault debt, included here only for context since it's the
  kind of thing this file's own history flags prominently.
- **`devices.mgmt_method` comment lists `'file'` as a valid value** alongside `'api'|'ssh'|'smc'`, but
  no vendor/adapter dispatch table anywhere in CLAUDE.md's "Supported Vendors" section references a
  `'file'` method — likely vestigial from an early design, not confirmed dead code but worth a second
  look before assuming it's reachable.

## Privilege notes

Applied by `lib/schema-grants.sql`, run separately under the `postgres` superuser (never by
`secvault_user`/`migrate.js` — `CREATE ROLE` needs `CREATEROLE`/superuser, which `secvault_user`
lacks). Two roles: `claude_readonly`, `nocvault_readonly` — always granted identically, in lockstep.

**Excluded entirely — no `GRANT SELECT`, no readonly view either:**
- `device_credentials` — the original, foundational exclusion (encrypted SSH/API/SMC/SNMP secrets).
- `credential_profiles` — same encrypted `encrypted_data`/`iv` shape as `device_credentials`; the one
  non-secret column (`username`) isn't judged worth carving a view out for.

**Base table REVOKE'd + a readonly VIEW granted instead** (secret-bearing column(s) excluded from the
view; `REVOKE` issued explicitly every run, not just an omitted `GRANT`, since this file re-applies on
every update and only `REVOKE` undoes a privilege a previous run already granted on a live DB):
- `settings` → `settings_readonly` view (`SELECT key, value, updated_at ... WHERE key <> 'admin_password_hash'`)
- `users` → `users_readonly` view (`SELECT id, username, role, created_at, updated_at` — omits `password_hash`)

**Directly `GRANT SELECT`'d on the base table** (24 tables — everything else): `devices`,
`device_versions`, `device_configs`, `firewall_rules`, `network_objects`, `zone_classifications`,
`object_analysis_results`, `advisories`, `advisory_conditions`, `device_cve_assessments`,
`vendor_recommended_releases`, `feed_sync_log`, `config_diffs`, `config_backups`,
`rule_analysis_results`, `finding_acknowledgements`, `cve_assessment_acknowledgements`,
`audit_checks`, `audit_findings`, `device_risk_history`, `fleet_dashboard_snapshots`, `activity_log`,
`vpn_session_snapshots`, `snmp_metric_snapshots`.

Note: `device_configs`/`config_backups` carry full config text/trees and ARE granted — safe only
because every adapter redacts secrets before storage (see CLAUDE.md's "Stored configs are REDACTED"
section) — this grant would be a real secret leak if any adapter's redaction pass regressed.
`config_diffs` similarly relies on its own separate value-level `SECRET_PATH_PATTERN` redaction pass.

Every new table added to `schema.sql` needs its own `GRANT SELECT` line added here — both
`Install-SecVault.ps1` and `Update-SecVault.ps1` re-apply this file unconditionally on every run
(idempotent, best-effort — a failure here logs a warning and never fails the install/update, since
these roles are diagnostic-only).
