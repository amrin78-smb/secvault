# CLAUDE.md — SecVault

> **Read this file completely before making any change to this codebase.**
> Update this file whenever a significant architectural decision is made.

---

## Codebase Index — READ FIRST

Pre-built index files live in `.ai-codex/`. Read these BEFORE exploring:
- `.ai-codex/routes.md`         — API routes
- `.ai-codex/pages.md`          — page tree
- `.ai-codex/lib.md`            — library exports
- `.ai-codex/schema.md`         — schema + debt + privilege notes
- `.ai-codex/connectors.md`     — vendor integrations and their quirks
- `.ai-codex/cve-pipeline.md`   — CVE source -> assessment flow
- `.ai-codex/components.md`     — component index
- `.ai-codex/gotchas.md`        — footguns and redaction rules
- `.ai-codex/compliance-pipeline.md` — audit-check seed -> evaluation -> score flow
- `.ai-codex/roadmap.md`        — what is built, what is next, and what is deliberately deferred

### Maintaining the index — MANDATORY

A stale index is worse than none — it sends sessions confidently to the wrong place, and on a
security product, potentially to the wrong redaction assumption. Any commit that changes the shape
of the codebase MUST update the matching index file in the SAME commit — check this at the same
point as the version bump, don't defer it:

route → routes.md · page → pages.md · lib export → lib.md · schema/migration → schema.md · vendor
connector auth/parsing/quirks → connectors.md · CVE source/matching/clearing logic → cve-pipeline.md
· compliance check/predicate logic → compliance-pipeline.md · component added/removed/props changed
→ components.md · new footgun or redaction field → gotchas.md

This file (CLAUDE.md) is the durable-rules/architecture document. It is NOT a changelog — do not
add dated incident narrative here; put durable lessons in the matching `.ai-codex/*.md` file instead.
Trimmed twice on 2026-07-30 (once from ~5,800 lines, again to move detail already duplicated in
`.ai-codex/` out of here) — full history in git log if needed.

---

## What SecVault Is

Standalone on-premises **firewall security and management platform**.
**SEPARATE PRODUCT** from the NocVault suite — own auth, own DB, own services, own server.
Not a module of NetVault, LogVault, DDIVault, or SpanVault. No runtime dependency on any of them.

- **Port:** 3010 (Next.js frontend + API routes)
- **Install path:** `C:\Apps\SecVault\`
- **Repo:** `amrin78-smb/secvault` (private)
- **DB:** `secvault` (PostgreSQL 16, user: `secvault_user`)
- **Dev path (office):** `D:\Users\rahamr00\Documents\NocVault\SecVault\`
- **Deploy:** `git push` → `& "C:\Apps\SecVault\installer\Update-SecVault.ps1"`

---

## ⛔ Critical Rules — Never Violate

These rules exist because violations build clean, pass all static checks, then silently break in production.

### React
- **NEVER define a React component inside another React component.** Causes full remount on every keystroke, losing input focus. Define all components at module top level.
- **`tableLayout: 'fixed'` is required** when using percentage column widths. Without it, table columns collapse unpredictably on overflow.

### Services
- **NEVER use PowerShell service cmdlets** (`Start-Service`, `Stop-Service`, `Get-Service`). They silently disconnect WinRM sessions and hang terminals. **Always use `sc.exe`:**
  ```powershell
  sc.exe stop SecVault-App
  sc.exe start SecVault-App
  ```
- **NEVER use `npm install`** in any script. Always use `npm ci` (respects lockfile, deterministic).

### Database
- **NEVER remove `pool` from any function that accesses the DB or calls credStore.** Removing it breaks DB connections and credential decryption silently — builds clean, fails at runtime.
- **ALWAYS use parameterized queries.** No string interpolation in SQL. Ever.
- **ALWAYS cast timestamp parameters explicitly:**
  ```javascript
  pool.query('SELECT * FROM t WHERE created_at > $1::timestamptz', [date])
  ```
  Without `::timestamptz`, PostgreSQL returns "could not determine data type of parameter $N".
- **Use `CREATE TABLE IF NOT EXISTS`** in every schema.sql statement — safe to re-run on update.
  **This guards table creation only, never column changes** — adding a column to an existing table
  needs a companion `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` right after it, or every
  already-deployed server silently keeps the old shape and the first query selecting that column
  crashes with "column ... does not exist" — the `CREATE TABLE` body still *looks* correct in the
  diff, which is what makes this easy to repeat.
- **UUIDs as primary keys** (`gen_random_uuid()`), not SERIAL.

### Security
- **NEVER store credentials in plaintext.** All external credentials (SMC API keys, SSH passwords) go through `lib/credStore.js` → `device_credentials` table.
- **NEVER hardcode credentials in source files.** Use `.env.local` (gitignored). Commit `.env.local.example` only.
- **Per-table `GRANT SELECT` for readonly users** — never `GRANT SELECT ON ALL TABLES`. The `device_credentials` table must never be readable by `claude_readonly` or `nocvault_readonly`. Grant per table, explicitly.
- **NEVER commit `.env.local`.** The `.gitignore` must list it.
- **Stored configs are REDACTED — load-bearing, not optional hygiene.** Any adapter returning a raw
  text config (`cisco_asa`, `sangfor`, `checkpoint`) MUST redact secrets before `getConfig()` returns
  — those readonly roles can read `device_configs`/`config_backups` even though they're barred from
  `device_credentials` (full mechanism under CVE Engine Architecture below).

### Tri-state values — never collapse `unknown` to `no`
`config_applies`/predicate evaluation is tri-state (`yes`/`no`/`unknown`) for both CVE applicability
and compliance checks. **`unknown` must never silently default to `no`** — that would silently
downgrade a KEV-listed CVE from `patch_now` to `monitor`. Widen an uncertain bound, never narrow it
(same instinct governs CPE wildcard ranges and compliance's `pass_when` — see below).

### ⛔ A failed read is NOT a measurement — the most-repeated bug in this codebase
Every instance of this class builds clean, passes every static check, and produces a confident,
plausible, WRONG number in production. It has now been found in `getRules()` returning `[]`,
`getConfig()` on a read failure, the Panorama rule fallback, and `hit_count`. The rule:
**when a read fails or a vendor cannot supply a value, store NULL/unknown — never the zero,
empty array, or `false` that looks like a real answer.** Tolerating the failure is correct;
recording it as a fact is not.

`firewall_rules.hit_count` is the canonical example and is **TRI-STATE**: a real count, `0`
meaning the device genuinely reported zero, or **NULL meaning NOT MEASURED**. It was
`NOT NULL DEFAULT 0` until 2026-08-25, so every vendor/transport that cannot read hit counts —
Fortinet SSH, Sangfor, Palo Alto SSH, and, because of a PAN-OS command that was being rejected
outright, **every Palo Alto** — asserted "zero hits", and `ruleAnalysis.js` turned that into a
fabricated `unused` finding. `unused` now requires a MEASURED zero. Never coerce NULL to 0 in a
query, a renderer, or an engine; sort with `NULLS LAST`.

### Adapter contract
- **`getRules()` must THROW on a retrieval failure — never return `[]`.** `collectAndStore` DELETEs
  a device's `firewall_rules` before reinserting; an empty array from a *failed* pull silently wipes
  the real ruleset. `[]` means "this device genuinely has no rules," nothing else.
- **`zone_classifications` is per-device**, `(device_id, zone_name)` unique — it was originally built
  as a single global table, found unusable in practice, and rebuilt per-device the same day. Don't
  reintroduce a global shape.

### PowerShell (PS5 compatibility — Windows Server uses PS5 not PS7)
- `try/catch` cannot pipe directly in PS5 — assign to a variable first, then pipe: `$out = git pull; $out | Write-Host` (not `try { git pull | Write-Host } catch {}`)
- No `-Parallel` on `ForEach-Object`, no `-TimeoutSeconds` on `Test-Connection` (both PS7-only)
- `$PID` is a reserved variable — use `$procPid` instead
- Write multi-line PS scripts to temp `.ps1` files; never use `-Command` with newlines

### External API Integrations
- **Verify all field names against live responses before writing any parser — documentation lies.**
  Vendor APIs return different fields than documented, especially on older firmware. Log raw
  responses on first integration test; never assume CPE strings/endpoints/field names from docs alone.

### Pre-Commit Checklist
`node --check` + `npm run build` before every commit — full checklist under Claude Code Workflow's "Before Committing" at the end of this file.

---

## Architecture

### Services (3 NSSM Windows Services)

| Service | Command | Port | Purpose |
|---|---|---|---|
| `SecVault-App` | `next start -p 3010` | 3010 (public) | Next.js frontend + API routes |
| `SecVault-Engine` | `node services/engine-worker.js` | None | Scheduled jobs (feeds, CVE match, config pull) |
| `SecVault-Collector` | `node services/collector.js` | 514 UDP/TCP | Syslog listener (Phase 8a — BUILT 2026-09-08) |

### Stack

| Layer | Technology |
|---|---|
| Frontend + API | Next.js 14.2.35, React 18.3, App Router (`app/` directory — NOT `pages/`) |
| Auth | next-auth 4.24.7, standalone (no suite SSO dependency) |
| Database | PostgreSQL 16, `pg` module (pool pattern) |
| Runtime | Node.js v20 |
| CSS | Plain CSS custom properties + suite utility classes (`app/globals.css`) — NO framework. See "Design System" below. |
| Icons | Hand-rolled inline SVG (`components/icons.js`) — no icon library |
| Charts | `recharts` |
| Credentials | `lib/credStore.js` (AES-256-GCM, per-record IV) |
| Logging | `winston` → `C:\Apps\SecVault\logs\` |
| Scheduling | `node-cron` in engine-worker.js |
| Services | NSSM (Windows service manager) |

### File structure

Don't rely on a hand-drawn tree here — it drifts. For the current, exhaustive,
machine-checked file/route/component inventory use `.ai-codex/pages.md`,
`.ai-codex/routes.md`, and `.ai-codex/components.md`. Top-level orientation:
`app/(auth)/login`, `app/(dashboard)/{alerts,analysis,compliance,devices,settings,
vpn,vulnerability}`, `app/api/{...}` (one route folder per resource — see routes.md).
`lib/adapters/<vendor>/` holds one adapter folder per Tier-1 vendor; `lib/engines/`
holds the shared analysis/CVE/compliance engines; `services/engine-worker.js` is
the scheduled-job runner; `installer/` holds the three PS1 scripts.

---

## Database

### Connection Pool (`lib/db.js`)

Singleton pattern (`lib/db.js` exports one `pool` built from `DATABASE_URL`) — one pool per
process, passed as parameter to all functions, never instantiated per-request.

**NEVER instantiate a new `Pool` inside a request handler or per-query function.**
**NEVER omit `pool` from any function signature that needs DB access** — silent runtime failures.

### Schema Migration

- `lib/schema.sql` uses `CREATE TABLE IF NOT EXISTS` on every table — safe to re-run. `lib/migrate.js` runs it via the `pg` client, connected as `secvault_user`.
- `lib/schema-grants.sql` (readonly role creation + per-table grants) is a **separate file**, run under the `postgres` superuser — **not** run by `migrate.js`, which only has DB-level (not CREATEROLE/superuser) privileges. Both installer scripts apply it automatically, idempotently, every run — Update reads the superuser password back out of the deployed `.env.local`'s `PG_ADMIN_PASSWORD`.
- Never use `DROP TABLE` in schema.sql — destructive and irreversible in production.

### Primary Keys

All tables use `UUID` PKs with `gen_random_uuid()`, not `SERIAL`.

```sql
id UUID PRIMARY KEY DEFAULT gen_random_uuid()
```

### Key Tables

Full table list with purpose/phase is in `.ai-codex/schema.md` — keep that current, don't duplicate
here. Notable groupings: `devices`/`device_versions`/`device_credentials`/`device_configs`/
`firewall_rules` (inventory), `advisories`/`advisory_conditions`/`device_cve_assessments` (CVE),
`audit_checks`/`audit_findings` (compliance), `rule_analysis_results`/`finding_acknowledgements`/
`device_risk_history` (rule analysis), `config_diffs`/`config_backups` (change tracking),
`saved_views` (per-user named table filters, v2.88.0), `activity_log` (operator audit trail), `credential_profiles` (reusable creds, excluded from readonly
grants same as `device_credentials`), `notification_channels`/`notification_dispatch_log` (outbound
alerting — Slack/Teams/email/webhook, see Outbound Alerting section below; `notification_channels`
excluded from readonly grants same as `credential_profiles`).

### Readonly Access for Diagnostics

Two readonly users exist for Claude Code to query the live DB directly: `claude_readonly` and `nocvault_readonly` (same password, `ClaudeRead@2026!`).

**These users must NEVER have access to `device_credentials`.** Grant per-table explicitly, in `lib/schema-grants.sql` — **NOT** in `lib/schema.sql`: `GRANT SELECT ON TABLE new_table_name TO claude_readonly;` (and identically to `nocvault_readonly`), never a blanket `ON ALL TABLES`.
**Second exception: `settings`, granted via a `settings_readonly` VIEW, never the base table** — it stores the local admin's bcrypt hash under `key='admin_password_hash'`; a blanket table grant let readonly roles read it via raw SQL even though the app's `HIDDEN_KEYS` filter hid it from HTTP. Any future secret-bearing row added to `settings` needs the same treatment. `users` gets the identical treatment (`users_readonly` view, excludes `password_hash`).

---

## credStore — Credential Encryption

All external credentials (SMC API keys, SSH passwords) encrypted before DB storage.
`lib/credStore.js`, AES-256-GCM (node `crypto`, random 12-byte IV per record), key from
`CREDENTIAL_KEY` env var (32-byte hex, generated at install — **not** derived from
`NEXTAUTH_SECRET`, SecVault is standalone). Ciphertext+authTag stored as one `enc:tag` hex string in
`encrypted_data`, IV stored separately in `iv` — both columns on `device_credentials`.

Callers use `getCredential(deviceId, credentialType, pool)` / `setCredential(deviceId, credentialType, plaintext, pool)` — both require `pool`. **`setCredential` is a single atomic `INSERT ... ON CONFLICT (device_id, credential_type) DO UPDATE`, not DELETE+INSERT** — DELETE+INSERT was atomic per-request but not against two concurrent calls for the same key, which could leave two rows behind. Relies on a `UNIQUE(device_id, credential_type)` constraint. `getCredential` still reads via `ORDER BY created_at DESC LIMIT 1` for defense in depth.

Key generated at install time into `.env.local`'s `CREDENTIAL_KEY` via `RNGCryptoServiceProvider.GetBytes(32)` in `Install-SecVault.ps1`.

---

## Authentication

NextAuth 4.24.7, JWT strategy, two providers:
1. **Local admin** — username + bcrypt hash, now stored per-user in the `users` table (see RBAC).
2. **LDAP/AD** — optional, `LDAP_URL` + `LDAP_BASE_DN` in `.env.local`.

`NEXTAUTH_SECRET` generated at install, separate from any suite secret. If `NETVAULT_URL` is set,
SecVault can optionally federate SSO to NetVault — default disabled, do not implement suite SSO as
a default code path.

`middleware.js`: protects all `/(dashboard)` routes (redirect to `/login`), allows `/login` +
`/api/auth/*` unauthenticated, API routes return `401` (not redirect) when unauthenticated.

---

## Supported Vendors (Tier 1) — Slugs, Credentials, Dispatch

Six vendors implemented. The slug is load-bearing: it must match across `devices.vendor`,
`VENDOR_PARSERS` (`lib/engines/versionComparator.js`), `ADAPTERS` (`lib/adapters/index.js`),
`VENDOR_CPES` (`lib/feeds/nvd.js`), and `VENDOR_META` (`components/devices/vendorMeta.js`). Never
invent a new spelling.

**A vendor can support more than one access method.** `devices.mgmt_method` is chosen by the
operator in the Add Device form — dispatch is `(vendor, mgmt_method) → adapter class`.

| slug | mgmt_method | Access | Connection fields | credential_type |
|---|---|---|---|---|
| `forcepoint` | `smc` | SMC REST :8082 | `smc_host`+`smc_port` | `smc_api` (raw API key string, not JSON) |
| `fortinet` | `api` / `ssh` | REST / SSH | `mgmt_ip`+`mgmt_port` | `rest_api` / `ssh` |
| `paloalto` | `api` / `ssh` | XML API (keygen) / SSH | `mgmt_ip`+`mgmt_port` | `rest_api` / `ssh` |
| `checkpoint` | `api` | Mgmt API (mgmt server, **not** gateway) | `mgmt_ip`+`mgmt_port` | `rest_api` |
| `cisco_asa` | `ssh` | SSH | `mgmt_ip`+`mgmt_port` | `ssh` (+`enable_password`?) |
| `sangfor` | `ssh` | SSH | `mgmt_ip`+`mgmt_port` | `ssh` |

Forcepoint is SMC-only **by design** — never SSH to Forcepoint engines (see the SMC section below).
Credential plaintext is built by `buildCredentialPlaintext()` (vendorMeta.js) and read by
`parseApiCredential()`/`parseJsonCredential()`. `parseApiCredential` also accepts a bare non-JSON
string as an api-key — deliberate backward compatibility, don't remove it.

#### Two registries, deliberately duplicated — keep them in step

`components/devices/vendorMeta.js` is an ES module (client components import it); `lib/adapters/index.js` is CommonJS (`engine-worker.js` `require()`s it under plain node, which can't load ESM) — so these two must be updated together: `VENDOR_META[slug].accessMethods` ↔ `ADAPTERS[slug]`'s inner keys, `defaultAccessMethod` ↔ `DEFAULT_METHOD[slug]`. Drift here is a silent runtime bug.

#### Dispatch rules
- **Adapters implement ONLY the FirewallAdapter interface** (testConnectivity/getVersion/getRules/getConfig) — the shared persistence pipeline lives ONCE in `lib/adapters/index.js` (`collectAndStore`), never copied into a vendor folder. New vendor = adapter folder + `ADAPTERS`/`DEFAULT_METHOD` + `VENDOR_PARSERS` + `VENDOR_CPES` + `VENDOR_META` entries.
- **`getRules()` must THROW, never return `[]`, on a retrieval failure** (see Critical Rules above).
- **Check Point: never pick a policy package positionally** (`packages[0]` was a real, fixed bug) and **Fortinet: collect every VDOM or fail** (a partial VDOM failure must throw, not return the rest) — both detailed in `gotchas.md`'s Vendor adapters section.
- SSH vendors share `lib/adapters/sshClient.js` (legacy algorithm compat for old ASA images) — don't open raw ssh2 connections in adapters. `mgmt_port` is nullable, each adapter applies its own default (443 API / 22 SSH / 8082 SMC).
- `advisories.cve_id` is UNIQUE with a single `vendor` — a CVE affecting two vendors stays with
  whichever ingested it first.

### Live validation status

Each adapter logs its raw response (`[<Vendor> Debug]` in `engine.log`) on first live use — live
connections are a verification step, not a smoke test. Full verification history and confirmed
field mappings: `.ai-codex/connectors.md` — check there before assuming a field name.

**Known limitations (by design, not bugs)** — hit-count COVERAGE (which vendors/transports can
read them at all; the tri-state rule above governs how a gap is recorded), gateway resolution, Panorama fallback,
VDOM-aware analysis status: all detailed in `gotchas.md`'s Vendor adapters / Rule analysis sections.

---

## Forcepoint SMC Integration — Condensed

**NEVER SSH directly to Forcepoint engines** — always the SMC REST API on `:8082` (one exception: SNMP, which hits `devices.snmp_host` directly since SMC doesn't proxy per-engine metrics). **Self-signed SSL polarity** is per-device (`devices.allow_self_signed_ssl` column, not the env var — that only seeds the Add Device form default): `rejectUnauthorized: allowSelfSignedSsl === false`, used identically by every vendor adapter — get this backwards and every self-signed endpoint starts failing TLS. SMC responses use HATEOAS `href` links — never construct URLs from element IDs. **CVE data is NVD-only** (Forcepoint has no PSIRT/RSS) — use `virtualMatchString`, never `cpeName` (404s on wildcard CPEs), and query both pre-7.1 (`next_generation_firewall`) and 7.1+ (`flexedge_secure_sd-wan`) CPEs, dedupe by `cve_id`. Full endpoint list and field-mapping history: `.ai-codex/connectors.md` / `cve-pipeline.md`.

---

## CVE Engine Architecture

Full pipeline detail (matching, dashboard, cleanup/reorder tabs, config-diff classification) is in
`.ai-codex/cve-pipeline.md` and `.ai-codex/lib.md` — this section keeps only what must not drift
without updating this file first.

### Version Schemes (per vendor — `lib/engines/versionComparator.js`)

| Vendor slug | Example | Tuple |
|---|---|---|
| `forcepoint` | `6.10.21` | `[6, 10, 21]` (7.1+ = FlexEdge rebrand, same scheme) |
| `fortinet` | `v7.4.3,build2573` | `[7, 4, 3, 0]` (leading `v` and `,build…` stripped) |
| `paloalto` | `11.1.2-h3` | `[11, 1, 2, 3]` (hotfix = 4th segment) |
| `cisco_asa` | `9.18(4)15` | `[9, 18, 4, 15]` (interim = 4th segment) |
| `checkpoint` | `R81.20 Take 41` | `[81, 20, 41, 0]` (R stripped, Take = 3rd segment) |
| `sangfor` | `8.0.85` | `[8, 0, 85]` (plain dot-split) |

### Priority Decision Tree (strict order — do not reorder)

```
1. kev_listed=true + version_affected=true + config_applies!='no'  → patch_now
2. log_hit=true + version_affected=true + config_applies!='no'     → patch_now
3. cvss>=9.0 + version_affected=true + config_applies='yes'        → patch_now
4a. cvss>=7.0 + version_affected=true + config_applies='yes'
    + is_fixed_recommended=true                                     → scheduled
4b. cvss>=7.0 + version_affected=true + config_applies='yes'
    + is_fixed_recommended=false                                    → monitor (wait for stable)
5. version_affected=true + config_applies='unknown'                → scheduled (conservative)
6. all others                                                       → monitor

Asset criticality modifier (apply after base band):
  device.asset_criticality='critical' → bump one band up
  monitor → scheduled | scheduled → patch_now
```

**Any change to this decision tree must be documented here before the code is changed.**

#### What `log_hit` MEANS (defined 2026-09-08, before the producer was written)

The tree above was always correct; `log_hit` simply had no producer, so it was `false`
everywhere. Defining it is a tree-behaviour change even though no branch moved — rule 2 sits
**above CVSS 9.0**, immediately after KEV, so whatever sets it claims a confidence equal to
"known exploited in the wild".

⛔ **`log_hit` = the VULNERABLE SERVICE WAS REACHED on this device, FROM THE INTERNET.** All of:
1. the advisory has at least one curated `port_exposed` condition naming a port; **and**
2. firewall logs show traffic ARRIVING at one of that device's own `device_interfaces`
   addresses on that port; **and**
3. the source was PUBLIC — outside RFC1918/loopback/link-local/CGNAT. An admin on the LAN
   reaching a management port is real reachability but a much weaker claim, and admitting it
   would fire rule 2 on every device with a curated management port; **and**
4. the traffic was **ALLOWED**. A blocked probe is not a reached service.

Ports within one advisory are **ORed** — reaching one exposed port of several is still reaching
the service. This deliberately differs from `applicability.js`, which ANDs its conditions,
because the questions differ: "does this advisory apply" vs "was it reached".

⛔ **"Allowed" is not the same as `action = allow`.** Verified on live logs: Fortinet records a
session that was established and then ended as `close`/`client-rst`/`server-rst`, and FortiGate
SSL-VPN on 10443 is reached from public sources logged `close`, NEVER `allow` — matching only
`allow` would miss the most exposed service on the fleet. Palo Alto's `reset-both` belongs to
the same visual family but is a BLOCK (its IPS resetting both ends). ⛔ An action string in
neither list is **unknown and never fires** — an unrecognised vendor verb must not be able to
manufacture a `patch_now`.

⛔ **Two cases write NOTHING rather than `false`:** a device with no syslog coverage in the
window, and a device with no collected `device_interfaces` rows (without which traffic TO the
device cannot be told from traffic THROUGH it). Both are UNMEASURED; writing `false` there is
the failed-read-as-a-fact bug again.

⛔ **REJECTED definition: "a threat signature fired against this device."** It is available
today and it is wrong here. It is not CVE-specific, so it would escalate EVERY advisory on
that device; measured on this fleet, threat events land on nearly every device, which would
move ~all 155 assessments to `patch_now`. A queue where everything is urgent has no
prioritisation left, which is strictly worse than `log_hit` staying honestly false. That data
is still worth surfacing — as device-level attack CONTEXT beside the CVEs, never as a band
modifier.

⛔ **`false` here means "not observed", NOT "not exploitable".** It is the safe direction
because rule 2 only ever escalates on `true`, but no UI may render a `false` as "this is not
reachable". Absence of an observation is not evidence of absence — the same rule as
`hit_count`.

⛔ **It requires curated conditions, and that is deliberate.** With `advisory_conditions`
empty (as it was on this fleet) `log_hit` can never fire, and that is the correct behaviour:
without a curated port there is nothing to look for, and guessing one from advisory prose is
the "documentation lies" trap. See `/vulnerability/advisories` for the curation worklist.

Computed by `lib/engines/logHit.js` in the ENGINE, never on page load: it reads raw
`syslog_events` over a bounded lookback and that is a background cost, not an interactive one.

### Fleet & per-device Security Score (`lib/engines/securityScore.js`, v2.53.0)

0-100, **higher is better**, weighted: vulnerability 40 / rule hygiene 30 / compliance 30. Each
component reuses the engine that already measures it. Used by the dashboard headline tile, the
nightly snapshot (`fleet_dashboard_snapshots.security_score`) and per-device on `/devices`.

⛔ **POLARITY.** `riskScore.js` is 0-100 higher-is-WORSE and feeds this. The inversion happens in
exactly ONE place (`hygieneSubscore`) and must not be "simplified" away — getting it backwards
throws nothing and renders a plausible number that says the fleet is healthiest exactly when it is
worst.

⛔ An unmeasurable component is **dropped from the denominator**, never scored 0 (same rule as
compliance's `na`) — otherwise a fresh install reports a data gap as a security problem. All three
unmeasurable → `null`, rendered "—". `monitor`-band CVEs contribute nothing by design.

**Any change to these weights or to the polarity must be documented here before the code changes.**

### Applicability Tri-State Default

See Critical Rules above for the core "never collapse `unknown` to `no`" rule. Specifics not covered
there: no `advisory_conditions` row for an advisory → `config_applies = 'unknown'`. "No usable
config" (`hasUsableConfig()`) also means an EMPTY object, not just null/non-object/array — a real
reachable failure (an adapter meeting an unexpected live shape can return `{}`), not a hypothetical
one.

Predicate types: `config_key_exists` / `config_value_equals` / `config_value_matches` (path missing → `'no'`), `feature_enabled`, `port_exposed` / `admin_access_from_zone` (not found → `'unknown'`). Conditions for an advisory are ANDed: any `'no'` → `'no'`; else any `'unknown'` → `'unknown'`; else `'yes'`. `evaluatePredicate()` never throws — internal errors resolve to `'unknown'`. A third predicate type, `ruleset_property`, exists only in the Compliance Engine. Conditions are DATA (new CVE conditions are new DB rows via `/advisories/[cveId]/conditions`), not code.

### ⛔ Stored configs are REDACTED — do not "fix" this

See Critical Rules above for the requirement; full per-vendor redacted-field list, the universal
keyword pattern (and its per-file duplication convention), and the database-level exclusions are in
`.ai-codex/gotchas.md`'s Redaction rules section — read that before touching any adapter's config
retrieval or `configDiff.js`.

Rule analysis (10 finding types), the risk-scoring dashboard, cleanup/optimization/reorder tabs, risk trend history, and config-diff classification/redaction internals are documented in `.ai-codex/cve-pipeline.md` / `lib.md` / `gotchas.md` — read those before touching `lib/engines/ruleAnalysis.js`, `riskScore.js`, or `configDiff.js`.

---

## Compliance Engine (Phase 7 — `/compliance`)

Full stage-by-stage mechanics (seed library, all three predicate-evaluation shapes, write/trigger/
score flow) live in `.ai-codex/compliance-pipeline.md` — this section keeps only what must not
drift without updating this file first.

Reuses `applicability.js`'s predicate evaluator (`evaluatePredicate`/`hasUsableConfig`) — compliance checks and CVE-applicability conditions both "evaluate a predicate against `device_configs.config_parsed`," for different purposes. `evaluatePredicate()` only returns `yes`/`no`/`unknown` — a compliance check needs a fourth state (`pass`/`fail`/`warning`/`na`), and different checks need **opposite polarity** (a `feature_enabled` check on `logging.enabled` wants `yes`=PASS; `admin_access_from_zone` on the WAN zone wants `yes`=FAIL). Resolved via each check's `pass_when: 'yes'|'no'`: predicate `unknown` → `warning`; result `=== pass_when` → `pass`, else `fail`; no usable config at all → `na`; **`pass_when` missing or not exactly `yes`/`no`** → `warning`, never a silent default polarity (a curated-data bug, not a device problem).

A third predicate type, `ruleset_property` (**3 checks**, not 2 — see compliance-pipeline.md), is a positive existence question evaluated directly against `firewall_rules`, not one fixed config path. Check-library seed (`lib/auditChecksSeed.js`) is currently **45 checks** — recount via `grep -c "checkId:"` if you touch that file, it has drifted before.

`scorePct = round(100 * pass / (pass + fail + warning))`, **excluding `na` from the denominator**; `null` (rendered "—"), not `0`/`NaN`, when nothing is measurable.

### ⛔ `warning` vs `na` — whose limitation is it? (changed 2026-08-25)

Both mean "not a pass and not a fail", but they answer different questions and only one belongs
in the score's denominator:

- **`warning` = a fact about THIS DEVICE.** We collected a config and asked a real question of it,
  and the answer came back indeterminate. That uncertainty is genuinely the device's (or the
  curated check definition's), so it counts against the score. Sources: a predicate resolving
  `unknown` against a config we DID collect, and an invalid/missing `pass_when`.
- **`na` = a fact about SECVAULT.** The question cannot be asked of this device at all — nothing
  the operator could change on the firewall would make it answerable. It is dropped from the
  denominator. Sources: no usable config at all, `ruleset_property` with no ruleset collected,
  and — since 2026-08-25 — **`predicate_type: 'not_evaluable_from_config'`**.

`not_evaluable_from_config` used to land on `evaluatePredicate()`'s `default: return 'unknown'`
and so became a `warning`. That was the wrong bucket. These checks are declared unanswerable BY
CONSTRUCTION — either the fact is inherently per-rule and the predicate engine only supports one
fixed dot-path (`fortinet-ips-internet-facing-policies`), or it needs telemetry a static config
snapshot never contains (`fortinet-unused-interfaces-shutdown`). Scoring a device down for a
question SecVault cannot pose is the same error as `hit_count`'s old `DEFAULT 0`: **our inability
to measure, recorded as a negative fact about the device.** Measured live on the 16-device fleet:
43 of 61 warnings were this, and moving them to `na` took the fleet from 46% to 51%, every device
up 3-7 points. No check changed status from pass to fail or vice versa — only the denominator.

The findings are still WRITTEN and still shown, with their `reason` — `na` suppresses them from
the score, never from the operator, who still needs to know these are manual-verification items.

---

## Network Topology & Path Analysis (`/topology`, added 2026-08-02)

Two layers, built in this order — read `lib/engines/objectResolver.js` before `lib/engines/topology.js`,
the second reuses the first UNCHANGED as its per-hop evaluator:

1. **Per-device Access Path Query** (`/devices/[id]/analysis?tab=access-path`, shipped first) —
   `lib/engines/objectResolver.js`'s `queryAccessPath()` resolves a device's `firewall_rules`
   address/service fields (almost always OBJECT NAMES) down to real IP ranges/ports via
   `network_objects`, recursively expanding group membership, and walks enabled rules in
   `sequence_number` order. Tri-state throughout (`'match'|'no-match'|'unresolved'`) — an
   unresolved object (FQDN address, unmatched name) is never coerced to a non-match. The first rule
   not definitively excluded decides, including one whose match involved an unresolved object
   (flagged `hasCaveat:true`, not skipped past). No rule decides → `verdict:'unspecified'`, **never
   `'deny'`** — no default/implicit-policy data exists anywhere in this codebase, for any vendor.
   Single-device, config-only — has no idea what any other firewall does.

2. **Fleet-wide multi-hop Path Query** (`/topology?view=query`, the default view) —
   `lib/engines/topology.js` adds ONE orchestration layer on top: infers which devices are adjacent
   (two DIFFERENT devices' interfaces whose `device_interfaces.ip_address` ranges overlap share a
   link), applies NAT translation between hops, and crosses devices via longest-prefix-match routing
   against `device_routes`. At each hop it calls `objectResolver.queryAccessPath()` unmodified — this
   file never re-implements or duplicates rule evaluation, only decides which device is next. Stops
   on a `deny`, a dead-end route, the fleet boundary (egress subnet not shared with any known
   device), or a defensive 25-hop cap (guards a routing loop between misconfigured devices) — each
   case returns an explanatory `note`, never silently upgrading an unresolved/trailing path to a
   confident verdict.
3. **Fleet Map** (`/topology?view=map`, added 2026-08-02) — `buildFleetTopologyGraph()` (same file)
   dedupes that same adjacency computation into one visual diagram: every active device as a node
   (hand-rolled inline SVG, circular layout — no diagramming library in this codebase), every
   inferred link as a line. Every active device appears as a node EVEN with zero
   `device_interfaces` rows (dashed/muted, `hasInterfaceData:false`) — the map stays honest about
   fleet coverage gaps instead of silently omitting uncollected devices. **Click-through** (added
   2026-08-03): a node with `hasInterfaceData:true` is wrapped in a plain SVG `<a>` to
   `/topology?view=query&srcIp=<ip>` — no client JS, the IP is that device's first interface
   (sorted by name) whose address parses cleanly, editable before submitting. **VPN-tunnel-peer
   edges** (added 2026-08-03): a SECOND, independent edge type (`type:'vpn'`, dashed) alongside the
   original shared-subnet edges (`type:'subnet'`, solid) — `buildVpnEdges()` matches each device's
   already-collected `vpn_ipsec_tunnels.peer` (the `getVpnTunnels()` adapter capability, scheduled
   independently of the rule-version-pull job — see Feed Sources/Engine Worker) against every OTHER
   device's own interface IPs. Exists because several Fortinet branches use UNNUMBERED IPsec tunnel
   interfaces (`ip: 0.0.0.0`, confirmed live) — invisible to the subnet-overlap mechanism even
   though the devices are genuinely connected. Only `status:'up'` tunnels with a resolvable,
   non-`0.0.0.0` peer draw an edge. **Visual-only** — deliberately NOT fed into
   `simulateMultiHopPath()`'s own adjacency graph (Layer 2 above); a peer gateway IP alone doesn't
   say what's routable through that tunnel.

**Collection (vendor scope — deliberately incomplete, not a bug)**: three new OPTIONAL
adapter methods (`getInterfaces()`/`getRoutingTable()`/`getNatRules()`, see `lib/adapters/interface.js`),
implemented by `paloalto` on **both SSH and API transport** (API transport added 2026-08-03,
live-verified against ITC-SLY — its `getNatRules()` reuses `sshParser.parseNatPolicyOutput()`
directly since the API's NAT response is byte-identical in format to the SSH transport's plain
text) and `fortinet`'s **SSH transport only** — Fortinet's API transport and the other 4 vendors
are not yet wired (no live device to verify real command output against, for any of them, per
this file's own "verify against live responses before writing any parser" rule — add later
following the identical adapter-method pattern once a live device exists). Fortinet's
`getNatRules()` (added 2026-08-02, live-verified against TSR-TL) derives NAT
from `show firewall policy`/`vip`/`ippool` — FortiOS has no separate ordered NAT rulebase like Palo
Alto, NAT is a per-policy `set nat enable` flag plus VIP objects referenced from `dstaddr`.
Destination NAT via a VIP resolves cleanly (VIPs bind to a real physical interface). Source NAT
resolves to the egress interface's own IP only when the policy's `dstintf` names a real interface —
**every policy on the live device uses an SD-WAN virtual interface (`"virtual-wan-link"`) instead**,
which has no IP of its own, so that case reports the translation as unresolved rather than guessing
which physical WAN link the traffic actually egresses through. A device pair not covered by either
vendor's collection simply won't chain together in the adjacency graph — the query still returns a
result, just possibly ending earlier ("path continues beyond SecVault's managed fleet") than the real
network actually does. Collection runs inline inside the existing `rule-version-pull` job
(`CONFIG_PULL_INTERVAL_HOURS`, no new cron job, no new env var) — routing/interface data is
structural, slow-changing, not live session state.

Three new live-snapshot tables (`device_interfaces`/`device_routes`/`nat_rules`, DELETE+reinsert per
pull, same lifecycle as `network_objects`) — `nat_rules`' `original_*`/`translated_*` columns use the
EXACT SAME shape as `firewall_rules.src_addresses` (JSONB array of literal IPs or object names),
deliberately, so `objectResolver.js`'s address resolver works unchanged against NAT rows too.

**Not admin-gated** (`POST /api/devices/[id]/access-path`, `POST /api/topology/path-query`) — both
are pure read-only computations over already-collected data with no persistence. See the RBAC
section below for why a non-mutating POST is treated like a GET here.

---

## Device Lifecycle & Health (`/lifecycle`, added 2026-08-03)

Four facts SecVault could not previously answer, all collected from the management API/CLI it
already talks to. Optional adapter methods `getLicenses()`/`getHaStatus()`/`getDiskUsage()` plus a
`contentVersions` field on `getVersion()`. **Palo Alto: all four, both transports. Fortinet
(added 2026-08-04): licences + content versions over SSH** — via `diagnose autoupdate versions`,
`diagnose test update info` (its **System contracts** block is the only CLI source of the
SPRT/HDWR/ENHN/COMP support entitlements) and `get system fortiguard`. ⛔ An earlier note here said
Fortinet had no licence surface; that was wrong, and came from probing only `get system status` —
one command returning nothing does not prove a vendor lacks the data. Fortinet HA/disk remain
deferred (no HA-enabled FortiGate to verify a peer parser against). Tables: `device_licenses`, `device_ha_status`, `device_disk_usage`,
`device_content_versions` — all latest-snapshot, all detailed in `.ai-codex/schema.md`.

- **Licences / support expiry** — the fleet renewal-planning view. ⛔ `expires_at` is TRI-STATE
  with `expires_raw`: a NULL date means *perpetual* when raw is `'Never'` and *unknown* otherwise;
  never collapse those, because treating an unparsed expiry as "fine" is how a contract lapses.
- **HA state** — including peer identity, config-sync state, and PAN-OS's own Version Compatibility
  block. `version_compat_ok` is tri-state (NULL = the device reported no block; never default it to
  true). A `User requested` suspension is NOT a fault and is deliberately excluded from
  `last_nonfunctional_reason`.
- **Disk** — from `show system disk-space`, NOT SNMP, so it carries none of `snmp_metric_snapshots`'
  `lowConfidence` caveat. Sizes stay as the device's own `df -h` strings; only the percentage is
  numeric.
- **Content/signature versions** — extracted from the `show system info` response `getVersion()`
  already fetches. **No additional device command is issued.**

Derived status (`expiring`/`stale`/`degraded`/...) is computed at READ time by the pure
`lib/engines/deviceHealth.js`, never stored — the raw facts are what's persisted, and staleness is a
function of those plus the current time. Wiring these into `/alerts` and outbound notifications is a
deliberate follow-up, not an oversight.

**Command syntax was verified per-command against live devices and there is NO general rule** —
licences need the nested form while `show interface all` needs the value form, and each was
rejected live in the other shape. See `connectors.md` entry 11 before touching any of it.

### Baseline config drift

`device_configs.is_baseline` (partial unique index — one baseline per device is a DB guarantee, so
setting a new one must CLEAR the old one first) marks an operator-designated known-good snapshot.
Drift is "latest vs baseline", which is a genuinely different question from `config_diffs`' "latest
vs previous pull" — a consecutive-pull comparison target may itself already be drifted. Both drift
and arbitrary version-A-vs-B comparison reuse `configDiff.js`'s already-pure
`diffConfigs`/`classifyDiff` **unchanged**; only the caller was ever hardwired. Computed on read, no
new table and no new cron job.

### Config-snapshot retention (`lib/engines/configRetention.js`, added 2026-08-25)

`device_configs` stores one full snapshot per device per pull whether or not anything changed —
measured at 449 MB of a 529 MB database (85%), ~9.5 MB/day, ~3.4 GB/year, with no retention of any
kind. The daily `[config-retention]` engine job bounds it. Safe to run because the CHANGE record
does not live here: `config_diffs` is append-only with its own stored JSONB payload and **no
reference to any `device_configs` row** (verified empirically — the only FK on/into
`device_configs`/`config_backups` is their own `device_id -> devices(id)`), and `config_backups`
holds a full copy at each *detected* change. Retention only removes the long tail of
near-identical snapshots.

⛔ **Four protections, none optional, each expressed TWICE (classify query + DELETE predicate):**
1. `is_baseline = true` is NEVER deleted at any age — it is the drift comparison target, and a
   silently-lost baseline reads as "no drift", the most dangerous wrong answer available here.
2. The NEWEST row per device is NEVER deleted at any age. A device that stopped being collected two
   years ago must still show its last known config; "retention deleted the only copy" is strictly
   worse than a large database.
3. A minimum COUNT per device survives regardless of age (`MIN_KEEP_CONFIGS`=10 /
   `MIN_KEEP_BACKUPS`=5) — **not env vars**, because they are safety floors, not tuning knobs.
   Precisely: they are the DEFAULTS for an in-process caller option, clamped to >= 1, and
   `services/engine-worker.js` passes only the two day counts, so nothing configurable can reach
   them. An in-process caller *can* lower this one to 1 — at which point protection 2 (never the
   newest row) is what still holds, which is why the clamp floor is 1 and not 0.
   ⚠️ This is the structurally weakest of the four: unlike 1, 2 and 4 it rests on a single clause
   inside the DELETE rather than being doubled within that statement. It degrades gracefully
   (losing it falls back to protection 2), but do not add a third caller to it casually.
4. `config_backups` rows whose `label` is not `'auto'` (`'manual'`/`'pre-change'`) are NEVER
   deleted — operator intent outranks a size budget.

`CONFIG_BACKUP_RETENTION_DAYS` (365) is deliberately far longer than `CONFIG_RETENTION_DAYS` (60):
every `config_backups` row is a distinct moment of real change at ~1.5% of the volume. Do not
"simplify" the two windows into one. `runConfigRetention()` NEVER THROWS (per-table errors are
returned in its summary) and is idempotent. Its log line reports what was KEPT and by which
protection alongside what was deleted, so an operator can tell retention from data loss.

Note a `DELETE` only frees space for REUSE (which bounds growth — the actual goal); it does not
shrink the file on disk. A one-time `VACUUM FULL`/`pg_repack` is needed to return space to the OS
and is deliberately NOT in the job (ACCESS EXCLUSIVE lock).

⛔ **The root cause is upstream and is NOT fixed by this job**: only 106 real changes produced
1,730 snapshots, 508 of which are byte-identical to their immediate predecessor (~161 MB of pure
duplicates). Deduping belongs in `collectAndStore` at WRITE time, not in a retention job — a
stored row is also evidence that a collection succeeded at time T, so skipping the write changes
that meaning and needs its own decision.

## Phase 8 — Syslog Ingestion (IN PROGRESS, started 2026-09-08)

Replaces ManageEngine Firewall Analyzer, which was removed after a failed service-pack
upgrade left it unrecoverable. FWA had been the fleet's syslog collector on the SAME host as
SecVault (192.168.7.69), taking **~1,083 datagrams/sec sustained (~93M events/day)** from 27
devices. Its 335 GB raw-log archive was preserved out of the install tree before uninstall.

Two reasons this belongs in SecVault rather than being left to LogVault, which also ingests
syslog: (1) CLAUDE.md's CVE priority tree already has `log_hit=true` as decision rule 2, and
that input has never had a data source; (2) `firewall_rules.hit_count` is NULL — genuinely
unmeasurable — for every vendor/transport whose API cannot report hits (Fortinet SSH, Sangfor,
Palo Alto SSH). Log evidence supplies both. **Neither is something a general log analyser can
do, because it does not know the rulebase, the CVE exposure or the compliance posture.** The
log storage itself is not the point; the fusion is.

**Retention decision (drives the schema), REVISED 2026-09-08 with live measurements:** raw
searchable events **30 days**, rolled up into per-rule / per-device / per-hour aggregates kept
indefinitely. Anything older than the raw window is answered from aggregates. Time-partitioned
tables, dropped by partition.

30 days was reachable only after the row itself got smaller. Measured on the live fleet, in
the same partition, either side of the `SYSLOG_RAW_MESSAGE=security` deploy:

| | before | after |
|---|---|---|
| rows keeping `message` | 100% | 11% |
| heap bytes/row | ~1,000 | **~340** |
| index bytes/row | ~75 | ~75 |

⛔ **A partition average mixes both eras and is NOT the steady-state figure.** The
`syslog_events_20260908` partition reads ~941 heap bytes/row, which is neither the old nor the
new number — it holds pre-change and post-change rows. Sizing off it over-states the footprint
by ~2.7x. Measure a window that starts after the deploy, or read the per-hour breakdown.

Projection at the observed rate (~74M events/day, from an afternoon-to-night curve peaking at
5.3M/hour): **~31 GB/day, ~920 GB for the 30-day window**, plus the compressed archive at
~8.4 GB/day. ⛔ This is an EXTRAPOLATION FROM A PARTIAL DAY — the collector had not yet run a
full 24h when it was taken. Re-measure over a complete day before treating it as capacity fact.

⛔ **This only fits because PostgreSQL lives on `E:`.** The data directory is
`E:PostgreSQLdata` (2 TB volume, 1,629 GB free at time of writing) and the archive is
`E:SecVaultArchive`. `C:` has ~159 GB free and could not hold even a third of the raw window.
A future rebuild that accepts the PostgreSQL installer default (`C:Program FilesPostgreSQLdata`)
silently gets a fifth of the capacity this retention assumes, and fills the SYSTEM volume doing
it. Check the data directory before changing `SYSLOG_RETENTION_DAYS` upward.

### Landed so far — the pure parsers only

`lib/syslog/syslogParser.js` (RFC 3164/5424 frames) and `lib/syslog/vendorParsers.js` (Fortinet
key=value, Palo Alto positional CSV). Both pure, both unit-tested, neither wired to anything yet.

⛔ **Every vendor field mapping was read off REAL CAPTURED LOGS** from the preserved archive, not
from documentation, per this file's own "documentation lies" rule. The captured lines are the
test fixtures.

⛔ **At 93M events/day a wrong DEFAULT is not a rounding error, it is a fabricated dataset.**
Every parser field is nullable and stays null when the log did not carry it — no defaulting a
missing timestamp to "now", an unknown vendor to "generic", or an absent severity to info. This
is the same Critical Rule as `hit_count`; syslog is simply where it is easiest to get wrong and
hardest to notice.

### The collector (`services/collector.js`, built 2026-09-08)

NSSM service `SecVault-Collector`. UDP + TCP listeners (`SYSLOG_UDP_PORT`/`SYSLOG_TCP_PORT`,
both 514 by default and configurable so it can be exercised on 1514 first).

⛔ **Durable spool BEFORE the database**, per this file's own Reliability Rules. The cycle is
datagram → in-memory buffer → (every `SYSLOG_FLUSH_MS`) written and **fsync'd** to a `.tmp`
file, atomically renamed to `.ready`, parsed, batch-INSERTed, and **only then deleted**. Any
`.ready` files found at startup are replayed first. A crash between write and insert therefore
costs a duplicate replay, never a lost event — for firewall logs, storing evidence twice beats
losing it once.

⛔ **Overflow is COUNTED, never hidden.** If the buffer hits `SYSLOG_MAX_BUFFER` the collector
increments `dropped` and writes it to `syslog_ingest_stats`. A collector that silently loses
datagrams under load is indistinguishable from a quiet network — the same
failed-read-as-a-fact rule as `hit_count`, applied to ingest.

⛔ **An unmatched sender stores `device_id NULL` and is still stored.** A firewall SecVault does
not manage still produces evidence; dropping it would make the fleet look quieter than it is.
The IP→device map is refreshed every 5 minutes and a failed refresh KEEPS the previous map
rather than blanking it, so a DB blip cannot orphan every event.

### Storage (see `.ai-codex/schema.md` for the columns)

| table | lifetime | why |
|---|---|---|
| `syslog_events` | ~30 days, DAILY PARTITIONS | raw forensics |
| `syslog_rollup_hourly` | permanent | low-cardinality traffic/severity counts |
| `syslog_rule_hits_hourly` | permanent | per-rule usage evidence (Phase 8b input) |
| `syslog_ingest_stats` | permanent | received/parsed/stored/**dropped** per flush |

⛔ **Raw events are aged out by DROPPING A PARTITION, never by DELETE.** At ~93M rows/day a
DELETE would generate more WAL and vacuum work than the ingest itself and would not return the
space. `dropOldPartitions()` only ever drops names matching `^syslog_events_\d{8}$`.

⛔ The rollups use **`UNIQUE NULLS NOT DISTINCT`** (PostgreSQL 15+) so their grouping keys can
stay honestly nullable. Without it NULLs compare unequal and every flush inserts a duplicate
"unknown vendor" row instead of incrementing one — and the usual workaround, sentinel strings
like `'unknown'`, is precisely the fabricated-value pattern this file bans.

### Phase 8b — BUILT (this section was stale until 2026-09-09)

Rule-hit correlation to `firewall_rules` is DONE (`lib/engines/ruleHitCorrelation.js`, consumed
by `ruleAnalysis.js`), the rollup population job runs in the collector, and the dashboard Traffic
tab is live. Measured on the fleet: 8,803 rows in `syslog_rule_hits_hourly` across all 15 devices,
and `firewall_rules.hit_count` genuinely tri-state at 164 unmeasured / 466 measured-zero / 1,086
with hits — which is what makes the 185 `unused` findings evidence-backed rather than assumed.

⛔ This section previously said none of that was built, a full phase after it shipped. A stale
"not built yet" is worse than none: it sends a session off to rebuild something that works. If
you finish a phase, correct the sentence that says you have not. Forward-looking work now lives
in `.ai-codex/roadmap.md`, which exists so this file does not have to track it.

Both installer scripts now handle `SecVault-Collector`: `Install-SecVault.ps1` registers it
(NSSM, auto-start, depends on PostgreSQL), creates the spool directory from its `-SpoolDir`
parameter, and opens inbound firewall rules for every port in `-SyslogPorts`.
`Update-SecVault.ps1` stops it with the others and restarts it after the build.

⛔ **Inbound firewall rules are not optional.** Without them the collector binds, reports itself
healthy, and receives nothing — Windows drops the datagrams before they reach the socket, with
no error anywhere. Same failure shape as binding the wrong port: every health signal green, and
the system deaf.

⛔ **`-SpoolDir` must not default to a data volume that may not exist.** The env example briefly
hardcoded `E:\SecVaultSpool`, which is right for the reference deployment and wrong for any
machine without an E: drive. It now defaults under the install root and the installer creates it.

---

## VPN Traffic Attribution (`/vpn?vtab=traffic`, added 2026-09-10, v2.101.0)

Joins `vpn_sessions.assigned_ip` against the `syslog_talker_hourly` rollup to say what a NAMED VPN
user actually did. Read-time, no table, no cron job. Detail in `.ai-codex/lib.md`; the rules:

⛔ **IP REUSE IS THE WHOLE PROBLEM.** An hour is attributed ONLY if it falls entirely inside exactly
one session's tenure on that address. Partial hour, overlap, or an hour no known session held are
each UNATTRIBUTED with their own reason and counts. Measured live: **two-thirds of pool-address
traffic (3,023 buckets / 550,722 events) belongs to no retained session** — "most recent holder wins"
would have filed one employee's activity under another's name.

⛔ **Coverage is clipped PER GATEWAY, never fleet-wide.** A fleet-wide bound lets a device added later
claim weeks its sessions could not be enumerated in, so an hour reads unambiguous while an invisible
second session held the address. Filters are applied AFTER attribution, so narrowing can never make
an ambiguous address look clean. Both pinned by tests.

⛔ **`syslog_events` IS REFUSED and a test enforces it** — no `src_ip` index, 27 GB/day partitions,
~1,000 inserts/sec. Adding an index is not the answer: at 28M rows/day the write cost lands on the
collector. Per-user destinations/applications are therefore NOT POSSIBLE (no `src_ip` in
`syslog_app_hourly`/`syslog_blocked_dst_hourly` grain) and are not approximated. Closing that gap
needs a rollup schema change, not a query change.

⛔ **`src_user` (PAN User-ID) is populated and is a genuinely better source for some questions** —
cheaper, independent, no IP-reuse hazard — but it measures a DIFFERENT fact (all traffic under that
identity, including on-LAN). Deliberately not shown beside session-derived numbers, because
presenting both invites conflation. Revisit as its own view, not as a column here.

## VPN Detections (`/vpn?vtab=detections`, added 2026-09-10, v2.100.0)

Six named detections over `syslog_vpn_auth_hourly`, computed at READ time — no table, no cron job,
no env var. Full detail in `.ai-codex/lib.md`; the rules that must not drift:

⛔ **A THIN BASELINE IS NOT A CLEAN BASELINE.** Each detection reports
`measured` / `insufficient_baseline` / `no_data` with the baseline it needed and the baseline that
exists. Two of the six are gated today (history is ~1 day; new-country needs 7, off-hours 14) and
render as a HATCHED, HUELESS panel — never a green all-clear. "We have never seen this user" and
"this user has never done this" are separate code paths, because rendering them the same way is this
file's own failed-read-as-a-fact bug in detection form.

⛔ **An unjudgeable observation is COUNTED, never dropped** (`unverifiable[]` + an always-exact
`unverifiableTotal`). Dropping it makes a coverage gap look like a clean result.

⛔ **A device that logs failures but not successes is excluded from every success-dependent
detection, and the cost is accepted.** The fleet's strongest brute-force candidate (Panama, ≥57
attempts, breadth 1) is reported UNVERIFIABLE rather than asserted, because only success-blind
devices saw it. Asserting it would mean concluding "everyone fails here" from a reporting gap.

⛔ **`country_change` IS NOT IMPOSSIBLE TRAVEL.** No city and no lat/lon exists anywhere in this
codebase (`syslog_events` carries `src_country` only), so there is no distance/velocity model to
build and none may be implied. Do not rename it, and do not invent coordinates for a country.

⛔ **Thailand stays unflagged because of the SUCCESS GATE, not a country allowlist** — Thai NAT
gateways do reach spray-shaped username counts but also have successes. Never add a geographic
allowlist; it breaks the moment an attacker uses a local host.

⛔ **`credential_spray` reuses `vpnAuthStats.findUsernameSprayers()` UNCHANGED.** Two files deciding
"is this a sprayer" independently would eventually disagree.

## VPN Session History (`vpn_sessions`, added 2026-09-10, v2.99.0)

Every VPN poll already returned username, `assigned_ip`, `login_time` and `client` for each connected
user — measured live, **187 of 187 rows populated** — and `storeVpnSessions()` DELETE+reinserted
`vpn_active_sessions` on every poll, so all of it was DISCARDED every `VPN_POLL_INTERVAL_MINUTES`.
Only a bare count survived, in `vpn_session_snapshots`. Every question an operator actually asks about
VPN — who was connected, when, for how long, from where — was unanswerable not because SecVault could
not see it, but because it threw it away.

`vpn_active_sessions` keeps its meaning UNCHANGED: exactly who is connected RIGHT NOW. `vpn_sessions`
is the history beside it, written in the SAME transaction.

⛔ **The natural key is `(device_id, username, login_time)`, not a per-poll row.** `login_time` is the
DEVICE'S OWN report of when the session began, so it is stable across polls: the same triple seen in
ten consecutive polls is ONE session upserted ten times, not ten rows. That is ~180 rows/day instead
of ~8,640, and it is what makes a year of history affordable.

⛔ **A FAILED poll must never end anything.** End-detection runs only after `getVpnSessionSummary()`
has already resolved, inside the same `try` — a throw jumps to the per-device catch and cannot reach
it. Otherwise one unreachable firewall would fabricate a mass disconnection of every user on it. The
placement is load-bearing and pinned by two tests (a source-property test, plus a repo scan asserting
`SET ended_at =` against `vpn_sessions` appears in exactly one file).

⛔ **`ended_at = last_seen_at`, never `now()`**, and `ended_at IS NULL` means STILL CONNECTED AS OF
`last_seen_at` — never "ended at an unknown time". A session listed again by a successful poll has
`ended_at` cleared unconditionally: it never really ended, our sampling did.

⛔ **Upsert uses `COALESCE(EXCLUDED.x, vpn_sessions.x)`, not bare `EXCLUDED.x`** — a field the device
omits on one poll must not erase one it reported earlier.

⛔ **DURATION IS A LOWER BOUND WITH A KNOWN ERROR BAR, and every consumer is told so.** The START is
exact (the device reported it); the END is only known to within one poll interval. Rows carry
`duration_is_lower_bound: true` and `duration_precision_seconds` (the interval in force when that row
was written, or NULL when it was unknown — an unknown error bar reads as unknown). True duration lies
in `[duration_seconds, duration_seconds + duration_precision_seconds]`. **A session shorter than the
poll interval may never be observed at all** — this is a SAMPLE of connections, not a complete
register, and no UI may report "total connected time" without saying so.

⛔ **A negative duration is not a number and not a zero.** It becomes `duration_seconds: null` with
reason `clock_mismatch` — it is proof the device's clock/zone disagrees with the server's, not a
measurement.

⛔ **The device's OWN epoch wins over parsing its display string.** PAN-OS reports BOTH on every
session — `"login-time":"Sep.10 09:03:53"` and `"login-time-utc":"1789005833"` — and
`resolveLoginTime()` prefers the epoch (verified live: that value is `2026-09-10T02:03:53Z`, exactly
the displayed time at +07). Inferring a year and a zone that the source already stated verbatim is
the same mistake as recording a failed read as a fact, in a quieter register; the epoch is also the
only thing that stops a firewall in a different timezone from the host skewing a duration.

⛔ **The string fallback still exists and still matters** — no other vendor supplies an epoch today.
When it is used: the live format is `Sep.09 01:31:51` — no year, no timezone. The year is inferred
as the most recent one in which that month/day/time is not in the future (a session cannot start in
the future), stable across a New Year boundary so the key never splits one session in two. The zone
assumed is the SERVER'S local zone — the same assumption the fixed-HH:MM cron jobs already make.
Anything missing, empty or unparseable is **counted, never guessed**: the job logs
`N not sessionizable (no usable login_time — connected, but absent from history)`. Live today that
count is **0 of 187**.

⛔ **This is a PALO ALTO history today.** Only Palo Alto's `getVpnSessionSummary()` returns a
per-session array; Fortinet returns a count with no per-user detail and the other four vendors have no
VPN capability wired. Nothing in the engine assumes otherwise — but a UI must not present it as
fleet-wide VPN history.

## Role-Based Access Control

Two roles only, `admin` and `viewer` — no granular permission system (a coarse boundary is safer than a fine-grained one). `viewer` is strictly read-only (cannot acknowledge, run analyses, sync, rotate credentials, manage devices/users/settings); changing your own password is the one exception. `users` table holds `username`, `password_hash`, `role` (no CHECK constraint, validated in app code); `password_hash` is `REVOKE`d from base grants, exposed only via a `users_readonly` view.

`lib/rbac.js` — pure, dependency-free CommonJS: `isAdmin(session)`, `forbiddenResponse()` (403 JSON). Does NOT resolve its own session — every route calls `getServerSession(authOptions)` itself, then checks `if (!isAdmin(session)) return forbiddenResponse();`. Applied to every mutating (POST/PUT/DELETE/PATCH) route; GET routes are never gated. **A non-mutating POST that only computes over already-collected data and persists nothing is treated like a GET, not gated** — e.g. `POST /api/devices/[id]/access-path` (query-only, no DB write) — the "mutating" test is about persistence, not HTTP verb; don't read the rule as "every POST needs isAdmin." **The JWT's role is re-validated on every token use, not just at sign-in** — `jwt()` re-queries `SELECT role FROM users WHERE id=$1` for local-provider tokens, failing closed on a DB error, so a role change/demotion takes effect immediately rather than waiting for a stale JWT to expire.

**Saved views are the second documented exception to the mutating-route rule** (after "change your
own password"). `POST`/`DELETE /api/saved-views` are NOT admin-gated: a saved view is this user’s
own bookmark and changes no device, no assessment and no score, and a read-only operator who cannot
save the filter they use every morning is being denied the feature for no security benefit. The
rule gates mutations of SHARED SYSTEM STATE. What does the security work is that `user_id` comes
from the SESSION and never the request body, and that the DELETE is owner-scoped inside the SQL
rather than in the route.

`session.user.id` and `session.user.provider` are exposed for this. ⛔ The two providers do NOT
return the same kind of id — local gives a UUID with a `users` row, LDAP gives the bare username
with no row at all — so per-user storage works only for local accounts, and callers check the
SHAPE of the id rather than trusting the provider name.

**LDAP provider limitation, not fixed**: hardcodes `role: 'admin'` for any successful bind, no group-to-role mapping — revisit if a viewer-role LDAP user is ever needed. UI-level hiding of write-action buttons is defense-in-depth only; real enforcement is always the server-side guard.

---

## Feed Sources

| Feed | URL | Schedule | Notes |
|---|---|---|---|
| NVD API 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0` | 6h | 1 req/6s no key, 5 req/30s w/ `NVD_API_KEY`. Always `virtualMatchString`, never `cpeName`. |
| Palo Alto PSIRT | `security.paloaltonetworks.com/api/v1/products/PAN-OS/advisories` | 6h, after NVD | Bulk beta API, ~346 advisories/call, CVE Record Format 5.x. |
| Fortinet FortiGuard | `fortiguard.com/rss/ir.xml` → CSAF 2.0 JSON | 6h, after PA | RSS discovery-only; CSAF is the real data source. |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | 6h | Full download, cross-referenced by cve_id |

Sync order is deliberately **sequential**: NVD → Palo Alto → Fortinet → KEV. Each feed's failure is isolated (its own try/catch) and never blocks the next; each gets its own `feed_sync_log` row.

**NVD → CIRCL fallback** (`vulnerability.circl.lu`) triggers ONLY on a true network-level failure (`err.status == null` — timeout/DNS/connection refused), never on an NVD HTTP error response. `FETCH_TIMEOUT_MS = 20000` on every feed call. Full triggering condition, endpoint, and per-vendor fetch quirks (Palo Alto's beta-bulk-endpoint-only rule, Fortinet's CSAF-over-RSS + 1-second inter-fetch delay): `.ai-codex/cve-pipeline.md`, stages 1-2.

---

## Engine Worker (`services/engine-worker.js`)

Runs as `SecVault-Engine` NSSM service. CommonJS only (not ES modules).

### Scheduled Jobs

| Job | Default interval | Config key |
|---|---|---|
| Feed sync (NVD + KEV) | 6 hours | `FEED_POLL_INTERVAL_HOURS` |
| CVE match + prioritization | After each feed sync | (triggered) |
| Rule + version pull (all devices) | 24 hours | `CONFIG_PULL_INTERVAL_HOURS` |
| Rule analysis (Phase 5) | After each rule pull | (inside `collectAndStore`) |
| Config diff + auto backup (Phase 6) | After each config pull | (inside `collectAndStore`) |
| CVE re-match on config change (Phase 6) | Only when a pull detects a config diff | (triggered by rule-version-pull job) |
| VPN session poll (vendors with `getVpnSessionSummary()`) | 5-59 min | `VPN_POLL_INTERVAL_MINUTES` |
| Device metric poll (job name `snmp-poll`) — `getPerformanceMetrics()` on every active device, else `getSnmpMetrics()` on `snmp_enabled` devices | 5-59 min | `SNMP_POLL_INTERVAL_MINUTES` |
| Fleet dashboard snapshot | Daily, fixed 00:10 **server-local** | (not configurable) |
| Snapshot retention (`vpn_session_snapshots`/`snmp_metric_snapshots`) | Daily, fixed 00:30 **server-local** | `SNMP_VPN_RETENTION_DAYS` |
| VPN session-history retention (`vpn_sessions`) | inside the same 00:30 job, **own window** | `VPN_SESSION_RETENTION_DAYS` |
| Config retention (`device_configs`/`config_backups`) | Daily, fixed 00:45 **server-local** | `CONFIG_RETENTION_DAYS` / `CONFIG_BACKUP_RETENTION_DAYS` |
| Outbound alerting (`notification-dispatch`) | 5-59 min | `NOTIFICATIONS_POLL_INTERVAL_MINUTES` |
| `log_hit` correlation (`log-hit`) | Hourly, fixed `20 * * * *` | `LOG_HIT_LOOKBACK_DAYS` |
| Compliance report (`compliance-report`) | Monthly, fixed `0 6 1 * *` | (not configurable) |

⛔ **These "fixed HH:MM" cron jobs run in the SERVER’S LOCAL ZONE, not UTC.** `node-cron` is
registered with no `timezone` option, so `10 0 * * *` fires at 00:10 **Asia/Bangkok** on the
reference deployment (UTC+7). This table said UTC for a long time and was simply wrong.

It is harmless TODAY only because the value written alongside it is `CURRENT_DATE`, which
PostgreSQL also evaluates in that same local zone — the tick and the date agree. ⛔ Change either
one ALONE — add a `timezone` to the cron, or move the database to UTC — and every `snapshot_date`
shifts by a day while nothing errors and nothing looks broken. If you touch one, touch both.

### Reliability Rules (learned from LogVault collector)

- Each job runs in `try/catch` — **one failed job must never crash the service**. Log start/end/duration/error to `C:\Apps\SecVault\logs\engine.log`.
- On startup: run an immediate feed sync + CVE match before starting scheduled cycles.
- On `SIGTERM`/`SIGINT`: finish current job then exit cleanly (don't kill mid-write).
- Spool pattern for a future log collector: durable write-to-disk before DB insert, replay on restart.

---

## Installer Scripts

`Install-SecVault.ps1` bundles its own prerequisite installers under `installer/dependencies/`
(node/postgres/nssm/git/vcredist + `secvault_deploy`, an ed25519 SSH deploy key for the private
repo) — it doesn't assume any are already on the target server. Gitignored except `README.txt`;
copy from the existing NocVault-Suite distribution package. NSSM is extracted to
`C:\Apps\SecVault\nssm\nssm-2.24\win64\nssm.exe` — always this exact path, never assumed on `PATH`.
`secvault_deploy` is copied to **both** `%USERPROFILE%\.ssh\` (the installing admin's own profile —
pinned via SSH config, `known_hosts` pre-seeded, auth-tested before `git clone`) **and**
`C:\ProgramData\SecVault\ssh\` machine-wide, since the SYSTEM-scheduled update task (below) runs
under a different profile than whoever installed. Both copies must exist — see `gotchas.md`'s Deploy
section.

### Update Script — Exact Order (do not change without testing)

```powershell
# installer/Update-SecVault.ps1
1. sc.exe stop SecVault-App
2. sc.exe stop SecVault-Engine
2b. sc.exe stop SecVault-Collector
3. git pull origin main
4. npm ci
5. node lib/migrate.js          ← schema migration BEFORE start
5b. lib/schema-grants.sql       ← readonly grants, best-effort (never fails the update)
6. npm run build
7. sc.exe start SecVault-Engine
7b. sc.exe start SecVault-Collector   ← before the App: while it is down, UDP syslog is LOST
8. sc.exe start SecVault-App
```

Step 5b re-runs `schema-grants.sql` unconditionally (idempotent) using `PG_ADMIN_PASSWORD` read back out of the deployed `.env.local`; missing/empty value or a `psql` failure only logs a warning, never fails the update.

### NSSM registration

```powershell
& $NssmExe install SecVault-App node
& $NssmExe set SecVault-App AppParameters "node_modules\next\dist\bin\next start -p 3010"
& $NssmExe set SecVault-App AppDirectory "C:\Apps\SecVault"
& $NssmExe set SecVault-App AppEnvironmentExtra "NODE_ENV=production"
```

**⚠️ `AppEnvironmentExtra` casing and `AppParameters` target are both load-bearing** — wrong path casing causes duplicate React instances and silent rendering failures; pointing at `node_modules\.bin\next` (npm's POSIX shell wrapper, not JS) crashes on every start while `sc.exe start` still reports success. Full explanation of both: `gotchas.md`'s Services section. Always use `node_modules\next\dist\bin\next`.

Uninstall removes services via `sc.exe delete` — no NSSM path needed.

---

## In-App Updater

Detection is **live, no DB caching**, via git's own transport — NOT the GitHub REST API (tried and
abandoned suite-wide after rate-limiting under a shared corporate egress IP). `lib/updateCheck.js`:
`git rev-parse HEAD` (local) vs `git ls-remote origin main` (remote); `git fetch --quiet origin
main` + `git show FETCH_HEAD:package.json` for remote version, only once a commit diff is known.
`update_available` = hashes differ — independent of `package.json` version.

Two routes: `GET /api/system/update-status` (full live check, any git/network failure degrades to
safe defaults, never a false-positive; `release_notes` hand-maintained per version) and `GET
/api/system/update-available` (lightweight, cached, polled by the banner every 6h).

**Trigger is a one-time SYSTEM scheduled task, not `child_process.spawn`** — the API runs as a
limited service account that can't reliably start/stop services or survive its own parent service
restarting:
```powershell
schtasks /create /tn "SecVaultUpdate" /tr "powershell.exe -NonInteractive -ExecutionPolicy Bypass -File \"<repoRoot>\installer\Update-SecVault.ps1\"" /sc once /st 00:00 /f /ru SYSTEM
schtasks /run /tn "SecVaultUpdate"
```
Returns `{started:true}` immediately. The progress UI polls `GET /api/health` every 2s through a
`starting → down → back_up` state machine (a probe must be observed failing before success counts
as "recovered"; 3 consecutive healthy probes required), then compares `current_commit` to declare
success vs. `verify_failed`.

**Past silent-no-op git pull, root cause**: `core.sshCommand` is interpreted by git's bundled MSYS2
shell, which silently eats Windows path backslashes — build it with forward slashes only. Testing
`ssh` by hand does NOT exercise this (bypasses `core.sshCommand`). Full detail: `gotchas.md`'s Deploy
section.

---

## Environment Variables

Complete list of all `.env.local` variables. Every variable referenced in code must be here.

```bash
# Server
SERVER_IP=
APP_PORT=3010

# Database
DATABASE_URL=postgresql://secvault_user:PASSWORD@SERVER_IP:5432/secvault

# Auth (standalone — not shared with NocVault suite)
NEXTAUTH_URL=http://SERVER_IP:3010
NEXTAUTH_SECRET=                           # Generate: openssl rand -base64 32

# Credentials encryption (SEPARATE from NEXTAUTH_SECRET)
CREDENTIAL_KEY=                            # 32-byte hex — generate at install

# LDAP/AD (optional — leave blank for local admin only)
LDAP_URL=
LDAP_BASE_DN=
LDAP_BIND_DN=
LDAP_BIND_PASSWORD=

# SMC
ALLOW_SELF_SIGNED_SSL=true                 # Accept self-signed certs from SMC

# Feeds
FEED_POLL_INTERVAL_HOURS=6
CONFIG_PULL_INTERVAL_HOURS=24
NVD_API_KEY=                               # Optional — increases NVD rate limit
VPN_POLL_INTERVAL_MINUTES=30               # 5-59
SNMP_POLL_INTERVAL_MINUTES=15              # 5-59
SNMP_VPN_RETENTION_DAYS=180                # vpn_session_snapshots + snmp_metric_snapshots cleanup
VPN_SESSION_RETENTION_DAYS=365              # vpn_sessions history. Ages on last_seen_at, NOT login_time,
                                           # so a session still being observed is never deleted however
                                           # long it has been up. Deliberately longer than both
                                           # neighbours: one row per CONNECTION (~180/day), and these
                                           # rows are the durable index into evidence that is itself
                                           # short-lived (SYSLOG_RETENTION_DAYS is 30).
CONFIG_RETENTION_DAYS=60                   # device_configs snapshot retention
CONFIG_BACKUP_RETENTION_DAYS=365           # config_backups ('auto' label only)
NOTIFICATIONS_POLL_INTERVAL_MINUTES=15     # 5-59

# Syslog ingestion (Phase 8 — SecVault-Collector)
SYSLOG_UDP_PORT=514,1514                   # comma-separated; FWA held 514 during migration
SYSLOG_TCP_PORT=514,1514
SYSLOG_FLUSH_MS=2000                       # spool+insert cycle
SYSLOG_MAX_BUFFER=200000                   # in-memory datagrams; overflow is COUNTED, not hidden
SYSLOG_RETENTION_DAYS=30                   # raw events; enforced by DROPPING partitions
SYSLOG_RAW_MESSAGE=security                # all|security|none -- which events keep the raw text.
                                           # `security` is what makes 30 days fit: it drops the
                                           # raw line for ordinary allowed traffic (~89% of rows)
                                           # and KEEPS it for threat/vpn/utm/denied. Junk value
                                           # falls back to `security`, never to `all`.
SYSLOG_SPOOL_RETRY_MINUTES=30              # how long a spool file keeps being retried before
                                           # quarantine. ⛔ TIME-based, not attempt-based: the old
                                           # 5-attempt budget expired in ~10 SECONDS at a 2s flush,
                                           # and nothing ever re-read a quarantined `.failed` file,
                                           # so a one-minute DB blip stranded ~78,000 events for
                                           # good. Startup now re-arms `.failed` back to `.ready`.
SYSLOG_SPOOL_DIR=                          # durable spool, fsync'd before the DB insert;
                                           # blank = <install dir>\spool. Installer sets it.
SYSLOG_DETAIL_RETENTION_DAYS=30            # per-host/app/blocked-dst rollups (high cardinality)
SYSLOG_ARCHIVE_ENABLED=true                # compressed raw-log archive (FWA storage model)
SYSLOG_ARCHIVE_DIR=                        # blank = <install dir>archive
SYSLOG_ARCHIVE_RETENTION_DAYS=60           # ~500 GB at 8.4 GB/day measured
SYSLOG_ROLLUP_RECENT_HOURS=1               # frequent narrow re-aggregation (+1h; was 3, overran the cycle)
SYSLOG_ROLLUP_LOOKBACK_HOURS=24            # hourly WIDE sweep, SLICED 6h/pass; catches late-arriving events
SYSLOG_ROLLUP_INTERVAL_MINUTES=5
LOG_HIT_LOOKBACK_DAYS=7                    # [log-hit] window; SHORTER than retention on purpose

# Log retention
LOG_RETENTION_HOT_DAYS=90
LOG_RETENTION_WARM_DAYS=365

# Suite integration (optional — leave blank for standalone)
NETVAULT_URL=
```

---

## Design System — SecVault's own (rewritten 2026-09-09, v2.87.0)

⛔ **No longer aligned with the NocVault suite.** Until 2026-09-09 `app/globals.css` was a port of
the shared suite token file (NetVault/LogVault/DDIVault/SpanVault are byte-for-byte identical on
tokens) plus one `--accent-teal` addition. It now carries SecVault's own palette, type scale and
spacing scale. **Do not resync this file with the siblings, and do not copy changes from it into
them.** The cost of the divergence is two token sets to maintain; it was accepted because SecVault
is a separate product with its own auth, DB and server, and because the shared palette contained a
defect this product could not carry (below).

- **No Tailwind** — unchanged and still load-bearing. Plain CSS custom properties + inline
  `style={{}}` + a shared hand-written utility-class set, all in `app/globals.css`. Do not
  reintroduce a CSS framework.

### ⛔ Colour means RISK — the rule the palette exists to enforce

`--primary` was `#C8102E`, the shared suite red, and drove every button, link, focus ring and
active state — while `--red` (`#dc2626`) meant "this firewall is critically exposed". One hue
family doing both jobs, so the product's most urgent signal competed with its own Save button.
**Red is now reserved for danger and nothing else**; every interactive affordance uses `--primary`,
which is SecVault's own teal.

⛔ **That separation only holds because `--sev-low` is SLATE, not blue.** Dropping blue out of the
severity ramp is what keeps the brand hue unambiguous. Putting blue back into severity collapses
the whole scheme — do not.

⛔ **NOT MEASURED is a first-class visual state with NO HUE**: `--unmeasured` for the text/em-dash,
`--hatch` for a bar segment or swatch. This is CLAUDE.md's own failed-read-as-a-fact rule made
visible on screen. A null hit count, a device with no ruleset, a compliance check SecVault cannot
ask — none of these may be drawn as a zero, a pass, or a reassuring grey that reads as fine.

### Themes

- **Dual theme, light default**: `localStorage['secvault-theme']`, applied as `data-theme="dark"` on
  `<html>` (not a class, not `prefers-color-scheme` alone) by a blocking inline `<script>` in
  `app/layout.js`'s `<head>` before first paint; a `secvault:theme` window event keeps every
  `ThemeToggle` in sync.
- ⛔ **CHANGED: brand and status hues now flip between themes.** The old file froze them across both
  themes deliberately. That is affordable for a saturated red and wrong for anything else —
  `#0A8FA3` teal is correct on white and goes muddy on a near-black ground; `#17825A` green reads
  almost black. Each dark value is re-picked for that ground, not algorithmically inverted.
- **Any tinted surface behind text MUST use a `--tint-*`/`--tint-*-fg` pair**, never a hardcoded hex.
- ⛔ **EXCEPT on the shell.** The header and sidebar are dark in BOTH themes, so `--tint-*-fg` is
  wrong there — it flips, and in light mode a flipped fg is a dark colour on a dark bar, i.e.
  invisible. Text and icons sitting on `--navy` use `--shell-fg` / `--shell-fg-ok` /
  `--shell-fg-bad`, which do not flip.

### Table density (v2.88.0)

A third member of the theme/corners family: `lib/density.js` stamps `data-density` on `<html>`,
with a no-flash inline script in `app/layout.js` and a control in Settings -> Appearance. Three
values, `comfortable` (default) / `compact` / `dense`.

It exists because one row height cannot serve this product: a device on the reference fleet has
**706 firewall rules**, and the analyst auditing that ruleset and the manager reading a compliance
score want opposite things. `comfortable` is the default because it reads best to someone seeing
the product for the first time, who has not found the switch yet.

⛔ Row geometry resolves through `--row-pad-y` / `--row-pad-x` / `--row-font`. A cell that
hardcodes `padding: 12px 16px` opts ITSELF out silently and sits at one height while the table
around it changes — the same failure mode as a hardcoded `border-radius` under the corners switch.

⛔ **Density changes ROW GEOMETRY ONLY.** It must never hide a column, truncate a value or drop a
badge. A denser table shows the same facts in less space, not fewer facts — otherwise the control
becomes a data-integrity setting an operator can get wrong from a dropdown.

### Navigation (v2.88.0)

Twelve flat destinations became four groups — **Monitor / Inventory / Risk / Access** — plus a
pinned Settings, in `components/layout/Sidebar.js`. Labels were renamed to the operator’s language:
Dashboard->Overview, Devices->Firewalls, Rule Analysis->Rule hygiene, Vulnerability->Vulnerabilities,
VPN->VPN & identity.

⛔ **HREFS ARE UNCHANGED.** Only labels moved, so every bookmark, every link inside an already-sent
notification and every URL pasted into a ticket still resolves. Do not "finish the job" by renaming
the routes.

⛔ Every nav entry must keep a DISTINCT GLYPH. That, not colour, is the per-item wayfinding cue —
the active chip is always the brand accent (see the note in `Sidebar.js` for why the old per-item
hues were wrong and why the comment defending them was factually incorrect).

⌘K/Ctrl+K opens the existing header search rather than a second overlay; it also matches PAGES
client-side off the nav list. ⛔ `PAGE_KEYWORDS` there carries the OLD names on purpose — someone
who has used this for a year will type "devices" long after the label became "Firewalls", and a
palette that answers "no results" to the product’s own former vocabulary is worse than none.

### Tokens (`app/globals.css` is authoritative)

Brand `--primary`/`--primary-dark`/`--primary-light`/`--focus-ring`/`--accent-teal` · shell
`--navy*`, `--shell-fg*` · surfaces `--bg-primary`/`--bg-card`/`--surface-subtle`/`--border`/
`--border-light` · text `--text-primary`/`--text-secondary`/`--text-muted` · status
`--red`/`--orange`/`--yellow`/`--green`/`--blue`/`--purple`/`--teal` with semantic aliases
`--sev-crit`/`--sev-high`/`--sev-med`/`--sev-low`/`--sev-ok` (prefer the aliases in new code) ·
unmeasured `--unmeasured`/`--hatch` · tints `--tint-{info,success,warn,danger,purple,teal,orange}`
and `-fg` · **space `--s1`(4px) … `--s9`(96px)** · radius `--radius-sm`/`--radius`/`--radius-lg`/
`--radius-pill` · type `--text-xs` … `--text-3xl`, `--font-sans`, `--font-mono`.

Density adds `--row-pad-y` / `--row-pad-x` / `--row-font`.

⛔ **Spacing is a token scale now.** Before the rewrite there was none: 14 distinct inline gap
values (including 1, 3, 5, 7 and 14px) and five near-identical paddings doing the same job. A
component that invents its own 7px gap opts itself out of every future spacing change silently,
exactly the way a hardcoded hex opts out of the palette.

### Fonts — SELF-HOSTED, never a CDN

⛔ `globals.css` used to open with `@import url('https://fonts.googleapis.com/…Inter…')`. SecVault
installs on an on-premises firewall-management server, frequently segmented or air-gapped, where
that request **fails silently** and the whole product renders in the browser default — for exactly
the customers most likely to buy it, with no error anywhere. IBM Plex Sans/Mono (OFL) are vendored
into `public/fonts/` and declared with `@font-face`. Do not reintroduce a font CDN and do not add a
font npm package: `Update-SecVault.ps1` runs `npm ci`, and a font is a static asset, not a
dependency.

### The rest

- **Icons**: hand-rolled in `components/icons.js`, Feather-compatible convention. Never add an icon
  library. ⛔ Every sidebar entry must keep a DISTINCT GLYPH — that, not colour, is the per-item
  wayfinding cue (the active nav chip is always the brand accent; see the note in `Sidebar.js`).
- Shared `components/ui/`: `Badge`(forwards `title`)/`Button`/`Card`(+sub-parts)/`Table`(enforces
  `tableLayout: 'fixed'`)/`Modal`/`StatusDot`/`EmptyState`/`LoadingSpinner`/`StatCard`(opt-in
  `compact`)/`PageHeader`/`IconChip`/`TimeAgo`.
- Priority band colors: `patch_now`→red "Patch Now", `scheduled`→yellow "Scheduled", `monitor`→muted
  "Monitor". KEV badge is a hand-rolled solid-red span, deliberately not a tinted `<Badge>`.

---

## Versioning Policy

- Version tracked in `package.json`
- **Bump patch** on any push that touches UI or logic
- **Bump minor** on new feature or phase completion
- **Bump major** on breaking schema changes or major architectural shifts
- Update detection uses git's own transport (`git ls-remote`/`git fetch`), **not** the GitHub REST
  API — see In-App Updater above. When bumping the version, also add 3-5 bullets to the
  `releaseNotes` object in `app/api/system/update-status/route.js` — no separate CHANGELOG.md.

---

## Other Features (brief reference)

Full component-level detail is in `.ai-codex/components.md` / `pages.md` — kept short here since
none of these carry Critical-Rules-level footguns.

- **Fleet Alerts** (`/alerts`): cross-entity feed of finding/CVE/diff alerts, filterable via query params (`AlertsFilters`), per-row ack (`AlertAckControl`).
- **Outbound Alerting** (`Settings` → `Notifications`, admin-only): Slack/Teams/email/generic-webhook
  notifications for patch_now CVEs, critical compliance failures, and unacknowledged config diffs.
  Named channels (`notification_channels`, mirrors `credential_profiles`' secret-storage shape) each
  filter to a subset of the three alert types (`alert_types TEXT[]`). Dispatched by
  `lib/engines/notificationDispatch.js`, polled by `services/engine-worker.js`'s
  `notification-dispatch` job — decoupled from feed-sync/rule-version-pull (unrelated cadences; a
  slow/dead webhook must never stall real data collection). `notification_dispatch_log` dedupes by a
  per-alert-type stable natural key with a `cleared_at` column (not a one-time row) so a genuine
  re-occurrence (a fixed compliance check failing again, a CVE re-entering `patch_now`) can re-notify
  — critical compliance failures have no acknowledgement mechanism today (see `audit_findings`'s own
  gap, above), so "open" there is simply every currently-failing critical check. A 4th alert type,
  `compliance_report`, routes the monthly fleet compliance PDF (see below) — `email`-only, gated in
  `NotificationsPanel.js` (a Slack/webhook channel opted into it would just be silently skipped by the
  job forever, with no error surfaced).
- **Compliance Reports** (`/compliance` download link, admin `Settings` → `Notifications` for the
  monthly email list): a fleet-wide PDF (fleet summary + per-device scores + a fail/warning findings
  appendix across PCI DSS/ISO 27001/CIS v8/NIST/SANS) — on-demand via `GET /api/compliance/report/pdf`
  (ungated, same as every other compliance GET route) or scheduled via `services/engine-worker.js`'s
  fixed-monthly `compliance-report` job. Rendered by `lib/engines/complianceReport.js` via **`pdfkit`**
  — pure-JS vector PDF drawing, no browser/native process spawned at all — the same convention already
  used successfully by every sibling NocVault suite app (LogVault/DDIVault/SpanVault). This replaced an
  earlier `puppeteer-core` + headless-Edge implementation (v2.41.0-v2.41.3) that worked in every manual
  test but consistently failed to launch specifically when spawned from inside the `SecVault-App`/
  `SecVault-Engine` NSSM Windows services (`LocalSystem`, Session 0) — root cause never conclusively
  identified; pdfkit sidesteps the whole class of "can a browser launch under this service account"
  problems by not needing a browser at all. Cover page/tables/headers-footers are hand-drawn helpers
  (`drawCover`/`drawTable`/`stampHeadersFooters`/`sectionTitle`) ported from `spanvault/api/reportsPdf.js`
  — read-only reference on this dev machine, never a runtime dependency (SecVault has no import/require
  on any sibling suite app's code, per this file's "SEPARATE PRODUCT" rule above). `generateReportPdf(pool)`
  returns a `Buffer` (collected from `doc.on('data'/'end'/'error')`), used identically by the on-demand
  download route and the email-attachment scheduler. `compliance_report_log` tracks one `'success'` per
  calendar month via a **partial unique index** (`WHERE status='success'`), not just app logic — the job
  runs both on cron and once at every service startup, so a real DB constraint is what prevents a
  double-send if a deploy lands near the monthly tick; failed attempts don't block a retry.
- **Rule cleanup loop** (`lib/engines/ruleChangeRequests.js`, `/devices/[id]/analysis?tab=cleanup`,
  v2.93.0): select evidence-backed `unused`/`redundant`/`shadow` rules → a change request → CSV/PDF
  for whoever edits the firewall → **SecVault verifies against the re-collected ruleset whether they
  actually went**. ⛔ The verify half is the reason this exists — listing unused rules is what
  ManageEngine Firewall Analyzer already does; stating whether the change was made is what it
  cannot. There is deliberately no manual "mark as done": a request reaches `verified` only because
  a later `firewall_rules` pull no longer contains the rules. ⛔ An unmeasured `hit_count` is
  REFUSED from a request server-side, never warned about — "we cannot tell whether this rule is
  used" is not a reason to delete it, and `getCleanupCandidates` returns `{eligible, withheld}` so
  the UI cannot silently show a shorter list. ⛔ Verification requires
  `devices.last_rules_collected_at` (stamped ONLY when `getRules()` succeeded) to be STRICTLY newer
  than `submitted_at`; without that, a device whose rule collection is failing would report every
  requested rule as removed, turning a collection outage into a fabricated cleanup. Full detail:
  `.ai-codex/lib.md` + `schema.md`.
- **VPN Summary**: per-device active session count + trend chart, `VPN_POLL_INTERVAL_MINUTES`. Live-polling and per-vendor gaps (Sangfor/Check Point) are tracked in `.ai-codex/connectors.md`'s cross-vendor table, not here.
- **Network Object Catalog**: per-device address/service/group objects from adapter `getObjects()`; the standalone analysis-tab `ObjectsTab` view is flagged unused/duplicate in `components.md` — check before extending.
- **Device Admins tab** (`lib/engines/adminAccountSummary.js` — the FIREWALL's own local admins, NOT SecVault's own users below): per-vendor coverage in `.ai-codex/connectors.md`.
- **Admin Account Summary**: RBAC user list + CRUD, admin-only (`UsersPanel`) — SecVault's own users.
- **Credential Profiles**: reusable named credential bundles, separate from per-device rotation, excluded from readonly grants same as `device_credentials`.
- **SNMP Monitoring**: per-vendor CPU/memory/session metrics, `lowConfidence:true` when only generic MIB-II/HOST-RESOURCES-MIB support exists (no vendor MIB).
- **Rule Reorder Recommendation**: `reorder_candidate` finding type, CSV export via `ReorderTab`.
- **Access Path Query / Network Topology**: see the dedicated "Network Topology & Path Analysis"
  section above — covers both the per-device tool and its fleet-wide multi-hop successor.

---

## Operational Notes

- **NVD CPE matching**: CPE strings are approximate — verify via NVD's own CPE dictionary endpoint. `versionEndIncluding` = up to AND including; `versionEndExcluding` = up to BUT NOT including — reversed, patched devices get marked vulnerable. **A CPE `criteria` version field can carry a wildcard** (e.g. `"10.0.*"`), not just whole-field `*`/`-` sentinels — `branchRangeFromWildcardCriteria` expands it into a bounded range rather than collapsing to a point (which under-reported real vulnerable devices). A code fix doesn't retroactively fix already-persisted values — see `backfillPaloAltoVersionRanges()` (paloalto vendor, both its PSIRT-CVE-Record and NVD-native rows) and `backfillNvdNativeVersionRanges()` (the other five vendors' NVD-native rows only — those vendors have no PSIRT/CSAF feed of their own).
- **Next.js API routes**: every DB-touching route must export `dynamic = 'force-dynamic'`, or `npm run build`'s prerendering step crashes hitting the DB at build time.
- **Schema files**: two files, two privilege levels — never merge `schema-grants.sql` back into `schema.sql`. Every new table needs both a `CREATE TABLE IF NOT EXISTS` entry AND a `GRANT SELECT` entry; both installer scripts apply grants automatically.
- **Rule shadow analysis** is O(n²) against rule count — capped at 1000 rules (warning above threshold, not silently truncated), run off-hours for 500+ rulesets. Address/service object resolution needs all elements loaded before analysis — cache per device per session.
- **Windows Server tool paths and `psql` exit-code quirks**: see `gotchas.md`'s Deploy section.

---

## Testing (`tests/`, added 2026-08-25)

`npm test` — Node 20's **built-in** test runner (`node --test tests/`). Read `tests/README.md`
before adding any.

⛔ **`package.json` has NO `devDependencies`, and that is deliberate — keep it that way.** The
production server installs with `npm ci` in `Update-SecVault.ps1`, so every devDependency would
ship to a firewall-management box for no runtime benefit. `node:test` + `node:assert/strict` are
already in the runtime this app requires, so there is no config file to drift and no transform
between the source and what actually runs in production. Do not add Jest or Vitest without a
concrete reason that outweighs this.

Scope is **the pure engines only** — `ruleAnalysis`, `configAuditor`, `securityScore`,
`riskScore`, `configRetention`. They take data in and return data out, which is exactly what is
cheap to pin and what has actually broken. There is NO route/component/browser test harness, and
nothing here talks to a database: an engine that takes a `pool` gets a STUB that returns canned
rows and records the SQL it was handed. Live verification against the real fleet is still a
separate, required step for anything touching a device — these tests replace neither that nor the
"verify against live responses before writing any parser" rule.

**What a test here is FOR.** Nearly every bug these cover is one class: a failed read recorded as
an affirmative value (`hit_count` defaulting to 0, `getRules()` returning `[]`, an unanswerable
compliance check scored as a `warning`). So a new test must include the **"we could not measure
this"** case, not just the pass and fail cases. That is the one that regresses silently, because
the wrong answer is a plausible number rather than a crash.

These also make CLAUDE.md's own "document before you change it" rules enforceable rather than
advisory: the security-score weights, the risk-score polarity, and retention's four delete
protections are each pinned by a test, so weakening one fails a build instead of silently
shipping.

---

## Claude Code Workflow

### Starting a Session
1. Read CLAUDE.md (this file) completely
2. Run `git log --oneline -5` — know the current state
3. Run `ls -la` — confirm working directory
4. For changes touching vendor adapters: read the relevant adapter files before editing
5. For DB changes: read `lib/schema.sql` before adding new tables

### Parallel Sub-Agents
- Fan out only after foundation work is complete and committed
- Each agent owns specific files — **no file written by more than one agent**
- Provide each agent with a frozen contract (exact file list + exact function signatures)
- Verify agent diffs before integrating — especially adapter parser changes
- High-risk refactors (engine core, credStore, schema changes) done by primary agent, not sub-agents

### Before Committing
```bash
node --check lib/**/*.js services/**/*.js app/api/**/*.js
npm test                                                  # must be zero failures
npm run build                                             # must be zero errors
# If schema.sql changed: verify all new tables have per-table grants for readonly users
# If new env vars added: add to .env.local.example
# Update CLAUDE.md if architectural decisions were made
```

### Deploy After Commit
```powershell
# On production server:
& "C:\Apps\SecVault\installer\Update-SecVault.ps1"
```
