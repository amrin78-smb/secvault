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
| `SecVault-Collector` | `node services/collector.js` | 514 UDP/TCP | Syslog listener (Phase 8 — not yet built) |

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
`activity_log` (operator audit trail), `credential_profiles` (reusable creds, excluded from readonly
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

**Known limitations (by design, not bugs)** — hit counts, gateway resolution, Panorama fallback,
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

---

## Role-Based Access Control

Two roles only, `admin` and `viewer` — no granular permission system (a coarse boundary is safer than a fine-grained one). `viewer` is strictly read-only (cannot acknowledge, run analyses, sync, rotate credentials, manage devices/users/settings); changing your own password is the one exception. `users` table holds `username`, `password_hash`, `role` (no CHECK constraint, validated in app code); `password_hash` is `REVOKE`d from base grants, exposed only via a `users_readonly` view.

`lib/rbac.js` — pure, dependency-free CommonJS: `isAdmin(session)`, `forbiddenResponse()` (403 JSON). Does NOT resolve its own session — every route calls `getServerSession(authOptions)` itself, then checks `if (!isAdmin(session)) return forbiddenResponse();`. Applied to every mutating (POST/PUT/DELETE/PATCH) route; GET routes are never gated. **The JWT's role is re-validated on every token use, not just at sign-in** — `jwt()` re-queries `SELECT role FROM users WHERE id=$1` for local-provider tokens, failing closed on a DB error, so a role change/demotion takes effect immediately rather than waiting for a stale JWT to expire.

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
| SNMP metric poll (vendors with `getSnmpMetrics()`, `snmp_enabled` devices) | 5-59 min | `SNMP_POLL_INTERVAL_MINUTES` |
| Fleet dashboard snapshot | Daily, fixed 00:10 UTC | (not configurable) |
| Snapshot retention (`vpn_session_snapshots`/`snmp_metric_snapshots`) | Daily, fixed 00:30 UTC | `SNMP_VPN_RETENTION_DAYS` |
| Outbound alerting (`notification-dispatch`) | 5-59 min | `NOTIFICATIONS_POLL_INTERVAL_MINUTES` |

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
3. git pull origin main
4. npm ci
5. node lib/migrate.js          ← schema migration BEFORE start
5b. lib/schema-grants.sql       ← readonly grants, best-effort (never fails the update)
6. npm run build
7. sc.exe start SecVault-Engine
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
NOTIFICATIONS_POLL_INTERVAL_MINUTES=15     # 5-59

# Log retention
LOG_RETENTION_HOT_DAYS=90
LOG_RETENTION_WARM_DAYS=365

# Suite integration (optional — leave blank for standalone)
NETVAULT_URL=
```

---

## Design System — NocVault Suite Alignment (v2.0.0)

SecVault's UI matches the shared NocVault suite design system (NetVault/LogVault/DDIVault/SpanVault
are byte-for-byte identical on tokens; SecVault ports the same `app/globals.css` plus one addition,
`--accent-teal`).

- **No Tailwind** — fully removed, not re-themed. Plain CSS custom properties + inline `style={{}}` + a shared hand-written utility-class set, all in `app/globals.css`. Do not reintroduce a CSS framework.
- **Dual theme, light default**: `localStorage['secvault-theme']`, applied as `data-theme="dark"` on `<html>` (not a class, not `prefers-color-scheme` alone) by a blocking inline `<script>` in `app/layout.js`'s `<head>` before first paint; a `secvault:theme` window event keeps every `ThemeToggle` in sync. Brand/status colors stay the same in both themes — only neutral surfaces and the adaptive `--tint-*`/`--tint-*-fg` pairs flip. **Any tinted surface behind text MUST use a `--tint-*`/`--tint-*-fg` pair, never a hardcoded hex**, or it won't adapt in dark mode.
- `app/globals.css` is authoritative for tokens: `--primary` (shared suite red `#C8102E`), `--navy`, `--accent-teal` (SecVault's own identity — logo + active sidebar chip only, controls still use `--primary`), status colors, `--tint-{info,success,warn,danger}`/`-fg`.
- **Icons**: hand-rolled in `components/icons.js`, Feather-compatible convention. Never add an icon library.
- Shared `components/ui/`: `Badge`/`Button`/`Card`(+sub-parts)/`Table`(enforces `tableLayout: 'fixed'`)/`Modal`/`StatusDot`/`EmptyState`/`LoadingSpinner`/`StatCard`(opt-in `compact` prop)/`PageHeader`/`IconChip`.
- Priority band colors: `patch_now`→red "Patch Now", `scheduled`→yellow "Scheduled", `monitor`→muted "Monitor". KEV badge is a hand-rolled solid-red span, deliberately not a tinted `<Badge>`.

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
  gap, above), so "open" there is simply every currently-failing critical check.
- **VPN Summary**: per-device active session count + trend chart, `VPN_POLL_INTERVAL_MINUTES`. Live-polling and per-vendor gaps (Sangfor/Check Point) are tracked in `.ai-codex/connectors.md`'s cross-vendor table, not here.
- **Network Object Catalog**: per-device address/service/group objects from adapter `getObjects()`; the standalone analysis-tab `ObjectsTab` view is flagged unused/duplicate in `components.md` — check before extending.
- **Device Admins tab** (`lib/engines/adminAccountSummary.js` — the FIREWALL's own local admins, NOT SecVault's own users below): per-vendor coverage in `.ai-codex/connectors.md`.
- **Admin Account Summary**: RBAC user list + CRUD, admin-only (`UsersPanel`) — SecVault's own users.
- **Credential Profiles**: reusable named credential bundles, separate from per-device rotation, excluded from readonly grants same as `device_credentials`.
- **SNMP Monitoring**: per-vendor CPU/memory/session metrics, `lowConfidence:true` when only generic MIB-II/HOST-RESOURCES-MIB support exists (no vendor MIB).
- **Rule Reorder Recommendation**: `reorder_candidate` finding type, CSV export via `ReorderTab`.

---

## Operational Notes

- **NVD CPE matching**: CPE strings are approximate — verify via NVD's own CPE dictionary endpoint. `versionEndIncluding` = up to AND including; `versionEndExcluding` = up to BUT NOT including — reversed, patched devices get marked vulnerable. **A CPE `criteria` version field can carry a wildcard** (e.g. `"10.0.*"`), not just whole-field `*`/`-` sentinels — `branchRangeFromWildcardCriteria` expands it into a bounded range rather than collapsing to a point (which under-reported real vulnerable devices). A code fix doesn't retroactively fix already-persisted values — see `backfillPaloAltoVersionRanges()` (paloalto vendor, both its PSIRT-CVE-Record and NVD-native rows) and `backfillNvdNativeVersionRanges()` (the other five vendors' NVD-native rows only — those vendors have no PSIRT/CSAF feed of their own).
- **Next.js API routes**: every DB-touching route must export `dynamic = 'force-dynamic'`, or `npm run build`'s prerendering step crashes hitting the DB at build time.
- **Schema files**: two files, two privilege levels — never merge `schema-grants.sql` back into `schema.sql`. Every new table needs both a `CREATE TABLE IF NOT EXISTS` entry AND a `GRANT SELECT` entry; both installer scripts apply grants automatically.
- **Rule shadow analysis** is O(n²) against rule count — capped at 1000 rules (warning above threshold, not silently truncated), run off-hours for 500+ rulesets. Address/service object resolution needs all elements loaded before analysis — cache per device per session.
- **Windows Server tool paths and `psql` exit-code quirks**: see `gotchas.md`'s Deploy section.

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
