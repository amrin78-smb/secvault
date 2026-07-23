# CLAUDE.md — SecVault

> **Read this file completely before making any change to this codebase.**
> Update this file whenever a significant architectural decision is made.

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
- **UUIDs as primary keys** (`gen_random_uuid()`), not SERIAL. Consistent with suite pattern.

### Security
- **NEVER store credentials in plaintext.** All external credentials (SMC API keys, SSH passwords) go through `lib/credStore.js` → `device_credentials` table.
- **NEVER hardcode credentials in source files.** Use `.env.local` (gitignored). Commit `.env.local.example` only.
- **Per-table `GRANT SELECT` for readonly users** — never `GRANT SELECT ON ALL TABLES`. The `device_credentials` table must never be readable by `claude_readonly` or `nocvault_readonly`. Grant per table, explicitly.
- **NEVER commit `.env.local`.** The `.gitignore` must list it.

### PowerShell (PS5 compatibility — Windows Server uses PS5 not PS7)
- `try/catch` cannot pipe directly in PS5. Assign to `$out` first, then pipe:
  ```powershell
  # WRONG (PS7 only):
  try { git pull | Write-Host } catch { }
  # CORRECT (PS5):
  $out = git pull; $out | Write-Host
  ```
- No `-Parallel` on `ForEach-Object` (PS7 only)
- No `-TimeoutSeconds` on `Test-Connection` (PS7 only)
- `$PID` is a reserved variable — use `$procPid` instead
- Write multi-line PS scripts to temp `.ps1` files; never use `-Command` with newlines

### External API Integrations
- **Verify all field names against live responses before writing any parser.** Documentation lies. Vendor APIs return different fields than documented, especially for older firmware. Use curl/fetch to get actual response shapes first.
- **NEVER assume CPE strings, API endpoint paths, or field names from documentation alone.** Test against live systems. Log raw responses during first integration test.

### Pre-Commit Checklist
Run both before every commit:
```bash
node --check lib/**/*.js services/**/*.js   # syntax check all JS
npm run build                               # must pass with zero errors
```

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

### File Structure

```
secvault/
├── CLAUDE.md                        ← you are here
├── package.json                     ← version bumped on every push
├── next.config.js
├── .env.local.example               ← committed (no secrets)
├── .env.local                       ← gitignored (has secrets)
├── middleware.js                    ← route protection (auth gate)
├── app/
│   ├── layout.js                    ← root layout + blocking theme-init <script>
│   ├── globals.css                  ← NocVault suite design tokens + utility classes (no Tailwind)
│   ├── (auth)/login/page.js
│   ├── (dashboard)/
│   │   ├── layout.js                ← sidebar + header wrapper (.sv-shell/.sv-body/.sv-content)
│   │   ├── page.js                  ← main dashboard
│   │   ├── devices/                 ← device inventory
│   │   ├── cve/                     ← fleet CVE posture
│   │   ├── advisories/              ← advisory browser
│   │   ├── analysis/                ← rule analysis dashboard
│   │   └── settings/
│   └── api/
│       ├── auth/[...nextauth]/route.js
│       ├── devices/                 ← CRUD + test/collect/analysis/acknowledgements/diffs/backups
│       ├── advisories/
│       ├── cve/
│       ├── analysis/                ← fleet analysis + run-all
│       ├── feeds/                   ← feed sync trigger + status
│       ├── search/                  ← header search (devices + advisories)
│       ├── notifications/summary/   ← header bell aggregate count
│       └── settings/
├── lib/
│   ├── db.js                        ← PostgreSQL pool singleton
│   ├── schema.sql                   ← tables (CREATE TABLE IF NOT EXISTS, runs as secvault_user)
│   ├── schema-grants.sql            ← readonly roles + per-table grants (runs as postgres superuser)
│   ├── migrate.js                   ← runs schema.sql
│   ├── credStore.js                 ← AES-256-GCM credential encryption
│   ├── theme.js                     ← dual-theme mechanism (localStorage + data-theme + custom event)
│   ├── feedStatus.js                ← shared feed_sync_log query (header pill + Advisories page)
│   ├── activityLog.js               ← operator-action audit trail (never throws)
│   ├── apiUtils.js                  ← isValidUuid() path-param guard
│   ├── feeds/
│   │   ├── nvd.js                   ← NVD API 2.0 client (dual-CPE for Forcepoint)
│   │   ├── kev.js                   ← CISA KEV ingestion
│   │   └── index.js                 ← feed orchestrator
│   ├── adapters/
│   │   ├── interface.js             ← base adapter interface
│   │   └── forcepoint/
│   │       ├── index.js             ← Forcepoint adapter (implements interface)
│   │       ├── smc.js               ← SMC REST API client
│   │       └── parser.js            ← SMC response parser
│   └── engines/
│       ├── versionComparator.js     ← version string → tuple + comparison
│       ├── versionMatcher.js        ← device × advisory matching (+ applicability context)
│       ├── prioritization.js        ← priority band decision tree
│       ├── ruleAnalysis.js          ← Phase 5: 9 rule-hygiene finding types
│       ├── configDiff.js            ← Phase 6: snapshot diff + labeled backups
│       └── applicability.js         ← Phase 6: advisory_conditions predicate evaluator
├── services/
│   └── engine-worker.js             ← SecVault-Engine (scheduled jobs)
├── components/
│   ├── icons.js                     ← hand-rolled SVG icon set (no icon library)
│   ├── ui/                          ← Badge/Button/Card/Table/Modal/StatusDot/EmptyState/
│   │                                   LoadingSpinner/StatCard/PageHeader — plain suite CSS classes
│   ├── layout/                      ← Header (server), Sidebar, HeaderSearch, NotificationBell,
│   │                                   UserMenu, ThemeToggle
│   ├── devices/
│   ├── cve/
│   ├── advisories/
│   ├── analysis/                    ← rule analysis dashboard tabs + charts
│   └── config/                      ← config change/backup/predicate UI
└── installer/
    ├── Install-SecVault.ps1
    ├── Update-SecVault.ps1
    ├── Uninstall-SecVault.ps1
    └── dependencies/                ← bundled prerequisite installers (gitignored except README.txt)
        └── README.txt
```

---

## Database

### Connection Pool (`lib/db.js`)

Singleton pattern — one pool per process, passed as parameter to all functions.

```javascript
const { Pool } = require('pg');
const pool = new Pool({ connectionString: process.env.DATABASE_URL });
module.exports = { pool };
```

**NEVER instantiate a new `Pool` inside a request handler or per-query function.**
**NEVER omit `pool` from any function signature that needs DB access** — silent runtime failures.

### Schema Migration

- `lib/schema.sql` uses `CREATE TABLE IF NOT EXISTS` on every table — safe to re-run
- `lib/migrate.js` runs `schema.sql` via the `pg` client, connected as `secvault_user`
- `lib/schema-grants.sql` (readonly role creation + per-table grants) is a **separate file**, run under
  the `postgres` superuser — **not** run by `migrate.js`, which connects as `secvault_user`. See
  "Readonly Access for Diagnostics" below for why. Both `Install-SecVault.ps1` **and**
  `Update-SecVault.ps1` apply it (Update reads the superuser password back out of the deployed
  `.env.local`'s `PG_ADMIN_PASSWORD` — see the Update Script section) — every statement in the file is
  idempotent (`CREATE ROLE IF NOT EXISTS`, plain `GRANT`), so re-running it on every update is always
  safe, not just when a table was actually added.
- Update script runs `migrate.js` (schema.sql) THEN `schema-grants.sql`, both BEFORE restarting services
  (see Update Script section)
- Never use `DROP TABLE` in schema.sql — destructive and irreversible in production
- **⛔ Adding a column to an EXISTING table? `CREATE TABLE IF NOT EXISTS` will NOT add it on a
  server that already has that table — the whole statement is a no-op there, guarding only table
  *creation*, never column changes. Found live in production 2026-07-18: `audit_findings.matched_rule_ids`
  was added inside the `CREATE TABLE IF NOT EXISTS audit_findings (...)` body; every server that had
  already run the Phase 7 compliance rollout silently kept the old table shape, and the per-device
  Compliance page (the only query selecting that column) crashed with a raw "column ... does not
  exist" Postgres error on every click — the fleet page, which doesn't select it, kept working,
  masking the gap until a user reported the crash directly. Fixed the same day with a companion
  `ALTER TABLE audit_findings ADD COLUMN IF NOT EXISTS matched_rule_ids UUID[];`** — always add BOTH:
  the column in the `CREATE TABLE IF NOT EXISTS` body (for a truly fresh install) AND a matching
  `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` right after it (for every already-deployed server) —
  never just one. This is the exact same class of bug the `device_versions.serial` fix already fixed
  once before (search this file for it) — a genuinely easy mistake to repeat because the CREATE
  TABLE body still LOOKS correct in a diff.

### Primary Keys

All tables use `UUID` PKs with `gen_random_uuid()`, not `SERIAL`.
(SERIAL vs UUID was a schema debt issue in NetVault — do not repeat it here.)

```sql
id UUID PRIMARY KEY DEFAULT gen_random_uuid()
```

### Key Tables

| Table | Purpose | Phase |
|---|---|---|
| `settings` | App config + local admin password hash | 1 |
| `devices` | Firewall inventory (vendor, mgmt_ip, smc_host, criticality) | 2 |
| `device_versions` | Running firmware history per device | 2 |
| `device_credentials` | AES-256-GCM encrypted creds (credStore) | 2 |
| `device_configs` | Config snapshots (jsonb) | 2 |
| `firewall_rules` | Normalized rule extraction across all vendors | 2 |
| `advisories` | Normalized CVE advisory store (all feed sources). `cwe_ids TEXT[]` + `vulnerability_category TEXT` (added Dashboard Rebuild — see `lib/engines/vulnerabilityCategory.js`) extracted from each feed's own raw CWE shape at ingest, vendor-ownership-guarded on conflict same as every other non-neutral column | 1 |
| `advisory_conditions` | Applicability predicate rules (curated data, evaluated by Phase 6 engine) | 1 |
| `device_cve_assessments` | Per-device CVE match results + priority bands | 3 (built in this Phase 1+2 pass ahead of schedule for the matcher/prioritization engines) |
| `vendor_recommended_releases` | Manually-maintained mature/preferred release table | 2/3 |
| `feed_sync_log` | Feed run history (NVD, KEV) | 1 |
| `config_diffs` | Structured diffs between config snapshots | 6 ✅ |
| `config_backups` | Labeled config snapshots (auto/manual/pre-change) for download | 6 ✅ |
| `rule_analysis_results` | Rule hygiene findings (unused, shadow, risky, etc.) | 5 ✅ |
| `finding_acknowledgements` | Operator status per finding (new/acknowledged/dismissed/actioned), keyed on `rule_id_vendor` not `firewall_rules.id` | Dashboard Phase 2 ✅ |
| `device_risk_history` | Risk-score snapshot per completed analysis run (scheduled or manual) | Dashboard Phase 4 ✅ |
| `activity_log` | Operator-action audit trail (run analysis, acknowledge finding/diff) — not a general app log | Dashboard Phase 4 ✅ |
| `cve_assessment_acknowledgements` | Operator status per patch-now CVE assessment (new/acknowledged/dismissed/actioned), keyed on `(device_id, advisory_id)` — mirrors `finding_acknowledgements`, since `device_cve_assessments` has no ack column of its own | Fleet Alerts Page ✅ |
| `firewall_logs` | Ingested syslog events (with retention expiry) | 8 (not yet created) |
| `audit_checks` | Compliance check library (curated, seeded via `lib/auditChecksSeed.js`) — `standards` is `TEXT[]`, not singular, since one check can score against multiple standards at once | 7 ✅ |
| `vpn_session_snapshots` | Polled active-VPN-session-count timestamps (Fortinet only — `getVpnSessionSummary()`), a coarse substitute for real syslog-derived VPN usage telemetry | VPN Summary ✅ |
| `audit_findings` | Per-device compliance results (pass/fail/warning/na), DELETE+reinsert per device per run like `rule_analysis_results` | 7 ✅ |
| `fleet_dashboard_snapshots` | One row per calendar day (`snapshot_date` UNIQUE), fleet-wide CVE severity counts + compliance scores — feeds the main Dashboard's day-over-day deltas, populated by a daily `engine-worker.js` job | Dashboard Rebuild ✅ |
| `credential_profiles` | Reusable named credential bundles (`credential_type`-scoped, not vendor-scoped), copied into a device's `device_credentials` at apply-time — no FK, no live reference. Excluded from `claude_readonly`/`nocvault_readonly` entirely, same as `device_credentials` | Credential Profiles ✅ |
| `snmp_metric_snapshots` | Polled SNMP metric snapshots (CPU/memory/session-count/uptime) — only successful polls insert a row, same lifecycle as `vpn_session_snapshots` | SNMP Monitoring ✅ |
| `advisory_signatures` / `device_cve_log_hits` | Exploitation correlation | 8 (not yet created) |

Tables marked "not yet created" are part of the full architecture (see repo root architecture doc in project history) and will be added via new `CREATE TABLE IF NOT EXISTS` statements in their respective phases — do not pre-create empty tables for features that are not yet implemented.

### Readonly Access for Diagnostics

Two readonly users exist for Claude Code to query the live DB directly:
- `claude_readonly` / `ClaudeRead@2026!`
- `nocvault_readonly` / (same)

**These users must NEVER have access to `device_credentials`.** Grant per-table explicitly, in `lib/schema-grants.sql` — **NOT** in `lib/schema.sql`:
```sql
-- Grant after creating each new table:
GRANT SELECT ON TABLE new_table_name TO claude_readonly;
GRANT SELECT ON TABLE new_table_name TO nocvault_readonly;
-- Exception: device_credentials — NEVER grant to these users
```

**Second exception: `settings`, granted via a VIEW, never the base table.** `settings` stores the
local admin's bcrypt hash under `key='admin_password_hash'` — the app's own `HIDDEN_KEYS` filter
(`app/api/settings/route.js`) only hides that row from the HTTP API, not from raw SQL. A blanket
`GRANT SELECT ON TABLE settings` was found in a full-app audit (2026-07-16) to let these roles read
the hash directly. Fixed with `REVOKE SELECT ON TABLE settings ...` (required, not just deleting the
old `GRANT` line — this file is re-applied on every update, and only `REVOKE` undoes a privilege a
previous run already granted on a live database) plus a `settings_readonly` view excluding that one
row, granted instead of the table. Any new secret-bearing row added to `settings` in the future needs
the same treatment — a view excluding it, not a bare table grant.

**Why a separate file:** `lib/schema.sql` runs via `lib/migrate.js`, which connects as `secvault_user` — an account that only has `GRANT ALL PRIVILEGES ON DATABASE`, not `CREATEROLE`/superuser. `CREATE ROLE` inside `schema.sql` would throw a permission error, and because a multi-statement `pool.query()` call is one implicit transaction, that failure would roll back every `CREATE TABLE` in the same call — silently breaking every fresh install. `lib/schema-grants.sql` is applied separately, under the `postgres` superuser (`psql -U postgres -d secvault -f lib/schema-grants.sql`), after the tables it grants on already exist, and its failure is logged as a warning, never fatal — these roles are diagnostic-only and not required for the app to function.

**Applied automatically by both installer scripts** — no manual step needed after adding a new table's `GRANT SELECT` line. `Install-SecVault.ps1` runs it with the just-generated superuser password (still in scope at that point in the script); `Update-SecVault.ps1` runs it too, reading the same password back out of the already-deployed `.env.local`'s `PG_ADMIN_PASSWORD` value (originally persisted there "for later reference" — this is that reference, used programmatically). Safe to re-run unconditionally on every update because every statement in the file is idempotent. If `.env.local` predates `PG_ADMIN_PASSWORD` (an install from before this was added) or the value is empty, the Update step logs a warning and skips — it never fails the update.

---

## credStore — Credential Encryption

All external credentials (SMC API keys, SSH passwords) encrypted before DB storage.

### Pattern (inherited from DDIVault, adapted for SecVault)

```javascript
// lib/credStore.js
const crypto = require('crypto');
const ALGORITHM = 'aes-256-gcm';

// Key source: CREDENTIAL_KEY env var (32-byte hex, generated at install)
// NOT derived from NEXTAUTH_SECRET (SecVault is standalone — no suite secret)
function getKey() {
  const hex = process.env.CREDENTIAL_KEY;
  if (!hex || hex.length !== 64) throw new Error('CREDENTIAL_KEY missing or invalid');
  return Buffer.from(hex, 'hex');
}

// Stored format in device_credentials: encrypted_data (hex), iv (hex) — separate columns
// NOT the "iv:tag:enc" single-column format used in DDIVault
// SecVault stores as separate columns for cleaner querying

function encrypt(plaintext) {
  const key = getKey();
  const iv = crypto.randomBytes(12);
  const cipher = crypto.createCipheriv(ALGORITHM, key, iv);
  const enc = Buffer.concat([cipher.update(plaintext, 'utf8'), cipher.final()]);
  const tag = cipher.getAuthTag();
  // Returns: { encrypted: hex string, iv: hex string, tag: hex string }
  return {
    encrypted: enc.toString('hex') + ':' + tag.toString('hex'),
    iv: iv.toString('hex')
  };
}

function decrypt(encrypted, iv) {
  const key = getKey();
  const [encHex, tagHex] = encrypted.split(':');
  const decipher = crypto.createDecipheriv(ALGORITHM, key, Buffer.from(iv, 'hex'));
  decipher.setAuthTag(Buffer.from(tagHex, 'hex'));
  return Buffer.concat([
    decipher.update(Buffer.from(encHex, 'hex')),
    decipher.final()
  ]).toString('utf8');
}
```

### Key Generation (at install time)

```powershell
# In Install-SecVault.ps1:
$credKey = [System.BitConverter]::ToString(
  (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes(32)
).Replace('-','').ToLower()
# Write to .env.local: CREDENTIAL_KEY=$credKey
```

---

## Authentication

### Standalone (default, no suite dependency)

NextAuth 4.24.7 with two providers:
1. **Local admin** — username + bcrypt hash stored in `settings` table (`key='admin_password_hash'`)
2. **LDAP/AD** — optional, configured via `LDAP_URL` + `LDAP_BASE_DN` in `.env.local`

Session: JWT strategy. NEXTAUTH_SECRET generated at install (separate from suite NEXTAUTH_SECRET).

### Optional Suite Integration

If `NETVAULT_URL` is set in `.env.local`, SecVault can optionally federate SSO to NetVault.
Default: disabled. Do not implement suite SSO as a default code path.

### Middleware (`middleware.js`)

- Protect all `/(dashboard)` routes — redirect unauthenticated users to `/login`
- Allow `/login`, `/api/auth/*` without auth
- API routes return `401` for unauthenticated requests (not redirect)

---

## Supported Vendors (Tier 1) — Slugs, Credentials, Dispatch

Six vendors are implemented. The slug is load-bearing: it must match across `devices.vendor`,
`VENDOR_PARSERS` in `lib/engines/versionComparator.js`, `ADAPTERS` in `lib/adapters/index.js`,
`VENDOR_CPES` in `lib/feeds/nvd.js`, and `VENDOR_META` in `components/devices/vendorMeta.js`.
Never invent a new spelling.

**A vendor can support more than one access method.** `devices.mgmt_method` is *chosen by the
operator* in the Add Device form (from that vendor's `accessMethods`) — it is NOT derived from
the vendor slug. Adapter dispatch is `(vendor, mgmt_method) → adapter class`.

| slug | mgmt_method | Access | Connection fields | credential_type | Credential plaintext |
|---|---|---|---|---|---|
| `forcepoint` | `smc` | SMC REST :8082 | `smc_host` + `smc_port` (8082) | `smc_api` | raw API key string (RAW, not JSON — legacy, works, don't "tidy") |
| `fortinet` | `api` | REST API | `mgmt_ip` + `mgmt_port` (443) | `rest_api` | JSON `{"api_key"}` or `{"username","password"}` |
| `fortinet` | `ssh` | SSH | `mgmt_ip` + `mgmt_port` (22) | `ssh` | JSON `{"username","password"}` |
| `paloalto` | `api` | XML API (user/pass → `?type=keygen` → key) | `mgmt_ip` + `mgmt_port` (443) | `rest_api` | JSON `{"api_key"}` or `{"username","password"}` |
| `paloalto` | `ssh` | SSH | `mgmt_ip` + `mgmt_port` (22) | `ssh` | JSON `{"username","password"}` |
| `checkpoint` | `api` | Mgmt API (mgmt server IP, **not** gateway) | `mgmt_ip` + `mgmt_port` (443) | `rest_api` | JSON `{"api_key"}` or `{"username","password"}` |
| `cisco_asa` | `ssh` | SSH | `mgmt_ip` + `mgmt_port` (22) | `ssh` | JSON `{"username","password","enable_password"?}` |
| `sangfor` | `ssh` | SSH | `mgmt_ip` + `mgmt_port` (22) | `ssh` | JSON `{"username","password"}` |

Forcepoint is SMC-only **by design** — CLAUDE.md's core rule is never to SSH to Forcepoint engines.

Credential plaintext is written by `buildCredentialPlaintext(vendor, accessMethod, {...})`
(vendorMeta.js) and read by `parseApiCredential()` (`lib/adapters/credentials.js`) for API
vendors / `parseJsonCredential()` (`lib/adapters/sshClient.js`) for SSH vendors. `parseApiCredential`
also accepts a **bare non-JSON string** as an api-key — that is deliberate backward compatibility
for fortinet/paloalto devices added before access-method selection existed. Don't remove it.

#### ⚠️ Two registries, deliberately duplicated — keep them in step

`components/devices/vendorMeta.js` is an **ES module** (client components import it).
`lib/adapters/index.js` is **CommonJS** (`services/engine-worker.js` `require()`s it under plain
node, which cannot require ESM). So the dispatcher cannot import the vendor table, and these two
must be updated together:

| vendorMeta.js (ESM) | lib/adapters/index.js (CJS) |
|---|---|
| `VENDOR_META[slug].accessMethods` keys | `ADAPTERS[slug]` inner keys |
| `VENDOR_META[slug].defaultAccessMethod` | `DEFAULT_METHOD[slug]` |

Drift here is a silent runtime bug (the form offers a method dispatch can't honour, or a legacy
row falls back to the wrong transport). Same class of cross-registry constraint as the slugs above.

Rules that keep this working:
- **Adapters implement ONLY the FirewallAdapter interface** (testConnectivity/getVersion/getRules/getConfig).
  The shared persistence pipeline — device_versions, firewall_rules, device_configs, Phase 5 rule analysis,
  Phase 6 diff/backup — lives ONCE in `lib/adapters/index.js` (`collectAndStore`). Never copy it into a vendor folder.
- New vendor = adapter folder + `ADAPTERS` entry (+ `DEFAULT_METHOD` entry) + `VENDOR_PARSERS` entry
  + `VENDOR_CPES` entry + `VENDOR_META` entry.
- **`getRules()` must THROW on a retrieval failure — never return `[]`.** `collectAndStore` DELETEs a
  device's `firewall_rules` before reinserting, so an empty array returned by a *failed* pull silently
  wipes the real ruleset, cascades away its Phase 5 findings, and reports success. `[]` means "this
  device genuinely has no rules", nothing else. (Fixed once in sangfor and fortinet; don't reintroduce.)
- **Check Point: never pick a policy package positionally.** The Mgmt API talks to a management server
  that can manage MANY gateways, each with a different package — `packages[0]` stored *another device's
  rules* against this device. Resolution order is: the gateway's own installed policy → its
  installation-targets → the only package on the server (if there is exactly one) → **throw, naming the
  candidates**. Storing the wrong device's ruleset is far worse than storing none; a hard, actionable
  failure is the correct outcome.
- **Fortinet: collect every VDOM, or fail.** Requests without a `?vdom=` param silently return only the
  token's default VDOM, and rule analysis then treats that partial set as complete. If VDOM enumeration
  succeeds but one VDOM's rules fail, `getRules()` throws rather than returning the rest — see the
  `getRules()` rule above for why partial success is the dangerous case.
- **Any adapter returning a raw text config MUST redact it before returning from `getConfig()`** — see
  "Stored configs are REDACTED" under Config Change Tracking.
- SSH vendors share `lib/adapters/sshClient.js` (`runCommands`, `parseJsonCredential`) — ssh2 shell channel with
  legacy-algorithm compat for old ASA images. Don't open raw ssh2 connections in adapters.
- `mgmt_port` is nullable — every adapter applies its own default (443 API / 22 SSH / 8082 SMC) when NULL.
- Cross-vendor NVD limitation: `advisories.cve_id` is UNIQUE with a single `vendor` — a CVE affecting two vendors
  stays with whichever vendor ingested it first.

### Live Validation Status — READ BEFORE TRUSTING ANY VENDOR DATA

**Every adapter, including Forcepoint, was built against documentation and synthetic data. NONE has
been run against real hardware.** Every endpoint path, field name and auth flow below is doc-derived.
Per CLAUDE.md's "documentation lies" rule this is expected, not an oversight — but it means the first
live connection to each vendor is a *verification step*, not a smoke test.

Each adapter logs its raw response on first use. Grep the engine log for these exact prefixes:

| Prefix | Adapter |
|---|---|
| `[SMC Debug]` | Forcepoint SMC engine element |
| `[Fortinet Debug]` | FortiOS REST API + session login |
| `[PaloAlto Debug]` | PAN-OS XML API |
| `[PaloAlto SSH Debug]` | PAN-OS SSH (`set`-format config) |
| `[CheckPoint Debug]` | Mgmt API gateway/package resolution |
| `[CiscoASA Debug]` | ASA SSH show output |
| `[Sangfor Debug]` | Sangfor SSH output |

On first connect: compare the raw response against what that vendor's `parser.js` expects, fix the
field mappings, then **record the verified field names here** so the next person doesn't re-derive them.
Adapters are written to fail loudly on an unexpected shape rather than return wrong data — a loud
failure on first connect is the design working, not a regression.

#### Palo Alto SSH — RESOLVED (2026-07-16, PAN-OS 11.1.13-h5, two independent devices)

`getRules()`/`getConfig()` over SSH parse the PAN-OS **brace tree**, not `set` format. Three
rounds to get here, kept in full below because the dead ends are exactly what stops a future
change from re-treading them:

- **Round 1** (a PA-440): `show config running` in operational mode (`>`) returned the brace
  tree (`config { mgt-config { users { ... } } }`), never flat `set` lines. Attempted fix:
  `configure` → `set cli config-output-format set` → bare `show`, on the documented theory
  that the format preference only takes effect inside configuration mode.
- **Round 2** (a SECOND device, a PA-3220): Round 1's command sequence runs correctly
  (confirmed: the debug log shows `show`, not `show config running`; the dump grew from 93KB
  to 1.2MB, consistent with pulling the whole tree from root) — but the text **still** starts
  with the brace tree (`deviceconfig { system { panorama { ... } } }`). Two independent real
  devices agreeing ruled out Round 1's theory; a third guessed command sequence was
  deliberately NOT attempted.
- **Round 3** (resolution): rather than guess again, `ssh.js` was given a targeted debug
  search for the literal substring `"rulebase"`, logging an 8000-char window centered there
  regardless of total file size (the plain head-of-file preview twice landed in
  `deviceconfig`/`mgt-config` and never reached it on a 93KB–1.2MB dump). That surfaced the
  real rulebase text: `rulebase { security { rules { RuleName { from ...; to ...; action
  drop; } } } } }` — genuine brace format, confirmed directly, not inferred.

**The fix:** `sshParser.js` now has a real tokenizer + recursive-descent parser for this
grammar (`tokenizeBraceConfig`/`parseBraceBlock`/`parseBraceConfig`), replacing the dead
`set`-format code entirely (renamed `parseRulesFromSetConfig`→`parseSecurityRules`,
`parseConfigFromSet`→`parseConfig` — update any reference to the old names).
`findSecurityRulesContainers()` searches the parsed tree depth-first for any
`rulebase.security.rules` container, wherever it sits (bare single-vsys root — this is what
both real test devices are — `vsys { entry { ... } }`, `shared { ... }`, or a Panorama
`pre-rulebase`/`post-rulebase` shape), the same "search deep, don't assume the absolute path"
approach `fortinet/cliParser.js`'s `findBlockDeep()` already uses in this codebase. The `ssh.js`
command sequence (`configure` → `set cli config-output-format set` → bare `show`) is UNCHANGED
— it reliably retrieves the full config tree containing the rulebase; only the parser needed
to change, from expecting `set` lines to parsing what the firmware actually returns.

**Verified against real data, not just live-shaped samples**: the parser was run against the
actual captured rulebase text from the PA-3220 log before this shipped — 15/15 rules extracted
correctly, names/actions/enabled-states/zones all matching the source text exactly, including
the unspaced-list-bracket edge case (`[ DMZ1 DMZ2 DMZ3]` — no space before `]`) and a rule with
a nested `profile-setting` sub-block.

**Security note for `parseConfig()`**: `getConfig()` now redacts the raw text FIRST, then
builds `parsed.tree` from the REDACTED text (previously the `set`-format summary was narrow
enough to never touch secret-bearing fields; the new `parsed.tree` is a full parsed structure,
and `device_configs.config_parsed` is GRANT SELECT'd to `claude_readonly`/`nocvault_readonly`
— the same roles `device_credentials` is barred from). Rule parsing still uses the unredacted
text, which is fine — rules never carry secrets.

Also confirmed live (all rounds): `show system info` field names match this file's existing
assumptions exactly (`hostname`, `sw-version`, `model`, `serial`, etc.) — no changes needed
there. PAN-OS API/username-password method has separately worked on these same devices,
confirming XML-API rule collection was never affected by this SSH-specific bug.

#### Palo Alto SSH — OPEN CASE: Panorama-managed device with no rulebase text at all (2026-07-23)

A real device (Panorama-managed, PA-3410, PAN-OS 11.1.13-h5) returned a genuine, large
(617,170-char) config dump via the exact same `configure` → `set cli config-output-format set`
→ bare `show` sequence documented as resolved above — but the dump contains **neither**
`rulebase` **nor** `pre-rulebase`/`post-rulebase` anywhere in it (the existing
`/rulebase/i` search is already substring-inclusive of both, so this rules out the whole
established PAN-OS naming pattern, not just an unexpected nesting depth). `getRules()`
correctly threw rather than storing an empty ruleset (`no \`rulebase.security.rules\`
container was found anywhere in the parsed config tree`), so no data was lost — this is a
collection gap, not a correctness bug.

Leading theory, **not yet confirmed**: a restricted local admin role. PAN-OS admin roles can
toggle the "Policy" permission category off independently of System/Network/Device — plausible
specifically on a Panorama-managed firewall, where policy is meant to be owned centrally by
Panorama rather than edited locally. This would explain the exact symptom: `show system info`
(a different permission category) succeeds fully, the config dump is large and real (not an
error, not empty), but the policy/rulebase section specifically is never in it. **Not verified
against the device's actual assigned admin role yet** — flagged as the leading hypothesis, not
asserted as fact, per this section's own standing "verify before guessing" discipline.

Fixed defensively either way: when `/rulebase/i` finds nothing, `_getConfigText()`
(`lib/adapters/paloalto/ssh.js`) now also logs every shallow (depth ≤ 3) brace-block key
actually present in the dump (`extractShallowBlockKeys()`, a deliberately naive depth-counting
scanner — debug-only, never used for real parsing) — a real "table of contents" instead of
guessing a fifth keyword blind. Next step when this recurs: check the new shallow-key log
output, AND separately check the SSH account's assigned PAN-OS admin role for a disabled
Policy permission (Device tab → Admin Roles on the firewall or its managing Panorama).

### Known Limitations (by design — documented, not bugs)

- **Fortinet over SSH has no hit counts.** The CLI has no reliable per-rule hit-count equivalent, so
  `hit_count` is 0 for every rule. Phase 5 flags a zero-hit rule as `unused`, so an SSH-collected
  FortiGate will report **every rule unused**. Use the REST transport if unused-rule findings matter.
  Same limitation applies to Sangfor.
- **Shadow analysis is not VDOM-aware.** `ruleAnalysis` orders by `sequence_number` per *device*, with
  no VDOM dimension, so identical rules in different Fortinet VDOMs can false-positive as `shadow`.
  Fixing this needs a schema + engine change (a VDOM column on `firewall_rules`).
- **Check Point in a distributed deployment**: `mgmt_ip` is the *management server*, so gateway identity
  rests on `devices.name` matching the gateway object's name. Where it doesn't, a multi-package server
  now **hard-fails** rather than importing another gateway's rules — that's the intended bar. The error
  names the candidate gateways; fix by aligning the device name.
- **✅ RESOLVED 2026-07-19** (was: "Check Point `getVersion()`/`getConfig()` still use `findGateway()`'s
  'first gateway' fallback, so on a name mismatch they can report another gateway's version/config").
  `_findGateway()` (index.js) now calls `findGatewayByIdentity()` — the same strict, no-fallback matcher
  policy-package resolution already used — for every purpose (version, config, AND policy). Both call
  sites now throw, naming candidate gateways, on no identity match, matching the already-fixed
  `packages[0]` rules bug's error style exactly. The old fallback-permitting `findGateway()` function
  had no remaining callers once this landed and was removed from `lib/adapters/checkpoint/parser.js`
  rather than left as unused dead code. Also fixed the same day: `getConfig()` never redacted the stored
  gateway/api_versions object at all — the only one of six adapters with no redaction pass — now runs a
  generic keyword-based `redactSecrets()` (mirrors `fortinet/parser.js`'s `redactSecretFields()`) before
  storing, fail-closed (a redaction-pass error drops that subtree to a placeholder rather than risk
  returning it unredacted).
- **PAN-OS XML `getRules()` returns `[]` (does not throw) when a reachable device reports an empty
  rulebase** — it can't distinguish "genuinely empty" from "wrong xpath" without live verification.
  The any-vsys fallback narrows it; the ambiguity remains until first live connect.

## Forcepoint SMC Integration

### Core Rule
**NEVER SSH directly to Forcepoint engines.** Always go through the SMC REST API on `:8082`.
The SMC is the management plane — all operations happen there.

**⛔ One deliberate, documented exception: SNMP.** Forcepoint SNMP polls engine IPs
directly (deliberate exception to the SMC-only rule — SNMP only, not SSH/config/rules).
NGFW engines each run their own SNMP agent; the SMC does not proxy or aggregate engine
metrics, so there is no way to reach per-engine CPU/memory/session data through the SMC
REST API at all. `getSnmpMetrics()` (`lib/adapters/forcepoint/index.js`) is the ONLY
method on this adapter that connects anywhere other than the SMC — it opens a UDP SNMP
session straight to `devices.snmp_host` (a NEW column, required for this vendor — see
"SNMP Monitoring" below). Every other method (`testConnectivity`/`getVersion`/
`getRules`/`getConfig`) is completely unchanged and still goes exclusively through the
SMC. Do not widen this exception to any other protocol or any other adapter method.

### Authentication

Preferred method: **API key header** (stateless, no session management)
```javascript
headers: { 'SMC-API-KEY': apiKey }
```

Alternative: session auth via `POST /api/login` → `JSESSIONID` cookie. Use only if API key unavailable.

### Self-Signed SSL

Most enterprise SMC instances use self-signed certificates. Default to accepting.

**Source of truth is the per-device `devices.allow_self_signed_ssl` column** (NOT NULL,
DEFAULT true) — not the `ALLOW_SELF_SIGNED_SSL` env var, which only seeds the Add Device
form's default. The flag is per-device because one server can manage a mix of appliances.

```javascript
// The pattern every vendor adapter uses (forcepoint/smc.js, fortinet/api.js,
// paloalto/api.js, checkpoint/api.js). Note the polarity carefully:
const agent = new https.Agent({ rejectUnauthorized: allowSelfSignedSsl === false });
// allowSelfSignedSsl true  -> rejectUnauthorized false -> self-signed ACCEPTED
// allowSelfSignedSsl false -> rejectUnauthorized true  -> cert VALIDATED
```

⚠️ Earlier revisions of this file documented `rejectUnauthorized: process.env.ALLOW_SELF_SIGNED_SSL !== 'false'`,
which is **inverted** (it rejects self-signed certs when the flag says to allow them) and was
never what the code did. Corrected here; do not reintroduce it.

### HATEOAS Pattern

SMC API uses HATEOAS — responses contain `href` links. Follow `href` values:
```javascript
// DO this:
const engineHref = engines[0].href;
const engine = await smcGet(engineHref);

// NOT this:
const engine = await smcGet(`/api/elements/engines/${id}`);
```

### Field Name Verification

SMC API field names for engine software version differ between SMC 6.x and 7.x.
**Never assume field names from documentation.** On first connect, log the full engine element:
```javascript
console.log('[SMC Debug] Engine element:', JSON.stringify(engineElement, null, 2));
```
Adjust `parser.js` field mappings based on actual live output.

### ⚠️ Pool Warning (learned from SpanVault Aruba Central)

The Forcepoint SMC adapter's `testConnectivity()` and all functions that call `credStore.decrypt()` **must always receive and use the `pool` parameter**, even if it looks like a pure connectivity test. Removing `pool` from `testConnectivity()` causes credential decryption to fail on the next click — builds clean, passes all static checks, silently breaks at runtime.

```javascript
// CORRECT:
async testConnectivity(pool) {
  const cred = await getCredential(this.device.id, pool);
  ...
}

// WRONG — will brick the integration:
async testConnectivity() {
  const cred = await getCredential(this.device.id);  // pool missing
  ...
}
```

### Key SMC Endpoints (verify against live SMC)

```
GET /api/                              API version + info
GET /api/elements/engines              All managed engine elements
GET /api/elements/ngfw_clusters        Cluster topology + HA status
GET /api/elements/fw_policy            Firewall policies
GET /api/elements/network_elements     Address objects (for rule resolution)
GET /api/elements/service_elements     Service/port objects
```

Pagination: check for `paging` object in responses. Follow `next` href if present.
Rate limiting: SMC API has no documented rate limit but batch requests on slow links.

---

## Forcepoint CVE Data (NVD — Only Programmatic Source)

Forcepoint has NO public PSIRT API, RSS feed, or advisory endpoint. NVD is the only automated source.

### ⚠️ NVD API Parameter — Critical Bug Fixed in MVP Build

**Use `virtualMatchString`, NOT `cpeName`, for wildcard CPE queries.**

The NVD API 2.0 documentation lists `cpeName`, but live-testing against the real endpoint during
the MVP build proved it returns **HTTP 404** on wildcard/version-less CPE strings (e.g.
`cpe:2.3:a:forcepoint:next_generation_firewall:*:*:*:*:*:*:*:*`). `virtualMatchString` is the
correct parameter for pattern-based CPE matching and was confirmed live (HTTP 200, real Forcepoint
CVEs returned).

```javascript
// WRONG — 404s on wildcard CPEs (despite being in the documented spec):
const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?cpeName=${cpeString}`;

// CORRECT — verified against the live NVD API:
const url = `https://services.nvd.nist.gov/rest/json/cves/2.0?virtualMatchString=${cpeString}`;
```

Had this shipped as documented, every feed sync would fail outright (404) with no advisory data
and no obvious error. Never revert to `cpeName` for wildcard queries. See `lib/feeds/nvd.js`.

### Dual-CPE Query (critical — covers pre/post v7.1 rebrand)

```javascript
const CPE_STRINGS = [
  'cpe:2.3:a:forcepoint:next_generation_firewall:*:*:*:*:*:*:*:*',  // pre-7.1
  'cpe:2.3:a:forcepoint:flexedge_secure_sd-wan:*:*:*:*:*:*:*:*'     // 7.1+ rebrand
];
// Run both queries using the virtualMatchString parameter (see above).
// Deduplicate by cve_id before inserting.
// Verify exact CPE vendor/product strings via NVD CPE dictionary:
// https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=forcepoint
```

### Advisory Detail Source

Forcepoint KBAs (support.forcepoint.com) are **login-gated** — no programmatic access.
Advisory conditions (applicability predicates) must be sourced manually via Thai Union's
Forcepoint support account, then encoded into `advisory_conditions` table rows.
This is curated data, not code.

---

## CVE Engine Architecture

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

When no `advisory_conditions` predicate exists for an advisory:
- `config_applies` = `'unknown'` (not `'no'`)
- Unknown is treated **conservatively** (same as yes for prioritization)
- NEVER default unknown to 'no' — would silently suppress CVEs with no predicates

**"No usable config" includes an EMPTY object, not just null** (`lib/engines/applicability.js`
→ `hasUsableConfig()`). `{}`, a non-object, and an array all mean *the config pull did not
produce anything we can interrogate* — they must yield `'unknown'`, exactly like `null`.

This is a real, reachable failure, not a theoretical one. An adapter parser meeting an
unexpected live response shape can legitimately return `{}` (the five non-Forcepoint adapters'
field names are still unverified against live hardware), and a Cisco ASA session that fails to
reach enable mode parses to an empty skeleton. Without the guard, `{}` reaches `getByPath()`,
every lookup returns `undefined`, and the key-based predicates answer `'no'` — so prioritization
skips rules 1–4 (which require `config_applies !== 'no'` / `=== 'yes'`) and lands on rule 6 →
`monitor`. **A KEV-listed, actively-exploited, version-affected CVE would be silently downgraded
from `patch_now` to `monitor` by a failed config pull** — the exact "looks fine, isn't" failure
this tri-state rule exists to prevent. Verified end-to-end before/after.

### Applicability Engine (Phase 6 — `lib/engines/applicability.js`)

The predicate evaluator is now live. Semantics (do not change without documenting here first):
- Conditions for an advisory are **ANDed**: any `'no'` → `'no'`; else any `'unknown'` → `'unknown'`; else `'yes'`
- No conditions, or no collected config for the device → `'unknown'` (never `'no'`)
- `evaluatePredicate()` never throws — any internal error resolves to `'unknown'`
- Predicate types: `config_key_exists` / `config_value_equals` / `config_value_matches` (path missing → `'no'`),
  `feature_enabled`, and `port_exposed` / `admin_access_from_zone` (deep-scan; **not found → `'unknown'`**, because
  absence of evidence in a parsed config is not provable absence)
- **Every lookup goes through `getLatestConfigParsed()`, which normalizes the config root via
  `normalizeConfigParsedRoot()` before any predicate ever sees it** — see "Compliance predicate engine
  was reading the wrong root for Palo Alto" below for why this exists. Both this engine and
  `configAuditor.js`'s compliance checks call the same `getLatestConfigParsed()`, so the fix applies to
  CVE applicability and compliance simultaneously.
- A THIRD predicate type, `ruleset_property`, exists only in `configAuditor.js` (not this file) — see
  the Compliance Engine section below for why it's separate (it reads `firewall_rules`, not
  `config_parsed`, so `evaluatePredicate()`'s config-path model doesn't apply to it).
- `versionMatcher.runMatchForAllDevices()` loads conditions once per vendor and the latest `config_parsed` per
  device, and passes them into `matchDeviceToAdvisories(..., applicability)` — the 5th param is optional; legacy
  callers omitting it get `'unknown'` everywhere
- Admin UI: `/advisories/[cveId]/conditions` (CRUD + test-against-device); API under `/api/advisories/[cveId]/conditions`

### Advisory Conditions Are Data, Not Code

Applicability predicates live in the `advisory_conditions` table.
New CVE conditions = new DB rows via admin UI, not code changes.
The predicate engine code should not need to change for new CVEs.

### Rule Analysis Engine (Phase 5 — `lib/engines/ruleAnalysis.js`)

10 finding types with fixed severities: `any_any` (critical); `risky_service`, `shadow`, `reorder_candidate` (high);
`redundant`, `correlation`, `overly_permissive`, `unused`, `expiring_soon` (medium); `log_disabled` (info).
- **`correlation` (added 2026-07-18)**: ManageEngine Firewall Analyzer's "Policy Anomalies >
  Correlation" concept — two enabled rules with the same action category, same zones, and same
  service(s), differing in ONLY source OR ONLY destination addresses (not both — that's `redundant` —
  and not neither), where the differing side isn't already `any` on either rule (nothing meaningful
  left to merge). A ruleset-simplification suggestion, not a security exposure, hence `medium`
  alongside `redundant`/`overly_permissive` rather than `high`/`critical`. Lives in the same
  `maxRulesForShadow`-gated O(n²) block as `shadow`/`redundant`/`reorder_candidate`, with its own
  `correlationPairs` de-dupe Set (checked against `shadowPairs` too, though the two shouldn't overlap
  by construction: `redundant` requires src AND dst equal, `correlation` requires exactly one to
  differ). Surfaced in the Cleanup tab (`components/analysis/CleanupTab.js`) alongside
  `unused`/`redundant`/`overly_permissive` — all four are "simplify the ruleset" suggestions.
- Runs automatically after every rule pull (inside `collectAndStore`) — findings are DELETE+reinserted per device
- `rule_analysis_results.rule_id` cascades from `firewall_rules`, which is itself rewritten each pull — safe because
  analysis always reruns immediately after the rewrite
- Shadow/redundant/reorder analysis is O(n²) and **skipped entirely above 1000 rules** (warning logged)
- Optional overrides via `settings` keys: `rule_unused_days`, `rule_expiry_window_days`, `risky_ports` (JSON array)
- `firewall_rules.comment`/`.applications`/`.schedule` were always collected by most vendor parsers
  (`comment` by all 6; `applications` by 4 of 6 — Fortinet, Forcepoint, Palo Alto both transports;
  `schedule` by 4 of 6) but never surfaced anywhere until 2026-07-19 — added as columns to
  `/devices/[id]/rules`'s table and its `GET .../rules?format=csv` export (`comment` in particular
  had zero consumers anywhere despite every adapter populating it — the clearest "dead data" case
  found in that pass). Purely a UI/export addition — `ruleAnalysis.js` itself does not read any of
  the three, and still doesn't; no finding type currently depends on them.
- Coverage tests (`fieldCovers`, used by `shadow`/`reorder_candidate`) are string-equality PLUS
  CIDR-aware containment as of 2026-07-19 (`lib/engines/cidrUtils.js`) — an S-side address-list item
  that's a literal IPv4/CIDR (e.g. Palo Alto rules typed directly with `"10.0.0.0/16"` instead of an
  address-object reference) now correctly covers a narrower R-side literal (`"10.0.5.0/24"`) even
  though the strings differ. `cidrContains()` returns `null` (never `false`) whenever either side
  isn't a parseable IPv4 literal — which is the common case, since most address-list items across
  every Tier 1 vendor are unresolved OBJECT NAMES (`"LAN-subnet"`), not literal CIDRs — so this only
  ever ADDS matches on top of the pre-existing string-equality test, never removes any; it's a pure
  false-negative reduction, not a change to the "deliberately conservative, no false shadows"
  philosophy. Deliberately scoped narrow: IPv4 only (IPv6 returns `null`, untouched), no
  address-OBJECT-to-CIDR resolution (would need a new per-vendor fetch layer — `config firewall
  address` on Fortinet, `address`/`address-group` xpaths on Palo Alto — that doesn't exist), and only
  applied to `fieldCovers` — `fieldEquals` (used by `redundant`) deliberately was NOT given the same
  treatment, since CIDR-aware SET equality is a harder bipartite-matching problem once either side has
  more than one item, and a wrong `redundant` finding (suggesting a rule be deleted) is worse than a
  wrong `shadow` finding — flagged as an accepted, un-done follow-up rather than guessed at.
- **⛔ `analyzeRules()` was blocking the entire app during "Collect Now" — fixed 2026-07-21, reported
  directly by a user ("clicking Collect makes the app hang sometimes... the whole app, other pages
  freeze too").** Root cause: this file runs FOUR separate O(n²) passes over the ruleset in one
  uninterrupted synchronous block (shadow, redundant, correlation, reorder_candidate — up to ~4
  million pairwise comparisons for a device near the 1000-rule cap), and SecVault is one Node.js
  process serving every user off a single event loop — nothing was wrong with WHAT was computed, only
  that nothing ever yielded control back to it while computing. Only showed up on devices with a
  large-ish ruleset (explaining "sometimes") and froze every other page/user at once (explaining "the
  whole app"), not just the collecting device's own request. Fixed: `analyzeRules()` is now `async`,
  and the outer pairwise loop calls a new `yieldToEventLoop()` (`setImmediate`-based) every 25
  iterations — this only changes WHEN control returns to the event loop, never the iteration order or
  any computed finding. Verified behavior-preserving by diffing this file's pre-fix vs. post-fix output
  on a 57-rule synthetic set (with a planted shadow/redundant/correlation/reorder_candidate/any_any/
  risky_service/log_disabled/disabled-rule case each) AND a 400-rule randomized set — byte-identical
  findings both times. `runAnalysisForDevice()`'s single call site now `await`s it; no other caller
  exists in the repo (`analyzeRules` is exported but only ever consumed via that one wrapper).
  `lib/engines/objectUsage.js`'s transitive-closure loop is a smaller, less-certain version of the same
  risk on devices with very large object catalogs — flagged as the next place to look if a
  large-object-catalog device ever shows this same symptom; not changed in this pass.

### Rule Analysis Dashboard (`lib/engines/riskScore.js`)

Pure, no-DB risk scoring layered on top of the Phase 5 findings — built to bring the Rule
Analysis UI closer to feature parity with commercial firewall-analyzer dashboards (stat
grid + bar chart + a single glanceable risk number), while staying **recommend-only**: no
adapter gained a write-back/push-to-device capability, and none is planned — see the
"Rule Analysis → Firewall-Analyzer-style Dashboard" plan for the full phased scope.

- `computeRiskScoreFromCounts({critical,high,medium,info})` → weighted sum (10/5/2/0),
  clamped to 0–100, banded into `low`/`medium`/`high`/`critical`. `computeRiskScore(findings)`
  is a convenience wrapper that tallies severity counts from a raw findings array first.
- Deliberately coarse (a triage signal, not a tuned risk model) — see the file's own comments
  for why the band cut points land where they do (a single critical finding scores `medium`,
  not `low`; three or more escalates to `high`).
- Computed on read wherever it's needed (the `/api/devices/[id]/analysis` GET summary, the
  per-device analysis page, the fleet analysis page) — no caching column, no scheduled job.
  A future phase may snapshot it periodically for a trend view; not built yet.
- `/devices/[id]/analysis` is now tabbed (`?tab=summary|rules|findings`, the same
  server-rendered query-param pattern as `/devices/[id]/page.js`) instead of one flat page —
  `summary` carries the risk badge, the stat grid (existing severity counts plus
  Allowed/Denied/Inactive/Any-Any/Logging-Disabled pulled from `firewall_rules` directly),
  and a bar chart of the 9 finding types via **`recharts`** (added as a dependency —
  `components/analysis/FindingsBarChart.js`, `'use client'`, since Recharts needs a DOM).
  Bar fill colors are read from `app/globals.css`'s CSS custom properties at render time
  (`getComputedStyle(document.documentElement)`, with a hardcoded hex fallback for the
  server-render pass, where `window`/`document` don't exist) rather than hardcoding hex a
  second time — keeps the chart in sync with `SeverityBadge`'s severity→color mapping
  automatically if the palette ever changes. `recharts` is scoped to this one route via
  Next.js's automatic code-splitting (not in the shared bundle) — an earlier hand-built
  Tailwind-only version (no dependency, div height as a `%`) was replaced after the user
  asked for "a proper chart plugin"; keep using `recharts` for future chart needs in this
  app rather than reintroducing a second hand-built version.

#### Cleanup / Optimization / Reorder (Phase 2 — `finding_acknowledgements`)

Recommend-only acknowledge-tracking for Phase 5 findings — three more tabs on
`/devices/[id]/analysis` (`?tab=cleanup|optimization|reorder`), each a filtered view over
specific finding types with a per-row status control (`new`/`acknowledged`/`dismissed`/`actioned`).
No write-back to devices anywhere — same confirmed scope as the rest of this dashboard.

- **`finding_acknowledgements` is keyed on `(device_id, rule_id_vendor, finding_type)`, NOT
  `firewall_rules.id` or `rule_analysis_results.id`.** Both of those are fully DELETE+reinserted
  on every pull (`rule_analysis_results` on every analysis run, `firewall_rules` on every
  *collect* — collectAndStore runs on a 24h schedule), so either UUID would be a brand-new
  random value after the very next scheduled collect, silently losing every acknowledgement.
  `rule_id_vendor` (the vendor-native rule identifier — e.g. the PAN-OS rule name, the Fortinet
  policy ID) stays stable across recollects as long as the rule itself isn't renamed/recreated
  on the device. `rule_id_vendor` is nullable on `firewall_rules` for a handful of
  already-degraded/unparseable rule shapes across adapters — acknowledgement is simply
  unavailable for those rows (the UI omits the control) rather than accepting an ambiguous
  NULL-keyed row, since Postgres `UNIQUE` treats multiple `NULL`s as distinct from each other.
- `app/api/devices/[id]/acknowledgements/route.js` is **POST-only** (upsert one row) — there is
  no GET. Every tab is a server component that `LEFT JOIN`s `finding_acknowledgements` directly
  in its own query, the same "server components query the DB directly, API routes exist for
  client-triggered writes" convention already used throughout this app.
- `components/analysis/AcknowledgeControl.js` (`'use client'`): a `<select>` that auto-saves on
  change (optimistic update, reverts on error) rather than needing a separate Save button per
  table row — POSTs, then `router.refresh()`.
- `components/analysis/{CleanupTab,OptimizationTab,ReorderTab}.js`: async server components,
  each doing their own `pool.query`, each rendering the shared `Table`/`SeverityBadge`/
  `AcknowledgeControl` components. Finding-type split: Cleanup = `unused`/`redundant`/
  `overly_permissive`; Optimization = `risky_service`/`any_any`/`overly_permissive`; Reorder =
  `reorder_candidate` only. `ReorderTab.js` additionally resolves each finding's
  `affected_rule_ids` (the earlier allow rule that shadows the deny) against a same-request
  snapshot of the device's full ruleset — that resolution is safe precisely because it's never
  persisted, only rendered once per request; the ids themselves are NOT stable across pulls,
  which is exactly why `finding_acknowledgements` doesn't key on them.

#### Risk Trend + Audit/Tracking (Phase 4 — `device_risk_history` / `activity_log`)

Two more tabs on `/devices/[id]/analysis` (`?tab=risk|tracking`). Phase 3 (Expiry Notification +
Alerting) is explicitly KIV — no notification/alerting infrastructure was built or is planned for
now; skip straight from Phase 2 to Phase 4 in this codebase's actual history.

- **Risk trend**: `device_risk_history` (`device_id`, `score`, `band`, `recorded_at`) is
  snapshotted from **inside `runAnalysisForDevice()`** (`lib/engines/ruleAnalysis.js`), not at
  either of its callers. That one function is what both the scheduled 24h collect
  (`collectAndStore`) and a manual "Run Analysis" click (`POST /api/devices/[id]/analysis`) go
  through, so snapshotting there covers both triggers without duplicating the logic at each call
  site. Best-effort: a snapshot failure is caught and warned, never allowed to fail the analysis
  run itself (the findings are already committed by that point in the function).
  `components/analysis/RiskTab.js` (server component, queries ascending by `recorded_at`) +
  `components/analysis/RiskTrendChart.js` (`'use client'` recharts `LineChart`, same
  CSS-custom-property color convention as `FindingsBarChart.js`).
- **Audit/Tracking**: `activity_log` (`actor`, `action`, `device_id` nullable, `detail`,
  `occurred_at`) is **NOT a general app log** — `services/engine-worker.js`'s scheduled jobs
  already have `C:\Apps\SecVault\logs\engine.log` for that. This table only records
  HTTP-route-triggered operator actions, via `lib/activityLog.js`'s `logActivity(pool, {actor,
  action, deviceId, detail})` (CommonJS; never throws, catches its own errors — an audit-log
  failure must never fail the primary action it's describing). Three call-sites today:
  `POST /api/devices/[id]/analysis` (`run_analysis`), `POST /api/devices/[id]/acknowledgements`
  (`acknowledge_finding`), `PUT /api/devices/[id]/diffs/[diffId]` (`acknowledge_config_diff`).
  `components/analysis/TrackingTab.js` (server component, capped at 100 rows, generic
  snake_case→Title Case label transform rather than a hardcoded action-name lookup).
- **`actor` comes from `getServerSession(authOptions)`** (`next-auth/next`), added to this
  codebase's API routes for the first time by this phase — `session.user.name` (the local admin's
  or LDAP-bound username, per `app/api/auth/[...nextauth]/route.js`'s `authorize()`), falling back
  to `'unknown'` only if the session lookup itself fails. **Every route wraps the session lookup
  in its own try/catch, separate from the route's main try/catch** — a `getServerSession` hiccup
  must never turn an already-successful primary action (analysis already ran, finding already
  acknowledged) into a reported 500 to the client; that would be the audit trail's secondary
  concern masking the primary action's real success. The diffs route is the one exception where
  the resolved actor ALSO feeds the primary `UPDATE ... SET acknowledged_by` (not just the audit
  log), so there it degrades to `'unknown'` rather than being skipped — the acknowledge still
  needs to complete either way.
  - Fixed in passing: `PUT /api/devices/[id]/diffs/[diffId]` used to trust a client-supplied
    `acknowledged_by` body field (default `'admin'`) — the actual UI caller
    (`components/config/AcknowledgeButton.js`) never sent one, so `config_diffs.acknowledged_by`
    was always the literal string `'admin'` regardless of who was actually logged in. Now derived
    from the real session for both the column and the audit trail.

#### Rule Composition Chart, Clickable Drill-Down, CSV Export (2026-07-19)

The Summary tab's flat StatCard row gained a `RuleStatsBarChart` (`components/analysis/
RuleStatsBarChart.js`, `'use client'`, same recharts/CSS-var-color-reading template as
`FindingsBarChart.js`) sitting alongside the existing `FindingsBarChart` in a responsive 2-column
grid — `RuleStatsBarChart` charts rule-COMPOSITION (Allowed/Denied/Inactive/NAT Enabled/Any-to-Any/
Logging Disabled), distinct from `FindingsBarChart`'s finding-TYPE breakdown. Includes a new **NAT
Enabled** stat — `firewall_rules.nat_enabled` already existed in the schema but had never been
surfaced in any UI until now (`getRuleStats()` extended with `COUNT(*) FILTER (WHERE nat_enabled =
true)`).

Every StatCard on the Summary tab that has a real filtered destination is now a `Link`: Total →
unfiltered `/devices/[id]/rules`, Allowed → `?action=allow`, Inactive → `?enabled=false`, NAT →
`?nat=true`, Any-to-Any / Logging Disabled → the Findings tab pre-filtered by `finding_type`
(`?tab=findings&finding_type=...`, already-existing support). **Denied needed a small filter
extension first**: the StatCard counts `action IN ('deny','drop','reject','block')`, but
`/devices/[id]/rules`'s `action=` filter only ever matched a single exact value — linking it to
`?action=deny` alone would have undercounted relative to what the tile actually showed. `action=` now
accepts a comma-separated list (`?action=deny,drop,reject,block`), matched via `= ANY($N::text[])`
instead of plain `=` (a bare single value still works identically — `ANY()` over a 1-element array
equals `=`) — added identically to both `app/(dashboard)/devices/[id]/rules/page.js`'s own
`buildFilters()` and the sibling `app/api/devices/[id]/rules/route.js`'s copy (this file's established
per-file-duplication convention, not a shared module), plus a matching `nat=true|false` filter in
both. The rules page's filter form gained matching `<select>` options for both.

Export CSV (`?format=csv` on `GET /api/devices/[id]/analysis`, see the Compliance Engine section
above for the shared CSV pattern this mirrors) — an "Export CSV" action button was added next to the
existing risk badge and "Run Analysis" button.

#### Per-rule risk banding — "Risky Rules" tab (added 2026-07-18)

`computeRiskScoreFromCounts`/`computeRiskScore` (above) weigh a whole DEVICE's finding counts into
one number. `computeRuleRiskBand(ruleFindings, enabled)` (also in `lib/engines/riskScore.js`) is a
different, simpler granularity: bands a single RULE from its own `rule_analysis_results` rows only
(never `affected_rule_ids`, which names OTHER rules in a shadow/redundant/correlation relationship —
a different concept). No weighted sum, no clamping — a rule's band is just the worst severity among
its own findings (`critical`→critical, `high`→high, `medium`→medium, `info`→low), because a single
rule can only be as risky as its worst individual finding, unlike a whole device where many findings
genuinely compound.

A 5th band, **`attention`**, exists alongside the 4 severity-derived ones — mirroring ManageEngine
Firewall Analyzer's own Risk tab, which has 5 stat tiles (Critical/High/Medium/Low/Attention), not
just 4. An ENABLED rule with zero findings of its own is `attention`, not `low` — "nothing flagged"
isn't the same claim as "confirmed fine," and collapsing the two would overstate confidence. A
DISABLED rule with zero findings is `low` — Phase 5 findings only ever key off enabled rules' live
behavior, so "no findings + disabled" really is the unambiguous low-risk case.

`components/analysis/RiskyRulesTab.js` (new tab, `?tab=risky-rules` on
`devices/[id]/analysis/page.js`, positioned right after the existing device-level `risk` tab —
sibling, not a replacement: `RiskTab.js` still trends one score for the whole device over time, this
tab is the per-rule breakdown) — async server component, `LEFT JOIN rule_analysis_results` grouped
by `rule_id` with `array_agg(severity) FILTER (WHERE severity IS NOT NULL)` so a zero-finding rule
still appears (an inner join would silently drop it, breaking the `attention` band). Renders 5
`StatCard` tiles (Critical/High/Medium/Low/Attention counts of RULES, not findings), a "N Risky
Rules of Total: M" summary line (N = every band except `low`, matching Firewall Analyzer's own
apparent inclusion of its `Attention` bucket in the risky total), then a full rule table sorted
worst-band-first with a colored `Badge` per rule's band.

### Config Change Tracking (Phase 6 — `lib/engines/configDiff.js`)

- After every config pull, `collectAndStore` diffs the two latest snapshots → `config_diffs`; an `'auto'` backup is
  written to `config_backups` **only when something changed** (avoids duplicating every unchanged daily pull)
- A detected config change triggers an immediate CVE re-match in the engine worker (config_applies may have flipped)
- UI: `/devices/[id]/changes` (timeline, diff viewer, acknowledge, backups + download)
- `config_diffs.acknowledged_note TEXT` (added 2026-07-20, both in the `CREATE TABLE IF NOT EXISTS`
  body and a companion `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` per this file's own schema-migration
  rule) — an optional free-text reason on acknowledgement, mirroring
  `cve_assessment_acknowledgements`'s existing optional `note` field, which config-diff
  acknowledgement never had. `PUT /api/devices/[id]/diffs/[diffId]` accepts an optional `note` in the
  body and folds it into the `logActivity` detail string when present.
  `components/config/AcknowledgeButton.js` (the Changes-page control) and
  `components/alerts/AlertAckControl.js`'s `'diff'` branch (the fleet Alerts-page control) both gained
  an optional "+ note" toggle that reveals a small text input before acknowledging; the note renders
  alongside the "Acknowledged by X · date" badge once set. This route is RBAC-gated (admin-only, see
  Role-Based Access Control above) — it wasn't gated at all before RBAC existed.
- **`classifyDiff()` — raw-diff classification for display (added 2026-07-20).** Direct user report:
  a real 501-entry `config_diffs` row (all Palo Alto address-object additions) was rendering in the
  Changes-page diff viewer as 501 stacked raw JSON rows, with no way to tell "did a rule change" from
  "an object catalog got re-parsed." Root cause traced to the SAME event already documented above under
  "Palo Alto SSH redaction corrupted the config brace structure" — a one-time, self-resolving side
  effect of that brace-corruption bug (confirmed via direct live production DB investigation, not
  assumed): the corrupted snapshot's massive garbage key got compared against the next, correctly-parsed
  snapshot once the redaction fix landed, producing one abnormally large diff. `diffConfigs()` itself was
  never the problem (it correctly diffs the full parsed tree into flat `{added, removed, modified}`
  dot-path entries — the right shape to PERSIST, vendor-agnostic, no tree-shape knowledge needed to
  compute or store) — the problem was purely presentational: a raw path like
  `tree.rulebase.security.rules.RuleName.action` or `tree.address.TUMN-2` means nothing to an operator
  scanning a long list for "what actually changed."
  `classifyDiff(diff)` (pure, no DB, called at READ time by `GET /api/devices/[id]/diffs/[diffId]` —
  never at write time, so a future improvement to section labeling or rule-path detection applies
  retroactively to every historical row for free, with no migration needed) groups an already-computed
  diff into (a) a "Rule Changes" table (rule name / field / old→new, matching ManageEngine Firewall
  Analyzer's own change-tracking table shape — the thing operators actually care about most) and (b)
  everything else collapsed into per-section summaries with just a count (e.g. "Address Objects: 500
  added") instead of a raw dump, via `classifyPath()`/`sectionLabelFor()`. **Scoping limitation, by
  design, not an oversight**: only Palo Alto SSH-transport rule paths resolve into the rule table today
  — on that transport the rule NAME is a literal path segment
  (`tree.rulebase.security.rules.<RuleName>.<field>`), directly extractable. Palo Alto XML/API-transport
  rules are array-indexed (`rulebase.security.rules.entry[N].<field>` — the name is a SIBLING `@_name`
  field inside `entry[N]`, not recoverable from the diff entry's path alone without a live full-tree
  lookup, a bigger, separate change) and fall through to the generic section bucket rather than being
  guessed at or mislabeled — same "no ruleset is safer than the wrong one" honesty this file's
  `getRules()` fail-loud rule already applies elsewhere. No other vendor's `config_parsed` contains a
  rulebase at all (Fortinet's is flat settings sections only — see the Compliance Engine section above),
  so this only ever applies to Palo Alto devices, on either transport, for the object/section grouping;
  only the SSH transport additionally gets the rule table. **Still-open, explicitly out-of-scope gap**:
  there is still no "who made this change on the device" column — `acknowledged_by` only ever records
  who acknowledged the change *inside SecVault* afterward, never who made it on the firewall itself; a
  real answer to that requires syslog/audit-log ingestion from the device (Phase 8, not built), a
  structurally different and much larger feature than a diff-rendering improvement, not attempted here.
  Code: `lib/engines/configDiff.js`'s `classifyDiff()`/`classifyPath()`/`sectionLabelFor()`, consumed by
  `GET /api/devices/[id]/diffs/[diffId]` (`classified` field on the response) and rendered by
  `components/config/DiffViewer.js`. Verified against real production data (live read-only DB access)
  before shipping: the actual 501-entry diff now groups into `{label: 'Address Objects', addedCount:
  500}` instead of 501 raw rows, and a real Palo Alto SSH rule addition elsewhere in the same device's
  history correctly appears in the rule-changes table. Every OTHER `config_diffs.diff` consumer in the
  app (`components/dashboard/ConfigChangesWidget.js`, `app/api/events/route.js`,
  `app/(dashboard)/alerts/page.js`, `app/api/notifications/summary/route.js`) was checked and confirmed
  to already only read `jsonb_array_length(cd.diff->'added'|'removed'|'modified')` counts or the
  free-text `change_summary` column — never individual raw entries — so this classifier is genuinely
  scoped to the one place (`DiffViewer.js`) that had the problem, not silently under-applied elsewhere.
- **⛔ Follow-up bug found the SAME DAY, by the user directly testing the `classifyDiff()` fix above**:
  the fix only covers the EXPANDED "View diff" content — `change_summary`, the short one-line preview
  that renders unconditionally on the Changes page BEFORE a user ever clicks "View diff", is a
  SEPARATE, cached string (`summarizeDiff()`, computed once at diff-detection time and stored in
  `config_diffs.change_summary`) that `classifyDiff()` never touches. Confirmed live in production: one
  row's `change_summary` was **13,647 characters** — `summarizeDiff()` picks up to 3 example PATHS with
  no length cap, and two of that diff's four paths were themselves ~6,800-character corrupted blobs
  from the SAME brace-corruption incident documented above, this time corrupting a PATH (an object key)
  rather than a value. `sanitizeExamplePath()` (new, in `lib/engines/configDiff.js`) now guards both
  failure shapes: any example path containing whitespace or a brace character (a real dot/bracket path
  never legitimately contains either) is swapped for an honest `(unreadable path — see full diff for
  details)` placeholder instead of a truncated garbage fragment; anything else is truncated to 80
  characters. `regenerateOversizedChangeSummaries(pool)` (new, same
  one-time-but-safely-rerunnable/best-effort shape as `cleanupVolatileConfigDiffs()`, wired into
  `lib/migrate.js`'s `main()` right after it) re-derives `change_summary` for any EXISTING row over 500
  characters using the fixed `summarizeDiff()` — a code fix alone doesn't retroactively repair a value
  already persisted in the DB, same reasoning as every other retroactive-cleanup migration in this
  codebase. Verified directly against the real affected row before shipping: 13,647 chars → 181 chars,
  with both corrupted paths correctly replaced by the placeholder text instead of truncated garbage.
- **⛔ THIRD occurrence, found by the user directly testing the fix above, same day**: even after both
  fixes, expanding a corrupted diff's "Address Objects" (or any other) section still showed the raw
  ~6,800-character corrupted path as the row label — `classifyDiff()`'s `sections[].entries[]` correctly
  BUCKETED the entry (classification runs against the real, untruncated path — correct), but handed the
  entry's raw, unsanitized `path` straight through to the UI, so `DiffViewer.js`'s per-row label
  rendered the same blob one level deeper (inside "Show details", not the top-level summary). Fixed by
  extracting `sanitizeExamplePath()`'s logic into a shared `truncatePathForDisplay(path, maxLength)`
  (same shape-check + truncate-or-placeholder behavior, parameterized by length — 80 for the one-liner,
  a more generous 200 for a full table/list row), applied to `sections[].entries[].path` AND
  `ruleChanges[].ruleName`/`.field` (the latter defensively, since rule-path segments are far less
  likely to be corrupted, but not assumed safe) — applied strictly AFTER `classifyPath()` has already
  used the real path to decide bucket/rule-name, never before, so classification accuracy is unaffected
  by the display-only truncation. Verified against the real affected row: the section-entry path now
  renders as the same 45-character placeholder instead of the raw blob, with the real rule-table row
  (`FW_Analyzer-NIST_NVD`, correctly extracted, unaffected) still showing correctly alongside it.
  **Lesson for future config-diff work, revised**: `config_diffs` has (at least) THREE independent
  places a path can render, all fed by the same underlying `diff` but each requiring its OWN
  sanitization: (1) `change_summary`'s cached one-liner (always visible), (2) `classifyDiff()`'s
  `sections[].entries[].path` (behind "View diff" → a section's "Show details"), (3) `classifyDiff()`'s
  `ruleChanges[].ruleName`/`.field` (the Rule Changes table). A fix to one is not a fix to the others —
  do not declare a diff-rendering corruption bug closed without checking all three, and consider
  whether any FUTURE new rendering surface for `diff` data needs the same `truncatePathForDisplay()`
  treatment before shipping it.

#### ⛔ Stored configs are REDACTED — do not "fix" this

Adapters that retrieve a full text config (`cisco_asa`, `sangfor`) run it through a
fail-closed redactor **before** it is persisted. Secrets never reach `device_configs.config_raw`,
and therefore never reach `config_backups.config_raw` (which is copied from it verbatim) or the
`/api/devices/[id]/backups/[backupId]` download.

This is not optional hygiene — it closes a real disclosure path. A `show running-config` carries
enable/user password hashes, IKE pre-shared keys, SNMP communities and RADIUS/TACACS+ secrets;
**`lib/schema-grants.sql` grants `SELECT` on `device_configs` and `config_backups` to
`claude_readonly` / `nocvault_readonly`.** Those are the exact roles CLAUDE.md bars from
`device_credentials` — without redaction they would read device secrets straight out of the
config tables, defeating that rule entirely.

Consequences to know before changing anything here:
- **Backups are for diff/audit/reference, NOT for restore-to-device.** A redacted config cannot be
  replayed onto an appliance. Restore is not implemented, and adding it would require rethinking
  this tradeoff (e.g. a separately-encrypted restore artifact via credStore) — not just removing
  redaction.
- Redaction is deterministic, so it **cannot** cause spurious change detection. It is also
  irrelevant to diffing: `configDiff.js` diffs `config_parsed`, never `config_raw`.
- Any NEW adapter that returns a raw text config MUST redact before returning it from `getConfig()`.

#### ⛔ Retroactive `config_diffs` cleanup + a real secret-disclosure bug (found and fixed 2026-07-19)

User report: the Dashboard's "Config Changes" widget was showing entries like "5 modified — e.g.
system_info.time, system_info.uptime, system_info.wildfire-version" and asked, correctly, "these
aren't real changes — an admin didn't do this." Investigated directly against live production data
(read-only DB access — see "SecVault readonly DB access" section) rather than guessing:

- **The noise-filtering allowlist (`MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR`, above) was already correct
  and already working** — confirmed live: zero NEW noisy `config_diffs` rows recorded across ~15
  collects spanning 2 days, despite `system_info.time`/`.uptime` being mathematically guaranteed to
  differ every single collect. What the widget was showing was **28 historical rows recorded before
  this allowlist existed**, still inside the widget's 7-day trailing window — not a live bug.

- **While auditing those 28 rows to confirm they were safe to bulk-delete, found a real secret-disclosure
  bug**: one row (`ITC-SLY`, a Palo Alto API-transport device, 2026-07-16) had its `old` value containing
  a **raw, unredacted certificate private key and 16 local-admin/user password hashes**, captured
  verbatim at the exact moment that device's own redaction was fixed (old snapshot = raw secret, new
  snapshot = the vendor adapter's own `'<redacted>'` placeholder). `diffConfigs()` has no concept of
  "this leaf might be a secret" — it faithfully copies whatever `old`/`new` value it's given into the
  diff it persists. `config_diffs` is `GRANT SELECT`'d to `claude_readonly`/`nocvault_readonly` (see
  "Readonly Access for Diagnostics" above) — the exact roles this file bars from `device_credentials` —
  so this raw private key and these password hashes were readable by both roles in production. A
  **separate SSH-transport (`IDC FW`) row from the same day**, which wholesale-added an entire parsed
  config tree (`tree`/`vsys`/`services` — the exact moment the sshParser tokenizer rewrite landed, see
  "Palo Alto SSH — RESOLVED" above), was checked the same way and found already safely redacted at
  every private-key/phash occurrence — confirming this was a real but narrow, single-transport,
  single-day gap, not a broad ongoing leak.

**Fix, in `lib/engines/configDiff.js`:**
- **`SECRET_PATH_PATTERN`** — a value-level redaction pass, applied to every diff entry's
  `old`/`new`/`value` whenever the entry's leaf field name looks secret-shaped. Mirrors the
  `SECRET_KEY_PATTERN` convention already identical in `lib/adapters/checkpoint/parser.js` and
  `lib/adapters/forcepoint/parser.js`, widened to also catch `phash` (the exact field that leaked) and
  `pre[-_]?shared` (a bare `private[-_]?key` check does NOT match `"pre-shared-key"` — different word
  entirely, confirmed by testing the narrower pattern against the real leaked path and finding it
  silently missed it). A small **exception set** (`SECRET_PATH_EXCEPTIONS`, currently just
  `password_policy`/`password-policy`) exists because the broad `password` substring match would
  otherwise wholesale-redact Fortinet's real, legitimate `password_policy` config section (see
  "Fortinet gap closed 2026-07-19" above) just for containing that substring in its section NAME, not
  a credential value — found and fixed by testing the pattern against every real path in production
  history before shipping, not assumed safe. Same asymmetric-risk reasoning as
  `MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR`'s allowlist but inverted: a short, growable denylist-of-
  exceptions is fine here because missing one just over-redacts a section (safe direction), unlike
  under-listing the volatile-fields allowlist (which would be unsafe).
- Applied in **two places**: inside `diffConfigs()` itself (protects every diff computed from now on —
  defense in depth, on top of the adapter-level redaction that's supposed to make this layer
  unnecessary in the first place, same "redact defensively even when the upstream layer should already
  have done it" posture this codebase already applies to Check Point's/Forcepoint's `getConfig()`), and
  inside a new **`filterDiffForCurrentRules(diff, vendor)`** — re-applies both the volatile-path filter
  AND the new secret redaction to an ALREADY-STORED diff object, which is what actually scrubs the
  already-leaked secret out of the database, not just prevents new ones.
- **`cleanupVolatileConfigDiffs(pool)`** — a new, idempotent, best-effort migration (same pattern as
  `backfillVulnerabilityCategories()` in `lib/engines/vulnerabilityCategory.js`), wired into
  `lib/migrate.js`'s `main()` so it runs automatically on every `Update-SecVault.ps1` deploy. Re-filters
  every existing `config_diffs` row through the current rules: a row that becomes fully empty is
  **deleted** (pure noise); a row that still has real content after filtering is **updated in place**
  (noise dropped, any secret value redacted, `change_summary` re-derived) — never silently discarding a
  real change just because noise or a secret happened to be sitting next to it in the same row.
  Verified directly against live production data before shipping (not just unit-tested in isolation):
  of 31 total historical rows, 28 are pure noise (deleted), 2 have real content that survives filtering
  (updated — including the `ITC-SLY` secret, now redacted), 1 is untouched (the legitimate Fortinet
  `dns`/`ntp`/`fortiguard`/... section additions — see "Fortinet gap closed 2026-07-19" above; these
  are a genuine one-time collector-capability change, not noise, and correctly survive unfiltered).
  Compares the FULL re-filtered object against the original (not just entry counts), since secret
  redaction changes a row's CONTENT without changing its entry COUNT — a count-only comparison would
  have silently missed the exact case this migration exists to fix.
- **Not yet run against production** — this fix ships in code; the actual DB cleanup (deleting the 28
  noise rows, redacting the 2 real ones) happens the next time `Update-SecVault.ps1` (or the in-app
  "Update Now") runs `node lib/migrate.js` on the server. Until then, the already-exposed secret
  remains in the live database — deploy promptly after this lands.

#### ⛔ Palo Alto SSH redaction corrupted the config brace structure (found and fixed 2026-07-20)

Follow-up to the section above: a user reported the Dashboard's "Config Changes" widget rendering as
an unreadable wall of text — not the noise/secret issue already fixed, a new, distinct bug.
Root-caused directly against the live device's stored `config_raw` (read-only DB access): a real,
legitimate PAN-OS address object had a free-text `description` field written by an admin —
`description "Manage Change Password <text>";` — that happened to contain the word "Password".
`lib/adapters/paloalto/sshParser.js`'s `redactLine()` correctly matched it as secret-shaped
(fail-closed is the right call here — a description merely *mentioning* a password is exactly the
kind of ambiguous case that should redact), but its replacement discarded everything from the matched
word to the end of the line — **including the value's closing `"` and the trailing `;`**.
`tokenizeBraceConfig()` tracks quote state character-by-character and does not stop at a newline while
inside an open `"..."`, so the now-unterminated quote caused it to keep consuming every following
character — other objects' real `{`/`}`/`;` included — until the next `"` anywhere later in the file
happened to close it. That merged dozens of unrelated, subsequent address objects into one ~13,000-
character garbage key, which is exactly what `config_diffs.change_summary` and the per-device Changes
page were rendering.

**Fix**: `redactLine()` now locates every quoted span on the line first (`findQuotedSpans()`, mirroring
`tokenizeBraceConfig()`'s own backslash-escape handling exactly, so the two never disagree about what
counts as "inside a quote"), then branches on where the matched secret-shaped token sits — inside a
quoted free-text value, redact only the quoted CONTENT and keep the opening/closing `"` and trailing
`;` intact (`description "<redacted>";`); outside any quote (the token IS the real leaf key), redact
only the VALUE via a new `redactValuePreservingStructure()` helper, which likewise preserves a quoted
value's closing quote or a bare value's trailing `;`. Both properties — secret hidden, brace structure
never corrupted — hold simultaneously; this does not weaken redaction, it only stops the replacement
from eating structural characters it never should have touched. `redactConfig()`/`redactLine()` is the
one shared redaction pass for the whole SSH transport, so this single fix covers every quoted field
(descriptions, comments, etc.), not just the one that happened to surface.

**Known limitation**: this only prevents corruption on the *next* collect. It does not retroactively
repair the device's already-corrupted `config_diffs`/`device_configs` rows in production — unlike the
secret-disclosure case above, this doesn't need an active scrubbing migration, because the corrupted
snapshot is superseded by a correctly-parsed one on the device's next scheduled collect (the stale
snapshot simply ages out of the two-most-recent-snapshots diff window); expect one more noisy
"everything looks modified" diff on that next collect as the corrupted blob gets compared against the
real, correctly-parsed catalog, then it self-resolves.

#### ⛔ Dashboard widget grid: a corrupted `change_summary` string could blow the whole grid off-screen (found and fixed 2026-07-20)

Same underlying corrupted data as above, but a second, independent bug in how the Dashboard rendered
it — worth fixing on its own merits since ANY future long unbroken string in any widget could trigger
this identically, not just this one incident. The symptom looked like "two widgets vanished and the
remaining ones have wildly uneven widths" — live DOM inspection (`getComputedStyle`, not a screenshot
guess) showed `.dashboard-widget-grid`'s computed `grid-template-columns` as `194px 57696px 268px`: all
8 widgets were genuinely present in the DOM (`RiskByCategory`/`DeviceStatusSummary` were never
missing), just shoved to x≈58,183px — off-screen — because the middle column was ~58,000px wide.

Root cause: a CSS Grid item's default `min-width` is `auto`, which resolves to its content's
min-content size. `ConfigChangesWidget.js` renders each `change_summary` in a
`white-space: nowrap; overflow: hidden; text-overflow: ellipsis` span — correct for normal-length text,
but a `nowrap` span's min-content width is its FULL, untruncated text width (nowrap means no
line-break opportunities to shrink at), and `overflow:hidden`/ellipsis on the span itself does nothing
to stop that intrinsic size from propagating up to the ancestor GRID ITEM, which also defaults to
`min-width: auto`. The corrupted ~13,000-character string (see the redaction bug above) drove that
one grid item's min-content — and therefore its entire COLUMN's width, since CSS Grid sizes a column
track across all rows sharing it — to ~57,700px, dragging column 3 far outside the viewport with it.

**Fix**: `.dashboard-widget-grid > * { min-width: 0; }` in `app/globals.css`, scoped to direct children
of this one grid (not a global `.card` change, so no other page is affected). Verified live via
`getComputedStyle` before and after: before, `194.7px 57696.6px 268.9px`; after, all three tracks
exactly `533.33px`, all 8 widgets back in the visible viewport. This is a durable, generic fix — it
protects every current and future dashboard widget from this exact class of bug regardless of what
pathological content a future data source produces, not just this one corrupted row.

---

## Fleet Alerts Page (v2.1.0 — `/alerts`)

Fixes a real UX gap: the header notification bell (`components/layout/NotificationBell.js`)
surfaces fleet-wide "needs attention" items (originally new rule findings, patch-now CVEs,
unacknowledged config diffs — see the 2026-07-20 scope change below), but until this phase every
click either dropped the operator onto an unrelated device page or, for the dropdown's static
footer link, onto the fleet Rule Analysis summary — there was nowhere the bell itself could lead to
actually acknowledge/resolve anything.

**⛔ Scope change 2026-07-20 — `new_finding` REMOVED, direct user feedback.** A 2026-07-19 bug-sweep
fix correctly made rule-level findings visible here for the first time (they'd been invisible due to
a query bug — see the bug-sweep history below) — but a single device can carry hundreds of
`unused`/`shadow` findings, and surfacing every one blew the bell badge past its 99+ cap and buried
the two genuinely low-cardinality, curated types underneath a flood of findings that already have a
correct, dedicated triage home: the Cleanup/Optimization/Reorder tabs on `devices/[id]/analysis`
(`CleanupTab.js`'s `getCleanupFindings()`, which was never affected by the visibility bug in the
first place). Every mention of "new rule findings" / `new_finding` / three-way / `fetchNewFindings`
below this point describes the ORIGINAL, now-superseded design — kept for history, not current
behavior. Current state: `app/api/events/route.js`, `app/(dashboard)/alerts/page.js`, and
`app/api/notifications/summary/route.js` all support exactly two types, `patch_now` and
`config_diff`; `fetchNewFindings()` was deleted from all three (not merely disabled).

- **New table**: `cve_assessment_acknowledgements` (see Key Tables above) — `device_cve_assessments`
  has no ack column of its own, unlike `finding_acknowledgements` and `config_diffs.acknowledged_at`
  which already had one each. New ack route: `POST /api/devices/[id]/cve-acknowledgements`, body
  `{advisory_id, status, note?}`, upserts on `(device_id, advisory_id)` — copy of the existing
  `POST /api/devices/[id]/acknowledgements` pattern, adapted to the CVE key shape.
- **`GET /api/events`** — the fleet-wide, filterable, paginated version of what
  `app/api/notifications/summary/route.js` already does at a top-5-preview scale. Query params
  `type` (`new_finding`/`patch_now`/`config_diff`, omit = all three), `status` (`open` default /
  `all`), `device_id`, `page`. Three separate bounded queries (`LIMIT 500` each) merged/sorted/
  paginated **in JS**, not a DB-side UNION — same "bounded, not built for unlimited scale"
  tradeoff this codebase already accepts elsewhere (Phase 5 rule analysis caps at 1000 rules).
- **`app/(dashboard)/alerts/page.js`** — the actual page. Per this app's established convention
  ("server components query the DB directly, API routes exist for client-triggered writes" — see
  Rule Analysis Dashboard Phase 2 above), this page does **not** fetch its own `/api/events` route
  — it duplicates the same three-source query/merge/paginate logic directly via `pool.query`.
  `/api/events` exists for `AlertAckControl`'s post-save `router.refresh()` path and any future
  client-side consumer, not for this page's initial render. **This duplication is deliberate, not
  an oversight — the same pattern already exists once between `notifications/summary/route.js`
  (bell preview) and `/api/events` (full feed).** If you change the query/shape logic in one of
  the three places (`notifications/summary/route.js`, `api/events/route.js`,
  `alerts/page.js`), check the other two — nothing enforces them staying in sync automatically.
  A device_id filter that isn't a valid UUID is silently dropped (not a raw Postgres error) — a
  server-rendered page has no response-status channel to reject it the way the API route's
  `isValidUuid` 400 does.
- **`components/alerts/AlertAckControl.js`** — one control, branches on `item.ack.kind`:
  `finding`/`cve` render the shared 4-state `new/acknowledged/dismissed/actioned` select (POSTing
  to the respective ack route); `diff` is binary — `config_diffs` has no status enum, only
  `acknowledged_at`/`acknowledged_by` set once via the existing `PUT
  /api/devices/[id]/diffs/[diffId]` — so it renders a one-shot "Acknowledge" button, or a static
  "Acknowledged by X · date" label once set.
- **Notification bell rewiring**: `app/api/notifications/summary/route.js`'s three item queries
  now emit `href: /alerts?type=<type>&device_id=<id>` instead of per-type device-page links; the
  dropdown's footer button now reads "View All Alerts →" and routes to `/alerts` instead of the
  fleet Rule Analysis summary. Fleet Rule Analysis (`/analysis`) is unchanged and still exists —
  it's the aggregate severity-counts-per-device view, a different thing from this page's
  chronological cross-device event feed.
- **Sidebar nav**: new `Alerts` entry (`IconBell`, reused from the notification bell), positioned
  right after Dashboard.

---

## Compliance Engine (Phase 7 — `/compliance`, added 2026-07-17)

Reuses `lib/engines/applicability.js`'s predicate evaluator (`evaluatePredicate`, `hasUsableConfig`)
rather than a second implementation — compliance checks and CVE-applicability conditions are both
"evaluate a predicate against `device_configs.config_parsed`," just for different purposes.
`applicability.js` itself was touched only to export `hasUsableConfig` (it wasn't previously
exported) — its actual tri-state logic is unchanged.

### The tri-state → four-state polarity problem

`evaluatePredicate()` returns `'yes'|'no'|'unknown'` with no concept of which outcome is "good" —
a compliance check needs four states (`pass`/`fail`/`warning`/`na`), and different checks need
**opposite polarity** (a `feature_enabled` check on `logging.enabled` wants `'yes'` to mean PASS;
an `admin_access_from_zone` check on the WAN zone wants `'yes'` — access WAS found — to mean FAIL).
Resolved via a `pass_when: 'yes'|'no'` field inside each check's `predicate_config`, read by
`lib/engines/configAuditor.js`'s `evaluateCheck()`:
- No usable config at all (`hasUsableConfig()` false) → **every** check for that device → `'na'`,
  one early return, no per-check evaluation attempted ("nothing to check," not "checked and
  unsure").
- `evaluatePredicate()` result `'unknown'` → `'warning'` (config WAS collected, this specific value
  couldn't be resolved).
- result `=== pass_when` → `'pass'`; otherwise → `'fail'`.
- **`pass_when` missing or not exactly `'yes'`/`'no'`** (a malformed or hand-edited `audit_checks`
  row) → `'warning'`, never a silent default to either polarity — a bug here is a curated-data
  problem, not a device problem, and inverting pass/fail with no error would be exactly the kind of
  "looks fine, isn't" failure this whole tri-state discipline exists to prevent (same instinct as
  the "unknown never collapses to no" rule above). Found and fixed during this phase's own review
  before it shipped — an earlier version silently defaulted an invalid `pass_when` to `'yes'`.

### A third predicate type — `ruleset_property` (Dashboard Rebuild round, 2026-07-18)

Found via direct comparison against a competing firewall analyzer's compliance report on the same
real devices (see "Bug-sweep fixes... third-party comparison" below): two checks it has that
SecVault lacked — "explicit deny-all rule present" and "unwanted ICMP blocked" — are POSITIVE
existence questions ("does a required pattern exist SOMEWHERE in the ruleset?"), not the single-path
config lookups `evaluatePredicate()` (`applicability.js`) is built for, and not the "a bad pattern
should NOT exist" shape `rule_scan` checks already cover via Phase 5's `rule_analysis_results`. A
third predicate type, evaluated entirely inside `lib/engines/configAuditor.js` (NOT
`applicability.js` — it reads `firewall_rules` directly, not `config_parsed`, so the config-path
predicate model doesn't apply):
- `predicate_config: { predicate_type: 'ruleset_property', property: 'has_explicit_deny_all' |
  'blocks_icmp' }`
- `runComplianceAuditForDevice()` bulk-loads `SELECT action, src_addresses, dst_addresses, services,
  enabled FROM firewall_rules WHERE device_id = $1` once per device (only when the device has rules
  at all — `ruleCount === 0` short-circuits to `'na'`, matching every other check's "nothing to
  measure" convention) and reuses it for both checks, rather than re-querying per check.
- `hasExplicitDenyAll(rules)`: true when an enabled rule's action is a deny-family action
  (`deny`/`drop`/`reject`/`block`) AND every one of its src/dst/service fields resolves to an "any"
  alias (`ANY_ALIASES` — reuses the same any-detection vocabulary `ruleAnalysis.js`'s `isAny()`
  already established, so a rule this check calls "deny-all" is the same thing the Phase 5 `any_any`
  finding would call "any-any" if it were an allow rule).
- `blocksIcmp(rules)`: true when an enabled deny-family rule's `services` array contains an entry
  matching `/\bicmp\b/i` — a plain substring/word-boundary test, not full protocol-object resolution
  (an ICMP block expressed only via an unresolved custom service-object name won't be detected; same
  "resolved literals only" limitation the CIDR-aware `fieldCovers()` work already accepts elsewhere
  in this codebase).
- Both checks are `severity: 'medium'`/`'low'` respectively, `vendor: null` (apply to every vendor —
  rule fields are already normalized to `NormalizedRule` shape by every adapter, so no vendor-specific
  path is needed, unlike almost every other check in this file).

### `audit_checks.standards` is `TEXT[]`, not a single value

The compliance spec's own standard-mapping ("logging checks → PCI_DSS + ISO_27001," "access-control
checks → PCI_DSS + CIS_V8 + ISO_27001 + NIST") requires ONE check to score against MULTIPLE
standards simultaneously — a single-value column can't represent that many-to-many relationship. A
plain Postgres array avoids a join table for what is small, rarely-changing curated data (same
tradeoff `affected_version_ranges`/`fixed_in_versions` already make as JSONB instead of child
tables). `node-postgres` returns this as a real JS array automatically — no parsing needed on read.

### Seed library — `lib/auditChecksSeed.js`, called from `lib/migrate.js`

44 checks as of the Dashboard Rebuild round (42 vendor-specific/shared config-path checks + the 2
new `ruleset_property` checks above, which are `vendor: null` and apply fleet-wide — see that
section for what they check). The original count was 28 checks (8 shared concepts × 2 vendors, since Fortinet's and Palo Alto's `config_parsed` trees
have completely different shapes per their different parsers — a single vendor-NULL row with one
`path` can't realistically match both — plus 6 Fortinet-specific + 6 Palo Alto-specific), following
`lib/migrate.js`'s existing `seedDefaultAdmin()` pattern: an idempotent JS function
(`ON CONFLICT (check_id) DO UPDATE`), not a raw `.sql` seed file — called **unguarded** from
`main()` (unlike `schema-grants.sql`'s best-effort tolerance: a seed failure here means the
compliance feature silently has zero checks, which should fail the whole `migrate.js` run loudly,
not be swallowed).

Predicate paths are grounded in this codebase's own parser output where verifiable — Palo Alto's
`lib/adapters/paloalto/sshParser.js` is live-verified (see "Live Validation Status" above:
`mgt-config.users`, `deviceconfig.system.panorama`, `rulebase.security.rules` are real, confirmed
paths) — and, as of 2026-07-19, so is 5 of 7 Fortinet gaps (see below). **3 Palo Alto checks still
use `predicate_type: 'not_evaluable_from_config'`** (⛔ count corrected again 2026-07-19 — this
section previously said "11 of 28, 8 Fortinet + 3 Palo Alto"; the real number, counted directly
against `checkId`/`predicate_type` pairs in `lib/auditChecksSeed.js` — not re-derived from this
file's own prior text, which is exactly how the miscount happened the first time — was 7 Fortinet +
3 Palo Alto = 10. The 2026-07-19 Fortinet adapter extension below closed 5 of those 7, leaving 2
Fortinet + 3 Palo Alto = 5 still `not_evaluable_from_config` today), a string that doesn't match any
of `applicability.js`'s six real predicate cases and therefore correctly falls through to its
`default: return 'unknown'` branch — i.e. these checks always render as `'warning'`, honestly, rather
than guessing a path into a config section the relevant adapter's `getConfig()` doesn't currently
collect. The 3 Palo Alto checks have this gap against `lib/adapters/paloalto/sshParser.js`'s
collected tree — extending that adapter's collected sections is the natural follow-up, same pattern
as the Fortinet fix below, not yet done.

**Fortinet gap closed 2026-07-19 (5 of 7 checks) — `lib/adapters/fortinet/index.js`/`api.js`
(REST) and `ssh.js`/`cliParser.js` (SSH) now collect 6 more `config_parsed` sections**, on top of
the original 5 (`global`/`interfaces`/`ssl_vpn`/`snmp`/`admins`): `ntp`, `dns`, `log_syslogd`,
`password_policy`, `fortiguard`, `autoupdate_schedule` — each a flat `{key: value}` object of that
FortiOS section's direct settings (CLI: `settingsOfFirst(path) = flattenSettings(findBlockDeep(tree,
path))`, the same pattern the original 5 already used; REST: one new `api.js` fetch function +
`sections` array row each, same data-driven pattern as the original 5). Deliberately flat-only — e.g.
`system ntp`'s nested `ntpserver` table is NOT collected, since the checks below only need the flat
`ntpsync` toggle. This let 5 of the 7 Fortinet `not_evaluable_from_config` checks be upgraded to real
predicates: `fortinet-ntp-configured` (`feature_enabled`, `ntp.ntpsync`), `fortinet-dns-configured`
(`config_key_exists`, `dns.primary`), `fortinet-logging-enabled` (`feature_enabled`,
`log_syslogd.status`), `fortinet-password-min-length` (`config_key_exists`,
`password_policy.minimum-length` — presence-only, same "doesn't prove a non-default value" caveat as
the sibling `fortinet-session-timeout` check), `fortinet-fortiguard-updates-enabled`
(`feature_enabled`, `autoupdate_schedule.status`). The remaining 2 Fortinet checks —
`fortinet-ips-internet-facing-policies` (per-rule data, lives in `firewall_rules.raw_rule` not
`device_configs.config_parsed` — the predicate engine only supports one fixed dot-path per check, not
"for every rule") and `fortinet-unused-interfaces-shutdown` (needs traffic/hit-count telemetry a
static config snapshot structurally cannot contain) — are **not** fixable by collecting more config
sections and remain `not_evaluable_from_config` for those structural reasons; see
`lib/auditChecksSeed.js`'s own header comment for the reason-(a)-vs-(b) taxonomy.

⚠️ **All 6 new sections' field paths (`ntp.ntpsync`, `dns.primary`, `log_syslogd.status`,
`password_policy.minimum-length`, `autoupdate_schedule.status`) are doc-derived from standard
FortiOS CLI/REST conventions, matching the same "written without a live FortiGate" posture as every
other Fortinet field mapping in this file — NOT yet confirmed against a live device.** A live
Fortinet SSH device exists in this deployment (added 2026-07-19); its next collect should be checked
against `[Fortinet Debug]` log output to confirm/correct these paths, same verification step every
other unresolved vendor mapping in this file is waiting on. If any turn out wrong, only
`lib/auditChecksSeed.js` and the two adapter files need updating — the predicate engine itself
(`applicability.js`) needs no change either way.

**Second round, same day: 2 more real Fortinet checks + Cisco ASA's first-ever compliance
coverage.** `fortinet-admin-2fa-required` (`feature_enabled`, `admins.0.two-factor`) and
`fortinet-password-policy-enabled` (`feature_enabled`, `password_policy.status`) needed **no
adapter work at all** — `admins`/`password_policy` were already-collected sections from the first
round above. `fortinet-admin-2fa-required` is notable: unlike almost every other Fortinet path in
this file, `admins[0]['two-factor']` is **live-confirmed**, not doc-derived — a direct production DB
query the same day read a real device's `admins[0]` and found `"two-factor": "disable"` (see the VPN
Summary section below for how that DB access came about). Same index-0-only limitation as
`fortinet-default-admin-active` (no "for every admin" capability in this predicate engine — see
`lib/engines/adminAccountSummary.js` below for the UI-layer alternative that CAN iterate the whole
array). `fortinet-password-policy-enabled` is a stronger check than the existing
`fortinet-password-min-length` — it proves the policy block is actually enforced (`status enable`),
not just that a field is present in the dump.

`lib/auditChecksSeed.js` also gained its first `vendor: 'cisco_asa'` rows (3 checks) — Cisco ASA had
ZERO compliance coverage before this, despite `lib/adapters/cisco_asa/parser.js`'s `parseRunningConfig()`
already collecting real, checkable data. `cisco-asa-telnet-disabled` (`critical` — a configured
`telnet_sources` entry is a genuine cleartext-management finding, not a hardening suggestion) and
`cisco-asa-http-server-disabled` (`high`) are both real predicates. Both needed a small correctness
question answered first: `parsed.telnet_sources`/`parsed.usernames` are ARRAYS, and an empty array
still resolves `config_key_exists` to `'yes'` on the bare path (an empty array is defined, not
undefined) — the fix is targeting `path: 'telnet_sources.0'` specifically. `getByPath()`'s tokenizer
(`([^[\].]+)|\[(\d+)\]`) never reaches its `[digit]` branch for a bare dot-segment like `.0` — it
captures `'0'` via the **string** alternative — but `array['0']` resolves identically to `array[0]`
in JS (array indices are just string-keyed properties), so `config_key_exists` on `telnet_sources.0`
correctly means "index 0 exists" = "the array is non-empty", exactly the signal needed, confirmed by
reading `getByPath()`'s actual implementation rather than assumed. A third candidate check,
`cisco-asa-local-admin-accounts-present`, was deliberately left `not_evaluable_from_config` — ASA's
`usernames` field captures names only (no role/privilege/password data, by the parser's own explicit
design), and "at least one local account exists" isn't a real pass/fail concept (local accounts are
often necessary) — forcing a polarity on it would have been exactly the kind of misleading
confident-answer this file's own `not_evaluable_from_config` convention exists to prevent.

### Engine — `lib/engines/configAuditor.js`

`runComplianceAuditForDevice(deviceId, pool)` mirrors `runAnalysisForDevice()`'s shape (Phase 5):
load device + latest `config_parsed` (via `applicability.js`'s `getLatestConfigParsed`) + applicable
checks (`vendor IS NULL OR vendor = $1`), evaluate, then DELETE+reinsert that device's
`audit_findings` inside one transaction — same "a partial rewrite must never leave findings in a
mixed old/new state" reasoning as `rule_analysis_results` and `firewall_rules`. Runs automatically
in `lib/adapters/index.js`'s `collectAndStore`, right after the Phase 6 config-diff block, gated on
`result.configCollected`; also runnable on-demand via `POST /api/compliance/[deviceId]/run`.

### API + UI

`GET /api/compliance/[deviceId]` (per-device findings + per-standard pass/fail/warning/na counts +
`scorePct`), `GET /api/compliance/fleet` (same shape, one row per active device), `POST
/api/compliance/[deviceId]/run` (on-demand trigger). `scorePct = round(100 * pass / (pass + fail +
warning))`, **excluding `na` from the denominator** (an inapplicable check shouldn't count against
the score), `null` — not `0`/`NaN` — when nothing is measurable (never audited, or every mapped
check is `na`) — rendered as "—", since null and 0% mean very different things.

`/compliance` (fleet-wide) and `/compliance/[deviceId]` (per-device) both query the DB directly
rather than fetching their own paired API route, same "server components query the DB directly"
convention as the Alerts page — the API routes exist for `RunAuditButton`'s POST and any future
client-side consumer, not for these pages' own initial render; the aggregation SQL is therefore
intentionally duplicated in 4 places (both API routes + both pages) and must be kept in step by
inspection if the scoring formula ever changes, same caveat as the Alerts/events split above.

#### Standard donut cards, print report, CSV export (2026-07-19)

Both compliance pages' original "flat StatCard tiles + table" layout was replaced with a
`StandardCard` (`components/compliance/StandardCard.js`) grid, one card per standard: a
`StandardDonut` (`components/compliance/StandardDonut.js`, `'use client'`, recharts `Pie`, one
2-segment ring so the colored arc + gray track always sum to a full circle — color pulled from
`ComplianceMatrix.js`'s existing `scoreColor`/`SCORE_COLOR_VAR`, reused rather than re-derived), a
short factual description + external reference link per standard (`STANDARD_META`, exported from
`ComplianceMatrix.js` alongside `STANDARDS` — generic "this assessment is based on..." wording,
never a claim about SecVault's own certification status, since it has none), and a "Failed" quick-list
(up to 5 items + "+N more"). At `scorePct === 100` the card shows a `Badge color="success"`
"Fully Compliant" in place of the failed-list (no emoji anywhere in this codebase, confirmed by grep
before choosing this — see `StandardCard.js`'s own comment).

**⛔ Superseded 2026-07-18** (see the dated subsection below): this paragraph originally described
`compliance/page.js`'s Cards view as fleet-wide, with its quick-list showing DEVICE names instead of
check names. That fleet-aggregate Cards view no longer exists — Cards is now per-device, exactly
like `compliance/[deviceId]/page.js`, chosen via a dropdown. Both pages' quick-lists now show the
same thing: failing CHECK NAMES for whichever one device is on screen.

#### Fleet Cards view becomes per-device, via a dropdown (changed 2026-07-18)

Direct user feedback, comparing against ManageEngine Firewall Analyzer: "the main compliance page
shows the donuts and percentage for the current chosen firewall. It does not show summary for all."
`compliance/page.js`'s "Cards" view used to sum every active device's findings into ONE set of
fleet-wide donuts per standard — genuinely not what an operator auditing a SPECIFIC firewall wants,
and there was no way to drill into one device's posture from that view at all (only via
`compliance/[deviceId]` reached some other way, e.g. the fleet dashboard or Devices list).

Cards now shows exactly ONE device's compliance posture at a time, chosen via
`components/compliance/DeviceSelect.js` (new, `'use client'`, a plain `<select>` — same
"navigate via `router.push` on every `onChange`" convention `components/alerts/AlertsFilters.js`
already uses for its own filter selects, a real Next.js client-side navigation rather than a full
page reload, satisfying "interactively update" without any client-side fetch/state management) —
driven by `?device=<deviceId>` on the SAME `/compliance` URL. **Never falls back to a fleet-wide
aggregate**: no `?device=` (or a malformed/stale one — validated with `isValidUuid()` AND checked
against the active-devices list, same defensive posture as everywhere else in this app) defaults to
the first active device alphabetically; zero active devices renders `EmptyState` before any
per-device query is attempted.

The per-device query/aggregation/JSX in `compliance/page.js`'s Cards branch DELIBERATELY duplicates
`compliance/[deviceId]/page.js`'s own (down to the query shapes and comments) rather than importing
from it — same "duplicate small per-page queries, don't extract a shared module" convention this
codebase already uses for the Alerts/Compliance query triplication. `compliance/[deviceId]/page.js`
itself is UNCHANGED and still a valid, separate, deep-linkable "this device's compliance" page
(reached from the Devices list, Alerts, etc.) — Cards and that page now render near-identically,
just reached differently.

**"Compare Devices" (`?view=table`) is UNCHANGED** — still the fleet-wide device×standard
`ComplianceMatrix` table, still the place to see every device's score side by side; `getFleetCompliance()`
(the query feeding it) was kept. `getFleetFailedDevicesByStandard()` and `getFleetStandardTotals()`
(both used ONLY by the old fleet-aggregate Cards rendering) were removed as dead code rather than
left unused.

`Export CSV` is now conditional on which view is active: Cards points at the SELECTED device's own
`GET /api/compliance/[deviceId]?format=csv` (since that's what's actually on screen), table keeps
pointing at the fleet-wide `GET /api/compliance/fleet?format=csv` exactly as before.

#### Rule-evidence drill-down + `rule_scan` checks + SANS standard (added 2026-07-18)

**The gap this closes**: every check up to this point (`predicate_type`: `config_key_exists` /
`config_value_equals` / `config_value_matches` / `feature_enabled` / `port_exposed` /
`admin_access_from_zone` / `not_evaluable_from_config`) is evaluated by `applicability.js`'s
`evaluatePredicate()` against ONE fixed dot-path in `device_configs.config_parsed` — a failed check
produced only a generic sentence, never a list of which actual RULES caused the failure. A
competing product (ManageEngine Firewall Analyzer) shows exactly that: click a failed section, see
the offending rules in a table, plus written remediation. SecVault already had the rule-scanning
half of this — `lib/engines/ruleAnalysis.js`'s Phase 5 findings — just not surfaced as compliance
evidence.

**`predicate_type: 'rule_scan'`** — a SECOND, distinct kind of `audit_checks` row, evaluated by
`configAuditor.js` directly (`evaluateRuleScanCheck()`/`loadRuleFindingsByType()`), NOT by
`applicability.js`. `predicate_config` shape: `{predicate_type: 'rule_scan', finding_types: [...]}`
— no `pass_when`, since every rule_scan check today is fixed-polarity ("this bad pattern should
never exist" — zero matching rules is always PASS, any match is always FAIL; there's no meaningful
inverse reading the way `feature_enabled`/`admin_access_from_zone` need one). Reuses
`rule_analysis_results` findings that `ruleAnalysis.js` already computed rather than a second
detection pass — `rule_scan` checks don't need `device_configs.config_parsed` (`hasUsableConfig()`)
at all, only `firewall_rules` to exist; a device with rules collected but no successful config pull
yet still gets real `rule_scan` results instead of a blanket `na`.

**`audit_findings.matched_rule_ids UUID[]`** (nullable) carries the evidence: the `firewall_rules.id`
values that caused a `rule_scan` fail. NULL for every config-predicate check (nothing single-rule to
point at) and for a passing/na `rule_scan` check. Not a DB-enforced FK-on-array-element (Postgres has
none) — safe regardless, since both `firewall_rules` and `audit_findings` are fully DELETE+reinserted
on every pull/run, so a stale id here just resolves to zero rows on the next JOIN, never a broken
reference living past the next collect.

**7 new rule_scan checks** (`vendor: null` — `firewall_rules`/`rule_analysis_results` are already
vendor-normalized, no per-vendor duplication needed): `rule-no-any-any-allow` (`any_any`, critical),
`rule-no-risky-services` (`risky_service`, high), `rule-logging-enabled-on-rules` (`log_disabled`,
medium), `rule-no-shadowed-rules` (`shadow`, high), `rule-no-redundant-rules` (`redundant`, medium),
`rule-no-overly-permissive-rules` (`overly_permissive`, medium), `rule-stale-unused-rules-reviewed`
(`unused`, low). `correlation` (see Rule Analysis Dashboard section above) was deliberately NOT given
a compliance check — it's a ruleset-simplification suggestion, not something any of the mapped
standards actually mandate as a checklist item; forcing a pass/fail polarity onto it would be the
same kind of misleading confident-answer this codebase's `not_evaluable_from_config` convention
already exists to avoid.

**UI**: `components/compliance/RuleEvidenceTable.js` (new) — a compact table (Rule Name/Action/
Source/Destination/Service/Src Zone/Dst Zone), mirroring `devices/[id]/rules/page.js`'s cell-
formatting convention (comma-joined, `—` fallback) rather than inventing a new one — that file
doesn't export its `joinArray()` helper, so it's duplicated, matching this app's established
per-file-duplication convention for small render helpers. `StandardTabs.js` gained a Pass/Fail/All
sub-filter. **Superseded 2026-07-18** (see the fifth bug-sweep pass below): the inline "Show N
offending rule(s)" expand/collapse described here originally was REMOVED after a user reported it
looked like clicking a failed check did nothing — evidence is now shown on a dedicated per-check
page (`compliance/[deviceId]/checks/[findingId]/page.js`), a real navigation, not a same-page
toggle; `RuleEvidenceTable` is still used, just from that page instead of inline in this table.
`compliance/[deviceId]/page.js` resolves `matched_rule_ids` to full rule rows in ONE bulk
`WHERE id = ANY($1::uuid[])` query (deduped across every finding, not per-row) and also gained a
**Network Details** card — distinct zone names aggregated from this device's `firewall_rules.src_
zones`/`dst_zones`. Those columns' shape varies by vendor and is not guaranteed to always be a flat
JSON array (some parser could store something else), so the aggregation query guards with
`jsonb_typeof(...) = 'array'` and the whole thing is wrapped in try/catch — any error just omits the
card silently rather than risk crashing the page render, since this is an enrichment, not a required
element. `GET /api/compliance/[deviceId]` (JSON + CSV) also carries `matchedRuleIds`/a "Matched
Rules" column now, for the RunAuditButton refresh path and CSV export.

**New standard: SANS.** Real, cited source — SANS Institute's own published "Firewall Checklist"
(Krishni Naidu), `https://www.sans.org/media/score/checklists/FirewallChecklist.pdf`, a 91-item
numbered SCORE checklist, fetched and read directly (not paraphrased from memory) before writing any
check. `STANDARD_META.SANS` is explicit that this maps to the checklist's recurring THEMES, not
literal section-numbered citations of a formal regulatory framework, since SANS SCORE checklists are
practitioner guidance, not a certifiable standard — the same honesty `STANDARD_META`'s existing
entries already apply to SecVault's own non-certification status. 11 checks carry the `SANS` tag,
each with the specific checklist item numbers cited in its `description` (e.g. `rule-no-risky-
services` cites items 34/37/44-45/53-55/57-58/70 for Telnet/FTP/TFTP/rlogin-rsh/NetBIOS-SMB/SNMP).
**Deliberately did NOT add every standard ManageEngine ships** (NERC-CIP, SOX, GDPR, CJIS, GSMA,
HIPAA, ...) — those require interpreting legal/regulatory text, not enumerating a published
checklist, and getting that wrong is a compliance-liability risk, not a feature. NIST SP 800-41 Rev.
1 ("Guidelines on Firewalls and Firewall Policy," `https://csrc.nist.gov/pubs/sp/800/41/r1/final`)
was folded into the EXISTING `NIST` standard's description (formal change-control ruleset review,
continuous log/alert monitoring) rather than added as a confusing second NIST-labeled standard key.

The fleet page (`compliance/page.js`) gained a `?view=cards|table` toggle (`cards` is now the
default) — `cards` shows the new fleet-wide `StandardCard` grid (per-standard totals summed in JS
from the same per-device data `getFleetCompliance` already fetches, no new query for the numbers
themselves), `table` is the original device×standard `ComplianceMatrix` comparison table, unchanged
and still reachable, since a wide fleet is easier to scan as a table than as N cards.

`StandardTabs.js`'s hash-based deep-link (`/compliance/[deviceId]#CIS_V8` preselects that tab) used
to only read `window.location.hash` once, on mount — the new `StandardCard` failed-check links point
at `#STANDARD_KEY` anchors on the *same* page, and a same-page `next/link` hash change doesn't
remount the component under App Router, so the original mount-only read never saw it. Fixed by
adding a `hashchange` listener alongside the existing mount-time read (`StandardTabs.js`) — both the
original cross-page case and the new same-page case now work identically.

**CSV export** — `?format=csv` was added to all three `GET` routes above (`/api/compliance/[deviceId]`,
`/api/compliance/fleet`, and `/api/devices/[id]/analysis` for the Rule Analysis sibling below),
mirroring the pre-existing `GET /api/devices/[id]/rules?format=csv` pattern exactly (per-route
`csvEscape`/`buildCsv` duplicates, `Content-Disposition: attachment` — this codebase's established
per-file-duplication convention for small helpers, not a shared utility module). Every compliance/
analysis page now has an "Export CSV" action button pointing at its sibling route with `?format=csv`.

**Print report** — a new route, `/compliance/[deviceId]/print`, a server-rendered, chrome-free report
page (duplicates `getDevice`/`getFindings`/`aggregateStandards` from the sibling live page, same
"duplication is deliberate" convention) showing **all 4 standards' full findings in one scroll**
(unlike the live page's client-side `StandardTabs`, which shows one standard at a time) — that's the
whole point of an exportable report. A `PrintReportButton` (`'use client'`, the only client boundary
needed — `window.print()` requires `onClick`, which a Server Component can't hold) triggers the
browser's native print/Save-as-PDF dialog. `app/globals.css` gained an additive-only `@media print`
block (nothing existing was touched) that hides the `.sv-topbar`/`.sv-sidebar` app chrome and any
`.no-print`-marked element, forces light-theme colors regardless of the operator's saved dark-mode
preference (paper should never render dark colors), and gives `.print-report` sensible page-break/
margin behavior. This print stylesheet applies to any page printed while inside the dashboard shell,
not just the report route, since hiding app chrome on paper is a reasonable default everywhere.

---

## VPN Summary + Session Polling (added 2026-07-19)

Two distinct capabilities, deliberately kept separate — mirrors the split ManageEngine Firewall
Analyzer itself has between "VPN Summary" (config-derived) and "VPN Reports" (log-derived), a
useful model since SecVault genuinely can only build the first one without syslog ingestion:

1. **VPN config summary** — read-only interpretation of each vendor's already-collected
   `device_configs.config_parsed`, showing whatever VPN/remote-access config exists. No new
   collection was needed for 2 of 4 covered vendors (see below) — this closes a real "collected but
   never surfaced" gap, same pattern as `nat_enabled` and the Fortinet compliance-section work.
2. **VPN active-session polling** — a NEW, Fortinet-only capability: periodically ask the device how
   many SSL-VPN sessions are active right now and store a timestamped snapshot. A coarse,
   polling-based APPROXIMATION of real VPN usage telemetry — genuine per-user login history,
   session duration, and bytes transferred all require syslog ingestion (Phase 8, not built) and
   cannot be produced by polling. This is explicitly the bounded, no-log-ingestion-required
   substitute discussed when this was scoped, not a replacement for Phase 8.

### `lib/engines/vpnSummary.js` — per-vendor config interpretation

Pure module, `summarizeVpnConfig(vendor, configParsed) -> {supported, hasConfig, enabled?,
sourceInterface?, foundAt?, fields, lowConfidence?, error?}`. One interpreter function per vendor,
each grounded in that vendor's ACTUAL `config_parsed` shape (verified by reading the real adapter
code before writing this, not assumed):

- **Fortinet**: `ssl_vpn` is already a flat `{key: value}` object (both transports collect it — see
  Compliance Engine section above). `source-interface` presence is used as the signal, the same
  field `fortinet-sslvpn-not-wan-exposed` (Compliance Engine) already treats as grounded/real.
- **Cisco ASA**: `parsed.webvpn.{enabled, enabled_interface}`, a real boolean added to
  `lib/adapters/cisco_asa/parser.js`'s `parseRunningConfig()` this same day — minimal, low-risk
  presence detection only (a `webvpn` block + `enable <interface>` line, mirroring the existing
  `currentInterface` block-tracking pattern already in that file). Deliberately does NOT parse
  `tunnel-group`/`group-policy`/`anyconnect image` — out of scope, would need much deeper ASA config
  modeling than this file currently supports.
- **Sangfor**: `parsed.sections.ssl_vpn.enabled`, a **tri-state** (`true`/`false`/`null`) added to
  `lib/adapters/sangfor/parser.js`. Sangfor is this codebase's least-verified adapter (see Live
  Validation Status below) — `null` (undetected) is documented as the EXPECTED common case, not a
  failure, and the UI renders a "Low confidence — doc-derived, unverified for this vendor" badge
  whenever this vendor's summary is shown, so the uncertainty is visible, not hidden.
- **Palo Alto (both SSH and XML/API transports)**: **no adapter change was needed at all** — the
  full config tree is already present in `config_parsed` (SSH under `.tree`; XML/API spread directly
  at the top level — see `lib/adapters/paloalto/{sshParser,parser}.js`'s own `parseConfig()`).
  `vpnSummary.js` does a bounded (depth 8) deep search for a key whose name contains
  `global-protect`/`globalprotect`, rather than assuming one exact path — PAN-OS config nesting
  varies (single-vsys root, `vsys.entry`, `shared`, Panorama pre/post-rulebase), the exact same
  structural variability `findSecurityRulesContainers()` already has to search deep for security
  rules, for the identical reason (see Live Validation Status below). This is a UI-layer concern,
  free to search deeply — the compliance predicate engine (`evaluatePredicate()`, exactly one fixed
  dot-path per check) could NOT do this safely, which is why **no Palo Alto GlobalProtect compliance
  check was added** — a deliberate scope decision, not an oversight.
  - ⛔ **Bug fixed 2026-07-19, found the same day this shipped**: the SSH-transport branch originally
    searched `configParsed.tree` assuming a `{settings, blocks: {name: Node}, entries: [Node]}` Node
    shape (mirroring Fortinet's `cliParser.js` tree). That assumption was wrong — verified directly
    against `lib/adapters/paloalto/sshParser.js`'s real, current `parseBraceBlock()`, which builds a
    **plain nested object** instead (`node[key] = child`, no `.blocks`/`.entries` wrapper — the same
    shape the XML/API transport already has). The dedicated tree-walking helpers
    (`deepFindBlockInTree`/`flattenNodeSettings`) were therefore searching for a `.blocks` property
    that never exists on a real parsed tree, meaning GlobalProtect was **never found for any
    SSH-collected Palo Alto device**, including this deployment's live `IDC FW` device — silently
    rendering "no VPN config found" regardless of the device's actual configuration. Fixed by
    deleting both Node-shaped helpers and using the same plain-object `deepFindKeyByPattern()` the
    XML/API branch already used correctly, rooted at `.tree` instead of `configParsed` itself — both
    transports turn out to need the identical generic walker.
- **Check Point**: not in the dispatch table at all — `summarizeVpnConfig` returns
  `{supported: false, ...}`, which the UI renders distinctly from `{supported: true, hasConfig:
  false}` ("collected, and it's genuinely empty" is a different fact from "not implemented yet").

⚠️ All four vendors' VPN fields are doc-derived and NOT yet live-verified (Fortinet's `ssl_vpn`
fields specifically — `source-interface`/`port`/`idle-timeout`/`ssl-min-proto-ver` — same standing
caveat as the rest of this file's Fortinet work; Cisco ASA/Sangfor's detection logic likewise). A
live Fortinet SSH device exists in this deployment — check its VPN Summary page against the real
device's actual SSL-VPN config on the next collect.

### `vpn_session_snapshots` — active-session polling (Fortinet only)

New table (`lib/schema.sql`): `device_id`, `active_session_count` (NOT NULL — a row is only ever
inserted on a SUCCESSFUL poll, never a guessed/zero value on failure), `raw` (jsonb, the adapter's
raw response for future debugging), `sampled_at`. No retention/cleanup job exists yet (accepted
simplification — ~17.5k rows/device/year at the default 30-minute interval, not a near-term scaling
concern).

**Fortinet adapter** (both transports) gained an OPTIONAL capability, `getVpnSessionSummary()` — NOT
part of the `FirewallAdapter` base interface (`testConnectivity`/`getVersion`/`getRules`/
`getConfig`), checked via `typeof adapter.getVpnSessionSummary === 'function'` before use, since
most vendors don't implement it:
- **SSH**: `get vpn ssl monitor` (a real, documented FortiOS operational command), parsed by
  `cliParser.countActiveVpnSessions()` — counts numbered session rows under a "SSL VPN Login Users:"
  header rather than parsing every field (only the COUNT is needed). Returns `null` (not `0`) when
  the header itself isn't found at all — the caller MUST treat that as "unrecognized output, don't
  trust a count," never as "confirmed zero active sessions" (finding the header IS the signal this
  is the right output shape; zero rows after a found header is a legitimate real zero). `getRules()`
  /`getConfig()`'s existing fail-loud philosophy applies here too — `getVpnSessionSummary()` throws
  rather than guessing.
- **REST**: `GET /api/v2/monitor/vpn/ssl` (a monitor endpoint, not cmdb — live/operational state).
  Counts `results.length` rather than parsing individual session fields, sidestepping uncertainty
  about the exact per-session field shape (not yet live-verified).

⛔ **VDOM-awareness bug fixed 2026-07-19, found the same day this shipped**: both transports
originally ran their session-count command exactly once, in the admin session's own default-VDOM
context — the identical "silent under-count on a multi-VDOM box" class of bug this file's own VDOM
rule already documents for `getRules()` (a request without `?vdom=`/VDOM enumeration only reflects
one VDOM, and looks like a complete, correct total). Fixed to mirror `getRules()`'s existing
`_discoverVdoms()`/per-VDOM pattern on both transports (REST: `getSslVpnMonitor(conn, vdom)` now
takes an optional vdom param, summed across all VDOMs; SSH: a new `getVpnSessionSummaryMultiVdom()`
batches `config vdom`/`edit <vdom>`/`get vpn ssl monitor`/`end` for every VDOM in one round-trip, the
same command-batching shape as `_getRulesMultiVdom()`). Deliberately **more lenient** than
`getRules()` in one respect, on purpose: `getRules()` has no per-VDOM try/catch (one VDOM's failure
must fail the whole authoritative ruleset collection), but the VPN poll degrades gracefully per VDOM
(`raw.partial: true` when some VDOMs failed) since a partial count is still a meaningful coarse trend
signal — only throws overall when the VDOM list itself can't be enumerated at all (mirroring
`getRules()`'s reasoning there exactly: a KNOWN multi-VDOM box silently falling back to a
single-VDOM count would look like a real, complete total, which is worse than an error).

⛔ **Job-overlap race fixed 2026-07-19, found the same day this shipped**: `node-cron` 3.x has no
overlap protection of its own — a scheduled tick fires unconditionally even if the previous
invocation of the SAME job is still running. Unlikely to matter for the two pre-existing jobs' hours-
scale cadences, but the new minutes-scale `vpn-session-poll` job made two failure modes routinely
reachable: (a) the job overlapping its own next tick if a poll cycle runs long, and (b)
`vpn-session-poll` and `rule-version-pull` running concurrently against the SAME device, opening two
separate SSH/REST sessions to one firewall at once (`lib/adapters/fortinet/api.js` notes a concurrent
admin-session cap that a second session can hit). Two boolean flags (`ruleVersionPullInFlight`,
`vpnPollInFlight`) close both cases: a job never re-enters itself, and `vpn-session-poll` (a coarse,
can-wait-a-cycle signal) defers a whole tick rather than run alongside the higher-priority,
authoritative `rule-version-pull` job. Not a full per-device lock — that's a bigger change, not done.

**`services/engine-worker.js`** gained a third scheduled job, `vpn-session-poll`, on its OWN interval
(`VPN_POLL_INTERVAL_MINUTES`, default 30, clamped 5-59 — deliberately minutes-scale, unlike the
other two jobs' hours-scale intervals, since a meaningful "sessions over time" trend needs much
finer sampling). Iterates active devices, skips any whose adapter lacks `getVpnSessionSummary`,
inserts one `vpn_session_snapshots` row per successful poll, logs and continues past any per-device
failure — same per-device isolation as `runRuleVersionPullJob`.

⛔ **Bug fixed in passing, found while adding this job**: `isJobRunning` (the flag `shutdown()` polls
to let an in-flight job finish before the process exits) was a **boolean**, correct for exactly one
job in flight at a time. The two pre-existing jobs' hours-scale cron cadences were unlikely to ever
overlap in practice, so this was a latent bug, not yet a reachable one. The new minutes-scale VPN
poll job will routinely overlap with the still-running `rule-version-pull` job (which sequentially
collects every device over SSH/REST — credibly minutes to complete on a real fleet): with a boolean,
job A finishing while job B is still running flips the flag to `false`, and `shutdown()` would
proceed to stop the process while job B was still mid-collect — the exact "finish current job then
exit" contract violation this codebase already fixed once before (the 150000ms hard-ceiling bump),
reintroduced through a different mechanism. Changed to `runningJobCount`, a counter.

### UI

`/vpn` (fleet-wide table: device, vendor, VPN status badge, config timestamp, latest active-session
count if polled) and `/devices/[id]/vpn` (per-device: config summary card +
`VpnSessionTrendChart` — a `recharts` `LineChart`, same CSS-custom-property color convention as
`RiskTrendChart.js`/`FindingsBarChart.js` — showing session-count history when any exists). Both are
server components querying the DB directly (this app's established convention); `GET /api/vpn/fleet`
and `GET /api/devices/[id]/vpn` exist for `?format=csv` export and any future client-side consumer,
same "duplicated query, not shared" tradeoff as the rest of this app. A "VPN" sidebar entry was
added (reusing `IconUser` — no dedicated VPN/tunnel icon exists in `components/icons.js`, same
"reuse what's there even if not a perfect semantic match" call already made for Compliance ->
`IconSearch`), and a "VPN →" link was added next to the existing "Rule analysis →" link on the
per-device overview page.

---

## Network Object Catalog (added 2026-07-18)

Answers "Unused Objects" / "Duplicate Objects" (the ManageEngine Firewall Analyzer "Rule Management
> Cleanup/Optimization > Objects" concept) — a genuinely NEW collection dimension, unlike VPN
Summary/Admin Account Summary above (both of which are read-only interpreters over data adapters
already collected for other reasons). `firewall_rules.src_addresses`/`dst_addresses`/`services`
store whatever a RULE references — usually an object's NAME, sometimes a literal inline value with
no backing object at all — never the object CATALOG itself (what named objects exist on the device,
and what they resolve to/contain). Closing that gap needs each adapter to collect the object
definitions too.

### `FirewallAdapter.getObjects()` — optional, unlike every other interface method

`lib/adapters/interface.js` documents the contract in a comment (not a throwing default — the base
class simply omits the method; `lib/adapters/index.js`'s `collectAndStore()` checks
`typeof adapter.getObjects === 'function'` before calling it, same optional-method pattern as the
existing `getVpnSessionSummary()`):
```js
async getObjects() {
  return {
    addresses: [ { name, type?, value } ],      // leaf address objects
    addressGroups: [ { name, members: [...] } ], // members = names of other addresses/groups
    services: [ { name, value } ],                // e.g. value: "tcp/443"
    serviceGroups: [ { name, members: [...] } ],
  };
}
```
**Must degrade gracefully per sub-category** (try/catch each of the 4 fetches internally, `[]` on
failure) rather than throwing whole on one sub-fetch's failure — deliberately the OPPOSITE of
`getRules()`'s fail-loud rule. There is no destructive "DELETE then store nothing" risk here the way
an empty `getRules()` result silently wipes `firewall_rules` — a partial object catalog is still
useful data, not a dangerous one.

### Schema — `network_objects` / `object_analysis_results`

Same DELETE+reinsert-per-device-per-pull lifecycle as `firewall_rules`/`rule_analysis_results`.
`network_objects` (`device_id, object_type, name, value, members jsonb`) stores the raw catalog;
`object_analysis_results` (`device_id, object_id, finding_type: 'unused'|'duplicate', detail,
related_object_ids jsonb`) stores `lib/engines/objectUsage.js`'s findings, mirroring
`rule_analysis_results`' own shape. Both are brand-new tables (safe as plain `CREATE TABLE IF NOT
EXISTS` — see the schema-migration bug two sections below for why that distinction matters).

### `lib/engines/objectUsage.js` — pure analysis, mirrors `ruleAnalysis.js`'s shape

`analyzeObjectUsage(objects, rules)`: **unused** = an object's name never appears directly in any
rule's address/service fields, AND is never a MEMBER of a group that's itself in use — a transitive
closure (bounded by object count, since each pass that changes anything must add ≥1 name), not just
a direct-reference check, otherwise every address inside a used GROUP would be wrongly flagged just
because the rule names the group, not the member. **duplicate** = two LEAF objects (address/service
only, never groups) of the same type sharing the exact same value under different names —
deliberately NOT extended to groups, same "member-SET equality is a harder bipartite-matching
problem, and a wrong `duplicate` finding suggesting an object be merged/deleted is worse than a
missed one" reasoning `ruleAnalysis.js`'s `fieldEquals`/`fieldCovers` comment already documents for
this codebase. Verified via a synthetic test before shipping: a group-member address correctly
survived as "used" via transitive closure, an unreferenced address was correctly flagged unused, and
two same-value address objects were correctly cross-referenced as duplicates of each other.

`runObjectUsageAnalysisForDevice()` runs in `collectAndStore()` right after the compliance-audit
block, gated on `typeof adapter.getObjects === 'function'` — a device with zero `network_objects`
(vendor doesn't implement `getObjects()` yet, or the last collect failed before storing any) is a
legitimate, common state, not an error: it clears any stale findings from a previous pull and
returns cleanly.

### Per-vendor status (2026-07-18)

| Vendor | Status | Source |
|---|---|---|
| Palo Alto (both transports) | Implemented, **no new device call** | Reuses the ALREADY-collected full config tree via `getLatestConfigParsed()` (called after `collectAndStore()`'s config block, so this pull's own row is already committed) — bounded deep search for `address`/`address-group`/`service`/`service-group` keys, same "search deep, don't assume the path" convention as `findSecurityRulesContainers()`/`vpnSummary.js`/`adminAccountSummary.js`. Field SHAPE is grounded (fast-xml-parser `@_name` convention, SSH plain-nested-object convention — both already live-confirmed elsewhere in this codebase); the specific PAN-OS object leaf field names (`ip-netmask`/`ip-range`/`fqdn`, `protocol.tcp.port`, etc.) are doc-derived, not yet live-verified — no prior code in this repo touched address/service objects. |
| Fortinet (both transports) | Implemented, VDOM-aware | REST: `cmdb/firewall/address`, `/addrgrp`, `firewall.service/custom`, `/group`, per discovered VDOM. SSH: `show firewall address`/`addrgrp`/`service custom`/`service group` per VDOM, same `config vdom`/`edit <vdom>`/`end` batching as `_getRulesMultiVdom()` — but unlike that fail-loud method, a single VDOM's failure is skipped, not fatal (a coarse catalog partially covering the fleet is still useful, unlike an authoritative ruleset). Doc-derived field names, not live-verified. `network_objects` has no VDOM column — an identically-named object across two VDOMs collapses to whichever was collected last; accepted, documented simplification, not a bug. |
| Check Point | Implemented | Reuses the adapter's EXISTING Mgmt API session (`api.withSession`) — no second login. `show-hosts`/`show-networks`/`show-address-ranges` → addresses, `show-groups` → address groups, `show-services-tcp`/`show-services-udp` → services, `show-service-groups` → service groups, each paginated via a new shared `_fetchAllPages()` helper (extracted from the gateway-listing code that already paginated this way — DRY, not new pagination logic). The `details-level: 'full'` assumption (group members return inline names, not just uids) is unverified; degrades to uid-named members rather than dropped ones if wrong. |
| Cisco ASA | Implemented | Parses `object network`/`object-group network`/`object service`/`object-group service` blocks from the SAME `show running-config` text already fetched for `getRules()`/`getConfig()`, using this adapter's existing line-by-line block-tracking style (mirrors `currentInterface` tracking) — not a generic brace-tree parser, deliberately consistent with this vendor's established simple-parser convention. A bare inline literal inside a group (`network-object host 1.2.3.4` with no backing named object) correctly contributes no member name, rather than inventing one. |
| Forcepoint | Implemented | `GET /api/elements/network_elements` / `/service_elements`, reusing the adapter's existing HATEOAS pagination helper and `resolveRef()` (including its `{any: true}` handling) for group members — no new pagination or ref-resolution logic. Object catalog is SERVER-wide, not per-engine, so — unlike `getRules()`/`getConfig()`/`getVersion()` — this method deliberately does NOT call `_resolveEngine()`. Whether the list endpoints return full inline fields or summary-only entries requiring a per-object href-follow is unverified (chose not to follow per-object hrefs, to avoid an N+1 explosion on a large catalog) — a `[SMC Debug]` sample log was added for the first live connection to confirm. |
| Sangfor | **Deliberately not implemented** — returns `{addresses: [], addressGroups: [], services: [], serviceGroups: []}` unconditionally | A real engineering decision, not a gap: this codebase's least-verified adapter has no live device, no documentation trail, and no already-captured config text plausibly containing object definitions to parse against (unlike the existing `ssl_vpn.enabled` tri-state detection, which is grounded in one already-known CLI line). Writing regex against invented block syntax would fabricate unused/duplicate findings as confidently as real ones — exactly what this file's own "documentation lies, verify against live systems" rule warns against. "Not yet built" is the correct, honest choice here, matching this codebase's own established acceptance of the same posture elsewhere (e.g. several Palo Alto/Fortinet compliance checks intentionally left `not_evaluable_from_config`). |

### UI

New **Objects** tab on `devices/[id]/analysis` (`?tab=objects`, positioned after the existing Risky
Rules tab), `components/analysis/ObjectsTab.js` — a server component LEFT JOINing `network_objects`
with `object_analysis_results`, three stat tiles (Total/Unused/Duplicate), and two tables (Unused
Objects, Duplicate Objects). Zero `network_objects` rows for a device renders an `EmptyState`
explaining the vendor may not support object collection yet — not an error, a normal state for
Sangfor and for any device not yet re-collected since this feature shipped.

### ⛔ Bug fixed 2026-07-18, found live in production the same day the rule-evidence drill-down
shipped — see the Schema Migration section's own entry on `CREATE TABLE IF NOT EXISTS` not adding
columns to an already-existing table. Unrelated to the object catalog itself, but fixed in the same
pass since it was found while this round's schema changes were already in flight — see that entry
for the full story, not repeated here.

### Compliance page UX fixes (found live the same day, 2026-07-18)

Two real usability bugs, reported directly by a user testing the rule-evidence drill-down feature
right after it shipped:
- **Clicking a failed-check link did nothing visible.** `StandardCard.js`'s failed-check links point
  at `/compliance/[deviceId]#STANDARD_KEY` — while already ON that exact page, this is a same-URL,
  hash-only change. Next.js App Router's `<Link>` does not natively scroll to a same-page hash target
  the way a plain browser `<a href="#foo">` anchor would; `StandardTabs.js`'s `hashchange` listener
  correctly updated which tab was active, but nothing ever scrolled the content into view, so a user
  below the fold saw literally no reaction to their click. Fixed: `StandardTabs.js`'s outer container
  now has a ref, and `applyHash()` calls `scrollIntoView({behavior:'smooth', block:'start'})` after a
  successful match — covers both the cross-page arrival case and the same-page click case identically.
- **"What are the network details for?"** — the Network Details card (distinct zone names aggregated
  from a device's collected rules) rendered as a bare, unlabeled wall of 40+ zone-name badges with no
  explanation. Fixed with a one-line caption ("Zones seen across this device's collected firewall
  rules — referenced by the zone-based checks below"). Deliberately did NOT attempt to categorize
  zones into DMZ/WAN/LAN-style buckets (the way ManageEngine's own Network Details groups them) —
  real zone names in this deployment (`TFM-HQ`, `YCC`, `VRZ`, ...) aren't reliably classifiable by
  name pattern, and a confidently-wrong categorization is worse than an honest flat list.

---

## Admin Account Summary (added 2026-07-19)

Direct architectural sibling of VPN Summary above — same "read-only interpretation of
`device_configs.config_parsed`, kept out of the adapters themselves" pattern, this time answering
"who can log into this firewall, and with what privilege" from data several adapters already collect
but never surfaced anywhere.

### `lib/engines/adminAccountSummary.js`

`summarizeAdminAccounts(vendor, configParsed) -> {supported, accounts: [{username, privilege,
twoFactorEnabled, sourceRestricted}], totalCount, superuserCount, error?}`. Unlike the compliance
predicate engine (one fixed dot-path per check, so `fortinet-default-admin-active`/
`fortinet-admin-2fa-required` can only ever look at `admins[0]`), this module iterates the WHOLE
account array — a UI-layer concern, same "free to search/iterate deeply" latitude `vpnSummary.js`
already has.

- **Fortinet**: `admins[]` — same section both compliance checks above already use. Real shape
  confirmed live (2026-07-19, production `TUS`): `{name, accprofile, "two-factor", trusthost1..10,
  ...}`. `sourceRestricted` is true only when at least one present `trusthostN`'s address token isn't
  `"0.0.0.0"` — a MISSING trusthost slot is treated the same as "not restricted" as an explicitly
  wide-open one (FortiOS omits unset slots entirely rather than filling them with the wide-open
  value; "absence of evidence isn't provable absence" doesn't apply here the way it does elsewhere in
  this app, since a missing slot genuinely means no restriction was configured on it).
- **Palo Alto (both transports)**: `mgt-config.users` — XML/API has it directly at the top level
  (`{users: {entry: [...] | {...}}}`, handling fast-xml-parser's single-element-collapses-to-bare-
  object convention); SSH has it nested in `.tree` (a plain object, per the vpnSummary.js bug-fix
  note above — this module was written fresh against the REAL shape, not the stale Node-shape
  assumption, so its own small bounded deep search never had that bug). `privilege` is derived from
  `Object.keys(entry.permissions['role-based'])[0]` — whichever role key is actually present
  (`superuser`/`superreader`/`deviceadmin`/...) — identical logic on both transports, since
  `permissions.role-based` has the same shape either way. `twoFactorEnabled`/`sourceRestricted` are
  always `null` ("not modeled here", never coerced to `false`) — PAN-OS `mgt-config` doesn't carry an
  equivalent concept the way Fortinet's `trusthostN`/`two-factor` do.
- **Cisco ASA**: `usernames[]` — plain strings only (no role/2FA/source data, by the parser's own
  explicit design — see the Compliance Engine section's Cisco ASA paragraph above). `privilege`/
  `twoFactorEnabled`/`sourceRestricted` always `null`.
- **Sangfor, Check Point, Forcepoint**: `supported: false` — none of the three collect admin/user
  account data today (confirmed by reading all three parsers directly, not assumed).

`superuserCount` uses a best-effort, case-insensitive cross-vendor heuristic
(`/^super(_?admin|user)$/i`) — anchored on purpose, not a bare `/super/i` substring test, so Palo
Alto's `superreader` (read-only, despite the "super" prefix) does NOT count as a superuser. An
initial unanchored version of this pattern was tried and miscounted `superreader`, caught by this
module's own pre-ship test — not a live incident, but worth keeping the anchoring intentional in any
future edit here. This is a UI summary signal, not a security boundary, and won't catch every
vendor's own naming for "full admin."

### UI

A new **"Admins"** tab on the existing per-device page (`app/(dashboard)/devices/[id]/page.js`,
`?tab=admins` — NOT a new top-level route, unlike VPN Summary; this app already has a growing sidebar
and this data is scoped to one device at a time with no obvious fleet-wide rollup worth a dedicated
page yet). Shows a summary line, then a table (username/privilege/2FA badge/source-restricted
badge, both 3-state — `Enabled`/`Disabled`/`Unknown`, never collapsing an unmodeled fact to a
confident answer, same discipline as everywhere else in this app) or an `EmptyState` for
`!supported`/zero accounts.

⚠️ Same standing caveat as VPN Summary: every field path here (except Fortinet's `two-factor`, which
is live-confirmed — see the Compliance Engine section's `fortinet-admin-2fa-required` paragraph) is
doc-derived and not yet independently live-verified.

---

## Role-Based Access Control (added 2026-07-20)

Scoped from the ManageEngine Firewall Analyzer gap-analysis research — "at minimum: read-only vs.
full admin." Two roles only, `admin` and `viewer`, no granular permission system (deliberately
rejected a middle ground like "viewer can acknowledge but not delete" — a coarse, unambiguous
boundary is safer than a fine-grained one that's easy to get subtly wrong across dozens of routes).
`viewer` is strictly read-only: cannot acknowledge/dismiss findings, run analyses, trigger syncs,
rotate credentials, add/delete devices, manage users, or change any global setting. Changing your
OWN password is the one exception — that's self-service account management, not an administrative
action, and is available to both roles.

### `users` table replaces the old single global admin identity

Local-admin identity used to be one global row pair in `settings`
(`admin_username`/`admin_password_hash` — a single shared login, no concept of "who"). RBAC needed
real per-person identity, so a new `users` table (`lib/schema.sql`) holds `username`, `password_hash`,
`role` ('admin' | 'viewer', no CHECK constraint — validated in application code only, same convention
as every other enum-like column in this file). `lib/migrate.js`'s `seedUsers()` is guarded on `users`
being empty (so it only ever does something once per database) and handles both cases: an
already-deployed install has its identity sitting in the legacy `settings` rows — migrated forward
into `users` (role `admin`) so the existing username/password keep working; a genuinely fresh install
gets the same well-known default identity (`admin`/`changeme`) the old `seedDefaultAdmin()` used to
seed, just directly into `users` now. The legacy `settings` rows are left in place (not deleted) —
harmless, and nothing reads them as the source of truth anymore.

`users.password_hash` gets the same secret-bearing-column treatment as `settings.admin_password_hash`
before it: `REVOKE SELECT ON TABLE users` + a `users_readonly` view (excluding the hash) granted to
`claude_readonly`/`nocvault_readonly` instead of the base table (`lib/schema-grants.sql`).

### `lib/rbac.js` — the shared guard

A pure, dependency-free CommonJS module: `ADMIN_ROLE`/`VIEWER_ROLE` constants, `isAdmin(session)`,
`forbiddenResponse()` (a 403 JSON Response). Deliberately does NOT import `authOptions` or do session
resolution itself — every route continues to resolve its own session via the already-established
per-route `getServerSession(authOptions)` pattern, then calls `isAdmin(session)` from here. This
sidesteps any ESM/CJS interop risk between a CJS lib file and the ESM Next.js route files that import
it (`lib/activityLog.js` already established the "CommonJS for every lib/*.js file, even ones only
consumed by App Router routes" convention this follows).

Standard guard shape for a write-method route handler:
```javascript
import { getServerSession } from 'next-auth/next';
import { authOptions } from '<relative>/api/auth/[...nextauth]/route';
import { isAdmin, forbiddenResponse } from '<relative>/lib/rbac';

export async function POST(request, { params }) {
  const session = await getServerSession(authOptions);
  if (!isAdmin(session)) return forbiddenResponse();
  // ... existing logic
}
```
Applied to every mutating (POST/PUT/DELETE/PATCH) API route in the app — device CRUD/credentials/
collect/test, analysis/compliance/CVE run-now triggers, feed sync, advisory-conditions CRUD, the
system self-update trigger, and every acknowledgement route (findings/CVE/config-diff). GET routes
are never gated — read access is the same for both roles. Several routes already resolved a
`getServerSession` result for an unrelated purpose (deriving an `actor` name for `logActivity`,
inside its own best-effort try/catch, positioned AFTER the mutating work) — those were hoisted so the
admin check runs BEFORE any write, with the later actor-name resolution reusing the same session
object rather than calling `getServerSession` twice.

Server Actions (only two exist in the whole app — both `deleteDeviceAction`, in `devices/page.js` and
`devices/[id]/page.js`) can't return an HTTP status code the way an API route can, so they guard with
`redirect('/devices?error=forbidden')` instead of a 403 Response; the page renders a small banner off
that query param.

### LDAP provider — known limitation, not fixed

`app/api/auth/[...nextauth]/route.js`'s LDAP provider still hardcodes `role: 'admin'` for any
successful bind — there is no LDAP-group-to-role mapping. A successful bind against
`LDAP_URL`/`LDAP_BASE_DN` was already an explicit trust boundary this app relied on before RBAC
existed; building real group-to-role mapping is a feature addition, out of scope for "read-only vs.
full admin, at minimum." Revisit if a viewer-role LDAP user is ever needed.

### UI-level hiding — defense in depth only

Write-action buttons/links (Add Device, Delete, the Users management card, etc.) are hidden for a
viewer session in several places, but this is cosmetic UX only — the real enforcement is every write
route's own server-side `isAdmin()` guard above. `components/settings/UsersPanel.js` in particular
relies entirely on this: it calls `GET /api/users` on mount, and that route's own `isAdmin()` check
(403 for a viewer) is what makes the whole Users card render as nothing for a non-admin — there is no
separate client-side role check to keep in sync.

---

## Settings Page — Tabbed Layout (added 2026-07-20)

`app/(dashboard)/settings/page.js` was rewritten from a flat single-column page into a 4-tab layout
(General / Users / Updates / About) at direct user request, to match the standardized tabbed
Settings pattern documented in `C:\Users\amrin\Documents\NocVault\SETTINGS-STANDARDIZATION.md` — a
cross-app spec doc that lives one level up from all the sibling NocVault suite app repos, **not**
part of this repo. Netvault's own live `app/(app)/settings/page.tsx` was actually opened and read as
the reference implementation before building this, rather than working from the spec doc alone.

**SecVault is explicitly NOT part of that suite** — see "What SecVault Is" at the top of this file
("SEPARATE PRODUCT from the NocVault suite — own auth, own DB, own services, own server. Not a
module of NetVault, LogVault, DDIVault, or SpanVault. No runtime dependency on any of them."). The
tab *structure and styling* were adopted purely because it's a good, proven pattern and SecVault
already shares the same design tokens by independent choice (see "Design System" below) — not
because SecVault is answering to or reporting into that suite. The new About tab is careful to say
so: it states only `SecVault v{pkg.version}` and `"Standalone firewall security and management
platform."` (the exact phrase this file's own opening section uses) — it makes no mention of the
NocVault suite, no claim of membership, and no cross-app version/status reporting of any kind.

### The 4 tabs

- **General** — the pre-existing Feed Sync interval form and Change Your Password form, unchanged in
  behavior, now living under one tab instead of stacked on the flat page.
- **Users** — renders the existing `components/settings/UsersPanel.js` unmodified. Self-gates via its
  own `GET /api/users` 403 check for a `viewer`-role session (see "Role-Based Access Control" above,
  directly preceding this section) — the tab itself has no separate visibility check, it just always
  renders the panel, which then renders as nothing for a non-admin.
- **Updates** — renders the existing `components/settings/UpdatePanel.js` unmodified, inside the same
  `Card` wrapper ("Software Update") it always had.
- **About** — new. A plain HTML `<table>` (not the shared `Table` component — a static 5-row detail
  list has no need for `Table`'s sorting/pagination machinery), `tableLayout: 'fixed'` set per this
  file's own Critical Rules (percentage-width columns collapse unpredictably on overflow without it).
  Rows: Product (`SecVault — Firewall Security Platform`), Version (`v{pkg.version}`), Port (`3010`),
  Runtime (`Node.js v20 · Next.js 14.2.35 · React 18.3`), Database (`PostgreSQL 16`) — all static
  strings except the version, which reads `package.json` the same way `Sidebar.js`'s version footer
  already does (`import pkg from '../../../package.json'`, no API call).

### Tab mechanism — a deliberate, scoped exception to this app's usual `?tab=` convention

Every other multi-tab page in this app (`/devices/[id]/analysis`, `/compliance/[deviceId]`, etc.)
uses the `?tab=` query param as the actual state — a server component reads it and re-renders
server-side on every tab switch. Settings does NOT follow that pattern: `activeTab` is plain
client-side `useState` (`'use client'`, the whole page already was one), and `?tab=` is read exactly
ONCE inside a mount-only `useEffect` purely as a deep-link convenience (e.g. a future
`/settings?tab=users` link) — after initial mount, switching tabs never touches the URL or triggers
a server round-trip. This matches netvault's own Settings tab implementation specifically (their
other tabbed pages may still use a different pattern) — copied deliberately, not a drift from this
app's convention. Worth calling out explicitly so a future reader doesn't "fix" this page to match
`/devices/[id]/analysis`'s server-driven `?tab=` pattern — that would be reverting an intentional,
scoped choice, not correcting an inconsistency.

### Dark-mode verification (done 2026-07-20, before this section was written)

The whole file was read end-to-end and checked for hardcoded hex/`rgb()`/`rgba()` colors in every
inline `style={{}}` — none found; every color is a `var(--...)` token (`--primary`, `--border`,
`--text-primary`, `--text-secondary`, `--text-muted`, `--bg-primary`, `--bg-card`), including the new
About-tab table. The sticky tab bar's `background: 'var(--bg-primary)'` was specifically checked
against `app/globals.css`: `--bg-primary` is defined with distinct real values under both `:root`
(`#f4f6f9`) and `[data-theme="dark"]` (`#0d1220`), and `.sv-content` (the actual scrolling ancestor
this sticky bar sticks within, per `app/(dashboard)/layout.js`) uses that same `--bg-primary` as its
own background — so the sticky bar is opaque and color-matched against the page background it sticks
over in both themes, and the `Card` content that scrolls underneath it uses the distinct `--bg-card`
token as intended (no mismatch). Confirmed clean, not assumed.

---

## Rule Reorder Recommendation (added 2026-07-20)

Closes a real gap the ManageEngine Firewall Analyzer research identified: `ruleAnalysis.js`'s
`reorder_candidate` finding (see Rule Analysis Engine above) only ever flags INDIVIDUAL problem rules
("this deny is shadowed by that allow") — there was no synthesis step producing one recommended full
rule order, the equivalent of ManageEngine's "Rule Reorder & Recommendation" tool.

`lib/engines/ruleReorder.js` — pure, no-DB (same "pure engine" pattern as `riskScore.js`). Each
`reorder_candidate` finding means rule `rule_id` (a deny) is unreachable because an earlier rule
`affected_rule_ids[0]` (an allow) fully covers its traffic — read as a precedence CONSTRAINT: the
deny must end up before its shadowing allow. `computeRecommendedOrder(rules, findings)` solves this
via **Kahn's algorithm (topological sort)**, not naive pairwise swapping, specifically because Kahn's
algorithm has a clean, correct answer for the case naive swapping doesn't: a genuine CYCLE (rule A
must precede rule B per one finding, rule B must precede rule A per another — two constraints no
single order can satisfy). A cycle's rules are detected and reported as `unresolvedRuleIds`, left at
their original position, rather than guessed at — the same "no ruleset is safer than the wrong one"
posture this codebase already applies to `getRules()`'s fail-loud contract. Rules not referenced by
any finding are never touched; the algorithm does a stable merge that only reorders the minimal
subset of involved rules into the slots they already occupied, so the recommendation is the smallest
possible diff from the current order, not a full re-sort. A finding referencing a rule id no longer
in the current `firewall_rules` snapshot (stale relative to the last collect) is silently skipped,
same defensive posture `ReorderTab.js` already has for `affected_rule_ids` resolution.

`GET /api/devices/[id]/reorder-recommendation` — JSON by default, `?format=csv` for a downloadable
export, matching the established `?format=csv` convention (`/api/devices/[id]/rules`,
`/api/compliance/[deviceId]`, etc.). Read-only — no RBAC guard needed (GET routes are never gated),
and critically **no write-back to the device or to `firewall_rules`** — this is a recommendation for
a human to apply manually, the same recommend-only scope as every other finding in this dashboard
(see the Rule Analysis Dashboard section above — no adapter has ever gained a write-back capability).
`components/analysis/ReorderTab.js` gained an "Export Recommended Order" link pointing at the CSV
variant.

---

## Rule Analysis Intelligence Round — "Path A" (added 2026-07-22)

A competitive deep-research pass (Tufin/AlgoSec/FireMon/Skybox/Palo Alto Policy Optimizer/Cisco
Policy Analyzer, plus the academic literature the whole "shadow/redundant/correlation" taxonomy
traces back to — Al-Shaer & Hamed, INFOCOM 2004) found that SecVault's rule-analysis engine is a
faithful, correctly-implemented version of that same foundational academic model — not naive — but
that every commercial "intelligent" competitor layers one of: traffic/log data, cross-device
topology, or vulnerability/exposure context on top of the identical static analysis SecVault already
has. That research split into two paths: things needing real traffic-log ingestion (Phase 8, not
built — deferred, not attempted) and things buildable today, config-only, from data already
collected. This round built the config-only path ("Path A") in full: 4 pieces, fanned to 4 parallel
sub-agents after the two correctness-critical core-engine pieces were built by the primary agent
directly (per this file's own "high-risk refactors done by primary agent, not sub-agents" rule —
modifying `ruleAnalysis.js` itself and designing the exposure-correlation join both qualify). Every
sub-agent diff was personally re-read against its own file before integrating (not just trusted from
the agent's self-report) — this pass caught and fixed one real bug (`lib/engines/ruleRelationships.js`
shipped with `'use strict';` trapped inside a `//`-comment line, silently never active) and one
pre-existing, unrelated gap flagged by the first sub-agent while it worked (`FindingsBarChart.js` was
already missing a `correlation` entry in its hardcoded type/color list, from before this round even
started) — both fixed in the same pass.

### 1. `generalization` — an 11th finding type, closing a real direction gap

Every existing pairwise check (`shadow`, `redundant`, `correlation`, `reorder_candidate`) only ever
tests whether an EARLIER rule covers/equals a LATER one. None test the opposite direction: a LATER,
BROADER same-action rule that fully covers an EARLIER, NARROWER rule. That earlier rule still fires
first and isn't unreachable (unlike `shadow` — order matters, it's not dead code) — but for every
packet it matches, the later, broader rule (same action) would produce the identical decision, so it
adds no behavior beyond what the later rule already provides. `severity: 'medium'`, the same
ruleset-simplification class as `redundant`/`correlation`/`overly_permissive`, not a security-exposure
finding (same action either way). Stores `rule_id` = the earlier, narrower (now-pointless) rule,
`affected_rule_ids` = `[the later, broader rule]`.

Implemented as one more pass inside `ruleAnalysis.js`'s existing O(n²) pairwise block (same
`ruleCovers()`/`fieldEquals()` helpers, same `yieldToEventLoop()` interruptibility, same per-pair
`break`-after-first-match convention as every sibling check) — reusing `ruleCovers(r, s)` with the
roles reversed from every other check (`r` = later/outer-loop rule, `s` = earlier/inner-loop rule).
**Deliberately excludes the case where `s` and `r`'s fields are fully equal** — that pair is already
reported by `redundant` (which runs in the `s`-covers-`r` direction and flags `r` as the duplicate);
without this exclusion, an exact-duplicate pair would be double-reported under two different finding
types in opposite directions. Verified with a 5-case synthetic smoke test before shipping (narrower
rule correctly flagged; exact duplicates correctly produce `shadow` only — see below — never
`generalization`; different-action pairs never fire; the pre-existing `shadow`/`reorder_candidate`
cases are unaffected).

**A real, useful side-finding from writing that test**: in a simple 2-rule universe, two EXACTLY
duplicate same-action rules are always reported as `shadow` by the pre-existing engine, never
`redundant` — equal fields trivially satisfy `ruleCovers()` too, and `shadow`'s loop runs first and
wins (`redundant`'s loop explicitly skips any pair already recorded in `shadowPairs`). This isn't a
bug and wasn't changed — just a pre-existing engine behavior worth knowing before ever touching this
area again: `redundant` only fires today when the exact-duplicate rule isn't the FIRST covering match
`shadow`'s own loop happens to land on.

Propagated everywhere the app enumerates finding types: `CleanupTab.js` (added alongside
`unused`/`redundant`/`overly_permissive`/`correlation` — same "simplify the ruleset" bucket),
`FindingTypeBadge.js`, `FindingsBarChart.js` (medium-severity color group), `OverviewRuleHygieneCard.js`
(folded into the "Other Issues" donut bucket, same bucket as `correlation`), and — most importantly —
`app/api/devices/[id]/acknowledgements/route.js`'s `FINDING_TYPES` allow-list, the exact list this file
already documents a real historical incident about (`correlation` was once left out of this same list,
permanently 400ing every acknowledge attempt for that type). Also added to
`devices/[id]/analysis/page.js`'s `FINDING_TYPES` array (the Findings-tab filter dropdown + summary bar
chart zero-fill list) directly by the primary agent, alongside two new tab-scaffolding entries (see
below).

### 2. Exposure Risk correlation — CVE engine × rule engine, joined for the first time

`lib/engines/exposureCorrelation.js` (new, pure-ish DB-backed engine): SecVault has run a rule-hygiene
engine and a CVE-prioritization engine completely independently since Phase 3/5 — they have never once
been queried together. This is the single highest-ROI item from the competitive research: Tufin's and
FireMon's own headline "intelligent" differentiator (config analysis correlated with vulnerability/
exposure data) needed zero new data sources here, only a join. `getExposureCorrelationForDevice(deviceId,
pool)` pairs every open exposure-widening rule finding (`any_any` / `overly_permissive` / `risky_service`
— deliberately NOT the ruleset-hygiene types like `shadow`/`redundant`/`generalization`, which say
nothing about exposure) with that SAME device's open `priority_band = 'patch_now'` CVE assessments.

**This is a DEVICE-LEVEL correlation, not a claim that a specific rule and a specific CVE target the
same port/service** — no such mapping exists anywhere in this app's data model
(`device_cve_assessments` only knows "this device's installed version is affected," never "on which
port/service"). The finding is "this rule widens what can reach this box, and this same box also has
an actively relevant, unpatched vulnerability," matching exactly how the competitive research describes
Tufin's/FireMon's own exposure-context risk framing — not a per-port claim stronger than the underlying
data supports.

Deliberately **computed at read time, never stored** — same convention as `riskScore.js`'s
`computeRiskScore()`/`configAuditor.js`'s `scorePctFromCounts()`. `rule_analysis_results` and
`device_cve_assessments` refresh on two independent schedules (rule analysis: every rule pull or manual
"Run Analysis"; CVE assessment: every feed sync, or a config-change-triggered re-match) — storing a
derived join would need its own staleness/invalidation model for no real benefit; a live join is always
accurate as of the two inputs' own last-refresh times and is cheap (bounded by matches per device, not
the O(n²) cost `ruleAnalysis.js` itself has to manage).

`components/devices/OverviewExposureCard.js` (new) renders it on the device Overview tab, immediately
after `OverviewCveCard` (the most CVE-adjacent existing neighbor) — reuses `SeverityBadge`/
`FindingTypeBadge`/`CVEBadge` verbatim rather than inventing new badge styling (`CVEBadge` already
returns `null` for a non-KEV CVE, so it's safe to render unconditionally). The empty case (no
correlation — the common outcome, since it requires both an exposure finding AND an open patch-now CVE
on the same device) renders as a calm one-line message, not an alarming empty-state box, matching
`OverviewComplianceCard.js`'s own "don't over-dramatize a good outcome" precedent. A fleet-wide count
helper, `countDevicesWithExposureCorrelation(pool)`, exists in the engine file for potential future use
(a Dashboard summary tile) but is **not wired into any UI yet** — deliberately scoped out of this round
to keep it to the per-device card, not a new fleet-wide page invented ad hoc.

### 3. Reachability tab — single-device, config-only zone reachability

The competitive research's one genuinely "big swing" differentiator — multi-hop, cross-device network
path analysis (Tufin/AlgoSec's most expensive tier) — is **not attempted**: SecVault has no topology
model of how devices connect to each other (which subnet sits behind which device/interface), and
building one is a real, separate, much larger feature, not something to fake. What WAS built instead is
the single-device slice that's honestly answerable from data already collected:
`lib/engines/reachabilityMatrix.js`'s `computeZoneReachability(rules)` — a pure function answering
"given this device's own enabled ruleset, which zone-to-zone paths does it currently allow, deny, or
leave unspecified?"

Algorithm (deliberately a simple, defensible first-match-wins model, not a full 5-tuple packet
simulator): collect every distinct REAL (non-wildcard) zone name across all rules' `src_zones`/
`dst_zones`; for every ordered `(srcZone, dstZone)` pair including same-zone pairs, walk the enabled
rules in `sequence_number` order — the FIRST rule whose zones cover that pair (wildcard or explicit
membership) decides the verdict. No match at all is `'unspecified'` — **deliberately never coerced to
"deny by default"**, since different vendors have different default policies and this codebase doesn't
reliably know each device's own default; same tri-state-honesty discipline as the CVE applicability
engine's "`unknown` never collapses to `no`" rule. A device with no zone data at all (several vendors'
adapters don't collect it) returns `hasZoneData: false` rather than fabricating a matrix from nothing.
Local `isAny()`/`normList()`/`actionCategory()` helpers are duplicated from `ruleAnalysis.js` rather than
imported (that file doesn't export them — matches this codebase's own established small-helper-
duplication convention).

`components/analysis/ReachabilityTab.js` (new tab, `?tab=reachability` on `devices/[id]/analysis`)
renders the matrix as a plain `<table>` (via the shared `Table` wrapper, which already enforces
`tableLayout: 'fixed'` internally) — `Badge` colors (`success`/`danger`/`muted`) per cell, a tooltip
naming the deciding rule, and an explicit caption stating the three scope limits verbatim: zone-only
granularity (not full address/service matching within a zone pair), single-device only (not cross-device
topology), and `'unspecified'` meaning "no explicit rule found," never a claim about the device's
default policy either way.

### 4. Relationships tab — clustering the 5 relationship-shaped finding types

A PhD thesis surfaced in the competitive research found that matrix/tree/sunburst visualizations are
inadequate for representing firewall rule-anomaly relationships and built custom hive-plot/
dynamic-slice visualizations instead — evidence that the flat-table status quo (SecVault's own Findings
tab) is a recognized, real usability gap in this exact problem space, not a cosmetic nice-to-have.
`lib/engines/ruleRelationships.js`'s `clusterRelationshipFindings(findings)` (new, pure, standard
union-find with path compression) groups the 5 finding types that each describe a relationship between
two specific rules — `shadow` / `redundant` / `correlation` / `generalization` / `reorder_candidate` —
into connected clusters via the `rule_id` ↔ `affected_rule_ids` edges every one of those finding rows
already carries. A 2-rule cluster (a single shadow/redundant/correlation/generalization/reorder pair) is
just as valid a result as a larger one — never filtered out. Clusters sort worst-severity-first, then by
rule count descending.

**Deliberately not a new graph-drawing dependency or a hand-rolled force-directed SVG layout** — this
codebase has no graph-visualization library (only `recharts`, which isn't suited to relationship graphs),
and a badly-executed node-link diagram is worse than a clean list; a full graph renderer was explicitly
scoped out as too risky for this round, matching this codebase's own bias toward the simpler, safer
option when uncertain. `components/analysis/RuleRelationshipTab.js` (new tab, `?tab=relationships`)
instead renders one `Card` per cluster: a severity/rule-count/relationship-count summary header, an
optional chip-row overview for 3+ rule clusters (skipped for the common 2-rule case, where the single
edge row below already shows the same two rules as a chip → chip chain — repeating them above would be
pure redundancy), and a stacked list of edge rows each showing rule → affected-rule chips, the finding's
own real `detail`/`remediation` text verbatim (never re-derived), and its badges. `affected_rule_ids` is
resolved against a same-request snapshot of the device's rules — never persisted or cached — same
discipline `ReorderTab.js`'s own header comment already documents (`firewall_rules` is fully
DELETE+reinserted on every collect, so these ids aren't stable across pulls).

### Tab scaffolding

Both new tabs' plumbing (`?tab=reachability|relationships` validity, tab-bar links, conditional render
blocks, component imports) was added directly by the primary agent to
`app/(dashboard)/devices/[id]/analysis/page.js` BEFORE fanning the two building sub-agents — this let
each sub-agent own exactly one new component file with zero risk of two agents racing on the same
shared page file, the same "frozen contract, no file written by more than one agent" discipline this
file's own "Parallel Sub-Agents" section documents, applied by pre-building the shared integration point
rather than trying to avoid it.

---

## Zone Classification (added 2026-07-22)

**⛔ Superseded the SAME DAY — see "Rebuilt PER-DEVICE the same day" near the end of this section.**
The `zone_classifications` table/UI described immediately below shipped as GLOBAL (fleet-wide), was
found unusable within hours (a flat list mixing every device's zones with no way to tell which
firewall each belonged to), and was rebuilt per-device. Kept below for the history of why the global
design was chosen in the first place — not a description of current behavior. Current: per-device
table, per-device `lib/engines/zoneClassification.js` functions, per-device API route, UI on each
device's own Manage tab (NOT Settings).

Direct follow-up to the Reachability tab (see "Path A" above): the user asked whether SecVault should
do what ManageEngine Firewall Analyzer does — explicitly ask the operator which zone is Internal/
External/DMZ, so compliance/reachability features don't misreport. This is a genuinely different
proposal from something already tried and rejected once: the Compliance page's Network Details card
(see that section above) already tried AUTOMATIC zone-name pattern matching and correctly rejected
it, since this deployment's real zone names (`TFM-HQ`/`YCC`/`VRZ`) aren't reliably classifiable by
name. An explicit, operator-supplied mapping sidesteps that exact risk entirely — it's a fact the
admin supplies, not a guess this app makes — so it was built.

### `zone_classifications` — a small, global, operator-only table

`lib/schema.sql`'s `zone_classifications` (`zone_name TEXT UNIQUE`, `role: 'internal'|'external'|
'dmz'`) is keyed on the NORMALIZED (lowercase, trimmed) zone name, **global across the fleet, not
per-device** — the same zone name is assumed to mean the same thing on every device that reports it,
matching how these names are actually assigned in real deployments (a real org's "DMZ" zone means the
same thing on every firewall that has one). Every consumer MUST treat "no row for this zone" as
"unclassified" — never silently assumed any particular role — the same tri-state-honesty discipline
this app already applies to CVE applicability (`unknown` never collapses to `no`) and compliance
predicate evaluation (`na` when nothing is measurable). Not secret data — granted to
`claude_readonly`/`nocvault_readonly` like any other non-credential table.

`lib/engines/zoneClassification.js`: `getZoneRoleMap(pool)` (the plain lookup map every consumer
below actually uses), `getDistinctFleetZones(pool)` (every distinct real zone name ever observed
across the WHOLE fleet's `firewall_rules`, left-joined against its current classification — the
Settings UI's data source, wrapped in try/catch/`jsonb_typeof(...) = 'array'` guards, same defensive
pattern the Network Details card already established for this exact jsonb shape), `setZoneRole()` /
`clearZoneRole()` (upsert/delete, admin-only via the API route).

`GET/PUT /api/zone-classifications` — GET is **not** admin-gated (unlike credential-profiles' own GET,
which IS gated because that data is credential-adjacent; zone names/roles carry no secret material at
all, so the general "GET routes are never gated" rule applies instead). PUT is admin-only, matching
every other mutating route in this app. A `role: null` PUT clears the classification rather than
needing a separate DELETE endpoint for a one-row-per-zone table.

**Settings > Zones** (`components/settings/ZoneClassificationsPanel.js`, new tab in
`app/(dashboard)/settings/page.js`) lists every distinct fleet zone with a role `<select>` that
auto-saves on change (optimistic, reverts on error — same pattern as
`components/analysis/AcknowledgeControl.js`). Visible to every authenticated user (a viewer sees a
read-only `Badge` instead of the `<select>`) — the real enforcement is the API route's own
`isAdmin()` check, this is UI-hiding only, same "defense in depth, not the boundary" posture as
every other admin-only Settings surface.

### Three consumers, all reusing the same classification data

**1. `external_exposure` — a 12th `rule_analysis_results` finding type.** An enabled ALLOW rule
whose source zone(s) explicitly include one classified External AND destination zone(s) explicitly
include one classified Internal. Deliberately does NOT treat an "any"/wildcard zone as "could be
External" — that's already what `any_any`/`overly_permissive` exist to flag; this check's only job is
catching an EXPLICITLY named External zone reaching an EXPLICITLY named Internal one. `severity:
'medium'` (not high/critical) — a real External-to-Internal path is often entirely legitimate (a VPN
termination zone, a partner site-to-site link), so this is a "worth reviewing" flag, the same posture
already taken for `overly_permissive`, not a "definite problem" claim like `any_any`.
`loadOptionsFromSettings()`'s sibling call, `getZoneRoleMap()`, is loaded once per `runAnalysisForDevice()`
run and passed into `analyzeRules()` via `options.zoneRoles` (default `{}` — so with no classification
data at all, this check simply never fires, never treated as "assume the worst" or "assume the
best"). Verified with a 6-case synthetic smoke test (explicit match fires; no zone data at all never
fires; External→DMZ doesn't fire; a wildcard `any` src doesn't count as External; a deny action never
fires; Internal→Internal doesn't fire) before shipping. Propagated through the same checklist as
`generalization` before it: `OptimizationTab.js` (joins `risky_service`/`any_any`/`overly_permissive`
— a genuine security-exposure finding, not the ruleset-simplification group `generalization` joined),
`FindingTypeBadge.js`, `FindingsBarChart.js`, `OverviewRuleHygieneCard.js`'s "Other Issues" bucket, and
— critically — the acknowledgements route's `FINDING_TYPES` allow-list (see that file's own comment
on the `correlation` incident this keeps not repeating).

**2. `rule-no-external-to-internal-access` — a compliance check that is NOT a plain `rule_scan` check,
on purpose.** Every existing `rule_scan` check (`rule-no-any-any-allow` etc.) treats zero matching
findings as an unconditional PASS — correct for those checks, because their underlying detection data
(risky ports, CVE assessments, etc.) always has SOME baseline coverage. `zone_classifications` starts
completely EMPTY on every fresh install with no possible sane default (real zone names are
deployment-specific) — reusing the plain `rule_scan` shape here would mean every device, fleet-wide,
shows a false "PASS" with 100% certainty until an admin manually classifies at least one zone. That is
exactly the "looks fine, isn't" trap this compliance engine's whole tri-state design exists to
prevent — and directly the risk the user was originally asking about. Fixed by building it as a THIRD
`ruleset_property` (alongside `has_explicit_deny_all`/`blocks_icmp`), with its own dedicated
`evaluateExternalToInternalExposure()` in `lib/engines/configAuditor.js`: first checks whether THIS
device's own rules reference zones classified BOTH External and Internal at all (via a small,
duplicated `collectDeviceZoneNames()` helper — same per-file-duplication convention as everywhere
else in this app) — if not, resolves `'na'`, never a false `'pass'`. If both roles ARE represented,
reuses `ruleAnalysis.js`'s ALREADY-COMPUTED `external_exposure` finding (via the same
`ruleFindingsByType` map `evaluateRuleScanCheck()` already loads) for the actual pass/fail decision and
`matched_rule_ids` — the detection logic itself lives in exactly one place, never duplicated a second
time. Verified with a 4-case synthetic smoke test (no zone data → `na`; both roles classified fleet-wide
but this device's own rules only touch Internal zones → still `na`; both roles present on this device,
zero matches → real `pass`; matches present → `fail` with `matchedRuleIds`) before shipping — case 1 is
the one that would have silently misreported under a naive `rule_scan` reuse. Tagged `PCI_DSS`/`NIST`/
`CIS_V8` (network segmentation is a core requirement across all three — PCI-DSS Requirement 1's network
security controls between the CDE and other networks is the most direct citation).

**3. Reachability tab enhancement.** `components/analysis/ReachabilityTab.js` now fetches
`getZoneRoleMap()` alongside the rule set, shows each zone's role under its name in both the row and
column headers, and outlines a cell in red when it's an Allow from a classified External zone straight
to a classified Internal one, or amber for DMZ→Internal — standard network segmentation reasoning
(External should reach DMZ, not Internal directly; DMZ reaching Internal is a common real-world pivot
path), applied only when BOTH zones in the pair are actually classified. A load failure degrades to "no
cell highlighted this render" (best-effort, same posture as the other two consumers), never breaks the
tab.

### Follow-up, same day: considered and rejected the full ManageEngine-style score block

Direct follow-up question: should the compliance page do what ManageEngine Firewall Analyzer
apparently does — show NO compliance score for ANY standard until zones are classified? **Decided
against it, deliberately**, and built a narrower alternative instead (`ZoneClassificationBanner`).
Reasoning: ManageEngine's all-or-nothing block makes sense for ITS OWN check composition, where most/
all checks likely depend on zone/segment context. SecVault's doesn't work that way — of PCI-DSS's/
NIST's/CIS v8's full check lists, only ONE check (`rule-no-external-to-internal-access`) actually
depends on zone data; everything else (explicit deny-all, ICMP blocked, logging enabled, password
policy, 2FA required, etc.) is fully computable with zero zone data. `scorePctFromCounts()` already
excludes `na` results from the denominator (see the Compliance Engine section above), so a standard's
score today is ALREADY correctly computed from every other check when this one is `na` — blocking the
whole score over one excluded check would throw away real, valid results for the other 15-20+ checks
per standard, which is worse than showing the (already-correct) partial score plainly.

`components/compliance/ZoneClassificationBanner.js` (new, presentational only, no DB access — each
caller derives `standards` from data it already fetched, no new query) renders a `--tint-warn`-styled
notice ("Zones haven't been classified yet — the External-to-Internal segmentation check is excluded
from the [standards] score(s) below") with a link to Settings > Zones, whenever the zone-dependent
check's `audit_findings` row for that device has `status === 'na'` — found by matching
`ac.check_id === 'rule-no-external-to-internal-access'` in the SAME `findings` array each page already
fetches for its `StandardCard` grid (no new query in any of the three call sites: both
`compliance/[deviceId]/page.js` and `compliance/page.js`'s Cards view added `ac.check_id AS check_slug`
to their existing, already-duplicated `getFindings()` SELECT; `OverviewComplianceCard.js` (the device
Overview tab's condensed version) got the same column added and shows a smaller inline text note
instead of the full banner box, since there's no room for one among several Overview-tab cards).

### ⛔ Rebuilt PER-DEVICE the same day — the global design was reported as unusable

Direct user report, with a screenshot: the fleet-wide Settings > Zones list rendered as one giant
alphabetical table mixing every device's zone names together with no indication of which firewall each
belonged to — `3bb`, `apc`, `awsvpn`, `azure-express`, `backup-vpn`, `dmz1`..`dmz6`, all in one flat
list. This exposed that the ORIGINAL design's core assumption ("the same zone name means the same
thing on every device that reports it") was wrong for this fleet: these are per-device VPN tunnel/site
identifiers, not shared role names reused identically across devices. The fix wasn't a UI filter
dropdown bolted onto the global list — it was changing the data model itself to PER-DEVICE, which
turned out to be the more natural fit anyway: all three consumers (`ruleAnalysis.js`'s
`runAnalysisForDevice(deviceId)`, `configAuditor.js`'s `runComplianceAuditForDevice(deviceId)`,
`ReachabilityTab({ deviceId })`) already operate on one device at a time, so `getZoneRoleMap(deviceId,
pool)` is a more direct fit than the global version ever was.

**Schema**: `zone_classifications` gained a `device_id UUID NOT NULL REFERENCES devices(id) ON DELETE
CASCADE`, unique on `(device_id, zone_name)` instead of `zone_name` alone. Per this file's own standing
"`CREATE TABLE IF NOT EXISTS` doesn't add columns to an already-existing table" rule, an already-deployed
server (this table shipped mere hours earlier, same session) needs a real migration, not just a schema.sql
edit — `lib/migrate.js`'s `migrateZoneClassificationsToPerDevice()` (best-effort, wired into `main()`):
adds `device_id` as nullable first, **deletes any row where it's still NULL** (a legacy global-scoped row
can't be retroactively attributed to a device — confirmed harmless to discard, since every row on the one
deployment checked directly was still "Unclassified", meaning zero real classification work existed
anywhere yet), drops the old single-column `UNIQUE` constraint, adds the new composite one inside a `DO $$
... IF NOT EXISTS ... END $$` block (Postgres has no native `ADD CONSTRAINT IF NOT EXISTS`), then sets
`device_id NOT NULL`. Every step is independently idempotent, so re-running this on a server that's already
migrated (or a fresh install, where `CREATE TABLE` already produced the final shape) is a safe no-op.

**`lib/engines/zoneClassification.js`** rewritten per-device: `getZoneRoleMap(deviceId, pool)`,
`getDeviceZones(deviceId, pool)` (replaces the old fleet-wide `getDistinctFleetZones` — now scoped to one
device's own `firewall_rules`), `setZoneRole(deviceId, zoneName, role, pool)`, `clearZoneRole(deviceId,
zoneName, pool)`. The old global API route, `app/api/zone-classifications/route.js`, was deleted outright
and replaced with `app/api/devices/[id]/zone-classifications/route.js` (GET not admin-gated, same "zone
data isn't secret" reasoning as before; PUT admin-gated).

**UI moved out of Settings entirely, onto each device's own Manage tab.** `components/settings/
ZoneClassificationsPanel.js` and the Settings "Zones" tab are both gone. `components/devices/
ZoneClassificationPanel.js` (new) renders as a third card on the Manage tab, right after "Rotate
Credentials", inside the same `tab === 'manage' && canWrite` block those two cards already live in —
meaning it needs no client-side admin check of its own (the whole block is already fully admin-gated,
tab link and content both) and always shows the edit `<select>`s directly, unlike the old Settings
version's `canWrite`-conditional read-only fallback. Same per-row auto-save pattern as
`AcknowledgeControl.js` (optimistic update, revert on error).

Every place that used to link to `/settings?tab=zones` was updated to `/devices/${deviceId}?tab=manage`
instead: `ZoneClassificationBanner.js` (gained a required `deviceId` prop, threaded through from all 3
call sites), `OverviewComplianceCard.js`'s own separate inline note, and — found only via a full grep
sweep during this round, not one of the originally-identified call sites — `ReachabilityTab.js`'s own
explanatory caption text, which had an identical stale link.

Built via 2 parallel sub-agents after the schema/engine/API-route foundation was done directly by the
primary agent (same "high-risk foundation first, then fan out" sequencing as the earlier Path A round):
one built the new `ZoneClassificationPanel.js` + Manage-tab wiring, the other removed the old Settings
UI and fixed every stale link — zero file overlap between the two by construction (the primary agent
pre-built the API route contract both could depend on independently).

### ⛔ Live production failure the SAME DAY: the per-device migration's own CREATE INDEX broke every upgrading server

Reported directly by the user, with the real `Update-SecVault.ps1` transcript: `node lib\migrate.js`
failed with `error: column "device_id" does not exist` (Postgres code 42703, routine
`ComputeIndexAttrs` — an index-creation error), and the whole update aborted before `SecVault-App` was
allowed to restart (correctly, per this file's own `$migrateSucceeded` gating — a broken/incomplete
schema must never serve traffic). Root cause: `lib/schema.sql` had a bare
`CREATE INDEX IF NOT EXISTS idx_zone_classifications_device_id ON zone_classifications(device_id);`
statement right after the table definition — this runs inside `runSchema()`, which is the FIRST thing
`migrate.js`'s `main()` calls, BEFORE `migrateZoneClassificationsToPerDevice()` (the function that
actually adds `device_id` to an already-deployed server's table) ever gets a chance to run. On a fresh
install this was invisible (`CREATE TABLE` already includes `device_id`, so the index statement right
after it in the same batch succeeded) — it only broke a server upgrading from the table's original
GLOBAL shape, which in practice meant every server that had deployed since this table first shipped
hours earlier the same day, including this one. `runSchema()` throwing aborted the ENTIRE schema
migration, not just this one table — the per-device migration function never even got called.

**Fixed** by moving the index creation OUT of `schema.sql` and into
`migrateZoneClassificationsToPerDevice()` itself (`lib/migrate.js`), issued last, after that function's
own `ALTER TABLE ADD COLUMN` unconditionally guarantees `device_id` exists — safe on a fresh install
(no-op, index already implied by nothing conflicting) or an upgrade alike. Fixed in the same pass, found
while re-reading this function rather than a second live incident: the composite `UNIQUE` constraint
name the migration checked for (`zone_classifications_device_zone_key`) didn't match Postgres's own
default auto-generated name for `CREATE TABLE`'s inline `UNIQUE (device_id, zone_name)`
(`zone_classifications_device_id_zone_name_key`, following the `<table>_<col1>_<col2>_key` convention)
— harmless on its own (Postgres allows two differently-named UNIQUE constraints over the same columns),
but would have left every FRESH install with a redundant, confusingly-named duplicate constraint;
corrected to use Postgres's own auto-generated name so a fresh install and an upgraded one converge on
the identical constraint.

**Lesson, stated plainly for next time**: a companion `CREATE INDEX` (or any other DDL) for a column
added to an EXISTING table by a JS migration belongs in that JS migration, run after the column-adding
step — never as a bare `schema.sql` statement. Every `schema.sql` statement runs inside `runSchema()`,
which always executes before any JS migration in `main()` gets a chance to prepare an upgrading
server's table for it, regardless of how that statement is guarded (`IF NOT EXISTS` guards against the
INDEX already existing, not against the COLUMN it references not existing yet).

---

## Credential Profiles (added 2026-07-21)

Reusable named credential bundles ("connection profiles") — save a username/password, API key, or
SSH login (optionally with a Cisco-ASA-style enable password) once under a name, then apply it when
adding a device or rotating an existing device's credential, instead of retyping the same secret for
every firewall that shares it. Modeled on ManageEngine Firewall Analyzer's own SSH/REST-API
connection-profile concept, built at direct user request.

### Schema — `credential_profiles` is credential_type-scoped, NOT vendor-scoped

`lib/schema.sql`'s `credential_profiles` table (`id`, `name UNIQUE`, `credential_type`, `username`,
`encrypted_data`, `iv`, timestamps) keys on `credential_type` (`'smc_api' | 'rest_api' | 'ssh'` —
`components/devices/vendorMeta.js`'s `CREDENTIAL_TYPES`, same vocabulary `device_credentials`
already uses), not on a vendor slug. This is safe, not a shortcut, because the plaintext PARSERS
consuming a credential are already shared across every vendor that uses a given credential_type:
`lib/adapters/credentials.js`'s `parseApiCredential()` for `rest_api` (fortinet/paloalto/checkpoint
all read the identical JSON shape), `lib/adapters/sshClient.js`'s `parseJsonCredential()` for `ssh`
(fortinet/paloalto/cisco_asa/sangfor). A single `ssh`-type profile's optional `enable_password` field
is Cisco-ASA-only — every other `ssh` vendor's parser simply never reads it, the same "one JSON shape
safely serves every vendor sharing the type" reasoning `vendorMeta.js`'s own `userpass_enable` shape
comment already documents for a single device's own stored credential. A vendor-scoped table would
have meant either duplicating an identical profile per vendor or building a vendor→type resolution
layer neither this feature nor its ManageEngine reference needs.

**No FK to `devices`/`device_credentials`, on purpose.** Applying a profile COPIES its decrypted
plaintext into the target device's own `device_credentials` row at that moment — a one-time stamp,
not a live reference. Renaming, rotating, or deleting a profile afterward never touches any device
that already used it (mirrors this table's own comment block in `schema.sql` almost verbatim — read
it directly for the full rationale). `username` is stored **unencrypted**, display-only (never the
password/api_key/enable_password), so the profile list can show "which login" without decrypting
anything — `NULL` for an api-key-only profile, which has no username to show.

**`lib/schema-grants.sql` deliberately excludes `credential_profiles` from `claude_readonly`/
`nocvault_readonly` entirely** — same treatment as `device_credentials`, and unlike `settings`/
`users` it gets **no readonly view either**: the whole row is credential-adjacent secret material
(the same `encrypted_data`/`iv` shape as `device_credentials`), and there's no "safe subset" column
worth carving out a view for (the one non-secret column, `username`, isn't worth a view on its own).

### `lib/credentialProfiles.js` — encrypt/decrypt CRUD, reusing `credStore.js` directly

Reuses `credStore.js`'s `encrypt`/`decrypt` functions directly — **not** `credStore.js`'s
`getCredential`/`setCredential`, which are `device_id`-scoped and don't apply to a profile with no
device. `buildProfilePlaintext(credentialType, {...})` is a deliberately SEPARATE function from
`vendorMeta.js`'s `buildCredentialPlaintext` (same JSON-shape rules, same RAW-string special case for
`smc_api`) rather than a shared import: `buildCredentialPlaintext` resolves its shape from
`VENDOR_META[vendor][method]`, which a profile — no vendor, no method, only a `credential_type` — has
no way to supply. Every function here except `getProfilePlaintext()` returns metadata-only rows
(`id`/`name`/`credential_type`/`username`/timestamps) safe to hand straight to `NextResponse.json()`;
`getProfilePlaintext()` exists ONLY for server-side use (copying a profile's secret into a device's
own `device_credentials` row) and its decrypted plaintext must never leave the process — called from
the devices routes below, never from a GET a browser can see. `deriveDisplayUsername()` best-effort
parses a `username` out of a JSON-shaped plaintext for the profile list's display column, never
throwing on a malformed/non-JSON (bare API key) plaintext — cosmetic, not load-bearing.
`credential_type` is immutable once a profile is created (`updateProfile()` only ever touches
`name`/`plaintext`) — a shape change means a new profile, the same way rotating a single device's own
credential never changes its `credential_type` either.

### API — CRUD + the device-routes "apply" contract

`GET/POST /api/credential-profiles` and `PUT/DELETE /api/credential-profiles/[id]` — plain CRUD,
admin-gated via `lib/rbac.js` on **every** method including GET, matching `GET /api/users`'s same
posture: a profile is only ever consumed from an already admin-only flow (Add Device, credential
rotation), so there's no viewer-facing use for the list, and erring toward the credential-adjacent
default is cheap. Plaintext is always built server-side from typed fields (`buildProfilePlaintext()`)
— never trusted pre-built from the client — so a profile's stored shape can never disagree with its
declared `credential_type`. `PUT` treats rotation as DETECTED (any secret-bearing field present) not
an explicit flag, so a `{name}`-only body renames without touching the secret.

`POST /api/devices` and `PUT /api/devices/[id]` both gained two optional body fields:
- **`credential_profile_id`** — applies a saved profile. Resolved via `getProfilePlaintext()`,
  validated with `isValidUuid()`, and its `credentialType` is checked against the resolved
  vendor+method's own `config.credentialType` **before any write** — a mismatch 400s rather than
  silently storing a credential shaped for the wrong transport. Checked first, ahead of the existing
  manual-`credential`-field path and the legacy Forcepoint-only `smc_api_key` field, in both routes.
- **`save_as_profile_name`** — the inverse: save a freshly-typed (not profile-applied) credential as
  a new named profile in the same request, so an operator doesn't have to visit Settings first.
  Best-effort and **non-fatal** — a failure (almost always a duplicate name) never fails the device
  create/rotation that already succeeded; it's surfaced instead as a `warning` string folded into the
  200/201 JSON response (`{...device, warning}`) rather than an error status. Skipped entirely when
  `credential_profile_id` was used instead (`usedExistingProfile` — nothing new to save).

### UI

**Built:** `components/settings/CredentialProfilesPanel.js` — a new Settings tab (`app/(dashboard)/
settings/page.js`'s tab array gained `{key: 'profiles', label: 'Credential Profiles'}`, rendered only
`{isAdminUser && ...}`, same pattern as the Updates tab) — full CRUD (create, rename, rotate-secret
inline-expand, delete), structurally mirroring `UsersPanel.js`: fetch-on-mount list, the same
visible/loadError 403-vs-network-failure distinction (a genuine `fetch()` rejection keeps the panel
visible with a Retry button instead of rendering as nothing, which would be indistinguishable from
the deliberate viewer-role hide), no separate client-side role check beyond reflecting the API's own
`isAdmin()` gate.

`components/devices/DeviceForm.js` (Add Device) and `components/devices/CredentialForm.js` (rotate an
existing device's credential) both gained a "Use Saved Profile" `<select>` — a default
"— Enter credentials manually —" option plus every profile matching the form's currently-resolved
`config.credentialType`, refetched once on mount (`GET /api/credential-profiles`, silently empty on a
403/network error rather than showing an error banner — this UI is only ever reachable by an admin
already). Picking one hides the manual secret/username/password/enable-password inputs entirely (the
form submits `credential_profile_id` instead of `credential`/`credential_type`) and, in `DeviceForm`,
invalidates any prior Forcepoint connectivity test the same way every other credential-relevant field
already does. Switching vendor/access-method (`DeviceForm`'s `resetCredentialInputs()`) or auth mode
(both files) resets the picker back to manual — a profile picked for one `credential_type` is not
valid after the shape changes.

**Deliberately scoped OFF Forcepoint's `smc_api` shape** — gated on `!isSmc` in `DeviceForm.js` /
`!isSecretShape` in `CredentialForm.js`. Reason: Forcepoint's Add Device Save button is gated on a
successful client-side "Test Connectivity" call (`handleTest`), which POSTs the raw secret from
browser state to `/api/devices/test-smc` to prove it works *before* Save is enabled — a saved
profile's plaintext deliberately never reaches the browser, so there is nothing for that existing
test flow to test against. Re-plumbing the test-gate to work against an opaque profile id was out of
scope here (and matches the original request, which was explicitly "either via ssh or rest api", not
SMC) — a Forcepoint operator can still create/apply nothing via the picker, but can still save a
freshly-typed-and-tested SMC key as a new profile via the "save as profile" checkbox (useful for a
later manual lookup even though this UI can't apply it back). Both forms also gained that same "save
these credentials as a reusable profile" checkbox + name field on the manual-entry path, wired to the
`save_as_profile_name` field described above.

---

## SNMP Monitoring (Phase 1, added 2026-07-21)

Answers the "SNMP monitoring and metrics collection" gap identified against ManageEngine
Firewall Analyzer — periodically polls each firewall's own SNMP agent for CPU/memory/
active-session-count/uptime and stores a timestamped snapshot, shown as gauges + `recharts`
trend lines on a new per-device tab. Modeled directly on the existing VPN active-session-
polling feature (`lib/engines/vpnSummary.js` + `vpn_session_snapshots` +
`services/engine-worker.js`'s `vpn-session-poll` job) — same "optional adapter capability,
only a successful poll writes a row, no retention job yet" shape, extended to SNMP.

**Phase 1 scope** (explicit, scoped narrowly per this app's own "don't over-build" discipline):
Cisco ASA, Fortinet, Palo Alto, Forcepoint, Sangfor (generic-only). **Check Point is
deliberately deferred to Phase 2** — not started, not stubbed.

### Credential — a SEPARATE type from the device's management-plane credential

New `device_credentials`/`credential_profiles` `credential_type`: `'snmp'`
(`components/devices/vendorMeta.js`'s `CREDENTIAL_TYPES`). Deliberately never routed through
`resolveAccessMethod()`/`buildCredentialPlaintext()` (vendorMeta.js) or `DeviceForm.js`/
`CredentialForm.js` — SNMP is an orthogonal, optional MONITORING credential, not part of the
vendor+`mgmt_method` dispatch those drive, and a device's SNMP config doesn't change when its
management transport does. Applied through its own dedicated route,
`PUT /api/devices/[id]/snmp` (`components/devices/SnmpConfigForm.js`), separately from
`PUT /api/devices/[id]`.

`lib/adapters/snmpCredential.js`'s `parseSnmpCredential(plaintext)` is the read side (mirrors
`lib/adapters/credentials.js`'s `parseApiCredential` / `lib/adapters/sshClient.js`'s
`parseJsonCredential`); `lib/credentialProfiles.js`'s `buildProfilePlaintext()` gained an
`'snmp'` branch as the write side, reused by both the credential-profiles system (a named,
reusable SNMP credential bundle, same as every other type) and `PUT /api/devices/[id]/snmp`'s
own inline manual-entry path. Stored plaintext shapes:
```json
{"version":"v1"|"v2c","community":"..."}
{"version":"v3","username":"...","authProtocol":"SHA"|"MD5"|null,"authPassword":"..."|null,"privProtocol":"AES"|"DES"|null,"privPassword":"..."|null}
```

**Security default: SNMPv3, with an explicit cleartext acknowledgment required for v1/v2c.**
SNMPv1/v2c sends its community string in CLEARTEXT on the wire — a genuinely new risk class
for this app (every other credential type here rides an encrypted transport: SSH, HTTPS, or
the SMC's TLS session). The UI defaults the version picker to v3 and only reveals the "I
understand this is sent in cleartext" checkbox for v1/v2c; **the same gate is enforced
SERVER-SIDE** (`app/api/credential-profiles/route.js`'s POST/PUT, and
`PUT /api/devices/[id]/snmp`) via a required `insecure_ack: true` body field whenever
`snmp_version !== 'v3'` — a direct API call cannot bypass the warning by skipping the UI.

`credential_profiles`/`device_credentials` already excluded `claude_readonly`/
`nocvault_readonly` entirely before this feature (see "Credential Profiles" above) — SNMP
credential rows get that same treatment automatically, no new grant work needed.

### Devices table additions + target host resolution

```sql
devices.snmp_enabled BOOLEAN NOT NULL DEFAULT false
devices.snmp_host    TEXT              -- NULL = poll via mgmt_ip (see exception below)
devices.snmp_port    INTEGER NOT NULL DEFAULT 161
```

`snmp_host` is an OPTIONAL override for every vendor except Forcepoint, where it is
**required**: Forcepoint devices store `smc_host` (the SMC's own address), never an engine's
IP, and `mgmt_ip` doesn't exist on a Forcepoint row at all (it's an `smc`-connection vendor).
`getSnmpMetrics()` on the Forcepoint adapter throws a clear, actionable error rather than
falling back to `smc_host` if `snmp_host` is unset — SNMP-polling the SMC server itself would
silently return nonsense (SMC-server health, not firewall-engine health) if it responded at
all. See the Forcepoint SMC Integration section's Core Rule above for the full exception
rationale.

### `lib/snmpClient.js` — shared net-snmp session/GET/WALK wrapper

Thin wrapper over the `net-snmp` npm package (added as a dependency this phase — actively
maintained, v1/v2c/v3 support). FROZEN CONTRACT, used identically by every vendor adapter:
`createSession(credential, host, port, timeoutMs)`, `getMetrics(session, oidMap, timeoutMs,
host)` (GETs a flat map of scalar OIDs, tolerant of PER-OID errors — a vendor not
implementing one OID in a set doesn't fail the whole poll), `walkSubtree(session, baseOid,
timeoutMs, host)` (for table-indexed metrics — e.g. Cisco ASA's per-CPU-entry load table),
`closeSession(session)`.

**Every call is wrapped in an OUTER hard timeout** (`DEFAULT_TIMEOUT_MS` + a margin,
`Promise.race`), not just `net-snmp`'s own per-request `timeout` option — `net-snmp` has
documented edge cases (a wrong SNMPv3 auth/priv passphrase in particular) where its internal
callback never fires at all. Without the outer race, a misconfigured v3 credential could hang
a poll indefinitely instead of failing cleanly — the same "an SNMP client can silently never
resolve" risk flagged during this feature's research phase, addressed proactively rather than
discovered live.

`lib/adapters/interface.js` documents the full `getSnmpMetrics()` contract (optional, same
pattern as `getObjects()`/`getVpnSessionSummary()` — checked via `typeof adapter.
getSnmpMetrics === 'function'`, never assumed present):
```js
// → { cpuPercent: number|null, memoryPercent: number|null, sessionCount: number|null,
//     uptimeSeconds: number|null, raw: object, lowConfidence?: boolean, targetHost: string }
```
MAY throw (missing credential, timeout, auth failure — the engine-worker job's existing
per-device try/catch treats it like any other polling failure). MUST NOT guess a metric value
when an OID didn't resolve — `null` for that field, same "no confident-looking wrong answer"
discipline as the applicability tri-state rule elsewhere in this file.

### Per-vendor status (2026-07-21) — READ BEFORE TRUSTING ANY VENDOR'S NUMBERS

Every OID below is doc-derived and, except where noted, has NOT been confirmed against a live
SecVault-connected device — same standing caveat as every other vendor field mapping in this
file (see "Live Validation Status" above). Each adapter logs the raw OID/table response once
via a `[Vendor SNMP Debug]` console line, same first-connect verification ritual as every
other integration in this codebase.

| Vendor | Confidence | Uptime | CPU | Memory | Sessions |
|---|---|---|---|---|---|
| Cisco ASA | High — OIDs verified against Cisco's own MIB Reference Guide + oidref.com during this build | `sysUpTime.0` (standard MIB-II) | `cpmCPUTotal5minRev` (CISCO-PROCESS-MIB `1.3.6.1.4.1.9.9.109.1.1.1.1.8`, walked table, first row) | `ciscoMemoryPoolUsed`/`ciscoMemoryPoolFree` (CISCO-MEMORY-POOL-MIB `...48.1.1.1.5`/`.6`, walked, computed %) | `cfwConnectionStatValue` instance `1.3.6.1.4.1.9.9.147.1.2.2.2.1.5.40.6` (CISCO-FIREWALL-MIB, current global connections) |
| Fortinet | High — standard, widely-cited FORTIGATE-MIB OIDs, cross-checked via oidref.com/mibs.observium.org | `sysUpTime.0` | `fgSysCpuUsage.0` (`1.3.6.1.4.1.12356.101.4.1.3.0`) | `fgSysMemUsage.0` (`...4.0`) | `fgSysSesCount.0` (`...8.0`) |
| Palo Alto | **Low — explicit `lowConfidence: true`, UI badge shown** | `sysUpTime.0` | HOST-RESOURCES-MIB `hrProcessorLoad` table (`1.3.6.1.2.1.25.3.3.1.2`, walked, averaged across cores) | HOST-RESOURCES-MIB `hrStorage` table (4-column walk, matched by `hrStorageDescr` text — fiddly, may be `null`) | PAN-COMMON-MIB `panSessionActive.0` (`1.3.6.1.4.1.25461.2.1.2.3.3.0`, a real count — `panSessionUtilization` was checked and rejected as a %, not a count; a candidate `panSysResourceUtilization` CPU OID was checked directly against the real MIB listing and does NOT exist, dropped rather than guessed) |
| Forcepoint | **Low — explicit `lowConfidence: true`, UI badge shown** | `sysUpTime.0` | `fwCpuTotal` (STONESOFT-FIREWALL-MIB `1.3.6.1.4.1.1369.5.2.1.11.1.1.3`, walked, "total" row) | `fwMemBytesUsed`/`fwMemBytesTotal` (STONESOFT-FIREWALL-MIB `...11.2.5`/`.4`, walked, computed %) | `fwConnNumber` (STONESOFT-FIREWALL-MIB `1.3.6.1.4.1.1369.5.2.1.4`) — Forcepoint NGFW was formerly "Stonesoft"; engines still ship this MIB per Forcepoint's own SNMP docs, confirmed via two independent third-party MIB-browser sites agreeing on every OID (not one uncorroborated guess) |
| Sangfor | **Low — explicit `lowConfidence: true`, UI badge shown, generic-only by design** | `sysUpTime.0` | HOST-RESOURCES-MIB `hrProcessorLoad` (walked, averaged) | HOST-RESOURCES-MIB `hrStorage` (best-effort, may be `null`) | No generic OID exists — always `null` |
| Check Point | **Not implemented — Phase 2** | — | — | — | — |

Sangfor's generic-only scope is deliberate, not a gap — same reasoning this file already
documents for Sangfor's `getObjects()` being unimplemented: no live device, no reliable
documentation trail, and fabricating a vendor-proprietary OID guess would be exactly the
"documentation lies, verify against live systems" trap this file warns against elsewhere.
Forcepoint's `FORCEPOINT-NGFW-ENGINE-MIB` (the modern, 6.11+ MIB name) was searched for
during this build and only its TRAP definitions were found publicly documented — no polled-
metric OID catalog for that MIB — which is why Forcepoint's metrics use the older
Stonesoft-era MIB instead (a real, corroborated source) rather than the modern MIB name with
guessed OIDs.

### `services/engine-worker.js` — `snmp-poll` job

Third minutes-scale job, alongside `vpn-session-poll` (same `*/n * * * *` cron shape,
`SNMP_POLL_INTERVAL_MINUTES` env var, default 15, clamped 5-59 — shorter default than VPN's 30
since SNMP-over-UDP is lighter-weight than an SSH/REST session). Query is
`WHERE active = true AND snmp_enabled = true` — gated on the DEVICE's own opt-in flag, not
just adapter capability, since SNMP needs a separately-configured credential (and, for
Forcepoint, an explicit engine IP) an operator must deliberately set up. Own in-flight guard
(`snmpPollInFlight`), and defers a whole tick when `rule-version-pull` is already running —
same same-device-concurrent-session caution as `vpn-session-poll`, even though SNMP is a
separate UDP protocol from SSH/REST. A row is only ever inserted on a successful poll; a
per-device failure is logged and skipped, never fatal to the job.

### UI

**⛔ Superseded again 2026-07-21, later still the same day — see "Device Overview Tab" →
"Identity card removed, tab bar moved to top of page" below.** The note immediately below this
one already corrected the SNMP card's placement once (into the `tab === 'overview'` block); a
second page restructuring the same day moved the "device info card" and "tab bar" that note
refers to as well — the always-visible identity card was replaced with a bare identity strip,
and the tab bar itself relocated to the very top of the page, immediately after "← Back to
devices". The SNMP card's position RELATIVE TO the Overview tab's own content is unchanged by
that later move: it is still the first thing rendered inside `tab === 'overview'`, now directly
beneath a new "Device Details" card (the old device-info grid, relocated into that tab's body)
rather than beneath nothing. See that subsection for the current, real page structure.

**⛔ Superseded 2026-07-21, later the same day — see "Device Overview Tab" → "Follow-up
round, same day" below.** The always-visible, above-the-tab-bar placement described in this
subsection was itself relocated a few hours later: the SNMP card now renders inside the
`tab === 'overview'` block, not between the device info card and the tab bar. Kept below for
the placement history (why the always-visible design was chosen in the first place), not as
a description of current behavior.

**⛔ Placement changed 2026-07-21, same day this shipped — direct user feedback.** The
original entry point was a small "SNMP →" link at the bottom of the Rules tab, mirroring the
pre-existing VPN link's placement exactly — but the Rules tab isn't the tab a device page
lands on by default (that's CVE Posture), and a text link stacked after a table is easy to
miss regardless. The user's ask was explicit: SNMP metrics should show on the main device
page itself, like a summary widget, not be buried behind a click. Fixed: `devices/[id]/
page.js` now queries the latest `snmp_metric_snapshots` row (and whether an `snmp`
credential exists) UNCONDITIONALLY — same as `getLatestVersion()`, not gated behind any tab
— and renders an always-visible "SNMP Monitoring" card between the device info card and the
tab bar: 4 `StatCard` tiles (CPU/Memory/Sessions/Uptime) + last-polled timestamp when a
snapshot exists, an "enabled but nothing polled yet" message when `snmp_enabled` is true with
no data, or a plain "Not configured" prompt otherwise — each state links to the full
`/devices/[id]/snmp` page (relabeled "Full history & config →" / "Configure →" depending on
state). **The VPN link's identical original placement was NOT changed** — this fix was scoped
to the specific feature the user flagged, not a blanket redesign of every "→" link on this
page; revisit VPN's placement separately if the same complaint comes up for it.

### Config-based detection — "SNMP already looks enabled" (added 2026-07-21)

Direct follow-up question from the user during this feature's own proposal review: can
SecVault tell from already-collected config whether SNMP is already configured, instead of
always requiring manual entry? Answer, grounded rather than assumed: **detecting that SNMP
looks enabled is safe and cheap for Fortinet and Palo Alto today; auto-extracting the actual
community string is deliberately NOT built, and shouldn't be** — see the two reasons below.

`lib/engines/snmpConfigDetection.js` — same architectural family as `vpnSummary.js`/
`adminAccountSummary.js` (pure, no DB, read-only interpretation of already-collected
`device_configs.config_parsed`, kept out of the adapters themselves). `detectSnmpConfig(vendor,
configParsed)` returns `{supported, hasConfig, enabled, foundAt, fields, lowConfidence?}`;
`looksConfigured(detected)` is the UI convenience predicate (`hasConfig && enabled !== false`).

- **Fortinet**: `config_parsed.snmp` (FortiOS `system snmp sysinfo`, already collected on both
  transports, zero new adapter work) — `snmp.status === 'enable'/'disable'` (FortiOS's own bare
  vocabulary) maps to `enabled: true/false`. This adapter never fetches the separate `system
  snmp community` table (the actual secret) — only this global agent-status object — so there
  is nothing secret-shaped in the detection result to worry about.
- **Palo Alto (both transports)**: bounded deep search (same `deepFindKeyByPattern()`
  approach as `vpnSummary.js`'s GlobalProtect detection, for the identical "PAN-OS nesting
  varies" reason) for a key matching `/snmp-setting/i` — the real PAN-OS path
  (`deviceconfig system snmp-setting ...`) was NOT guessed fresh for this feature; it's the
  same path `lib/adapters/paloalto/{parser,sshParser}.js`'s own pre-existing secret-redaction
  lists already target (`snmp-community-string`). PAN-OS has no explicit enable/disable toggle
  the way FortiOS does, so `enabled` is always `null` here — the block's mere presence is the
  signal, carried via `hasConfig: true` instead. `lowConfidence: true` always, matching this
  vendor's SNMP-metrics treatment elsewhere in this section.

**Why extracting the actual community string was explicitly rejected, not just deferred:**
verified directly against the real code (not assumed) that by the time either vendor's
`config_parsed` exists, the secret is already gone — Fortinet never collects the community
table at all; Palo Alto's `getConfig()` on both transports builds `parsed` FROM the
already-redacted raw text/response (`parser.parseConfig(redactedConfigResult, ...)` — see the
"Palo Alto SSH — RESOLVED" and Check Point/Forcepoint redaction sections above for this app's
established redact-before-parse discipline). Even if it weren't already redacted, silently
importing a scraped credential would bypass the SNMPv2c/v1 cleartext-acknowledgment gate this
feature was built around — an explicit, informed opt-in, not something a config scrape should
short-circuit.

**UI**: `devices/[id]/page.js`'s always-visible SNMP card shows a "Detected in config" badge
(instead of "Not Configured") plus an inline nudge naming where it was found, linking to
`/devices/[id]/snmp`. That page shows the same nudge above the config form and passes
`detected` to `SnmpConfigForm` to pre-check the Enable toggle — a convenience default only,
never applied once a real config already exists (`initial.snmpEnabled` already true), and
never pre-fills any credential field.

Cisco ASA, Forcepoint, and Sangfor have no detector yet — `detectSnmpConfig()` returns
`supported: false` for them, rendered distinctly from "checked, not there." A natural
per-vendor follow-up (Cisco ASA's `show snmp-server` equivalent isn't currently collected into
`config_parsed` either) — not built now.

### On-demand test — `POST /api/devices/[id]/snmp/test` (added 2026-07-21)

Direct user feedback: after configuring an SNMP credential, there was no way to find out
whether it actually works without waiting up to `SNMP_POLL_INTERVAL_MINUTES` for the next
scheduled poll. Mirrors `POST /api/devices/[id]/test`'s shape (`{ok, message}`) and
`DeviceActions.js`'s save-then-test convention — tests the ALREADY-SAVED credential (not a
client-supplied one; there is no pre-save dry-run the way Forcepoint's SMC form has one),
by calling the adapter's `getSnmpMetrics()` directly, once, outside the scheduled job. **On
success it ALSO inserts a `snmp_metric_snapshots` row** — a real metrics fetch just happened;
discarding it would be wasteful and would leave the trend chart looking unchanged right after
a successful test. On failure, nothing is inserted — same "only a successful poll writes a
row" discipline as the scheduled job. Returns a clear, distinct message when the vendor's
adapter has no `getSnmpMetrics()` at all (Check Point, or any future vendor before its adapter
work lands) rather than a generic 500.

`components/devices/SnmpConfigForm.js`'s "Test Connectivity" button only appears once
`initial.hasCredential` is true (nothing to test before a credential is saved) — `handleSave()`
now calls `router.refresh()` on success specifically so this button appears immediately after
a first-time save without a manual page reload.

### Full page

The full `/devices/[id]/snmp` page (linked from the summary card, not removed) still carries
the deeper content the main-page card intentionally doesn't: stat tiles restated for context,
`components/snmp/SnmpMetricsCharts.js` (two `recharts` `LineChart`s: CPU%+Memory% on a shared
0-100 scale, session count on its own scale — deliberately two charts, not one dual-axis
chart, so neither axis is a misleading secondary scale), and `components/devices/
SnmpConfigForm.js` (enable toggle, host/port, saved-profile picker, manual v3/v2c/v1 entry
with the cleartext-ack gate). `GET /api/devices/[id]/snmp` supports `?format=csv` export,
same convention as the VPN page. **No fleet-wide `/snmp` page yet** (VPN has one at `/vpn`) —
a natural Phase 2+ follow-up once per-device data exists to aggregate, not built now.

### Trend charts on the summary card (added 2026-07-21, later still)

Direct user request: the always-visible SNMP Monitoring card (now inside the Overview tab, see
"Identity card removed, tab bar moved to top of page" above) originally showed only the LATEST
polled value per metric (`getLatestSnmpSnapshot()`, a single row) — no trend, just a number, even
though the full `/devices/[id]/snmp` page already had real trend charts. `components/snmp/
SnmpTrendMini.js` is a compact sibling of `SnmpMetricsCharts.js` (same CPU+Memory-shared-scale /
Sessions-own-scale two-chart split, same `resolveColor()` CSS-custom-property pattern, same
tooltip content) but deliberately smaller and stripped down for a summary-widget context: no Y
axis, minimal X axis (time-of-day only, not a full date), 90px tall instead of 220px, no
gridlines. It renders directly under the existing CPU/Memory/Sessions/Uptime `StatCard` row inside
the same card — the numbers stay (still the fastest way to read "what's the value right now"), the
chart adds "what's it been doing" underneath. Uptime deliberately has no sparkline (it's
monotonically increasing until a reboot — a flat line carries no information a single number
doesn't already give).

Data source: a new `getRecentSnmpHistory()` query, capped at the most recent 30 snapshots (a
subquery `ORDER BY sampled_at DESC LIMIT 30`, then re-ordered `ASC` in JS to match every chart
component's oldest-to-newest convention) — roughly 7.5 hours of trend at the default 15-minute
`SNMP_POLL_INTERVAL_MINUTES`. Deliberately NOT the full unlimited history
`/devices/[id]/snmp`'s own `SnmpMetricsCharts.js` uses — this is a glanceable recent-trend
indicator on a page that already has a lot on it, not the detailed history view (which stays
exactly as it was, unchanged, for whenever a longer look-back is actually needed). Only fetched
when `tab === 'overview'`, same conditional-fetch convention `cveRows`/`rules` already use on this
page for their own tab-specific queries. `SnmpTrendMini` renders nothing (`return null`) when
fewer than 2 points exist — a lone snapshot can't show a trend, and the `StatCard` row above it
already covers that case.

---

## Device Overview Tab (added 2026-07-21)

The user shared a ChatGPT-generated mockup of a much richer per-device dashboard (reached by
clicking a device from the Devices list) and asked for a feasibility check before building
anything. A 6-agent parallel research pass (one per widget group) audited the mockup against
this app's real data model — the findings became a three-tier plan: 🟢 items already fully
computed elsewhere and just needing to be surfaced, 🟡 items needing modest new work but no
new product decisions, 🔴 items that don't map to this app's real data or architecture at all
(a composite "Security Score," a "High Risk Issues" tile, an "Affected Feature" CVE column,
GDPR/HIPAA compliance standards — neither exists in this app — HA status, a named "Collector"
field implying a multi-tenant distributed architecture SecVault doesn't have, and a precise
per-device "Next Collection" time, since the pull interval is a single global env var, not
per-device). This round built the 🟢 tier only; 🟡 is an explicit, deliberate follow-up.

**New default tab**: `devices/[id]/page.js`'s tab list is now `overview|cve|rules|config|admins`
(previously `cve|rules|config|admins`), with `overview` as the new default landing tab instead
of `cve` — matching the mockup's own "Overview first" intent. The other four tabs are
completely unchanged. **Updated later the same day**: a sixth tab, `manage`, was added
(`overview|cve|rules|config|admins|manage`) — admin-only, does not render at all for a
`viewer`-role session, either as a tab link or as content. See "Identity card removed, tab bar
moved to top of page" below.

Built as 4 independent card components, each a standalone async server component owning its
own DB query (same "widget owns its DB access" convention already established by
`components/dashboard/ConfigChangesWidget.js`) — assembled into the tab by `devices/[id]/
page.js`, not by any shared query layer:

- **`components/devices/OverviewCveCard.js`** — patch-now/scheduled counts + a top-5 CVE table,
  reusing the EXISTING `CVETable` component verbatim (same row shape the CVE Posture tab
  already queries) rather than a new table. Deliberately omits an "Affected Feature" column —
  `advisories` has no such field, and deriving one reliably from `title`/`description` text
  would be guesswork, not data.
- **`components/analysis/RuleHygieneDonut.js`** (new, generic, reusable — no domain wording
  baked in) + **`components/devices/OverviewRuleHygieneCard.js`** — a genuinely NEW multi-slice
  categorical donut chart, distinct from `components/compliance/StandardDonut.js` (a single-
  value 2-segment gauge). Six categories: 5 direct `rule_analysis_results.finding_type` values
  (`unused`/`shadow`/`redundant`/`any_any`/`log_disabled`) plus an "Other Issues" bucket summing
  the remaining 5 real types (`correlation`/`risky_service`/`reorder_candidate`/
  `expiring_soon`/`overly_permissive`) — kept as one bucket, not 10 slices, for legend
  readability. A finding_type with zero rows still appears in the legend at `0` (the query
  result is merged onto a fixed category list, never iterated directly, so a missing row can't
  silently vanish from the legend). Also added an "Expired" rule count
  (`expiry_date < now()`) alongside the already-existing Total/Active/Disabled — the one
  genuinely new query in this whole batch; everything else is either identical to or a
  device-scoped variant of an already-existing query.
- **`components/devices/OverviewConfigChangesCard.js`** — a per-device analog of
  `ConfigChangesWidget.js`'s fleet-wide card (same real Added/Removed/Modified counts via
  `jsonb_array_length(diff->...)`), with one real improvement: each row shows an
  Acknowledged/Unacknowledged `Badge` from `config_diffs.acknowledged_at` — **deliberately NOT**
  a fabricated High/Medium/Low "impact" badge, since no severity/impact concept exists
  anywhere in `config_diffs` (confirmed during the feasibility research; inventing one is
  explicitly deferred to the 🟡 follow-up, pending a real threshold decision).
- **`components/devices/OverviewComplianceCard.js`** — a condensed version of the already-
  fully-built `/compliance/[deviceId]` page: the exact same `getFindings()`/
  `aggregateStandards()`/`scorePctFromCounts()` logic (tri-state honesty preserved — `na`
  excluded from the denominator, `null` never coerced to `0`), reusing `StandardDonut` directly
  at a smaller `size` instead of a new gauge component. Renders the 5 REAL standards (PCI-DSS,
  ISO 27001, CIS v8, NIST, SANS) side by side — **deliberately no blended overall compliance
  score**, since no aggregation formula for one exists anywhere in this app; inventing the
  weighting is explicit 🟡 follow-up work, not done here.

**⛔ Placement description superseded twice, see "Follow-up round, same day" immediately below
and "Identity card removed, tab bar moved to top of page" further below** — by the time this
paragraph was written the SNMP card had not yet moved into the Overview tab (that happened a
few hours later the same day, documented in the very next subsection), and the page structure
around it changed again later still. The REASONING here (don't show the same numbers twice on
one page) still holds and is why the SNMP card was never duplicated inside `OverviewCveCard`'s
grouping either — only the "above the tab bar" placement claim is stale.

**Deliberately NOT duplicated on the Overview tab**: a "System & Resources" section — the SNMP
Monitoring card (CPU/Memory/Sessions/Uptime, see above) is already an ALWAYS-VISIBLE card
sitting above the tab bar on this same page (built earlier the same day, specifically in
response to a discoverability complaint) — repeating it inside the Overview tab would be
redundant UI showing the same numbers twice on one page.

**Verified before integrating**: all 4 sub-agents' components were personally read in full
against their frozen contracts before being wired into `devices/[id]/page.js` (per this file's
own "verify agent diffs before integrating" rule), and `npm run build` was run clean after
each wiring step.

### Follow-up round, same day — SNMP card relocated, two 🟡 items resolved

**SNMP card moved into the Overview tab.** It used to sit ABOVE the tab bar (always visible
regardless of active tab — a deliberate choice at the time, made specifically to fix a
discoverability complaint before this Overview tab existed). Direct user feedback once the
Overview tab shipped: it was "sticky across all tabs," visible even on Rules/Admins/Config
Changes, which now reads as redundant clutter rather than a feature — the Overview tab is the
new, better answer to the original discoverability problem. The whole SNMP Monitoring `<div
className="card">` block moved unchanged (same JSX, same queries — `snmpSnapshot`/
`snmpHasCredential`/`snmpDetected`/`snmpDetectedLooksConfigured` are still fetched
unconditionally at the top of the page, not gated behind `tab === 'overview'`, since the cost
is negligible and gating them would add complexity for no real benefit) into the top of the
`tab === 'overview'` block, ahead of `OverviewCveCard`.

**⛔ Position note added 2026-07-21, later still the same day**: "top of the `tab === 'overview'`
block" above is still accurate, but it's no longer the first CARD an operator's eye lands on
when the tab opens — a later restructuring (see "Identity card removed, tab bar moved to top of
page" below) inserted a new "Device Details" card ahead of it, inside the same tab body. The SNMP
card is now second, not first, within `overview` — still unconditionally fetched, still unchanged
JSX, just no longer the leading element.

**Two 🟡-tier decisions from the earlier feasibility research were resolved by the user
(via `AskUserQuestion`, not guessed) and built the same day:**

- **Config-change Impact badge** (`components/devices/OverviewConfigChangesCard.js`) — a
  DERIVED heuristic (no `impact`/`severity` column exists in `config_diffs`, and none was
  added), computed fresh on every read by reusing `lib/engines/configDiff.js`'s ALREADY-BUILT
  `classifyDiff()` (never re-parses diff paths a second time). Decided mapping: any resolved
  individual rule change (`classifyDiff()`'s `ruleChanges` non-empty) or an unresolvable-rule
  section label (`'Rules (detail unavailable for this device)'`, `'Policy-Based Forwarding
  Rules'`) → **High**; NAT/VPN/admin/zones/network/device-level config sections → **Medium**;
  everything else (address/service objects, SNMP, NTP, DNS, logging, password policy,
  FortiGuard, system info, any unrecognized section) → **Low**. Rendered as a `Badge` next to
  the existing Acknowledged/Unacknowledged badge on each row. Required adding `cd.diff` to
  this card's existing SELECT list (it previously only selected the `jsonb_array_length`
  counts, not the raw diff object needed for classification).
- **Blended Compliance Score** (`components/devices/OverviewComplianceCard.js`) — this card
  previously deliberately showed no such number (see its original header comment, now
  updated). Decided formula: a simple, UNWEIGHTED average of whichever standards have a real
  (non-null) `scorePct`; a never-audited or unmeasurable standard is EXCLUDED from the average
  entirely, never coerced to `0` (same tri-state-honesty discipline this file already applies
  to a single standard's own score); if literally every standard is null, the overall score is
  null too, rendered as "—" rather than a fabricated number. Rendered as a visually distinct
  bordered panel with a larger `StandardDonut` above the existing per-standard grid, captioned
  "Average of N audited standards" — deliberately NOT styled as a 6th grid tile, so it reads
  as one derived summary rather than a genuine independent standard sitting alongside the 5
  real ones.

Both diffs were personally reviewed against their frozen contracts before integrating, and
`npm run build` was run clean after each.

### Identity card removed, tab bar moved to top of page (added 2026-07-21, later still the same day)

Direct follow-up user request, applying the exact same lesson the SNMP card relocation above
already established a few hours earlier: an always-visible, above-the-tabs card reads as
clutter once tabs exist as the page's real navigation — "sticky across all tabs" was the
precise complaint that moved the SNMP card into the Overview tab; the user asked for that
identical reasoning applied a second time, to the device identity card itself. Tabs should be
the page's primary navigation, device-management actions belong grouped together instead of
scattered across an always-visible control strip, and device-summary data (the IP/version/
model/build/serial grid) belongs inside Overview alongside the SNMP tiles it's the same kind
of fact as, not as a permanent widget everyone sees regardless of which tab they're on.

The card that used to sit at the top of the page — status dot/name/vendor badge, Collect Now/
Test Connectivity/Delete buttons, the Management IP/Version/Model/Build/Serial/Last Collected
grid, and (admin-only) the Rotate Credentials form — was replaced with a bare identity strip:
just the status dot, device name, and vendor `Badge`, no card chrome, no buttons, no data. The
tab bar itself moved from partway down the page to immediately below that strip — now the
first thing under "← Back to devices", ahead of every card on the page, including the Overview
tab's own content.

The device-details grid (Management IP/SMC Host, Version, Model, Build, Serial, Last Collected)
moved into a new "Device Details" card — now the FIRST card inside the `overview` tab body,
ahead of the SNMP Monitoring card (see "Position note added 2026-07-21" above) — same query
(`getLatestVersion()`), same fields, same `'—'` fallbacks, just relocated wholesale rather than
rebuilt. Its heading (`fontSize: 'var(--text-lg)', fontWeight: 700, color: 'var(--text-primary)'`)
deliberately matches the SNMP Monitoring card's own heading style, since the two are now
adjacent siblings in the same tab.

**New tab: `manage`** — a sixth entry on the tab bar (`overview|cve|rules|config|admins|manage`,
see "New default tab" above). Holds two cards, both moved verbatim from the old identity card:
"Device Actions" (`DeviceActions` — Collect Now/Test Connectivity — plus the Delete button) and
"Rotate Credentials" (`CredentialForm`, unchanged). **Double-gated on `canWrite` for defense in
depth**, matching every other admin-only control in this app: the tab LINK itself only renders
via `{canWrite && tabLink(device.id, tab, 'manage', 'Manage')}` (a viewer never sees the tab at
all), and the tab's CONTENT is separately gated via `{tab === 'manage' && canWrite && (...)}` —
a viewer hand-typing `?tab=manage` into the URL bar sees nothing, not a link that happens to be
hidden elsewhere. As always, this is UI-hiding only, not the real enforcement — every route
these controls call (`PUT`/`DELETE devices/[id]`, `POST devices/[id]/test`, `POST
devices/[id]/collect`) is independently `isAdmin()`-gated server-side regardless of what this
page shows or hides.

**Name deliberately chosen to avoid colliding with the pre-existing `admins` tab.** `admins` is
a completely different, unrelated concept — the FIREWALL's own admin/user accounts, rendered via
`summarizeAdminAccounts()` (see "Admin Account Summary" above) — left entirely unchanged by this
round. `manage` reads unambiguously as "manage this SecVault device entry," distinct from
"view the firewall's own admin accounts."

**Delete confirmation URL now always uses `tab=manage`.** The Delete button (now inside the
`manage` tab) and the confirmation `Modal`'s Cancel link both point at
`/devices/[id]?tab=manage&confirmDelete=1` / `?tab=manage` unconditionally — previously the
identity card's Delete button preserved whatever tab happened to be active
(`?tab=${tab}&confirmDelete=1`), which made sense when Delete lived in a card visible from every
tab. Now that Delete only lives inside `manage`, returning to some other tab after Cancel would
be a confusing non-sequitur — Cancel now always lands back on `manage`, where the button that
opened the dialog actually lives.

---

## Feed Sources

| Feed | URL | Schedule | Notes |
|---|---|---|---|
| NVD API 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Every 6h | Rate: 1 req/6s without key, 5 req/30s with `NVD_API_KEY`. Multi-vendor: `VENDOR_CPES` in `lib/feeds/nvd.js` maps every vendor slug to live-verified CPE strings (cisco_asa needs BOTH `o:` and `a:` part variants — NVD is split). Always `virtualMatchString`, never `cpeName`. |
| Palo Alto PSIRT | `https://security.paloaltonetworks.com/api/v1/products/PAN-OS/advisories` | Every 6h, sequential after NVD | `lib/feeds/paloalto.js`. Bulk beta API, one call, ~346 advisories, CVE Record Format 5.x (same shape NVD's CIRCL fallback already parses). See "Vendor PSIRT Feeds" below. |
| Fortinet FortiGuard | `https://www.fortiguard.com/rss/ir.xml` (→ redirects to `filestore.fortinet.com`) | Every 6h, sequential after Palo Alto | `lib/feeds/fortinet.js`. RSS for discovery + per-advisory CSAF 2.0 JSON for structured data, 1s rate limit between advisories. See "Vendor PSIRT Feeds" below. |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Every 6h | Full download, cross-reference by cve_id |

Sync order (`lib/feeds/index.js`'s `runFullSync`) is deliberately **sequential, not parallel**: NVD → Palo Alto PSIRT → Fortinet FortiGuard → KEV. One feed's failure is fully isolated (its own try/catch) and never blocks the next. Each of the four gets its own `feed_sync_log` row (`feed_name`: `nvd`/`paloalto_psirt`/`fortinet_psirt`/`kev`) — `getFeedStatusBySource(pool)` returns the latest row per source (`null` for a feed that hasn't run yet, not an error). CIRCL is **not** a fifth `feed_sync_log` row — it has no independent scheduled run of its own, it's an in-band fallback inside the NVD sync; its usage is derived from the `nvd` row's own `errors` jsonb via `summarizeCirclUsage()` (every CIRCL code path, success or failure, pushes a `[CIRCL fallback] ...`-prefixed entry there — the success path didn't originally do this and under-reported CIRCL usage on the Advisories page banner until fixed alongside this phase; see `lib/feeds/nvd.js`'s `tryCirclFallback`).

### NVD Rate Limiting

Implement exponential backoff on 403/429:
```javascript
// Base: 6s delay between requests (no API key)
// On 429: wait 30s then retry
// On 403: log and skip (API key issue)
// Never hammer NVD — will get IP banned
```

### NVD Fallback — CIRCL Vulnerability-Lookup (added 2026-07-16)

**Root cause this fixes:** a production SecVault server had its outbound firewall block
`services.nvd.nist.gov` specifically (confirmed via `Test-NetConnection` — DNS resolved correctly,
`github.com:443` connected fine from the same host, only NVD was blocked) while `node-fetch@2` had
no request timeout at all, so a blocked NVD request hung indefinitely instead of failing — a sync
that should take ~1-2 minutes looked hung for 7+ minutes. Two independent fixes, both in
`lib/feeds/nvd.js`:

1. **`FETCH_TIMEOUT_MS = 20000`** on every NVD `fetch()` call — a stalled request now fails fast
   instead of hanging.
2. **CIRCL fallback** (`vulnerability.circl.lu`, CIRCL's public "Vulnerability-Lookup" project) —
   triggers ONLY when an NVD request fails with a true network-level error (`err.status == null`,
   meaning `fetch()` itself threw — timeout, DNS failure, connection refused/reset). NVD remains
   primary and is never skipped in favor of CIRCL; an NVD HTTP response of any kind (429/403/5xx)
   is a *different* failure class and does NOT trigger the fallback, only a request that never got
   a response does.

**Live-verified before writing any code** (per this file's own "verify against live responses"
rule — the user's assumed endpoint, `/api/query`, 404s and doesn't exist):
- Real endpoint: `GET /api/vulnerability/search/{vendor}/{product}?page&per_page&since` (confirmed
  against the live `swagger.json`). `{vendor}/{product}` are derived directly from each
  `VENDOR_CPES` string's own `cpe:2.3:<part>:<vendor>:<product>:...` segments — no separate mapping
  table needed.
- **`/api/vulnerability/cpesearch/{cpe}` was tried and rejected** — passing our exact wildcard CPE
  strings (e.g. `cpe:2.3:o:fortinet:fortios:*:*:*:*:*:*:*:*`) returned an unrelated product
  (FortiPAM, under a FortiOS query) and has no pagination metadata. The vendor/product endpoint's
  matching was precise and paginated across every vendor tested; `cpesearch` was not used.
- `per_page` is a real, documented parameter, but the server silently clamps values above 100 (a
  request for `per_page=200` came back as `page_size: 100`) — `CIRCL_PER_PAGE = 100` reflects the
  verified ceiling, not a guess.
- No API key is required for this endpoint (confirmed live: unauthenticated requests return real
  200 OK data for all 6 vendor/product pairs). CIRCL's `Authorization` header is only for
  account-specific write operations (comments, bundles, user management) — irrelevant here. **Do
  not wire in a CIRCL API key** unless a real rate-limiting need shows up later; one is not needed
  today.
- Response shape is CVE Record Format 5.x (MITRE's own schema — `containers.cna`/`containers.adp`),
  NOT NVD API 2.0's shape. CVSS data can be under `containers.cna.metrics[]` OR any
  `containers.adp[].metrics[]` entry depending on which org authored the record — confirmed both
  placements live, `pickCvssFromCveRecord` scans both. `total_count` counts raw entries across the
  `nvd` + `cvelistv5` result buckets CIRCL merges, which commonly both carry the same CVE, so a
  deduped record count well below `total_count` is normal and NOT a sign of truncation — only log
  a "capped" warning when `CIRCL_MAX_PAGES` (10) was actually reached with more still outstanding.

**⛔ Stale note corrected 2026-07-19, found in a follow-up bug sweep:** this paragraph previously said
`changes[]` is "ignored" outright — that stopped being true as of the 2026-07-17/2026-07-18 fixes to
`highestVersionFromChanges`/`allCheckpointsFromChanges` (see those functions' own comments in
`lib/feeds/nvd.js` and `lib/feeds/paloalto.js`, and the identical logic ported into
`lib/feeds/fortinet.js`'s CSAF parsing), and a further 2026-07-19 fix now collects `changes[]`
checkpoints **unconditionally** rather than only when no top-level `lessThan`/`lessThanOrEqual` bound
is present. `changes[]` IS used, on all three CVE-Record-Format-consuming feeds: the highest
`'unaffected'` change point sets `max`/`excludeFixed` when no top-level bound exists, and every
`'unaffected'` change point (regardless of whether a top-level bound exists) is collected into
`safe_exact_versions` so `versionComparator.js`'s `isSafeOnMatchingTrain` can check a device against
its own hotfix train, not just the coarse `{min,max}` range. What genuinely remains a known,
accepted simplification: a `changes[]` entry's own *sub*-timeline (a point patched, then regressed
in a later change within the same entry) isn't modeled — only the flat set of `'unaffected'` points is
extracted, with no ordering/dependency between them. This can only make the recognized-safe set
**wider** than strictly correct in a regression-after-patch edge case, never narrower — same
conservative direction as the "unknown treated as applicable" tri-state rule under CVE Engine
Architecture above, never the dangerous direction.

**Logging:** `[NVD] <cpeString>: N CVE(s)` on a normal successful fetch, `[CIRCL fallback] ...` on
every fallback attempt/result/failure — grep `engine.log` for either prefix to see which source
served a given sync.

---

## Vendor PSIRT Feeds — Palo Alto + Fortinet (added 2026-07-17)

Both live-verified with curl before writing any parser, per this file's own "documentation lies,
test against live systems" rule — the endpoints/shapes below are confirmed, not assumed from
vendor docs. `[PaloAlto PSIRT Debug]` / `[Fortinet PSIRT Debug]` are logged on the first advisory
processed each run, same convention as every other feed/adapter in this codebase.

### Palo Alto — `lib/feeds/paloalto.js`

**Use the beta bulk endpoint, `GET /api/v1/products/PAN-OS/advisories`, as the ONLY source.**
Do **not** use `GET /json` / `GET /json?product=PAN-OS` / `GET /json/{id}` — live-verified to only
return the 25 most recent bulletins (not full history), with a fragile parallel-array version-range
format (`"< 12.1.4-h8, < 12.1.7-h2, < 12.1.8"`, comma-separated hotfix-train upper bounds with no
explicit lower bound) and no valid CVSS vector (only separate AV/AC/PR/UI/C/I/A letters, missing
Scope). The beta endpoint, by contrast, returns **346 advisories in one call** (~4.3MB, no
pagination), and every entry is a **full CVE Record Format 5.x object** — the exact same shape
`lib/feeds/nvd.js`'s CIRCL fallback already parses (`extractAffectedRangesFromCveRecord` etc.) —
`paloalto.js` mirrors that logic rather than importing it (kept independent so this feed's parsing
can't regress the already-verified NVD file; some duplication accepted, same tradeoff as the
alerts/events split documented elsewhere in this file).

Confirmed live:
- `cveMetadata.cveId` is `CVE-YYYY-NNNNN` for most entries, `PAN-SA-YYYY-NNNN` for informational
  bulletins with no assigned CVE (59 of 346 at verification time) — stored as-is in `advisories.cve_id`
  (just a unique text key, not format-validated).
- `containers.cna.affected[]` entries carry a `product` field (`"PAN-OS"`, `"Cloud NGFW"`,
  `"Prisma Access"`, ...) — filter to `product === 'PAN-OS'` **exact string match**; an advisory
  with zero matching entries (PAN-OS-unaffected) is skipped, not inserted as an empty row.
  `versions[]` per matching entry: `{status, version, lessThan, changes}` — 0 of 346 entries had
  unusable version data at verification time.
- `containers.cna.metrics[]` mixes `cvssV4_0`/`cvssV3_1`/`cvssV3_0` across different advisories
  (Palo Alto is mid-migration to v4.0), and **can hold multiple entries for the SAME CVE**
  representing different deployment "scenarios" (e.g. management-interface-exposed vs. restricted).
  Preference cascade `cvssV4_0 → cvssV3_1 → cvssV3_0`, **first match wins, not highest score** — a
  scenario-specific narrative isn't the general-case recommendation.
- `containers.cna.references[0].url`, `.title`, `.descriptions[0].value` are all clean, real,
  vendor-authored — used directly, no synthesis needed (unlike NVD, which has no title field).
- No rate limiting needed (one bulk call, not N-per-advisory) — still gets the standard
  `FETCH_TIMEOUT_MS = 20000`.

### Fortinet — `lib/feeds/fortinet.js`

**RSS is discovery-only. CSAF 2.0 JSON is the real data source, NOT HTML table scraping**, despite
an earlier plan assuming HTML scraping (with a `Accept: application/json` content-negotiation
attempt) would be the primary path — live-verified that the advisory HTML page ignores that header
entirely and has no embedded client-hydration JSON, but **does** link to a genuine OASIS CSAF 2.0
JSON file per advisory. HTML table scraping is kept only as a fallback for the rare advisory where
CSAF is missing/broken (verified the fallback logic itself against real HTML, but could not find a
live pre-CSAF advisory to exercise the fallback's *trigger* end-to-end — every guessed old FG-IR-ID
either had CSAF or 404'd).

Confirmed live, exact mechanics:
1. `GET https://www.fortiguard.com/rss/ir.xml` returns **HTTP 500 with no User-Agent header**, and a
   302 redirect to `https://filestore.fortinet.com/fortiguard/rss/ir.xml` (HTTP 200, real RSS 2.0)
   **with one** — always send a browser-like `User-Agent`. Each `<item>`'s `link` is
   `https://fortiguard.fortinet.com/psirt/FG-IR-YY-NNN` (note: `fortiguard.fortinet.com`, **not**
   `www.fortiguard.com`) — use the RSS `<link>` value directly, don't reconstruct it. RSS items have
   no CVE ID field.
2. Fetch that advisory page → regex out the `csaf_url=` query-param value from an `<a href="/psirt/csaf/{ID}?csaf_url=https://filestore.fortinet.com/fortiguard/psirt/csaf_<slug>_<id>.json">`
   link, then fetch **that** filestore URL directly (confirmed live: hitting
   `fortiguard.fortinet.com/psirt/csaf/{ID}` directly, without the query param, 422s — "Invalid
   Parameters").
3. CSAF shape: `vulnerabilities[]`, one entry **per CVE per affected product** — the same CVE can
   appear twice (once scoped to FortiOS, once to FortiProxy) with different `product_status`/`scores`
   each time (confirmed live on CVE-2026-59840). Filter to FortiOS-scoped entries at BOTH the
   `vulnerabilities[]`-entry level and the per-string level inside `known_affected`/
   `known_not_affected` (an advisory can legitimately bundle a FortiOS-relevant CVE and a
   FortiProxy-only one under the same FG-IR-ID) — this is more precise than a whole-advisory
   FortiOS/FortiProxy filter and is what the code does.
4. `known_affected`/`known_not_affected` string formats, confirmed live, tolerate all three
   (separators are genuinely inconsistent — space, `/`, and `-` all appear):
   - `"FortiOS >=7.6.0|<=7.6.3"` → `{min:"7.6.0", max:"7.6.3"}` (both bounds inclusive)
   - `"FortiOS 7.2 all versions"` / `"FortiOS/ 8.0 all versions"` → `{min:"X.Y.0", max:"X.Y.999"}`
   - `"FortiOS-7.6.4"` (bare version, no range operator, seen in `known_not_affected`) → a single
     fixed version, not a range.
5. **1-second delay required between advisory fetches** (FortiGuard is rate-sensitive per this
   file's own requirement) — a real sequential `for` loop with `await sleep(1000)`, covering the
   HTML-page-fetch + CSAF-fetch pair as one unit, never `Promise.all`/parallel.
6. **`cheerio` was added as a new dependency** (`npm install cheerio`, real command — package.json
   AND package-lock.json both updated) specifically for the HTML-table-scrape fallback path — a
   hand-rolled regex-over-stripped-text scraper was deliberately rejected as too fragile against
   real-world HTML's inconsistent nesting. `fast-xml-parser` (already a dependency) is reused as-is
   for the RSS XML, no new package needed there.

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

### Reliability Rules (learned from LogVault collector)

- Each job runs in `try/catch` — **one failed job must never crash the service**
- Log every job start, end, duration, and error to `C:\Apps\SecVault\logs\engine.log`
- On startup: run an immediate feed sync + CVE match before starting scheduled cycles
- On `SIGTERM`/`SIGINT`: finish current job then exit cleanly (don't kill mid-write)
- Spool pattern for log collector (when built): durable write-to-disk before DB insert, replay on restart

---

## Installer Scripts

### Bundled Dependencies (`installer/dependencies/`)

`Install-SecVault.ps1` follows the same convention as the NocVault suite installer
(`Install-NocVault-Suite.ps1`): it does **not** assume Git, Node.js, PostgreSQL, or NSSM are
already on the target server, and it does **not** download them from the internet either. Instead
it installs each one, silently/unattended, from a local installer file placed in
`installer\dependencies\` next to the script — skipping any tool that's already present. See
`installer/dependencies/README.txt` for the exact files required:

```
installer/dependencies/
  node-v20.19.0-x64.msi            (required)
  postgresql-16.x-windows-x64.exe  (required)
  nssm-2.24.zip                    (required)
  secvault_deploy                  (required -- SSH deploy key, see below)
  Git-2.54.0-64-bit.exe            (used if Git not already present)
  VC_redist.x64.exe                (installed if present; skipped if not)
```

These binaries are **not committed to git** (too large, not source) — the `.gitignore` excludes
everything in that folder except `README.txt`. Copy them from the existing NocVault-Suite-v1.1
distribution package rather than re-downloading; same versions are reused across the whole suite.

**`installer/dependencies/secvault_deploy` (required) is different from the rest** — it's not a
prerequisite installer, it's an ed25519 SSH deploy key (no passphrase, no file extension) for the
private `amrin78-smb/secvault` repo (GitHub → repo → Settings → Deploy keys). `Install-SecVault.ps1`
copies it to `%USERPROFILE%\.ssh\secvault_deploy`, configures an SSH config entry pinning
`github.com` to it (`IdentityFile` set to the copied key's **absolute** path — SSH does not resolve
relative paths in config), pre-seeds `known_hosts` via `ssh-keyscan` (not a hardcoded host key, so a
future GitHub key rotation is picked up automatically), and tests authentication
(`ssh -T git@github.com`, matching `successfully authenticated` in the output — GitHub's own `-T`
handshake always exits non-zero even on success, so the text match is checked, not the exit code)
**before** attempting `git clone`. If the key is missing or doesn't authenticate, the installer
fails clearly rather than letting `git clone` fail with a confusing generic permission error.
`Update-SecVault.ps1` guards on the same key path at startup (before touching any service) and
fails with a clear message pointing back at `Install-SecVault.ps1` if it's missing — the SSH config
and `known_hosts` set up during install are what let its `git pull` work non-interactively.

NSSM is extracted from the bundled zip into `C:\Apps\SecVault\nssm\nssm-2.24\win64\nssm.exe` at
install time — the installer always references this exact path (`$NssmExe`), never assumes `nssm`
is on `PATH`. **Uninstall does not need this path at all** — `Uninstall-SecVault.ps1` removes the
services via `sc.exe delete` (works on any NSSM-registered service, no `nssm.exe` required), matching
the pattern used by the NocVault suite uninstaller.

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

Schema migration runs before services restart — ensures new tables exist before
code that references them starts running. This is the same ordering used across
all NocVault suite apps.

Step 5b reads the postgres superuser password back out of the already-deployed
`.env.local`'s `PG_ADMIN_PASSWORD` (see "Schema Migration" above) and re-runs
`lib/schema-grants.sql` unconditionally — every statement in that file is
idempotent, so this is safe on every update, not just when a table was added.
Wrapped so it can only ever warn, never throw: missing `.env.local`, an empty
`PG_ADMIN_PASSWORD`, or a `psql` failure all log a warning and the update
continues — these roles are diagnostic-only, never required for the app itself.

### NSSM Service Registration

`$NssmExe` below is the bundled copy extracted at install time (`C:\Apps\SecVault\nssm\nssm-2.24\win64\nssm.exe`)
— see "Bundled Dependencies" above. Never assume `nssm` is on `PATH`.

```powershell
# SecVault-App
& $NssmExe install SecVault-App node
& $NssmExe set SecVault-App AppParameters "node_modules\next\dist\bin\next start -p 3010"
& $NssmExe set SecVault-App AppDirectory "C:\Apps\SecVault"
& $NssmExe set SecVault-App AppEnvironmentExtra "NODE_ENV=production"

# SecVault-Engine
& $NssmExe install SecVault-Engine node
& $NssmExe set SecVault-Engine AppParameters "services\engine-worker.js"
& $NssmExe set SecVault-Engine AppDirectory "C:\Apps\SecVault"
& $NssmExe set SecVault-Engine AppEnvironmentExtra "NODE_ENV=production"
```

**⚠️ NSSM casing bug (from suite experience):** `AppEnvironmentExtra` path casing must match the actual filesystem case. Wrong casing causes duplicate React instances and silent rendering failures. Double-check paths.

**⚠️ Never point AppParameters at `node_modules\.bin\next`.** That file is npm's generated POSIX shell-script wrapper (`basedir=$(dirname ...)` — actual bash, not JavaScript). `node` tries to parse it as JS and crashes immediately with a `SyntaxError` on every start attempt; NSSM marks the service `Paused` after enough rapid failures, and `sc.exe start` still reports success (it only confirms the SCM accepted the start request, not that the process stayed up) — the install can complete and print success while the app never actually comes up. Use `node_modules\next\dist\bin\next` instead — the real Next.js CLI entry point, an actual JS file with a `#!/usr/bin/env node` shebang, safe to run directly with `node`.

---

## In-App Updater (v2.1.0)

Copied from the NocVault suite's proven pattern (netvault is the closest architectural match —
one Next.js App Router process, one port — so its implementation was the literal template;
logvault/ddivault/spanvault run a split frontend+Express-API shape SecVault does not have). This
**supersedes** the old aspirational "compare git hash to GitHub API" line that used to live under
Versioning Policy below — that was never implemented, and the suite's own history (see the
sibling repos' `releaseNotes`) shows the GitHub REST API approach was tried and abandoned
suite-wide after `raw.githubusercontent.com`/`api.github.com` rate-limited and timed out under a
shared corporate egress IP. The real mechanism uses git's own transport instead.

### Detection — live, no DB caching

`lib/updateCheck.js` (CommonJS, shared by both routes below):
- `findGitRoot(startDir)` walks up from `process.cwd()` looking for `.git` (repo root).
- `localCommitHash(repoRoot)` — `git rev-parse HEAD`, 7-char short SHA, `null` on failure.
- `remoteCommitHash(repoRoot)` — `git ls-remote origin main` (NOT the GitHub REST API), 7-char
  short SHA, `null` on failure.
- `remoteVersion(repoRoot)` — `git fetch --quiet origin main` then `git show
  FETCH_HEAD:package.json`, parsed for `.version`; only called once a commit diff is already
  known (avoids paying a network fetch on the common up-to-date path).
- `update_available` = local and remote hashes both resolved AND differ — **independent of
  `package.json` version**, so a patch pushed without a semver bump still surfaces as available.

Two routes consume this:
- `GET /api/system/update-status` — full live check on every call, auth-gated (via
  `middleware.js`'s blanket `/api/*` gate — no extra role check, since SecVault has no
  admin/viewer role split anywhere in this app; see Authentication above). Returns
  `{current_version, latest_version, current_commit, latest_commit, up_to_date,
  update_available, release_notes, release_date, error?}`. Any git/network failure degrades to
  `{up_to_date:true, update_available:false, error:'Could not check for updates'}` — **never**
  a 500, never a false "available". `release_notes` is a hand-maintained object in the route
  file keyed by version string (3-5 bullets), `'default'` fallback
  `['Bug fixes and performance improvements']` — **update it alongside every version bump**,
  same convention as the NocVault suite (no separate CHANGELOG.md).
- `GET /api/system/update-available` — lightweight, polled by the banner every 6h. Backed by a
  module-level cache refreshed on process start + every 24h (`setInterval`) — safe because
  `next start` is one long-lived Node process, not serverless. Same auth gate as above.

`GET /api/health` — trivial `{status:'ok'}`, no DB dependency, used only by the post-update
liveness poll (see below). Same auth gate as everything else — no exemption added.

### Trigger — one-time SYSTEM scheduled task, not a spawned child process

`POST /api/system/update`: `getServerSession` → 401 if none (the only gate — matches every other
write route in this app, since there's no role concept to check further); 400 if `SERVER_IP` is
unset. Then, same as the suite:
```powershell
schtasks /delete /tn "SecVaultUpdate" /f          # best-effort, swallow "not found"
schtasks /create /tn "SecVaultUpdate" /tr "powershell.exe -NonInteractive -ExecutionPolicy Bypass -File \"<repoRoot>\installer\Update-SecVault.ps1\"" /sc once /st 00:00 /f /ru SYSTEM
schtasks /run /tn "SecVaultUpdate"
```
Returns `{started:true}` immediately (fire-and-forget — the HTTP response can't stay open while
the very service serving it restarts). **Why a scheduled task and not `child_process.spawn`**:
the API runs as a limited service account; a spawned child dies when the parent service stops,
and the service account may lack rights to start/stop Windows services anyway. A Task Scheduler
job running as `SYSTEM` is fully detached from this process tree and has the permissions +
lifetime to finish. Unlike netvault's version, SecVault's trigger does **not** pass `-ServerIp` —
`Update-SecVault.ps1` already reads everything it needs from the deployed `.env.local` and its
own hardcoded `$InstallRoot`.

`installer/Update-SecVault.ps1`'s existing 8-step order (see "Update Script — Exact Order" above)
is unchanged. Two additions, both non-fatal, made specifically because this script can now be
launched by SYSTEM (which has never run git in this checkout before):
- `git config --global --add safe.directory $repoRoot` — Git ≥2.35.2 refuses to operate in a repo
  it doesn't consider "owned" by the current account otherwise.
- `Start-Transcript`/`Stop-Transcript` to a separate timestamped file per run
  (`update-yyyyMMdd-HHmmss.log` under `C:\Apps\SecVault\logs\`) — a fire-and-forget SYSTEM task
  leaves no other durable record, so this is in addition to (not instead of) the existing
  `Write-Log`/`update.log` mechanism.

### UI — banner + Settings panel, no separate tab system

- `components/layout/UpdateNotifier.js` — dismissible top banner, mounted in
  `app/(dashboard)/layout.js` only (never on `/login`). Polls `/api/system/update-available`
  every 6h; dismissal is `sessionStorage`-keyed on the specific `latest` version so a newer patch
  re-shows the banner even if an older one was dismissed this session.
- Settings page (`app/(dashboard)/settings/page.js`) has no tab system (unlike the suite apps'
  `?tab=updates`) — it's a flat list of `Card`s, so the update UI is just a third Card,
  "Software Update", rendering `components/settings/UpdatePanel.js`. Fetches
  `/api/system/update-status` on open + a manual "Check for Updates" button; shows current
  version/commit when up to date, or version/commit/release-notes + an "Update Now" button that
  opens a confirm dialog (reuses `components/ui/Modal.js` — do not hand-roll a second modal
  primitive) when an update exists.
- Confirming opens a full-screen, non-dismissible progress overlay that polls `GET /api/health`
  every 2s. State machine (`starting → down → back_up`, or `timeout` after 10 minutes): a probe
  **must** be observed failing at least once before any later success counts as "recovered" (else
  the overlay could declare victory against the still-running pre-restart process), then **3
  consecutive** healthy probes are required before flipping to `back_up`. On `back_up`, it
  re-fetches `/api/system/update-status` and compares `current_commit` against the value captured
  before the update was triggered — if unchanged, shows `verify_failed` instead of a false
  success. Only then: a 15s visible countdown (lets the freshly-restarted Next.js process settle),
  then `window.location.href = '/?updated=true'` — a full navigation, which also naturally
  re-validates the session.

### What was deliberately NOT copied from the suite

- **No license-gating** on the trigger route — SecVault has no license system at all (unlike
  every suite app, which blocks the trigger on `disabled`/`grace`/`expired` license states).
- **No separate unauthenticated allowlist path** — the suite apps exempt `update-available` from
  their license gate so the banner still works when the app itself is disabled. SecVault has
  nothing to exempt it from, so it stays behind the same blanket `/api/*` auth as every other
  route; no change to `middleware.js` was needed or made.
- **SpanVault's missing role-check on the trigger route was a real gap found during suite
  research and is explicitly not replicated** — every write path in SecVault (including this one)
  requires a valid session at minimum.

### ⛔ The in-app updater's git pull silently never worked at all — root-caused and fixed 2026-07-21

Direct user report: "Update Now" detected an update, ran, reported success (services genuinely
restarted), but the version never actually changed. Root-caused in two stages — the first stage's
fix was real but incomplete, and briefly made a live run fail *worse* before the second, complete
fix landed the same day.

**Stage 1.** `core.sshCommand="ssh -i <deploy key> ..."` uses bare `ssh`, which is PATH-resolved —
an interactive admin's `PATH` resolves it to Windows' own OpenSSH client
(`C:\Windows\System32\OpenSSH\ssh.exe`), while the SYSTEM-scheduled task's `PATH` instead resolves
it to **Git's own bundled MSYS2 `ssh.exe`** — a different build with different default-identity
behavior. Fixed by pinning the full path to Win32-OpenSSH in both `installer/Update-SecVault.ps1`
and `lib/updateCheck.js`, instead of trusting bare `ssh` resolution.

**Stage 2 — the actual complete root cause, found the same day after Stage 1's fix caused a live
run to fail with `command not found`.** `core.sshCommand`'s value is **always interpreted by
git's own bundled MSYS2 shell** before the named ssh binary ever runs, regardless of which binary
that is or which account invokes `git`. That shell treats backslash as an escape character in an
unquoted word — so a native Windows path (`C:\ProgramData\SecVault\ssh\secvault_deploy`, or even
Stage 1's own pinned `C:\Windows\System32\OpenSSH\ssh.exe` binary path) silently loses every
backslash before ssh ever sees it. **This explains the "Identity file ... not accessible" warning
that had appeared on every single run throughout this entire multi-day debugging history,
including runs that went on to succeed** — an interactive admin's own `~/.ssh/config` (read
directly by ssh via a real file API, never touched by this shell layer at all) quietly carried
those connections instead of the mangled `-i` key; `SYSTEM` has no such config and had nothing to
fall back to, hence total failure specifically (and only) on the real in-app-triggered path.

Fix: stop using backslashes inside this one command string, full stop — convert every path to
forward slashes (`-replace '\\','/'` in PowerShell, `.replace(/\\/g,'/')` in JS) immediately before
building `$sshCommand`/`sshCommand`. Forward slashes are not a shell metacharacter and both Windows
OpenSSH and git's bundled ssh accept them natively on Windows — this sidesteps the escaping problem
entirely rather than trying to quote backslashes correctly across the three parsing layers already
in play (PowerShell/JS string interpolation → git config-value parsing → git's own internal shell
re-invocation of ssh) — the exact fragility this file's own long-standing comment on this code had
already flagged as a reason to avoid nested quoting, without yet knowing backslashes themselves
were the live problem.

**Lesson for any future fix to this specific mechanism:** an *interactive* verification (e.g.
running `ssh -v -i <key> ...` directly by hand in a terminal) does **not** exercise the actual
failure surface — it bypasses `core.sshCommand`'s shell-interpretation layer entirely, since
PowerShell passes arguments directly to the process with no shell involved. That gap is exactly
what made Stage 1's fix look fully confirmed when it wasn't. Any future change to this ssh command
construction needs to be verified either by triggering the real scheduled task (`schtasks /run /tn
SecVaultUpdate`) or by re-deriving the exact string that will reach git's `-c
core.sshCommand=...`, not by testing the named binary directly.

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
VPN_POLL_INTERVAL_MINUTES=30               # 5-59 — see "VPN Summary + Session Polling" below

# Log retention
LOG_RETENTION_HOT_DAYS=90
LOG_RETENTION_WARM_DAYS=365

# Suite integration (optional — leave blank for standalone)
NETVAULT_URL=
```

---

## Design System — NocVault Suite Alignment (v2.0.0)

**Major architectural reversal from v1.x.** SecVault's UI was rebuilt to match the shared NocVault
suite design system used identically by NetVault, LogVault, DDIVault, and SpanVault — verified by
reading each sibling's own live `app/globals.css` directly, not assumed. All four are byte-for-byte
identical on tokens; SecVault ports that same file with one addition (`--accent-teal`, see below).

### No Tailwind

Tailwind (`tailwindcss`/`postcss`/`autoprefixer`) has been **fully removed** — not re-themed, removed.
Every sibling app styles with plain CSS custom properties (`app/globals.css`) plus inline
`style={{}}` objects and a shared hand-written utility-class set (`.card`, `.kpi-card`, `.badge*`,
`.btn*`, `.input`/`.select`, `.data-table`, `.skeleton`, `.modal-overlay`, `.page-header`, etc. — all
defined in `app/globals.css`, read that file directly for the full class vocabulary before writing
any new UI). Do not reintroduce Tailwind or any other CSS framework — match this exact pattern for
all new UI work.

### Dual theme — light default, dark toggle

**Reverses the old "dark-only" decision.** Light is now the default; dark is an opt-in toggle,
matching every sibling app. Mechanism (`lib/theme.js`, `components/layout/ThemeToggle.js`):
- Theme stored in `localStorage['secvault-theme']`, applied as a `data-theme="dark"` attribute on
  `<html>` (NOT a `.dark` class, NOT `prefers-color-scheme` alone).
- A blocking inline `<script>` in `app/layout.js`'s `<head>` (`THEME_INIT_SCRIPT` from `lib/theme.js`)
  applies the saved theme before first paint — avoids a flash of the wrong theme.
- A `window` custom event (`secvault:theme`) keeps every mounted `ThemeToggle` instance in sync.
- Light tokens live under `:root` in `app/globals.css`; dark overrides live under
  `[data-theme="dark"]`. **Brand colors (`--primary`, `--navy*`, `--accent-teal`) and status colors
  (`--green`/`--yellow`/`--red`/`--blue`/`--orange`/`--purple`/`--teal`) intentionally stay the same
  in both themes** — only neutral surfaces/text/borders/shadows and the adaptive `--tint-*`/
  `--tint-*-fg` pairs flip. Any new UI that needs a tinted surface behind text (a status banner, a
  badge) MUST use a `--tint-*`/`--tint-*-fg` pair, never a hardcoded hex, or it won't adapt in dark
  mode (a real gap — `.badge-orange` was hardcoded, found and fixed during the migration).

### Tokens (`app/globals.css` — full file is authoritative, this is a summary)

```css
:root {
  color-scheme: light;
  --primary:        #C8102E;   /* shared suite red — buttons, focus rings, badges, links */
  --primary-dark:   #a00d24;
  --navy:           #1a2744;   /* header + sidebar background */
  --bg-primary:     #f4f6f9;   /* page background */
  --bg-card:        #ffffff;   /* cards, panels, modals */
  --border:         #e2e8f0;
  --text-primary:   #0f172a;
  --text-secondary: #334155;
  --text-muted:     #64748b;
  --radius:         8px;
  --radius-sm:      6px;

  --green: #16a34a; --yellow: #d97706; --red: #dc2626; --blue: #2563eb;
  --orange: #ea580c; --purple: #7c3aed; --teal: #0891b2;

  /* SecVault's own identity — unclaimed by any sibling (NetVault=red,
     LogVault=blue, DDIVault=amber, SpanVault=green). Logo wordmark +
     active sidebar-nav-chip color ONLY — every interactive control
     (buttons, focus rings, links, badges) still uses the shared --primary
     red above, exactly like every sibling app does for its own accent. */
  --accent-teal:    #0891b2;

  --text-xs: 11px; --text-sm: 12px; --text-base: 13px; --text-md: 14px;
  --text-lg: 16px; --text-xl: 20px; --text-2xl: 28px;
  --font-mono: 'JetBrains Mono', 'Fira Code', 'Consolas', 'Courier New', monospace;

  /* Adaptive tint pairs — use these for any tinted surface behind text */
  --tint-info: #eff6ff;    --tint-info-fg: #1d4ed8;
  --tint-success: #f0fdf4; --tint-success-fg: #15803d;
  --tint-warn: #fffbeb;    --tint-warn-fg: #b45309;
  --tint-danger: #fef2f2;  --tint-danger-fg: #b91c1c;
}
[data-theme="dark"] {
  --bg-primary: #0d1220; --bg-card: #1a2235; --border: #2d3a52;
  --text-primary: #f1f5f9; --text-secondary: #cbd5e1; --text-muted: #94a3b8;
  /* --primary/--navy/--accent-teal/status colors unchanged; --tint-* pairs
     get dark-appropriate rgba() + light-foreground overrides — see the file. */
}
```

Font: Google Fonts Inter (loaded via `@import` in `app/globals.css`, matching every sibling — not
`next/font`). Monospace: JetBrains Mono stack, applied via the `.mono` class.

### Icons — hand-rolled, no dependency

`components/icons.js` — every icon (nav, bell, search, sun/moon, chevrons, etc.) is a small inline
SVG using the suite-wide Feather-compatible convention: `viewBox="0 0 24 24" fill="none"
stroke="currentColor" strokeWidth={2}` round caps/joins. Never add an icon library — hand-roll new
icons matching this exact convention (see the `base()` helper in `components/icons.js`).

### Header / Sidebar structure

- `components/layout/Header.js` — a **server component** (queries `feed_sync_log` directly via
  `lib/feedStatus.js`'s `getSyncPillStatus()` for the sync-status pill — no client round-trip for
  that value). 72px navy bar: hand-drawn logo SVG + "Sec"(white)/"Vault"(teal) wordmark, a divider,
  an uppercase subtitle ("FIREWALL SECURITY PLATFORM"), a centered `HeaderSearch` (client, debounced,
  "/" shortcut, hits `GET /api/search`), then a sync-status pill, `NotificationBell` (client, polls
  `GET /api/notifications/summary` every 60s — a REAL three-way aggregate: `finding_acknowledgements`
  status='new' + `device_cve_assessments` priority_band='patch_now' + unacknowledged `config_diffs`,
  not cosmetic), `ThemeToggle`, and `UserMenu` (avatar + name/role + dropdown, reuses the `session`
  already resolved server-side by `app/(dashboard)/layout.js` — never re-fetches session client-side).
- `components/layout/Sidebar.js` — 240px navy (64px collapsed), a "NAVIGATION" eyebrow label,
  per-route colored icon chips (neutral gray when inactive, a distinct accent color only when
  active — see the `NAV` array for the exact per-route hue), a 3px rounded accent bar (`--primary`)
  on the active item, a bottom collapse toggle persisted to
  `localStorage['secvault-sidebar-collapsed']`, and a version footer reading `package.json`'s
  version (passed down server-side from `app/(dashboard)/layout.js` — `import pkg from
  '../../package.json'` — no API call needed for this one value).

### Shared UI components (`components/ui/`)

`Badge`/`Button`/`Card` (+`CardHeader`/`CardTitle`/`CardBody`)/`Table`/`Modal`/`StatusDot`/
`EmptyState`/`LoadingSpinner` all rebuilt on the plain suite CSS classes — same props/call sites as
before the migration, no page changes needed if you're just using them normally. Two components
added specifically for this migration: `StatCard` (the `.kpi-card` colored-left-border tile — the
standard stat-grid unit on every dashboard/summary page) and `PageHeader` (`.page-header`/
`.page-title`/`.page-subtitle` + an optional `actions` slot — replaces ad hoc `<h1>`/`<p>` pairs).
`Table` still enforces `tableLayout:'fixed'` internally — the CLAUDE.md rule below is unchanged,
just now satisfied inside a component instead of a raw Tailwind class.

**Compact density variants (added 2026-07-19, for the main Dashboard only).** Direct user feedback
on the Dashboard Rebuild: the widget grid was too tall, needing too much scrolling, with only 2
widgets fitting per row regardless of screen width. `StatCard` takes an opt-in `compact` prop
(default `false` — every existing page's `StatCard` usage is pixel-identical, unaffected) that swaps
in `.kpi-card-compact`/`.stat-value-compact`/`.stat-label-compact`/`.stat-sub-compact`
(`app/globals.css`, additive-only, no existing class touched). For `Card`'s header/body, there is no
component-level `compact` prop — callers needing compact chrome use the raw `.card-header-compact`/
`.card-title-compact`/`.card-body-compact` classes directly instead of the `CardHeader`/`CardTitle`/
`CardBody` sub-components (those sub-components hardcode the base `card-header`/`card-body` classes
internally, and layering a second class on top would depend on fragile CSS-cascade ordering between
the two rules rather than a clean override). A third scoped class, `.dashboard-compact-table`
(applied via `Table`'s existing `className` prop), tightens `th`/`td` padding for the Dashboard's
`RecentActivityFeed`/`TopRiskyDevices` tables without touching the global `table th`/`table td` rule
every other table in the app relies on. `app/(dashboard)/page.js`'s widget layout also changed from
several hardcoded two-column row pairs to one shared `repeat(auto-fill, minmax(300px, 1fr))` grid —
the browser now packs 2/3/4 widgets per row depending on actual viewport width instead of a fixed
2-up pairing that wasted space on a wide screen.

Priority band visual encoding (unchanged mapping, new token names):
- `patch_now` → `var(--red)` / `<Badge color="danger">`, label "Patch Now"
- `scheduled`  → `var(--yellow)` / `<Badge color="warning">`, label "Scheduled"
- `monitor`    → `var(--text-muted)` / `<Badge color="muted">`, label "Monitor"
- KEV badge → solid `var(--red)` background, white text, "KEV" label — deliberately NOT a tinted
  `<Badge>`, a hand-rolled solid-fill span, to stay visually distinct from the softer tinted badges.

---

## Versioning Policy

- Version tracked in `package.json`
- **Bump patch** on any push that touches UI or logic
- **Bump minor** on new feature or phase completion
- **Bump major** on breaking schema changes or major architectural shifts
- Update detection + in-app updater: see "In-App Updater" section above — implemented (v2.1.0)
  using git's own transport (`git ls-remote`/`git fetch`), **not** the GitHub REST API (an earlier
  version of this line described the REST-API approach; it was never built, and the NocVault
  suite's own history shows that approach was tried and abandoned suite-wide after
  `raw.githubusercontent.com`/`api.github.com` rate-limited under a shared corporate egress IP —
  see the In-App Updater section for the real mechanism). When bumping the version, also add 3-5
  bullets for it to the `releaseNotes` object in `app/api/system/update-status/route.js` — no
  separate CHANGELOG.md, same convention as the rest of the suite.

---

## Adapted Patterns From NocVault Suite

These patterns proved themselves in the suite apps and are directly inherited:

### From DDIVault
- credStore.js AES-256-GCM pattern (adapted: separate columns for encrypted_data + iv, own CREDENTIAL_KEY env var)
- PowerShell PS5 compatibility rules (sc.exe, $out variable before pipe)
- Three-service NSSM architecture (API/App/Collector equivalent)
- `pg` pool singleton passed as parameter to all functions

### From SpanVault
- Pre-commit validation: `node --check` + `npm run build` before every commit
- Schema migration runs before service restart in update script
- Live API response verification before writing any parser
- Parallel sub-agent strategy: frozen contracts per file, verify diffs before integrating
- Per-table `GRANT SELECT` for readonly users (never blanket grant)
- The `pool` parameter rule — never omit it from functions that need credentials/DB

### From LogVault
- Engine worker job isolation: one job failure must never crash the service process
- Durable spool pattern for collector (write to disk first, DB second, replay on restart)
- Log rotation: `winston` with daily rotation, keep last N files
- Retention policy: hot/warm/archive tiers for log storage
- Enrichment pipeline pattern: collect raw → enrich async → store enriched

### From NetVault
- UUID primary keys (not SERIAL)
- `CREATE TABLE IF NOT EXISTS` in every schema.sql statement
- Separate install/update/uninstall scripts under `installer/`
- `.env.local.example` committed, `.env.local` gitignored
- `NODE_ENV=production` in NSSM AppEnvironmentExtra

---

## Known Issues & Gotchas

### ⚠️ UI vendor-scoping gap (found 2026-07-16) — backend generic ≠ UI generic

The backend CVE pipeline (`lib/feeds/nvd.js`'s `VENDOR_CPES` loop, `lib/engines/versionMatcher.js`'s
`runMatchForAllDevices`, `prioritization.js`, `applicability.js`) has been vendor-generic across all
6 Tier 1 vendors from the start — verified by a full sweep, not assumed. The gap was entirely in the
UI layer, in two places, both now fixed:
- `app/(dashboard)/advisories/page.js` and `app/(dashboard)/cve/page.js`'s vendor-filter `<select>`
  dropdowns only listed `<option value="forcepoint">Forcepoint</option>` — the underlying
  `vendor = $N` SQL filter already worked for any of the 6 slugs, the dropdown just never offered
  them as choices. A user filtering by vendor would see nothing wrong technically, just a dropdown
  that silently couldn't select 5 of the 6 vendors it already had data for.
- `app/(dashboard)/devices/page.js` (the fleet devices list) queried and displayed only `smc_host`,
  never `mgmt_ip` — every non-Forcepoint device row rendered `—` in that column even though the
  address was sitting right there in `mgmt_ip`. The sibling per-device page
  (`devices/[id]/page.js`) already had the correct pattern
  (`device.vendor === 'forcepoint' ? device.smc_host : device.mgmt_ip`) — it just was never applied
  to the list page too.

**Lesson for future vendor-facing UI:** a backend loop over all vendors does not guarantee the UI
surfaces all vendors — check every `<select>`/filter/column that touches `devices.vendor` or
`advisories.vendor` against the full 6-slug list (`forcepoint`, `fortinet`, `paloalto`,
`checkpoint`, `cisco_asa`, `sangfor`), not just against "does the query work."

### ⚠️ Bug-sweep fixes (2026-07-17) — a follow-up audit, all confirmed and fixed

A second full-app bug sweep (independent finders per subsystem, then adversarially re-verified
against the actual code before anything was reported as real) found and fixed the following. Two
reported items were investigated and found NOT to be real bugs — noted at the end so they aren't
re-investigated.

**Security (secrets):**
- `lib/adapters/sangfor/parser.js`'s `getRules()` built `raw_rule.text` from the UNREDACTED cached
  config text (the caching itself is correct — field extraction needs real tokens — but the STORED
  `raw_rule` didn't go through `redactConfig()` the way `getConfig()`'s output already did).
  `firewall_rules` is whole-table `GRANT SELECT`'d to `claude_readonly`/`nocvault_readonly`, so a
  rule block that happened to also contain a secret-bearing line (plausible on Sangfor's
  undocumented, varying firmware dialects) could persist a secret in the clear. Fixed: `redactConfig()`
  is now applied to `blockText` at the point `raw_rule` is constructed — field extraction still reads
  the original unredacted lines, only the stored copy is redacted.
- `lib/adapters/fortinet/cliParser.js`: `redactConfig()`'s multi-line-quote tracking (`inMultilineSecret`)
  only activated for KEY-recognized-as-secret values. A non-secret multi-line value (a `replacemsg`
  body, banner, description field) whose body happened to contain a line that trimmed to exactly `end`
  could desync `blockPath`, causing a LATER genuinely-secret line (e.g. an SNMP community) to be
  misjudged as outside its secret context and left unredacted. Fixed: multi-line-quote suspension is
  now generic (tracked for ANY `set key "..."` value via unescaped-quote counting), not gated on the
  key being secret-shaped — reproduced the exact leak against the pre-fix code, confirmed fixed.
- `lib/adapters/sshClient.js`: `enablePassword` is written verbatim to an interactive privileged shell
  (unlike the login password, which is authenticated at the SSH protocol level, never as shell text).
  An embedded `\r`/`\n` in a malformed/corrupted stored credential would inject extra commands into a
  root shell. Now refused with a clear error before being sent, rather than silently written.
- `lib/adapters/cisco_asa/parser.js`: `redactConfig()` was missing the single-line
  `radius-common-pw <secret>` AAA form (the multi-line `key <secret>` sub-mode form was already
  covered). Added.

**Silent data loss:**
- `lib/adapters/paloalto/sshParser.js`: `parseBraceBlock`'s root-level call had no way to distinguish
  "a real nested block's closing `}`" from "a stray/unmatched `}` anywhere in a truncated or corrupted
  SSH dump" — the latter silently ended parsing right there, discarding everything after it, including
  a rulebase that might appear later. Fixed via an `isRoot` flag: a stray `}` at the root is now
  skipped like any other unrecognized token (matching this function's existing "skip and keep going"
  philosophy for nested content), while a real block's `}` still terminates it correctly. Chained fix
  in `lib/adapters/paloalto/ssh.js`: `getRules()` previously could not distinguish "no rulebase
  container found anywhere in the tree" (a structural failure that must THROW, per this file's own
  rule) from "a container was found and is genuinely empty" (`parseSecurityRules` now returns
  `{ rules, containersFound }` so `getRules()` can tell them apart) — closes the path where the brace
  truncation above would previously warn-and-return-`[]`, letting `collectAndStore` silently wipe a
  device's real ruleset.
- `lib/adapters/fortinet/ssh.js`: multi-VDOM collection captured and validated the
  `show firewall policy` output per VDOM, but discarded the preceding `edit <vdom>` command's own
  output entirely — a failed `edit` (renamed/deleted VDOM, VDOM-scoped admin, transient CLI rejection)
  would leave the shell in the wrong VDOM's context with no error, storing that VDOM's real policies
  under the WRONG VDOM's label. Fixed: `edit <vdom>`'s own output is now captured and checked for a
  known FortiOS failure string (`CLI_ERROR_REGEX`, extended with `entry not found`) before its paired
  policy output is trusted; throws (no try/catch, matching this file's existing fail-loud posture for
  the equivalent REST-transport risk) if the switch can't be confirmed.

**Correctness / concurrency:**
- `lib/engines/versionMatcher.js`: `runMatchForAllDevices()` has three independent call sites that can
  run concurrently for the same device (the "Assess Now" button, the scheduled feed-sync-and-match
  job, and the config-change-triggered re-match) with no locking — an overlapping run computed from
  stale data could DELETE+INSERT after a newer, correct run already removed a since-patched CVE's row,
  resurrecting a stale `patch_now` assessment. Fixed: the DELETE+INSERT+prioritization write phase for
  each device now runs inside its own transaction holding
  `pg_advisory_xact_lock(hashtext(device_id))` — auto-released at COMMIT/ROLLBACK, so a crash can't
  leave it held. The read phase above stays unlocked (cheap; staleness there just means slightly older
  source data, not a correctness bug).
- `lib/feeds/kev.js` had no fetch timeout at all — the exact node-fetch@2-hangs-forever bug fixed the
  same day in `nvd.js`'s CIRCL-fallback work, just missed in this sibling file. Since `runFullSync`
  awaits NVD then KEV sequentially, a blocked KEV request could stall the entire feed-sync cycle
  indefinitely. Now uses the same `FETCH_TIMEOUT_MS` as `nvd.js`. No CIRCL-style fallback added —
  CISA KEV has no equivalent alternate source; failing cleanly on timeout is sufficient.
- `lib/feeds/nvd.js`: three refinements to the CIRCL fallback logic. (1) A malformed-JSON response on
  an HTTP 200 (corrupted/truncated body) was satisfying the same `err.status == null` check used to
  detect "NVD unreachable," misclassifying a reachable-but-corrupted response as a network outage —
  now tagged separately (`err.nvdJsonParseError`) and excluded from the CIRCL trigger. (2) A genuine
  timeout/DNS/connection-refused error fell to CIRCL on the very first failure with zero NVD retries,
  asymmetric with the 429 branch's one-retry-then-backoff; added a single short-delay retry against
  NVD first. (3) When a vendor's multiple CPE strings (forcepoint, checkpoint, cisco_asa) mix NVD- and
  CIRCL-sourced results for the same `cve_id` within one sync run, a later CIRCL record could silently
  overwrite an earlier, more precise NVD record; the merge now tags each entry's source and refuses to
  let CIRCL clobber an existing NVD entry.
- `lib/activityLog.js`'s `logActivity()` claims to "NEVER throw," but destructured its second
  parameter with a default that only applies to `undefined`, not `null` — `logActivity(pool, null)`
  would throw before the try block. No current call site does this, but the contract is unconditional.
  Fixed by destructuring from `entry || {}` inside the function body instead.
- `lib/adapters/checkpoint/index.js`: `getVersion()` already threw when no gateway object could be
  found at all (not the documented "first gateway" fallback case, which remains open and unchanged —
  see "Known Limitations" above — but the case where there's no fallback candidate either). `getConfig()`
  had no equivalent check and silently persisted a near-empty config as a successful collection. Now
  throws the same way, naming candidate gateway objects found on the server (via the same
  `describeGatewayCandidates()` helper `_resolvePolicyPackage()` already uses).
- `services/engine-worker.js`: the SIGTERM/SIGINT shutdown hard ceiling (30s) was sized for the
  original single lightweight SMC adapter. The Tier-1 SSH adapters now legitimately run a single
  config pull up to 120s, and devices collect sequentially in one job — a stop landing mid-pull was
  hard-killed well before that pull could finish, silently truncating the run for every device still
  queued behind it. (Not a data-corruption risk — `collectAndStore`'s rule rewrite is already
  transaction-safe — just a "finish current job then exit" contract violation.) Raised to 150s.
- Malformed UUID path params (`/api/devices/foo`) across the `devices/[id]` route family threw a raw
  Postgres type-cast error caught only by each route's generic 500 handler, leaking an internal error
  message for what should be a clean 400. New `lib/apiUtils.js` exports `isValidUuid()`; applied as an
  early guard in `devices/[id]/route.js`, `devices/[id]/acknowledgements/route.js`,
  `devices/[id]/analysis/route.js`, and `devices/[id]/diffs/[diffId]/route.js`.
- `components/analysis/AcknowledgeControl.js` seeded its local `status` from the `currentStatus` prop
  only on mount, with no resync when the prop changed on a later render for a reason other than this
  control's own save (e.g. a `router.refresh()` from editing a different row). Added a
  `useEffect` resyncing on `currentStatus` change, deliberately skipped while a save is in flight (see
  the component's own comment — resyncing during `saving` would stomp the just-applied optimistic
  value with the still-stale prop before the refresh lands, causing a visible flicker).

**Installer (PS5, `installer/*.ps1`):**
- `Install-SecVault.ps1`'s superuser-password-reset retry loop checked `$LASTEXITCODE -eq 0`, the only
  `psql` call site in either script that didn't also accept `-1` as success per the documented WinRM
  stderr quirk — could hard-fail an install that actually succeeded. Fixed to match every other call
  site's `-eq 0 -or -eq -1` pattern.
- Both scripts' docstrings claimed "Never uses ... Get-Service," while the bodies use it for read-only
  `.Status` polling (deliberate — CLAUDE.md's actual rule is about the state-changing cmdlets, which
  can hang a WinRM session; read-only polling is a different, already-tested operation). Docstrings
  corrected to state the real, narrower rule; no executable code changed — the Get-Service polling
  itself was already correct and stays.
- A `Fail` message echoed the generated superuser password in plaintext, which would persist to disk
  under output redirection/transcription. Removed the literal password from the message.

**Investigated, found NOT to be bugs (do not re-investigate without new evidence):**
- Fortinet REST's `_discoverVdoms()` catching an enumeration failure and falling back to the implicit
  single-VDOM request is a deliberate, correctly-reasoned tradeoff (older firmware / VDOM-scoped admin
  tokens routinely can't enumerate VDOMs; hard-failing every such box would break far more devices than
  it protects) — not the "any error → silent partial ruleset" bug an initial pass described. The
  explicit multi-VDOM loop (once VDOMs ARE known) has no try/catch on purpose and correctly throws
  whole on any single VDOM's failure.

### ⚠️ Bug-sweep fixes (2026-07-19) — third-pass audit, all confirmed and fixed

A third full-app bug sweep (independent finders per subsystem, then the highest-severity findings
personally re-verified against the actual code before any fix was written) found and fixed the
following. Primary-agent fixes plus 6 fanned single-file agent fixes, each verified against the
real diff before integrating (per this file's own "Verify agent diffs before integrating" rule).

**CVE engine correctness (`lib/feeds/nvd.js`, mirrored in `paloalto.js`/`fortinet.js`):**
- `extractAffectedRanges()` (NVD API 2.0 path): an NVD `cpeMatch` entry can be `vulnerable: true`
  with NONE of `versionStartIncluding`/`versionEndIncluding`/`versionEndExcluding` set — NVD's shape
  for "this one exact CPE version is affected," no range needed. The old code fell through to
  `{min: null, max: null}`, and `isInRange()` treats a null bound as "no constraint on that side" (by
  design, for genuinely unbounded ranges) — so an exact-version CVE silently matched EVERY version of
  that vendor's product, forever, flipping every device to `patch_now`/`scheduled` for a CVE that may
  only affect one specific old build. Fixed: falls back to `extractVersionFromCriteria(match.criteria)`
  (the same helper `extractFixedVersions` already used correctly) to pull the pinned version and use
  it as both `min` and `max`; if neither a range field nor a usable pinned version exists, the entry
  is skipped rather than emitting an unbounded range from nothing.
- `extractAffectedRangesFromCveRecord()` (CVE Record Format 5.x path — CIRCL fallback in nvd.js,
  native in paloalto.js/fortinet.js): checkpoint collection (`allCheckpointsFromChanges(v.changes)`,
  feeding `safe_exact_versions` for `versionComparator.js`'s `isSafeOnMatchingTrain`) was only reached
  inside the branch where NEITHER `v.lessThan` NOR `v.lessThanOrEqual` was present. A real entry can
  have a top-level bound AND a `changes[]` timeline of per-hotfix-train fix points at the same time —
  every checkpoint was silently dropped in that shape. Fixed: checkpoints are now collected
  unconditionally whenever `changes[]` is present, independent of which branch sets `max`/
  `excludeFixed`. Same fix applied identically in `paloalto.js` and `fortinet.js` (verified present
  and fixed in both, not assumed).
- `upsertAdvisory()` in all three feed files: every column except `title`/`affected_version_ranges`/
  `fixed_in_versions` (already vendor-ownership-guarded) was unconditionally overwritten with
  `EXCLUDED.*` on a `cve_id` conflict — `description`/`cvss_score`/`cvss_vector`/`published_at`/
  `advisory_url`/`raw_data`. A genuine cross-vendor `cve_id` collision (a shared-library CVE, or a
  different feed's own take on the "same" CVE) could silently overwrite the owning vendor's CVSS
  score and description with an unrelated source's data purely due to sync order, while leaving that
  row's title/ranges untouched — a corrupted hybrid record with mismatched severity and version data.
  **This reverses previously-intentional behavior**, not just a bugfix: the original design explicitly
  treated CVSS/description as "vendor-neutral, any sync can refresh" data. Every column is now guarded
  by the same `CASE WHEN advisories.vendor = EXCLUDED.vendor THEN EXCLUDED.x ELSE advisories.x END`
  pattern, in all three files.
- `lib/feeds/fortinet.js`'s CSAF parser had a separate, distinct bug: a bare version string like
  `"FortiOS-7.4.2"` (no range operator) was filed into `fixedVersions` unconditionally, regardless of
  whether it came from `known_affected` (means: THIS exact version is vulnerable) or
  `known_not_affected` (means: this version is fixed) — the inverse of its true meaning for the
  `known_affected` case, which would make `versionMatcher.js` treat a device on the exact vulnerable
  version as already patched. Fixed: `parseAffectedEntry()` now takes the originating status
  explicitly; a bare version under `'affected'` now yields a pinned `{min: v, max: v}` range instead
  of a fixed-version entry.

**In-app updater / deploy pipeline (`installer/*.ps1`, `lib/updateCheck.js`):**
- `installer/Update-SecVault.ps1`: `Invoke-Step`'s boolean return value was captured nowhere — every
  step, including `npm run build`, ran as fire-and-forget "best-effort recovery" per the script's own
  design (both services still start at the end regardless of any step's outcome). That's defensible
  for most steps, but NOT for `npm run build`: `SecVault-App` runs `next start` directly against
  `.next\` on disk, and a failed build can leave that directory stale (serves old code silently — looks
  like a successful deploy, isn't), half-written, or missing entirely (fresh install). Fixed: the
  build step's result is now captured (`$buildSucceeded`), and step 8 (`sc.exe start SecVault-App`)
  is skipped with a loud `[SKIP]` log line when it's `$false`, rather than starting the app against a
  broken build. `SecVault-Engine` (step 7) is intentionally NOT gated the same way — it runs directly
  under `node`, no dependency on the Next.js build output.
- Same script: the SSH-deploy-key-not-found `exit 1` path (used when neither known key location
  exists) was the ONLY exit point in the whole script that skipped `Stop-Transcript` — every other
  path falls through to the try/`Stop-Transcript`/catch at the bottom. This is also the single most
  likely real-world failure path (see the deploy-key relocation fix below), so it's exactly the run
  most likely to need the durable per-run transcript this script otherwise always captures. Fixed:
  `Stop-Transcript` now runs before this `exit 1` too.
- Same script: `New-Item -ItemType Directory -Force -Path $LogDir` ran before `Write-Log` is defined,
  with `$ErrorActionPreference = 'Stop'` already active — a failure here (e.g. `C:\Apps\SecVault` not
  yet created, a permissions issue under the SYSTEM-scheduled-task path) was an uncaught terminating
  error with no logged trace and no guaranteed console visibility when launched non-interactively via
  `schtasks`. Wrapped in try/catch with `Write-Warning` + a clear `exit 1` so the failure is at least
  reported.
- **Deploy key placement (`installer/Install-SecVault.ps1`, `installer/Update-SecVault.ps1`,
  `lib/updateCheck.js`)**: the SSH deploy key used to be copied ONLY to
  `$env:USERPROFILE\.ssh\secvault_deploy` — the profile of whichever admin ran `Install-SecVault.ps1`
  interactively. That works for a manual `& Update-SecVault.ps1` run by that same admin (every
  confirmed-successful update this project's history has seen), but the in-app updater ("Update Now")
  schedules `Update-SecVault.ps1` as a Windows Scheduled Task running as SYSTEM, and SYSTEM's own
  `$env:USERPROFILE` resolves to an unrelated profile with no copy of the key — and
  `lib/updateCheck.js` (the SecVault-App service's own live update-status check, a DIFFERENT service
  account again) only ever checked the repo-relative `installer/dependencies/secvault_deploy` path,
  which this project's own prior debugging already confirmed missing on a real deployed server. Three
  independent accounts, three different reliable-key-location needs, no single existing path covered
  all of them. Fixed: `Install-SecVault.ps1` now ALSO places a copy at
  `C:\ProgramData\SecVault\ssh\secvault_deploy`, locked down via `icacls` to `SYSTEM:R` +
  `BUILTIN\Administrators:R` — a machine-wide location readable by any account on the box.
  `Update-SecVault.ps1` and `lib/updateCheck.js` both now check this path FIRST, ahead of their
  existing fallbacks (which remain, for an install that hasn't been re-run since this fix landed).
  **✅ Exercised for real 2026-07-18, and it failed as anticipated**: a production server (installed
  before this fix existed) had "Update Now" run, report success, and silently leave the app on the
  old version — `C:\ProgramData\SecVault\ssh\secvault_deploy` genuinely did not exist there
  (`Test-Path` confirmed `False` directly on the box), because that path is only ever POPULATED by
  `Install-SecVault.ps1` at install time, and nothing re-runs that step on update. A manual
  `& Update-SecVault.ps1` run by the interactive admin worked fine throughout (their own profile had
  a working fallback copy), which is exactly what masked the gap until the in-app button was actually
  tried. Fixed on that server by hand (copied the repo-relative `installer\dependencies\secvault_deploy`
  up to the machine-wide path with the same `icacls` lockdown `Install-SecVault.ps1` uses). See
  `Update-SecVault.ps1`'s own self-heal fix immediately below for why no OTHER already-deployed
  server should need the same manual fix.
- **`Update-SecVault.ps1` self-heal, added the same day**: right after the deploy-key resolution
  block (the one that picks machine-wide → repo-relative → user-profile, in that order), a new check
  fires whenever the RESOLVED key wasn't the machine-wide one — it copies whichever fallback key was
  actually used up to `C:\ProgramData\SecVault\ssh\secvault_deploy` and re-applies the same
  `SYSTEM:R` + `BUILTIN\Administrators:R` lockdown `Install-SecVault.ps1` uses, right then, before
  continuing. Best-effort (a failure here is logged but never blocks the update — the run already has
  a working key via the fallback it found). This means the NEXT scheduled "Update Now" click after
  any manual/interactive update run will already have a working machine-wide key, with no manual
  intervention — the exact gap that caused this incident closes itself on the very next successful
  run, on this server or any other already-deployed one carrying the same gap.

**Alerts / dashboard data correctness:**
- `app/api/notifications/summary/route.js`'s patch_now count and `recentPatchNow` list queries had no
  `LEFT JOIN cve_assessment_acknowledgements` at all — unlike `app/api/events/route.js` and
  `app/(dashboard)/alerts/page.js`, which both correctly join and exclude `dismissed`/`actioned`
  statuses (see "Fleet Alerts Page" above for why this triplication exists and why it's a known,
  accepted "must be kept in step by inspection" risk). The header bell's badge count and dropdown
  could show/list a patch_now CVE an operator had already dismissed. Fixed: both queries now carry
  the identical join/filter the other two files already use.
- `components/advisories/SyncNowButton.js`: the post-sync `allDone` check only verified every feed
  source's `finished_at` was set — never its `status` field — so a partial feed failure (e.g. NVD
  errored, KEV succeeded) still rendered a green "Sync complete" message. Fixed: now checks each
  source's `status` against `'error'` (same convention as `lib/feedStatus.js`'s `getSyncPillStatus()`,
  reusing its same known-feed-name list) and reports which source(s) failed when any did.
- `components/cve/AssessNowButton.js`: `POST /api/cve/assess` (`runMatchForAllDevices()` in
  `lib/engines/versionMatcher.js`) can return HTTP 200 with a non-empty per-device `errors` array
  (skipped/failed devices) with no top-level `error` field — the button only checked the top-level
  field, so it showed "Assessment complete." even when some devices' assessment genuinely failed.
  Fixed: now surfaces a partial-failure message naming the error count and affected device id(s) when
  `data.errors` is non-empty.
- `components/settings/UpdatePanel.js`: `POST /api/system/update` deletes+recreates+runs the
  `SecVaultUpdate` scheduled task on every call with no idempotency check server-side, and the "Start
  Update" button had no in-flight guard — a rapid double-click (or a second click before the confirm
  Modal had fully unmounted) could fire the POST twice, and a second call while the first
  `Update-SecVault.ps1` run is still executing could disrupt it mid-run. Fixed: a `starting` state now
  disables both the "Start Update" and "Cancel" buttons for the window between the click and the POST
  resolving/throwing; only reset on the error path (success transitions to the full-screen updating
  overlay, which unmounts the button entirely).

**Investigated, found already correctly handled or intentionally out of scope (do not re-investigate
without new evidence):**
- `lib/engines/configDiff.js`'s `MEANINGFUL_SUBTREE_FIELDS_BY_VENDOR` allowlist (Palo Alto
  `system_info` noise filtering — see that file's own extensive comments) was flagged as possibly too
  narrow. Deferred, not code-changed: correctly extending it requires comparing against a live PAN-OS
  `show system info` response to find any further noisy-but-unlisted field, the same "verify against
  live responses before writing any parser" constraint this file's own header comment already states
  for itself. No live PAN-OS access was available to do that verification in this pass — flagged here
  as an open, needs-live-verification item rather than guessed at.
  **✅ RESOLVED 2026-07-19** — live production DB access (see "SecVault readonly DB access" — direct
  `claude_readonly` Postgres access, not SSH to a firewall) made this verifiable directly against real
  `config_diffs` rows instead of needing a live PAN-OS connection: the allowlist itself was confirmed
  CORRECT and already fully suppressing new noise (zero new noisy diffs recorded across ~15 collects
  over 2 days) — the user's actual complaint was 28 historical rows recorded BEFORE the allowlist
  existed, still visible in the Dashboard's 7-day "Config Changes" widget. See the new "Retroactive
  config_diffs cleanup" section below for the fix and the secret-disclosure bug found alongside it.

### ⚠️ Bug-sweep fixes (2026-07-18, fifth pass) — 7 parallel finders over the rule-evidence/object-catalog rounds + a fresh Alerts audit

Requested as "do a complete bug sweep of all changes you just made or maybe just do whole app" —
7 parallel READ-ONLY finder agents (no edits), each scoped to one subsystem from the two most
recent rounds (rule-evidence compliance engine; correlation + per-rule risk; the object-usage
engine + schema; Fortinet/Palo Alto `getObjects()`; Check Point/Cisco ASA/Forcepoint/Sangfor
`getObjects()`; the Objects tab UI + `collectAndStore` wiring) plus one fresh-eyes pass on a
subsystem this session hadn't recently re-audited (chose the Alerts page, per CLAUDE.md's own
"must be kept in step by inspection" flag on its 3-way query duplication). All 13 findings below
were personally re-verified against the actual code before being fixed — several were confirmed
by directly reading the file and tracing the concrete failure scenario, not just trusted from the
finder's report.

**Correctness (compliance/rule-analysis engines):**
- `lib/engines/ruleAnalysis.js`'s `runAnalysisForDevice()` rewrote `rule_analysis_results` via
  DELETE then a per-row `pool.query()` INSERT loop with **no transaction** — despite
  `configAuditor.js`'s own header comment claiming to follow "the same reasoning as
  rule_analysis_results and firewall_rules" for this exact rewrite shape, this file itself was
  never actually wrapped in one. A failure partway through the INSERT loop left the DELETE
  committed and only some findings inserted — a corrupted partial state that Phase 7's `rule_scan`
  checks then read from, meaning a critical check like `rule-no-any-any-allow` could silently
  under-report. Fixed to match `configAuditor.js`'s real transaction pattern (one client,
  BEGIN/COMMIT, ROLLBACK + release on error).
- `correlation`'s pairwise loop could mischaracterize a rule pair as "consider merging" (medium)
  when it was actually fully `shadow`ed (high, unreachable) by that same earlier rule — `shadow`'s
  own loop only records the FIRST covering match it finds (`break` after one), so its
  `shadowPairs` guard didn't catch every earlier rule that also happens to fully cover `r`.
  Fixed: `correlation`'s loop now skips ANY `s` where `ruleCovers(s, r)` is true, not just the
  specific pair `shadowPairs` recorded.
- `app/api/compliance/[deviceId]/route.js` and `app/api/compliance/fleet/route.js` both hardcode
  their own `STANDARDS` list (a deliberate duplication of `ComplianceMatrix.js`'s export, per this
  app's established per-file-duplication convention) — both had drifted out of sync, missing the
  new `SANS` standard, so their JSON responses silently had no SANS key at all. Not reachable via
  the live UI (both sibling page.js components import the correct list directly), but exactly the
  drift this file's own comment on that duplication warns about. Fixed in both.
- `components/analysis/RiskyRulesTab.js`'s `BAND_ORDER` (drives the stat-tile render order) used to
  list `low` before `attention`, while `SORT_RANK` (drives the actual table row order) ranks
  `attention` before `low` — the tiles and the table below them visually contradicted each other on
  this one pair. `BAND_ORDER` now matches `SORT_RANK`.

**Network Object Catalog:**
- `lib/engines/objectUsage.js`'s `analyzeObjectUsage()` used ONE flat name→object map spanning every
  `object_type`, seeded from a rule's address AND service fields mixed together — an address object
  and a service object CAN legitimately share a name on a real device (e.g. both named "DNS",
  separate namespaces on every Tier-1 vendor), and the flat map meant a rule referencing service
  "DNS" would ALSO mark an unrelated, genuinely-unreferenced address object named "DNS" as used,
  silently suppressing a real `unused` finding. Fixed: names, the lookup map, and the
  transitive-closure walk are now fully namespace-partitioned (address vs. service), verified with a
  synthetic test reproducing the exact collision.
- `components/analysis/ObjectsTab.js` selected `finding_type`/`detail` as two INDEPENDENT
  `array_agg()` calls with no guaranteed correlated order, then matched them with a blind
  `.find(d => d)` — grabbing whichever detail string came first, not the one belonging to the
  finding_type being rendered. An object CAN carry both an `unused` AND a `duplicate` finding at
  once (nothing makes them mutually exclusive), so the "Duplicate Of" column could show the
  `unused` explanation text instead. Fixed by aggregating `(finding_type, detail)` as one paired
  JSON object per finding (`json_agg(json_build_object(...))`) — no separate-arrays alignment
  problem to have.
- `lib/adapters/index.js`'s object-usage analysis used to run unconditionally whenever
  `getObjects()` was attempted, even when it threw and `storeObjects()` never ran — recomputing
  `object_analysis_results` from a STALE `network_objects` catalog against this pull's FRESH
  `firewall_rules`. Mismatched-freshness inputs can produce actively wrong verdicts, not just stale
  ones (e.g. a renamed object: the stale catalog still has the old name, current rules reference the
  new one, so the old name gets a fresh "unused" verdict that misrepresents a rename as an
  abandonment). Fixed to mirror the exact `rulesCollected` gate already used for Phase 5 above —
  usage analysis only runs when object collection actually succeeded THIS pull.
- `PUT /api/devices/[id]` cleans up stale `device_credentials` on a vendor/method change (see the
  2026-07-19 bug-sweep entry below) but had no equivalent for `network_objects`/
  `object_analysis_results` — a vendor change left the PREVIOUS vendor's object catalog behind
  indefinitely, displayed under the device's new identity with no indication it was orphaned. Fixed:
  gated on vendor change specifically (not `methodChanged` alone — a same-vendor transport switch,
  e.g. fortinet api→ssh, doesn't invalidate what an object catalog fundamentally IS), best-effort
  (a cleanup failure here must not block the device update itself).
- Forcepoint's `classifyNetworkElement()`/`classifyServiceElement()` own header comment claims to
  "prefer an explicit type field, falling back to shape-based inference when absent" — the code
  didn't implement that priority: the shape-based `Array.isArray(el.element)` group check ran
  BEFORE the explicit `type === 'host'`/`'network'` branches, so an element with an explicit
  non-group type that also happened to carry an `element` array field would be misclassified as a
  group, silently dropping its real address/service value. Fixed: an explicit, recognized `type`
  now fully decides classification and returns before ever reaching shape-based inference.
- Check Point's new `_fetchAllPages()` (shared pagination helper extracted from the existing
  gateway-listing code) had no warning when the `MAX_PAGES` cap was hit, unlike its sibling
  `_fetchAccessRulebasePages()` — a catalog exceeding the cap silently returned truncated with zero
  log signal. Added the same warning convention.
- Fortinet REST's `restGroupToNamedGroup()` only ever read `entry.member` as an array — a FortiOS
  response returning a single-item table field as a bare object instead of a 1-element array (the
  same single-item-collapse class of issue already documented for Palo Alto's XML parser) silently
  discarded the group's one real member with no warning. The SSH-transport sibling already handled
  this shape; the REST version didn't. Fixed to accept either shape, matching it — covers both
  address groups and service groups, since both reuse this one function.
- **Known, accepted, NOT fixed this pass**: Palo Alto's `getObjects()` reads back
  `device_configs.config_parsed` via `getLatestConfigParsed()`, which has no way to distinguish
  "this pull's own fresh row" from "an older successful pull's row" — if `getConfig()` fails THIS
  cycle, `getObjects()` still runs and silently persists a stale object catalog with no flag
  indicating it wasn't refreshed. Not gated on `result.configCollected` because that block is
  vendor-generic and 5 of 6 vendors' `getObjects()` don't depend on config at all. Partially
  mitigated: `ObjectsTab.js` shows a "last collected" timestamp, so staleness isn't fully invisible
  to the operator. Flagged rather than over-engineered — low-medium severity, no crash, no wrong
  vendor's data.

**Compliance page navigation — changed per direct user feedback, not a bug fix:**
A user explicitly reported that clicking a failed check from a `StandardCard`'s "Failed: N" list
only scrolled to a shared table further down the SAME page (the original rule-evidence
drill-down's same-page anchor + scroll-into-view design from the round before this one) — they
expected a REAL new page. Built `app/(dashboard)/compliance/[deviceId]/checks/[findingId]/page.js`,
a dedicated per-check detail page (check name, standard/severity/status badges, description,
result detail, remediation, and the rule-evidence table if the check is `rule_scan`-backed).
`StandardCard`'s failed-check links and `StandardTabs.js`'s check-name cells now both navigate here
via real `next/link` `<Link>` navigation. `StandardTabs.js`'s inline expand/collapse
`RuleEvidenceTable` rendering was REMOVED (redundant now that the dedicated page shows the same
evidence, and having two different "see more" affordances live side by side was itself a source of
confusion) — the table's Detail cell now just names the offending-rule count with a "click the
check name for details" hint. `viewMoreHref` ("+N more" on a `StandardCard`) still points at the
`#STANDARD_KEY` same-page anchor, since there's no single check to deep-link to for "see the rest of
this standard's checks" — that one link's same-page-scroll behavior is correct and unchanged. A
`findingId` from an older audit run legitimately 404s here (findings are DELETE+reinserted every
run) — handled as a clear "this result is from an earlier run, go back" message, not a raw 404.

**Follow-up, same day (2026-07-18):** the per-check page above closed HALF the "everything crammed
onto one scrolling page" complaint — the other half was that `compliance/[deviceId]/page.js` still
stacked the full multi-standard browsable table (`StandardTabs`) below the 5 `StandardCard`s, so
reaching it meant scrolling past all of them regardless. Split into two pages:
`compliance/[deviceId]/page.js` is now JUST the `StandardCard` grid + Network Details (its
`getFindings()` query is correspondingly slimmer — it never needed `matched_rule_ids`/rule evidence,
only `status`/`standards`/`name` for the cards' stats and failed-check quick-list); the table moved
to a new `compliance/[deviceId]/standards/page.js`, reached via each card's "+N more" link or a new
"View All Checks" header action. `viewMoreHref` now points there (with the `#STANDARD_KEY` hash
still preselecting a tab, same `StandardTabs.js` mechanism as before) instead of a same-page anchor.
The print report (`compliance/[deviceId]/print/page.js`) was deliberately left untouched — showing
every standard in one continuous scroll is the correct, intentional design for a printable document,
not the same "too much on one screen" problem the interactive page had.

**Alerts subsystem (fresh-eyes pass — first re-audit since Phase 4, not touched by any of this
session's other passes):**
- None of `fetchNewFindings`/`fetchPatchNow`/`fetchConfigDiffs` (duplicated identically in
  `app/api/events/route.js` and `app/(dashboard)/alerts/page.js`), nor the three queries in
  `app/api/notifications/summary/route.js`, filtered on `devices.active` — every OTHER fleet-wide
  view in this app (dashboard, fleet CVE/analysis/compliance/VPN pages, `versionMatcher.js`,
  `ruleAnalysis.js`, `engine-worker.js`) consistently excludes deactivated devices; this subsystem
  never did. A decommissioned device's existing `patch_now` CVE or unacknowledged finding/diff kept
  inflating the header bell badge and the Alerts feed forever, with no way to even filter directly
  to it (the device filter dropdown DID correctly exclude inactive devices — only the actual event
  queries didn't). Fixed by adding `d.active = true` unconditionally (not just under the `open`
  filter — an inactive device's history shouldn't appear even under "All") to all 6 queries across
  the 3 files.
- `fetchPatchNow`'s "open" definition (`caa.status IS NULL OR caa.status NOT IN ('dismissed',
  'actioned')` — i.e. `acknowledged` still counted as open) was inconsistent with
  `fetchNewFindings`' stricter definition (only bare `'new'` counts as open), despite
  `AlertAckControl.js` rendering the IDENTICAL 4-state `new`/`acknowledged`/`dismissed`/`actioned`
  select for both row kinds — selecting "Acknowledged" made a finding row vanish from the default
  Open view but left a CVE row visible, the same control behaving differently depending on which
  row it happened to be attached to. Aligned to the stricter, findings-side definition everywhere.

### ⛔ CRITICAL — Compliance predicate engine was reading the wrong root for Palo Alto (2026-07-18)

Reported directly by a user: "a lot of the fails are actually ok — logging is already enabled, HTTP
management is not enabled, DNS is configured for some already." This was NOT per-check bad data —
it was a shared, architectural bug in `lib/engines/applicability.js`'s `getLatestConfigParsed()`,
affecting **every** `deviceconfig.*`/`shared.*`/`mgt-config.*`-path predicate on **every** Palo Alto
device, on both transports, since this engine was built. Root-caused directly against real
`device_configs` rows (readonly prod DB access), not guessed — see the exact investigation queries
in this session's history if the reasoning below needs re-deriving.

**Root cause 1 — wrong root, per transport:**
- **SSH** (`lib/adapters/paloalto/sshParser.js`): the ENTIRE real config tree (`shared`,
  `deviceconfig`, `network`, `rulebase`, everything) lives under a `.tree` wrapper key, with
  `model`/`hostname`/`sw_version` as siblings at the true top level. Every predicate path in
  `lib/auditChecksSeed.js` for this vendor assumes those keys are at the top level.
  `getByPath(configParsed, 'deviceconfig.system.service.disable-http')` was resolving against
  `configParsed.deviceconfig`, which is always `undefined` — `feature_enabled`/`config_key_exists`
  both treat `undefined` as an unconditional 'no', **regardless of the device's real
  configuration**. Confirmed live on IDC FW: `disable-http` is genuinely `"yes"` (HTTP correctly
  off), `shared.log-settings.syslog` is genuinely populated (2 real syslog servers configured), yet
  every check reading those paths showed FAIL.
- **XML/API** (`lib/adapters/paloalto/parser.js`): `shared` and `mgt-config` genuinely ARE at the
  top level (confirmed live on ITC-SLY) — but `deviceconfig` specifically is nested three levels
  down at `devices.entry.deviceconfig`, not at the top level every `deviceconfig.*` path assumes.

**Fix**: a new `normalizeConfigParsedRoot()` in `applicability.js`, applied inside
`getLatestConfigParsed()` — the SINGLE function both the compliance engine
(`configAuditor.js`) and the CVE-applicability engine (`getConfigAppliesForDevice()`, feeding
`versionMatcher.js`'s CVE prioritization) both call. Fixing it there fixes both consumers at once,
and is a no-op for every other vendor (confirmed: no other adapter's `getConfig()` ever produces a
top-level `.tree` key or a `devices.entry.deviceconfig` key). SSH: swap the effective root to
`.tree` wholesale. XML/API: keep the root, hoist `deviceconfig` up from `devices.entry.deviceconfig`
non-destructively (only when not already present at the top level, so it can never shadow a real
key on some future adapter shape).

**Root cause 2 — FortiOS's bare enable/disable vocabulary:**
`applicability.js`'s `TRUTHY_FEATURE_VALUES`/`FALSY_FEATURE_VALUES` only recognized
`'enabled'`/`'disabled'` — but FortiOS genuinely uses the BARE strings `"enable"`/`"disable"`
(confirmed live on TUS: `log_syslogd.status`, `password_policy.status`, `autoupdate_schedule.status`,
`ntp.ntpsync`, `admins[].two-factor` — every single one). Every `feature_enabled` check against a
Fortinet device was silently resolving `'unknown'` (neither list matched) instead of the correct
`'yes'`/`'no'` — a real PASS showed as `'warning'`, and worse, a real FAIL (2FA genuinely disabled on
TUS's admin account) was ALSO downgraded to a vague warning instead of a proper fail. Fixed by adding
the bare forms alongside the existing `-d` forms.

**Root cause 3 — one genuinely wrong path**: `paloalto-logging-enabled` pointed at
`shared.server-profile.syslog`, which doesn't exist on either real device. The real syslog
server-profile location, confirmed on BOTH transports, is `shared.log-settings.syslog` — fixed.

**Verified end-to-end against real production data** (not just unit-tested in isolation) before
shipping: re-ran `evaluatePredicate()` directly against real `device_configs` rows for both real
Palo Alto devices and the real Fortinet device, for every check the user's screenshot showed as
wrongly failing plus several more. All now resolve correctly — including confirming that
`fortinet-admin-2fa-required` correctly flips to a genuine FAIL post-fix (2FA really is off on that
account — the fix didn't just make failures disappear, it also correctly surfaces a real gap that
was previously being masked as a harmless warning).

**Also swept, both fully verified against real data, found correct, NOT changed**: every other
Fortinet check (the SSL-VPN WAN-exposure and weak-TLS findings are genuine, confirmed real
misconfigurations on TUS, not bugs — same for the default-named `"admin"` account and default HTTPS
port 443, both real). Most other Palo Alto checks also verified correct post-fix.

**Known, NOT fixed this pass — a separate, deeper gap, flagged rather than guessed at**:
`mgt-config` (used by `paloalto-password-min-length`/`paloalto-session-timeout`) does not exist
ANYWHERE in IDC FW's real SSH-collected config tree (confirmed via a bounded deep search, not just
the top level) — this isn't a path bug, the SSH adapter genuinely never captures that section for
this device, the same "reason (a): section never collected" class of gap this file's own
`not_evaluable_from_config` convention already documents elsewhere. Those two checks will keep
showing FAIL rather than an honest `unknown`/`warning` for SSH-collected Palo Alto devices
specifically, until the SSH adapter is confirmed to (or extended to) actually collect that section —
not attempted here without live SSH access to verify what command would surface it. Cisco ASA's
compliance checks remain entirely unverified against real data — no Cisco ASA device exists in this
deployment to check against.

## Main Dashboard Rebuild (v2.10.0, 2026-07-18)

The main `/` Dashboard was data-thin (device cards + one summary row + a feed-sync footer). Rebuilt
around a ChatGPT-generated mockup the user shared as inspiration, but scoped to ONLY what's honestly
buildable from data this app actually collects — no simulated/placeholder numbers anywhere. Built as
10 new standalone widget components (`components/dashboard/*.js`), each an independent async server
component doing its own `pool.query` (this app's established "server components query the DB
directly" convention), assembled into `app/(dashboard)/page.js` alongside the pre-existing device-card
grid and feed-sync footer (both kept, still real/useful data).

Built via 5 parallel fan-out agents once the shared foundation (schema + CWE engine + snapshot job)
was done by the primary agent first — per this file's own "high-risk/core work done by primary agent,
sub-agents fan out only after foundation work is committed" convention. Every agent owned a disjoint
file list (frozen contracts, zero file collisions), and every agent's diff was personally read and
verified against real column names/exports before being trusted, same standard as every prior
sub-agent round in this codebase.

### New: CWE-derived vulnerability categorization (`lib/engines/vulnerabilityCategory.js`)

CVE severity alone (Critical/High/Medium/Low) doesn't answer "what KIND of risk is this" — the
Dashboard's "Risk by Category" widget needed a real categorization, not a guessed one. Built on CWE
(Common Weakness Enumeration), which all three feed sources already carry in their raw responses but
this app never extracted before now:
- `CATEGORIES`: `RCE` ("Remote Code Execution"), `PRIV_ESC` ("Privilege Escalation"),
  `INFO_DISCLOSURE` ("Information Disclosure"), `DOS` ("Denial of Service"), `OTHER` ("Other" — the
  honest fallback for an unmapped/ambiguous CWE or a CVE with no CWE data at all, never guessed into
  one of the first four).
- `CWE_CATEGORY_MAP`: a curated, deliberately non-exhaustive map of ~35 real, well-known CWE IDs
  (e.g. CWE-78 OS Command Injection → RCE, CWE-269 Improper Privilege Management → PRIV_ESC, CWE-200
  Information Exposure → INFO_DISCLOSURE, CWE-400 Uncontrolled Resource Consumption → DOS). An
  unmapped CWE correctly falls to `'Other'` rather than being force-fit into the nearest bucket.
- `categorizeCwes(cweIds)`: when a CVE carries multiple CWEs mapping to different categories, picks
  by fixed priority RCE > PRIV_ESC > INFO_DISCLOSURE > DOS > OTHER — the worst-case category wins,
  consistent with this app's general "conservative/worse-case" bias (same instinct as the tri-state
  applicability rules).
- **Three independent raw-CWE-extraction functions, one per feed shape** (this app's established
  per-file-duplication convention, not a shared parser): `lib/feeds/nvd.js`'s `extractCweIds()` (NVD
  API 2.0's `weaknesses[].description[].value`) and `extractCweIdsFromCveRecord()` (CVE Record Format
  5.x's `containers.cna/adp[].problemTypes[].descriptions[].cweId`, used by both the CIRCL fallback
  in `nvd.js` AND natively by `lib/feeds/paloalto.js`, an independent duplicate copy per the same
  convention); `lib/feeds/fortinet.js`'s CSAF 2.0 extraction, shape-different again — `cwe` is a
  SINGLE object per `vulnerabilities[]` entry, not an array (`vulnerabilities[].cwe.id`), collected
  into a per-CVE `Set` across every FortiOS-scoped entry merged for that CVE.
- `upsertAdvisory()` in all three feed files stores `cwe_ids`/`vulnerability_category` using the same
  vendor-ownership-guarded `CASE WHEN advisories.vendor = EXCLUDED.vendor THEN EXCLUDED.x ELSE
  advisories.x END` pattern every other non-neutral advisories column already uses (the 2026-07-19
  cross-vendor-collision fix — see the CVE engine correctness bullet in the third bug-sweep pass).
- `backfillVulnerabilityCategories(pool)`: a one-time-but-safely-rerunnable migrate-time backfill
  (`lib/migrate.js`, best-effort/non-fatal unlike `seedAuditChecks()`) that derives `cwe_ids`/
  `vulnerability_category` for every EXISTING `advisories` row from its own already-stored `raw_data`
  — no re-fetch from any feed needed, only rows where `vulnerability_category IS NULL` are touched
  (cheap on every re-run after the first).
- `advisories.cwe_ids TEXT[]` / `advisories.vulnerability_category TEXT`: added via BOTH the
  `CREATE TABLE IF NOT EXISTS` body AND a companion `ALTER TABLE ... ADD COLUMN IF NOT EXISTS` — per
  this file's own documented "CREATE TABLE IF NOT EXISTS is a no-op on an existing table" incident,
  every new column on an existing table needs both forms or an already-deployed server never gets it.

### New: daily fleet snapshot job (`lib/engines/dashboardSnapshot.js`, `fleet_dashboard_snapshots`)

The Dashboard's CVE-severity "vs yesterday" delta and the Compliance Score widget's trend both need a
point-in-time fleet-wide snapshot, not just a live query — `fleet_dashboard_snapshots` (one row per
calendar day, `snapshot_date DATE UNIQUE`) is populated by a new `services/engine-worker.js` job,
`runDashboardSnapshotJob()`, scheduled via `cron.schedule('10 0 * * *', ...)` (a fixed daily time, NOT
a configurable `*_INTERVAL_*` env var like the other 3 jobs — a once-a-day snapshot doesn't need
operator tuning), plus run once on startup alongside the existing 3 jobs. No in-flight guard needed
(pure read-then-upsert, no adapter/device I/O, can't meaningfully overlap itself in any harmful way).
`computeAndStoreDashboardSnapshot(pool)` computes:
- `computeFleetCveSeverity(pool)`: fleet-wide (active devices only) CVE counts bucketed by
  `advisories.cvss_score` — **NULL/unparseable scores are excluded from every bucket, never guessed
  into `'low'`**, same tri-state-honesty discipline as the Applicability Tri-State Default.
- `computeFleetComplianceScores(pool)`: fleet-wide overall + per-standard `scorePct`, the EXACT same
  formula as `app/(dashboard)/compliance/page.js`'s `scorePctFromCounts` (pass / (pass+fail+warning),
  `na` excluded from the denominator, `null` — never `0` — when nothing is measurable).
- `ON CONFLICT (snapshot_date) DO UPDATE` — idempotent within the same calendar day, so a manual
  re-run or a retry after a transient failure always reflects the latest computation, never a
  duplicate row.
- Both `CveSeveritySummary.js` and `ComplianceScoreWidget.js` fall back to a LIVE on-the-fly
  computation (mirroring this file's exact query/formula, so the two numbers never structurally
  disagree) when the snapshot table is empty — a normal "day one, job hasn't run yet" state, not an
  error, so the widget is never blank just because the daily job hasn't fired yet.

### The 10 new widgets (`components/dashboard/*.js`) — none wired into any OTHER page

All standalone, all real data, all following this app's tri-state-honesty conventions:
- `CveSeveritySummary` — live fleet CVE severity counts + "vs yesterday" delta (only shown when a
  fresh-enough snapshot exists — stale/missing snapshot silently omits the delta rather than showing
  a misleading one).
- `TopRiskyDevices` — top-N active devices by latest `device_risk_history` score, `INNER JOIN LATERAL`
  (deliberately not LEFT — a device with no risk history yet has nothing to rank and simply doesn't
  appear, rather than showing a fake zero).
- `VendorDistribution` — active-device count by vendor, plain CSS bars (no chart library — a simple
  proportion view doesn't need one).
- `RulesetOverview` — fleet-wide rule totals + 4 finding-type counts as flat StatCard tiles, NOT a
  donut/pie, with an explicit on-page disclaimer that the 4 finding counts are NOT a partition of
  Total (a rule can carry more than one finding type at once) — a donut would visually misrepresent
  that as a breakdown.
- `ComplianceScoreWidget` — big `StandardDonut` gauge for the pooled overall score + a compact
  per-standard list, reading the latest snapshot with the live-fallback described above.
- `RiskByCategory` — CVE counts by the new CWE-derived category, fixed display order imported from
  `vulnerabilityCategory.js`'s own `CATEGORIES` (never hardcoded a second time), zero-count categories
  still render as a visible zero-width row rather than being hidden.
- `DeviceStatusSummary` — titled "Device Connectivity", NOT "Devices Online" — SecVault has no
  real-time health-check polling, only `devices.last_connectivity_ok` (the last test result), so the
  widget carries an explicit "not real-time monitoring" caption rather than overclaiming live status.
- `RecentCriticalAlerts` — most recent fleet-wide `patch_now` CVE assessments, query copied verbatim
  (not reinvented) from `app/api/events/route.js`'s `fetchPatchNow()` — same JOINs, same
  `d.active = true` filter, same "open" definition (bare `'new'`/unset only).
- `RecentActivityFeed` — fleet-wide top-N `activity_log` rows, rendering conventions (date format,
  `actionLabel()` snake_case→Title Case transform) copied verbatim from
  `components/analysis/TrackingTab.js` so this widget and the per-device Tracking tab read identically
  for the same underlying rows.
- `ConfigChangesWidget` — fleet-wide config-change summary over a trailing N-day window (default 7).
  `config_diffs.diff` is genuinely a structured jsonb column (`{added, removed, modified}` —
  `lib/engines/configDiff.js`'s `diffConfigs()`), so the Added/Removed/Modified breakdown is real data
  read via `jsonb_array_length()`, not a fabricated split — confirmed by reading `configDiff.js`
  first rather than assuming only free-text `change_summary` existed.

Layout in `app/(dashboard)/page.js`: the original top-row StatCards (Devices/Patch Now/Scheduled/
Monitor) and the device-card grid + feed-sync footer are UNCHANGED — the 10 new widgets are inserted
between them as a full-width CVE-severity card, then 4 two-column responsive rows pairing
RulesetOverview+ComplianceScoreWidget, RiskByCategory+VendorDistribution, TopRiskyDevices+
DeviceStatusSummary, RecentCriticalAlerts+ConfigChangesWidget, then a full-width RecentActivityFeed.
Some widgets self-wrap in `<Card>` (their own internal heading), others (`CveSeveritySummary`,
`TopRiskyDevices`, `VendorDistribution`) return bare content and are wrapped in `<Card><CardHeader>
<CardTitle>...` by the assembling page — a deliberate per-widget choice made by whichever agent built
it, reconciled at assembly time rather than forced into one convention retroactively.

### Palo Alto `hit_count` was hardcoded to 0 on both transports (found via third-party comparison)

Found by comparing SecVault's rule analysis against a competing firewall analyzer's own report for
the same real devices (IDC FW, TUS) — confirmed live: 752/752 and 64/64 rules showing zero hits on
Palo Alto specifically (every other Tier-1 vendor's adapter does populate `hit_count`, or explicitly
documents why it can't — see "Known Limitations" above for Fortinet-over-SSH/Sangfor). Root cause:
`hit_count` was never even attempted — `parser.js`'s `parseRuleEntry()` set it to a literal `0` with a
comment noting the config-get API doesn't carry hit counts, and no code anywhere called the real
operational command that does.

**Fix, both transports, ADDITIVE enrichment only — never affects `getRules()`'s core contract:**
- **XML/API** (`api.js`/`parser.js`/`index.js`): new `api.getRuleHitCount(conn, vsysName)` issues the
  op command `show rule-hit-count vsys <vsys> rule-base security rules all`. `parser.parseRuleHitCount()`
  does a bounded depth-first walk for any node carrying a rule-identifying `@_name` plus a sibling key
  matching `/hit.?count/i` — deliberately shape-agnostic (doc-derived, unverified response shape;
  guessing one fixed nesting path risked silently returning nothing if the guess is wrong, the same
  "search deep, don't assume the absolute path" approach `findSecurityRulesContainers()` already uses).
- **SSH** (`ssh.js`/`sshParser.js`): `show rule-hit-count vsys <vsys-name> rule-base security rules
  all` over the CLI. `sshParser.resolveVsysNames()` looks for a `vsys { <name>: {...} }` wrapper in
  the parsed brace tree, falling back to the PAN-OS default `vsys1` name when none is found (the
  confirmed-live shape for this deployment's single-vsys device). `parseRuleHitCountOutput()` is a
  line-based table parser: accepts a row only when it has ≥2 whitespace-delimited columns AND at
  least one column after the first is purely numeric — anything else (headers, separators,
  unrecognized shapes) is skipped, never guessed at.
- **Both transports run enrichment ONLY on the unambiguous single-vsys path, and skip it entirely
  (not "best-effort attempt it anyway") on the multi-vsys path** — rule names are unique per vsys, not
  globally (`parseRulesDeep()`'s own existing comment), so merging a per-vsys hit-count map back onto
  a flattened multi-vsys rule list by name alone risks attributing one vsys's count to a DIFFERENT
  vsys's identically-named rule. A wrong hit count is worse than a missing one — same "no ruleset is
  safer than the wrong one" principle CLAUDE.md's `getRules()` rule already applies, extended here to
  enrichment data.
- **The whole enrichment step is wrapped in try/catch that only warns, never throws** — a hit-count
  fetch failure leaves every rule at its prior default (`hit_count: 0`) and never blocks or alters the
  already-built, already-returned rule list. This is a deliberately DIFFERENT failure contract from
  `getRules()` itself (which must throw on a real retrieval failure) — a missing hit-count is a
  degraded-but-safe state, not a data-loss risk.
- ⚠️ **Doc-derived, NOT yet live-verified** — no live PAN-OS device has confirmed either transport's
  exact `show rule-hit-count` response/output shape for this codebase. Both transports log the full
  raw response/output the first time this runs (`[PaloAlto Debug] rule-hit-count raw response:` /
  `[PaloAlto SSH Debug] rule-hit-count raw output:`) — same "first live connect is the real
  verification step" posture as every other unverified Palo Alto field in this file.

### ⚠️ Bug-sweep fixes (2026-07-18, fifth pass) — sweep of the Dashboard Rebuild round itself

Requested immediately after the Dashboard Rebuild round shipped ("do a complete bug sweep after to
make sure all ok") — 4 parallel read-only finder agents, one per subsystem of that round (dashboard
widgets + snapshot job; CWE categorization + feed extraction; an adversarial second-opinion re-review
of the Palo Alto hit-count fix; the new `ruleset_property` compliance checks), followed by personal
verification of every finding against the actual code before fixing anything, same standard as every
prior bug-sweep pass in this file.

**CRITICAL — `lib/feeds/paloalto.js`'s `upsertAdvisory()` never persisted `cwe_ids`/
`vulnerability_category` at all.** `normalizePaloAltoRecord()` correctly computed both values, but
the INSERT column list, VALUES placeholders, `ON CONFLICT DO UPDATE SET` clause, and parameter array
all omitted them entirely (unlike `nvd.js`/`fortinet.js`, whose `upsertAdvisory()` copies were
correctly extended) — every one of the ~346 Palo Alto PSIRT advisories synced with `vulnerability_category`
silently left `NULL` forever on every direct feed sync, only self-correcting via the next
`migrate.js` run's backfill. Fixed to match `nvd.js`'s pattern exactly (12th/13th params, matching
`CASE WHEN` guard).

**LOW — `lib/feeds/fortinet.js`'s HTML-table-scrape fallback path** (used only when CSAF is
missing/broken for an advisory) omitted `cwe_ids`/`vulnerability_category` from its returned record
entirely, degrading to `NULL` on upsert rather than the codebase's own established explicit-`'Other'`
convention for "genuinely nothing to categorize." Fixed: explicit `cwe_ids: []`,
`vulnerability_category: categorizeCwes([])` — self-corrects if the same advisory is later ingested
via CSAF, since the vendor-match `CASE WHEN` guard lets that later sync overwrite it.

**MEDIUM — `CveSeveritySummary.js`'s "vs yesterday" delta label was hardcoded regardless of how
stale the comparison snapshot actually was.** `pickComparisonSnapshot()` only validates the freshness
of the MOST RECENT snapshot before picking a comparison row — if the daily snapshot job were ever
down for a stretch (say 10 days) and then resumed, the function correctly picks the second-most-recent
row as the comparison baseline, but the label still unconditionally said "since yesterday," silently
misrepresenting a multi-day delta as a one-day one. Fixed: `deltaLabel()` now takes the actual
`daysAgo()` of the chosen comparison row and renders `"vs Nd ago"` for anything other than a genuine
1-day gap.

**HIGH — `configAuditor.js`'s new `rule-has-explicit-deny-all` check false-failed on Cisco ASA.**
ASA ACEs encode "all IP protocols" as the literal token `ip` in the services field (`access-list
OUTSIDE_IN extended deny ip any any` → `services: ['ip']`, never normalized to `"any"`) — the single
most common real-world ASA explicit-deny-all pattern. `isAnyField(['ip'])` returned `false` because
`'ip'` isn't in the shared `ANY_ALIASES` vocabulary, so a genuinely compliant device reported FAIL.
Fixed with a service-field-only `SERVICE_ANY_ALIASES` extension (`ANY_ALIASES` + `ip`/`ip4`/`ip6`),
passed to `isAnyField()` only for the services check — deliberately NOT folded into the shared
`ANY_ALIASES` used for address fields, since `ip` as a protocol-wildcard token is a different concept
from an address wildcard and merging them would risk misclassifying an address object literally
named "ip." `ruleAnalysis.js`'s own `any_any` finding has the identical blind spot for `permit ip any
any` on ASA — deliberately NOT fixed there in this pass, since that has a much wider blast radius
(every existing ASA shadow/redundant/any_any finding) and needs its own independently-verified
change, not a side effect of this one.

**MEDIUM — the same round's `rule-blocks-icmp` check missed FortiOS's own default `ALL_ICMP`/
`ALL_ICMP6` builtin service objects.** The original `\bicmp\b` pattern's word-boundary does not fire
between `_` and `I` (underscore is a `\w` character), so a FortiGate rule using FortiOS's
out-of-the-box "block all ICMP" object reported FAIL despite being correctly configured. Fixed to
`/(^|[^a-z])icmp/i` — only requires the character immediately before "icmp" to not be a letter
(start-of-string, underscore, digit, hyphen all qualify), matching `ALL_ICMP`/`ALL_ICMP6`/`icmpv6`
while still excluding an unrelated name that merely contains "icmp" as a non-leading letter run.

**LOW — `isAnyField()` didn't filter empty/whitespace-only entries before checking array length**,
unlike `ruleAnalysis.js`'s own `normList()`, which the header comment claims this duplicates — an
array like `['', ' ']` was treated as NOT-any (length 1) instead of any (all entries empty). Fixed to
filter empty strings first, matching the vocabulary it's meant to mirror.

**HIGH (structural, unverified — no live multi-vsys Palo Alto device exists in this deployment) —
the SSH-transport Palo Alto hit-count enrichment's vsys-ambiguity detection was less shape-tolerant
than the rule-finder it was meant to protect.** `sshParser.js`'s `resolveVsysNames()`/
`walkForVsysNames()` only recognizes one exact `vsys { <name>: {...} }` wrapper shape, unlike
`findSecurityRulesContainers()`'s deliberately deep, shape-agnostic search (which already has to
tolerate a bare single-vsys root, a `vsys.entry` wrapper, `shared`, or a Panorama pre/post-rulebase
shape). On a genuinely multi-vsys device whose real vsys-wrapper didn't match the one shape
`walkForVsysNames()` recognizes, it would silently fall back to `['vsys1']` as if that were
CONFIRMED single-vsys — `_enrichHitCounts()` would then treat this as the safe case and merge
vsys1's hit counts onto same-named rules that were actually collected from a DIFFERENT vsys
container, exactly the cross-vsys corruption this whole enrichment step was built to prevent. Fixed:
`parseSecurityRules()` now also returns the parsed `tree` it already builds internally (avoiding a
redundant second full re-parse of the config text as a side benefit), and `ssh.js`'s
`_enrichHitCounts()` now gates FIRST on `containersFound !== 1` (the same signal `getRules()` itself
already trusts to decide whether the ruleset is unambiguous) before even attempting vsys-name
resolution — "exactly one container" is at least as trustworthy as anything the narrower vsys-name
walk could independently conclude, and any value other than 1 skips enrichment entirely rather than
guessing. Also corrected an overstated comment on the XML/API transport's sibling code path, which
had claimed the queried vsys was "unambiguous" when what's actually true is narrower: that path is
only reached when the hardcoded `api.DEFAULT_VSYS` xpath alone already yielded rules, which is safe
to enrich against that same vsys regardless of whether the device is otherwise multi-vsys — not
because topology was confirmed.

**Investigated, flagged but NOT changed — already-honest, inherent doc-derived-guess limitations,
not something a code change can safely resolve without a live device**: `parseRuleHitCountOutput()`'s
"first purely-numeric column after the name wins" heuristic (SSH) has no way to distinguish a real
hit-count column from an earlier unrelated numeric column (e.g. a rule position/ID) if PAN-OS's real
table layout happens to have one — the exact response shape remains unverified. `collectHitCounts()`
(XML/API) does an unscoped name+regex walk that could in principle misattribute a value from an
unrelated summary node, or let a nested duplicate silently overwrite a correct one. Both are
consequences of the deliberately shape-agnostic "search deep, don't assume the path" design this
codebase already uses elsewhere for doc-derived Palo Alto parsing, both are already flagged in-code
as unverified, and both need a live device's actual raw output (already logged on first connect) to
resolve correctly rather than trading one guess for another. The extra SSH session per collect that
hit-count enrichment now costs (a second `_run()` call beyond the cached config-pull session) was
also flagged as a real but low-severity performance tradeoff, not a correctness issue — not changed,
since consolidating it into the existing cached session would mean restructuring already-verified
session-caching code for a best-effort enrichment step.

### ⚠️ Bug-sweep fixes (2026-07-19, fourth pass) — full-app sweep alongside a feature round

Requested as "do the full compliance/rule-analysis/admin-account feature round PLUS a full feature
check and bug fix" — six parallel fan-out agents (three building features, three doing read-only
audits of subsystems not yet swept this session: Forcepoint, device CRUD/credentials/settings,
auth/middleware + a fresh self-review of this same day's own VPN round), followed by a seventh
agent fixing everything the Forcepoint audit found. All findings personally verified against the
actual diffs before being reported as done, same standard as every prior pass.

**Forcepoint (`lib/adapters/forcepoint/*.js`) — this codebase's ORIGINAL MVP vendor, never
re-audited until now, had 5 real bugs, 2 critical:**
- **CRITICAL — no device-to-engine identity matching at all.** `getVersion()`/`getRules()`/
  `getConfig()` each did `const primaryEngine = engines[0]` — `smc.getEngines()` returns EVERY
  engine on the whole SMC server, unfiltered, with no use of `this.device.name` anywhere. On any SMC
  managing more than one engine (CLAUDE.md's own Forcepoint section already says 50+ is a normal
  case), every SecVault device pointed at that `smc_host` silently collapsed onto whichever engine
  happened to be first in the server's listing. Fixed with a new `findEngineByIdentity()`/
  `describeEngineCandidates()` pair in `parser.js`, mirroring Check Point's already-established
  strict-match-or-throw-naming-candidates pattern exactly — a new `_resolveEngine(conn)` in
  `index.js` replaces all three `engines[0]` picks.
- **CRITICAL — `getRules()` fell back to a positionally-picked policy** (`policies[0]` from the
  ENTIRE SMC server's `fw_policy` list) whenever the resolved engine element didn't expose a
  `fw_policy`/`policy` href — a real possibility since these are doc-derived, unverified field
  names. Now throws instead, naming what WAS found on the engine element (or that nothing was) — no
  ruleset is safer than the wrong one, same principle as the already-fixed Check Point
  `packages[0]` bug.
- **HIGH — `getConfig()` stored the full engine element with zero secret redaction** — the only one
  of six adapters with no redaction pass at all (every other adapter, including the API/JSON-based
  ones, redacts defensively even when it's unverified whether the vendor API itself already blanks
  secrets). Fixed with a new `redactEngineElement()`/`isSecretKey()` pair in `parser.js`, mirroring
  `fortinet/parser.js`'s `redactSecretFields()` bounded-recursion style.
- **MEDIUM-HIGH — unresolved SMC "any" refs landed as raw objects, defeating `any_any`.** SMC's
  convention for an unrestricted source/destination/service is `{any: true}`, which `resolveRef()`'s
  existing `.ref`/`.href`/`.name` fallback chain didn't recognize — it fell through to returning the
  raw `{any: true}` object itself into `src_addresses`/`dst_addresses`/`services`.
  `String({any:true})` is `"[object Object]"`, which `ruleAnalysis.js`'s `isAny()` never matches — so
  a genuine Forcepoint allow-any rule silently never triggered the `critical`-severity `any_any`
  finding (or `overly_permissive`/`shadow`/`redundant`/`reorder_candidate`, all of which key off the
  same `isAny()`). Fixed: `ref.any === true` now returns the literal string `'any'`, which
  `ANY_ALIASES` already recognizes — zero `ruleAnalysis.js` changes needed.
- **MEDIUM, conservative fix (no live SMC to fully confirm)** — the version-string candidate list
  checked `dynamic_package` (the installed Dynatic Update signature-package version — a DIFFERENT
  concept) before `engine_version` (the actual firmware version concept). Reordered so
  `engine_version` is preferred; `dynamic_package` demoted to last-resort. Flagged doc-derived in
  the code, pending live SMC verification — no Forcepoint devices exist in this deployment's
  production database to check against right now.

**Device CRUD / credentials / settings — 2 real findings, fixed:**
- **Stale `device_credentials` row silently reused after a vendor/`mgmt_method` change with no fresh
  credential supplied.** `credStore.setCredential()` only ever cleans up the row for the
  `credential_type` it's actively writing — never a device's OTHER credential-type rows. `PUT
  /api/devices/[id]` accepts a vendor/method change with no credential in the same request (a
  legitimate call shape the credential-rotation UI never triggers, but nothing stops a direct API
  call). Concrete failure: `fortinet`+`ssh` → `paloalto`+`ssh` (both resolve to `credential_type:
  'ssh'`) with no new credential — the adapter dispatch changes to `PaloaltoSshAdapter`, but
  `getCredential(deviceId, 'ssh', pool)` silently returns the STALE Fortinet SSH username/password.
  Fixed: whenever the vendor or method actually changes, `PUT /api/devices/[id]` now deletes every
  `device_credentials` row for that device OTHER than the type the device will need going forward —
  a device can only ever need exactly one credential_type at a time, so anything else is stale by
  definition. A credential supplied in the SAME request for the new type is unaffected, written
  afterward by the existing `setCredential()` call.
- **`isValidUuid` guard missing on 7 of the `devices/[id]/*` routes** — `collect`, `test`, `cve`,
  `rules`, `backups`, `backups/[backupId]` (both `id` AND `backupId`), `diffs`. A malformed id hit a
  raw Postgres "invalid input syntax for type uuid" error, surfaced as an unhelpful 500 instead of a
  clean 400 — the exact failure mode a 2026-07-17 fix already closed for 4 sibling routes, just never
  extended to these. Fixed identically across all 7.
- **Lower severity, fixed opportunistically while already touching `device_credentials`**: no
  DB-level `UNIQUE(device_id, credential_type)` constraint existed — `setCredential()`'s DELETE+INSERT
  transaction is atomic for one request but doesn't prevent two CONCURRENT calls (e.g. a
  double-submitted credential rotation) from each leaving a row behind, with `getCredential()`'s
  `ORDER BY created_at DESC LIMIT 1` picking one with no DB-enforced guarantee. Added the constraint
  (with a dedupe pass immediately before it in `schema.sql`, safe to run against a production
  database that might already have accumulated a duplicate — `claude_readonly`/`nocvault_readonly`
  correctly cannot read this table to check ahead of time) and rewrote `setCredential()` as a single
  `INSERT ... ON CONFLICT (device_id, credential_type) DO UPDATE` — genuinely atomic under real
  concurrency via Postgres row-level locking, not application-level DELETE-then-INSERT timing.

**Auth/middleware self-review — clean**, plus one informational gap noted but not fixed:
`LDAP_URL`/`LDAP_BASE_DN` are fully wired in `authorize()` (correctly falls back to local-admin
when unset, correctly fails closed on a connection error) — but `app/(auth)/login/page.js` only
ever calls `signIn('local', ...)`; there is no LDAP option anywhere in the UI. Not a security bug
(fails safe, just unreachable), but the documented "optional LDAP/AD" feature doesn't actually work
end-to-end today. Flagged as a real, known gap — building LDAP login UI is a feature addition, out
of scope for a bug-fix pass.

**Device inventory — serial numbers parsed then dropped, `build` queried then never rendered:**
Both Fortinet SSH and Palo Alto SSH successfully parse a device serial number
(`parseSystemStatus().serial` / `parseSystemInfo().serial` respectively) — `getVersion()`'s own
return object simply never included it, and `device_versions` had no column for it anyway. Fixed:
`ALTER TABLE device_versions ADD COLUMN IF NOT EXISTS serial TEXT` (safe to re-run on an
already-deployed table), all four transports' `getVersion()` updated (`serial: info.serial || null`
for the two SSH cases; Fortinet REST's `parser.js` already read `statusBody.serial` but only as a
last-resort MODEL fallback, never as its own field, now extracted separately too; Palo Alto XML/API
never parsed `serial` at all before this — added, doc-derived, not yet live-verified for that one
specific transport). `collectAndStore()`'s INSERT extended to include it. Separately, `build` was
already queried by `getLatestVersion()` on the device detail page and simply never rendered in the
JSX — pure UI gap, no data/adapter issue. Both now render as new tiles on the device summary card.

**`lib/engines/ruleAnalysis.js` — dead condition in the `unused` finding, simplified:** the
condition read `Number(rule.hit_count) === 0 && !rule.last_hit_at`. No adapter, for any vendor, has
ever populated `firewall_rules.last_hit_at` — it isn't even in `collectAndStore()`'s INSERT column
list — so `!rule.last_hit_at` was always `true`, permanently vacuous. Simplified to
`Number(rule.hit_count) === 0` alone (that was always the real, entire decision) and updated the
finding's `detail` text, which previously referenced "no last-hit timestamp" as if it were a real,
sometimes-false signal.

### ⚠️ Bugs Found and Fixed — full-app orchestrated sweep (2026-07-19, sixth pass)

Requested directly as "do a full bug sweep of the entire app... fan agents across the app, check all
nooks and crannies" before a dev session the next day — the first sweep in this codebase's history run
as an actual multi-agent Workflow rather than a handful of parallel Task agents: **16 parallel
read-only finders**, one per subsystem (every vendor adapter individually — Forcepoint, Fortinet, Palo
Alto, and Check Point/Cisco ASA/Sangfor grouped — the CVE feed engine, applicability/compliance, rule
analysis/object usage, the Dashboard, Alerts, the brand-new Vulnerability page merge, device CRUD,
auth/shell, VPN/admin summary, config-diff/engine-worker, the updater/installer, and shared UI
components), **56 agents total**, every one of the 22 findings put through an adversarial skeptical
verifier (told to default to REFUTED unless it could personally trace the exact failure through the
real, current code) before any fix was attempted — all 22 survived verification. Fixes were then
applied grouped by file so no two agents touched the same file, followed by a personal review of every
diff (not just a build check) before integrating, per this file's own "verify agent diffs before
integrating" rule. The three files changed earlier that same day (Dashboard icons, the Vulnerability
merge, the config-diff secret-redaction fix) were explicitly called out to their respective finders for
extra scrutiny rather than assumed clean just because they were new.

**Security:**
- `lib/adapters/forcepoint/parser.js`'s `SECRET_KEY_PATTERN` was still the OLD narrow pattern
  (`secret|password|passwd|psk|private[-_]?key|community|credential|token|api[-_]?key`) — the exact
  keyword gap that caused the real production secret leak documented in the Config Change Tracking
  section above (a `phash` field). The widened pattern (adding `phash`/`pre[-_]?shared`/`keytab`) had
  only ever landed in `lib/engines/configDiff.js`'s downstream `SECRET_PATH_PATTERN`, never
  back-ported to this file — the FIRST and only adapter-level redaction pass before `device_configs`
  (granted to `claude_readonly`/`nocvault_readonly`) is populated for Forcepoint. Fixed to match.
- **Two more gaps found in the SAME `configDiff.js` secret-redaction work from earlier that day**,
  confirmed by giving that file's own finder explicit "genuinely skeptical, not a rubber stamp"
  instructions rather than trusting it was already correct: (1) `redactSecretEntries()`/`isSecretPath()`
  only ever inspected a diff entry's own top-level PATH, never the object it carries — `diffValue()`
  never recurses into a key that exists on only one side of a diff (a whole new/removed subtree is
  captured as one opaque `value`), so a secret nested inside e.g. a newly-created Palo Alto admin user
  object (`mgt-config.users.newadmin: {phash: '...', ...}`) was never inspected at all, because the
  entry's own path (`...newadmin`) isn't itself secret-shaped. (2) `isVolatilePath()` only matches a
  nested leaf path with a trailing-dot prefix (`system_info.time`) — if the WHOLE `system_info` subtree
  appears/disappears as one add/remove entry rather than field-by-field, the bare path `system_info`
  never matches its own `${root}.` prefix test, so the noise-suppression allowlist is bypassed entirely
  for that one diff. Fixed with `deepRedactSecrets()` (recursively redacts any secret-shaped KEY found
  at any depth inside a carried value, applied to every entry regardless of its own path) and
  `isRegisteredSubtreeRoot()` (decomposes a whole-subtree add/remove of a registered volatile root via
  a recursive `diffValue(subtree, {}, ...)` / `diffValue({}, subtree, ...)` call instead of capturing it
  as one opaque entry, so per-leaf `isVolatilePath` filtering applies correctly). Re-verified against
  live production data (read-only) after the fix, including a synthetic whole-subtree-add test
  confirming both a nested `phash` and nested volatile `system_info.time`/`.uptime` are now correctly
  handled in the one-sided-diff shape that was missed before.
- `lib/adapters/checkpoint/parser.js`'s `findGatewayByIdentity()` had no object-type filter — on a
  distributed deployment (`device.mgmt_ip` = the Security Management Server's own IP, the exact
  scenario this function's own header comment already calls out as needing name-based disambiguation),
  the SMC's own `checkpoint-host`/server object can share that IP and get matched as "the gateway"
  before the real gateway's name-based match is ever reached (list order from the API isn't
  guaranteed). Fixed with `isGatewayLikeType(type)` (`/gateway|cluster/i`, matching this file's existing
  `_showGatewayElement()` type-check convention), required alongside the IP/name match.

**Correctness / data-loss risk:**
- `lib/adapters/forcepoint/parser.js`'s `parsePolicy()` returned `[]` identically whether a policy
  genuinely has zero rules OR its rules live under a field name other than the two doc-derived,
  unverified guesses (`rules`/`fw_ipv4_access_rules`) — `getRules()` returned that `[]` straight
  through with no way to tell the two apart, and `collectAndStore()` would DELETE the device's real
  `firewall_rules` before inserting the empty result, silently wiping the ruleset on a field-name
  mismatch while reporting success. The exact "getRules() must throw, never return []" violation this
  file documents as already fixed once in Sangfor/Fortinet. Fixed: throws when NEITHER known field is
  present on the element at all; still returns `[]` (correctly) when a known field IS present but
  resolves empty — a genuine zero-rule policy.
- `lib/adapters/paloalto/sshParser.js`'s `findSecurityRulesContainers()` only ever matched a literal
  `rulebase` key, never Panorama's `pre-rulebase`/`post-rulebase` — contradicting its own header
  comment and this file's own claim (both asserted the Panorama shape was already tolerated). A
  Panorama-managed device with rules only under `pre-rulebase`/`post-rulebase` would fail SSH
  collection outright (`containersFound === 0` → throw) despite having a real, enforced ruleset. Fixed
  to check all three keys at every recursion level.
- `lib/feeds/nvd.js`'s CIRCL-fallback path (`matchingAffectedEntriesFromCveRecord`) required
  `entry.cpes[]` to be present — an optional, NVD-specific enrichment that raw CVE List v5 records
  commonly omit (e.g. a CVE not yet processed by NVD's own CPE-matching pipeline, the exact class of
  CVE the CIRCL fallback exists to surface during an NVD outage). An entry with no `cpes[]` was
  silently dropped, `normalizeCirclRecord()` had no guard analogous to `paloalto.js`'s zero-match skip,
  and the resulting advisory row was upserted anyway with empty `affected_version_ranges`/
  `fixed_in_versions` — permanently unmatchable to any device, the opposite of what CIRCL is for. Fixed
  with a fallback match on the entry's plain `vendor`/`product` strings (normalized, required on every
  CVE Record affected[] entry) when `cpes[]` is absent.
- `lib/feeds/nvd.js`'s `pickCvss()`/`pickCvssFromCveRecord()` never checked `cvssMetricV40`/`cvssV4_0`
  — only `paloalto.js`'s equivalent cascade had been extended for this, despite both consuming the
  identical CVE Record Format 5.x shape. A CVE carrying only a v4.0 metric resolved to `cvss_score =
  null`, which `prioritization.js` coerces to `0`, permanently blocking priority-tree steps 3/4
  (cvss>=9.0/7.0) regardless of real severity. Fixed to match `paloalto.js`'s cascade exactly.
- `app/api/devices/[id]/acknowledgements/route.js`'s `FINDING_TYPES` allow-list was missing
  `'correlation'` (the 10th finding type, added 2026-07-18) — acknowledging a correlation finding from
  the Cleanup tab always 400'd, permanently stuck at "New" unlike its three sibling finding types in
  the same tab. Fixed by adding it.
- **`app/api/events/route.js`'s `fetchNewFindings()` was rooted FROM `finding_acknowledgements`**,
  which only ever gets a row via a human-triggered ack POST — a genuinely new finding from the latest
  scheduled rule-analysis run (which never touches that table) had zero rows and was invisible to the
  bell badge, `GET /api/events?type=new_finding`, and the Alerts page, the exact opposite of what
  `new_finding` is supposed to surface. Fixed by rooting FROM `rule_analysis_results` instead, `LEFT
  JOIN finding_acknowledgements`, `COALESCE(fa.status, 'new')` — mirroring the pattern
  `CleanupTab.js`'s `getCleanupFindings()` already used correctly. **Found only in one of the three
  places this exact query is deliberately duplicated** (per this file's own "must be kept in step by
  inspection" warning on that duplication) — the sweep's fix-grouped-by-file strategy only touched the
  one file its finder flagged, so `app/(dashboard)/alerts/page.js`'s own copy and
  `app/api/notifications/summary/route.js`'s bell-count/recent-items queries were independently
  checked and found to have the identical bug, then fixed identically by hand immediately after
  integrating the sweep's other fixes — a gap in the sweep's own file-grouping strategy for findings
  that are supposed to apply to more than one file, worth remembering for the next orchestrated sweep.
- `components/dashboard/RecentActivityFeed.js`'s fleet-wide activity query had no `d.active = true`
  filter (or any device-status condition) — the one Dashboard widget in its own grid that didn't,
  unlike the identical 2026-07-19 fix already applied to the Alerts subsystem the day before. A
  deactivated device's old logged actions could occupy multiple of the widget's only 8 slots
  indefinitely. Fixed with `WHERE al.device_id IS NULL OR d.active = true` — the `IS NULL` half
  specifically preserves fleet-wide entries (`Trigger Update` etc., which have no `device_id`) that a
  bare `d.active = true` would have wrongly dropped via the `LEFT JOIN`'s NULL.
- `app/(dashboard)/devices/page.js`'s "Edit" action linked to the exact same URL as "View", and that
  destination page has no field-editing form at all (only credential rotation, Collect/Test, Delete) —
  `PUT /api/devices/[id]` fully supports updating name/vendor/mgmt_ip/site/asset_criticality, but
  nothing in the UI ever calls it with anything but a credential. The only UI recovery from a typo'd
  field was Delete + re-add, cascading away the device's entire historical trail. Fixed by removing the
  dead/misleading Edit link (the smallest correct fix for a bug-sweep; building an actual edit form is
  a real, separate feature gap worth its own follow-up, not attempted here).

**UI / navigation:**
- `components/compliance/ComplianceMatrix.js`'s fleet "Compare Devices" score-chip links, and
  `app/(dashboard)/compliance/[deviceId]/checks/[findingId]/page.js`'s "Back to Compliance" link, both
  still pointed at `/compliance/{deviceId}#{standardKey}` — a same-page hash anchor that stopped doing
  anything the moment the 2026-07-18 split moved `StandardTabs`' hashchange/scrollIntoView handling off
  that summary page onto the separate `/compliance/{deviceId}/standards` route. Every OTHER link in the
  same feature (`StandardCard`'s own `viewMoreHref` in both compliance pages) was updated at the time;
  these two were missed. Fixed by adding `/standards` to both.
- `components/dashboard/ComplianceScoreWidget.js` had no staleness bound on the
  `fleet_dashboard_snapshots` row it reads as the Dashboard's PRIMARY compliance score — unlike its
  sibling `CveSeveritySummary.js`, which explicitly refuses a comparison snapshot more than 2 days old.
  The daily snapshot cron job only logs-and-skips on failure with no retry before the next day's tick,
  so a persistent failure could leave the Dashboard silently showing a frozen, arbitrarily-old score
  indefinitely with only a small 10px date caption as the sole hint. Fixed with the identical >2-day
  `daysAgo()` staleness gate `CveSeveritySummary.js` already uses, falling back to the live computation
  (already used for "no snapshot yet") when the snapshot is present but stale too.
- `app/(dashboard)/devices/[id]/vpn/page.js` checked `summary.enabled === null` but not `undefined` for
  the "state unknown" badge — Fortinet/Palo Alto devices whose VPN module returns `undefined` (not
  `null`) for an unmodeled confidence state never rendered ANY Enabled/Disabled/Unknown badge at all.
  Fixed to match the fleet-wide `/vpn` page's own equivalent fallback exactly (`Configured (state
  unknown)`, warning color) — closing both the missing-badge bug and a wording/color inconsistency
  between the two pages in one fix.
- `components/ui/Modal.js` had no focus trap, no initial-focus management, and no `role`/`aria-modal` —
  interactive elements behind an open confirm dialog (Delete Device, Start Update?) remained reachable
  and activatable via Tab while the modal was open. Fixed: focus moves into the dialog on open and
  restores to the triggering element on close, Tab/Shift+Tab now cycles only within the dialog's own
  focusable elements, and `role="dialog"`/`aria-modal="true"`/`tabIndex={-1}` were added to the panel.
  Purely additive to the existing `open`/`onClose` `useEffect` — no existing call site's rendering
  changes.

**Observability (silent-verification gaps, not user-facing bugs):**
- `lib/adapters/forcepoint/smc.js`'s mandatory `[SMC Debug] Engine element:` first-connect log (the
  raw-response evidence this file's own Live Validation Status protocol requires before trusting any
  field mapping) only fired on the branch that follows an engine's href for full data — a live SMC
  whose `/api/elements/engines` list response already returns complete elements inline (arguably the
  more common REST shape) never logged anything, for any collect cycle, silently defeating the
  verification protocol while the adapter ran with no visible error. Fixed by moving the log outside
  the conditional href-follow branch so it fires unconditionally per engine.
- `lib/adapters/fortinet/cliParser.js`'s `parseSystemStatus()` warned on a failed version-line match
  but not a failed `Virtual domain configuration:` match — the sole gate for whether multi-VDOM
  enumeration is even attempted (`isMultiVdom()` silently treats an unparsed line as single-VDOM by
  design). A real multi-VDOM device with slightly different firmware wording on that one line would
  silently collect only the default VDOM's rules with zero `engine.log` signal pointing at the cause.
  Fixed to warn, matching the sibling versionLine pattern.

**Installer:**
- `installer/Update-SecVault.ps1` step 8 (`sc.exe start SecVault-App`) was gated only on `npm run
  build` succeeding, not on step 5 (`node lib\migrate.js`) — a failed schema migration still let the
  app restart running new code against the old/incomplete schema (the exact class of failure the
  `audit_findings.matched_rule_ids` incident above documents). Fixed by capturing `$migrateSucceeded`
  (mirroring the existing `$buildSucceeded` pattern exactly) and gating step 8 on both. The final
  summary log line also unconditionally claimed "Both services were still (re)started" even when step
  8 was deliberately skipped — fixed to report accurately which service(s) actually started.
- `app/api/system/update-available/route.js`'s polled-banner cache started at the hardcoded
  `{available:false}` default and only refreshed at process start + every 24h — if the very first
  resolution failed (e.g. network not fully up right after a reboot), the cache silently stayed at a
  confident-looking "no update" for up to 24 hours with no retry. Fixed with a `resolvedOnce` flag and
  a 5-minute retry loop that stops once a check actually resolves either hash.

**Result:** all 20 touched files (18 from the sweep + the 2 hand-fixed duplicates) `node --check`ed
(PowerShell files syntax-validated via `PSParser`), every diff personally reviewed against the actual
finding before integrating, `npm run build` clean.

### ⚠️ Bugs Found and Fixed — full-session orchestrated sweep (2026-07-20, seventh pass)

Run as a single Workflow (6 parallel dimension finders → adversarial verify-per-finding, told to
default to REFUTED unless it could trace the exact failure through the real code → fix grouped by
file → personally re-reviewed every diff before integrating), scoped to everything built in one
continuous session that day: RBAC (`lib/rbac.js`, the `users` table, every route guard), the rule
reorder recommendation export, config-diff acknowledgement notes, the `classifyDiff()`/`DiffViewer.js`
presentation rewrite (and its two same-day follow-up corruption fixes), and the Settings tabs
rewrite. 16 findings, all independently adversarially confirmed, all fixed same-pass.

**⛔ CRITICAL — `POST /api/analysis/run` (the fleet-wide "re-run rule analysis for every active
device" trigger) had no RBAC guard at all.** Not found in the original RBAC rollout's own route
inventory because it's a sibling of `POST /api/devices/[id]/analysis` (per-device, correctly
gated) sitting under a different path (`app/api/analysis/run/`, not `app/api/devices/[id]/analysis/`)
— an easy one to miss when sweeping by directory structure rather than by grepping every
POST/PUT/DELETE export in `app/api/**`. A `viewer`-role session (which passes `middleware.js`'s
blanket "any authenticated token" check — middleware only checks token *presence*, never role) could
`POST` here directly and trigger a real, DB-mutating, fleet-wide rewrite of
`rule_analysis_results`/`device_risk_history` — exactly the class of action RBAC exists to block.
Fixed with the identical three-line guard every sibling route already uses. **Lesson**: when
auditing RBAC route coverage, grep every `export async function (POST|PUT|DELETE|PATCH)` in
`app/api/**` directly and cross-reference against `isAdmin` usage, rather than trusting a
feature-by-feature route inventory to be complete.

**⛔ HIGH — RBAC role was baked into the JWT only at sign-in and never re-validated.** Demoting an
admin to viewer, or deleting their account entirely (both via the new Users panel,
`PUT`/`DELETE /api/users/[id]`), never touched that user's already-issued session — `jwt()` only set
`token.role` `if (user)` (i.e. only at the initial `authorize()` call), and `session()` just copied
whatever the JWT already had, no DB lookup. With no `session.maxAge` override anywhere in the app,
next-auth's default 30-day JWT lifetime applied — a revoked/deleted admin kept full admin capability
for up to 30 days or until they happened to log out themselves, completely defeating the point of the
role-change/delete-user controls. **Fixed**: `jwt()` now re-queries `SELECT role FROM users WHERE id
= $1` on **every** invocation (not just sign-in) for `local`-provider tokens, so a role change or
deletion takes effect on the very next request. `token.id`/`token.provider` are now stashed at
sign-in specifically to make this re-check possible. LDAP-authenticated tokens are deliberately
exempt (LDAP users have no `users` table row at all — role is always the hardcoded `admin` set in the
`ldap` provider's own `authorize()`, a pre-existing, documented limitation — querying `users WHERE id
= $1` with a non-UUID LDAP username would throw on every request and silently demote every LDAP admin
to viewer). A DB-unreachable error during the re-check fails **closed** (`token.role = null`), not
open. **A second, smaller fail-open bug found in the same file was load-bearing for this fix**: both
`jwt()`/`session()` used to default a falsy role to `'admin'` (`user.role || 'admin'`, `token.role ||
'admin'`) — without flipping this to `VIEWER_ROLE`, a deleted user's freshly-set `token.role = null`
from the fix above would have been silently turned back into `'admin'` by that same fallback,
completely undoing the revocation fix. Both changes shipped together, not independently — fixing the
JWT staleness without fixing the fail-open default would not have actually closed the gap.

**⛔ MEDIUM — `PUT /api/settings` could partially commit a mutation before returning 403.** The
self-service password-change block (allowed for any role) ran and committed unconditionally *before*
the `feed_poll_interval_hours` admin check — so a single request combining both fields from a
non-admin session would silently rotate the password, THEN hit the admin gate and return 403 for the
whole call, with no signal to the caller that the password half actually succeeded. A naive retry
(a normal reaction to a 403) would then fail a second time too, since `current_password` no longer
matched the just-rotated hash. Fixed by moving the `isAdmin()` check for `feed_poll_interval_hours` to
run first, before any DB write — authorize everything the request asks for before mutating anything.

**Config-diff engine — a fourth round of fixes in the same area that already burned through three
rounds of user-driven "looks fixed, wasn't" earlier the same day** (see the `classifyDiff()` /
`truncatePathForDisplay()` entries above): (1) `classifyDiff()`'s Rule Changes table grouped rows by
the ALREADY-TRUNCATED display `ruleName`, so two entirely unrelated corrupted rule names that both
collapse to the identical `"(unreadable path...)"` placeholder (or share the same first 200 display
characters) silently merged into one fake group — an operator would see what looked like one rule's
change history but was actually two different rules' changes interleaved with no way to tell them
apart. Fixed by carrying a raw, pre-truncation `ruleGroupKey` through internally and grouping on
that instead, stripped back out before the public shape is returned. (2) `sectionLabelFor()` had
`'shared'` registered as its own `SECTION_LABELS` entry (`'Shared Config'`) — but PAN-OS nests real,
type-specific objects directly under it (`shared.address.*`/`shared.service.*`/`shared.nat.*`, a
shape this codebase's own `paloalto/parser.js` comments already document), and the root-to-leaf scan
returns on the *first* matching segment — so `shared` won before the scan ever reached `address`/
`service`/`nat` underneath it, collapsing every shared-scope object change into the generic bucket and
losing the type-specific breakdown this whole classifier exists to provide. Fixed by moving `'shared'`
into `WRAPPER_SEGMENTS` (skipped, not matched) instead of `SECTION_LABELS`. (3) Panorama's
`pre-rulebase`/`post-rulebase` segments (vs. a bare `rulebase`) weren't recognized by
`sectionLabelFor()`'s strict per-segment equality check (unlike `RULE_PATH_MARKER`'s substring match,
which already tolerated the prefix) — an unresolvable-index rule change under either fell through to
the uninformative generic fallback (`"Other (Pre Rulebase)"`) instead of the intended `"Rules (detail
unavailable for this device)"` label. Fixed with explicit `SECTION_LABELS` entries for both. (4)
`DiffViewer.js`'s `formatValue()` had no length bound on plain STRING values — unlike paths (bounded
by `truncatePathForDisplay`) and objects/arrays (bounded by `CollapsibleValue`'s
`LARGE_VALUE_THRESHOLD`), a very large or corrupted string VALUE (the same brace-corruption bug class,
this time landing as a value instead of a key) would dump inline unbounded — a milder recurrence of
the exact "wall of text" complaint this whole feature was built across three rounds to fix, just for
values instead of paths. Fixed with a mirrored `LARGE_STRING_THRESHOLD`/`CollapsibleString`, and every
render call site (`DiffValueRow`, `LabeledValue`, `DiffModifiedRow`, `RuleChangeValueCell`) updated to
route through a shared `needsBlockRender()`/`renderBlockValue()` pair instead of the old
object/array-only `isExpandableValue()` check.

**`lib/engines/ruleReorder.js` — resolved/unresolved finding counts could undercount.** The dedup
`edgeKeys` Set (correctly used to avoid inflating in-degree counts when two findings name the same
deny/allow pair) was ALSO being used, unmodified, as the loop driving the final
`resolvedFindingCount`/`unresolvedFindingCount` tally — so two distinct findings that collapsed to the
same edge only contributed one increment total, not one each, undercounting relative to the function's
own documented contract ("two findings can independently name the same deny/allow pair"). Not
currently reachable via the app's real data flow (`ruleAnalysis.js`'s `reorder_candidate` generator
breaks after the first covering allow per deny rule, so a given `denyId` can only ever produce one
finding per device today) — a latent defect in the pure function's own accounting, not a live bug, but
fixed anyway (a `Map<edgeKey, count>` tracked separately from the dedup Set, added into the tally
instead of a flat `+= 1` per unique edge) since the two counts are already returned verbatim in `GET
/api/devices/[id]/reorder-recommendation`'s JSON body for any future consumer.

**UI-consistency gaps, both real but not security holes (server-side enforcement already held in
both cases)**: (1) `app/(dashboard)/devices/page.js` gated "Add Device"/"Delete" behind `canWrite` but
left `DeviceRowActions` (the inline Collect/Test buttons) unconditionally visible — a viewer saw
clickable buttons that would 403 and show a small `⚠` icon, instead of the control simply not being
there, unlike the device DETAIL page's equivalent `DeviceActions` (already correctly gated). Fixed by
wrapping it in the same `{canWrite && ...}` pattern used two lines below for Delete. (2) The Settings
page rewrite (same day, same session, immediately after RBAC shipped) never fetched session/role at
all — the Feed Sync "Save" button and the entire Updates tab (`UpdatePanel`, "Update Now") rendered
fully visible and clickable for a viewer, unlike every OTHER page touched in the RBAC pass, which all
resolve `canWrite` server-side via `getServerSession`. Settings stays a plain `'use client'` component
with no server-passed session prop (a deliberate earlier design choice — see "Settings Page — Tabbed
Layout" above), so there's no `getServerSession` available inside it; fixed instead via NextAuth's own
built-in `GET /api/auth/session` endpoint, fetched client-side into a new `isAdminUser` state
(defaults to `false`, fail-closed, same "hidden until proven admin" posture `UsersPanel`'s own
`visible` state already uses) — the Save button and the whole Updates tab now only render once that
resolves `true`.

**`components/settings/UsersPanel.js` — a genuine network failure was indistinguishable from a
viewer-role 403 hide.** `loadUsers()`'s `fetch('/api/users')` call had no try/catch — if `fetch()`
itself rejected (a true network-level failure: dropped connection, blocked request, DNS hiccup — as
opposed to resolving with a non-2xx status, which the existing `.catch(() => ({}))` on `res.json()`
already handled fine), the unhandled rejection meant `visible` never left its initial `false`, so the
whole Users card silently vanished with zero error message — an ADMIN hitting a transient network
blip would see exactly what a viewer sees on purpose, with no way to tell the two apart, potentially
concluding they'd lost admin rights entirely. Fixed with a new `loadError` state: a genuine
fetch-level exception now keeps the panel visible and shows a "Failed to load users" message with a
Retry button, while the deliberate 403 hide path is completely unchanged.

**`lib/schema.sql`** — one straightforward doc-drift fix: the `users` table's header comment
referenced a function named `seedUsersFromLegacyAdmin()`, which doesn't exist anywhere in the
codebase (the real function, doing exactly what the comment describes, is `seedUsers()` in
`lib/migrate.js`) — corrected to the real name.

**Result:** 10 files touched (`app/api/analysis/run/route.js`,
`app/api/auth/[...nextauth]/route.js`, `app/api/settings/route.js`, `lib/schema.sql`,
`components/settings/UsersPanel.js`, `lib/engines/ruleReorder.js`, `lib/engines/configDiff.js`,
`components/config/DiffViewer.js`, `app/(dashboard)/devices/page.js`,
`app/(dashboard)/settings/page.js`), every fix's `node --check` passing individually during the fix
phase, every diff personally re-reviewed against its finding before integrating, `npm run build`
clean end to end.

### ⚠️ Bugs Found and Fixed During MVP Build (v1.0.0)

Real production traps discovered during the Phase 1+2 build — documented here so they are never
reintroduced.

**1. NVD API parameter: `virtualMatchString` not `cpeName` for wildcard queries.**
The NVD 2.0 spec documents `cpeName`, but live testing proved it 404s on wildcard CPE strings.
`virtualMatchString` is correct. See "Forcepoint CVE Data" above. Would have silently broken every
feed sync with zero advisory data and no obvious error.

**2. Next.js static prerendering of DB-hitting API routes.**
Every API route handler under `app/api/` that calls `pool.query()` must export:
```javascript
export const dynamic = 'force-dynamic';
```
Without it, `npm run build` tries to statically prerender that route, hits the DB at build time
(before the DB necessarily exists/is reachable), and the build crashes. Add this export to every
route that touches the database.

**3. Schema privilege split: `schema.sql` + `lib/schema-grants.sql`.**
The original `schema.sql` tried to create readonly diagnostic roles (`claude_readonly`,
`nocvault_readonly`) inline. `secvault_user` (the account `lib/migrate.js` connects as) has no
`CREATEROLE` privilege — and because PostgreSQL treats a multi-statement `pool.query()` call as one
implicit transaction, that permission failure would have rolled back every `CREATE TABLE` in the
same call, silently breaking every fresh install. Fixed by splitting into two files — see "Schema
Migration" and "Readonly Access for Diagnostics" above.

**4. `next` 14.2.5 → 14.2.35 (critical npm vulnerability).**
Bumped during the MVP build to close a critical advisory set (same 14.2.x minor line, no breaking
changes). One remaining **moderate** vulnerability in `uuid` (pulled in via `next-auth`/`node-cron`)
requires a breaking major-version bump — deferred at the MVP deadline. Resolve before first
customer deployment.

### SMC API
- **Field names vary between SMC 6.x and 7.x.** The software version field is not consistently named. Always log raw element responses on first integration test, then update `parser.js`.
- **Pagination**: SMC lists can return partial results with a `paging.next` href. Always follow pagination for engine lists — some large environments have 50+ engines.
- **HATEOAS**: never construct URLs from element IDs. Use the `href` from the list response.
- **Live SMC field verification still pending** — the MVP was built without a live SMC instance. The first real connection to a Forcepoint 6.x or 7.x SMC will require checking the raw engine element response (already logged via `console.log('[SMC Debug] ...')` in `smc.js`) and updating `lib/adapters/forcepoint/parser.js` field-name fallbacks accordingly.

### NVD CPE Matching
- **Use `virtualMatchString` for wildcard queries** — see MVP bug #1 above. Never revert to `cpeName`.
- **CPE strings are approximate.** The exact vendor/product strings in NVD CPE dictionary may differ from what is documented. Verify via: `https://services.nvd.nist.gov/rest/json/cpes/2.0?keywordSearch=forcepoint`
- **Forcepoint rebrand coverage**: Some NVD entries for FlexEdge versions may still reference the NGFW CPE string (vendors are inconsistent about updating CVE records after rebrand). Query both strings always.
- **Version ranges in NVD**: `versionEndIncluding` means the vulnerability affects UP TO AND INCLUDING that version. `versionEndExcluding` means UP TO BUT NOT INCLUDING. Get this backwards and you'll mark patched devices as vulnerable.

### Next.js API Routes
- **Every API route that hits the DB must export `dynamic = 'force-dynamic'`** — see MVP bug #2 above. Without it, `npm run build`'s prerendering step will crash on any route calling `pool.query()`.

### Schema Files
- **Two schema files, two privilege levels** — see MVP bug #3 above. Never merge `schema-grants.sql` back into `schema.sql` — doing so will break fresh installs.
- Every new table added to `schema.sql` needs a corresponding `GRANT SELECT` added to `schema-grants.sql` — both `Install-SecVault.ps1` and `Update-SecVault.ps1` apply it automatically on every run (see "Update Script" and "Schema Migration" above), so no manual `psql` step is needed for this specific case anymore. Manual reapplication is only needed if `.env.local` predates `PG_ADMIN_PASSWORD` or its value has gone stale (e.g. the postgres superuser password was changed outside these scripts).

### Rule Shadow Analysis
- Shadow detection is O(n²) against rule count. For large rulesets (500+ rules), cap at 1000 rules or run off-hours. Log a warning when ruleset size exceeds threshold.
- Address object resolution requires loading all `network_elements` and `service_elements` from SMC before rule analysis. Cache these per device per session.

### Windows Server Specifics
- `psql.exe` path: `C:\Program Files\PostgreSQL\16\bin\psql.exe`
- Git path: `C:\Program Files\Git\cmd\git.exe`
- NSSM path: `C:\Windows\System32\nssm.exe`
- All paths in PowerShell scripts must use `\` not `/`

### PostgreSQL via psql in PowerShell
- `psql` can return exit code `-1` in WinRM sessions even on success (when any output goes to stderr). Accept `-1` as a success code for schema migration.
- Set `$env:PGPASSWORD` before calling `psql` for unattended execution.

---

### ⚠️ Bugs Found and Fixed — full-day orchestrated sweep (2026-07-21, eighth pass)

Run as a single Workflow (7 parallel dimension finders → adversarial verify-per-finding → fix grouped
by file → personally re-reviewed the highest-stakes diffs before integrating), scoped to everything
built in one day: Credential Profiles, SNMP Monitoring (Phase 1, all 5 vendors), the Device Overview
Tab, and the two infrastructure fixes (in-app updater SSH path handling, the Collect Now event-loop
freeze fix). 17 findings, all independently confirmed, all fixed same-pass.

**⛔ HIGH — `PUT /api/devices/[id]` could permanently delete a device's working credential on a
request that ultimately 400s.** The stale-`device_credentials` cleanup `DELETE` (added in an earlier
bug-sweep pass, for a genuinely different bug) ran *before* the newer `credential_profile_id`
resolution/validation block introduced by Credential Profiles. A vendor/method change combined with a
stale or wrong-type `credential_profile_id` in the same request let the DELETE commit (no transaction
wraps this handler — every `pool.query()` commits independently), then 400 out of the later validation
check before `setCredential()` ever ran — leaving a device with zero usable credentials, silently,
discoverable only on the next Collect/Test failure. Fixed by moving the entire credential-resolution/
validation block ahead of the DELETE, restoring the function's own documented invariant ("validated
BEFORE any write happens"). **Lesson**: adding a new validated-write path to a handler that already has
an earlier, unconditional side effect requires checking whether the new validation needs to move
earlier too — appending new logic at its "natural" spot near the related write is not automatically
safe when something upstream already commits irreversibly.

**⛔ HIGH — the SNMPv1/v2c cleartext-acknowledgment gate had a truthy-string bypass.** `PUT
/api/devices/[id]/snmp` checked `!insecure_ack`, so a client sending `insecure_ack: "false"` (a JSON
string, not the boolean) evaluated as truthy and sailed through the check meant to require an explicit,
informed opt-in before storing a credential that goes out in cleartext on the wire. Fixed to
`insecure_ack !== true` — only the literal boolean satisfies the gate now, matching the security intent
CLAUDE.md's own "SNMP Monitoring" section describes ("the same gate is enforced SERVER-SIDE... a direct
API call cannot bypass the warning by skipping the UI" — true again after this fix, wasn't quite true
before it).

**⛔ MEDIUM — the earlier Collect-Now freeze fix (yieldToEventLoop in `analyzeRules()`) widened a
pre-existing, previously-narrow concurrency race into an actually-reachable one.** `runAnalysisForDevice()`
has always been callable concurrently for the same device from two independent paths (`collectAndStore()`
and the manual "Run Analysis" route) with no per-device lock — but before the async-yielding fix, the
O(n²) analysis ran as one uninterrupted synchronous block, which incidentally made the window for a
second concurrent call to interleave its own DELETE+INSERT vanishingly small. Making `analyzeRules()`
yield to the event loop every 25 iterations reopened that window for real: two concurrent runs could now
each reach BEGIN/DELETE/INSERT/COMMIT while the other was still mid-computation, and whichever committed
second would silently overwrite the other's just-committed findings with results computed from a
possibly-stale rule snapshot. Fixed with a `pg_advisory_xact_lock(hashtext(device_id))` inside the
transaction — the exact same fix `lib/engines/versionMatcher.js` already applies for the identical race
on `device_cve_assessments`. **Lesson**: a fix that changes *when* control yields (not *what* gets
computed) can still change correctness, by changing the concurrency exposure of code that was already
reachable from multiple call sites — re-check every performance/responsiveness fix for this, not just
its own stated behavior-preservation claim.

**Credential Profiles — two more real bugs**: (1) `app/api/credential-profiles/route.js`'s
duplicate-name check (`SELECT` then `INSERT`, not atomic) let two concurrent same-name creates both pass
the pre-check and race to the real `UNIQUE` constraint — the losing request got a raw Postgres
constraint-violation message as a 500 instead of the intended clean 409; fixed by catching
`err.code === '23505'` and translating it (the sibling `[id]/route.js` PUT rename path has the identical
gap, flagged but not fixed in this pass — same fix needed there on a follow-up). (2)
`CredentialProfilesPanel.js`'s rotate-secret form always reset to SNMPv3 defaults regardless of the
profile's actual stored version, so rotating an existing v1/v2c SNMP profile showed the wrong fields
(v3 username/auth/priv instead of the community-string field it needed) — fixed by detecting the stored
version from the already-fetched, non-secret profile metadata (a v3 profile always has a `username`, v1/
v2c never does) and defaulting the form accordingly.

**SNMP credential/adapter correctness, five findings**: (1) `lib/credentialProfiles.js`'s SNMPv3
`buildProfilePlaintext()` branch didn't validate `authProtocol`/`privProtocol` against the real enum or
enforce "priv requires auth" the way the device-route builder already did, so a profile could be saved
with an inconsistent shape (e.g. `privPassword` set with no `authPassword` at all) — fixed to mirror the
device route's construction logic exactly. (2) `lib/adapters/snmpCredential.js`'s `parseSnmpCredential()`
could silently accept that same inconsistent shape and return a half-populated credential (auth password
present, protocol null) — now throws a clear, secret-free error instead of letting `snmpClient.js`
silently downgrade the session to `noAuthNoPriv`. (3) `SnmpConfigForm.js`'s cleartext-ack checkbox never
reset after a successful save, so a stale acknowledgment could carry into a later, unrelated community-
string entry in the same session, submitting `insecure_ack: true` without a fresh click — fixed to reset
alongside the other secret fields. (4) `lib/snmpClient.js`'s outer hard-timeout margin was a flat 3000ms,
but net-snmp's own retry cycle (1 retry, no backoff growth) needs up to `timeoutMs * 2` to naturally
exhaust — so the "backstop for the rare case net-snmp's callback never fires" outer race was actually
firing mid-retry on every ordinary unreachable-device timeout. Fixed to scale the margin with
`timeoutMs * DEFAULT_RETRIES` so the backstop only ever fires after net-snmp's own natural sequence would
have completed. (5) Cisco ASA's and Forcepoint's `getSnmpMetrics()` ran their multiple `walkSubtree()`
calls (CPU/memory/session tables) with no per-table try/catch, so one failing table walk threw and
discarded every ALREADY-obtained metric (including uptime, which had already succeeded) — a poll that
should have degraded to partial data (per `interface.js`'s own contract: null for an unresolved OID, not
a thrown error for the whole call) instead produced nothing at all. Fixed to match the pattern already
correct in `lib/adapters/paloalto/index.js` — each table walk gets its own try/catch, defaulting to an
empty result on failure.

**UI-consistency and doc-accuracy gaps**: (1) `app/(dashboard)/devices/[id]/snmp/page.js` had no RBAC
gating at all — a viewer saw the live Save/Test SNMP config form, which would 403 on submit, instead of
a read-only view (every other write surface in this session's earlier RBAC pass gates this way; this
page, built during the SNMP feature the same day, was missed). Fixed by gating `SnmpConfigForm` behind
the same `canWrite` convention used elsewhere. (2) The always-visible SNMP summary card on
`devices/[id]/page.js` could show a self-contradicting state — "Not Configured" badge next to real,
already-polled CPU/Memory/Session numbers — because the badge only checked `device.snmp_enabled` while
the content below it also treated a present `snmp_metric_snapshots` row as live (reachable via the
on-demand Test Connectivity flow, which inserts a snapshot without ever setting `snmp_enabled`). Fixed
to treat either signal as "enabled" for the badge/link. (3) `RuleHygieneDonut.js`'s legend was gated on
`total > 0`, so a genuinely clean ruleset (zero findings of any kind) showed no legend at all —
contradicting CLAUDE.md's own documented guarantee that a zero-count category "still appears in the
legend at 0." Fixed to gate on the category list's own length instead of the total count. (4) Two stale
comments corrected: `OverviewRuleHygieneCard.js`'s header claimed it was "not wired into any page yet"
(it already is, on the Overview tab), and the "SNMP Monitoring" CLAUDE.md section's own UI subsection
still described the SNMP card's original always-visible-above-the-tab-bar placement without noting it
was superseded by the same-day move into the Overview tab — both corrected/marked.

**Result:** 16 files touched, every fix `node --check`ed individually during the fix phase, the
highest-stakes diffs (the credential-deletion ordering fix, the cleartext-ack bypass fix, and the
advisory-lock concurrency fix) personally re-reviewed against their findings before integrating,
`npm run build` clean end to end (after `npm ci` — `net-snmp` was declared in `package.json` but not yet
installed in this environment's `node_modules`, unrelated to the sweep itself).

### ⚠️ Bugs Found and Fixed — full-day orchestrated sweep (2026-07-22, ninth pass)

Requested as "a complete bug sweep for all changes we made today" — the whole day's work, from the
device-detail-page restructure through the Rule Analysis Intelligence round ("Path A":
`generalization`, `external_exposure`, exposure correlation, the Reachability and Relationships tabs)
through Zone Classification's two full rebuilds (global → per-device) and the live migration-ordering
production incident fixed earlier the same day. Run as a single Workflow: 6 parallel finders, one per
subsystem, each told to read the real current file content rather than trust a description; every
candidate finding individually adversarially verified (told to default to REFUTED unless it could
personally trace the exact failure through the actual code); confirmed findings grouped by file and
fixed by one agent per group so nothing collided; every fix diff personally re-reviewed against its
finding, plus a full rebuild and re-run of every existing smoke test, before integrating. 11 candidate
findings, all 11 survived verification — collapsing to 5 real distinct bugs (several findings across
different dimensions independently rediscovered the same 2 underlying bugs, a good convergent-validity
signal rather than 11 separate problems).

- **`app/(dashboard)/devices/[id]/page.js`**: the Delete Device confirmation `<Modal>` was gated only on
  the `confirmDelete` query param, not on `canWrite` — a viewer session navigating directly to
  `/devices/<id>?confirmDelete=1` (works from any tab, not just Manage) saw a fully-rendered delete
  confirmation with a real, working-looking Delete button, escaping this page's own documented
  "double-gated, tab link and content both" admin-only design for the Manage tab this dialog is reached
  from. Not a data-loss bug — `deleteDeviceAction`'s own server-side `isAdmin()` check still blocked the
  actual delete — but a real UI/defense-in-depth gap exposing an admin-only workflow to non-admins.
  Fixed by wrapping the whole `<Modal>` in `{canWrite && (...)}`, matching every other admin-only control
  on this page.
- **`lib/engines/exposureCorrelation.js`** (Path A, shipped this same day) — two real bugs, found
  independently by 4 of the 6 dimensions between them: (1) `EXPOSURE_FINDING_TYPES` was never updated
  to include `external_exposure` after that finding type shipped later the same day, despite it being —
  per the file's own header comment framing "exposure-widening" findings — arguably the single most
  on-point finding type of the four for this exact feature. (2) Neither the rule-findings query nor the
  CVE-assessments query joined against their respective acknowledgement tables
  (`finding_acknowledgements` / `cve_assessment_acknowledgements`), so a rule finding or CVE an operator
  had already dismissed or actioned elsewhere in the app still rendered on the Overview tab's Exposure
  Risk card labeled "open" — directly contradicting both the UI's own copy and every other "open"
  query's established convention in this codebase. Fixed: added `external_exposure` to the type list;
  added the same `LEFT JOIN ... WHERE (status IS NULL OR status = 'new')` shape `app/api/events/route.js`'s
  `fetchPatchNow()` already uses (the STRICTER of two historical definitions this codebase already
  debated and settled on 2026-07-18 — see that section above — "acknowledged" does not count as open,
  only a bare `new`/unset status does) to both queries.
- **`lib/engines/ruleAnalysis.js`** — the new `generalization` pairwise loop (Path A) could double-report
  the identical rule pair as both `generalization` and `shadow`, or both `generalization` and
  `correlation`, with contradictory remediation advice on the same two rules. It only excluded pairs
  already claimed by `redundant` (via its `fieldsFullyEqual` check) — unlike the `correlation` loop's own
  already-established guards, it never checked the reciprocal `ruleCovers(s, r)` direction or
  `shadowPairs`/`correlationPairs`. Fixed by adding the identical three guards `correlation`'s loop
  already has. Verified against two synthetic constructions that previously reproduced the double-report
  exactly (a literal-superset-destination pair that should be `correlation`-only, and a mutual-CIDR-
  coverage pair via differing host bits that should be `shadow`-only) — both now report exactly one
  finding type, confirmed via the existing smoke-test file, extended with these two new cases.
- **`lib/engines/configAuditor.js`** — `evaluateExternalToInternalExposure()`'s `'na'` detail string
  (shown on the compliance check detail page, the standards page, the print report, and the CSV export)
  still told the operator to go to "Settings > Zones" — found independently by 3 of the 6 dimensions,
  all pointing at the exact same line. That page was deleted the same day, hours earlier, when Zone
  Classification was rebuilt per-device onto each device's own Manage tab (see that section above) — this
  one string was the only place in the whole rebuild that never got updated to match. Fixed to reference
  "this device's Manage tab" instead, matching the wording already used correctly in
  `ZoneClassificationBanner.js`/`OverviewComplianceCard.js`.
- **`lib/migrate.js`** — low severity, real but narrow: `migrateZoneClassificationsToPerDevice()`'s
  `DROP CONSTRAINT` cleanup only targeted the ORIGINAL global schema's constraint name
  (`zone_classifications_zone_name_key`), not the incorrectly-named duplicate constraint
  (`zone_classifications_device_zone_key`) an EARLIER revision of this exact same function (commit
  `ad0a0a7`, live for roughly 23 minutes before being superseded by the `6abc1d4` production-incident
  fix) would have mistakenly created on any server fresh-installed during that narrow window. Added a
  second `DROP CONSTRAINT IF EXISTS` for that name too — a safe no-op on every server outside that window,
  real cleanup for any server that happened to install during it.

All 5 fixes verified independently (not just trusted from each fix agent's own report): every diff
personally re-read against its finding, `node --check` on all 4 CommonJS files, a full `npm run build`,
and a full re-run of every pre-existing smoke test for the touched engines (`ruleAnalysis.js`'s
`generalization`/`external_exposure` cases, `configAuditor.js`'s na/pass/fail cases) — all green, no
regressions.

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
