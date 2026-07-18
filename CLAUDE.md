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
| `advisories` | Normalized CVE advisory store (all feed sources) | 1 |
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

---

## Fleet Alerts Page (v2.1.0 — `/alerts`)

Fixes a real UX gap: the header notification bell (`components/layout/NotificationBell.js`)
surfaces fleet-wide "needs attention" items (new rule findings, patch-now CVEs, unacknowledged
config diffs), but until this phase every click either dropped the operator onto an unrelated
device page or, for the dropdown's static footer link, onto the fleet Rule Analysis summary —
there was nowhere the bell itself could lead to actually acknowledge/resolve anything.

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

### `audit_checks.standards` is `TEXT[]`, not a single value

The compliance spec's own standard-mapping ("logging checks → PCI_DSS + ISO_27001," "access-control
checks → PCI_DSS + CIS_V8 + ISO_27001 + NIST") requires ONE check to score against MULTIPLE
standards simultaneously — a single-value column can't represent that many-to-many relationship. A
plain Postgres array avoids a join table for what is small, rarely-changing curated data (same
tradeoff `affected_version_ranges`/`fixed_in_versions` already make as JSONB instead of child
tables). `node-postgres` returns this as a real JS array automatically — no parsing needed on read.

### Seed library — `lib/auditChecksSeed.js`, called from `lib/migrate.js`

28 checks (8 shared concepts × 2 vendors, since Fortinet's and Palo Alto's `config_parsed` trees
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
(up to 5 items + "+N more"). **The two pages' cards mean something different in that quick-list**:
per-device (`compliance/[deviceId]/page.js`) shows the actual failing CHECK NAMES (derived from the
already-fetched `findings` array — no new query); fleet-wide (`compliance/page.js`) shows which
DEVICES have at least one failure for that standard (a new, separate `getFleetFailedDevicesByStandard`
query — a check-name list wouldn't say *where* at fleet scale, since the same check can fail
identically across many devices). At `scorePct === 100` the card shows a `Badge color="success"`
"Fully Compliant" in place of the failed-list (no emoji anywhere in this codebase, confirmed by grep
before choosing this — see `StandardCard.js`'s own comment).

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
