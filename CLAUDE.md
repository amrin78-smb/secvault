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
- **Check Point `getVersion()`/`getConfig()` still use `findGateway()`'s "first gateway" fallback**, so
  on a name mismatch they can report another gateway's version/config. Less destructive than the
  `packages[0]` rules bug (which is fixed), but the same class. Open.
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

9 finding types with fixed severities: `any_any` (critical); `risky_service`, `shadow`, `reorder_candidate` (high);
`redundant`, `overly_permissive`, `unused`, `expiring_soon` (medium); `log_disabled` (info).
- Runs automatically after every rule pull (inside `collectAndStore`) — findings are DELETE+reinserted per device
- `rule_analysis_results.rule_id` cascades from `firewall_rules`, which is itself rewritten each pull — safe because
  analysis always reruns immediately after the rewrite
- Shadow/redundant/reorder analysis is O(n²) and **skipped entirely above 1000 rules** (warning logged)
- Optional overrides via `settings` keys: `rule_unused_days`, `rule_expiry_window_days`, `risky_ports` (JSON array)
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

`/compliance` (fleet matrix: devices × standards, colored green >80% / amber 60–80% / red <60% /
muted null) and `/compliance/[deviceId]` (per-device: 4 score tiles + client-side standard tabs —
a deliberate, documented exception to this app's usual `?tab=` server-navigation convention,
since here all 4 standards' findings are already in one fetched payload and a full page reload per
tab would just re-fetch identical data). Both pages query the DB directly rather than fetching their
own paired API route, same "server components query the DB directly" convention as the Alerts page
— the API routes exist for `RunAuditButton`'s POST and any future client-side consumer, not for
these pages' own initial render; the aggregation SQL is therefore intentionally duplicated in 4
places (both API routes + both pages) and must be kept in step by inspection if the scoring formula
ever changes, same caveat as the Alerts/events split above.

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
  **Not yet confirmed against a real "Update Now" click** — same caveat this file's Live Validation
  Status section applies to vendor adapters: doc-derived reasoning, first live exercise is the real
  verification step.

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
