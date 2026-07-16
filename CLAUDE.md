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
| CSS | Tailwind CSS 3.4.x |
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
├── tailwind.config.js
├── .env.local.example               ← committed (no secrets)
├── .env.local                       ← gitignored (has secrets)
├── middleware.js                    ← route protection (auth gate)
├── app/
│   ├── layout.js                    ← root layout
│   ├── globals.css                  ← design tokens (CSS variables)
│   ├── (auth)/login/page.js
│   ├── (dashboard)/
│   │   ├── layout.js                ← sidebar + header wrapper
│   │   ├── page.js                  ← main dashboard
│   │   ├── devices/                 ← device inventory
│   │   ├── cve/                     ← fleet CVE posture
│   │   └── advisories/              ← advisory browser
│   └── api/
│       ├── auth/[...nextauth]/route.js
│       ├── devices/                 ← CRUD + test/collect actions
│       ├── advisories/
│       ├── cve/
│       ├── feeds/                   ← feed sync trigger + status
│       └── settings/
├── lib/
│   ├── db.js                        ← PostgreSQL pool singleton
│   ├── schema.sql                   ← tables (CREATE TABLE IF NOT EXISTS, runs as secvault_user)
│   ├── schema-grants.sql            ← readonly roles + per-table grants (runs as postgres superuser)
│   ├── migrate.js                   ← runs schema.sql
│   ├── credStore.js                 ← AES-256-GCM credential encryption
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
│   ├── ui/                          ← shared components
│   ├── layout/                      ← Sidebar, Header
│   ├── devices/
│   └── cve/
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
| `firewall_logs` | Ingested syslog events (with retention expiry) | 8 (not yet created) |
| `audit_checks` / `audit_findings` | Compliance check library + results | 7 (not yet created) |
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
- Coverage tests are string-equality provable-only (no CIDR math) — deliberately conservative to avoid false shadows

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
  and a hand-built Tailwind-only bar chart (no charting library in this repo — see the
  `FindingTypeBarChart` component in that page for the convention: div height as a `%`,
  colored via the same severity→Tailwind-class mapping `SeverityBadge` already uses).

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

## Feed Sources

| Feed | URL | Schedule | Notes |
|---|---|---|---|
| NVD API 2.0 | `https://services.nvd.nist.gov/rest/json/cves/2.0` | Every 6h | Rate: 1 req/6s without key, 5 req/30s with `NVD_API_KEY`. Multi-vendor: `VENDOR_CPES` in `lib/feeds/nvd.js` maps every vendor slug to live-verified CPE strings (cisco_asa needs BOTH `o:` and `a:` part variants — NVD is split). Always `virtualMatchString`, never `cpeName`. |
| CISA KEV | `https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json` | Every 6h | Full download, cross-reference by cve_id |

### NVD Rate Limiting

Implement exponential backoff on 403/429:
```javascript
// Base: 6s delay between requests (no API key)
// On 429: wait 30s then retry
// On 403: log and skip (API key issue)
// Never hammer NVD — will get IP banned
```

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

## Design System — Dark Theme

CSS variables in `app/globals.css`. Match NocVault suite visual language.

```css
:root {
  --bg-base:         #0f1117;   /* page background */
  --bg-sidebar:      #1a1d27;   /* sidebar */
  --bg-surface:      #1e2130;   /* cards, panels */
  --bg-elevated:     #252840;   /* modals, dropdowns */
  --border:          #2a2d3e;   /* all borders */
  --text-primary:    #e2e8f0;
  --text-secondary:  #94a3b8;
  --text-muted:      #64748b;
  --accent:          #6366f1;   /* indigo — primary action */
  --accent-hover:    #4f46e5;
  --success:         #10b981;   /* emerald */
  --warning:         #f59e0b;   /* amber */
  --danger:          #ef4444;   /* red */
  --info:            #3b82f6;   /* blue */
}
```

Priority band visual encoding:
- `patch_now` → `--danger` (#ef4444), label "Patch Now"
- `scheduled`  → `--warning` (#f59e0b), label "Scheduled"
- `monitor`    → `--text-muted` (#64748b), label "Monitor"
- KEV badge → solid `--danger` background, white text, "KEV" label

---

## Versioning Policy

- Version tracked in `package.json`
- **Bump patch** on any push that touches UI or logic
- **Bump minor** on new feature or phase completion
- **Bump major** on breaking schema changes or major architectural shifts
- Update detection: git commit hash comparison (same as NocVault suite pattern)
  ```javascript
  // Check for updates: compare current git hash to latest GitHub API response
  GET https://api.github.com/repos/amrin78-smb/secvault/commits/main
  // → compare sha to locally stored hash
  ```

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
