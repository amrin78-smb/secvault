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
- `.ai-codex/application-view-plan.md` — PROPOSAL ONLY (not built): the application-centric view
- `.ai-codex/central-cve-feed-proposal.md` — PROPOSAL ONLY (not built): moving CVE collection
  into the central nocvault-eol service and syncing a signed feed

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
`npm test` + `npm run build` before every commit — full checklist under Claude Code Workflow's
"Before Committing" at the end of this file. ⛔ **`node --check` is a NO-OP on any file with a
top-level `import`** (measured 2026-09-19: four different syntax errors, all exit 0 in ESM, all
exit 1 in CommonJS), so it is a real gate for `lib/**` and `services/**` and worth nothing for
`app/**`. `npm test` is the syntax gate — `tests/jsxSyntax.test.js` parses every file with SWC.

---

## Architecture

### Services (3 NSSM Windows Services)

| Service | Command | Port | Purpose |
|---|---|---|---|
| `SecVault-App` | `next start -p 3010` | 3010 (public) | Next.js frontend + API routes |
| `SecVault-Engine` | `node services/engine-worker.js` | None | Scheduled jobs (feeds, CVE match, config pull) |
| `SecVault-Collector` | `node services/collector.js` | 514 UDP/TCP | Syslog listener (Phase 8a — BUILT 2026-09-08) |

### TLS (v2.112.0)

⛔ **`next start` CANNOT SERVE TLS** — there is no flag for it, in any version. So the
`SecVault-App` service's NSSM `AppParameters` points at **`server.js`**, which wraps the same Next
request handler in `https.createServer`. **Rollback is one command:**
`nssm set SecVault-App AppParameters "node_modules\next\dist\bin\next start -p 3010"`.

Three listeners, and the second is the non-obvious one:

| port | what |
|---|---|
| 3010 | HTTPS — **the port is deliberately unchanged**, so every bookmark, ticket link and firewall rule still resolves |
| 3010 | …and plaintext HTTP on the SAME port, answered with a 301 to https |
| 3080 | plain HTTP, redirect only |

⛔ **The same-port plaintext redirect is not a nicety.** A plaintext request into a TLS listener is
not a redirect, it is a protocol failure — an old `http://host:3010` bookmark would get an
unexplained connection error. A TLS handshake begins with byte `0x16`; `server.js` peeks the first
byte and routes the connection to either the TLS server or a redirect server. ⛔ The `socket.unshift`
is load-bearing: the byte has already been consumed, and without pushing it back every request loses
its first character.

⛔ **THREE transport states, never two** (`lib/tlsConfig.js`): `active` / `disabled` (no certs — how
this product shipped for its whole life, not an error) / `failed` (certs configured, could not be
loaded). **`failed` must never look like `disabled`** — the operator asked for TLS and is not getting
it, and a reader concluding "we're encrypted" when they are not is the failed-read-as-a-fact rule at
its most dangerous. It logs a banner at error level every start and is reported in Settings.

⛔ **A broken certificate DEGRADES to HTTP rather than refusing to start.** On a firewall-management
platform an outage means nobody can see the fleet, which has its own security cost. That is only
safe BECAUSE `failed` is never silent — do not make it quiet.

### ⛔ Console address — settable from Settings (v2.155.0)

**Settings → Certificate → Console address** writes `NEXTAUTH_URL` to `.env.local`, so changing the
name the console answers on no longer means editing a file over RDP. It sits beside the certificate
deliberately: a certificate for a new hostname is useless until SecVault is told it is reached on
that hostname, and the two changes are made in the same sitting.

⛔ **IT IS THE MOST DANGEROUS FIELD IN SETTINGS, so the validation IS the feature.**
`lib/consoleUrl.js` is pure and separately tested. It REFUSES (never warns about) a scheme that
disagrees with the transport, a trailing path, a query/fragment, and embedded credentials — each of
which produces a callback URL that fails sign-in with no visible error. A missing scheme is caught
BEFORE `new URL()`, which otherwise parses `host:3010` as a protocol and reports the hostname as an
unsupported one.

⛔ **THE LOCKOUT GUARD.** A host that resolves somewhere other than this server needs explicit
confirmation (HTTP 409 + `needsConfirmation`), because that typo is the one way to make the console
unreachable by the person who made it. ⛔ An UNRESOLVABLE host is `pointsHere: null` — neither a pass
nor a refusal: an internal name may resolve from every workstation and not from this host, and
refusing a correct address because our own resolver is unhappy is its own lockout.

⛔ **`lib/envFile.js` GUARDS THE FILE THAT HOLDS EVERY SECRET** — `CREDENTIAL_KEY`, the database
password, `NEXTAUTH_SECRET`. It does a LINE EDIT (comments, ordering and untouched values survive
byte for byte), backs up first, and then RE-READS AND VERIFIES that every other key is unchanged,
restoring the backup if not. ⛔ It writes IN PLACE rather than by rename, so an ACL on `.env.local`
is not silently replaced by a fresh default. ⛔ A **duplicated key is refused**, not guessed at: which
copy a loader honours is the loader's property, and editing the wrong one reports success while
changing nothing — found by a test where the writer replaced the first occurrence and the parser
read the last.

⛔ **A restart is required and is stated in the API response, not only in the UI.** The panel shows
the saved value and the RUNNING value separately whenever they differ.

⛔ **`NEXTAUTH_URL` must follow the scheme.** NextAuth builds its callback from it; left on `http://`
while the server speaks https, the cookie is issued for an origin the browser is not on and every
sign-in silently bounces back to the login page with no error anywhere. The updater flips it, and
`server.js` logs loudly if the two disagree.

⛔ **The upgrade verifies and ROLLS BACK.** "Service Running" is not "app serving" — NSSM restarts a
crashing process, so `sc.exe` reports Running while node crash-loops. `Update-SecVault.ps1` probes
`https://127.0.0.1:<port>/api/health` after starting, and on no answer restores the previous
`AppParameters` and `NEXTAUTH_URL`, clears the cert paths and restarts on plain HTTP.

⛔ **Certificates are minted with OpenSSL, not `New-SelfSignedCertificate`** — on PS 5.1 the latter
can only export PFX (.NET Framework has no PKCS#8 private-key export) and node is being handed PEM.
Git for Windows is already a hard dependency and bundles OpenSSL; `installer/SecVault-Tls.ps1` is
shared by both installer scripts so they cannot drift. ⛔ **SANs are mandatory** — browsers ignore the
CN entirely — and an existing certificate is **never overwritten**, so an operator's real corporate
certificate survives every upgrade.

**Settings → Certificate** (`manage_settings`) shows subject/names/expiry and installs a replacement.
⛔ It validates the pair with `X509Certificate.checkPrivateKey()` BEFORE writing: a mismatched
certificate and key both parse perfectly and fail only at the next restart, weeks later, during an
unrelated upgrade. It backs up the previous pair, and states that a service restart is required —
node reads the certificate once, at startup.

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

### Idle session timeout (v2.159.0)

`lib/sessionPolicy.js` (pure) owns the whole policy; `SESSION_IDLE_MINUTES` (default **30**, `0`
disables, clamped 2-1440) drives NextAuth's `session` block, and Settings -> Security writes it via
`lib/envFile.js`.

⛔ **THERE WAS NO TIMEOUT AT ALL.** `session: { strategy: 'jwt' }` with no `maxAge` means
NextAuth's default applies — **30 days**. A browser left signed in on a firewall-management console
stayed signed in for a month.

⛔ **THE SERVER IS THE BOUNDARY; THE MODAL IS THE COURTESY.** NetVault's `IdleTimeout.tsx` is
client-only: it calls `signOut()`, which clears the cookie in that one browser while the JWT stays
valid for its full lifetime, so a copied cookie is untouched. Here the token itself expires and
`components/layout/IdleTimeout.js` exists so the expiry is not a surprise. Delete the component and
the timeout still happens — without warning.

⛔ **`updateAge` IS LOAD-BEARING.** With the JWT strategy NextAuth only rewrites (and so extends)
the token once `updateAge` has elapsed. Left at its 24h default beside a 30-minute `maxAge` the
token is never refreshed and every user is signed out 30 minutes after LOGGING IN, however hard
they are working — an ABSOLUTE timeout wearing an idle timeout's name. It is clamped to at most
half the window, and a TEST PINS THE RELATION rather than the number.

⛔ **ONLY AN EXPLICIT `0` DISABLES.** A negative or unparseable value falls back to the default: a
typo must not switch a security control off. Disabling restores `maxAge` to NextAuth's own 30 days,
i.e. exactly the behaviour before this existed, rather than "no expiry" or "expires instantly".

⛔ **ONE SOURCE OF TRUTH.** The browser reads `GET /api/system/session-policy` (open to any
signed-in user — someone who cannot read it is signed out with no warning) rather than carrying its
own copy. A second number in a settings table would drift, and the drift shows up as a modal
promising 60 seconds on a session that already ended. ⛔ A FAILED read arms NOTHING rather than
guessing a window, because a guess shorter than the real one signs people out of a valid session;
NetVault guesses 30 minutes, which it can afford to because there the client IS the timeout.

⛔ **THE LOGIN PAGE HONOURS `callbackUrl` THROUGH `safeReturnPath()`**, which accepts only a
same-site path — never `//` or `/\\`, both of which browsers resolve as absolute URLs to another
host. An unguarded redirect would turn the login page into a hop to a credential-harvesting clone.
A timeout is tinted as INFORMATION, not danger: shown in red it reads as a rejected sign-in and the
next thing the user doubts is their password.

⛔ **A SAVED VALUE IS NOT A RUNNING VALUE.** NextAuth reads its options once at startup, so the
panel reports both and states that a restart is required — the same rule the console-address panel
follows. Pinned by `tests/sessionPolicy.test.js` (16 cases, mutations verified).

### Multi-factor authentication (TOTP, v2.111.0)

`lib/totp.js` (pure RFC 6238/4226 + RFC 4648 base32, **zero dependencies** — node's own
`crypto`) + `lib/mfa.js` (enrolment, verification, recovery; takes a `pool`). Optional per user;
a Super Admin can REQUIRE it on an account (`user_mfa.required`).

⛔ **No library, deliberately.** `Update-SecVault.ps1` runs `npm ci` on a firewall-management
box and this repo carries no devDependencies. TOTP is an HMAC over a counter; `tests/mfa.test.js`
asserts it against **RFC 6238's own published test vectors**, including the one that exercises
the high 32 bits of the counter. A hand-rolled TOTP that is subtly wrong does not crash — it
emits six plausible digits no authenticator agrees with.

⛔ **SHA-1 is correct here and is not a defect.** RFC 6238's default, and what every
authenticator implements. TOTP's security rests on the secret, not on collision resistance;
changing it silently breaks every enrolled device.

⛔ **Single-form login** (username + password + code together). NextAuth v4's `authorize()` is
ONE call, so a two-step flow needs a pre-auth token table and custom session wiring — more
machinery on the login path of a security product, for no security gain.

⛔ **A code is SINGLE USE.** `user_mfa.last_counter` records the accepted step and is compared
with `<=`, not `!==` — rejecting only an exact repeat would still allow replaying the previous
step, which is also still live. NULL means never used, not step 0.

⛔ **The dominant risk is LOCKOUT, not bypass**, so there are THREE independent ways back in:
recovery codes (10, single-use, bcrypt-hashed, shown once); a Super Admin resetting **another**
account (`DELETE /api/users/[id]/mfa`, `MANAGE_USERS`); and `node lib/mfa-reset.js <username>`
on the server. The last is not a backdoor — it needs a shell on the host, which is strictly
more access than any SecVault account confers, and it removes only the second factor.

⛔ **A started-but-unconfirmed enrolment must NOT demand a code.** `enabled` stays false until
the user proves a code; otherwise closing the tab mid-enrolment locks them out.

⛔ **Fails closed at login**: if the MFA lookup throws (DB down, `CREDENTIAL_KEY` missing) the
login is REFUSED. An MFA check that degrades to 'skip it' is not a second factor.

⛔ **The login form is not an oracle**: the code field is always visible (revealing it per-account
would disclose which accounts are protected), and every failure returns one message. The specific
reason goes to the server log.

⛔ `user_mfa` holds the encrypted secret and the recovery hashes, so it is **excluded from the
readonly grants** — same rule as `device_credentials`. `POST/PUT/DELETE /api/mfa` is the THIRD
documented exception to the mutating-route rule (after own-password and saved views): it acts on
`session.user.id` and never on a body parameter, so the authorisation is structural.

Enrolment shows a QR (rendered SERVER-SIDE by `qrcode` into a data: URI, so nothing is fetched
at display time and it works air-gapped) alongside the setup key for manual entry. ⛔ Both are
shown: someone enrolling on the machine that is displaying the QR cannot scan it with that
machine. ⛔ This approach was taken from NetVault, which has had the same TOTP-on-node:crypto +
`qrcode` combination for longer — check the sibling apps before deciding an approach here, the way
the compliance PDF was ported from SpanVault.

**MFA is unavailable for LDAP accounts** — they have no `users` row to attach a secret to, and
their MFA belongs in the directory.

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

### ⛔ A VENDOR-PUBLISHED 0.0 IS A SCORE — DECIDED 2026-09-19, DO NOT REOPEN

Palo Alto publishes `baseScore: 0` with `baseSeverity: "NONE"` on advisories titled
**"Informational: Impact of \<third-party CVE\>"** — documents whose purpose is to say PAN-OS is
NOT impacted. Verified against the live bulk endpoint: **47 of 350 records score 0, and 45 of those
declare PAN-OS `status: "unaffected"`.** Live in the database: 46 such rows and **0 device
assessments across all of them**.

⛔ **DO NOT IMPORT A THIRD-PARTY SCORE OVER IT.** CVE.org scores CVE-2022-22963 at 9.8 — that is
the SPRING FRAMEWORK's severity, and filing it against a firewall whose own vendor says it is
unaffected would manufacture 46 urgent findings that are not real. Same trade as the vendor-level
CPE wildcard, tested and refused for the same reason. The vendor's 0 answers the question this
product actually asks (does this affect THIS product) and it is the best available answer.

⛔ **A 0.0 WHOSE VECTOR CONTRADICTS IT IS STILL STORED VERBATIM.** Four records carry
`CVSS:4.0/…/VC:H/VI:H/VA:H` with `baseScore: 0`. The vendor publishes both in ONE metric block, so
this is not a pairing error of ours; recomputing a score from the vector would invent a number
nobody published.

⛔ **TWO SEPARATE GUARDS KEEP THESE OFF DEVICES, AND THEY COVER DIFFERENT RECORDS.**
`extractAffectedRanges` skips `status !== 'affected'`, and `looksLikeVersion()` rejects the
`version: "All"` the informational bulletins use. The 45 bulletins are caught by the SECOND; the
status check earns its place on **261 live version entries that pair a non-affected status with a
real numeric version** (CVE-2026-0308 lists `unaffected: 12.2.0` beside three affected branches) —
delete it and an advisory that CLEARS a branch would file every device on it as vulnerable.
Pinned by `tests/cvssZeroScore.test.js`, whose first draft passed with the status check deleted
because its fixtures exercised only the other guard.

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

### ⛔ A PER-STANDARD SCORE IS A SHARE OF **OUR OWN** CHECKS (v2.163.0)

`/compliance` printed **"NIST 42%"** as if it were that framework's posture. Measured on the live
fleet: the library is **45 checks**, mapped CIS_V8 44 / ISO_27001 35 / PCI_DSS 21 / SANS 12 /
**NIST 7** — and of NIST's seven, three are vendor-scoped and four are generic firewall hygiene
(`rule-no-any-any-allow`, `rule-logging-enabled-on-rules`, `rule-has-explicit-deny-all`,
`rule-no-external-to-internal-access`) wearing a framework's name. On HRIS the figure was **17%
computed from six checks**. That was the one place this product overclaimed, and the fix is its own
denominator rule turned inward.

`lib/engines/complianceCoverage.js` is PURE and answers, per standard: mapped / applicable to this
fleet's vendors / evaluated / gradeable / `na`, plus an evidence grade on the **absolute gradeable
count** (`thin` <= 7, `moderate` 8-19, `broad` >= 20).

⛔ **NO FRAMEWORK TOTAL IS INVENTED, EVER.** Replacing "NIST 42%" with "7 of ~300 requirements"
would trade one overclaim for a fabricated denominator — this codebase holds no count of what any
framework publishes. The refusal is exported as `COVERAGE_CLAIM` and a test rejects both
`N requirements` and hedged forms (`about`/`roughly`/`~ N`) in every string the engine produces.

⛔ **TWO UNITS, KEPT APART.** A fleet finding is a (device, check) PAIR, so NIST's 91 finding rows
come from at most 7 distinct questions. The evidence grade is keyed on DISTINCT GRADEABLE CHECKS,
never on finding rows — grading on rows would make a 7-check standard look broad on a large fleet.

⛔ **THE SCORE ARITHMETIC IS UNCHANGED** and `scorePct` is carried through verbatim, pinned by a
test. This changed PRESENTATION only. `unknown` (the coverage read failed) is a distinct state from
`none` (nothing ran).

### ⛔ Compliance exceptions — accepted risk that CANNOT move the score (v2.163.0)

`compliance_exceptions` + `lib/engines/complianceExceptions.js` + `/api/compliance/[deviceId]/exceptions`.
An operator's recorded decision that a FAILING check is accepted on this device, with a
compensating control, an owner and a mandatory expiry. It exists because 151 checks fail fleet-wide
and there was nowhere to put "yes, and here is why that is mitigated" — without which the score is
un-actionable and people stop opening the page, the same dynamic that got `new_finding` pulled from
Alerts in July.

⛔ **AN EXCEPTION NEVER CHANGES A FINDING'S STATUS, AND THE HEADLINE SCORE IS COMPUTED WITHOUT
IT.** A failing check with an accepted exception is still `fail`: the firewall is still configured
that way, and letting a label somebody typed move a measurement is how a compliance score becomes a
number people MANAGE instead of a fact they ACT on. The UI shows COUNTS beside the score ("12
failing · 3 with a live exception"), deliberately **not a rival percentage** — a second figure
differing from the headline by a set of typed labels is exactly the artefact this rule exists to
prevent. A repo scan over the five files where the arithmetic lives pins it.

⛔ **GATED ON `OPERATE`, AND ONLY SAFE THERE BECAUSE OF THE RULE ABOVE.** `operate` already means
"acknowledge findings/alerts/diffs", and an exception is the same act one table over; segmentation
and application intent set the same precedent. ⛔ **If anyone ever makes an exception move a score,
this gate must be revisited in the SAME commit** — the authority that would justify escalating is
"can make the compliance number go up".

⛔ **KEYED ON `(device_id, check_slug)`, NEVER ON `audit_findings.id`** — findings are
DELETE+reinserted every run. And `check_slug` is `audit_checks.check_id` (the TEXT slug), while
`audit_findings.check_id` is a UUID FK to `audit_checks.id`: **two columns named `check_id`, two
tables, two types.** Every query routes through `audit_checks`, and a test pins the wrong forms
negatively.

⛔ **`expires_at` IS MANDATORY and expiry is evaluated at READ time** — no cron job, and a lapsed
row stops counting the moment it lapses. FOUR states, never two: `accepted` / `expiring` (30 days,
chosen because the scheduled report is monthly so a shorter window could open and close between two
reviews) / `expired` (DANGER tint — a positive actionable fact, not grey and not blank) /
`revoked` (history). A fifth, HUELESS state covers an unreadable expiry, which falls CLOSED to
expired and says why.

⛔ **`accepted_by` COMES FROM THE SESSION, NEVER THE BODY**, and an exception may only be recorded
against a check that is ACTUALLY FAILING on that device — otherwise someone could pre-accept a
future failure.

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
one command returning nothing does not prove a vendor lacks the data. ⛔ A second correction,
2026-09-15: this file also said **Fortinet HA was deferred**, and that was wrong too —
`lib/adapters/fortinet/ssh.js` implements `getHaStatus()` and all 5 live Fortinets carry
`device_ha_status` rows. Only **Fortinet disk** is genuinely still deferred. That is twice the
same sentence has under-stated a vendor's real coverage; a report that reads it and hardcodes a
vendor matrix inherits the error, so `lib/reports/fleetLifecycle.js` derives capability from the
ADAPTER REGISTRY (`typeof adapter.getX === 'function'`, nothing connected, nothing called) rather
than from prose here.

⛔ **Licence expiry is FOUR states, not three.** Besides a real date, perpetual (`expires_raw`
= `'Never'`) and unknown, `deviceHealth.licenseStatus()` returns **`not_licensed`** for FortiOS's
`'n/a'` — live, **44 of 305 entitlement rows**, every one on a Fortinet. It is an entitlement the
device does not hold, not one whose date failed to parse, and it must never enter a renewal table:
doing so would manufacture 44 renewals that do not exist. Tables: `device_licenses`, `device_ha_status`, `device_disk_usage`,
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

## Work Queue (`/work`, Phase 3, v2.115.0)

ONE ranked list of outstanding work, gathered from TEN sources at READ time (the tenth,
`application`, landed with the application view in v2.124.0). `lib/engines/workQueue.js`
is pure (banding + ranking, no pool); `lib/engines/workQueueData.js` is the ten gathers. No table, no
cron job — a stored queue goes stale against the data it indexes, and people WORK a stale to-do list.

⛔ **AN ITEM IS A DECISION, NOT A FINDING.** 1,132 rule-analysis findings exist on this fleet. They
appear as ONE item per firewall, with the count travelling alongside, linking to the tab where that
work is done. A list whose length grows with the fleet rather than with the outstanding work is a
database dump, not a queue.

⛔ **URGENCY IS A CLAIM ABOUT EVIDENCE.** Each item carries `evidence: measured | reported |
unmeasured`, and that field — not the source's opinion — decides the band. **`unmeasured` can NEVER
reach `act_now`**, and an unrecognised/missing value fails CLOSED to `verify`. This is the
`log_hit` lesson applied structurally: a queue where everything is urgent has no prioritisation left.

⛔ **THE THIRD BAND IS THE POINT.** `verify` ("Needs a human") holds what SecVault cannot measure —
the 44 licences whose expiry string will not parse, the firewall that cannot be collected from. It is
a VISIBLE, COUNTED, HUELESS band, never a collapsed footer and never the tail of `scheduled`. A
firewall nothing can be collected from contributes no CVEs, no failing checks and no rule findings,
which makes it look like the healthiest device on the fleet everywhere else in this product.

⛔ **A SHORT QUEUE MUST NEVER READ AS A CLEAN ONE.** Two separate mechanisms, both pinned by tests:
1. Every source is isolated; a throw reports `{ok:false, error}` and is banner'd. It must never
   contribute zero items silently — the page would look best when least trustworthy. (Caught
   `rule_cleanup` on the first live run: the ack join must route through `firewall_rules`, because
   `rule_analysis_results.rule_id` is a UUID FK while `finding_acknowledgements.rule_id_vendor` is
   the vendor's own text id.)
2. `PER_SOURCE_CAP` (50) discloses `shown of total` when it bites. A truncated list looks COMPLETE,
   which is the more insidious failure — the operator works to the bottom and believes they are
   finished. Live: compliance returned 50 of 74.
   `buildWorkQueueAnswer` refuses `tone:'ok'` while ANY of failed / truncated / verify is non-zero.

⛔ **Deliberately excluded**: compliance `warning`/`na`, and CVEs banded `scheduled`/`monitor`.
Neither is confirmed work a person can action, and padding the queue with items whose first step is
"find out whether this is even a problem" is how a queue stops being used.

⛔ Every item states **how SecVault will independently observe that it is done** — a re-assessed
version, a re-collected ruleset, a re-evaluated check. There is no "mark as done" (the unreviewed
config diff is the one exception, where acknowledgement IS the action). Same rule as the rule-cleanup
loop: listing the work is what the competition does; confirming it happened is what they cannot.

Segmentation is computed by the PAGE and passed in, not gathered inside `workQueueData.js` — it loads
the whole fleet's rules with traffic evidence and is by far the most expensive source; hiding that
cost behind the gather list would misrepresent what the page does.

⛔ The `application` source (v2.124.0) carries the SAME cost and resolves it differently, because
it must also work when no caller has pre-computed anything: it accepts an already-computed
`opts.applications` exactly as segmentation does, and otherwise puts a single COUNT on
`application_flows` in front of the whole-fleet load — nothing declared, no load. ⛔ That probe
FAILS OPEN: an unreadable count falls THROUGH to the evaluation, because "we could not read the
count" is not "nothing is declared", and that substitution would switch a whole source off in
silence.

## Application Intent — Phase 2 (v2.129.0)

Two inversions of the declared-flow model, both reusing `applicationView`'s evaluator UNCHANGED.

⛔ **IMPACT MAKES EXACTLY ONE CLAIM**, exported as `IMPACT_CLAIM` and pinned by a test that rejects
the words *safe*, *reachable*, *unused* and *guarantee*: "Removing this rule would leave N declared
flows with nothing permitting them." ⛔ **A rule no declared application uses is NOT proven safe to
remove** — with nothing declared, every rule serves nothing, and rendering that as safe would turn an
empty declaration into a fleet-wide deletion licence.

⛔ **UNKNOWN IS NOT ZERO, AND THE THREE ZEROES NEVER LOOK ALIKE.** `breaks` / `shared` / `unknown` /
`none`, with `null` counts (never 0) on an unavailable index. An unverified walk applies only a
rule's RESOLVED extent, so other permitters may be invisible — which is why unverified never becomes
"only support" even at a support count of 1.

⛔ **RETIRING PROPOSES; IT NEVER DELETES.** It produces a request through the existing
`ruleChangeRequests` loop, which already proves removal against the re-collected ruleset and already
refuses to verify while collection is failing. There is deliberately no second verifier and no "mark
as done".

⛔ **"ONLY THIS APPLICATION CLAIMS IT" IS THE SAFETY PROPERTY.** Other claimants include every other
application's flows in BOTH expectations and **including retired ones** — a status is a label someone
typed, not evidence traffic stopped. An unmeasured `hit_count` is REFUSED, not warned about. Both
lists always return together: a response carrying only `proposed` is a shorter list that looks
complete, with a delete button attached.

⛔ **NEITHER FEATURE CAN CONCLUDE ON THIS FLEET TODAY, AND THAT IS CORRECT.** 14 of 16 firewalls carry
rules referencing an address or service the device never reported, so impact reads "cannot tell" for
all 29 touched rules and retirement proposes 0 of 29. The fix is collecting the missing objects, NOT
loosening either engine — an engine that concluded anyway would be guessing about a firewall change.

### ⛔ The work queue is DISPATCHED OUTBOUND (`work_act_now`, v2.154.0)

`notificationDispatch.js` gains one alert type fed by `bandFor(item) === 'act_now'` — **not one
per source, and not the whole queue**. Twelve source types already carry severity, urgency and an
evidence grade; dispatching each as its own type would invent a FOURTH vocabulary beside the three
that were found disagreeing with each other in v2.153.0, and mailing `scheduled` or `verify` would
send work that is by definition not urgent.

⛔ **IT IS THE ANSWER TO THE NOISE PROBLEM THAT GOT AN ALERT REMOVED.** `new_finding` was taken
out of the Alerts feed on 2026-07-20 on direct user feedback. `act_now` cannot repeat it: an item is
a DECISION not a finding (1,132 rule findings are one item per firewall), and `bandFor()` refuses
anything `unmeasured` however urgent its source declared itself.

⛔ **AN INCOMPLETE QUEUE THROWS, AND THAT IS THE WHOLE SAFETY PROPERTY.** `gatherWorkQueue`
isolates each source, so a failure contributes zero items and reports `{ok:false}`. Returning that
shorter list would let the dispatcher's reconcile step read every missing `natural_key` as RESOLVED
and clear real, still-open security work — then re-notify on recovery. Throwing makes the loop
`continue` BEFORE the reconcile, so nothing changes. **Truncation (`PER_SOURCE_CAP` = 50, which has
bitten live) throws for the identical reason.** Silence for one cycle is recoverable; a false
all-clear is not.

⛔ **ONE DEVICE OR NONE.** An item spanning three firewalls names no `device_id` rather than the
first — the same fabricated-attribution rule `fetchOpenIngestDrop` follows. `affects` states who is
involved in words. ⛔ Called with **no opts**, so `segmentation` and `application` (the two expensive
sources) stay cheap: a 15-minute background poll must not pay a cost the page pays because a person
is waiting.

## Segmentation Intent (`/segmentation`, Phase 3, v2.113.0)

Declared zone-to-zone policy, tested TWO WAYS: **CAN** (the rulebase) and **DID** (the traffic).
`lib/engines/segmentation.js` is pure (zone matching + verdicts, no pool);
`lib/engines/segmentationData.js` is the plumbing. The split is what makes the judgement testable.

⛔ **WHAT "CAN" CLAIMS, PRECISELY:** at least one ENABLED allow rule matches the zone pair. It does
NOT claim a packet would pass — addresses, services, profiles and rule order all still apply and are
deliberately NOT modelled. The UI says "a rule permits this", never "this is reachable". Overclaiming
here would be worse than useless: an operator who trusts "reachable" and finds it was a guess stops
trusting the honest answers too.

⛔ **`any` IS A WILDCARD** (114 occurrences on the live fleet) and an EMPTY zone list is
unconstrained. Matching either literally would UNDERSTATE reachability — and on a segmentation
report that is the dangerous direction: a hole reported as closed is a false assurance, not a missed
finding.

⛔ **"DID" IS TRI-STATE AND `null` WINS OVER `false`.** If even ONE permitting rule cannot report
usage, the whole pair is UNKNOWN — that one rule might be the one carrying the traffic. Fortinet over
SSH reports no hit counts at all (0 of 180 rules live), so this is the common case, not a corner.
Evidence comes from `ruleHitCorrelation.js` UNCHANGED (it already separates `measured-zero` from
`no-coverage`); two implementations of that distinction would eventually disagree and the wrong one
would be recommending rule deletions.

⛔ **NO RULES COLLECTED IS `unknown`, NOT "blocked".** Otherwise a fleet whose rulesets were never
pulled reports every deny-intent as satisfied — a perfect segmentation score computed entirely from
missing data.

⛔ **Zones are DERIVED from the rules**, never hand-entered: a typed axis drifts the moment someone
renames a zone, and every cell referencing the old name would silently evaluate against nothing.

⛔ **No stored verdict column.** A verdict is a function of the current rulebase and traffic window;
storing one lets it go stale and be read as fact.

Verdicts (`VERDICTS` in segmentation.js): `violation_active` / `violation_permitted` /
`violation_unverified` / `ok_blocked` / `ok_in_use` / `unused_permission` / `ok_unverified` /
`expected_allow_missing` / `unknown`. ⛔ `violation_permitted` and `violation_unverified` must never
share a colour — the first is a safe deletion candidate, the second must be assumed live.

⛔ **AND THE THREE VIOLATION COLOURS MUST RANK IN THE SAME ORDER AS THE ACTION LIST**
(`violation_active` > `violation_unverified` > `violation_permitted`), on screen and in print.
Corrected 2026-09-15, v2.122.0: `SegmentationBoard.js` had given `violation_permitted` the full
danger tint and `violation_unverified` only a warning tint — the reverse of its own
`ACTION_ORDER` and the reverse of its own hover text, which says of unverified "assume it is live"
and of permitted "the safest kind to close". The rule above was satisfied to the letter (they did
not share a colour) while the louder of the two was the wrong one. `violation_active` and
`violation_permitted` ALSO both sat on `--sev-crit`, so "happening now" and "a standing hole" were
indistinguishable. Since Fortinet over SSH reports no hit counts at all, "cannot tell" is the
COMMON verdict on this fleet, not a corner — under-colouring it was the expensive half of the
mistake. Pinned by `tests/segmentation.test.js`, which reads the component source and asserts the
tint ranking against `ACTION_ORDER` rather than against a hardcoded list, so the two cannot
disagree again.

Mutating routes are gated on `OPERATE`, not `MANAGE_DEVICES`: declaring intent changes no device, no
rule and no score. Pinned by `tests/segmentation.test.js` (28 cases).

## Application Intent (`/applications`, Phase 1, v2.124.0)

A business application declared as a set of FLOWS — (src, dst, protocol, ports, `allow`|`deny`) —
and every flow re-checked against the COLLECTED rulebase. `lib/engines/applicationView.js` is pure
(flow -> verdict, given rules and objects); `applicationViewData.js` is the plumbing. Same split,
same reason, as segmentation: the judgement is the value, so the judgement has to be testable.

This is `/segmentation` moved from ZONE grain to FLOW grain. The competitive claim is the same one
this product makes everywhere: **Tufin's and AlgoSec's application maps are declared and never
re-verified — accurate the day they are typed, decaying silently after, with no statement of what
could not be checked.** Everything below exists to keep our half of that claim true.

⛔ **WHAT "PERMITTED" CLAIMS, PRECISELY:** at least one ENABLED allow rule on one device matches the
flow. It does NOT claim a packet would pass — rule order ACROSS devices, routing, NAT and security
profiles are deliberately not modelled, and no multi-hop path is simulated. The UI says "a rule
permits this", never "this is reachable". Overclaiming here would be worse than useless: an operator
who trusts "reachable" and finds it was a guess stops trusting the honest answers too. ⛔ And
`unspecified` is NEVER rendered as denied — no default/implicit-policy data exists in this codebase,
for any vendor.

⛔ **EXACT RANGE DECOMPOSITION, NOT A SAMPLED ADDRESS AND NOT PER-DIMENSION COMPARISON.**
`objectResolver.queryAccessPath()` — the evaluator `topology.js` and `exposure.js` both reuse
unchanged — requires `srcIp`/`dstIp` to be SINGLE /32 ADDRESSES and throws otherwise. A declared
flow is almost never a point ("the app subnet reaches the database subnet on 1521"), and answering
it by picking one address out of each /24 is the fabricated-measurement bug: the sample might be the
one address a rule covers, or the one it misses, and nothing in the output would show which. The
cheap alternative — compare src, dst and port separately and report the worst — is wrong in a way
that matters: given `deny 10.1.0.5 -> any:443` above `allow 10.1.0.0/24 -> any:443`, it reports the
flow BLOCKED when 254 of its 255 addresses are permitted. On a segmentation-shaped report that is a
hole reported as CLOSED, the dangerous direction. So the engine walks the rules in
`sequence_number` order carrying a set of undecided (src x dst x port) boxes, splitting each box as
rules claim parts of it, and reports exact permitted/blocked/unspecified volumes. ⛔ The genuinely
hard part is NOT reimplemented: group expansion, FQDNs and vendor service grammars come from
`objectResolver`'s own `buildObjectMap`/`resolveAddressField`/`resolveServiceField`, unchanged.
⛔ `MAX_UNDECIDED_BOXES` makes a pathological rulebase `unverified` — a refusal to answer, never a
partial answer dressed as a whole one.

⛔ **VOLUMES ARE NEVER UNIONED ACROSS DEVICES.** Two firewalls each permitting half a flow do not add
up to a permitted flow: they are different firewalls on (probably) different paths, and summing them
invents a reachability that exists on neither. The fleet answer is the BEST SINGLE DEVICE's answer.
⛔ A device with NO collected ruleset makes every flow `unverified`, never "blocked" — otherwise a
fleet whose rulesets were never pulled reports every application as safely contained, a perfect
result computed entirely from missing data.

⛔ **PER-FLOW TRAFFIC USAGE IS NOT ANSWERABLE, AND MAY NOT BE APPROXIMATED.** Every syslog rollup in
this product is source-keyed or destination-keyed; **none carries both ends of a flow**. So "did this
src -> dst:port carry traffic" cannot be asked of stored data at all. What IS answerable is whether
the RULE permitting it has seen traffic, which is strictly weaker and must be worded as one — the UI
prints "a rule permitting this flow is in use", never "this flow is in use". ⛔ `syslog_events` is
REFUSED as the fallback, for the same reasons VPN traffic attribution refuses it (no `src_ip` index,
~28M rows/day, and adding one puts the write cost on the collector). ⛔ The tri-state comes from
`ruleHitCorrelation.js` UNCHANGED, and one permitting rule with no usable hit count makes the whole
answer `unknown` — that rule might be the one carrying the traffic. Fortinet over SSH reports no hit
counts at all, so this is the COMMON case, not a corner. ⛔ Closing this gap needs a
`syslog_flow_hourly` rollup — a schema change argued on measured cardinality, not a query change.

⛔ **ORPHAN RULES ARE COVERAGE, NEVER A FINDING, AND NEVER "UNUSED".** `orphanCoverage()` reports how
much of the fleet's enabled allow rulebase no declared application claims. With nothing declared that
is ~1,095 of 1,095 rules on this fleet — accurate, and completely useless as a to-do list; as a
"finding" it would be an alarming number that means nothing on the feature's first screenshot, and
it is excluded from the work queue for exactly that reason. ⛔ And "unclaimed" is not "unused":
`unused` is `ruleAnalysis.js`'s word and it requires a MEASURED zero hit count. A rule nobody has
declared an application for is a gap in the DECLARATION, not evidence about the rule. Conflating them
manufactures deletion candidates out of an incomplete map — this codebase's signature bug wearing a
new hat.

⛔ **NO STORED VERDICT, NO CACHED RULE LIST**, same rule as segmentation: a verdict is a function of
the current rulebase and traffic window, and a stored one goes stale and is then read as fact —
precisely the defect this feature exists to beat the competition on. ⛔ `src`/`dst` are LITERAL
addresses, never vendor object names: `network_objects` is per-device, so a flow declared against one
device's object name would silently evaluate against nothing on every other device.

⛔ **AN APPLICATION IS AS UNVERIFIED AS ITS LEAST-VERIFIED FLOW**, and an all-clear is forbidden while
anything is unverified — the rule `lib/evidence.js` already enforces product-wide.

**Work queue (source #10).** ⛔ ONE ITEM PER APPLICATION, never per flow: a declaration is written to
be exhaustive, so an item per flow would grow the queue with the SIZE OF THE DECLARATION rather than
with the outstanding work. Work states are `violation`/`broken`/`partial`/`invalid`;
`unspecified` and `ok_unverified` are EXCLUDED as unconfirmed work. ⛔ ONE unverified flow makes the
whole item `unmeasured` and therefore `verify` — `act_now` is a claim about evidence, not about
importance — and a fully-verified violation is `reported` AT MOST, never `measured`, because
SecVault read the rulebase and did not observe a packet. ⛔ It is the only gather that runs an ENGINE
rather than a query, so a COUNT on `application_flows` stands in front of the whole-fleet load, and
that probe FAILS OPEN.

Mutating routes are gated on `OPERATE`, not `MANAGE_DEVICES`: declaring intent changes no device, no
rule and no score — the same call segmentation makes. ⛔ `applications.name` is a BUSINESS
application and must never share a label, column or table name with `syslog_app_hourly.application`
or `firewall_rules.applications`, which are the vendor L7 app-ID (`ssl`, `dns-base`) — a protocol
fingerprint, not an application.

## Role-Based Access Control

**THREE roles** (v2.110.0, was two): `super_admin`, `admin`, `operator`. `viewer` is retired and
is no longer assignable.

| Capability | super_admin | admin | operator |
|---|:--:|:--:|:--:|
| `manage_users` | ✓ | — | — |
| `manage_credential_profiles` | ✓ | — | — |
| `manage_devices` | ✓ | ✓ | — |
| `manage_settings` | ✓ | ✓ | — |
| `run_update` | ✓ | ✓ | — |
| `operate` | ✓ | ✓ | ✓ |
| `view_identity` | ✓ | ✓ | — |
| `view_log_search` | ✓ | ✓ | — |

`operate` = acknowledge findings/alerts/diffs, run analyses and collections, raise and verify rule
change requests. Changing YOUR OWN password is open to every role and is not a capability.

⛔ **`admin` cannot manage users AT ALL — not merely "cannot create" them.** The requirement was
phrased as create-only; that would be a hole rather than a boundary, because editing another
user's role or password achieves exactly what creating one does, and editing a credential profile
lets you replace and therefore control its stored secret. The capability covers create, update and
delete together.

⛔ **Grants are listed EXPLICITLY per role in `ROLE_CAPABILITIES`, never derived by subtraction.**
"Everything except X" computed at runtime means the next capability added leaks into `admin` by
default. `tests/rbac.test.js` asserts the matrix as a complete literal table.

⛔ **Fails closed everywhere.** No session, no user, a null role (what `jwt()` sets when the
database is unreachable), an unknown role, or a legacy `viewer` row all resolve to NO capabilities.
An unrecognised capability STRING also denies — a typo must never match.

⛔ **The last `super_admin` cannot be deleted or demoted.** Only that role holds `manage_users`, so
losing the last one leaves an installation where nobody can ever create or change an account again,
recoverable only by a direct database edit. The guard in `app/api/users/[id]/route.js` counts
super_admins, not the word "admin".

⛔ **Migration promotes the OLDEST admin to super_admin, once.** `migrateRolesToThreeTier()` in
`lib/migrate.js` runs only when NO super_admin exists, so it never re-promotes an account a Super
Admin deliberately demoted. It promotes ONE account, not every admin — granting user-management
authority to every existing admin would be a silent privilege escalation. ⛔ `viewer` rows are NOT
mapped to `operator` (operator can write, viewer could not); they are counted and reported instead.

`users` table holds `username`, `password_hash`, `role` (no CHECK constraint, validated in app
code against `ASSIGNABLE_ROLES`); `password_hash` is `REVOKE`d from base grants, exposed only via a
`users_readonly` view.

`lib/rbac.js` — pure, dependency-free CommonJS. The one check is `can(session, CAPABILITY)`;
`capabilitiesOf(session)` returns the whole object for handing to the UI. Does NOT resolve its own
session — every route calls `getServerSession(authOptions)` itself, then
`if (!can(session, X)) return forbiddenResponse(X);`. The 403 body names the missing capability,
because "admin role required" became actively misleading with three roles.

⛔ **`isAdmin(session)` survives as a LEGACY ALIAS meaning `manage_devices`**, and roughly twenty
routes still use it. That is deliberate: it makes introducing `operator` a pure restriction —
every un-migrated route denies operators by default and is opened up only by a deliberate edit.
Prefer `can()` in new code.

⛔ **A UI gate must never be STRICTER than the API it fronts.** If a button is hidden while its
route would have accepted the call, the operator concludes the product is broken rather than that
they lack access. `/alerts`, `/compliance/[deviceId]`, `/devices/[id]/analysis` and
`/vulnerability` therefore gate on `OPERATE`, matching their routes.

Applied to every mutating (POST/PUT/DELETE/PATCH) route; GET routes are never gated **with two
documented exceptions, both about personal data rather than mutation**: `/api/logs/search`
(`view_log_search` — raw syslog carries usernames, internal addresses and URLs) and the VPN
identity tabs (`view_identity`). ⛔ The VPN guard is TWO-PART: `visibleVpnTabs()` hides the tab so
it cannot be discovered, AND `app/(dashboard)/vpn/page.js` refuses to render an identity tab body
however the URL was reached. A hidden tab whose URL still works is decoration, not a boundary. **A non-mutating POST that only computes over already-collected data and persists nothing is treated like a GET, not gated** — e.g. `POST /api/devices/[id]/access-path` (query-only, no DB write) — the "mutating" test is about persistence, not HTTP verb; don't read the rule as "every POST needs isAdmin." **The JWT's role is re-validated on every token use, not just at sign-in** — `jwt()` re-queries `SELECT role FROM users WHERE id=$1` for local-provider tokens, failing closed on a DB error, so a role change/demotion takes effect immediately rather than waiting for a stale JWT to expire.

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

**LDAP roles come from directory groups since v2.134.0** — see the Commercial Licensing section's neighbour below. The old hardcoded `role: 'admin'` for any successful bind is gone. UI-level hiding of write-action buttons is defense-in-depth only; real enforcement is always the server-side guard.

### LDAP group-to-role mapping (v2.134.0) — replaces the hardcoded `admin`

`lib/ldapRoles.js` (pure `resolveRole`, plus three pool-taking storage functions),
`ldap_role_mappings`, `GET/POST/DELETE /api/ldap-mappings` (**`manage_users`** — super_admin
only), Settings → Users → Directory group access.

⛔ **THE UPGRADE IS THE DANGEROUS PART, AND "NO MAPPINGS CONFIGURED" ≠ "NO MAPPING MATCHED".**
The obvious fix — no mapping, no access — locks every existing LDAP install out of its own platform
on the deploy that delivers it, for customers who did nothing wrong. So:
**ZERO mappings = LEGACY MODE**, grant `admin` exactly as before; **≥1 mapping** means an
administrator has expressed an intent and a user in no mapped group is REFUSED. Same distinction the
vendor-PSIRT gate draws between an empty inventory and an unreadable one.
⛔ **Legacy mode is a ramp, not a resting state**: it warns on EVERY login and renders a full-danger
panel in Settings saying every directory user is currently an Administrator. An insecure default
that nothing complains about is one nobody ever fixes.

⛔ **UNREADABLE GROUPS IS NOT "NO GROUPS".** `groups === null` refuses the login with its own
outcome. This is an AUTHORISATION check and fails CLOSED — the opposite call from the licence guard
one section up, which fails open because it is only a billing one.
⛔ **`loadMappings` THROWS rather than returning `[]`** for the same reason: an empty array is an
INSTRUCTION here, so returning one for a database blip would grant Administrator to the whole
directory.

⛔ **THE MOST PRIVILEGED MATCH WINS.** A user in both "Firewall Admins" and "Helpdesk" is a firewall
admin; resolving down would make adding someone to a second group silently REMOVE access.

⛔ **DNs COMPARE CASE- AND SPACING-INSENSITIVELY** (around the commas only — `CN=Help Desk` is a
real group name). `group_dn_normalised` carries the UNIQUE constraint while `group_dn` keeps the
operator's own spelling for display; without that split the same group could be mapped twice to two
roles and row order would decide.

⛔ **A MAPPING CHANGE APPLIES IMMEDIATELY; A GROUP-MEMBERSHIP CHANGE APPLIES AT NEXT SIGN-IN.**
`jwt()` now re-resolves LDAP roles on every token use from groups captured at sign-in against the
CURRENT mapping table — LDAP users were previously exempt from the re-check local users have always
had, so a revoked mapping kept working for the life of the JWT. It deliberately re-reads the
MAPPINGS, not the directory: an LDAP round-trip on every request is not acceptable on the
authorisation path. The panel states both timings rather than hiding the asymmetry.

### ⛔ The LDAP bind was BROKEN, and the live probe is what found it

`ldapAuthenticate` built `cn=${username},${baseDn}`. Probed against the customer's own directory
(thaiunion.co.th, 2026-09-16) that DN **does not exist and could not have**:

- the account's real DN is `CN=Service MFA,OU=Hybrid Joined Device,OU=Windows Update Delivery
  Optimization,OU=TUF HQ,OU=TUF,DC=thaiunion,DC=co,DC=th` — **the CN is the DISPLAY NAME, not the
  login**, and the account sits four OUs below the base;
- `userPrincipalName` is `FIRMANS0@thaiunion.com` while the directory is `DC=thaiunion,DC=co,DC=th`
  — **the UPN suffix is not the DNS domain** and cannot be derived from the base DN;
- `memberOf` IS populated with full group DNs; groups live in mixed containers
  (`OU=Microsoft Exchange Security Groups`, `CN=Users`, `CN=Builtin`) and contain spaces.

So it is now **search-then-bind**: bind as the service account, search
`(|(sAMAccountName=…)(userPrincipalName=…))`, then bind as the DN the directory returned.
⛔ `LDAP_BIND_DN`/`LDAP_BIND_PASSWORD` have been in `.env.local.example` since the beginning and
were **never read by any code** — documented configuration that did nothing.
⛔ **The old direct-bind path is KEPT** as the fallback when no service account is configured: a flat
OpenLDAP tree where `cn=<login>,<base>` really is the DN is a real shape, and removing it would
break an install that works to fix one that does not. That path cannot SEARCH, so it reports
`groups: null` — and the panel warns that no mapping can ever match without a service account.

---

## Commercial Licensing (v2.131.0)

30-day trial by default, then a **per-firewall yearly subscription** (subscription + maintenance).
`lib/productLicense.js` is pure (validation, status, entitlement — no pool, no clock it does not
take as an argument); `lib/productLicenseData.js` is the plumbing and the route guards. Settings →
Subscription; banner in `app/(dashboard)/layout.js`.

⛔ **NAMED `productLicense`, NOT `license`.** `device_licenses`, `getLicenses()` and `/lifecycle`
already exist and are about the FIREWALL VENDOR's entitlements (FortiGuard contracts, PAN-OS
support). Those answer "is the customer's firewall still entitled to signatures"; this answers "is
the customer entitled to SecVault". One word apart is how a session edits the wrong one.

### How the suite does it, and why SecVault does it differently

**NetVault is the hub and validates locally. LogVault/DDIVault/SpanVault validate NOTHING** — each
HTTP-GETs NetVault's `/api/license`, caches the verdict for 5 minutes, and fails open on any network
problem (`<app>/api/licenseCheck.js`). That is correct for a suite module sold with the hub.

⛔ **SecVault CANNOT use the satellite model** — it is a separate product with no runtime dependency
on any sibling app, and it is sold on its own. It follows NetVault's shape: validate locally.

The **key format is byte-compatible with the existing NocVault generator** so one generator issues
keys for the whole range — `base64(ivHex + ':' + aes-256-cbc-hex)`, cipher key `sha256(secret)`,
payload `{customer, serverId, expiry, modules, maxDevices, issuedAt}`. Do not change it.

⛔ **`maxDevices` HAS ALWAYS BEEN IN THE PAYLOAD AND NETVAULT NEVER ENFORCED IT** — it appears there
only in the type, the API echo and the settings display. SecVault is the first product in the range
to make it mean something, so there is no prior art to copy and no sibling behaviour to match.

### Three independent boundaries — keep them separate

| boundary | field | rule |
|---|---|---|
| WHICH MACHINE | `serverId` | the 32-hex hash must match; **the prefix is ignored** |
| WHICH PRODUCT | `modules` | must contain `secvault`; **fails CLOSED** |
| WHEN | `expiry` | yearly; 14-day grace, 60-day renewal notice |
| HOW MANY | `maxDevices` | `active = true` devices; absent ⇒ **unlimited** |

⛔ **BOTH `SCV-` AND `NCV-` PREFIXES ARE ACCEPTED for the same machine hash.** Which one the
generator emits depends on a tool this repo does not contain, and rejecting the other would refuse
every legitimately-issued key for a reason no error message could explain. This loosens nothing:
the hash still has to match, and the PRODUCT boundary is `modules`, checked separately and strictly.

⛔ **`modules` FAILS CLOSED ON AN EMPTY LIST — the deliberate OPPOSITE of the siblings.** They treat
empty as "allow" so legacy suite keys are never bricked. SecVault has never shipped a licence, so
there are no legacy keys to protect, and failing open would turn every NocVault key already in the
field into a free SecVault licence.

⛔ **FIVE STATUSES, NOT FOUR — `invalid` IS ITS OWN STATE.** NetVault's rejected key falls through
to the trial branch, so a customer who pasted a key for the wrong server is told "trial, 12 days
remaining" and never learns their key did nothing. The key was READ AND REJECTED; reporting that as
"no key" is this file's own failed-read-as-a-fact rule wearing a commercial hat. Each rejection
carries one of four reasons — unreadable / wrong_server / wrong_product / expired — because the
customer's next action differs in each case.

### ⛔ THE LINE THE PRODUCT WILL NOT CROSS

**Collection, CVE assessment, compliance evaluation, rule analysis, syslog ingestion, alerting and
reporting run in EVERY licence state, including fully expired.** `monitoringAllowed()` returns a
literal `true` and a test pins the source shape.

This is not generosity. A firewall that silently stopped being assessed shows no CVEs, no failing
checks and no rule findings — **it renders as the healthiest device on the fleet.** That is this
codebase's most-repeated bug class with a commercial motive attached, aimed at exactly the customer
least likely to be watching. An unpaid invoice is a commercial problem; a security blind spot the
customer cannot see is a breach waiting to be attributed to us.

Expiry withholds **growth and administration** — adding a firewall, changing settings, creating an
account. All three are visible, actionable, and harmless to the customer's security posture.

⛔ **The device limit ONLY refuses a NEW firewall** (`canAddDevice`, enforced once, in
`POST /api/devices`). Nothing re-checks it against a device already in the inventory, ever.

⛔ **CHANGING YOUR OWN PASSWORD AND EDITING AN EXISTING ACCOUNT ARE NEVER GATED.** The settings
guard sits INSIDE the admin-field branch, not at the top of the handler. An expired subscription
that could strand an organisation with an account whose password cannot be reset turns a billing
lapse into a lockout from a security platform.

⛔ **THE LICENCE GUARD FAILS OPEN; THE RBAC GUARD FAILS CLOSED.** They sit one line apart in every
route that uses both, and the order is deliberate: RBAC first, because "you may not do this"
outranks "this costs more". A database blip must never lock a paying customer out of their own
platform, but it must also never let anyone past an authorisation check.

⛔ **AN UNCOUNTABLE FLEET IS UNKNOWN, NOT ZERO AND NOT OVER.** `deviceCount === null` leaves
`withinDeviceLimit` null and `canAddDevice` returns `uncountable` — try again. A failed `COUNT`
read as 0 reads as "plenty of headroom"; read as "over" it locks out a paying customer.
(`Number(null)` is 0 and 0 is finite, so a bare `Number.isFinite` guard on `maxDevices` would turn
"this licence does not state a count" into "this licence covers no firewalls".)

### Trial

⛔ **UNLIMITED FIREWALLS FOR 30 DAYS.** The thing being evaluated is whether SecVault can see a
whole estate; a trial capped at a handful demonstrates the opposite of the product.

⛔ **`install_date` IS SEEDED BY `schema.sql` WITH `ON CONFLICT DO NOTHING`**, which is what stops
every deploy restarting the clock. On an install that predates licensing this dates the trial to the
deploy that introduced it, and **that is correct** — deriving it from the oldest row would expire a
running customer the moment they upgraded, on the strength of a rule that did not exist when they
installed.

⛔ **DELETING THAT ROW DOES NOT BUY A FRESH 30 DAYS.** `resolveInstallDate` then re-derives it from
the first user account (falling back to the oldest device) and writes it back. NetVault reports the
full trial length when the row is missing, which makes one `DELETE` an unlimited extension.

### Machine identity

`SCV-` + first 32 hex of `sha256(hostname + '-' + MachineGuid)`. ⛔ **A failed registry read falls
back to a MAC address, not to the empty string.** NetVault's returns `''`, so every machine that
fails the same way AND shares a hostname gets the SAME server id and one key unlocks all of them. A
fallback identity is reported as `weak` in the panel rather than presented as a confident one.

### The secret, honestly

The shared symmetric literal is carried over from NetVault so one generator serves the range.
Anyone who can read the source can forge a key; there is no licence server and no revocation. It
raises the cost of casual copying and nothing more, which is the accepted trade for an on-premises
product with no call-home. ⛔ **The real fix, if this becomes worth attacking, is asymmetric signing
— ship only a public key. Rotating the literal is NOT that fix**: it re-issues every key in the
field for the same weakness.

`product_license_key` is excluded from `GET /api/settings` (`HIDDEN_KEYS`) and from the
`settings_readonly` view — nothing needs it back, and the verdict route never returns it.

### RBAC

New capability `manage_license`, **super_admin only** — the ninth. ⛔ Separate from
`manage_settings`, which `admin` holds: whoever can swap the key decides how many firewalls the
organisation may monitor and when the subscription lapses. That belongs with whoever can also create
accounts. `GET /api/license` is open to any signed-in user (the banner needs it, and an operator who
cannot see "lapses in nine days" is the person most likely to still be using it on day ten); the
Settings tab is visible to every role because the **Server ID** lives there and is the one thing a
customer must read off the server to buy or renew anything.

---

## Feed Sources

| Feed | URL | Schedule | Notes |
|---|---|---|---|
| **Central CVE hub** | `nocvault-eol` `/api/v1/cve-feed` | 6h, **FIRST** | Signed Ed25519 corpus. ⛔ Runs BEFORE NVD — `cve_id` is UNIQUE with one vendor, so feed ORDER IS the attribution rule. **DISCOVERY feed (it inserts), not enrichment.** See its own section below. |
| NVD API 2.0 | `services.nvd.nist.gov/rest/json/cves/2.0` | 6h | ⛔ **5 requests / rolling 30s WITHOUT a key, 50 / 30s WITH one** (verified 2026-09-17 — this table said `5 req/30s w/ NVD_API_KEY`, which is the UNKEYED rate and understates a key by 10x). So ~6.2s between requests unkeyed, ~0.7s keyed. Key goes in an `apiKey` REQUEST HEADER, not the query string (that was the 1.0 API). Always `virtualMatchString`, never `cpeName`. |
| Palo Alto PSIRT | `security.paloaltonetworks.com/api/v1/products/PAN-OS/advisories` | 6h, after NVD | Bulk beta API, ~346 advisories/call, CVE Record Format 5.x. |
| Fortinet FortiGuard | `fortiguard.com/rss/ir.xml` → CSAF 2.0 JSON | 6h, after PA | RSS discovery-only; CSAF is the real data source. |
| CISA KEV | `cisa.gov/.../known_exploited_vulnerabilities.json` | 6h | Full download, cross-referenced by cve_id |
| CVE.org | `cveawg.mitre.org/api/cve/{id}` | 6h, after KEV | **ENRICHMENT-ONLY**, never inserts. CVE Record 5.2. Bounded: ~150 gap rows/run, 13 hash buckets. |
| FIRST EPSS | `epss.empiricalsecurity.com/epss_scores-current.csv.gz` | 6h, last | **ENRICHMENT-ONLY**, never inserts. Bulk CSV; `api.first.org` fallback. |

| Cloud catalogue | M365 `endpoints.office.com` · AWS `ip-ranges.json` · Google `cloud.json` · Cloudflare `ips-v4` | 6h, LAST | **NOT a CVE feed.** Published cloud address space, so a rule referencing `outlook.office365.com` is readable. Live: 11,766 rows in 2.1s. |

⛔ **The cloud catalogue names a PROVIDER, never an application.** An address inside AWS's ranges is
AWS — not Salesforce or anything else a customer runs there. Only some feeds publish a service
breakdown (M365 by serviceArea, AWS by `service`); where a feed gives none, `service` stays NULL and
the label is the provider alone. ⛔ **The feed's granularity is the granularity we may report**: 125
of the 144 live matches fall in Microsoft's own catch-all, so Teams can be said and Word cannot.

⛔ **AN EMPTY CATALOGUE MEANS UNKNOWN, NEVER "NOT A CLOUD APP".** This product installs on segmented
and air-gapped networks — the target customer, not an edge case — where these feeds cannot be
fetched at all. `unavailable` is a distinct state from `no_match` and a test pins them apart. A
**plausibility floor per source** guards the prune so a 200 with a truncated body cannot empty the
catalogue; below it nothing is written or deleted and the sync reports failed. Full rules and the
measured wildcard/apex trade-off: `.ai-codex/lib.md`.

⛔ **A VENDOR PSIRT RUNS ONLY IF THAT VENDOR IS IN THE INVENTORY** (v2.130.0,
`lib/feeds/vendorPsirt.js`). A vendor's own feed is a bespoke integration whose advisories can only
ever match that vendor's devices, so carrying one for a vendor nobody owns is pure cost. ⛔ The
GENERAL databases are deliberately NOT gated — NVD and CIRCL are queried for every supported vendor
whether or not one is deployed, so a firewall added next month already has history behind it.

⛔ **THE GATE FAILS OPEN.** An inventory read that FAILS runs every feed, because a database hiccup
that silently switched off CVE discovery would leave the product not doing its main job while every
signal still looked healthy. ⛔ An EMPTY inventory and an UNREADABLE one are opposite instructions
and must never be collapsed: the first says "skip every vendor feed", the second says "we do not
know". ⛔ A skip is WRITTEN to `feed_sync_log` with status `skipped` and a reason — a feed that simply
stops appearing is indistinguishable from one that silently broke — and `skipped` renders MUTED, not
amber: a permanent warning chip for the system working correctly teaches an operator to ignore the
chip that matters. ⛔ Nothing is deleted; advisories already collected for a departed vendor are
history and stay.

⛔ **Registering a vendor requires a VERIFIED machine-readable source**, same rule as a device parser.
Both obvious additions are still REFUSED, but **the recorded reason for Check Point was wrong and is
corrected here (re-probed 2026-09-18 from three hosts)**:

- **Check Point** — this file said `advisories.checkpoint.com` and its `/feed/` answer **202
  text/html, a bot challenge**. That is NO LONGER TRUE and may never have been the whole story: it now
  answers **200 with 147 KB of ordinary HTML and no challenge markers**, from the SecVault box, an
  office connection and Netlify alike. `/feed/` answers **404**. It is still refused — HTML is not a
  machine-readable source — but the refusal rests on *there being no feed*, not on a bot wall.
  ⛔ A stale reason is worse than none: it sent a session looking for a proxy/UA workaround for a
  problem that had gone away, for a source that was never going to qualify anyway.
- **Cisco** — PSIRT RSS still works (**200, `application/xml`, 146 KB**, reachable from all three
  hosts) and is still a rolling window with no history. `api.cisco.com/security/advisories/v2/all`
  answers **403 "Developer Inactive"** — registered credentials, not merely a missing header.

### ⛔ `blocked` is a FEED STATUS in its own right (v2.152.0)

A feed that RAN and was REFUSED BY ITS PUBLISHER reports `blocked` — not `partial`, which painted a
permanent amber chip for a condition SecVault cannot act on, and **not `skipped`, which means
SecVault DECIDED not to run it**. Collapsing the two would claim we chose not to collect.

⛔ **Excluded from the pill's verdict, never from its evidence**: every title NAMES the blocked feed
and says its advisories come from the other feeds. ⛔ **Every feed blocked still reports
`FEEDS BLOCKED`, never green** — excluding it from the reduction must not let a fleet collecting
nothing read as an all-clear. ⛔ **Narrow and SELF-CLEARING** (`isPublisherBlocked`): true only when
every advisory-page failure was the challenge, NOTHING resolved, no upsert failed and the RSS
itself worked. One resolved page or one upsert error takes the feed straight back out, so no code
change is needed the day the challenge lifts.

⛔ **The exclusion is only right while ANOTHER feed covers that vendor**, and that is measured, not
assumed: Fortinet sits at **282/287 advisories (98%) with usable ranges**, and **all 10 FortiOS CVEs
NVD published in the last 120 days are held and matched** (2026-09-20). If FortiGuard ever became
the only source for a vendor, a block WOULD be a coverage loss and green would be the wrong colour.

⛔ **THE FORTINET BOT CHALLENGE IS ON THE ADVISORY PAGE, NOT THE FEED, AND MOVING HOSTS CANNOT FIX
IT.** Measured 2026-09-18 from the SecVault server, an office connection and a Netlify function:
`fortiguard.com/rss/ir.xml` returns **200 `text/xml`, 38 KB** everywhere (it redirects to
`filestore.fortinet.com`, which answers in ~46 ms and is not fronted by Cloudflare), while
`fortiguard.com/psirt/<id>` returns a **byte-identical 19,751-byte Cloudflare "Just a moment"
interstitial** from all three. It is a JAVASCRIPT challenge: **not IP-dependent and not UA-dependent**
— a Chrome user-agent gets the same page as a bot one. ⛔ **So relocating this fetch to the central
hub would move the failure, not fix it**, and a datacenter IP is typically treated more harshly, not
less. There is also no alternative path: `filestore.../psirt/*.json`, `/psirt/csaf/`, `psirt-csaf/`
and `fortinet.com/.well-known/csaf/provider-metadata.json` all **404** — Fortinet publishes no CSAF
provider endpoint. The cost is bounded: FortiOS is covered via NVD at **282 of 287 advisories with
usable ranges (98%)**; what is missing is Fortinet's own earlier-than-NVD disclosure timing.

⛔ **A VENDOR'S CPE PRODUCT LIST IS COVERAGE, AND UNDER-ASKING IS SILENT** (v2.132.0). Check Point
collected **7 advisories** for a firewall with a thirty-year CVE history, and nothing reported a
problem: the feed ran, the dashboard was green, and `/vulnerability` was simply almost empty. NVD
files the Check Point gateway under ~15 product names accumulated across three rebrands (FireWall-1
→ VPN-1 → Security Gateway → Quantum) and `VENDOR_CPES` asked for four. Expanded to **22 strings,
~107 CVEs**, each probed against the live NVD API with the `totalResults` it returned recorded
beside it. ⛔ **That number is true and misleading and must never travel alone**: only **12 of the
73 newly-reachable CVEs are from 2015 onward** (`firewall-1`'s 43 stop at 2006), so for a fleet on
Gaia R80+ the honest gain is about **7 → 20**. Legacy strings are kept because version matching makes
them incapable of producing a false finding — not because they are worth much. ⛔ And on a site where
NVD is unreachable the gain is **currently zero**: CIRCL returns the same records but without
parseable version bounds, so they are correctly refused as `unmatchable`. The remaining bottleneck
there is CIRCL version extraction, not the CPE list. Forcepoint likewise gained its SMC and the Stonesoft-era `stonegate`.

⛔ **THE VENDOR-LEVEL WILDCARD WAS TESTED, WORKS, AND WAS REFUSED.** `cpe:2.3:a:checkpoint` returns
129 more CVEs — ZoneAlarm, Harmony, Capsule, SmartConsole, the identity and VPN *clients*. None runs
on the firewall and the adapter talks to none of them. Filing an endpoint-agent CVE against a
firewall manufactures urgent work that is not real, which on an evidence-backed product is worse
than the gap it closes. `tests/vendorCpeCoverage.test.js` names those products and fails if one is
ever queried. **Do not "simplify" the list into a wildcard.**

⛔ **The MANAGEMENT plane is deliberately included** (`provider-1`, multi-domain, management/log
server for Check Point; the SMC for Forcepoint) — both adapters authenticate to the management
server, never the gateway, so a management-server CVE is a CVE in something SecVault talks to.

⛔ **A string that returns 0 is KEPT if the product is real.** `forcepoint:flexedge_secure_sd-wan`
answers 0 from both NVD and CIRCL today; the rebrand exists, and a removed string costs the first
advisory ever filed under it. A string that returns 0 because the SPELLING is wrong
(`sangfor:next_gen_application_firewall`) is not listed at all.

Sync order is deliberately **sequential**: NVD → Palo Alto → Fortinet → KEV → CVE.org → EPSS → cloud catalogue (last, so a slow publisher can never delay the advisory feeds).

⛔ **The last two are ENRICHMENT-ONLY and run LAST for that reason** — they add facts to advisories the
discovery feeds just landed. Neither may ever INSERT an advisory row. `advisories.cve_id` is UNIQUE and
carries exactly ONE vendor, so an inserting feed can permanently claim a CVE for the wrong vendor (live
proof: CVE-2022-0778 is an OpenSSL bug Fortinet republishes, and here it belongs to `paloalto` WITH 6 real
version ranges). `inserted` is a structural 0 for both. EPSS alone covers ~371,000 CVEs against the ~1,000
this product tracks. See `.ai-codex/roadmap.md` for the schema-level risk that remains.

⛔ **EPSS DOES NOT FEED THE PRIORITY DECISION TREE**, and that is a deliberate, measured decision, not an
oversight. Measured on the live fleet: 0 advisories are high-EPSS but banded low; the single `patch_now`
is ALSO the highest EPSS (0.861/99.7th pct); all 26 `scheduled` sit at ≤0.0167. So EPSS would only ever
*de*-prioritise here. It also disagrees with KEV in BOTH directions — 8 KEV-listed advisories score below
0.1 (lowest 0.00873) and 56 non-KEV score above 0.1 — so an EPSS gate would have demoted 8 known-exploited
CVEs. Changing the tree requires documenting it HERE first. Each feed's failure is isolated (its own try/catch) and never blocks the next; each gets its own `feed_sync_log` row.

**NVD → CIRCL fallback** (`vulnerability.circl.lu`) triggers ONLY on a true network-level failure (`err.status == null` — timeout/DNS/connection refused), never on an NVD HTTP error response. `FETCH_TIMEOUT_MS = 20000` on every feed call. Full triggering condition, endpoint, and per-vendor fetch quirks (Palo Alto's beta-bulk-endpoint-only rule, Fortinet's CSAF-over-RSS + 1-second inter-fetch delay): `.ai-codex/cve-pipeline.md`, stages 1-2.


## Central CVE feed (`cve_hub`, v2.137.0) — `lib/feeds/cveHub.js`

⛔ **THIS EXISTS BECAUSE THIS SERVER CANNOT REACH NVD AT ALL, AND NO FIREWALL RULE
CAN FIX THAT.** The sites use internal public IP ranges that **overlap NVD's own
address space**, so traffic to `services.nvd.nist.gov` routes to an internal
host. You cannot permit egress to a range your own network claims. Every NVD call
fails at the network level, every CPE string falls through to the CIRCL fallback,
and CIRCL's records carry no parseable version bounds — which `nvd.js` correctly
refuses as `unmatchable`.

Measured 2026-09-18 on the live fleet, both columns scored with **this repo's own
extractor**, so the only variable is the data source:

| vendor | usable ranges via CIRCL | usable from NVD |
|---|---|---|
| `cisco_asa` | 70 / 353 (20%) | **332 / 369 (90%)** |
| `checkpoint` | 0 / 7 (0%) | **68 / 80 (85%)** |

Fleet-wide, **439 of 1,006 advisories could never match a device**. Vendors with a
working PSIRT are healthy (`paloalto` 98%, `fortinet` 67%); the ones that depend on
NVD are gutted. ⛔ **The CPE list and the extractor were never the problem** — both
were fixed correctly in v2.132.0. Only the data reaching the box was wrong.

⛔ **THE TRANSPORT WAS PROVEN BEFORE THIS WAS BUILT**: `eol_catalogue` pulled 2,770
rows from that same hub into this same server on schedule while every NVD call
failed. The address overlap does not touch that path.

### Verification — fails CLOSED

Ed25519 detached signature over the exact received bytes, plus a `sha256` header,
identical in shape to the EOL feed so no new crypto was written. ⛔ **A feed whose
signature does not verify is REFUSED, not imported with a warning** — it is not the
publisher's feed, and applying it would write unverified data into the table that
drives the priority decision tree. ⛔ **Bytes are verified BEFORE `JSON.parse`**;
verifying a re-serialised object would check our own `stringify` output, which
differs from the publisher's for identical data. ⛔ **A verified-but-EMPTY feed is
refused** — a publisher bug emitting zero rows is otherwise a correctly-signed
instruction to change nothing, reported as a clean success.

⛔ **The public key is PINNED IN SOURCE.** The hub also serves it at
`/api/v1/cve-feed/pubkey`, and fetching it from there at verification time would
verify nothing — whoever could swap the feed could swap the key with it. The
repository is the trusted channel. `CVE_HUB_PUBLIC_KEY` overrides it only for a
customer running their own hub.

### The five apply rules — each decided by measurement, not judgement

From the collision report against the live fleet (909 distinct CVEs in the feed):
**74 absent, 835 present with the SAME vendor, 0 with a different vendor, 365
repairable, 1 that would degrade.**

1. **INSERT when the CVE is absent** (74).
2. **REPAIR ranges only when ours are empty and the hub's are real** (365).
3. ⛔ **NEVER replace a non-empty range with an empty one.** Not a preference —
   there is exactly **1** live case, and one is enough: it turns a matched advisory
   into an unmatchable one and the device silently stops being flagged. **The guard
   is expressed TWICE** (JS predicate + a `WHERE` clause on the `UPDATE`), the same
   doubling config retention uses for its delete protections.
4. ⛔ **NEVER change an existing row's vendor.** `advisories.cve_id` is UNIQUE with
   a single vendor, so a re-attribution is permanent and silent.
5. **A CVE the hub holds under TWO vendors** (1 case: CVE-2004-0112,
   checkpoint+forcepoint) keeps whichever we already hold; holding neither, it takes
   the **alphabetically first**, so the choice cannot depend on row order.

⛔ **`matchability` MUST BE `'matched'`, NOT MERELY A NON-EMPTY ARRAY.** An
`unmatchable` hub row with an incidentally-populated array would otherwise overwrite
a good local one — importing a known-bad extraction over a known-good gap, which is
worse than not running at all. Pinned by `tests/cveHub.test.js` (18 cases, 6
mutations verified).

⛔ **ORDER: FIRST, BEFORE NVD.** `cve_id` is UNIQUE with one vendor, so whichever
feed lands a CVE first owns it permanently, and the hub is the only source here with
usable ranges. ⛔ **It is a DISCOVERY feed — it INSERTS**, the opposite of
`cveorg`/`epss`, which is why it does not run last with them. ⛔ **Its failure is
isolated**: if the hub is unreachable the local NVD path still runs immediately
after and CIRCL still backs it up. A central feed that could block local discovery
would be worse than not having one.

### ⛔ The local NVD sync is SKIPPED when the hub delivered (v2.138.0)

On a site whose egress cannot reach NVD, `runNvdSync` can never succeed: it spends
~2 minutes on requests guaranteed to time out and then reports `partial` for ever.
**A permanent amber chip for a system working exactly as designed teaches an
operator to ignore the chip that matters** — the same reason the vendor-PSIRT gate
writes `skipped` rather than letting a feed quietly stop appearing.

⛔ **THE CONDITION IS THE WHOLE SAFETY OF IT.** The skip requires `hubDelivered` —
a VERIFIED, NON-EMPTY corpus **from this cycle**, never a config flag saying "we
use the hub now". If the hub is unconfigured, unreachable, or returned errors, NVD
runs exactly as before with CIRCL behind it. Otherwise the day the hub breaks,
discovery stops silently while every signal stays green.

⛔ **IT ALSO SKIPS CIRCL**, which only runs inside `runNvdSync` as NVD's
network-failure fallback. Those advisories are almost all `unmatchable` (CIRCL
publishes no parseable version bounds), so the loss is small — but it IS a loss,
and it is why the gate is on the hub having DELIVERED rather than on the hub being
configured.

⛔ **THE OTHER FEEDS ARE NOT FALLBACKS AND MUST NEVER BE TREATED AS ONE.** The hub
carries version ranges and nothing else. **CISA KEV is branch 1 of the priority
tree** and the hub does not carry it; Palo Alto PSIRT is vendor-authoritative and
better than NVD for that vendor; EPSS and CVE.org are enrichment the hub has no
column for. Suppressing them while the hub is healthy would stop the product
learning which CVEs are known-exploited — this codebase's signature bug aimed at
its own strongest signal.

### ⛔ `skipped` had no rank, and rendered DEGRADED (fixed v2.138.0)

`FEED_STATUS_ORDER` carried no `skipped` entry, so `feedStatusRank('skipped')` fell
through to the unknown-status rank (1) and `feedState` returned `degraded` — the
exact opposite of what this file has documented since the vendor-PSIRT gate
shipped. **It was latent only because nothing had ever been skipped**: both PSIRT
vendors are in the reference inventory, so `planVendorPsirts` never skipped either.
`skipped` is now its own state, excluded from the pill's worst-state reduction
alongside `missing` — and ⛔ **a fleet where EVERY feed is skipped reports `none`,
never `ok`**, because excluding them all would otherwise leave the reduce seed and
render a product collecting nothing as green. Pinned by `tests/feedSkipped.test.js`.

### ⛔ A frozen hub must be VISIBLE (v2.139.0)

Without this the feed that fixed the blind spot becomes one: a hub that stopped
publishing would be invisible here — the same `feed_version` fetched every six
hours, signature verifying perfectly, nothing applied, `success` logged for ever.
A green light over a corpus that stopped moving.

⛔ **IT READS `checked_at`, NOT `generated_at`, AND THE DIFFERENCE IS THE WHOLE
POINT.** The hub's publish is idempotent — an unchanged corpus republishes nothing
and keeps its version — so `generated_at` only advances when the CONTENT changes.
On a quiet week at NVD a dead hub and a healthy one are indistinguishable by that
field. `checked_at` is `MAX(cve_ingest_state.last_success_at)` on the hub: when it
last completed an ingest target. It advances every healthy run and stops when the
hub does. It arrives in the `X-Feed-Checked-At` header rather than the signed body,
because putting it in the body would change the bytes every run and defeat the
idempotent publish it exists to compensate for.

⛔ **STALE REPORTS; IT NEVER REFUSES.** A stale feed is still VALID data — the
advisories did not become wrong because the hub stopped collecting new ones — so
the feed is APPLIED and the verdict is pushed into `errors`, which is what turns
the sync `partial` and puts it on the banner. Refusing would throw away good
information to protest a different problem.

⛔ **MISSING, UNPARSEABLE, OR IN THE FUTURE ARE ALL `unknown`, NEVER `fresh`.** An
absent header is exactly what an older hub build serves. A `checked_at` in the
future is a clock disagreement, not freshness — the same call `vpn_sessions` makes
on a negative duration. ⛔ And an ABSENT VERDICT contributes an error too: the
defensive branch is where "default it to fine" survives review.

⛔ **A STALE HUB MAKES `hubDelivered` FALSE**, so the local NVD path runs again
with CIRCL behind it. On this site that attempt still fails — but loudly, and
CIRCL may still land something, which beats quietly trusting a frozen central feed
because it happened to verify.

Threshold `STALE_AFTER_MS` = 24h: the hub publishes 6-hourly, so that is four
missed runs. Pinned by `tests/cveHub.test.js` (29 cases, freshness mutations
verified — including one that initially ESCAPED because the test asserted the
`errors.push` LINE existed rather than that it ran; the logic was extracted into
`freshnessErrors()` so it could be tested by behaviour instead of by shape).

⛔ **NOT CONFIGURED IS NOT AN ERROR.** Without `CVE_HUB_LICENSE_KEY` the feed returns
`notRun` and is logged `skipped` **with a reason** — a feed that simply stops
appearing is indistinguishable from one that silently broke.

⛔ **`accept-encoding: gzip` IS SENT EXPLICITLY** — node's `fetch` does not negotiate
compression. Measured: 3.3 MB raw, **173 KB gzipped (5%)**. Omitting it costs a 20x
download on a link this product often shares with a syslog stream.

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

### Backup and restore (v2.133.0)

`installer\Backup-SecVault.ps1` (daily `SecVaultBackup` SYSTEM task, 02:30) and
`installer\Restore-SecVault.ps1`. Sizing figures and the full operator guide live in
`docs/SIZING-AND-BACKUP.md`; the rules that must not drift:

⛔ **RAW SYSLOG IS EXCLUDED BY `--exclude-table-data`, NEVER `--exclude-table`.** Measured
2026-09-16: raw syslog is **197 GB of a 199 GB database (99%)** and SecVault deletes all of it
within 30 days; the irreplaceable part — system of record 902 MB plus permanent rollups 1.9 GB — is
under 1%. But the dump must still carry the `CREATE TABLE` and every partition definition:
`--exclude-table` restores an installation with no partitioned `syslog_events`, the collector
starts, every INSERT fails, and the only symptom is a syslog pipeline that is quietly dead.

⛔ **`.env.local` IS PART OF THE BACKUP.** `device_credentials` is AES-256-GCM keyed on
`CREDENTIAL_KEY`, which exists nowhere else. A dump without it restores an installation that looks
completely healthy and cannot reach a single firewall — collection fails device by device with
authentication errors that read as though the firewalls changed their passwords. The restore
**compares the two keys and ABORTS on a mismatch** (`-SkipKeyCheck` to override deliberately).
⛔ The consequence is that the backup directory is as sensitive as the database — it holds the
encryption key beside the encrypted credentials. ACL it.

⛔ **A BACKUP VERIFIES ITSELF WHILE A GOOD COPY STILL EXISTS.** Free space is checked before the
dump (a dump that fills its volume leaves a TRUNCATED file that looks complete); the finished
archive is read back with `pg_restore --list`; an archive with fewer than 20 entries is rejected
and deleted (an EMPTY archive passes `--list` cleanly); and old sets are pruned **only after** the
new one is verified. A corrupt file that looks like a backup is worse than no backup.

⛔ **THE RESTORE IS A DRY RUN UNTIL `-Force`**, stops services with `sc.exe`, re-runs
`migrate.js` (the dump predates any schema shipped since) and `schema-grants.sql` (dropped by
`--no-acl`), then probes `/api/health` — NSSM reports a crash-looping process as Running.
⛔ It uses the SHARED `Test-SecVaultResponding`; a hand-rolled probe here is how two production
outages happened (see that function's own comment). ⛔ `pg_restore` exits non-zero for benign
"does not exist, skipping" notices on `--clean`; the exit code is not the verdict, the probe is.

⛔ **SIZING IS BY EVENTS/SEC, NEVER BY DEVICE COUNT.** On the reference fleet the busiest firewall
produces **94x** the traffic of the quietest (12.8M vs 136K events/day), so a per-device model is
wrong for almost every customer. `events/sec x 86,400 x 415 bytes x SYSLOG_RETENTION_DAYS`, plus
~35% for the archive. ⛔ The 415 bytes/row holds only at `SYSLOG_RAW_MESSAGE=security`; at `all`
the window roughly triples.

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

⛔ **THE UPDATER UPDATES ITSELF, SO A FIX TO IT LANDS ONE DEPLOY LATE.** Step 3's `git pull`
replaces `Update-SecVault.ps1` while that very script is running — and PowerShell parsed the OLD
copy into memory before step 1. So the run that DELIVERS a fix to the updater still EXECUTES the
unfixed version, and the fix takes effect on the NEXT deploy.

Measured 2026-09-22: v2.164.0 fixed the page-sweep step reporting a false failure, and its own
deploy reported that same false failure — which reads exactly like "the fix did not work". Proven
on the server afterwards that the new code was correct (a bare native call under
`$ErrorActionPreference = 'Stop'` threw; the same call through `Invoke-Native` returned cleanly with
the sweep passing 28/28).

⛔ So when changing this script, VERIFY THE NEW LOGIC DIRECTLY on the server rather than inferring
it from the deploy that shipped it, and expect one more deploy before the behaviour changes. The
same applies to anything else `git pull` replaces mid-run.

Step 5b re-runs `schema-grants.sql` unconditionally (idempotent) using `PG_ADMIN_PASSWORD` read back out of the deployed `.env.local`; missing/empty value or a `psql` failure only logs a warning, never fails the update.

### One-shot backfill ledger (v2.116.0) — why updates are no longer 15 minutes

Measured: `node lib/migrate.js` was **601-823s of a 740-980s deploy (84%)**, and almost none of it
was schema work. It was seven retroactive DATA REPAIRS re-scanning converged tables on every deploy
forever — their own logs read `rewrote 0`, `0 labels written`, `deleted 0, updated 0`.

⛔ **THE COST WAS NOT WHERE IT LOOKED.** The obvious suspect was the PAN-OS config redaction, since
`device_configs` is 776 MB and a candidate scan over it measures 39s. Instrumenting the run showed
otherwise:

| backfill | first run |
|---|---|
| `fortinet-ipsec-auth-repair` | **283.1s (89%)** |
| `palo-alto-config-redaction` | 35.3s |
| the other five combined | <1s |

The FortiOS repair issues `UPDATE syslog_events ... WHERE message LIKE %tunneltype=%ipsec%` with
**no `received_at` bound**, so it scans every daily partition across the whole retention window
(~28M rows/day) to reclassify zero rows. ⛔ That violates this files own rule — never touch
`syslog_events` without a narrow `received_at` window. Do not reinstate it unbounded; if it ever
needs a rerun, bound it and bump its revision. Guess-then-optimise would have fixed the wrong
thing here: measure first, which is why migrate now prints per-step durations.

`lib/backfillLedger.js` records each completed repair in `data_backfills` and skips it thereafter.

⛔ **THE SCHEMA MIGRATION IS NEVER GATED.** `schema.sql` runs unconditionally every deploy — that is
how a new table or column reaches an existing install. Only retroactive DATA repairs pass the gate.
Pinned by `tests/backfillLedger.test.js`.

⛔ **THE REVISION IS THE SAFETY MECHANISM.** Markers are keyed `(name, revision)`. If a repair's
LOGIC is corrected, BUMP ITS REVISION IN THE SAME COMMIT or every install still holding the broken
data will never run the fix. Precedent: the PAN-OS re-redaction shipped TWICE (the first pass was
XML-only and missed 343 rows in CLI brace grammar) — it is gated at revision 2 for that reason.

⛔ **ONLY A CLEAN RUN IS RECORDED.** These repairs are deliberately non-fatal, so silent failure is
possible; marking a failed repair complete is the failed-read-as-a-fact bug applied to this file's
own maintenance. ⛔ An UNREADABLE ledger **fails OPEN** — the one place in this codebase where that
is right, because re-running is idempotent and costs minutes while skipping wrongly leaves
plaintext secrets in the database.

⛔ **The FIRST update after this change still runs everything** (empty ledger) and is slow; the one
after it is fast.

⛔ Unexplained, left gated but flagged: `backfillPaloAltoVersionRanges` reported `cleaned up 302` on
EVERY run and 351 advisory rows share one `updated_at` — it was rewriting rows to identical values,
which also explains 18.6% dead tuples on `advisories`. Stored ranges look correct. First place to
look if advisory version matching ever regresses.

### ⛔ jsonb DOES NOT PRESERVE KEY ORDER — never compare it with JSON.stringify

`jsonb` is a parsed binary form: keys come back sorted by LENGTH then bytes, not as written. So
`JSON.stringify(valueFromDb) === JSON.stringify(valueBuiltInJs)` is **false for identical data**,
always. Live cost: `backfillPaloAltoVersionRanges` used exactly that as its "already clean" guard,
so the guard could never fire once — it rewrote the same 302 advisory rows with byte-identical data
every deploy for months, logged `cleaned up 302` each time, and left `advisories` at 18.6% dead
tuples. ⛔ **The data was never wrong; the comparison was** — which is why nobody looked. A guard
that cannot fire is worse than no guard: the code reads as handled and the log reads as success.

Use `lib/canonicalJson.js` (`jsonEquivalent`) for any has-this-changed check against a jsonb column.
⛔ Object keys are order-insensitive, ARRAYS ARE NOT — array order carries meaning and sorting one
would make genuinely different rangesets compare equal, suppressing a real repair.

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
# Sign out after inactivity. 30 by default; 0 switches it off. Accepted range
# 2-1440 minutes, and anything unparseable (including a NEGATIVE) falls back to
# 30 rather than to off -- a typo must never silently remove the control.
# Settable from Settings -> Security, which writes it here; NextAuth reads it
# ONCE at startup, so a change needs a SecVault-App restart and the panel says so.
SESSION_IDLE_MINUTES=30

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
SYSLOG_MAX_BUFFER=400000                   # in-memory datagrams; overflow is COUNTED, not hidden.
                                           # Raised from 200000 on 2026-09-12: at the measured
                                           # ~1,000 datagrams/sec this is ~400s of headroom, and
                                           # the incident that dropped 324,875 events stalled for
                                           # ~290s. NOT the fix (see the rollup deferral below) --
                                           # margin, so the next unknown stall is survivable.
                                           # ~340 bytes/datagram => ~136 MB worst case, on a box
                                           # where the collector normally holds well under 200 MB.
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
SYSLOG_ARCHIVE_RETENTION_DAYS=60           # ~500 GB at 8.4 GB/day measured.
                                           # ⛔ The reference deployment actually runs 45, set
                                           # explicitly in its own .env.local. This 60 is the CODE
                                           # default, which that box never uses -- see gotchas.md
                                           # ("Raising a CODE DEFAULT does nothing...") before
                                           # assuming any value in this list is what is running.
SYSLOG_ROLLUP_RECENT_HOURS=1               # frequent narrow re-aggregation (+1h; was 3, overran the cycle)
SYSLOG_ROLLUP_LOOKBACK_HOURS=24            # hourly WIDE sweep, SLICED 6h/pass; catches late-arriving events
SYSLOG_ROLLUP_INTERVAL_MINUTES=5
LOG_HIT_LOOKBACK_DAYS=7                    # [log-hit] window; SHORTER than retention on purpose

# Log retention
LOG_RETENTION_HOT_DAYS=90
LOG_RETENTION_WARM_DAYS=365

# Page-render smoke sweep (scripts/smoke.js). Optional; blank = the update logs a
# SKIP with its reason rather than reporting a pass. Use a dedicated local account
# WITHOUT MFA - the harness cannot supply a second factor.
SMOKE_USER=
SMOKE_PASS=


# Commercial licence (optional — leave BLANK on every normal install)
# SECVAULT_LICENSE_SECRET is a per-install ROTATION HOOK, not a setting to fill in.
# The shared NocVault secret is compiled in, which is what lets ONE generator issue
# keys for the whole product range. Setting this means keys minted with the shared
# secret stop working on THIS server and every key for it must be re-issued against
# the value you chose. No installer provisions it. Leave it blank unless you are
# deliberately isolating one deployment.
SECVAULT_LICENSE_SECRET=

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

⛔ **EVIDENCE IS A SEPARATE AXIS AND OWNS VIOLET** (`--evidence` / `--evidence-wash`, aliased
onto the purple tints, v2.107.0). Severity answers "how bad is this"; evidence answers "how well do
we know it", and a fully-proven critical and a poorly-evidenced one are both critical. So the proof
affordance may not borrow from the severity ramp at all. **Nothing else in the app is violet** — the
moment a second thing uses it, the mark stops being learnable at a glance and the operator has to
read every one to find out what it does. Used only by `.ev-*` and `EvidenceMark`.

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

- **Evidence drawer + answer-first headers** (v2.107.0, Phase 1 of the evidence-grade rework):
  every headline figure carries a violet mark that opens one global drawer showing the formula, the
  inputs, and **what could not be measured**. Descriptors are built by the pure `lib/evidence.js`;
  the dashboard sentence by the pure `lib/answers.js`. ⛔ The rule that makes it honest rather than
  decorative: **an all-clear is forbidden while coverage is incomplete** — a clean result over a
  partially-assessed fleet renders hueless as `unknown`, never green as `ok`. Pinned by
  `tests/evidence.test.js` + `tests/evidencePages.test.js`. **Phase 1 complete at v2.109.0** —
  wired on the dashboard, `/vulnerability`, `/compliance`, `/analysis`, `/lifecycle`, `/devices`
  and `/exposure`. ⛔ The drawer footer is CUSTOMER-FACING: it names a PRODUCT engine and a
  SecVault POLICY, never a source path and never this file — `tests/noInternalRefs.test.js`
  fails the build if `CLAUDE.md` appears in any string literal under `app/`, `components/` or
  `lib/` (comments are fine and encouraged). `/analysis` adds one read-time
  grouped count of `firewall_rules.hit_count`'s three states so the page can lead with how many
  rules have NO usage data — no schema change and no new job. Full detail in
  `.ai-codex/lib.md` / `components.md`.
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

### ⛔ Log search has THREE bounds, and the third was missing until v2.144.0

`lib/syslog/logSearch.js` bounded the WINDOW and the ROW COUNT. Neither prevents
the thing its own header warns about — "a careless query would evict the buffer
cache out from under an ingest running at ~1,500 rows/second" — because a legal
24h window on a busy firewall is still millions of rows, and
`ORDER BY received_at DESC LIMIT n` only exits early **if enough rows MATCH**.

Measured on OKF(F2) (~406,000 events/hour), same device, same 24h window:

| filter | time |
|---|---|
| common `src_ip` | **23ms** (fills the LIMIT at once) |
| busy `dst_ip` | **32ms** |
| **indexed** `threat_name`, 0 matches here | **10,969ms** |
| rare `application` | **never returned** |

⛔ **COST TRACKS HOW RARE THE VALUE IS, NOT WHICH COLUMN IS INDEXED** — the
indexed column was the slow one, because an index does not help when there is
nothing to find. And the rarest value is usually the one worth investigating, so
the worst case is the useful case.

⛔ **`STATEMENT_TIMEOUT_MS` (10s) is now the third bound**, applied with
`SET LOCAL` inside a transaction on a DEDICATED CLIENT — `pool.query` hands back
an arbitrary connection, so a timeout set that way leaks onto unrelated queries
or applies to none.

⛔ **A TIMED-OUT SEARCH IS ITS OWN STATE, NEVER AN EMPTY RESULT.** It returns
`timedOut: true` with a reason, and `LogResults` renders a distinct panel saying
so. Returning `[]` would render as "nothing matched" and an investigator would
conclude a host never connected when the question was simply never answered —
the failed-read-as-a-fact rule at its most dangerous, on a forensics page.

⛔ **INDEXING `src_ip`/`dst_ip` IS STILL REFUSED.** The write cost lands on the
collector at ~1,000 inserts/sec, and the measurement above shows an index would
not even fix the slow case.

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

### ⛔ The three gates OUTSIDE `npm test`, and why none of them is in it

`npm test` is pure engines with stub pools. That is deliberate and cheap, and it means the suite
can never see a route, a page, or a real schema. Three scripts cover those, each needing a built
app and/or a database, each FAILING LOUDLY rather than skipping (a gate that skips is the
guard-that-cannot-fire pattern), and each behind its own script:

| script | what it proves | scale |
|---|---|---|
| `npm run smoke` | every PAGE renders with a real session and a per-page content marker | 28 pages |
| `npm run apisweep` (v2.163.0) | every API route is auth-gated, refuses bad params, and does not 500 | 82 route files, 375 assertions |
| `npm run dbcheck` (v2.163.0) | every READ function's SQL executes against the real schema | 104 functions, 537 statements |

⛔ **`apisweep` FOUND A LIVE 500 ON ITS FIRST RUN** — `findGitRoot()` called with no argument
threw, so `GET /api/system/console-url` answered 500 and the PUT on both it and
`/api/system/session-policy` was DEAD: neither the console address nor the idle timeout could be
saved from Settings. `|| process.cwd()` after it was a fallback that could never fire. Nothing in
`npm test` calls a route, which is exactly why it was invisible.

⛔ **`dbcheck` CALLS THE REAL EXPORTED FUNCTIONS, never a copy of their SQL** — a second copy
drifts from what ships and then only proves things about itself. It also HARVESTS SWALLOWED ERRORS
(`gatherWorkQueue`'s per-source `{ok:false}`, the report builders' `failures[]`), because those
RESOLVE on a broken query: a checker that only asked "did it throw" would go green over a page
rendering a named gap. ⛔ Read-only is enforced THREE ways — the role, a name guard, and a
statement guard that inspects every query before it leaves the process. The third is not redundant:
`resolveInstallDate` begins with a READ verb and INSERTs, so the name guard passes it.
⛔ It exits non-zero when `schema.sql` declares something the live database lacks, which is the
`CREATE TABLE IF NOT EXISTS` trap in `.ai-codex/gotchas.md` made visible.

⛔ **NEITHER COVERS A MUTATING ROUTE.** `apisweep` refuses any verb outside a two-entry allow-list
because it runs against the production fleet, and `dbcheck`'s role cannot write. Every
400-on-bad-body and 409-on-conflict path is still unverified, and so is role-specific denial — only
a super_admin test account exists, so a genuine 403 cannot be produced live. Both are stated in
those files' headers rather than left implied.

### ⛔ The page-render smoke sweep (`npm run smoke`, v2.150.0) — the one gate that loads a page

**Nothing in `npm test` renders a page, and the four guards that sound like they do each stop
short by design**: `jsxSyntax` parses (syntax only), `moduleLoad` deliberately EXCLUDES `app/` and
`components/`, `importIntegrity` scans for a mentioned-but-unimported name, and `reportRoute`
regex-asserts `clientSafe()` on `/reports` alone. Every dashboard page is `force-dynamic`, so
`next build` never evaluates one either.

That is how **v2.120.0 shipped a blank `/reports`**: a `builder` FUNCTION passed from a server
component to a client one, which React refuses to serialise. 2,399 tests passed, the build was
clean, the deploy verified, and because a production build withholds the message "to avoid leaking
sensitive details" the only symptom was a digest on an empty page. The same blindness produced the
v2.86.1 outage (a wrong column name), where "the only real gate was loading the page".

`scripts/smoke.js` signs in and loads all 28 of them, asserting a per-page CONTENT MARKER.
⛔ **A marker may never be a NAV LABEL** — the sidebar renders those into every page from the
shared layout, so such a marker is satisfied by a working shell around a dead page, which is the
exact failure being hunted. Pinned by `tests/smokeHarness.test.js`, which also feeds the verdict
logic the v2.120.0 shape directly: a live sweep only ever exercises the green path, and a harness
that has never gone red proves nothing.

⛔ **IT IS NOT IN `npm test` AND MUST NOT BE.** It needs a built app, a running server and a
database. A test that skips when it cannot reach one is the guard-that-cannot-fire pattern; this
FAILS LOUDLY instead and lives behind its own script. `Update-SecVault.ps1` runs it after the HTTPS
verify, **non-fatally** — a broken page is not a reason to roll a deploy back (the rollback there
restores a TLS entry point, which would not fix it) — but it sets `hadFailure`, so the closing
banner cannot say "completed successfully" over a page that did not render.

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
# ⛔ node --check IS A NO-OP ON ESM. Measured 2026-09-19: an unterminated string, an
# unclosed paren, a double comma and a broken function signature ALL exit 0 in a file
# with a top-level `import`, and all exit 1 without one. It is a real check for the
# CommonJS half of the repo and worth nothing for app/** -- which is how a syntax
# error in an API route reached main. `npm test` is what actually catches this.
node --check lib/**/*.js services/**/*.js                 # CommonJS only -- see above
npm test                                                  # must be zero failures; the REAL syntax gate
npm run build                                             # must be zero errors
# If a PAGE or a server->client prop changed, also sweep a running instance:
#   SMOKE_URL=https://<server>:3010 SMOKE_USER=… SMOKE_PASS=… SMOKE_INSECURE=1 npm run smoke
# Nothing in `npm test` renders a page -- see the smoke-sweep note under Testing.
# If schema.sql changed: verify all new tables have per-table grants for readonly users
# If new env vars added: add to .env.local.example
# Update CLAUDE.md if architectural decisions were made
```

### Deploy After Commit
```powershell
# On production server:
& "C:\Apps\SecVault\installer\Update-SecVault.ps1"
```
