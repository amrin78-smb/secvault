# SecVault — Fresh Install Checklist

The operator-facing procedure for installing SecVault on a **clean Windows Server**, and for
proving afterwards that what came out actually works.

Everything below is grounded in the installer scripts, `CLAUDE.md`, or `.ai-codex/gotchas.md`.
Nothing here is a guess about what "should" happen — where this document says a check exists
because a specific failure happened, the failure is named.

> **The theme of this document.** Almost every failure this product has had on Windows looks
> *successful* from the outside: `sc.exe` reports Running while node crash-loops, `git pull`
> reports success while pulling nothing, the collector binds a port and receives nothing,
> a deploy reports "completed successfully" over a blank page. **So every verification step
> below checks an EFFECT, never an exit code.**

---

## 0. Before you touch the server — two decisions you cannot easily reverse

### 0.1 Where will PostgreSQL's data directory live?

⛔ **Decide this first. It is the single most consequential choice in the install, and the
installer does not ask.** `Install-SecVault.ps1` runs the bundled PostgreSQL installer with no
`--datadir`, so a fresh install lands on the vendor default:

```
C:\Program Files\PostgreSQL\16\data
```

— the **system volume**. SecVault's syslog ingestion is sized for the reference deployment, whose
data directory is on a separate 2 TB volume; `CLAUDE.md` states the case plainly: *"A future
rebuild that accepts the PostgreSQL installer default silently gets a fifth of the capacity this
retention assumes, and fills the SYSTEM volume doing it."*

Filling `C:` does not degrade SecVault. It takes **Windows** down.

**Either:**
- install PostgreSQL 16 yourself onto a data volume **before** running `Install-SecVault.ps1`
  (the installer detects an existing PostgreSQL via `C:\Program Files\PostgreSQL\16\bin\psql.exe`
  and will reuse it, resetting only the superuser password), **or**
- accept `C:` and **lower `SYSLOG_RETENTION_DAYS` / `SYSLOG_ARCHIVE_RETENTION_DAYS` accordingly**
  (see 0.2) before the collector ever starts.

⛔ If you pre-install PostgreSQL to a non-default path, note that `Install-SecVault.ps1` hardcodes
`$PgDataDir = 'C:\Program Files\PostgreSQL\16\data'` for its superuser-password reset and will
**Fail with an explicit message** if `pg_hba.conf` is not there. That is a loud failure, not a
silent one — but plan for it.

### 0.2 How much syslog will this fleet actually send?

⛔ **Size by EVENTS/SEC, never by device count.** On the reference fleet the busiest firewall
produces **94x** the traffic of the quietest (12.8M vs 136K events/day), so a per-device estimate
is wrong for almost every customer.

```
bytes = events/sec  x  86,400  x  415  x  SYSLOG_RETENTION_DAYS
archive ≈ + 35%
```

The 415 bytes/row figure holds **only** at `SYSLOG_RAW_MESSAGE=security`; at `all` the window
roughly triples. Full method: `docs/SIZING-AND-BACKUP.md`.

Write the two numbers you chose down now — you will set them in step 5.

---

## 1. Prerequisites

### 1.1 The server

| | |
|---|---|
| OS | Windows Server (PowerShell **5.1** — the scripts are written for it and use no PS7 syntax) |
| Rights | Run the installer from an **elevated** PowerShell. `Install-SecVault.ps1` declares `#Requires -RunAsAdministrator`. |
| Install path | `C:\Apps\SecVault` — **fixed**, not a parameter. NSSM path casing is load-bearing (see 7.2). |
| Network (in) | Inbound TCP on the console port; inbound UDP+TCP on the syslog ports. The installer creates these rules — see 6.5. |
| Network (out) | ⛔ **Mandatory.** `github.com:22` and `registry.npmjs.org:443` — see 1.2. |

### 1.2 Internet access — mandatory, and checked before anything is installed

⛔ **SecVault cannot be installed on an air-gapped server.** The prerequisites in
`installer\dependencies\` install from local files, but the **application itself** is cloned from
GitHub and its dependencies come from the npm registry:

| Destination | Why |
|---|---|
| `github.com:22` | `git clone` of the private `amrin78-smb/secvault` repo, over SSH with the deploy key |
| `registry.npmjs.org:443` | `npm ci` |

`Install-SecVault.ps1` probes both with a raw TCP connect **before it installs a single
prerequisite**, and stops with **nothing changed on the machine** if either is unreachable. Finding
this out at the end — after PostgreSQL, Node, Git and NSSM are already on the server — is the
difference between "not supported here" and "a half-provisioned server".

⛔ **A proxy can make the raw probe fail while `git` and `npm` themselves work.** That is the only
reason `-SkipConnectivityCheck` exists. It skips the **probe**, never the requirement: if the
endpoints really are unreachable the install still fails, just later and less clearly.

**Why the source is not bundled.** An earlier package shipped the application and `node_modules`
inside the installer so it could run offline. It was dropped deliberately: a copied tree carries no
`.git`, so `Update-SecVault.ps1` and Settings → Update had nothing to pull into and that
installation could **never update itself** — with no error, the update button simply doing nothing.
For a security product, "cannot ever update" is a worse property than "needs internet once".

### 1.3 The bundled dependency binaries

`Install-SecVault.ps1` installs its prerequisites **from local files**, with no internet download.
Place these in `installer\dependencies\` next to the script before running it
(`installer\dependencies\README.txt` is the authoritative list):

| File | Required? | Where it comes from |
|---|---|---|
| `node-v20.19.0-x64.msi` | yes | NocVault-Suite-v1.1 distribution package |
| `postgresql-16.14-1-windows-x64.exe` | yes | same |
| `nssm-2.24.zip` | yes | same |
| `Git-2.54.0-64-bit.exe` | yes* | same |
| `VC_redist.x64.exe` | optional | same |
| `secvault_deploy` | **yes** | GitHub → `amrin78-smb/secvault` → Settings → Deploy keys |

\* Git is skipped if already present — but **do not skip it deliberately**. Git for Windows is a
hard dependency for two separate reasons: `git pull` (the entire update mechanism) and **OpenSSL**,
which `installer\SecVault-Tls.ps1` uses to mint the certificate. `New-SelfSignedCertificate` cannot
be used — on PS 5.1 it can only export a PFX, and node's `https.createServer` is being handed PEM.

⛔ `secvault_deploy` is an **ed25519 private key, no passphrase, no file extension**. Without it the
installer stops at step 3 with an explicit message; the repo is private and `git clone` cannot
authenticate any other way on a clean server.

⛔ These binaries are **not** in the git repository (`.gitignore`); only `README.txt` is tracked.
Copy them from the NocVault-Suite distribution package rather than re-downloading, so versions match.

### 1.4 Anything already holding a syslog port

If the server already runs a syslog collector (ManageEngine Firewall Analyzer, a Splunk forwarder,
rsyslog-for-Windows), decide now whether it keeps 514. `SecVault-Collector` binding a port another
process holds is the one startup failure the closing banner calls out by name.

---

## 2. The command line

From an **elevated** PowerShell, in the directory containing `Install-SecVault.ps1`:

```powershell
.\Install-SecVault.ps1 -ServerIp 192.168.7.69
```

Every parameter:

| Parameter | Default | What it does, and what to watch for |
|---|---|---|
| **`-ServerIp`** | *(detected)* | The address a **browser** uses to reach the console — `NEXTAUTH_URL`, the certificate SAN, the closing banner. Leave it out: the installer lists this machine's own addresses, default-route interface first, and asks you to pick. ⛔ **It is NOT the database host** — `DATABASE_URL` is always loopback. ⛔ A value that is not an address on this machine is **confirmed, not refused** (a server behind NAT is a real shape) — a one-digit typo here completes the install and then bounces every sign-in with no error anywhere, which is exactly what happened on the first real fresh-install test. |
| `-AcceptServerIp` | off | Accept a `-ServerIp` that is not an address on this machine, without the confirmation. |
| `-SkipConnectivityCheck` | off | Skip the reachability **probe** (see 1.2), never the requirement. |
| `-Unattended` | off | Answer every prompt from its default. For a scripted or imaged deployment. |
| `-DbPassword` | `NVAdmin2026Secure` | Password for the `secvault_user` PostgreSQL role. **Change it.** Alphanumeric only, deliberately: it is embedded in a combined `-ArgumentList` string, and `#`/`@`/quotes can be silently re-parsed by the BitRock installer into a *different* password than the script thinks it set. |
| `-AppPort` | `3010` | Console port. HTTPS and the same-port plaintext→301 redirect both live here; the port does **not** change when TLS is on, so bookmarks and firewall rules keep resolving. |
| `-SpoolDir` | `C:\Apps\SecVault\spool` | Durable syslog spool — fsync'd **before** the DB insert and replayed on restart. Must exist and have room; the installer creates it. Point it at a data volume on a busy fleet. |
| `-SyslogPorts` | `514,1514` | Comma-separated. Both are bound **and** both get inbound firewall rules. 1514 is in the default because the fleet SecVault replaced had most firewalls configured to it. |
| `-EnableTls` | `$true` | Mint a self-signed certificate and serve HTTPS on `-AppPort`. Pass `$false` for plain HTTP. **Fresh-install default only** — `Update-SecVault.ps1` never switches an existing install's transport on its own. |
| `-HttpRedirectPort` | `3080` | Plain-HTTP listener that 301s to the console. Only used when TLS is on; gets its own firewall rule. |
| `-NetVaultUrl` | *(empty)* | Optional SSO federation to NetVault. **Leave blank** — SecVault is a separate product with no runtime dependency on any sibling. |

Realistic invocation:

```powershell
.\Install-SecVault.ps1 `
    -ServerIp      192.168.7.69 `
    -DbPassword    'ChooseSomethingAlphanumeric2026' `
    -SpoolDir      'E:\SecVaultSpool' `
    -SyslogPorts   '514,1514'
```

### What the installer generates for you — never supply these

Three secrets are generated fresh on **every** run and written to `.env.local`. There is no
parameter for any of them and you should never invent one:

- `CREDENTIAL_KEY` — 32 random bytes. AES-256-GCM key for `device_credentials`. ⛔ **It exists
  nowhere else on earth.** Lose it and every stored firewall credential is unrecoverable — see 8.
- `NEXTAUTH_SECRET` — session signing key.
- `PG_ADMIN_PASSWORD` — the PostgreSQL `postgres` superuser password. The app never uses it (it
  only ever connects as `secvault_user`); `Update-SecVault.ps1` reads it back out of `.env.local`
  to re-apply `lib\schema-grants.sql` non-interactively on every update.

⛔ If PostgreSQL is **already installed**, the script does not guess its existing superuser
password — it force-resets it to the freshly generated value through a temporary trust-auth window
in `pg_hba.conf`, restoring the original file in a `finally` whether or not the reset succeeded.
**If another application on this box connects as `postgres`, it will stop working.**

---

## 3. What the installer does, in order

Useful for knowing where you are when it stops.

1. **Connectivity preflight** — `github.com:22` and `registry.npmjs.org:443`. ⛔ Deliberately
   first: if it stops here, nothing on the machine has been changed.
2. Bundled prerequisites: VC++ → Git → Node.js → PostgreSQL → NSSM
3. SSH deploy key → `%USERPROFILE%\.ssh\` **and** `C:\ProgramData\SecVault\ssh\`
4. Auth test against GitHub, then `git clone` to `C:\Apps\SecVault`
5. `CREATE DATABASE` / `CREATE USER` / `GRANT ALL ON SCHEMA public` (all via `-h localhost`)
6. `.env.local` written from `.env.local.example`, secrets generated
7. `npm ci` → `node lib\migrate.js` → `lib\schema-grants.sql` → `npm run build`
8. TLS: mint certificate, set `ENABLE_TLS`/`TLS_*`/`NEXTAUTH_URL`, choose the service entry point
9. Register the three NSSM services
10. Create the spool directory; add firewall rules
11. `sc.exe start` × 3, verify they stayed running, probe `/api/health`
12. Register the `SecVaultBackup` daily task (02:30, SYSTEM) — best effort
13. Closing banner

⛔ **Both the SSH key copies are required.** `%USERPROFILE%\.ssh\` serves the admin running the
installer by hand; `C:\ProgramData\SecVault\ssh\` serves the in-app "Update Now" button, which runs
`Update-SecVault.ps1` as a **SYSTEM scheduled task** with a completely different profile. This was a
real bug: with only the first copy, in-app updates silently did nothing.

---

## 4. Read the closing banner — but do not stop there

A good banner looks like:

```
==================================================
 SecVault installed successfully.
 URL: https://192.168.7.69:3010
 TLS: ON (self-signed certificate -- your browser will warn until you install your own
      via Settings -> Certificate).
 Plain HTTP on port 3080 redirects here.
 Default login: admin / changeme (change immediately via Settings)
==================================================
```

⛔ **A browser certificate warning on first visit is EXPECTED.** The certificate is self-signed.
An operator meeting an unexplained security warning on a brand-new security product reasonably
concludes the install is broken — it is not. Replace it from **Settings → Certificate** when you
have a corporate one.

If the banner reports a service not running, it also names the log to read. Go to section 7.

---

## 5. Set the sizing values you chose in step 0 — BEFORE traffic arrives

Edit `C:\Apps\SecVault\.env.local` and restart the collector:

```powershell
sc.exe stop SecVault-Collector
# edit C:\Apps\SecVault\.env.local
sc.exe start SecVault-Collector
```

Keys to review on a fresh install (each is documented in place in `.env.local.example`):

| Key | Default | Why review it |
|---|---|---|
| `SYSLOG_RETENTION_DAYS` | `30` | Sized for the reference fleet on a 2 TB volume. See 0.1/0.2. |
| `SYSLOG_ARCHIVE_DIR` | *(blank)* | Blank = `C:\Apps\SecVault\archive` — a **second** claim on the system volume, ~8.4 GB/day at the reference rate. Set it to a data volume now; moving it later strands the existing archive. |
| `SYSLOG_ARCHIVE_RETENTION_DAYS` | `60` | ≈500 GB at the reference rate. Note the reference deployment itself runs **45**, set in its own `.env.local` — `60` is running nowhere today. |
| `SYSLOG_SPOOL_DIR` | *(set by `-SpoolDir`)* | Constantly rewritten. Keep it off the OS disk if you can. |
| `SNMP_POLL_INTERVAL_MINUTES` | `15` | ⛔ `15` is a **divisor** of `VPN_POLL_INTERVAL_MINUTES=30`, so the two cron jobs fire together at `:00`/`:30` and the metric poll defers. Half your metric ticks are lost, reported only as an INFO line in `engine.log`. Set it to a non-divisor (e.g. `14`) if you want the stated cadence. |

⛔ **`.env.local.example` is a TEMPLATE. Nothing reads it at runtime.** Once `.env.local` exists,
changing a default in the example — or in code — changes **nothing** on this server, for that key,
forever. This has caught the project twice. Edit `.env.local` itself.

---

## 6. Post-install verification — the part that actually matters

Do all of these. Each one proves something the one before it does not.

### 6.1 ⛔ `sc.exe` reporting Running is NOT evidence the app is serving

This is the most important sentence in this document, and it is in `CLAUDE.md` for the same reason:
**NSSM restarts a crashing process.** A node process that crashes on startup is restarted, crashes,
is restarted — and `sc.exe query` reports `RUNNING` the entire time. Two production outages, and one
blank-page deploy, went undetected behind a green service state.

```powershell
sc.exe query SecVault-App
sc.exe query SecVault-Engine
sc.exe query SecVault-Collector
```

Treat this as **necessary, not sufficient**. It tells you the service exists and the SCM has not
given up. It tells you nothing about the application.

### 6.2 The real liveness check: `/api/health`

```powershell
# From the server itself. -SkipCertificateCheck does NOT exist on PS 5.1 --
# this is the PS 5.1-compatible form the installer's own probe uses.
[System.Net.ServicePointManager]::SecurityProtocol = [System.Net.SecurityProtocolType]::Tls12
try {
    $r = Invoke-WebRequest -Uri 'https://127.0.0.1:3010/api/health' -UseBasicParsing -TimeoutSec 10
    Write-Host "Status: $($r.StatusCode)"
} catch {
    if ($_.Exception.Response) {
        Write-Host "Status: $([int]$_.Exception.Response.StatusCode) -- APP IS SERVING"
    } else {
        Write-Host "NO RESPONSE -- the app is NOT serving. Go to 7.1."
    }
}
```

⛔ **A `401` is a PASS.** `/api/health` sits behind the app's normal auth (`middleware.js` gates
every `/api/*` route with no exemption), so unauthenticated it answers 401 — and a 401 is proof
that node is up, Next is routing, and middleware ran. Any HTTP status counts as alive. Only *no
response at all* is a failure.

⛔ If the certificate makes this awkward, do **not** reach for
`ServerCertificateValidationCallback = { $true }`. **It does not work on PowerShell 5.1** — .NET
invokes that delegate on a background thread with no PowerShell runspace, the scriptblock throws
*"There is no Runspace available to run scripts in this thread"*, and the connection dies with a
misleading send error. **This cost two production outages**, because the updater's probe always
returned false over HTTPS and rolled back deployments that had worked. `installer\SecVault-Tls.ps1`
uses an `ICertificatePolicy` type instead, which is a real .NET type whose method runs on the
calling thread. Reuse `Test-SecVaultResponding` from that file rather than hand-rolling a probe:

```powershell
. C:\Apps\SecVault\installer\SecVault-Tls.ps1
Test-SecVaultResponding -Port 3010 -UseHttps -TimeoutSeconds 30    # $true = serving
```

### 6.3 ⛔ `/api/health` does NOT touch the database — prove that separately

`/api/health` is deliberately DB-free, so that a database hiccup during a service restart cannot
make health-polling itself throw. **A 200/401 therefore says nothing about the database.**

Prove the database separately:

```powershell
$env:PGPASSWORD = '<PG_ADMIN_PASSWORD from C:\Apps\SecVault\.env.local>'
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U postgres -h localhost -d secvault `
  -c "SELECT count(*) AS tables FROM information_schema.tables WHERE table_schema='public'"
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U postgres -h localhost -d secvault `
  -c "SELECT username, role FROM users"
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U postgres -h localhost -d secvault `
  -c "SHOW data_directory"
Remove-Item Env:\PGPASSWORD
```

Expect: a substantial table count, exactly one `users` row (`admin` / `super_admin` or `admin`),
and a `data_directory` that is the volume you decided on in step 0.

⛔ `psql` invoked from PowerShell can return exit code `-1` even when the command **succeeded**
(output went to stderr). Judge by the output, not the exit code.

### 6.4 Sign in — the only check that exercises the whole stack

Browse to the URL in the banner (`https://<ServerIp>:<AppPort>`), accept the self-signed warning,
and sign in.

```
username: admin
password: changeme
```

⛔ **Change it immediately**, from **Settings → Users**. It is seeded by `lib/migrate.js`
(`DEFAULT_ADMIN_USERNAME` / `DEFAULT_ADMIN_PASSWORD`), is identical on every SecVault installation
in the world, and is in a public-ish repository. Then, before anything else:

1. **Change the `admin` password.**
2. **Enrol MFA** (Settings → your account). TOTP, optional per user; a Super Admin can require it.
   Keep the 10 recovery codes — they are shown **once**.
3. If this is a customer deployment, deal with the diagnostic database roles — see 6.7.

⛔ **If sign-in bounces straight back to the login page with no error anywhere**, that is the
`NEXTAUTH_URL` scheme mismatch, not a wrong password. See 7.5.

### 6.5 Prove the collector is actually receiving — not merely bound

⛔ **A bound socket is not a receiving socket.** Without the inbound firewall rules Windows drops
the datagrams *before they reach the socket*, with no error anywhere: the collector binds, reports
itself healthy, and is deaf. Same failure shape as binding the wrong port — every signal green, and
the system receiving nothing.

```powershell
# 1. The rules exist (the installer creates one per protocol per port)
Get-NetFirewallRule -DisplayName 'SecVault Syslog *' |
    Select-Object DisplayName, Enabled, Direction, Action

# 2. The ports are actually bound
netstat -ano | findstr ":514 :1514"

# 3. THE ONE THAT MATTERS -- are rows arriving?
```

```sql
-- via psql, against the secvault database
SELECT max(received_at) AS newest, count(*) AS rows_last_5_min
  FROM syslog_events
 WHERE received_at > now() - interval '5 minutes';

-- and what the collector thinks of its own ingest
SELECT * FROM syslog_ingest_stats ORDER BY created_at DESC LIMIT 5;
```

⛔ Check `syslog_ingest_stats.dropped`. Overflow is **counted, never hidden** — a collector that
silently loses datagrams under load is indistinguishable from a quiet network. A non-zero `dropped`
on a fresh install means `SYSLOG_MAX_BUFFER` or the database cannot keep up with this fleet.

⛔ A firewall sending from an address that matches no `devices` row is **still stored**, with
`device_id NULL`. That is deliberate — see `/settings` device discovery — so do not read NULL
`device_id` rows as a fault.

### 6.6 Prove the engine is running its jobs

```powershell
Get-Content C:\Apps\SecVault\logs\engine.log -Tail 80
```

On startup the engine runs an immediate feed sync + CVE match before entering its scheduled
cycles, so within a few minutes you should see `Job [feed-sync-and-match] starting` / `finished`
and the `Scheduling [...] with cron "..."` lines for every job.

```sql
SELECT source, status, started_at, finished_at, error
  FROM feed_sync_log ORDER BY started_at DESC LIMIT 20;
```

⛔ **`skipped` is not a failure and renders muted, not amber.** A vendor PSIRT feed only runs if
that vendor is in the inventory, and on a fresh install the inventory is empty — so most vendor
feeds will legitimately report `skipped` **with a reason**. Likewise `cve_hub` reports `skipped`
when `CVE_HUB_LICENSE_KEY` is blank. Neither is a problem. A feed that simply *stops appearing*
would be the problem, which is why skips are written down.

⛔ On an air-gapped or segmented network, **every** external feed will fail. That is expected and
the product keeps working — but see the `CVE_HUB_*` keys in `.env.local.example` if this site
cannot reach NVD, and note that an empty cloud catalogue means **unknown**, never "not a cloud app".

### 6.7 Customer deployments: the two diagnostic database roles

`lib\schema-grants.sql` creates `claude_readonly` and `nocvault_readonly` with a password that is
**in the repository and identical on every installation**. They are SELECT-only, granted per table,
and cannot read `device_credentials`, `credential_profiles`, `notification_channels`, `user_mfa`,
or the admin/user password hashes — that containment is real. They are also unreachable remotely on
a default PostgreSQL `pg_hba.conf`, which admits only `127.0.0.1/32` and `::1/128`.

⛔ **That last protection is an accident of the default, not a control anything asserts.** If you
widen `pg_hba.conf` for any reason, you expose both roles with it and nothing will tell you.

On a customer deployment, either change both passwords or drop the roles — nothing the application
does depends on either:

```sql
ALTER ROLE claude_readonly    PASSWORD '<something local>';
ALTER ROLE nocvault_readonly  PASSWORD '<something local>';
-- or:  DROP ROLE ...  (you must REASSIGN/DROP OWNED first if they own nothing, they do not)
```

A changed password **survives updates** — the `CREATE ROLE` in that file is guarded by
`IF NOT EXISTS`, so re-running it recreates a role only when it is absent.

### 6.8 Prove the update path works, before you need it

⛔ **Do this on install day.** The single most expensive failure in this codebase's history is a
`git pull` that reports success and pulls nothing (see 7.4). Finding that out during an urgent
patch is the wrong time.

```powershell
cd C:\Apps\SecVault
git rev-parse HEAD
git ls-remote origin main
```

The two hashes should agree on a fresh install. Then confirm the in-app path works: the console's
**Settings → Updates** panel must show a version and a commit, not an error. It runs as a limited
service account and uses the **machine-wide** key at `C:\ProgramData\SecVault\ssh\secvault_deploy`
— a different path from the one your interactive shell just used.

```powershell
Test-Path C:\ProgramData\SecVault\ssh\secvault_deploy   # must be True
```

### 6.9 Prove the backup task exists and produces a real archive

```powershell
schtasks /query /tn SecVaultBackup /v /fo LIST | Select-String 'TaskName|Status|Next Run'
```

Registration is **best effort** — the installer warns rather than failing if it cannot create it.
If the warning appeared, register it by hand or run `installer\Backup-SecVault.ps1` on a schedule
of your own.

⛔ **`.env.local` is part of the backup, and that is not optional.** `device_credentials` is
AES-256-GCM keyed on `CREDENTIAL_KEY`, which exists nowhere else. A dump without it restores an
installation that looks completely healthy and cannot reach a single firewall — collection fails
device by device with authentication errors that read as though the firewalls changed their
passwords. **The consequence is that the backup directory is as sensitive as the database: ACL it.**

Full procedure and sizing: `docs/SIZING-AND-BACKUP.md`.

### 6.10 Optional but recommended: sweep every page

Nothing in `npm test` renders a page, and `next build` never evaluates a `force-dynamic` page
either — which is how a **blank `/reports`** shipped with 2,399 tests passing and a clean build.

```powershell
cd C:\Apps\SecVault
$env:SMOKE_URL='https://127.0.0.1:3010'; $env:SMOKE_USER='<local account>'
$env:SMOKE_PASS='<password>'; $env:SMOKE_INSECURE='1'
npm run smoke
```

⛔ Use a **dedicated local account without MFA** — the harness cannot supply a second factor and
says so rather than guessing. An operator-role account will legitimately fail to render the
admin-gated pages; that is a permissions boundary working, not a broken page.

---

## 7. Troubleshooting — the failures this codebase has actually hit

### 7.1 `SecVault-App` is Running but nothing answers on the port

The classic NSSM crash-loop. Read the **stderr** log, which is where the real error is:

```powershell
Get-Content C:\Apps\SecVault\logs\app-error.log      -Tail 60
Get-Content C:\Apps\SecVault\logs\engine-stderr.log  -Tail 60
Get-Content C:\Apps\SecVault\logs\collector-stderr.log -Tail 60
```

Most common causes, in order: 7.2, 7.6, a missing/blank `CREDENTIAL_KEY` or `DATABASE_URL`.

### 7.2 ⛔ NSSM `AppParameters` pointing at `node_modules\.bin\next`

`node_modules\.bin\next` is **npm's generated POSIX shell wrapper** (`basedir=$(dirname ...)` — real
bash, not JavaScript). `node` tries to parse it as JS and dies with a `SyntaxError` on **every**
start attempt, while `sc.exe start` still reports success and NSSM eventually marks the service
Paused after enough rapid failures.

```powershell
# The installer also copies nssm.exe to C:\Windows\System32, so a bare `nssm`
# usually works -- but never ASSUME it is on PATH. This is the canonical path.
C:\Apps\SecVault\nssm\nssm-2.24\win64\nssm.exe get SecVault-App AppParameters
```

It must be **either**:
- `node_modules\next\dist\bin\next start -p 3010` (plain HTTP — the real Next CLI entry point), **or**
- `server.js` (TLS — `next start` **cannot serve TLS**; there is no flag for it, in any version)

⛔ `nssm get` returns **UTF-16 with embedded NULs** — never round-trip its output back into
`nssm set`. Type the value.

⛔ Check the casing of `AppDirectory` and `AppEnvironmentExtra` too. Path casing that does not match
the filesystem exactly causes **duplicate React instances and silent rendering failures** — pages
that load but do not work.

```powershell
C:\Apps\SecVault\nssm\nssm-2.24\win64\nssm.exe get SecVault-App AppDirectory
C:\Apps\SecVault\nssm\nssm-2.24\win64\nssm.exe get SecVault-App AppEnvironmentExtra
```

Both must read `C:\Apps\SecVault` with exactly that casing.

⛔ Use `sc.exe` for every state change. **Never** `Start-Service`/`Stop-Service`/`Restart-Service` —
they silently disconnect WinRM sessions and hang terminals. Read-only `Get-Service ... .Status`
polling is fine.

### 7.3 The collector is Running and receiving nothing

Almost always the inbound firewall rules. Windows drops the datagrams before the socket sees them,
with no error anywhere. Work through 6.5 in order: rules exist → ports bound → rows arriving.

Other causes worth ruling out:
- **Another process holds the port.** `netstat -ano | findstr ":514"`, then match the PID.
- **The spool directory is not writable.** The collector fsyncs to it *before* every DB insert.
  Check `SYSLOG_SPOOL_DIR` in `.env.local` points somewhere that exists on this machine — the env
  example once hardcoded `E:\SecVaultSpool`, which is right for the reference deployment and wrong
  for any server without an `E:` drive.
- **The firewalls are configured to a port you did not bind.** `-SyslogPorts` defaults to
  `514,1514` for exactly this reason.

### 7.4 ⛔ `git pull` reports success and pulls nothing

The in-app updater drives git through `-c core.sshCommand=<...>` pointing at the machine-wide
deploy key. **`core.sshCommand` is always interpreted by git's own bundled MSYS2 shell**, regardless
of which account invokes git or which ssh binary is named — and a bare Windows backslash **silently
vanishes** before ssh ever sees it. The result is a `git pull` that exits 0 and does nothing.

⛔ **Do not diagnose this with `ssh -v` by hand.** That bypasses the shell-interpretation layer
entirely and will look fixed when it is not.

The path in `core.sshCommand` must use **forward slashes only**:

```
ssh -i C:/ProgramData/SecVault/ssh/secvault_deploy -o StrictHostKeyChecking=no
```

Verify the effect, not the exit code:

```powershell
cd C:\Apps\SecVault
git rev-parse HEAD          # before
# trigger the update
git rev-parse HEAD          # must have MOVED
```

Also confirm both key copies exist (`%USERPROFILE%\.ssh\secvault_deploy` **and**
`C:\ProgramData\SecVault\ssh\secvault_deploy`). The in-app button runs as SYSTEM and cannot see the
first one.

### 7.5 Sign-in bounces back to the login page, with no error anywhere

`NEXTAUTH_URL`'s scheme disagrees with the transport. NextAuth builds its callback URL from it;
left on `http://` while the server speaks https, the cookie is issued for an origin the browser is
not on, and **every** sign-in silently returns to the login page. Nothing is logged as an error.

```powershell
Select-String -Path C:\Apps\SecVault\.env.local -Pattern '^(NEXTAUTH_URL|ENABLE_TLS)='
```

`NEXTAUTH_URL` must be `https://<host>:<port>` when `ENABLE_TLS=true`, and `http://...` when it is
false. `server.js` logs loudly when the two disagree — check `C:\Apps\SecVault\logs\app.log`.

Fix it from **Settings → Certificate → Console address** rather than by hand where possible: that
panel validates the value (it refuses a scheme that disagrees with the transport, a trailing path,
a query/fragment and embedded credentials) and guards against the typo that makes the console
unreachable. ⛔ **A restart is required either way** — NextAuth reads its options once, at startup.

### 7.6 ⛔ A `pg_hba.conf` error at `node lib\migrate.js`

```
error: no pg_hba.conf entry for host "192.168.7.69", user "secvault_user", database "secvault"
[FATAL] Schema migration failed with exit code 1.
```

⛔ **THIS WAS THE INSTALLER'S OWN BUG AND IT IS FIXED — if you see it now, the cause is
different.** `Install-SecVault.ps1` used to build `DATABASE_URL` from `-ServerIp`, i.e. the **LAN
address you gave for the console**, while a default `pg_hba.conf` admits `127.0.0.1/32` and
`::1/128` and nothing else. Every `psql` call the installer itself makes uses `-h localhost` and
therefore succeeded; only the application's own connection used the LAN address, so the failure
arrived late and pointed at the wrong thing. It now writes `$DbHost = '127.0.0.1'` unconditionally,
and all three services run on this box so loopback is also the correct answer. `SERVER_IP` and
`NEXTAUTH_URL` keep the LAN address — that is the **console's** address, a different question.

**So on a current installer this error means PostgreSQL is not admitting loopback**, which happens
when PostgreSQL was pre-installed here (see 0.1) with a hardened or replaced `pg_hba.conf`. Check
it, and note the installer verifies the connection itself before going near `migrate.js`:

```powershell
Select-String -Path 'C:\Program Files\PostgreSQL\16\data\pg_hba.conf' -Pattern '^host'
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U secvault_user -h 127.0.0.1 -d secvault -c 'SELECT 1'
Select-String -Path C:\Apps\SecVault\.env.local -Pattern '^DATABASE_URL='
```

⛔ **Widening `pg_hba.conf` is not the fix here and carries its own cost**: it also exposes
`claude_readonly` / `nocvault_readonly` (see 6.7), whose password is in the repository. Admit
loopback rather than a subnet.

If the installer did reach this point, everything before it — prerequisites, clone, database,
`.env.local`, secrets — completed. Fix the connection and resume from `node lib\migrate.js`;
do **not** re-run the whole installer, which would generate a **new `CREDENTIAL_KEY`** and make
every already-stored firewall credential undecryptable.

### 7.7 TLS did not come up

The installer treats every TLS failure as non-fatal: it leaves a working plain-HTTP install rather
than a broken one, and says so. `.env.local` keeps `ENABLE_TLS=false`.

```powershell
Get-Content C:\Apps\SecVault\logs\tls-openssl.log -Tail 40
Select-String -Path C:\Apps\SecVault\.env.local -Pattern '^(ENABLE_TLS|TLS_CERT_PATH|TLS_KEY_PATH)='
Test-Path C:\Apps\SecVault\certs\secvault.crt, C:\Apps\SecVault\certs\secvault.key
```

- **"OpenSSL not found"** — Git for Windows is missing or was installed somewhere unexpected.
  `SecVault-Tls.ps1` looks in `%ProgramFiles%\Git\usr\bin`, `%ProgramFiles%\Git\mingw64\bin`,
  the x86 Git path, the PostgreSQL 16 `bin` directory, and finally `PATH`.
- **Certificate and key both exist but the app will not start** — the pair may not match. They both
  parse perfectly and fail only at startup. Settings → Certificate validates a replacement with
  `X509Certificate.checkPrivateKey()` **before** writing, precisely so this cannot be introduced
  later; a hand-placed pair gets no such check.
- **⛔ An existing certificate is NEVER overwritten**, at install or at upgrade. If you placed a
  corporate certificate at `certs\secvault.crt`/`.key`, the installer left it alone by design and
  reports *"Existing certificate left untouched."* — that message is not an error.
- **Three transport states, not two.** `active` / `disabled` (no certs configured — how this
  product shipped for its whole life) / `failed` (certs configured, could not be loaded). ⛔ A
  `failed` state **degrades to HTTP rather than refusing to start**, because on a
  firewall-management platform an outage means nobody can see the fleet. That is only safe because
  `failed` is never silent: it logs a banner at **error** level on every start and is reported in
  Settings. If Settings says `failed`, you are on plain HTTP and you should treat it as such.

To turn TLS on afterwards: set `ENABLE_TLS=true` in `.env.local` and run
`& "C:\Apps\SecVault\installer\Update-SecVault.ps1"`.

### 7.8 A fix to `Update-SecVault.ps1` appears not to have worked

⛔ **The updater updates itself, so a fix to it lands one deploy late.** Step 3's `git pull`
replaces `Update-SecVault.ps1` while that very script is running — and PowerShell parsed the **old**
copy into memory before step 1. The run that *delivers* a fix still *executes* the unfixed version.

Expect to deploy **twice**, and verify the step's **effect** rather than the deploy's exit code —
this has reported "completed successfully" both times while doing the wrong thing. The same trap
applies to any change the `git pull` replaces mid-run.

### 7.9 Other things that look broken and are not

- **A browser certificate warning on first visit.** Self-signed. Expected. See 4.
- **Most feeds reporting `skipped`.** A vendor PSIRT feed only runs if that vendor is in the
  inventory, and a fresh install has none. See 6.6.
- **Every headline score showing `—`.** An unmeasurable component is **dropped**, never scored 0 —
  a fresh install with no devices has nothing to measure, and reporting `0` would render a data gap
  as a security problem.
- **`firewall_rules.hit_count` empty for some devices.** It is genuinely **tri-state**: a real
  count, a device-reported `0`, or **NULL meaning NOT MEASURED**. Fortinet over SSH, Sangfor and
  Palo Alto over SSH cannot report hit counts at all. NULL is honest, not missing data.
- **The licence banner showing a trial.** 30 days, unlimited firewalls, by design. Collection, CVE
  assessment, compliance evaluation, rule analysis, syslog ingestion, alerting and reporting run in
  **every** licence state, including fully expired — only adding a firewall, changing settings and
  creating an account are withheld.
- **⛔ A licence key that will not activate on a server that also runs a NocVault suite app.** If
  `NETVAULT_LICENSE_SECRET` is set machine-wide, the SecVault services inherit it and validate keys
  against the wrong secret; every legitimate key is refused as `unreadable`, and **nothing names the
  cause**. Check with
  `[Environment]::GetEnvironmentVariable('NETVAULT_LICENSE_SECRET','Machine')` — see the block in
  `.env.local.example`.

---

## 8. ⛔ Before you consider the install finished

1. **`admin` / `changeme` has been changed.**
2. **MFA is enrolled** on at least the first Super Admin, and its recovery codes are stored
   somewhere other than this server.
3. **`C:\Apps\SecVault\.env.local` is backed up somewhere off this machine**, and that location is
   ACL'd. It holds `CREDENTIAL_KEY`, and `CREDENTIAL_KEY` exists nowhere else. Without it, a restored
   database cannot decrypt a single firewall credential, and the symptom will look like the
   firewalls changed their passwords.
4. **The `SecVaultBackup` task is registered and has produced one verified archive.**
5. **`data_directory`, `SYSLOG_ARCHIVE_DIR` and `SYSLOG_SPOOL_DIR` are all on volumes you chose
   deliberately**, with the retention windows sized to them.
6. **The update path has been exercised once** (6.8), while nothing is urgent.
