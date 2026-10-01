# Staging: a mock SecVault fleet with synthetic syslog

How to stand SecVault up on the Windows staging box with four fabricated firewalls and a
synthetic log stream, so the whole product can be exercised without touching the production
fleet. Written 2026-10-01.

⛔ **This is a DEV-STYLE install, deliberately not `Install-SecVault.ps1`.** The packaged
installer provisions prerequisites, mints certificates, registers three services, creates
scheduled tasks and opens firewall ports. Staging already runs CertVault and all the
prerequisites are present, so the installer's value here is near zero and its blast radius is
not. We clone, configure and register one service by hand, and we can take it all back out
again in four commands.

---

## What is already on the box (measured 2026-10-01, not assumed)

| | |
|---|---|
| host | `LAPTOP-6PETB251` · `192.168.31.10` · Windows 11 Home |
| PowerShell | **5.1**.26100.9444 — so the installer parse gate runs AUTHORITATIVELY here, unlike on the Linux dev box |
| node / npm | `C:\Program Files\nodejs\node.exe` · npm present |
| git | `C:\Users\Amrin\AppData\Local\Programs\Git\cmd\git.exe` 2.55.0 |
| nssm | `C:\Windows\System32\nssm.exe` |
| PostgreSQL | **16.15**, service `postgresql-x64-16` Running, listening on 5432 |
| `psql` | `C:\Program Files\PostgreSQL\16\bin\psql.exe` — ⛔ **NOT on PATH**, use the full path |
| PG data dir | `C:\Program Files\PostgreSQL\16\data` — ⛔ on **C:**, see the retention warning below |
| port 3010 | **free** |
| already running | `CertVault-App` + `CertVault-Engine` on **3014** — do not disturb |
| free space | 292.9 GB of 475.7 GB on C: |

⛔ **ASK AMRIN BEFORE INSTALLING ANYTHING ON THIS MACHINE.** It is not a scratch box; it hosts
CertVault. Everything below is written down so the install is mechanical once agreed, not so it
can be run unattended.

---

## Deliberate differences from a production install

| | production | here | why |
|---|---|---|---|
| path | `C:\Apps\SecVault` | `C:\Apps\SecVaultTest` | so nothing can be mistaken for a real install, and so a real one can be added later without collision |
| database | `secvault` | `secvault_mock` | ⛔ **load-bearing** — `seedMockFleet.js` REFUSES any database whose name does not match `/mock\|test\|staging\|scratch/i` |
| services | App + Engine + Collector | **`SecVaultTest-App` only** | the engine's jobs would try to reach firewalls that do not exist; the collector is started by hand only while generating logs |
| TLS | on | off (`ENABLE_TLS=false`) | no certificate is needed to exercise the product, and `disabled` is a documented, non-error transport state |
| syslog ports | 514 + 1514 | **1514 only** | 514 is privileged and this is a shared machine |
| retention | 30 days | ⛔ **2 days** | the PG data directory is on **C:**. CLAUDE.md's own warning: an install accepting the installer default gets a fifth of the assumed capacity and fills the SYSTEM volume doing it. Mock volume is tiny, but set the bound anyway |

---

## Steps

### 1. Clone

```powershell
git clone git@github.com:amrin78-smb/secvault.git C:\Apps\SecVaultTest
cd C:\Apps\SecVaultTest
npm ci                      # ⛔ never npm install
```

⛔ The repo is private, so this needs a key the box can authenticate with. If there is none,
Amrin authorises one — **never copy a private key between machines.**

### 2. Create the database and role

Run as the `postgres` superuser. ⛔ **Needs the staging superuser password — ask for it, use it in
the session only, and never write it into a file in the repo.**

```powershell
$psql = 'C:\Program Files\PostgreSQL\16\bin\psql.exe'
# -f a file, never a heredoc; and never embed the password in a committed script.
& $psql -U postgres -c "CREATE ROLE secvault_mock_user LOGIN PASSWORD '<generated>';"
& $psql -U postgres -c "CREATE DATABASE secvault_mock OWNER secvault_mock_user;"
```

⛔ **Generate the role password on the box** and record only its LOCATION, never its contents.

### 3. `.env.local`

⛔ **`DATABASE_URL`'s host is LOOPBACK, not the LAN address** — a default `pg_hba.conf` admits
`127.0.0.1/32` and `::1/128` only. Writing the LAN address makes node's first connection fail with
`no pg_hba.conf entry for host`.

```bash
SERVER_IP=192.168.31.10
APP_PORT=3010
DATABASE_URL=postgresql://secvault_mock_user:<generated>@127.0.0.1:5432/secvault_mock

NEXTAUTH_URL=http://192.168.31.10:3010
NEXTAUTH_SECRET=<generated>
CREDENTIAL_KEY=<generated 32-byte hex>
SESSION_IDLE_MINUTES=30

ENABLE_TLS=false

# No firewalls exist, so nothing should be dialled. Feeds are left on: they are
# the one part of the product that works identically with no devices attached.
CONFIG_PULL_INTERVAL_HOURS=24
VPN_POLL_INTERVAL_MINUTES=59
SNMP_POLL_INTERVAL_MINUTES=59

SYSLOG_UDP_PORT=1514
SYSLOG_TCP_PORT=1514
SYSLOG_RETENTION_DAYS=2
SYSLOG_ARCHIVE_ENABLED=false
SYSLOG_SPOOL_DIR=C:\Apps\SecVaultTest\spool
```

⛔ **Write it as UTF-8 and read it back with `-Encoding UTF8`.** A bare `Get-Content` decodes with
the ANSI codepage; the resulting read/write disagreement is what grew one comment to a
2.2 GB line in production and brought the console up on plaintext with no secrets loaded.

### 4. Migrate, build, seed

```powershell
node lib/migrate.js
npm run build

# ⛔ Three independent refusals guard this. All three must be satisfied:
#   - the host must not be the production fleet server
#   - the database name must say it is a test
#   - --i-know must be passed
$env:DATABASE_URL = 'postgresql://secvault_mock_user:<generated>@127.0.0.1:5432/secvault_mock'
node scripts\seedMockFleet.js --i-know
```

Expect four devices: a Fortinet with **no** hit counts at all, a Palo Alto with real counts
**including a genuine zero**, a Fortinet with an **unreadable version string**, and a Cisco ASA
that **nothing could be collected from**. That unevenness is the point — a uniformly healthy fleet
exercises only the path this product has never had a bug on.

### 5. Register one service

```powershell
$nssm = 'C:\Windows\System32\nssm.exe'
& $nssm install SecVaultTest-App node
& $nssm set SecVaultTest-App AppParameters "node_modules\next\dist\bin\next start -p 3010"
& $nssm set SecVaultTest-App AppDirectory "C:\Apps\SecVaultTest"
& $nssm set SecVaultTest-App AppEnvironmentExtra "NODE_ENV=production"
sc.exe start SecVaultTest-App          # ⛔ sc.exe, never Start-Service
```

⛔ `AppParameters` must point at `node_modules\next\dist\bin\next` — pointing at
`node_modules\.bin\next` (npm's POSIX shell wrapper, not JS) crashes on every start while
`sc.exe start` still reports success. ⛔ `server.js` is **not** used here because TLS is off.

⛔ **"Service Running" is not "app serving"** — NSSM restarts a crashing process, so verify:

```powershell
(Invoke-WebRequest http://127.0.0.1:3010/api/health -UseBasicParsing).StatusCode
```

### 6. Generate syslog

The collector is started by hand, only while generating:

⛔ **FIRST, ADD THE SENDER ADDRESSES — WITHOUT THEM NOTHING ATTRIBUTES.** The collector resolves a
device from the datagram's SOURCE address against `devices.mgmt_ip`. A generator running on the same
box sends from loopback, which matches no seeded device, so every event is stored with
`device_id NULL` — CORRECTLY, since an unmatched sender is still evidence — and **nothing errors**.
Measured on the dev box before this was fixed: 2,000 events arrived, every one parsed with the right
vendor, and **all 1,960 stored rows were unattributed**, so rule-hit correlation produced nothing.
That reads exactly like a broken collector or a broken rollup.

```powershell
# Windows: add each mock firewall's address to the loopback pseudo-interface.
netsh interface ipv4 add address "Loopback Pseudo-Interface 1" 10.99.0.11 255.255.255.255
netsh interface ipv4 add address "Loopback Pseudo-Interface 1" 10.99.0.21 255.255.255.255
```

`mockSyslog.js` binds one socket per vendor to those addresses and **REFUSES with the exact command
above if it cannot** (exit 1), rather than falling back to loopback and producing a dataset that
looks real and attributes to nothing. `--any-source` overrides it and states the cost.

```powershell
# terminal 1
node services\collector.js

# terminal 2 — finite and rate-limited by default
node scripts\mockSyslog.js --port 1514 --count 20000 --rate 500
```

Remove the addresses afterwards with `netsh interface ipv4 delete address "Loopback Pseudo-Interface 1" 10.99.0.11`.

⛔ **`sent` is not `received`.** UDP drops under burst even on loopback — measured 360 of 400 at
400/sec with an 8 MB receive buffer. Read `syslog_ingest_stats` (received / parsed / stored /
**dropped**), not the generator's own count. A shortfall is expected; matching numbers are not
proof of no loss either.

⛔ **No inbound firewall rule is needed** because the generator runs on the same box. If it is ever
driven from the dev machine, one IS needed — without it the collector binds, reports itself
healthy, and receives nothing, with no error anywhere.

Then wait for the rollups. ⛔ **Do not start a second collector to force them** — the rollup job
lives INSIDE the running collector (`SYSLOG_ROLLUP_INTERVAL_MINUTES`, default **5**), so a second
process would just fail to bind the port. Leave terminal 1 running for one tick and watch its log
for the rollup line, then check the tables:

```powershell
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U postgres -d secvault_mock -c "
  SELECT 'events' t, count(*) FROM syslog_events
  UNION ALL SELECT 'rule_hits', count(*) FROM syslog_rule_hits_hourly
  UNION ALL SELECT 'ingest_stats', count(*) FROM syslog_ingest_stats;"
```

⛔ **`syslog_rule_hits_hourly` staying empty is the thing to look for**, because it is what makes
`firewall_rules.hit_count` genuinely tri-state rather than assumed. The two vendors reach it by
different routes on purpose — Fortinet correlates on the vendor rule id, Palo Alto on the rule
NAME — so if only one vendor appears, the mismatch is in the identifiers, not the pipeline.

### 7. What to actually look at

The point of the mock fleet is the pages that need uneven data to be meaningful:

- `/devices` — one device must show **no usage data**, not zero usage
- `/analysis` — the `unused` count must EXCLUDE the Fortinet whose hit counts are NULL
- `/work` — the **`verify`** band must be non-empty (the unreadable version, the uncollectable device)
- `/compliance` — `na` vs `warning` on the device with no config at all
- `/vulnerability` — feeds work with no devices attached; assessments need the seeded versions
- `/exposure`, `/segmentation`, `/applications` — all should say "cannot tell" loudly rather than
  producing a confident number from missing data

⛔ **A clean-looking page over this fleet is a BUG, not a pass.** Three of the four devices are
deliberately partially-unmeasurable; any page that renders them as healthy is reproducing this
codebase's signature defect.

### 8. Run the gate that cannot run on Linux

Staging has PowerShell 5.1, so this is the authoritative machine for the installer parse gate
that skips on the dev box:

```powershell
npm test        # the installer suite should RUN here, not skip
```

⛔ If it skips here, the check has silently stopped happening anywhere — `tests/psScripts.test.js`
asserts exactly that from the Windows side.

---

## Removing it

```powershell
sc.exe stop SecVaultTest-App
sc.exe delete SecVaultTest-App
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U postgres -c "DROP DATABASE secvault_mock;"
& 'C:\Program Files\PostgreSQL\16\bin\psql.exe' -U postgres -c "DROP ROLE secvault_mock_user;"
Remove-Item -Recurse -Force C:\Apps\SecVaultTest
```

Nothing above touches CertVault, its services, its database or port 3014.

⛔ **To remove only the mock devices from a database worth keeping**, the seeder's own wipe is
prefix-scoped and safer than hand-written SQL: `node scripts\seedMockFleet.js --i-know --wipe`
deletes exactly the `MOCK-` devices and cascades their rules, configs and versions.
