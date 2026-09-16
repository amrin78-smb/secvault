# SecVault — Sizing and Backup

Every figure here was measured on the reference deployment on **2026-09-16** (16 active
firewalls, 15 of them sending syslog). Nothing in this document is estimated from a datasheet.

---

## 1. Sizing

### ⛔ Do not size by device count

The instinct is "X GB per firewall". It is wrong here by two orders of magnitude. Measured
events per day, same fleet, same window:

| firewall | vendor | events/day |
|---|---|--:|
| TUM(TUTH1) | Palo Alto | 12,819,735 |
| SMT | Palo Alto | 12,121,868 |
| ITC-SK | Palo Alto | 10,632,101 |
| OKF(F2) | Fortinet | 6,200,734 |
| TFM-MH | Palo Alto | 4,406,218 |
| … | | |
| TSR_EKC | Fortinet | 194,585 |
| ITC-SLY | Palo Alto | 136,188 |

The busiest firewall produces **94× the traffic of the quietest one on the same fleet.** A
site-count or device-count model will be wrong for almost every customer. Size on **events per
second**, which the customer's existing collector can tell you, or measure for a week.

### The two halves of the database, and they are nothing alike

| | measured | grows with | recomputable? |
|---|--:|---|---|
| Raw syslog (`syslog_events_*`) | **197 GB** | events/sec × retention days | n/a — expires at 30 days |
| Syslog rollups | 1.9 GB | events/sec × time, **forever** | ⛔ no |
| Everything else (system of record) | 902 MB | devices × config churn | ⛔ no |

**99% of the database is data SecVault itself deletes within 30 days.** That single fact drives
both the disk sizing and the backup design.

### Disk — the numbers to plan against

Fleet total: **55.2M events/day**, ~638/sec.

| quantity | measured |
|---|--:|
| Row cost, heap + index | **~415 bytes** (340 heap + 75 index) |
| Raw syslog per day | **~31 GB** |
| Raw syslog, 30-day window | **~920 GB** |
| Compressed archive per day | ~8.4 GB |
| Compressed archive, 45-day retention | ~380 GB |
| System of record | ~900 MB, growing slowly |

**Rule of thumb:** `events/sec × 86,400 × 415 bytes × SYSLOG_RETENTION_DAYS`, then add ~35% for
the compressed archive if `SYSLOG_ARCHIVE_ENABLED=true`.

At 638 events/sec that is ~920 GB of live database plus ~380 GB of archive. **Provision 1.5 TB
for a fleet this size**, and scale it linearly with events/sec.

### ⛔ The row cost above is only true because of `SYSLOG_RAW_MESSAGE=security`

That setting drops the raw log line for ordinary allowed traffic (~89% of rows) and keeps it for
threat / VPN / UTM / denied events. It is what took a row from ~1,000 bytes to ~340.

Set `SYSLOG_RAW_MESSAGE=all` and **the raw window roughly triples** — ~2.7 TB at this fleet's
rate. Do that deliberately or not at all.

### ⛔ PostgreSQL must not live on the system volume

The reference deployment runs its data directory on `E:\PostgreSQL\data` (2 TB) with the archive
on `E:\SecVaultArchive`. `C:` has ~159 GB free — **less than a fifth of one 30-day window**, and
filling it takes Windows down with it.

A rebuild that accepts the PostgreSQL installer's default (`C:\Program Files\PostgreSQL\data`)
silently gets a fraction of the capacity every retention setting assumes. **Check the data
directory before raising `SYSLOG_RETENTION_DAYS`.**

### Reducing the footprint, in order of effect

1. `SYSLOG_RETENTION_DAYS` — linear, and the rollups keep answering historical questions after
   the raw rows are gone.
2. `SYSLOG_ARCHIVE_RETENTION_DAYS` — ~35% of total footprint.
3. `SYSLOG_RAW_MESSAGE=security` — already the default; confirm it has not been raised to `all`.
4. Stop forwarding ordinary allow traffic from the busiest firewalls. Three Palo Altos are 65% of
   this fleet's volume.

⛔ A `DELETE` does not return space to the OS, and raw events are aged out by **dropping a
partition**, never by `DELETE`. After a one-off cleanup you need `VACUUM FULL` or `pg_repack` to
shrink the files — both take an `ACCESS EXCLUSIVE` lock, so neither is in any scheduled job.

---

## 2. Backup

    installer\Backup-SecVault.ps1        # write a verified backup
    installer\Restore-SecVault.ps1       # dry run — shows what it would do
    installer\Restore-SecVault.ps1 -Force

### What is backed up, and what is not

**Backed up:** every table except raw syslog rows — devices, credentials, rules, network objects,
advisories, CVE assessments, compliance findings, config snapshots and backups, rule-analysis
results, VPN session history, all syslog **rollups**, settings, users, the subscription key.

**Not backed up:** `syslog_events` **rows**. 197 GB of the 199 GB database, all of which SecVault
deletes within 30 days anyway.

⛔ **The exclusion is `--exclude-table-data`, not `--exclude-table`.** The dump still carries the
`CREATE TABLE` and every partition definition. With `--exclude-table` a restore loses the
partitioned structure, the collector starts, every insert fails, and the only symptom is a syslog
pipeline that is quietly dead.

Pass `-IncludeSyslog` if you genuinely need the raw rows. Expect the dump to grow by roughly your
whole retention window.

### ⛔ The credential key is part of the backup

`device_credentials` is AES-256-GCM ciphertext keyed on `CREDENTIAL_KEY`, which exists **only** in
`.env.local`. A database backup without it restores an installation that looks completely healthy
and cannot reach a single firewall — collection fails device by device with authentication errors
that read as though the firewalls changed their passwords.

So `Backup-SecVault.ps1` copies `.env.local` beside each dump, and `Restore-SecVault.ps1`
**compares the two keys and stops when they differ** rather than completing and leaving someone to
work it out from adapter logs.

> ⛔ **The backup directory is therefore as sensitive as the database itself** — it holds the
> encryption key beside the encrypted credentials. ACL it. Do not sync it to a share every domain
> user can read.

### What the backup verifies about itself

- **Free space is checked before the dump starts.** A dump that fills its volume leaves a
  truncated file that looks like a backup. Requires 3× the previous dump, minimum 2 GB.
- **The finished dump is read back** with `pg_restore --list`. Corruption is caught while a good
  copy still exists, not at the disaster.
- **An archive with fewer than 20 entries is rejected and deleted.** An empty but well-formed
  archive passes `--list`; a real SecVault database has dozens of tables.
- **Old backups are pruned only after the new one is verified.** Pruning first is how a bad night
  becomes data loss.

### Restore

The dry run is the default — `-Force` is required to change anything. It stops the three services
(with `sc.exe`, never the PowerShell cmdlets), restores with `--clean --if-exists`, re-runs
`lib/migrate.js` so any schema shipped since the backup is applied, re-applies the readonly grants
that `--no-acl` dropped, restarts, and then **probes `/api/health`** — because NSSM reports a
crash-looping process as Running.

⛔ `pg_restore` exits non-zero for benign "does not exist, skipping" notices on a `--clean` run.
The exit code is not the verdict; the health probe is.

### Schedule

`Install-SecVault.ps1` registers a daily `SecVaultBackup` scheduled task running as SYSTEM.
Default retention is 14 sets. At ~200 MB per set that is under 3 GB.

### ⛔ What a restore does not bring back

Raw syslog between the backup and the failure. The collector resumes immediately and the rollups
are intact, so historical traffic questions still answer — but per-event forensics for that window
are gone. If that matters for your compliance regime, either run `-IncludeSyslog` and provision
for it, or rely on the compressed archive, which is a separate mechanism with its own retention.
