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
| Raw syslog (`syslog_events_*`) | **197 GB** (measured 2026-09-16, ⛔ EIGHT days of ingest, not thirty) | events/sec × retention days | n/a — expires at 30 days |
| Syslog rollups | 1.9 GB | events/sec × time, **forever** | ⛔ no |
| Everything else (system of record) | 902 MB | devices × config churn | ⛔ no |

**99% of the database is data SecVault itself deletes within 30 days.** That single fact drives
both the disk sizing and the backup design.

### Disk — the numbers to plan against

⛔ **MEASURED AND DERIVED ARE MARKED SEPARATELY, because this section did not distinguish them and
the undated mixture is what let three figures go stale together.** A measured figure was read off
the reference deployment on the date given. A derived figure is arithmetic on a measured one, and
is only as good as its input.

Fleet total, **re-measured 2026-11-14 over 14 days and all 24 hours** (`syslog_rollup_hourly`):
**810 events/sec, 70.0M events/day.**

| quantity | value | kind |
|---|--:|---|
| Fleet rate | **810/sec · 70.0M/day** | measured 2026-11-14, 14 days |
| Row cost, heap + index | **~415 bytes** (340 heap + 75 index) | measured 2026-09-16 |
| Raw syslog per day | **~27 GiB** | derived: 70.0M × 415 B |
| Raw syslog, 30-day window | **~810 GiB** | derived |
| Compressed archive per day | **~5.5 GiB** | measured 2026-11-14 |
| Compressed archive, 45-day retention | **~245 GiB** | derived |
| Syslog rollups (permanent) | 1.9 GB | measured 2026-09-16 — ⛔ grows forever, re-measure |
| System of record | ~900 MB, growing slowly | measured 2026-09-16 |

**Rule of thumb:** `events/sec × 86,400 × 415 bytes × SYSLOG_RETENTION_DAYS`, then add **~20%**
for the compressed archive if `SYSLOG_ARCHIVE_ENABLED=true`.

At 810 events/sec that is ~810 GiB of live database plus ~245 GiB of archive, about **1.05 TiB**
all told. **Provision 1.5 TB for a fleet this size** — unchanged, and now with ~45% headroom
rather than the ~15% the old figures implied. Scale linearly with events/sec.

### ⛔ What was wrong here until 2026-11-14, and in which direction

Three of the figures above were wrong at once, and the directions differ — which is the part worth
reading before trusting any sizing document, including this one.

| figure | was | is | direction |
|---|--:|--:|---|
| Fleet rate | 638/sec · 55.2M/day | **810/sec · 70.0M/day** | **understated 27%** |
| Archive per day | ~8.4 GB | **~5.5 GiB** | overstated 54% |
| Archive, 45 days | ~380 GB | **~245 GiB** | overstated 54% |
| Archive share of raw | "add ~35%" | **~20%** | overstated |

⛔ **THE ARCHIVE ERROR WAS OVER-CAUTIOUS AND THE RATE ERROR WAS NOT.** An archive figure 54% too
high means nobody was ever under-provisioned by it — it asked for disk that was not needed. The
**fleet rate** is the dangerous one: it is the reference number a reader scales their own estimate
against, and it was 27% low. Anyone sizing from *their own* events/sec was unaffected, which is why
the rule of thumb is stated in those terms and not in firewalls.

⛔ **AND THIS SECTION CONTRADICTED ITSELF, WHICH IS HOW IT SHOULD HAVE BEEN CAUGHT WITHOUT ANY NEW
MEASUREMENT.** It stated 55.2M events/day two lines above a raw cost of ~31 GB/day. At 415 bytes a
row, 31 GiB/day **is 80.2M events/day** — so the two numbers on one screen could not both be true,
whatever the fleet was really doing. The GB figures were derived from a rate ~15% above what is
measured now; the stated events/day was from somewhere else entirely.

⛔ **8.4 GB/day WAS AN EXTRAPOLATION FROM A PARTIAL DAY, AND SO WAS THE 920 GB RAW WINDOW.** The
collector started 2026-09-08 and these were taken on 2026-09-16, so the 197 GB of raw syslog
measured then was **eight days of ingest, not thirty** — the 30-day window has never been observed
on this deployment at all. The header above says nothing here is estimated from a datasheet, which
is true and was read as "every number was measured directly". Hence the `kind` column.

⛔ **FOUR FIGURES COULD NOT BE RE-MEASURED ON 2026-11-14** because the VPN to the reference
deployment was down when this was written: the live database size, the raw-partition total, the
rollup total and bytes/row. They keep their 2026-09-16 dates above rather than being restated as
current. ⛔ **Bytes/row is the one that matters most** — every derived figure here multiplies by it,
it is a property of `SYSLOG_RAW_MESSAGE=security` and the schema rather than of the fleet, and
nothing has changed either since. Re-measure it when the link is up, and if it has moved, every
derived row above moves with it.

### ⛔ The row cost above is only true because of `SYSLOG_RAW_MESSAGE=security`

That setting drops the raw log line for ordinary allowed traffic (~89% of rows) and keeps it for
threat / VPN / UTM / denied events. It is what took a row from ~1,000 bytes to ~340.

Set `SYSLOG_RAW_MESSAGE=all` and **the raw window roughly triples** — ~2.4 TiB at this fleet's
measured rate (3 × 810 GiB), which no longer fits the 1.5 TB this document tells you to
provision. ⛔ This said ~2.7 TB, tripled off the superseded 920 GB window. Do that deliberately
or not at all, and re-provision first.

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
2. `SYSLOG_ARCHIVE_RETENTION_DAYS` — **~23% of total footprint** (245 of ~1,060 GiB). ⛔ This
   said ~35%, a FOURTH figure derived from the old 8.4 GB/day archive rate; cutting the archive
   window therefore buys about two thirds of what this list used to promise.
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

**Not backed up:** `syslog_events` **rows**. 197 GB of the 199 GB database as measured 2026-09-16
(a full 30-day window would be ~810 GiB of ~815 — the same 99%, which is the point), all of which SecVault
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
