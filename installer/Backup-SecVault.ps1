<#
.SYNOPSIS
    Backs up everything SecVault cannot recompute.

.DESCRIPTION
    Writes a compressed pg_dump of the SecVault database, plus a copy of
    .env.local and of the TLS key pair, verifies the dump is readable AND
    complete, and prunes old backups.

    Run by the SecVaultBackup scheduled task (registered by Install-SecVault.ps1)
    or by hand. Restore with installer\Restore-SecVault.ps1.

    ### WHY THIS IS NOT A DUMP OF THE WHOLE DATABASE

    Measured on the reference deployment, 2026-09-16:

        raw syslog (syslog_events_*)         197 GB   99.0%   expires in 30 days
        syslog rollups (permanent)           1.9 GB    1.0%   NOT recomputable
        everything else (system of record)   902 MB    0.4%   NOT recomputable

    The irreplaceable part is under 1% of the database. Dumping all 197 GB would
    take hours, need 197 GB of somewhere to put it, and spend all of that effort
    on forensic rows that SecVault itself deletes 30 days from now. So raw syslog
    is excluded by default and everything else is kept.

    #### The exclusion is --exclude-table-data, NOT --exclude-table

    That distinction is load-bearing and easy to get wrong. The dump must still
    carry the CREATE TABLE for syslog_events and its partitions: restore with
    --exclude-table and the partitioned structure is gone, the collector starts,
    every INSERT fails, and the only symptom is a syslog pipeline that is quietly
    dead. --exclude-table-data keeps the structure and drops the rows.

    ⛔ That rule is now ENFORCED, not merely documented -- see "Verify the dump
    is COMPLETE" below. It was a comment for two product minor-versions and a
    comment cannot fail a build.

    #### The exclusion list, enumerated (checked against lib\schema.sql)

    ONE pattern is excluded: public.syslog_events* -- the partitioned parent and
    its daily partitions, and nothing else in this schema shares that prefix
    (syslog_ingest_stats and the nine syslog_*_hourly rollups do not).
    ⛔ EVERY OTHER TABLE IS IN THE DUMP, INCLUDING THE HIGH-CARDINALITY
    ROLLUPS. syslog_talker_hourly / _app_hourly / _blocked_dst_hourly and their
    siblings are large, but they are the ONLY surviving record of traffic whose
    raw rows have already been dropped by partition. Excluding them to save
    space would silently destroy the evidence the product's own analysis reads.
    Do not add them to the pattern.

    #### .env.local is backed up too, and that is not optional

    device_credentials is AES-256-GCM ciphertext keyed on CREDENTIAL_KEY, which
    lives ONLY in .env.local. A database backup without that key restores to an
    installation that looks completely healthy and cannot reach a single
    firewall, with nothing on screen explaining why.

    #### ⛔ So is the TLS key pair, for the same reason

    An operator's own corporate certificate is installed through
    Settings -> Certificate, which writes the PEM pair to disk and NOTHING ELSE.
    The private key is in no database row and no other file. It joined the
    "exists nowhere else" category when TLS shipped (v2.112.0) and this script
    did not know about it: a rebuild would come up on a freshly-minted
    SELF-SIGNED certificate, every browser would warn, and the real key would be
    gone. Copied beside the dump when TLS_CERT_PATH/TLS_KEY_PATH are set.

    ### WHAT IS DELIBERATELY *NOT* HERE -- know this before the disaster

      * raw syslog rows (see above) -- gone, by design, 30-day data
      * SYSLOG_ARCHIVE_DIR, the compressed raw-log archive: ~8.4 GB/day on the
        reference fleet, hundreds of GB standing. It is genuinely irreplaceable
        forensic material and it is NOT in any database. It is out of scope here
        because a nightly pg_dump is the wrong tool for it -- BACK IT UP
        SEPARATELY (file-level/snapshot) if you need to keep it.
      * SYSLOG_SPOOL_DIR: transient by construction. Restoring a stale spool
        would replay old datagrams into a restored database as if they had just
        arrived; that is a fabricated measurement, not a recovery.
      * the OS, PostgreSQL itself, node, and the git checkout: all reinstallable
        from installer\Install-SecVault.ps1.

    ### THE BACKUP DIRECTORY IS AS SENSITIVE AS THE DATABASE

    It holds the credential-encryption key -- and now the TLS private key --
    beside the encrypted credentials. Put it somewhere ACL'd, and do not sync it
    to a share every domain user can read. The key material is written as its own
    files rather than inside the archive so it can be given different handling if
    you want it elsewhere -- but the restore will tell you plainly when it is
    missing.

.PARAMETER BackupDir
    Where backups go. Blank = <data volume>\SecVaultBackup, falling back to
    <InstallRoot>\backup. A backup on the same volume as the thing it protects
    is half a backup, so a data volume is strongly preferred.

.PARAMETER KeepBackups
    How many backup sets to retain. Default 14.

.PARAMETER IncludeSyslog
    Also dump raw syslog_events data. Off by default -- see above. Expect the
    dump to grow by roughly the size of your raw retention window.

.PARAMETER InstallRoot
    SecVault install directory. Default C:\Apps\SecVault.
#>

[CmdletBinding()]
param(
    [string]$BackupDir = '',
    [int]$KeepBackups = 14,
    [switch]$IncludeSyslog,
    [string]$InstallRoot = 'C:\Apps\SecVault'
)

$ErrorActionPreference = 'Stop'

$LogFile = Join-Path $InstallRoot 'logs\backup.log'
$logDir = Split-Path $LogFile -Parent
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }

function Write-Log {
    param([string]$Message)
    $ts = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
    $line = "[$ts] $Message"
    $line | Write-Host
    Add-Content -Path $LogFile -Value $line
}

# Native commands write to stderr for ordinary progress; PS5 turns that into a
# terminating error under $ErrorActionPreference='Stop'. Same helper the other
# installer scripts use, same reason.
function Invoke-Native {
    param([Parameter(Mandatory = $true)][scriptblock]$Command)
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Command } finally { $ErrorActionPreference = $prevEAP }
}

Write-Log '=========================================='
Write-Log 'SecVault backup starting'

# ── Locate the PostgreSQL client tools ──────────────────────────────────────
#
# ⛔ BOTH tools are resolved and BOTH are Test-Path'd. pg_restore used to be
# inferred from pg_dump's directory and never checked, and a missing one does
# not fail the way it looks like it would: PowerShell reports
# CommandNotFoundException and LEAVES $LASTEXITCODE AT ITS PREVIOUS VALUE
# (verified on 5.1.26100 -- it stayed 0 after a successful earlier call). The
# verification step below then read that stale 0 as "pg_restore --list
# succeeded" and logged "Verified readable" over a dump nothing had read.
$PgBin = 'C:\Program Files\PostgreSQL\16\bin'
$PgDump = Join-Path $PgBin 'pg_dump.exe'
$PgRestore = Join-Path $PgBin 'pg_restore.exe'
if (-not (Test-Path $PgDump)) {
    $cmd = Get-Command pg_dump -ErrorAction SilentlyContinue
    if ($cmd) {
        $PgDump = $cmd.Source
        $PgBin = Split-Path $cmd.Source -Parent
        $PgRestore = Join-Path $PgBin 'pg_restore.exe'
    } else {
        Write-Log "  [FAIL] pg_dump.exe not found at $PgDump and not on PATH."
        exit 1
    }
}
if (-not (Test-Path $PgRestore)) {
    $cmd = Get-Command pg_restore -ErrorAction SilentlyContinue
    if ($cmd) { $PgRestore = $cmd.Source }
    else {
        Write-Log "  [FAIL] pg_restore.exe not found beside pg_dump ($PgBin) and not on PATH."
        Write-Log '         Refusing to take a backup that cannot be verified: an unread dump is a hypothesis.'
        exit 1
    }
}

# ── Read the connection details out of the deployed .env.local ──────────────
$EnvFile = Join-Path $InstallRoot '.env.local'
if (-not (Test-Path $EnvFile)) {
    Write-Log "  [FAIL] $EnvFile not found -- cannot determine the database to back up."
    exit 1
}
# ⛔ UTF8: Get-Content decodes with the ANSI codepage on PS 5.1. See the
# long note in installer\SecVault-Tls.ps1 -- that mismatch grew a comment in
# .env.local to 2.2 GB and took the console down to plaintext HTTP. Here a
# wrong decoder would make the CREDENTIAL_KEY presence check compare
# mojibake, so a backup could report a key it had not really verified.
$envText = Get-Content $EnvFile -Raw -Encoding UTF8

if ($envText -notmatch '(?m)^DATABASE_URL=(.+)$') {
    Write-Log '  [FAIL] DATABASE_URL not found in .env.local.'
    exit 1
}
$dbUrl = $Matches[1].Trim()

# ⛔ HOST AND PORT ARE OPTIONAL, AND THE REFERENCE DEPLOYMENT OMITS BOTH.
#
# The first version of this required 'user:pass@host:port/db' and failed on its
# very first live run, because the real deployed .env.local reads
#     postgresql://secvault_user:<pass>@/secvault
# with no host and no port. node-pg fills those from libpq defaults, so the
# application had never cared and nothing anywhere said the URL was unusual.
#
# That was an ASSUMED format meeting a real one -- the same mistake this codebase
# bans for vendor APIs ("verify against live responses; documentation lies"),
# applied to our own configuration.
#
# ⛔ AND [System.Uri] IS NOT THE FIX. It throws "Invalid URI: The hostname could
# not be parsed" on exactly that hostless form, so the obvious "use a real URL
# parser" correction fails on the one input that prompted it. Tested, rejected.
#
# Host and port therefore default to what libpq would have used.
$dbHost = 'localhost'
$dbPort = '5432'
if ($dbUrl -notmatch '^postgres(?:ql)?://([^:@/]+)(?::([^@]*))?@([^:/]*)(?::(\d+))?/(.+)$') {
    Write-Log '  [FAIL] DATABASE_URL could not be parsed. Expected postgresql://user[:pass]@[host][:port]/dbname.'
    exit 1
}
# A password-less URL leaves $Matches[2] as $null (verified on PS 5.1: the
# non-participating group is simply absent from $Matches). UnescapeDataString
# coerces that to '' rather than throwing, so no guard is needed here -- noted
# because the opposite was assumed once.
$dbUser = [System.Uri]::UnescapeDataString($Matches[1])
$dbPass = [System.Uri]::UnescapeDataString($Matches[2])
if ($Matches[3]) { $dbHost = $Matches[3] }
if ($Matches[4]) { $dbPort = $Matches[4] }
$dbName = $Matches[5]

Write-Log "  Database : $dbName on ${dbHost}:${dbPort} as $dbUser"

# ── Choose the backup directory ─────────────────────────────────────────────
#
# Prefer the volume the data already lives on. The install volume on the
# reference deployment is C:, which has ~159 GB free and is also the system
# volume -- a backup there competes with the OS for the space it needs.
if (-not $BackupDir) {
    $candidate = ''
    if ($envText -match '(?m)^SYSLOG_ARCHIVE_DIR=(.+)$') {
        $archive = $Matches[1].Trim()
        if ($archive) {
            $qualifier = Split-Path $archive -Qualifier -ErrorAction SilentlyContinue
            if ($qualifier) { $candidate = Join-Path $qualifier 'SecVaultBackup' }
        }
    }
    if ($candidate) { $BackupDir = $candidate } else { $BackupDir = Join-Path $InstallRoot 'backup' }
}
if (-not (Test-Path $BackupDir)) { New-Item -ItemType Directory -Force -Path $BackupDir | Out-Null }
Write-Log "  Target   : $BackupDir"

# ── Refuse to start without room ────────────────────────────────────────────
#
# A dump that fills the volume it is written to leaves a TRUNCATED FILE THAT
# LOOKS LIKE A BACKUP. Checking first is the difference between a failed backup
# (visible, recoverable) and a corrupt one (invisible until the restore).
$requiredMb = 2048
$prev = Get-ChildItem -Path $BackupDir -Filter 'secvault-*.dump' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending | Select-Object -First 1
if ($prev) {
    $prevMb = [int]($prev.Length / 1MB)
    if (($prevMb * 3) -gt $requiredMb) { $requiredMb = $prevMb * 3 }
    Write-Log "  Previous dump was $prevMb MB; requiring $requiredMb MB free."
}
if ($IncludeSyslog) {
    # ⛔ Sizing off the previous dump is meaningless here: every previous dump
    # EXCLUDED raw syslog, so "3x the last one" is three times the wrong number
    # by roughly a hundredfold. Raw syslog measured ~31 GB/day at 30 days'
    # retention on the reference fleet. We cannot know this deployment's figure
    # from here, so demand a floor big enough that the answer is not silently
    # "yes, plenty" on a volume that cannot possibly hold it.
    if ($requiredMb -lt 51200) { $requiredMb = 51200 }
    Write-Log "  [WARN] -IncludeSyslog: the previous-dump estimate does not apply. Requiring at least $requiredMb MB free, which is still only a floor -- size this yourself from SYSLOG_RETENTION_DAYS."
}

# ⛔ A CHECK THAT COULD NOT RUN IS NOT A PASS, AND THIS ONE USED TO PASS
# SILENTLY. Split-Path -Qualifier returns NOTHING for a UNC path (verified on
# PS 5.1: '\\srv\share\dir' yields $null with -ErrorAction SilentlyContinue),
# so a backup directory on a file share skipped the free-space check entirely
# and said nothing about it -- the guard-that-cannot-fire pattern, in the one
# script whose whole job is not producing a truncated file.
$freeChecked = $false
$qual = Split-Path $BackupDir -Qualifier -ErrorAction SilentlyContinue
if ($qual) {
    $drive = Get-PSDrive -Name $qual.TrimEnd(':') -ErrorAction SilentlyContinue
    if ($drive -and ($null -ne $drive.Free)) {
        $freeChecked = $true
        $freeMb = [int]($drive.Free / 1MB)
        Write-Log "  Free space on $qual $freeMb MB"
        if ($freeMb -lt $requiredMb) {
            Write-Log "  [FAIL] Only $freeMb MB free, need $requiredMb MB. Refusing to write a backup that may be truncated."
            exit 1
        }
    }
}
if (-not $freeChecked) {
    Write-Log "  [WARN] FREE SPACE COULD NOT BE MEASURED for $BackupDir (UNC path, or the drive reported no free-space figure)."
    Write-Log "         This backup is proceeding WITHOUT the truncation guard -- $requiredMb MB was wanted. Check the target's free space yourself."
}

# ── Dump ────────────────────────────────────────────────────────────────────
$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$dumpPath = Join-Path $BackupDir "secvault-$stamp.dump"
$envCopy  = Join-Path $BackupDir "secvault-$stamp.env"
$certCopy = Join-Path $BackupDir "secvault-$stamp.cert.pem"
$keyCopy  = Join-Path $BackupDir "secvault-$stamp.key.pem"

$dumpArgs = @(
    '-U', $dbUser, '-h', $dbHost, '-p', $dbPort, '-d', $dbName,
    '-Fc',            # custom format: compressed, and pg_restore can do selective restores
    '--no-owner',     # restore into a differently-named role without errors
    '--no-acl',
    '-f', $dumpPath
)

if (-not $IncludeSyslog) {
    # ⛔ DATA ONLY. The CREATE TABLE and every partition definition stay in the
    # dump -- see the header. Removing the structure would restore an
    # installation whose collector cannot insert anything.
    $dumpArgs += @('--exclude-table-data=public.syslog_events*')
    Write-Log '  Excluding raw syslog DATA (structure is kept). Pass -IncludeSyslog to dump it.'
} else {
    Write-Log '  [WARN] -IncludeSyslog set: dumping raw syslog too. This will be very large.'
}

$sw = [Diagnostics.Stopwatch]::StartNew()
$out = $null
$dumpExit = 1
try {
    $env:PGPASSWORD = $dbPass
    $out = Invoke-Native { & $PgDump @dumpArgs 2>&1 }
    $dumpExit = $LASTEXITCODE
} finally {
    # ⛔ try/finally, not a trailing line. The database password must not survive
    # this step into any child process; the inline clear only ran on the happy
    # path. Same correction Update-SecVault.ps1 made for PG_ADMIN_PASSWORD.
    Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
}
$sw.Stop()

if ($out) { Add-Content -Path $LogFile -Value ($out -join "`n") }

if ($dumpExit -ne 0 -or -not (Test-Path $dumpPath)) {
    Write-Log "  [FAIL] pg_dump exited $dumpExit. No usable backup was produced."
    if (Test-Path $dumpPath) { Remove-Item $dumpPath -Force -ErrorAction SilentlyContinue }
    exit 1
}
$dumpMb = [math]::Round((Get-Item $dumpPath).Length / 1MB, 1)
Write-Log "  Dump written: $dumpMb MB in $([int]$sw.Elapsed.TotalSeconds)s"

# ── Verify the dump is READABLE, now, not at the disaster ───────────────────
#
# ⛔ A backup nobody has read is a hypothesis. pg_restore --list parses the
# archive's table of contents; it catches truncation and corruption at the
# moment they happen, when there is still a good copy to fall back on.
$listOut = Invoke-Native { & $PgRestore '--list' $dumpPath 2>&1 }
$listExit = $LASTEXITCODE
if ($listExit -ne 0) {
    Write-Log "  [FAIL] The dump could not be read back (pg_restore --list exited $listExit). Deleting it -- a corrupt file that looks like a backup is worse than no backup."
    Add-Content -Path $LogFile -Value ($listOut -join "`n")
    Remove-Item $dumpPath -Force -ErrorAction SilentlyContinue
    exit 1
}
$tocCount = ($listOut | Where-Object { $_ -match '^\d+;' }).Count
Write-Log "  Verified readable: $tocCount archive entries."

# ⛔ An EMPTY but well-formed archive passes --list. A real SecVault dump has
# dozens of tables; single digits means something went wrong upstream.
if ($tocCount -lt 20) {
    Write-Log "  [FAIL] Only $tocCount entries -- that is not a complete SecVault database. Deleting."
    Remove-Item $dumpPath -Force -ErrorAction SilentlyContinue
    exit 1
}

# ── ⛔ Verify the dump is COMPLETE, not merely readable ──────────────────────
#
# An entry COUNT is not a content check. "Readable, 40 entries" is satisfied by
# an archive missing device_credentials, missing every table added since this
# script was last touched, or -- the expensive one -- missing the partitioned
# structure of syslog_events because someone wrote --exclude-table where
# --exclude-table-data was meant. All three restore without complaint and all
# three are only discovered at the moment they cannot be fixed.
#
# ⛔ THE EXPECTED TABLE LIST IS DERIVED FROM lib\schema.sql, NOT HARDCODED
# HERE. A hardcoded list is a second inventory that drifts, and it drifts
# SILENTLY in the safe-looking direction: the new table is simply never checked.
# schema.sql is the one file a new table must always be added to, so reading it
# makes this check maintain itself. When it cannot be read, a floor list is used
# and the reduced coverage is STATED rather than assumed away.
$tocTableDdl = @{}
$tocTableData = @{}
foreach ($line in $listOut) {
    $s = [string]$line
    if ($s -match '^\d+;\s+\S+\s+\S+\s+TABLE DATA\s+(\S+)\s+(\S+)') {
        $tocTableData["$($Matches[1]).$($Matches[2])"] = $true
    } elseif ($s -match '^\d+;\s+\S+\s+\S+\s+TABLE\s+(\S+)\s+(\S+)') {
        $tocTableDdl["$($Matches[1]).$($Matches[2])"] = $true
    }
}
Write-Log "  Archive holds $($tocTableDdl.Count) table definition(s) and $($tocTableData.Count) table-data section(s)."

# ⛔ PARSING NOTHING IS NOT THE SAME AS FINDING NOTHING, and collapsing the two
# would be this script's own signature bug. If a future pg_restore changes its
# --list layout, every ContainsKey below returns false and the completeness
# check would report the entire database missing -- a nightly [FAIL] on a
# perfectly good backup, which trains an operator to ignore it. Zero parsed
# entries means THE CHECK COULD NOT RUN; that is stated and the check is
# skipped, never inverted into a failure or quietly into a pass.
$canVerifyContents = ($tocTableDdl.Count -gt 0)
if (-not $canVerifyContents) {
    Write-Log "  [WARN] No table entries could be parsed out of pg_restore --list ($PgRestore). The COMPLETENESS check below did not run; only readability was verified."
}

# ⛔ THE RULE THIS SCRIPT'S HEADER HAS ALWAYS STATED, NOW ENFORCED.
# Without the CREATE TABLE for syslog_events the restored collector starts,
# reports itself healthy, and fails every INSERT -- a syslog pipeline that is
# quietly dead. A comment cannot catch that; this can.
$verifyFailures = @()
if ($canVerifyContents -and (-not $tocTableDdl.ContainsKey('public.syslog_events'))) {
    $verifyFailures += 'the syslog_events TABLE DEFINITION is absent. Raw syslog must be excluded with --exclude-table-data (data only), NEVER --exclude-table (structure too) -- a restore from this dump would leave the collector unable to insert anything.'
}

# ⛔ AND THE CONVERSE: A PATTERN THAT MATCHES NOTHING IS NOT A pg_dump ERROR.
# Unlike -t, --exclude-table-data does not complain when it matches no table.
# Rename or re-namespace syslog_events and the exclusion silently stops
# applying: the next nightly dump quietly tries to write ~197 GB, fills the
# volume and leaves a truncated file. This is the -replace-that-matched-nothing
# bug class, in pg_dump's dialect.
if (-not $IncludeSyslog) {
    $leakedSyslog = @($tocTableData.Keys | Where-Object { $_ -like 'public.syslog_events*' })
    if ($leakedSyslog.Count -gt 0) {
        Write-Log "  [WARN] RAW SYSLOG DATA IS IN THIS DUMP despite -IncludeSyslog not being set -- $($leakedSyslog.Count) data section(s), e.g. $($leakedSyslog[0])."
        Write-Log '         The --exclude-table-data pattern matched nothing, which pg_dump does not treat as an error. Check whether syslog_events was renamed or moved schema.'
    }
}

# The expected-content manifest.
$expected = @()
$schemaSql = Join-Path $InstallRoot 'lib\schema.sql'
$manifestSource = ''
if (Test-Path $schemaSql) {
    try {
        $schemaText = Get-Content $schemaSql -Raw
        # Anchored at line start, so the phrase appearing inside a `--` comment
        # cannot contribute a bogus name (it does, several times, in that file).
        $matchesFound = [regex]::Matches($schemaText, '(?im)^[ \t]*CREATE\s+TABLE\s+(?:IF\s+NOT\s+EXISTS\s+)?(?:public\.)?([a-z_][a-z0-9_]*)')
        $expected = @($matchesFound | ForEach-Object { $_.Groups[1].Value } | Sort-Object -Unique)
        $manifestSource = "lib\schema.sql ($($expected.Count) tables)"
    } catch {
        $expected = @()
    }
}
if ($expected.Count -eq 0) {
    # ⛔ A REDUCED CHECK, ANNOUNCED. Falling back silently to a short list would
    # report "complete" on far weaker evidence than the words imply.
    $expected = @(
        'devices', 'device_credentials', 'device_configs', 'firewall_rules', 'users', 'user_mfa',
        'settings', 'credential_profiles', 'advisories', 'device_cve_assessments', 'audit_checks',
        'audit_findings', 'compliance_exceptions', 'user_device_scopes', 'ldap_role_mappings',
        'rule_change_requests', 'applications', 'application_flows', 'segmentation_intents',
        'saved_views', 'notification_channels', 'vpn_sessions', 'syslog_rollup_hourly',
        'syslog_rule_hits_hourly', 'activity_log', 'config_backups'
    )
    $manifestSource = "a built-in floor list ($($expected.Count) tables) -- lib\schema.sql could not be read, so COVERAGE IS REDUCED"
}
Write-Log "  Completeness manifest from: $manifestSource"

$missing = @()
if ($canVerifyContents) {
    foreach ($t in $expected) {
        # ⛔ syslog_events is skipped in BOTH modes, not only when excluded.
        # It is a PARTITIONED PARENT: pg_dump never emits a TABLE DATA section
        # for it even with -IncludeSyslog, because the rows live in the daily
        # partitions. Requiring one would fail every -IncludeSyslog backup for a
        # reason that is a property of partitioning, not of the dump. Its table
        # DEFINITION is what matters here and is asserted separately above.
        if ($t -eq 'syslog_events') { continue }
        if (-not $tocTableData.ContainsKey("public.$t")) { $missing += $t }
    }
    if ($missing.Count -gt 0) {
        $verifyFailures += "$($missing.Count) expected table(s) have NO data section in this dump: $($missing -join ', ')"
    }
}

$backupComplete = $true
if ($verifyFailures.Count -gt 0) {
    $backupComplete = $false
    Write-Log '  [FAIL] THIS DUMP IS READABLE BUT NOT COMPLETE:'
    foreach ($f in $verifyFailures) { Write-Log "         - $f" }
    # ⛔ THE FILE IS KEPT. It is structurally sound and holds most of the
    # database; deleting it would turn an incomplete backup into no backup.
    # What is NOT done is pruning (below) -- an older set may still contain what
    # this one is missing, and discarding it on the strength of a newer, worse
    # copy is precisely the data loss this script exists to prevent.
    Write-Log "         The dump has been KEPT at $dumpPath. Old backup sets will NOT be pruned this run."
}

# ── The credential key ──────────────────────────────────────────────────────
#
# ⛔ VERIFIED, NOT ASSUMED. This was a bare Copy-Item followed by a log line
# claiming it had happened. A dump whose key copy failed is the exact artefact
# the header warns about -- an installation that restores looking perfectly
# healthy and cannot authenticate to one firewall -- and the log said nothing.
$keyBackedUp = $false
try {
    Copy-Item -Path $EnvFile -Destination $envCopy -Force
} catch {
    Write-Log "  [FAIL] Could not copy .env.local beside the dump: $($_.Exception.Message)"
}
if ((Test-Path $envCopy) -and ((Get-Item $envCopy).Length -gt 0)) {
    $copyText = Get-Content $envCopy -Raw -Encoding UTF8
    if ($copyText -match '(?m)^CREDENTIAL_KEY=(.+)$' -and $Matches[1].Trim()) {
        $keyBackedUp = $true
        Write-Log '  Copied .env.local, and CREDENTIAL_KEY is present in the copy. Stored firewall credentials will be decryptable from this set.'
    } else {
        Write-Log '  [FAIL] The .env.local copy carries NO CREDENTIAL_KEY. Every device credential in this dump is undecryptable ciphertext.'
        Write-Log '         Check CREDENTIAL_KEY in the live .env.local before relying on this backup.'
    }
} else {
    Write-Log '  [FAIL] No usable .env.local copy was written beside the dump. This backup CANNOT restore device credentials.'
}
if (-not $keyBackedUp) { $backupComplete = $false }

# ── The TLS key pair ────────────────────────────────────────────────────────
#
# ⛔ An operator's own certificate is installed through Settings -> Certificate,
# which writes PEM files and nothing else -- the private key is in no table. A
# rebuild without it comes back on a fresh SELF-SIGNED certificate and every
# browser on the fleet starts warning, which reads as "the restore broke TLS".
# Self-signed material is copied too: it is cheap, and it keeps the restored
# console's identity stable rather than silently rotating it.
$certPath = ''
$keyPath = ''
if ($envText -match '(?m)^TLS_CERT_PATH=(.*)$') { $certPath = $Matches[1].Trim() }
if ($envText -match '(?m)^TLS_KEY_PATH=(.*)$')  { $keyPath  = $Matches[1].Trim() }
if ($certPath -and $keyPath) {
    if ((Test-Path -LiteralPath $certPath) -and (Test-Path -LiteralPath $keyPath)) {
        try {
            Copy-Item -LiteralPath $certPath -Destination $certCopy -Force
            Copy-Item -LiteralPath $keyPath  -Destination $keyCopy  -Force
            if ((Test-Path $certCopy) -and (Test-Path $keyCopy)) {
                Write-Log '  Copied the TLS certificate and PRIVATE KEY beside the dump. Treat this directory accordingly.'
            } else {
                Write-Log '  [WARN] The TLS key pair did not copy. A restore would come back on a newly minted self-signed certificate.'
            }
        } catch {
            Write-Log "  [WARN] Could not copy the TLS key pair: $($_.Exception.Message). A restore would come back on a newly minted self-signed certificate."
        }
    } else {
        # A configured-but-absent path is lib/tlsConfig.js's 'failed' state, and
        # that is worth saying out loud here too -- it means the console is
        # currently serving plain HTTP while its settings claim otherwise.
        Write-Log "  [WARN] TLS_CERT_PATH/TLS_KEY_PATH are set but one or both files do not exist ($certPath / $keyPath). Nothing to back up, and the console is probably running degraded on HTTP."
    }
} else {
    Write-Log '  TLS is not configured (no TLS_CERT_PATH/TLS_KEY_PATH) -- no certificate to back up.'
}

# ── Prune ───────────────────────────────────────────────────────────────────
#
# ⛔ Prunes by SET, and only AFTER a successful verified backup. Deleting old
# copies before the new one is proven good is how a bad night becomes a data
# loss. "Verified" now means readable AND complete AND carrying the credential
# key -- see above for why an incomplete set blocks pruning instead of
# replacing older, better ones.
if (-not $backupComplete) {
    $kept = (Get-ChildItem -Path $BackupDir -Filter 'secvault-*.dump' -ErrorAction SilentlyContinue).Count
    Write-Log "  Pruning SKIPPED because this backup did not fully verify. $kept set(s) now in $BackupDir -- this directory will grow until the problem above is fixed."
} else {
    $sets = @(Get-ChildItem -Path $BackupDir -Filter 'secvault-*.dump' -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending)
    if ($sets.Count -gt $KeepBackups) {
        foreach ($old in ($sets | Select-Object -Skip $KeepBackups)) {
            $base = $old.FullName -replace '\.dump$', ''
            Write-Log "  Pruning $($old.Name)"
            # ⛔ Every member of the set, by name. Missing one here leaves an
            # orphan .env -- a bare CREDENTIAL_KEY sitting in the backup
            # directory with nothing it can decrypt, which is pure exposure.
            foreach ($member in @($old.FullName, "$base.env", "$base.cert.pem", "$base.key.pem")) {
                if (Test-Path -LiteralPath $member) {
                    # ⛔ NOT -ErrorAction SilentlyContinue. A prune that cannot
                    # delete leaves key material on disk and reports nothing;
                    # the operator needs to know which file is stuck.
                    try { Remove-Item -LiteralPath $member -Force }
                    catch { Write-Log "  [WARN] Could not delete $member -- $($_.Exception.Message). Key material may remain on disk." }
                }
            }
        }
    }
}

$kept = (Get-ChildItem -Path $BackupDir -Filter 'secvault-*.dump' -ErrorAction SilentlyContinue).Count
if ($backupComplete) {
    Write-Log "SecVault backup complete -- $dumpMb MB, $kept backup set(s) retained in $BackupDir"
    Write-Log '=========================================='
    exit 0
}
# ⛔ A NON-ZERO EXIT IS THE ONLY THING THE SCHEDULED TASK CAN SEE. Ending 0 here
# would show "Last Run Result: 0x0" in Task Scheduler over a backup that cannot
# restore this installation.
Write-Log "SecVault backup FINISHED WITH PROBLEMS -- $dumpMb MB written to $dumpPath, but see the [FAIL] lines above. Do not rely on this set until they are resolved."
Write-Log '=========================================='
exit 1
