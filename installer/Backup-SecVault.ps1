<#
.SYNOPSIS
    Backs up everything SecVault cannot recompute.

.DESCRIPTION
    Writes a compressed pg_dump of the SecVault database plus a copy of
    .env.local, verifies the dump is readable, and prunes old backups.

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

    #### .env.local is backed up too, and that is not optional

    device_credentials is AES-256-GCM ciphertext keyed on CREDENTIAL_KEY, which
    lives ONLY in .env.local. A database backup without that key restores to an
    installation that looks completely healthy and cannot reach a single
    firewall, with nothing on screen explaining why.

    ### THE BACKUP DIRECTORY IS AS SENSITIVE AS THE DATABASE

    It holds the credential-encryption key beside the encrypted credentials.
    Put it somewhere ACL'd, and do not sync it to a share every domain user can
    read. The key is written as its own file rather than inside the archive so
    it can be given different handling if you want it elsewhere -- but the
    restore will tell you plainly when it is missing.

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

# ── Locate pg_dump ──────────────────────────────────────────────────────────
$PgBin = 'C:\Program Files\PostgreSQL\16\bin'
$PgDump = Join-Path $PgBin 'pg_dump.exe'
$PgRestore = Join-Path $PgBin 'pg_restore.exe'
if (-not (Test-Path $PgDump)) {
    $cmd = Get-Command pg_dump -ErrorAction SilentlyContinue
    if ($cmd) {
        $PgDump = $cmd.Source
        $PgRestore = Join-Path (Split-Path $cmd.Source -Parent) 'pg_restore.exe'
    } else {
        Write-Log "  [FAIL] pg_dump.exe not found at $PgDump and not on PATH."
        exit 1
    }
}

# ── Read the connection details out of the deployed .env.local ──────────────
$EnvFile = Join-Path $InstallRoot '.env.local'
if (-not (Test-Path $EnvFile)) {
    Write-Log "  [FAIL] $EnvFile not found -- cannot determine the database to back up."
    exit 1
}
$envText = Get-Content $EnvFile -Raw

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
$qual = Split-Path $BackupDir -Qualifier -ErrorAction SilentlyContinue
if ($qual) {
    $drive = Get-PSDrive -Name $qual.TrimEnd(':') -ErrorAction SilentlyContinue
    if ($drive -and $drive.Free) {
        $freeMb = [int]($drive.Free / 1MB)
        Write-Log "  Free space on $qual $freeMb MB"
        if ($freeMb -lt $requiredMb) {
            Write-Log "  [FAIL] Only $freeMb MB free, need $requiredMb MB. Refusing to write a backup that may be truncated."
            exit 1
        }
    }
}

# ── Dump ────────────────────────────────────────────────────────────────────
$stamp = (Get-Date).ToString('yyyyMMdd-HHmmss')
$dumpPath = Join-Path $BackupDir "secvault-$stamp.dump"
$envCopy  = Join-Path $BackupDir "secvault-$stamp.env"

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

$env:PGPASSWORD = $dbPass
$sw = [Diagnostics.Stopwatch]::StartNew()
$out = Invoke-Native { & $PgDump @dumpArgs 2>&1 }
$dumpExit = $LASTEXITCODE
$sw.Stop()
Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue

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

# ── The credential key ──────────────────────────────────────────────────────
Copy-Item -Path $EnvFile -Destination $envCopy -Force
Write-Log "  Copied .env.local (holds CREDENTIAL_KEY -- without it, stored firewall credentials cannot be decrypted)."

# ── Prune ───────────────────────────────────────────────────────────────────
#
# ⛔ Prunes by SET, and only AFTER a successful verified backup. Deleting old
# copies before the new one is proven good is how a bad night becomes a data
# loss.
$sets = Get-ChildItem -Path $BackupDir -Filter 'secvault-*.dump' -ErrorAction SilentlyContinue |
        Sort-Object LastWriteTime -Descending
if ($sets.Count -gt $KeepBackups) {
    $sets | Select-Object -Skip $KeepBackups | ForEach-Object {
        $base = $_.FullName -replace '\.dump$', ''
        Write-Log "  Pruning $($_.Name)"
        Remove-Item $_.FullName -Force -ErrorAction SilentlyContinue
        if (Test-Path "$base.env") { Remove-Item "$base.env" -Force -ErrorAction SilentlyContinue }
    }
}

$kept = (Get-ChildItem -Path $BackupDir -Filter 'secvault-*.dump' -ErrorAction SilentlyContinue).Count
Write-Log "SecVault backup complete -- $dumpMb MB, $kept backup set(s) retained in $BackupDir"
Write-Log '=========================================='
exit 0
