<#
.SYNOPSIS
    Restores a SecVault backup produced by Backup-SecVault.ps1.

.DESCRIPTION
    THIS IS DESTRUCTIVE. It drops and recreates every object the backup
    contains, in the live database. It refuses to run without -Force, and by
    default only tells you what it WOULD do.

    Order matters and is the same reasoning as Update-SecVault.ps1's: services
    stop before the database changes under them, and start again after --
    Engine, Collector, then App, because while the collector is down UDP syslog
    is not queued anywhere, it is simply lost.

    ### THE CREDENTIAL KEY CHECK IS THE POINT OF THIS SCRIPT

    device_credentials is AES-256-GCM ciphertext keyed on CREDENTIAL_KEY from
    .env.local. Restore a database against a DIFFERENT key and SecVault comes up
    looking completely healthy -- every page renders, every device is listed --
    and cannot authenticate to a single firewall. Collection fails device by
    device with authentication errors that look like the firewalls changed their
    passwords.

    So this script compares the key in the backup's .env copy against the live
    one and STOPS when they differ, rather than completing and leaving someone
    to work that out from adapter logs. That is the restore equivalent of this
    product's own rule about a failed read never being recorded as a fact.

    ### ⛔ AND THE SAME RULE APPLIES TO THIS SCRIPT'S OWN VERDICT

    Every step here now has to produce EVIDENCE that it worked, and the script
    exits non-zero when it cannot. It previously ended `exit 0` and the words
    "Restore complete." whatever had happened: a restore into a database that
    did not exist, a migrate.js that failed, a psql that was not where the
    script looked, and an application that never answered all produced the same
    cheerful final line. A restore that reports success it did not verify is the
    most expensive instance of this codebase's most-repeated bug, because it is
    read at the exact moment nobody can afford to re-check it.

.PARAMETER DumpPath
    The .dump file to restore. Blank = the newest in -BackupDir.

.PARAMETER BackupDir
    Where to look when -DumpPath is not given.

.PARAMETER Force
    Actually perform the restore. Without it this is a dry run.

.PARAMETER SkipKeyCheck
    Proceed even when the credential key differs. Only correct when you intend
    to re-enter every device credential afterwards.

.PARAMETER InstallRoot
    SecVault install directory. Default C:\Apps\SecVault.

.EXAMPLE
    .\Restore-SecVault.ps1                      # dry run against the newest backup
    .\Restore-SecVault.ps1 -Force               # do it
#>

[CmdletBinding()]
param(
    [string]$DumpPath = '',
    [string]$BackupDir = '',
    [switch]$Force,
    [switch]$SkipKeyCheck,
    [string]$InstallRoot = 'C:\Apps\SecVault'
)

$ErrorActionPreference = 'Stop'

# Shared TLS/health helpers -- one copy, three callers now.
$tlsHelpers = Join-Path $PSScriptRoot 'SecVault-Tls.ps1'
if (Test-Path -LiteralPath $tlsHelpers) { . $tlsHelpers }

$LogFile = Join-Path $InstallRoot 'logs\restore.log'
$logDir = Split-Path $LogFile -Parent
if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Force -Path $logDir | Out-Null }

function Write-Log {
    param([string]$Message)
    $ts = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
    $line = "[$ts] $Message"
    $line | Write-Host
    Add-Content -Path $LogFile -Value $line
}

function Invoke-Native {
    param([Parameter(Mandatory = $true)][scriptblock]$Command)
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Command } finally { $ErrorActionPreference = $prevEAP }
}

# ⛔ sc.exe ONLY, never Get-Service -- the PowerShell service cmdlets silently
# disconnect WinRM sessions and hang terminals on this platform (CLAUDE.md).
# Returns the state word ('STOPPED', 'RUNNING', ...) or '' when the service is
# not installed / could not be queried.
function Get-SecVaultServiceState {
    param([Parameter(Mandatory = $true)][string]$ServiceName)
    $out = Invoke-Native { & sc.exe query $ServiceName 2>&1 }
    $text = ($out | Out-String)
    if ($text -match 'STATE\s+:\s+\d+\s+([A-Z_]+)') { return $Matches[1] }
    return ''
}

function Wait-SecVaultServiceState {
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$State,
        [int]$TimeoutSeconds = 45
    )
    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    while ((Get-Date) -lt $deadline) {
        $s = Get-SecVaultServiceState -ServiceName $ServiceName
        if ($s -eq $State) { return $true }
        # Not installed at all counts as stopped: a rebuilt host may not have
        # the services yet, and waiting 45s for each of three is pure delay.
        if (-not $s -and $State -eq 'STOPPED') { return $true }
        Start-Sleep -Seconds 2
    }
    return $false
}

$verdictFailures = @()

Write-Log '=========================================='
if ($Force) { Write-Log 'SecVault RESTORE starting (-Force given: this WILL overwrite the database)' }
else { Write-Log 'SecVault restore DRY RUN -- nothing will be changed. Add -Force to perform it.' }

# ── Tools ───────────────────────────────────────────────────────────────────
#
# ⛔ psql IS RESOLVED HERE, NOT ASSUMED LATER. The grants step used to call
# "$PgBin\psql.exe" with $PgBin hardcoded to the PostgreSQL 16 directory, with
# no Test-Path, inside Invoke-Native and piped to Out-Null -- so on a host with
# PostgreSQL anywhere else the call raised CommandNotFoundException, the error
# went to Out-Null, $LASTEXITCODE KEPT ITS PREVIOUS VALUE (verified on PS
# 5.1.26100: it stays at the last native command's code, 0 here), and the script
# logged "Readonly grants re-applied." having run nothing at all.
$PgBin = 'C:\Program Files\PostgreSQL\16\bin'
$PgRestore = Join-Path $PgBin 'pg_restore.exe'
if (-not (Test-Path $PgRestore)) {
    $cmd = Get-Command pg_restore -ErrorAction SilentlyContinue
    if ($cmd) { $PgRestore = $cmd.Source; $PgBin = Split-Path $cmd.Source -Parent }
    else { Write-Log '  [FAIL] pg_restore.exe not found.'; exit 1 }
}
$Psql = Join-Path $PgBin 'psql.exe'
if (-not (Test-Path $Psql)) {
    $cmd = Get-Command psql -ErrorAction SilentlyContinue
    if ($cmd) { $Psql = $cmd.Source } else { $Psql = '' }
}
if (-not $Psql) {
    Write-Log "  [WARN] psql.exe not found beside pg_restore ($PgBin) or on PATH."
    Write-Log '         The pre-flight connection test, the readonly grants and the post-restore row counts will all be SKIPPED, and said so -- they will not be silently reported as done.'
}

$EnvFile = Join-Path $InstallRoot '.env.local'
if (-not (Test-Path $EnvFile)) { Write-Log "  [FAIL] $EnvFile not found."; exit 1 }
$envText = Get-Content $EnvFile -Raw

# ── Find the dump ───────────────────────────────────────────────────────────
if (-not $DumpPath) {
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
    $newest = Get-ChildItem -Path $BackupDir -Filter 'secvault-*.dump' -ErrorAction SilentlyContinue |
              Sort-Object LastWriteTime -Descending | Select-Object -First 1
    if (-not $newest) { Write-Log "  [FAIL] No secvault-*.dump found in $BackupDir"; exit 1 }
    $DumpPath = $newest.FullName
}
if (-not (Test-Path $DumpPath)) { Write-Log "  [FAIL] $DumpPath not found."; exit 1 }

$dumpItem = Get-Item $DumpPath
Write-Log "  Restoring from : $($dumpItem.Name)"
Write-Log "  Taken          : $($dumpItem.LastWriteTime.ToString('yyyy-MM-dd HH:mm:ss'))"
Write-Log "  Size           : $([math]::Round($dumpItem.Length / 1MB, 1)) MB"
$ageDays = [int]((Get-Date) - $dumpItem.LastWriteTime).TotalDays
Write-Log "  Age            : $ageDays day(s)"

# ── Is the archive readable at all? ─────────────────────────────────────────
$listOut = Invoke-Native { & $PgRestore '--list' $DumpPath 2>&1 }
if ($LASTEXITCODE -ne 0) {
    Write-Log '  [FAIL] This file is not a readable pg_dump archive. Restore ABORTED.'
    Add-Content -Path $LogFile -Value ($listOut -join "`n")
    exit 1
}
$tocCount = ($listOut | Where-Object { $_ -match '^\d+;' }).Count
Write-Log "  Archive entries: $tocCount"

# ⛔ SAY WHETHER THE PARTITIONED SYSLOG STRUCTURE IS IN THE ARCHIVE. A dump
# taken with --exclude-table (structure too) instead of --exclude-table-data
# (rows only) restores an installation whose collector starts, reports itself
# healthy and fails every INSERT. It is RECOVERABLE here only because
# lib\migrate.js runs below and schema.sql recreates the parent table -- which
# is another reason the migrate step's exit code is now checked rather than
# assumed.
$hasSyslogDdl = $false
foreach ($line in $listOut) {
    if ([string]$line -match '^\d+;\s+\S+\s+\S+\s+TABLE\s+public\s+syslog_events\s') { $hasSyslogDdl = $true; break }
}
if (-not $hasSyslogDdl) {
    Write-Log '  [WARN] This archive carries NO syslog_events table definition. lib\migrate.js below is what will recreate it; if migrate fails, the collector will run and insert nothing.'
}

# ── ⛔ THE CREDENTIAL KEY CHECK ─────────────────────────────────────────────
$envCopy = $DumpPath -replace '\.dump$', '.env'
$keyOk = $false
if (-not (Test-Path $envCopy)) {
    Write-Log "  [WARN] No .env copy beside this dump ($([System.IO.Path]::GetFileName($envCopy)))."
    Write-Log '         The credential key cannot be checked. If it does not match, every stored'
    Write-Log '         firewall credential in the restored database will be undecryptable and'
    Write-Log '         collection will fail on every device with authentication errors.'
} else {
    $backupEnv = Get-Content $envCopy -Raw
    $backupKey = ''
    $liveKey = ''
    if ($backupEnv -match '(?m)^CREDENTIAL_KEY=(.*)$') { $backupKey = $Matches[1].Trim() }
    if ($envText  -match '(?m)^CREDENTIAL_KEY=(.*)$') { $liveKey   = $Matches[1].Trim() }

    if (-not $backupKey) {
        Write-Log '  [WARN] The backup .env carries no CREDENTIAL_KEY -- cannot compare.'
    } elseif (-not $liveKey) {
        Write-Log '  [WARN] This installation has no CREDENTIAL_KEY set -- cannot compare.'
    } elseif ($backupKey -eq $liveKey) {
        $keyOk = $true
        Write-Log '  Credential key : MATCHES this installation. Stored credentials will decrypt.'
    } else {
        Write-Log '  [STOP] THE CREDENTIAL KEY IN THIS BACKUP DOES NOT MATCH THIS INSTALLATION.'
        Write-Log '         Restoring anyway produces an installation that looks entirely healthy'
        Write-Log '         and cannot authenticate to a single firewall.'
        Write-Log ''
        Write-Log '         Either:'
        Write-Log "           - copy CREDENTIAL_KEY from $envCopy into $EnvFile before restoring, or"
        Write-Log '           - re-run with -SkipKeyCheck and re-enter every device credential afterwards.'
        if (-not $SkipKeyCheck) { Write-Log 'Restore ABORTED.'; exit 1 }
        Write-Log '  [WARN] -SkipKeyCheck given: continuing with credentials that will NOT decrypt.'
    }
}

# ── ⛔ The TLS key pair, reported but NEVER auto-installed ──────────────────
#
# The private key of an operator's own certificate exists in no database row, so
# newer backup sets carry it beside the dump. It is deliberately NOT written
# over the live cert here: silently replacing the certificate a running console
# is serving is a transport change nobody asked this script to make, and the
# operator may be restoring data onto a host that legitimately has its own.
$certCopy = $DumpPath -replace '\.dump$', '.cert.pem'
$keyCopy  = $DumpPath -replace '\.dump$', '.key.pem'
if ((Test-Path $certCopy) -and (Test-Path $keyCopy)) {
    Write-Log "  This set also carries a TLS certificate and private key ($([System.IO.Path]::GetFileName($certCopy)))."
    Write-Log '         They are NOT installed automatically. If this host lost its certificate, copy them over'
    Write-Log '         TLS_CERT_PATH/TLS_KEY_PATH and restart SecVault-App -- node reads them once, at startup.'
} else {
    Write-Log '  No TLS key pair in this backup set. If this host has lost its certificate, the console will come'
    Write-Log '         back on a newly minted self-signed one and browsers will warn.'
}

# ── Connection details ──────────────────────────────────────────────────────
if ($envText -notmatch '(?m)^DATABASE_URL=(.+)$') { Write-Log '  [FAIL] DATABASE_URL not found.'; exit 1 }
$dbUrl = $Matches[1].Trim()
# ⛔ Host and port are OPTIONAL -- the reference deployment omits both
# (postgresql://secvault_user:<pass>@/secvault). See the longer note in
# Backup-SecVault.ps1; [System.Uri] cannot parse that form either.
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
Write-Log "  Target database: $dbName on ${dbHost}:${dbPort} as $dbUser"

# ── ⛔ PRE-FLIGHT: does that database exist, and can we reach it? ────────────
#
# pg_restore -d requires an EXISTING database; it does not create one. On a
# rebuilt host where Install-SecVault.ps1 has not run, every single statement
# fails -- and the old flow read that as pg_restore's familiar non-zero
# "does not exist, skipping" exit, warned that it was "usually harmless", ran
# migrate against nothing, started the services and printed "Restore complete."
# A total failure wearing the success message.
#
# Checking BEFORE -Force does anything also means a restore that cannot work
# does not first take the console down for several minutes.
$dbReachable = $null   # $null = not checked; the third state, never folded into $false
if ($Psql) {
    try {
        $env:PGPASSWORD = $dbPass
        $probe = Invoke-Native { & $Psql '-U' $dbUser '-h' $dbHost '-p' $dbPort '-d' $dbName '-t' '-A' '-c' 'select 1' 2>&1 }
        if ($LASTEXITCODE -eq 0) { $dbReachable = $true } else { $dbReachable = $false }
    } finally {
        Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
    }
    if ($dbReachable) {
        Write-Log "  Pre-flight     : connected to '$dbName' as $dbUser."
    } else {
        Write-Log "  [FAIL] Could not connect to database '$dbName' on ${dbHost}:${dbPort} as $dbUser."
        Add-Content -Path $LogFile -Value ($probe -join "`n")
        Write-Log '         pg_restore CANNOT create the database. Create it first (or run installer\Install-SecVault.ps1),'
        Write-Log "         e.g.  psql -U postgres -c ""CREATE DATABASE $dbName OWNER $dbUser"""
    }
} else {
    Write-Log '  Pre-flight     : SKIPPED (psql not found). Whether the target database exists is UNKNOWN, not assumed good.'
}

if (-not $Force) {
    Write-Log ''
    Write-Log '  DRY RUN -- nothing was changed.'
    Write-Log "  This would DROP AND REPLACE the contents of '$dbName' with the backup above."
    if (-not $keyOk) { Write-Log '  Resolve the credential-key warning above before doing that.' }
    if ($dbReachable -eq $false) { Write-Log '  ⛔ And the target database is not reachable -- with -Force this run would abort rather than proceed.' }
    Write-Log '  Re-run with -Force to proceed.'
    Write-Log '=========================================='
    exit 0
}

# ⛔ Only a DEFINITE false aborts. $null means the check could not run, which is
# not permission to proceed blindly but is also not evidence of a problem -- the
# restore continues and the final verdict below is what decides.
if ($dbReachable -eq $false) {
    Write-Log 'Restore ABORTED before anything was stopped or changed.'
    Write-Log '=========================================='
    exit 1
}

# ── Stop the services ───────────────────────────────────────────────────────
#
# ⛔ sc.exe, never Stop-Service -- the PowerShell cmdlets silently disconnect
# WinRM sessions and hang terminals on this platform.
Write-Log '  Stopping services...'
foreach ($svc in @('SecVault-App', 'SecVault-Engine', 'SecVault-Collector')) {
    Invoke-Native { & sc.exe stop $svc } | Out-Null
}

# ⛔ WAIT FOR STOPPED, do not sleep 5 seconds and hope. `sc.exe stop` only
# REQUESTS a stop; node can take longer, and a still-connected backend holds
# locks that make pg_restore's --clean DROPs fail or block. The old fixed sleep
# turned that race into an intermittent, unexplained partial restore.
foreach ($svc in @('SecVault-App', 'SecVault-Engine', 'SecVault-Collector')) {
    if (-not (Wait-SecVaultServiceState -ServiceName $svc -State 'STOPPED' -TimeoutSeconds 60)) {
        Write-Log "  [WARN] $svc did not report STOPPED within 60s (state: $(Get-SecVaultServiceState -ServiceName $svc)). Its open connections may block DROP statements below."
    }
}

# ⛔ And terminate anything still connected. A service can be STOPPED while a
# stray node.exe or a forgotten psql session keeps a backend alive; DROP TABLE
# then waits on that lock for as long as the session lives. secvault_user can
# terminate its own role's backends, which is exactly the set that matters here.
if ($Psql) {
    try {
        $env:PGPASSWORD = $dbPass
        $killed = Invoke-Native {
            & $Psql '-U' $dbUser '-h' $dbHost '-p' $dbPort '-d' $dbName '-t' '-A' `
                    '-c' 'SELECT count(pg_terminate_backend(pid)) FROM pg_stat_activity WHERE datname = current_database() AND pid <> pg_backend_pid()' 2>&1
        }
        if ($LASTEXITCODE -eq 0) { Write-Log "  Closed $(($killed | Select-Object -First 1)) leftover database connection(s)." }
    } catch {
        Write-Log "  [WARN] Could not close leftover database connections: $($_.Exception.Message)"
    } finally {
        Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
    }
}

# ── Restore ─────────────────────────────────────────────────────────────────
#
# --clean --if-exists drops each object before recreating it, so this works
# against a populated database. Single-transaction is deliberately NOT used:
# with --clean it aborts the whole restore on the first DROP of an object that
# was never there, which is the normal case on a partially-rebuilt server.
Write-Log '  Restoring (this may take several minutes)...'
$sw = [Diagnostics.Stopwatch]::StartNew()
$out = $null
$restoreExit = 1
try {
    $env:PGPASSWORD = $dbPass
    $out = Invoke-Native {
        & $PgRestore '-U' $dbUser '-h' $dbHost '-p' $dbPort '-d' $dbName `
                     '--clean' '--if-exists' '--no-owner' '--no-acl' $DumpPath 2>&1
    }
    $restoreExit = $LASTEXITCODE
} finally {
    # ⛔ try/finally. The database password must not survive this step into
    # node, psql or any other child process started below -- the inline clear
    # only ran on the happy path. Same correction Update-SecVault.ps1 made.
    Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
}
$sw.Stop()
if ($out) { Add-Content -Path $LogFile -Value ($out -join "`n") }

# ⛔ pg_restore exits non-zero for benign "does not exist, skipping" notices on
# a --clean run. The exit code alone is not the verdict; the log is, and the
# real verdict is whether the application starts and the data is there --
# which is now actually MEASURED at the end of this script rather than implied.
if ($restoreExit -ne 0) {
    Write-Log "  [WARN] pg_restore exited $restoreExit. On a --clean restore this is usually harmless"
    Write-Log '         ("does not exist, skipping"). The verification below is what decides.'
}
Write-Log "  Restore finished in $([int]$sw.Elapsed.TotalSeconds)s"

# ── Re-apply schema and grants ──────────────────────────────────────────────
#
# The dump predates any schema change shipped since it was taken, and readonly
# grants were dumped away by --no-acl. migrate.js is idempotent.
Write-Log '  Re-applying schema (lib/migrate.js)...'
$migrateOk = $false
$node = Get-Command node -ErrorAction SilentlyContinue
if (-not $node) {
    # ⛔ A missing node does NOT fail the way it looks like it will: PowerShell
    # raises CommandNotFoundException and LEAVES $LASTEXITCODE UNCHANGED, so a
    # later `if ($LASTEXITCODE -ne 0)` reads the previous command's success.
    Write-Log '  [FAIL] node is not on PATH, so lib\migrate.js DID NOT RUN. The restored schema is whatever the dump contained -- any table or column added since it was taken is missing.'
} else {
    Push-Location $InstallRoot
    try {
        $migrateOut = Invoke-Native { & node 'lib\migrate.js' 2>&1 }
        $migrateExit = $LASTEXITCODE
    } finally {
        Pop-Location
    }
    if ($migrateOut) { Add-Content -Path $LogFile -Value ($migrateOut -join "`n") }
    # ⛔ migrate.js exits 1 on failure and that code was never read. A failed
    # migration leaves an installation whose schema is older than its code:
    # every query naming a newer column crashes, and nothing here said so.
    if ($migrateExit -eq 0) {
        $migrateOk = $true
        Write-Log '  Schema migration completed (exit 0).'
    } else {
        Write-Log "  [FAIL] lib\migrate.js exited $migrateExit. THE SCHEMA IS INCOMPLETE -- do not treat this restore as finished. See the migrate output in $LogFile."
    }
}
if (-not $migrateOk) { $verdictFailures += 'the schema migration did not complete' }

# ── Superuser-level SQL: server settings, then readonly grants ──────────────
#
# Both are best-effort (diagnostic only, never required for the app to run),
# and both now report SKIPPED-and-why rather than claiming to have run.
$pgAdmin = ''
if ($envText -match '(?m)^PG_ADMIN_PASSWORD=(.*)$') { $pgAdmin = $Matches[1].Trim() }

function Invoke-SecVaultSuperuserSql {
    param(
        [Parameter(Mandatory = $true)][string]$SqlPath,
        [Parameter(Mandatory = $true)][string]$Label
    )
    if (-not $Psql)     { Write-Log "  [SKIP] $Label -- psql.exe was not found."; return }
    if (-not $pgAdmin)  { Write-Log "  [SKIP] $Label -- PG_ADMIN_PASSWORD is not set in .env.local."; return }
    if (-not (Test-Path $SqlPath)) { Write-Log "  [SKIP] $Label -- $SqlPath not found."; return }
    try {
        $env:PGPASSWORD = $pgAdmin
        $o = Invoke-Native { & $Psql '-U' 'postgres' '-h' $dbHost '-p' $dbPort '-d' $dbName '-f' $SqlPath 2>&1 }
        $code = $LASTEXITCODE
        Add-Content -Path $LogFile -Value ($o -join "`n")
        if ($code -eq 0) { Write-Log "  $Label applied." }
        else { Write-Log "  [WARN] $Label exited $code -- see $LogFile. This does not affect application function." }
    } catch {
        Write-Log "  [WARN] $Label threw: $($_.Exception.Message)"
    } finally {
        # ⛔ THE POSTGRES SUPERUSER PASSWORD MUST NOT SURVIVE THIS STEP. It was
        # previously cleared only on the happy path, so anything that threw in
        # between left it in this process's environment -- inherited by node,
        # by the services started below, and written into any transcript.
        Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
    }
}

# pg-server-settings.sql is ALTER SYSTEM (superuser-only) and so cannot live in
# schema.sql. Update-SecVault.ps1 applies it on every deploy; a restore onto a
# rebuilt server is exactly where it would otherwise be missing.
Invoke-SecVaultSuperuserSql -SqlPath (Join-Path $InstallRoot 'lib\pg-server-settings.sql') -Label 'lib\pg-server-settings.sql (server diagnostics)'
Invoke-SecVaultSuperuserSql -SqlPath (Join-Path $InstallRoot 'lib\schema-grants.sql') -Label 'lib\schema-grants.sql (readonly grants)'

# ── Start, then VERIFY ──────────────────────────────────────────────────────
#
# Engine and Collector before App, matching Update-SecVault.ps1: while the
# collector is down, inbound UDP syslog is not queued anywhere, it is lost.
Write-Log '  Starting services...'
Invoke-Native { & sc.exe start SecVault-Engine } | Out-Null
Invoke-Native { & sc.exe start SecVault-Collector } | Out-Null
Invoke-Native { & sc.exe start SecVault-App } | Out-Null

# ⛔ "Service Running" is NOT "app serving" -- NSSM restarts a crashing process,
# so sc.exe reports Running while node crash-loops. Same lesson the TLS upgrade
# learned; probe the app, not the service.
$appPort = 3010
if ($envText -match '(?m)^APP_PORT=(\d+)$') {
    $parsed = 0
    if ([int]::TryParse($Matches[1], [ref]$parsed) -and $parsed -gt 0) { $appPort = $parsed }
}

# ⛔ THE TRANSPORT COMES FROM TLS_CERT_PATH/TLS_KEY_PATH, NOT FROM NEXTAUTH_URL.
#
# This used to probe https only when NEXTAUTH_URL started with 'https'. Those
# two are separate settings that are ALLOWED to disagree -- CLAUDE.md documents
# NEXTAUTH_URL being left on http:// while the server speaks https as a real,
# recurring misconfiguration, and Settings -> Certificate can turn TLS on
# without touching it. Reading the wrong one probes http:// against a TLS
# listener, which is a protocol failure rather than a redirect, and concludes a
# perfectly healthy console is dead. Update-SecVault.ps1 reads the cert paths
# for exactly this reason.
#
# ⛔ And HTTPS is tried FIRST, then HTTP -- because lib/tlsConfig.js's 'failed'
# state DEGRADES a configured-but-unloadable certificate to plain HTTP by
# design. Probing only the configured transport would report that live console
# as dead too.
$certConfigured = ''
$keyConfigured = ''
if ($envText -match '(?m)^TLS_CERT_PATH=(.*)$') { $certConfigured = $Matches[1].Trim() }
if ($envText -match '(?m)^TLS_KEY_PATH=(.*)$')  { $keyConfigured  = $Matches[1].Trim() }
$consoleUsesHttps = ($certConfigured -and $keyConfigured)
Write-Log "  Console transport (from .env.local): $(if ($consoleUsesHttps) { 'HTTPS' } else { 'plain HTTP' })"

# ⛔ USES THE SHARED Test-SecVaultResponding, NOT A HAND-ROLLED PROBE.
#
# An earlier draft of this script wrote its own using -SkipCertificateCheck,
# which is PowerShell 7 ONLY and is a parameter error on the 5.1 this runs
# under. The shared helper exists because getting this wrong has already cost
# TWO PRODUCTION OUTAGES: the obvious ServerCertificateValidationCallback
# approach cannot work in 5.1 (the delegate runs on a thread with no runspace),
# so the probe ALWAYS returned false over HTTPS and the caller concluded a
# working deployment was dead and rolled it back. Read that function's comment
# before touching this. A false negative in a health check is worse than no
# health check.
$healthy = $false
if (Get-Command Test-SecVaultResponding -ErrorAction SilentlyContinue) {
    if ($consoleUsesHttps) {
        $healthy = Test-SecVaultResponding -Port $appPort -UseHttps -TimeoutSeconds 120
        if (-not $healthy) { $healthy = Test-SecVaultResponding -Port $appPort -TimeoutSeconds 30 }
    } else {
        $healthy = Test-SecVaultResponding -Port $appPort -TimeoutSeconds 120
    }
} else {
    # ⛔ A PROBE THAT COULD NOT RUN IS NOT A PASS. This is recorded as a
    # verdict failure, not shrugged off, because the whole point of the final
    # banner is that it means something.
    Write-Log '  [FAIL] installer\SecVault-Tls.ps1 not found -- Test-SecVaultResponding does not exist and THE CONSOLE WAS NEVER PROBED.'
    $verdictFailures += 'the application was never probed'
}

if ($healthy) {
    Write-Log '  Application is answering /api/health.'
} elseif (Get-Command Test-SecVaultResponding -ErrorAction SilentlyContinue) {
    Write-Log '  [FAIL] The application did not answer /api/health within 2 minutes. Check logs\app.log and logs\app-error.log.'
    $verdictFailures += 'the application did not answer /api/health'
}

# ── ⛔ A DATA-LEVEL VERDICT, not just a liveness one ─────────────────────────
#
# /api/health proves node is serving. It does not prove the data arrived: an
# empty database serves health perfectly. These counts are the cheapest
# available evidence that the restore actually landed, and a ZERO in devices or
# users is reported as a problem rather than printed as a number -- a restored
# installation with no users is one nobody can log into.
if ($Psql) {
    try {
        $env:PGPASSWORD = $dbPass
        foreach ($t in @('devices', 'device_credentials', 'users', 'firewall_rules', 'advisories', 'audit_findings')) {
            $c = Invoke-Native { & $Psql '-U' $dbUser '-h' $dbHost '-p' $dbPort '-d' $dbName '-t' '-A' '-c' "select count(*) from $t" 2>&1 }
            if ($LASTEXITCODE -eq 0) {
                # Trimmed: psql -t leaves a leading space on some builds even
                # with -A, and an untrimmed ' 0' would never equal '0', so the
                # empty-table guard below would silently never fire.
                $n = ([string]($c | Select-Object -First 1)).Trim()
                Write-Log "    $t : $n row(s)"
                if (($t -eq 'devices' -or $t -eq 'users') -and ($n -eq '0')) {
                    $verdictFailures += "$t is EMPTY after the restore"
                }
            } else {
                Write-Log "    $t : COULD NOT BE READ -- $($c -join ' ')"
                $verdictFailures += "$t could not be read after the restore"
            }
        }
    } finally {
        Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
    }
} else {
    Write-Log '  [WARN] Row counts SKIPPED (psql not found) -- whether the data actually landed is UNVERIFIED.'
}

Write-Log ''
if (-not $keyOk) {
    Write-Log '⛔ The credential key was not confirmed to match. If device collection now fails with'
    Write-Log '   authentication errors, that is why -- re-enter the device credentials.'
}
Write-Log '⛔ Raw syslog history is NOT in this backup by design. The collector resumes immediately,'
Write-Log '   but events between the backup and now are gone. Rollups and every other table are intact.'

if ($verdictFailures.Count -eq 0) {
    Write-Log 'Restore complete and VERIFIED: schema migrated, console answering, data present.'
    Write-Log '=========================================='
    exit 0
}
# ⛔ THE FINAL LINE IS A VERDICT, AND THE EXIT CODE CARRIES IT. Ending 0 with
# "Restore complete." over a failed migration or a dead console is the failure
# this whole script exists to prevent, committed by the script itself.
Write-Log 'RESTORE DID NOT FULLY VERIFY:'
foreach ($f in $verdictFailures) { Write-Log "  - $f" }
Write-Log 'Treat this installation as NOT RESTORED until the items above are resolved.'
Write-Log '=========================================='
exit 1
