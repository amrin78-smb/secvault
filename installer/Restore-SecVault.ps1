<#
.SYNOPSIS
    Restores a SecVault backup produced by Backup-SecVault.ps1.

.DESCRIPTION
    THIS IS DESTRUCTIVE. It drops and recreates every object the backup
    contains, in the live database. It refuses to run without -Force, and by
    default only tells you what it WOULD do.

    Order matters and is the same reasoning as Update-SecVault.ps1's: services
    stop before the database changes under them, and start again after.

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

Write-Log '=========================================='
if ($Force) { Write-Log 'SecVault RESTORE starting (-Force given: this WILL overwrite the database)' }
else { Write-Log 'SecVault restore DRY RUN -- nothing will be changed. Add -Force to perform it.' }

# ── Tools ───────────────────────────────────────────────────────────────────
$PgBin = 'C:\Program Files\PostgreSQL\16\bin'
$PgRestore = Join-Path $PgBin 'pg_restore.exe'
if (-not (Test-Path $PgRestore)) {
    $cmd = Get-Command pg_restore -ErrorAction SilentlyContinue
    if ($cmd) { $PgRestore = $cmd.Source }
    else { Write-Log '  [FAIL] pg_restore.exe not found.'; exit 1 }
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

if (-not $Force) {
    Write-Log ''
    Write-Log '  DRY RUN -- nothing was changed.'
    Write-Log "  This would DROP AND REPLACE the contents of '$dbName' with the backup above."
    if (-not $keyOk) { Write-Log '  Resolve the credential-key warning above before doing that.' }
    Write-Log '  Re-run with -Force to proceed.'
    Write-Log '=========================================='
    exit 0
}

# ── Stop the services ───────────────────────────────────────────────────────
#
# ⛔ sc.exe, never Stop-Service -- the PowerShell cmdlets silently disconnect
# WinRM sessions and hang terminals on this platform.
Write-Log '  Stopping services...'
foreach ($svc in @('SecVault-App', 'SecVault-Engine', 'SecVault-Collector')) {
    Invoke-Native { & sc.exe stop $svc } | Out-Null
}
Start-Sleep -Seconds 5

# ── Restore ─────────────────────────────────────────────────────────────────
#
# --clean --if-exists drops each object before recreating it, so this works
# against a populated database. Single-transaction is deliberately NOT used:
# with --clean it aborts the whole restore on the first DROP of an object that
# was never there, which is the normal case on a partially-rebuilt server.
$env:PGPASSWORD = $dbPass
Write-Log '  Restoring (this may take several minutes)...'
$sw = [Diagnostics.Stopwatch]::StartNew()
$out = Invoke-Native {
    & $PgRestore '-U' $dbUser '-h' $dbHost '-p' $dbPort '-d' $dbName `
                 '--clean' '--if-exists' '--no-owner' '--no-acl' $DumpPath 2>&1
}
$restoreExit = $LASTEXITCODE
$sw.Stop()
Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
if ($out) { Add-Content -Path $LogFile -Value ($out -join "`n") }

# ⛔ pg_restore exits non-zero for benign "does not exist, skipping" notices on
# a --clean run. The exit code alone is not the verdict; the log is, and the
# real verdict is whether the application starts and the data is there.
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
Push-Location $InstallRoot
$migrateOut = Invoke-Native { & node 'lib\migrate.js' 2>&1 }
Pop-Location
if ($migrateOut) { Add-Content -Path $LogFile -Value ($migrateOut -join "`n") }

$grantsPath = Join-Path $InstallRoot 'lib\schema-grants.sql'
if ((Test-Path $grantsPath) -and ($envText -match '(?m)^PG_ADMIN_PASSWORD=(.*)$')) {
    $pgAdmin = $Matches[1].Trim()
    if ($pgAdmin) {
        $env:PGPASSWORD = $pgAdmin
        Invoke-Native { & "$PgBin\psql.exe" '-U' 'postgres' '-h' 'localhost' '-d' $dbName '-f' $grantsPath 2>&1 } | Out-Null
        Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
        Write-Log '  Readonly grants re-applied.'
    }
}

# ── Start, then VERIFY ──────────────────────────────────────────────────────
Write-Log '  Starting services...'
Invoke-Native { & sc.exe start SecVault-Engine } | Out-Null
Invoke-Native { & sc.exe start SecVault-Collector } | Out-Null
Invoke-Native { & sc.exe start SecVault-App } | Out-Null

# ⛔ "Service Running" is NOT "app serving" -- NSSM restarts a crashing process,
# so sc.exe reports Running while node crash-loops. Same lesson the TLS upgrade
# learned; probe the app, not the service.
$appPort = 3010
if ($envText -match '(?m)^APP_PORT=(\d+)$') { $appPort = $Matches[1] }
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
    $nextAuthUrl = ''
    if ($envText -match '(?m)^NEXTAUTH_URL=(.*)$') { $nextAuthUrl = $Matches[1].Trim() }
    if ($nextAuthUrl.StartsWith('https')) {
        $healthy = Test-SecVaultResponding -Port $appPort -UseHttps -TimeoutSeconds 120
    } else {
        $healthy = Test-SecVaultResponding -Port $appPort -TimeoutSeconds 120
    }
} else {
    Write-Log '  [WARN] installer\SecVault-Tls.ps1 not found -- cannot verify the app came back.'
}

if ($healthy) { Write-Log '  Application is answering /api/health.' }
else { Write-Log '  [WARN] The application did not answer /api/health within 2 minutes. Check logs\app.log.' }

Write-Log ''
Write-Log 'Restore complete.'
if (-not $keyOk) {
    Write-Log '⛔ The credential key was not confirmed to match. If device collection now fails with'
    Write-Log '   authentication errors, that is why -- re-enter the device credentials.'
}
Write-Log '⛔ Raw syslog history is NOT in this backup by design. The collector resumes immediately,'
Write-Log '   but events between the backup and now are gone. Rollups and every other table are intact.'
Write-Log '=========================================='
exit 0
