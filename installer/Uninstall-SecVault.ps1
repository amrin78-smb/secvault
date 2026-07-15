<#
.SYNOPSIS
    Removes SecVault services (and, optionally, the database and/or install
    directory) from this server.

.DESCRIPTION
    Written for PowerShell 5.1  -  see CLAUDE.md "PowerShell (PS5 compatibility)".
    Never uses Start-Service/Stop-Service/Get-Service  -  sc.exe only.
    Never pipes directly out of try/catch  -  always `$out = cmd; $out | Write-Host`.

.PARAMETER DropDatabase
    If set, also drops the `secvault` database and `secvault_user` role.
#>

[CmdletBinding()]
param(
    [switch]$DropDatabase
)

$InstallRoot = 'C:\Apps\SecVault'

function Write-Step {
    param([string]$Message)
    $ts = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
    Write-Host "[$ts] $Message"
}

Write-Host '=================================================='
Write-Host ' SecVault Uninstaller'
Write-Host '=================================================='

# -----------------------------------------------------------------------
# 1. Confirmation prompt
# -----------------------------------------------------------------------
$confirm = Read-Host 'This will remove SecVault. Continue? [y/N]'
if (-not ($confirm -eq 'y' -or $confirm -eq 'Y')) {
    Write-Host 'Aborted. No changes made.'
    exit 0
}

# -----------------------------------------------------------------------
# 2. Stop services (sc.exe only  -  never Start-Service/Stop-Service)
# -----------------------------------------------------------------------
Write-Step 'Stopping services...'

$out = sc.exe stop SecVault-App
$out | Write-Host

$out = sc.exe stop SecVault-Engine
$out | Write-Host

# -----------------------------------------------------------------------
# 3. Remove NSSM services
# -----------------------------------------------------------------------
Write-Step 'Removing NSSM services...'

if (Get-Command nssm -ErrorAction SilentlyContinue) {
    $out = & nssm remove SecVault-App confirm 2>&1
    $out | Write-Host

    $out = & nssm remove SecVault-Engine confirm 2>&1
    $out | Write-Host
} else {
    Write-Host '[WARN] nssm was not found on PATH  -  skipping service removal. Remove the services manually if they still exist.' -ForegroundColor Yellow
}

# -----------------------------------------------------------------------
# 4. Optionally drop database + user
# -----------------------------------------------------------------------
if ($DropDatabase) {
    Write-Step 'Dropping database and user...'

    # NOTE: see the same assumption documented in Install-SecVault.ps1 -- there
    # is no parameter carrying the `postgres` superuser password; 'postgres'
    # is assumed as the default local superuser password. Override if needed.
    $env:PGPASSWORD = 'postgres'

    $out = & psql -U postgres -h localhost -c "DROP DATABASE IF EXISTS secvault" 2>&1
    $out | Write-Host
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
        Write-Host "[WARN] DROP DATABASE exited with code $LASTEXITCODE." -ForegroundColor Yellow
    }

    $out = & psql -U postgres -h localhost -c "DROP USER IF EXISTS secvault_user" 2>&1
    $out | Write-Host
    if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
        Write-Host "[WARN] DROP USER exited with code $LASTEXITCODE." -ForegroundColor Yellow
    }

    Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue

    Write-Step 'Database and user dropped.'
} else {
    Write-Step 'Skipping database removal (-DropDatabase not specified).'
}

# -----------------------------------------------------------------------
# 5. Optionally delete install directory
# -----------------------------------------------------------------------
$deleteConfirm = Read-Host "Also delete $InstallRoot entirely? This is IRREVERSIBLE DATA LOSS (logs, config, .env.local). [y/N]"
if ($deleteConfirm -eq 'y' -or $deleteConfirm -eq 'Y') {
    Write-Step "Deleting $InstallRoot..."
    if (Test-Path $InstallRoot) {
        Remove-Item -Recurse -Force -Confirm:$false -Path $InstallRoot
        Write-Step "$InstallRoot deleted."
    } else {
        Write-Step "$InstallRoot does not exist  -  nothing to delete."
    }
} else {
    Write-Step "Leaving $InstallRoot in place."
}

Write-Host ''
Write-Host '=================================================='
Write-Host ' SecVault uninstall complete.'
Write-Host '=================================================='
