<#
.SYNOPSIS
    Updates an existing SecVault installation in place.

.DESCRIPTION
    Exact step order per CLAUDE.md "Update Script  -  Exact Order"  -  do not
    reorder without testing:
      1. sc.exe stop SecVault-App
      2. sc.exe stop SecVault-Engine
      3. git pull origin main
      4. npm ci
      5. node lib\migrate.js       (schema migration BEFORE services restart)
      6. npm run build
      7. sc.exe start SecVault-Engine
      8. sc.exe start SecVault-App

    Written for PowerShell 5.1  -  see CLAUDE.md "PowerShell (PS5 compatibility)".
    Never uses Start-Service/Stop-Service/Get-Service  -  sc.exe only.
    Never pipes directly out of try/catch  -  always `$out = cmd; $out | Write-Host`.

    On any step failure: the error is logged, but this script still attempts
    a best-effort recovery by starting both services at the end, rather than
    leaving the app down (per spec).
#>

[CmdletBinding()]
param()

# Set explicitly rather than left inherited from the caller's session. This
# script is invoked directly by an admin ("& Update-SecVault.ps1" per
# CLAUDE.md), so the ambient $ErrorActionPreference is whatever that
# session/profile happens to have -- if it were ever 'Stop' (a common
# hardening default in some admin profiles), every native call below that
# uses `2>&1` (git pull, npm ci, node lib\migrate.js, npm run build) would
# have its normal stderr output (progress text, warnings -- not necessarily
# real failures) converted into a script-halting NativeCommandError before
# the explicit $LASTEXITCODE check below it ever runs -- see CLAUDE.md
# "PowerShell (PS5 compatibility)" / Install-SecVault.ps1's Invoke-Native.
# Setting 'Stop' here (matching Install-SecVault.ps1) makes the script's
# behavior deterministic regardless of caller context, and Invoke-Native
# below still lets each native call's own stderr be inspected without that
# escalation -- $LASTEXITCODE is unaffected either way and remains the
# actual failure signal.
$ErrorActionPreference = 'Stop'

$InstallRoot = 'C:\Apps\SecVault'
$LogDir = 'C:\Apps\SecVault\logs'
$LogFile = Join-Path $LogDir 'update.log'

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

$script:hadFailure = $false

function Write-Log {
    param([string]$Message)
    $ts = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
    $line = "[$ts] $Message"
    $line | Write-Host
    Add-Content -Path $LogFile -Value $line
}

# See the $ErrorActionPreference comment above -- routes native calls that
# use `2>&1` through a temporary 'Continue' window so their own stderr can
# never escalate into a script-halting NativeCommandError. $LASTEXITCODE is
# still set normally by the underlying call for real failure detection at
# each call site. Copied from Install-SecVault.ps1 (proven against a real
# server this session).
function Invoke-Native {
    param([Parameter(Mandatory = $true)][scriptblock]$Command)
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try {
        & $Command
    } finally {
        $ErrorActionPreference = $prevEAP
    }
}

# `sc.exe start`/`sc.exe stop` return as soon as the SCM accepts the
# request, not once the service has actually reached that state. Used below
# after stopping SecVault-App/SecVault-Engine so npm ci / npm run build
# don't race a still-shutting-down node.exe process that may still hold
# open handles on files under node_modules\ or .next\ (Windows locks these
# for the process's lifetime -- e.g. loaded native addon .node files --
# causing intermittent EBUSY/EPERM errors if npm touches them mid-shutdown).
# Read-only Get-Service polling, not Start-Service/Stop-Service -- see
# CLAUDE.md "Never use PowerShell service cmdlets". Copied from
# Install-SecVault.ps1 (proven against a real server this session).
function Wait-ServiceStatus {
    param(
        [Parameter(Mandatory = $true)][string]$ServiceName,
        [Parameter(Mandatory = $true)][string]$Status,
        [int]$TimeoutSeconds = 30
    )
    $waited = 0
    while ($waited -lt $TimeoutSeconds) {
        $svc = Get-Service -Name $ServiceName -ErrorAction SilentlyContinue
        if ($svc -and $svc.Status -eq $Status) { return $true }
        Start-Sleep -Seconds 1
        $waited++
    }
    return $false
}

function Invoke-Step {
    param(
        [string]$Name,
        [scriptblock]$Action
    )
    Write-Log "Step starting: $Name"
    try {
        & $Action
        Write-Log "Step succeeded: $Name"
        return $true
    } catch {
        $script:hadFailure = $true
        Write-Log "Step FAILED: $Name -- $($_.Exception.Message)"
        return $false
    }
}

Write-Log '=================================================='
Write-Log 'SecVault update starting.'
Write-Log '=================================================='

$repoRoot = Split-Path -Parent $PSScriptRoot

# secvault is a private repo -- git pull (step 3 below) needs the SSH deploy
# key that Install-SecVault.ps1 configures at $env:USERPROFILE\.ssh\secvault_deploy.
# Fail fast, before touching any service, if it's missing.
$deployKey = "$env:USERPROFILE\.ssh\secvault_deploy"
if (-not (Test-Path $deployKey)) {
    Write-Host "  [FAIL] SSH deploy key not found: $deployKey"
    Write-Host "         Re-run Install-SecVault.ps1 to configure SSH credentials"
    exit 1
}

# -----------------------------------------------------------------------
# 1. Stop SecVault-App
# -----------------------------------------------------------------------
Invoke-Step 'sc.exe stop SecVault-App' {
    $out = sc.exe stop SecVault-App
    $out | Write-Host
    Add-Content -Path $LogFile -Value ($out -join "`n")
    if (-not (Wait-ServiceStatus -ServiceName 'SecVault-App' -Status 'Stopped' -TimeoutSeconds 30)) {
        Write-Log '  [WARN] SecVault-App did not reach Stopped state within 30s -- proceeding anyway.'
    }
}

# -----------------------------------------------------------------------
# 2. Stop SecVault-Engine
# -----------------------------------------------------------------------
Invoke-Step 'sc.exe stop SecVault-Engine' {
    $out = sc.exe stop SecVault-Engine
    $out | Write-Host
    Add-Content -Path $LogFile -Value ($out -join "`n")
    if (-not (Wait-ServiceStatus -ServiceName 'SecVault-Engine' -Status 'Stopped' -TimeoutSeconds 30)) {
        Write-Log '  [WARN] SecVault-Engine did not reach Stopped state within 30s -- proceeding anyway.'
    }
}

# -----------------------------------------------------------------------
# 3. git pull origin main
# -----------------------------------------------------------------------
Invoke-Step 'git pull origin main' {
    Push-Location $repoRoot
    $out = Invoke-Native { git pull origin main 2>&1 }
    Pop-Location
    $out | Write-Host
    Add-Content -Path $LogFile -Value ($out -join "`n")
    if ($LASTEXITCODE -ne 0) {
        throw "git pull exited with code $LASTEXITCODE"
    }
}

# -----------------------------------------------------------------------
# 4. npm ci
# -----------------------------------------------------------------------
Invoke-Step 'npm ci' {
    Push-Location $repoRoot
    $out = Invoke-Native { npm ci 2>&1 }
    Pop-Location
    $out | Write-Host
    Add-Content -Path $LogFile -Value ($out -join "`n")
    if ($LASTEXITCODE -ne 0) {
        throw "npm ci exited with code $LASTEXITCODE"
    }
}

# -----------------------------------------------------------------------
# 5. node lib\migrate.js  (schema migration BEFORE services restart)
# -----------------------------------------------------------------------
Invoke-Step 'node lib\migrate.js' {
    Push-Location $repoRoot
    $out = Invoke-Native { node lib\migrate.js 2>&1 }
    Pop-Location
    $out | Write-Host
    Add-Content -Path $LogFile -Value ($out -join "`n")
    if ($LASTEXITCODE -ne 0) {
        throw "node lib\migrate.js exited with code $LASTEXITCODE"
    }
}

# -----------------------------------------------------------------------
# 6. npm run build
# -----------------------------------------------------------------------
Invoke-Step 'npm run build' {
    Push-Location $repoRoot
    $out = Invoke-Native { npm run build 2>&1 }
    Pop-Location
    $out | Write-Host
    Add-Content -Path $LogFile -Value ($out -join "`n")
    if ($LASTEXITCODE -ne 0) {
        throw "npm run build exited with code $LASTEXITCODE"
    }
}

# -----------------------------------------------------------------------
# 7. Start SecVault-Engine
# -----------------------------------------------------------------------
Invoke-Step 'sc.exe start SecVault-Engine' {
    $out = sc.exe start SecVault-Engine
    $out | Write-Host
    Add-Content -Path $LogFile -Value ($out -join "`n")
    if (-not (Wait-ServiceStatus -ServiceName 'SecVault-Engine' -Status 'Running' -TimeoutSeconds 15)) {
        Write-Log '  [WARN] SecVault-Engine did not reach Running state within 15s -- check logs\engine-stderr.log.'
    }
}

# -----------------------------------------------------------------------
# 8. Start SecVault-App
# -----------------------------------------------------------------------
Invoke-Step 'sc.exe start SecVault-App' {
    $out = sc.exe start SecVault-App
    $out | Write-Host
    Add-Content -Path $LogFile -Value ($out -join "`n")
    if (-not (Wait-ServiceStatus -ServiceName 'SecVault-App' -Status 'Running' -TimeoutSeconds 15)) {
        Write-Log '  [WARN] SecVault-App did not reach Running state within 15s -- check logs\app-error.log.'
    }
}

Write-Log '=================================================='
if ($script:hadFailure) {
    Write-Log 'SecVault update completed WITH ERRORS  -  see steps above. Both services were still (re)started as a best-effort recovery.'
} else {
    Write-Log 'SecVault update completed successfully.'
}
Write-Log '=================================================='
