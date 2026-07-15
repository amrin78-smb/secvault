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

# -----------------------------------------------------------------------
# 1. Stop SecVault-App
# -----------------------------------------------------------------------
Invoke-Step 'sc.exe stop SecVault-App' {
    $out = sc.exe stop SecVault-App
    $out | Write-Host
    Add-Content -Path $LogFile -Value ($out -join "`n")
}

# -----------------------------------------------------------------------
# 2. Stop SecVault-Engine
# -----------------------------------------------------------------------
Invoke-Step 'sc.exe stop SecVault-Engine' {
    $out = sc.exe stop SecVault-Engine
    $out | Write-Host
    Add-Content -Path $LogFile -Value ($out -join "`n")
}

# -----------------------------------------------------------------------
# 3. git pull origin main
# -----------------------------------------------------------------------
Invoke-Step 'git pull origin main' {
    Push-Location $repoRoot
    $out = git pull origin main 2>&1
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
    $out = npm ci 2>&1
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
    $out = node lib\migrate.js 2>&1
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
    $out = npm run build 2>&1
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
}

# -----------------------------------------------------------------------
# 8. Start SecVault-App
# -----------------------------------------------------------------------
Invoke-Step 'sc.exe start SecVault-App' {
    $out = sc.exe start SecVault-App
    $out | Write-Host
    Add-Content -Path $LogFile -Value ($out -join "`n")
}

Write-Log '=================================================='
if ($script:hadFailure) {
    Write-Log 'SecVault update completed WITH ERRORS  -  see steps above. Both services were still (re)started as a best-effort recovery.'
} else {
    Write-Log 'SecVault update completed successfully.'
}
Write-Log '=================================================='
