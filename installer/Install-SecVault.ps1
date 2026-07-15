<#
.SYNOPSIS
    Installs SecVault: provisions all prerequisites (Git, Node.js, PostgreSQL,
    NSSM, VC++ Redistributable) from a bundled dependencies folder, then
    provisions the database, configures .env.local, builds the app, and
    registers the NSSM services.

.DESCRIPTION
    Written for PowerShell 5.1 (Windows Server) -- see CLAUDE.md "PowerShell
    (PS5 compatibility)". Do not introduce PS7-only syntax:
      - No `try { cmd | Write-Host } catch {}` -- always `$out = cmd; $out | Write-Host`.
      - No `-Parallel` on ForEach-Object, no `-TimeoutSeconds` on Test-Connection.
      - Never use `$PID` (reserved) -- use `$procPid`.
      - Service control is `sc.exe` only -- never Start-Service/Stop-Service/Get-Service.

    Follows the same bundled-dependencies convention as the NocVault suite
    installer (Install-NocVault-Suite.ps1): required prerequisite installers
    live in a `dependencies\` folder next to this script, are installed
    silently/unattended from those local files (no internet download required
    for prerequisites), and are skipped if the tool is already present on the
    server. See `installer\dependencies\README.txt` for exactly what to place
    there before running this script.

.PARAMETER ServerIp
    IP address (or hostname) of this server. Used for DATABASE_URL / NEXTAUTH_URL
    and the final success banner.

.PARAMETER DbPassword
    Password to assign to the secvault_user PostgreSQL role.

.PARAMETER PgAdminPassword
    Password to set for the PostgreSQL `postgres` superuser. Only meaningful
    the first time PostgreSQL is installed on this server (this is the value
    being SET during a fresh PostgreSQL install); if PostgreSQL is already
    installed, this must match its existing superuser password so this script
    can create the SecVault database/user and apply schema-grants.sql.

.PARAMETER AppPort
    Port for the SecVault-App (Next.js) service.

.PARAMETER NetVaultUrl
    Optional. If set, NETVAULT_URL is written to .env.local for optional SSO
    federation (disabled by default -- see CLAUDE.md "Optional Suite Integration").
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerIp,

    [string]$DbPassword = 'NVAdmin@2026',

    [string]$PgAdminPassword = 'SecV@ult_Pg#2026',

    [int]$AppPort = 3010,

    [string]$NetVaultUrl = ''
)

$ErrorActionPreference = 'Stop'

$InstallRoot = 'C:\Apps\SecVault'
$LogDir = 'C:\Apps\SecVault\logs'

function Write-Step {
    param([string]$Message)
    $ts = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
    Write-Host "[$ts] $Message"
}

function Fail {
    param([string]$Message)
    $ts = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
    Write-Host "[$ts] [FATAL] $Message" -ForegroundColor Red
    exit 1
}

Write-Host '=================================================='
Write-Host ' SecVault Installer'
Write-Host '=================================================='

$SecVaultGitUrl = 'https://github.com/amrin78-smb/secvault.git'

# The application repo is cloned into $InstallRoot itself (CLAUDE.md: "Install
# path: C:\Apps\SecVault\" IS the repo root -- unlike some other suite apps
# there is no separate "\app" subfolder). This installer is a standalone
# distributable (dependencies bundled alongside it, e.g. C:\SecVault-Installer\)
# and is NOT expected to already be sitting inside a clone of the repo -- do
# not derive $repoRoot from $PSScriptRoot.
$repoRoot = $InstallRoot
$DepsDir = Join-Path $PSScriptRoot 'dependencies'

# -----------------------------------------------------------------------
# 1. Validate the bundled dependencies folder (fail fast, list what's missing)
# -----------------------------------------------------------------------
Write-Step 'Validating installer package...'

$NodeMsi      = Join-Path $DepsDir 'node-v20.19.0-x64.msi'
$NssmZip      = Join-Path $DepsDir 'nssm-2.24.zip'
$PgInstaller  = (Get-ChildItem (Join-Path $DepsDir 'postgresql-16*windows-x64.exe') -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
$GitInstaller = Join-Path $DepsDir 'Git-2.54.0-64-bit.exe'
$VcRedist     = Join-Path $DepsDir 'VC_redist.x64.exe'

$missing = @()
if (-not (Test-Path $NodeMsi)) { $missing += 'dependencies\node-v20.19.0-x64.msi' }
if (-not (Test-Path $NssmZip)) { $missing += 'dependencies\nssm-2.24.zip' }
if (-not $PgInstaller)         { $missing += 'dependencies\postgresql-16*-windows-x64.exe' }
if ($missing.Count -gt 0) {
    Write-Host "`n  Missing required files:" -ForegroundColor Red
    $missing | ForEach-Object { Write-Host "    - $_" -ForegroundColor Red }
    Write-Host "`n  Place the missing files in $DepsDir and retry. See dependencies\README.txt.`n" -ForegroundColor Red
    exit 1
}
Write-Step 'All required dependency files present.'

if (-not (Test-Path $GitInstaller)) {
    Write-Host '[WARN] Git-2.54.0-64-bit.exe not found in dependencies\ -- will fall back to a PATH-installed git, and fail later if git is also not already installed.' -ForegroundColor Yellow
}
if (-not (Test-Path $VcRedist)) {
    Write-Host '[WARN] VC_redist.x64.exe not found in dependencies\ -- skipping (Node.js/PostgreSQL may still need it if not already present from another install).' -ForegroundColor Yellow
}

# -----------------------------------------------------------------------
# 2. Clone (or verify) the SecVault application repo into $InstallRoot
# -----------------------------------------------------------------------
# Deliberately does NOT create $LogDir yet -- `git clone` refuses to clone
# into a non-empty directory, so $InstallRoot must still be empty (or not
# yet exist) at this point.
Write-Step 'Checking for an existing SecVault deployment...'

if (Test-Path (Join-Path $InstallRoot 'package.json')) {
    Write-Step "SecVault already present at $InstallRoot -- skipping clone. Use Update-SecVault.ps1 to pull the latest code instead of re-running this installer."
} elseif ((Test-Path $InstallRoot) -and ((Get-ChildItem $InstallRoot -Force -ErrorAction SilentlyContinue | Measure-Object).Count -gt 0)) {
    Fail "$InstallRoot exists and is not empty, but does not look like a SecVault checkout (no package.json). Refusing to clone into it -- clear it out or choose a different -ServerIp/InstallRoot and retry."
} else {
    Write-Step "Cloning SecVault from $SecVaultGitUrl..."
    New-Item -ItemType Directory -Force -Path $InstallRoot | Out-Null
    $out = & git clone $SecVaultGitUrl $InstallRoot 2>&1
    $out | Write-Host
    if ($LASTEXITCODE -ne 0) {
        Fail "git clone failed with exit code $LASTEXITCODE. Confirm this server has network access to GitHub and cached credentials for the private amrin78-smb/secvault repo (Git Credential Manager / SSH key), then retry."
    }
    # Mark the repo safe for the SYSTEM account (services/update jobs may run
    # git as SYSTEM) -- same reasoning as the NocVault suite installer.
    & git config --system --add safe.directory ($InstallRoot -replace '\\', '/') 2>$null
    Write-Step 'SecVault cloned.'
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# -----------------------------------------------------------------------
# 3. Visual C++ Redistributable (silent, best-effort)
# -----------------------------------------------------------------------
Write-Step 'Installing Visual C++ Redistributable...'
if (Test-Path $VcRedist) {
    $out = Start-Process -Wait -PassThru -FilePath $VcRedist -ArgumentList '/install', '/quiet', '/norestart'
    Write-Step "VC++ Redistributable installer exited with code $($out.ExitCode) (0 or 3010 = success; 3010 = reboot recommended, not required)."
} else {
    Write-Host '[WARN] VC_redist.x64.exe not present -- skipping.' -ForegroundColor Yellow
}

# -----------------------------------------------------------------------
# 4. Node.js v20 (from bundled MSI, skip if already installed)
# -----------------------------------------------------------------------
Write-Step 'Checking Node.js...'
$nodeVersion = $null
try { $nodeVersion = & node -v 2>$null } catch { $nodeVersion = $null }
if ($nodeVersion) {
    Write-Step "Node.js already installed: $nodeVersion"
} else {
    Write-Step 'Installing Node.js v20.19.0 from bundled MSI...'
    $out = Start-Process -Wait -PassThru -FilePath 'msiexec.exe' -ArgumentList "/I `"$NodeMsi`" /quiet /norestart"
    if ($out.ExitCode -ne 0) {
        Fail "Node.js MSI install failed with exit code $($out.ExitCode)."
    }
    # Refresh PATH in this process from the machine + user environment so the
    # rest of this script (npm ci, npm run build, etc.) can find node/npm
    # without requiring a new shell.
    $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [System.Environment]::GetEnvironmentVariable('Path', 'User')
    Write-Step 'Node.js v20.19.0 installed.'
}

# -----------------------------------------------------------------------
# 5. Git (from bundled installer, skip if already installed)
# -----------------------------------------------------------------------
Write-Step 'Checking Git...'
$gitVersion = $null
try { $gitVersion = & git --version 2>$null } catch { $gitVersion = $null }
if ($gitVersion) {
    Write-Step "Git already installed: $gitVersion"
} elseif (Test-Path $GitInstaller) {
    Write-Step 'Installing Git from bundled installer...'
    $out = Start-Process -Wait -PassThru -FilePath $GitInstaller -ArgumentList '/VERYSILENT', '/NORESTART'
    if ($out.ExitCode -ne 0) {
        Fail "Git install failed with exit code $($out.ExitCode)."
    }
    $env:Path = [System.Environment]::GetEnvironmentVariable('Path', 'Machine') + ';' +
                [System.Environment]::GetEnvironmentVariable('Path', 'User')
    Write-Step 'Git installed.'
} else {
    Fail 'Git is not installed and no bundled Git installer was found in dependencies\. Cannot continue.'
}

# -----------------------------------------------------------------------
# 6. PostgreSQL 16 (from bundled installer, skip if already installed)
# -----------------------------------------------------------------------
Write-Step 'Checking PostgreSQL...'
$PgBin = 'C:\Program Files\PostgreSQL\16\bin'
if (Test-Path (Join-Path $PgBin 'psql.exe')) {
    Write-Step 'PostgreSQL already installed.'
} else {
    Write-Step 'Installing PostgreSQL 16 from bundled installer (this can take a few minutes)...'
    $out = Start-Process -Wait -PassThru -FilePath $PgInstaller -ArgumentList `
        '--mode unattended', `
        '--unattendedmodeui minimal', `
        "--superpassword `"$PgAdminPassword`"", `
        '--serverport 5432', `
        '--servicename postgresql-x64-16'
    if ($out.ExitCode -ne 0) {
        Fail "PostgreSQL install failed with exit code $($out.ExitCode)."
    }
    Write-Step 'PostgreSQL 16 installed.'
}
$env:Path = "$PgBin;" + $env:Path

$PgSvcName = (Get-Service | Where-Object { $_.Name -like 'postgresql*' } | Select-Object -First 1).Name
if (-not $PgSvcName) { $PgSvcName = 'postgresql-x64-16' }
Write-Step "PostgreSQL service: $PgSvcName"

# -----------------------------------------------------------------------
# 7. NSSM (extracted from bundled zip into the install root -- not required
#    on PATH; every later step references $NssmExe explicitly)
# -----------------------------------------------------------------------
Write-Step 'Extracting NSSM...'
$NssmDir = Join-Path $InstallRoot 'nssm'
Expand-Archive -Path $NssmZip -DestinationPath $NssmDir -Force
$NssmExe = Join-Path $NssmDir 'nssm-2.24\win64\nssm.exe'
if (-not (Test-Path $NssmExe)) {
    Fail "NSSM extraction did not produce the expected binary at $NssmExe."
}
Write-Step "NSSM ready: $NssmExe"

# -----------------------------------------------------------------------
# 8. Create database + user via psql
# -----------------------------------------------------------------------
Write-Step 'Creating database and user...'

$env:PGPASSWORD = $PgAdminPassword

$out = & "$PgBin\psql.exe" -U postgres -h localhost -c "CREATE DATABASE secvault" 2>&1
$out | Write-Host
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
    Write-Host "[WARN] CREATE DATABASE exited with code $LASTEXITCODE (may already exist) -- continuing." -ForegroundColor Yellow
}

$createUserSql = "CREATE USER secvault_user WITH PASSWORD '$DbPassword'"
$out = & "$PgBin\psql.exe" -U postgres -h localhost -c $createUserSql 2>&1
$out | Write-Host
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
    Write-Host "[WARN] CREATE USER exited with code $LASTEXITCODE (may already exist) -- continuing." -ForegroundColor Yellow
}

$out = & "$PgBin\psql.exe" -U postgres -h localhost -c "GRANT ALL PRIVILEGES ON DATABASE secvault TO secvault_user" 2>&1
$out | Write-Host
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
    Fail "GRANT ALL PRIVILEGES failed with exit code $LASTEXITCODE."
}

Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue

Write-Step 'Database and user provisioned.'

# -----------------------------------------------------------------------
# 9. Configure .env.local
# -----------------------------------------------------------------------
Write-Step 'Configuring .env.local...'

$envExamplePath = Join-Path $repoRoot '.env.local.example'
$envLocalPath = Join-Path $repoRoot '.env.local'

if (-not (Test-Path $envExamplePath)) {
    Fail ".env.local.example not found at $envExamplePath"
}

Copy-Item -Path $envExamplePath -Destination $envLocalPath -Force

$credKeyBytes = (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes(32)
$credKey = [System.BitConverter]::ToString($credKeyBytes).Replace('-', '').ToLower()

$secretBytes = (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes(32)
$nextAuthSecret = [Convert]::ToBase64String($secretBytes)

$databaseUrl = "postgresql://secvault_user:$DbPassword@$ServerIp:5432/secvault"
$nextAuthUrl = "http://$($ServerIp):$($AppPort)"

$envContent = Get-Content -Path $envLocalPath -Raw

$envContent = $envContent -replace '(?m)^SERVER_IP=.*$', "SERVER_IP=$ServerIp"
$envContent = $envContent -replace '(?m)^APP_PORT=.*$', "APP_PORT=$AppPort"
$envContent = $envContent -replace '(?m)^DATABASE_URL=.*$', "DATABASE_URL=$databaseUrl"
$envContent = $envContent -replace '(?m)^NEXTAUTH_URL=.*$', "NEXTAUTH_URL=$nextAuthUrl"
$envContent = $envContent -replace '(?m)^NEXTAUTH_SECRET=.*$', "NEXTAUTH_SECRET=$nextAuthSecret"
$envContent = $envContent -replace '(?m)^CREDENTIAL_KEY=.*$', "CREDENTIAL_KEY=$credKey"

if ($NetVaultUrl) {
    $envContent = $envContent -replace '(?m)^NETVAULT_URL=.*$', "NETVAULT_URL=$NetVaultUrl"
}

Set-Content -Path $envLocalPath -Value $envContent -NoNewline

Write-Step ".env.local written to $envLocalPath"

# -----------------------------------------------------------------------
# 10. npm ci
# -----------------------------------------------------------------------
Write-Step 'Installing dependencies (npm ci)...'

Push-Location $repoRoot
$out = & npm ci 2>&1
$out | Write-Host
if ($LASTEXITCODE -ne 0) {
    Pop-Location
    Fail "npm ci failed with exit code $LASTEXITCODE."
}
Pop-Location

# -----------------------------------------------------------------------
# 11. Run schema migration (tables -- as secvault_user, via node)
# -----------------------------------------------------------------------
Write-Step 'Running schema migration (node lib/migrate.js)...'

Push-Location $repoRoot
$out = & node lib\migrate.js 2>&1
$out | Write-Host
if ($LASTEXITCODE -ne 0) {
    Pop-Location
    Fail "Schema migration failed with exit code $LASTEXITCODE."
}
Pop-Location

# -----------------------------------------------------------------------
# 12. Apply readonly diagnostic grants (lib/schema-grants.sql -- postgres superuser)
# -----------------------------------------------------------------------
# CREATE ROLE requires superuser/CREATEROLE, which secvault_user does not have,
# so this cannot be part of lib/migrate.js -- see CLAUDE.md "Readonly Access for
# Diagnostics". Best-effort: a failure here must never fail the overall install,
# these roles are diagnostic-only and not required for the app to function.
Write-Step 'Applying readonly diagnostic grants (lib/schema-grants.sql)...'

$env:PGPASSWORD = $PgAdminPassword
$grantsPath = Join-Path $repoRoot 'lib\schema-grants.sql'
$out = & "$PgBin\psql.exe" -U postgres -h localhost -d secvault -f $grantsPath 2>&1
$out | Write-Host
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
    Write-Host "[WARN] Readonly grants script exited with code $LASTEXITCODE -- claude_readonly/nocvault_readonly may not be fully configured. This does not affect application function." -ForegroundColor Yellow
}
Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue

# -----------------------------------------------------------------------
# 13. Build
# -----------------------------------------------------------------------
Write-Step 'Building application (npm run build)...'

Push-Location $repoRoot
$out = & npm run build 2>&1
$out | Write-Host
if ($LASTEXITCODE -ne 0) {
    Pop-Location
    Fail "npm run build failed with exit code $LASTEXITCODE."
}
Pop-Location

# -----------------------------------------------------------------------
# 14. Register NSSM services
# -----------------------------------------------------------------------
Write-Step 'Registering NSSM services...'

# NOTE: casing of C:\Apps\SecVault below is deliberately kept identical
# everywhere it appears in this script -- CLAUDE.md documents an NSSM bug
# where mismatched AppEnvironmentExtra path casing silently causes duplicate
# React instances.

& $NssmExe stop SecVault-App confirm 2>&1 | Out-Null
& $NssmExe remove SecVault-App confirm 2>&1 | Out-Null

$out = & $NssmExe install SecVault-App node 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-App AppParameters "node_modules\.bin\next start -p $AppPort" 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-App AppDirectory "C:\Apps\SecVault" 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-App AppEnvironmentExtra "NODE_ENV=production" 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-App DisplayName "SecVault - Firewall Security Platform" 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-App Start SERVICE_AUTO_START 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-App DependOnService $PgSvcName 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-App AppStdout "$LogDir\app.log" 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-App AppStderr "$LogDir\app-error.log" 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-App AppRotateFiles 1 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-App AppRotateBytes 10485760 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-App AppRotateOnline 1 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-App AppRestartDelay 3000 2>&1
$out | Write-Host

& $NssmExe stop SecVault-Engine confirm 2>&1 | Out-Null
& $NssmExe remove SecVault-Engine confirm 2>&1 | Out-Null

$out = & $NssmExe install SecVault-Engine node 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-Engine AppParameters "services\engine-worker.js" 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-Engine AppDirectory "C:\Apps\SecVault" 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-Engine AppEnvironmentExtra "NODE_ENV=production" 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-Engine DisplayName "SecVault - Engine (scheduled jobs)" 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-Engine Start SERVICE_AUTO_START 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-Engine DependOnService $PgSvcName 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-Engine AppStdout "$LogDir\engine-stdout.log" 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-Engine AppStderr "$LogDir\engine-stderr.log" 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-Engine AppRotateFiles 1 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-Engine AppRotateBytes 10485760 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-Engine AppRotateOnline 1 2>&1
$out | Write-Host
$out = & $NssmExe set SecVault-Engine AppRestartDelay 3000 2>&1
$out | Write-Host

Write-Step 'NSSM services registered.'

# -----------------------------------------------------------------------
# 15. Firewall rule
# -----------------------------------------------------------------------
Write-Step 'Configuring firewall...'
$ruleName = "SecVault Port $AppPort"
if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $AppPort -Action Allow | Out-Null
}
Write-Step "Firewall rule added for port $AppPort"

# -----------------------------------------------------------------------
# 16. Start services (sc.exe only -- never Start-Service)
# -----------------------------------------------------------------------
Write-Step 'Starting services...'

$out = sc.exe start SecVault-App
$out | Write-Host

$out = sc.exe start SecVault-Engine
$out | Write-Host

# -----------------------------------------------------------------------
# 17. Success banner
# -----------------------------------------------------------------------
Write-Host ''
Write-Host '=================================================='
Write-Host ' SecVault installed successfully.'
Write-Host " URL: http://$($ServerIp):$($AppPort)"
Write-Host ' Default login: admin / changeme (change immediately via Settings)'
Write-Host '=================================================='
