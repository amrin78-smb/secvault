<#
.SYNOPSIS
    Installs SecVault: provisions the database, configures .env.local,
    builds the app, and registers the NSSM services.

.DESCRIPTION
    Written for PowerShell 5.1 (Windows Server)  -  see CLAUDE.md "PowerShell
    (PS5 compatibility)". Do not introduce PS7-only syntax:
      - No `try { cmd | Write-Host } catch {}`  -  always `$out = cmd; $out | Write-Host`.
      - No `-Parallel` on ForEach-Object, no `-TimeoutSeconds` on Test-Connection.
      - Never use `$PID` (reserved)  -  use `$procPid`.
      - Service control is `sc.exe` only  -  never Start-Service/Stop-Service/Get-Service.

.PARAMETER ServerIp
    IP address (or hostname) of this server. Used for DATABASE_URL / NEXTAUTH_URL
    and the final success banner.

.PARAMETER DbPassword
    Password to assign to the secvault_user PostgreSQL role.

.PARAMETER AppPort
    Port for the SecVault-App (Next.js) service.

.PARAMETER NetVaultUrl
    Optional. If set, NETVAULT_URL is written to .env.local for optional SSO
    federation (disabled by default  -  see CLAUDE.md "Optional Suite Integration").
#>

[CmdletBinding()]
param(
    [Parameter(Mandatory = $true)]
    [string]$ServerIp,

    [string]$DbPassword = 'NVAdmin@2026',

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

# -----------------------------------------------------------------------
# 1. Prerequisite checks
# -----------------------------------------------------------------------
Write-Step 'Checking prerequisites...'

$nodeVersion = $null
try {
    $nodeVersion = node -v
} catch {
    $nodeVersion = $null
}
if (-not $nodeVersion) {
    Fail 'Node.js is not installed or not on PATH. Install Node.js v20 before continuing.'
}
Write-Step "Node.js found: $nodeVersion"

$psqlCmd = Get-Command psql -ErrorAction SilentlyContinue
if (-not $psqlCmd) {
    Fail 'psql is not installed or not on PATH. Install PostgreSQL client tools before continuing.'
}
Write-Step "psql found: $($psqlCmd.Source)"

$nssmCmd = Get-Command nssm -ErrorAction SilentlyContinue
if (-not $nssmCmd) {
    Write-Host '[WARN] nssm was not found on PATH. Service registration (step 8) will fail unless nssm is installed before this script reaches that step.' -ForegroundColor Yellow
} else {
    Write-Step "nssm found: $($nssmCmd.Source)"
}

$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if (-not $gitCmd) {
    Write-Host '[WARN] git was not found on PATH. This is only needed for future updates via Update-SecVault.ps1, not for this install.' -ForegroundColor Yellow
} else {
    Write-Step "git found: $($gitCmd.Source)"
}

# -----------------------------------------------------------------------
# 2. Create database + user via psql
# -----------------------------------------------------------------------
Write-Step 'Creating database and user...'

# NOTE: the spec for this script only defines -DbPassword (the password to
# assign to the new secvault_user role) -- there is no parameter for the
# existing `postgres` superuser's password. 'postgres' is assumed here as the
# default local superuser password for a fresh PostgreSQL 16 install on this
# server; override this line if the real superuser password differs.
$env:PGPASSWORD = 'postgres'

$out = & psql -U postgres -h localhost -c "CREATE DATABASE secvault" 2>&1
$out | Write-Host
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
    Write-Host "[WARN] CREATE DATABASE exited with code $LASTEXITCODE (may already exist)  -  continuing." -ForegroundColor Yellow
}

$createUserSql = "CREATE USER secvault_user WITH PASSWORD '$DbPassword'"
$out = & psql -U postgres -h localhost -c $createUserSql 2>&1
$out | Write-Host
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
    Write-Host "[WARN] CREATE USER exited with code $LASTEXITCODE (may already exist)  -  continuing." -ForegroundColor Yellow
}

$out = & psql -U postgres -h localhost -c "GRANT ALL PRIVILEGES ON DATABASE secvault TO secvault_user" 2>&1
$out | Write-Host
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
    Fail "GRANT ALL PRIVILEGES failed with exit code $LASTEXITCODE."
}

Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue

Write-Step 'Database and user provisioned.'

# -----------------------------------------------------------------------
# 3. Configure .env.local
# -----------------------------------------------------------------------
Write-Step 'Configuring .env.local...'

$repoRoot = Split-Path -Parent $PSScriptRoot
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
# 4. npm ci
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
# 5. Run schema migration
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
# 5b. Apply readonly diagnostic grants (lib/schema-grants.sql)
# -----------------------------------------------------------------------
# CREATE ROLE requires superuser/CREATEROLE, which secvault_user does not have,
# so this file is NOT part of lib/migrate.js -- it must run under the postgres
# superuser, after the tables it grants SELECT on already exist. Best-effort:
# a failure here (e.g. postgres superuser password differs from the assumption
# below) must never fail the overall install -- these roles are only used for
# Claude Code / diagnostic readonly queries, not by the application itself.
Write-Step 'Applying readonly diagnostic grants (lib/schema-grants.sql)...'

$env:PGPASSWORD = 'postgres'
$grantsPath = Join-Path $repoRoot 'lib\schema-grants.sql'
$out = & psql -U postgres -h localhost -d secvault -f $grantsPath 2>&1
$out | Write-Host
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
    Write-Host "[WARN] Readonly grants script exited with code $LASTEXITCODE -- claude_readonly/nocvault_readonly may not be fully configured. This does not affect application function." -ForegroundColor Yellow
}
Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue

# -----------------------------------------------------------------------
# 6. Build
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
# 7. Create log directory
# -----------------------------------------------------------------------
Write-Step "Creating log directory at $LogDir..."
New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# -----------------------------------------------------------------------
# 8. Register NSSM services
# -----------------------------------------------------------------------
Write-Step 'Registering NSSM services...'

if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
    Fail 'nssm is required to register services and was not found on PATH. Install nssm and re-run this script (or register the services manually  -  see CLAUDE.md "NSSM Service Registration").'
}

# NOTE: casing of C:\Apps\SecVault below is deliberately kept identical
# everywhere it appears in this script  -  CLAUDE.md documents an NSSM bug
# where mismatched AppEnvironmentExtra path casing silently causes duplicate
# React instances.

$out = & nssm install SecVault-App node 2>&1
$out | Write-Host
$out = & nssm set SecVault-App AppParameters "node_modules\.bin\next start -p $AppPort" 2>&1
$out | Write-Host
$out = & nssm set SecVault-App AppDirectory "C:\Apps\SecVault" 2>&1
$out | Write-Host
$out = & nssm set SecVault-App AppEnvironmentExtra "NODE_ENV=production" 2>&1
$out | Write-Host

$out = & nssm install SecVault-Engine node 2>&1
$out | Write-Host
$out = & nssm set SecVault-Engine AppParameters "services\engine-worker.js" 2>&1
$out | Write-Host
$out = & nssm set SecVault-Engine AppDirectory "C:\Apps\SecVault" 2>&1
$out | Write-Host
$out = & nssm set SecVault-Engine AppEnvironmentExtra "NODE_ENV=production" 2>&1
$out | Write-Host

Write-Step 'NSSM services registered.'

# -----------------------------------------------------------------------
# 9. Start services (sc.exe only  -  never Start-Service)
# -----------------------------------------------------------------------
Write-Step 'Starting services...'

$out = sc.exe start SecVault-App
$out | Write-Host

$out = sc.exe start SecVault-Engine
$out | Write-Host

# -----------------------------------------------------------------------
# 10. Success banner
# -----------------------------------------------------------------------
Write-Host ''
Write-Host '=================================================='
Write-Host ' SecVault installed successfully.'
Write-Host " URL: http://$($ServerIp):$($AppPort)"
Write-Host '=================================================='
