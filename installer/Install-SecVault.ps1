<#
.SYNOPSIS
    Installs SecVault: provisions all prerequisites (Git, Node.js, PostgreSQL,
    NSSM, VC++ Redistributable) from a bundled dependencies folder, configures
    SSH authentication to GitHub via a bundled deploy key, clones the private
    secvault repo, then provisions the database, configures .env.local,
    builds the app, and registers the NSSM services.

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

# PS5 converts ANY stderr output from a native executable into a
# non-terminating ErrorRecord the moment a `2>` redirection operator is
# used on it (2>&1, 2>$file, 2>$null -- the target doesn't matter, PS
# converts stderr to an ErrorRecord before routing it to that target).
# With $ErrorActionPreference = 'Stop' in effect, that ErrorRecord
# immediately becomes a script-halting NativeCommandError -- even when the
# "error" is just normal progress/notice text, not a real failure (git
# clone's "Cloning into ..." line, ssh's "successfully authenticated"
# banner, psql NOTICEs, npm warnings, nssm's "service does not exist"
# message on a first install, etc). Route every such native command
# through this so its own stderr can never halt the script; $LASTEXITCODE
# is still set normally by the underlying call for real failure detection
# at each call site.
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

Write-Host '=================================================='
Write-Host ' SecVault Installer'
Write-Host '=================================================='

$SecVaultGitUrl = 'git@github.com:amrin78-smb/secvault.git'

# The application repo is cloned into $InstallRoot itself (CLAUDE.md: "Install
# path: C:\Apps\SecVault\" IS the repo root -- unlike some other suite apps
# there is no separate "\app" subfolder). This installer is a standalone
# distributable (dependencies bundled alongside it, e.g. C:\SecVault-Installer\)
# and is NOT expected to already be sitting inside a clone of the repo -- do
# not derive $repoRoot from $PSScriptRoot.
$repoRoot = $InstallRoot
$DepsDir = Join-Path $PSScriptRoot 'dependencies'

# -----------------------------------------------------------------------
# 1. Install prerequisites from dependencies\ (idempotent: skip whatever is
#    already installed; otherwise install silently, add to PATH, verify)
# -----------------------------------------------------------------------
# Order matters: Git must be ready before the clone step below (section 3);
# Node.js, PostgreSQL, and NSSM are needed by later steps in this script.
# $VcRedist/$GitInstaller/$NodeMsi/$PgInstaller/$NssmZip are also read by
# sections 4-8 further down -- keep them defined even on the "already
# installed" branches below so those later checks never see a null path.
Write-Step 'Installing dependencies...'

# --- 1a. Visual C++ Redistributable ---
$VcRedist = Join-Path $DepsDir 'VC_redist.x64.exe'
$vcKey = 'HKLM:\SOFTWARE\Microsoft\VisualStudio\14.0\VC\Runtimes\X64'
if (Test-Path $vcKey) {
    Write-Host '    [SKIP] VC++ Redistributable already installed.'
} else {
    if (-not (Test-Path $VcRedist)) {
        Write-Host '[FAIL] dependencies\VC_redist.x64.exe not found.' -ForegroundColor Red
        exit 1
    }
    $proc = Start-Process -FilePath $VcRedist -ArgumentList '/install', '/quiet', '/norestart' -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        Write-Host "[FAIL] VC++ Redistributable installer exited with code $($proc.ExitCode)." -ForegroundColor Red
        exit 1
    }
    Write-Host '    [OK] VC++ Redistributable installed.'
}

# --- 1b. Git ---
$gitCmd = Get-Command git -ErrorAction SilentlyContinue
if (-not $gitCmd) {
    if (Test-Path 'C:\Program Files\Git\cmd\git.exe') {
        $env:Path += ';C:\Program Files\Git\cmd'
        $gitCmd = Get-Command git -ErrorAction SilentlyContinue
    }
}
$GitInstaller = Join-Path $DepsDir 'Git-2.54.0-64-bit.exe'
if ($gitCmd) {
    Write-Host "    [SKIP] Git already installed: $(& git --version)"
} else {
    $gitInstallerFile = Get-ChildItem (Join-Path $DepsDir 'Git-*.exe') -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $gitInstallerFile) {
        Write-Host '[FAIL] No Git installer found in dependencies\ (expected Git-*.exe).' -ForegroundColor Red
        exit 1
    }
    $GitInstaller = $gitInstallerFile.FullName
    $proc = Start-Process -FilePath $GitInstaller `
        -ArgumentList '/VERYSILENT /NORESTART /NOCANCEL /SUPPRESSMSGBOXES /COMPONENTS="icons,ext\reg\shellhere,assoc,assoc_sh"' `
        -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        Write-Host "[FAIL] Git installer exited with code $($proc.ExitCode)." -ForegroundColor Red
        exit 1
    }
    $env:Path += ';C:\Program Files\Git\cmd'
    Write-Host '    [OK] Git installed.'
}
if (-not (Get-Command git -ErrorAction SilentlyContinue)) {
    Write-Host '[FAIL] git is still not available after install -- cannot continue.' -ForegroundColor Red
    exit 1
}

# --- 1c. Node.js ---
$nodeCmd = Get-Command node -ErrorAction SilentlyContinue
if (-not $nodeCmd) {
    if (Test-Path 'C:\Program Files\nodejs\node.exe') {
        $env:Path += ';C:\Program Files\nodejs'
        $nodeCmd = Get-Command node -ErrorAction SilentlyContinue
    }
}
$NodeMsi = Join-Path $DepsDir 'node-v20.19.0-x64.msi'
if ($nodeCmd) {
    Write-Host "    [SKIP] Node.js already installed: $(& node -v)"
} else {
    $nodeMsiFile = Get-ChildItem (Join-Path $DepsDir 'node-*.msi') -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $nodeMsiFile) {
        Write-Host '[FAIL] No Node.js MSI found in dependencies\ (expected node-*.msi).' -ForegroundColor Red
        exit 1
    }
    $NodeMsi = $nodeMsiFile.FullName
    $proc = Start-Process -FilePath 'msiexec' -ArgumentList "/i `"$NodeMsi`" /qn /norestart ADDLOCAL=ALL" -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        Write-Host "[FAIL] Node.js installer exited with code $($proc.ExitCode)." -ForegroundColor Red
        exit 1
    }
    $env:Path += ';C:\Program Files\nodejs'
    Write-Host '    [OK] Node.js installed.'
}
if (-not (Get-Command node -ErrorAction SilentlyContinue) -or -not (Get-Command npm -ErrorAction SilentlyContinue)) {
    Write-Host '[FAIL] node/npm still not available after install -- cannot continue.' -ForegroundColor Red
    exit 1
}

# --- 1d. PostgreSQL ---
# Uses $PgAdminPassword (the script's own -PgAdminPassword parameter, already
# defined above) for --superpassword/--servicepassword/PGPASSWORD -- NOT a
# hardcoded literal -- so it stays the same value sections 9/13 further down
# use for every `psql -U postgres` call. A hardcoded password here would
# silently mismatch those and break the whole install on a fresh server.
$psqlCmd = Get-Command psql -ErrorAction SilentlyContinue
if (-not $psqlCmd) {
    if (Test-Path 'C:\Program Files\PostgreSQL\16\bin\psql.exe') {
        $env:Path += ';C:\Program Files\PostgreSQL\16\bin'
        $psqlCmd = Get-Command psql -ErrorAction SilentlyContinue
    }
}
$PgInstaller = (Get-ChildItem (Join-Path $DepsDir 'postgresql-16*windows-x64.exe') -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
if ($psqlCmd) {
    Write-Host "    [SKIP] PostgreSQL already installed: $(& psql --version)"
} else {
    $pgInstallerFile = Get-ChildItem (Join-Path $DepsDir 'postgresql-*.exe') -ErrorAction SilentlyContinue | Select-Object -First 1
    if (-not $pgInstallerFile) {
        Write-Host '[FAIL] No PostgreSQL installer found in dependencies\ (expected postgresql-*.exe).' -ForegroundColor Red
        exit 1
    }
    $PgInstaller = $pgInstallerFile.FullName
    $proc = Start-Process -FilePath $PgInstaller `
        -ArgumentList "--mode unattended --unattendedmodeui none --superpassword `"$PgAdminPassword`" --servicename postgresql-x64-16 --servicepassword `"$PgAdminPassword`" --install_runtimes 0" `
        -NoNewWindow -Wait -PassThru
    if ($proc.ExitCode -ne 0 -and $proc.ExitCode -ne 3010) {
        Write-Host "[FAIL] PostgreSQL installer exited with code $($proc.ExitCode)." -ForegroundColor Red
        exit 1
    }
    $env:Path += ';C:\Program Files\PostgreSQL\16\bin'
    Write-Host '    [OK] PostgreSQL installed.'
}
$env:PGPASSWORD = $PgAdminPassword
if (-not (Get-Command psql -ErrorAction SilentlyContinue)) {
    Write-Host '[FAIL] psql still not available after install -- cannot continue.' -ForegroundColor Red
    exit 1
}

# If PostgreSQL was already installed here (the [SKIP] branch above -- this
# script did not just set its superuser password), -PgAdminPassword is only
# a guess: the real password was set whenever Postgres was FIRST installed
# on this server, by whatever installed it. Probe known candidates and
# adopt whichever one actually authenticates, instead of ploughing ahead
# with a guess and failing confusingly three separate psql calls later.
# 'NocV@ult_Pg#2026' is the NocVault Suite installer's own PostgreSQL
# superuser default -- worth trying since PostgreSQL is a single shared
# instance per server and this box may have had the suite installed first.
$pgPasswordCandidates = @($PgAdminPassword, 'NocV@ult_Pg#2026') | Select-Object -Unique
$pgAuthOk = $false
foreach ($candidate in $pgPasswordCandidates) {
    $env:PGPASSWORD = $candidate
    $testOut = Invoke-Native { & psql -U postgres -h localhost -c 'SELECT 1' 2>&1 }
    if ($LASTEXITCODE -eq 0) {
        if ($candidate -ne $PgAdminPassword) {
            Write-Host "    [OK] Authenticated to the existing PostgreSQL instance using a fallback candidate password -- this server's postgres superuser password was set by an earlier install, not by -PgAdminPassword."
        }
        $PgAdminPassword = $candidate
        $pgAuthOk = $true
        break
    }
}
if (-not $pgAuthOk) {
    Fail @"
Could not authenticate to PostgreSQL as the 'postgres' superuser with any known
candidate password (tried -PgAdminPassword '$($pgPasswordCandidates[0])' and the
NocVault Suite's default). PostgreSQL was already installed on this server (step
1d skipped a fresh install), so its actual superuser password was set whenever it
was FIRST installed here. Re-run with the correct password: -PgAdminPassword
'<actual password>', or reset it manually (e.g. via a temporary trust connection
in pg_hba.conf) before retrying.
"@
}

# --- 1e. NSSM ---
$NssmZip = (Get-ChildItem (Join-Path $DepsDir 'nssm-*.zip') -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
if (-not $NssmZip) {
    Write-Host '[FAIL] No NSSM zip found in dependencies\ (expected nssm-*.zip).' -ForegroundColor Red
    exit 1
}
$nssmCmd = Get-Command nssm -ErrorAction SilentlyContinue
if (-not $nssmCmd) {
    if (Test-Path 'C:\Windows\System32\nssm.exe') {
        $nssmCmd = Get-Item 'C:\Windows\System32\nssm.exe'
    }
}
if ($nssmCmd) {
    Write-Host '    [SKIP] NSSM already installed.'
} else {
    $nssmTemp = Join-Path $env:TEMP 'nssm-extract'
    Expand-Archive -Path $NssmZip -DestinationPath $nssmTemp -Force
    $nssmExtracted = Get-ChildItem $nssmTemp -Recurse -Filter 'nssm.exe' | Where-Object { $_.FullName -like '*win64*' } | Select-Object -First 1
    if (-not $nssmExtracted) {
        Write-Host '[FAIL] nssm.exe not found inside the extracted NSSM zip (expected a win64 subfolder).' -ForegroundColor Red
        exit 1
    }
    Copy-Item -Path $nssmExtracted.FullName -Destination 'C:\Windows\System32\nssm.exe' -Force
    Remove-Item $nssmTemp -Recurse -Force -ErrorAction SilentlyContinue
    Write-Host '    [OK] NSSM installed.'
}
if (-not (Get-Command nssm -ErrorAction SilentlyContinue)) {
    Write-Host '[FAIL] nssm still not available after install -- cannot continue.' -ForegroundColor Red
    exit 1
}

# -----------------------------------------------------------------------
# 2. Configure SSH authentication for GitHub (deploy key)
# -----------------------------------------------------------------------
# secvault is a private repo -- git clone (below) and every future
# git pull (Update-SecVault.ps1) must authenticate non-interactively on
# this server. Uses a deploy key bundled with the installer package
# rather than relying on a credential the target machine may not have.
Write-Step 'Configuring SSH deploy key for GitHub...'

$DeployKeySource = Join-Path $DepsDir 'secvault_deploy'
if (-not (Test-Path $DeployKeySource)) {
    Write-Host '[FAIL] dependencies\secvault_deploy not found.' -ForegroundColor Red
    Write-Host '       Obtain the SecVault deploy private key and place it at:' -ForegroundColor Red
    Write-Host "         $DeployKeySource" -ForegroundColor Red
    Write-Host '       (ed25519 private key, no passphrase, no file extension -- see' -ForegroundColor Red
    Write-Host '       github.com -> amrin78-smb/secvault -> Settings -> Deploy keys)' -ForegroundColor Red
    exit 1
}
Write-Host '    [OK] Deploy key found in dependencies\.'

$sshDir = Join-Path $env:USERPROFILE '.ssh'
if (-not (Test-Path $sshDir)) {
    New-Item -ItemType Directory -Force -Path $sshDir | Out-Null
    Write-Host "    [OK] Created $sshDir"
} else {
    Write-Host "    [OK] $sshDir already exists."
}

$deployKeyDest = Join-Path $sshDir 'secvault_deploy'
if (Test-Path $deployKeyDest) {
    $out = Invoke-Native { icacls $deployKeyDest /reset 2>&1 }
}
Copy-Item -Path $DeployKeySource -Destination $deployKeyDest -Force
Write-Host "    [OK] Deploy key copied to $deployKeyDest"

# SSH refuses to use a private key with loose permissions -- lock it down
# to read-only for the current user, inheritance removed.
$out = Invoke-Native { icacls $deployKeyDest /inheritance:r /grant:r "${env:USERNAME}:R" 2>&1 }
$out | Write-Host
if ($LASTEXITCODE -ne 0) {
    Write-Host "[WARN] icacls exited with code $LASTEXITCODE while locking down $deployKeyDest -- ssh may refuse this key as a result." -ForegroundColor Yellow
} else {
    Write-Host "    [OK] Permissions locked down on $deployKeyDest (read-only, $env:USERNAME only)."
}

# SSH config: pin github.com to this key. IdentityFile must be an absolute
# path -- ssh does not resolve relative paths in config. accept-new (not
# `no`) accepts the host key on first connection and verifies the
# fingerprint on every connection after that -- better security than
# StrictHostKeyChecking=no for a security product.
$sshConfigPath = Join-Path $sshDir 'config'
$sshConfigEntry = @"
Host github.com
    IdentityFile $deployKeyDest
    StrictHostKeyChecking accept-new
    IdentitiesOnly yes
"@

$needsConfigEntry = $true
if (Test-Path $sshConfigPath) {
    $existingConfig = Get-Content -Path $sshConfigPath -Raw
    if ($existingConfig -and $existingConfig.Contains($deployKeyDest)) {
        $needsConfigEntry = $false
    }
}
if ($needsConfigEntry) {
    Add-Content -Path $sshConfigPath -Value "`n$sshConfigEntry"
    Write-Host "    [OK] SSH config entry added to $sshConfigPath"
} else {
    Write-Host "    [OK] SSH config already references $deployKeyDest -- skipping."
}

# Pre-seed GitHub's host key into known_hosts so the clone below is fully
# non-interactive. Uses ssh-keyscan (not a hardcoded key) so a future
# GitHub host key rotation is picked up automatically instead of this
# script silently trusting a stale key forever.
$knownHostsPath = Join-Path $sshDir 'known_hosts'
$hasGithubHostKey = $false
if (Test-Path $knownHostsPath) {
    $existingKnownHosts = Get-Content -Path $knownHostsPath -Raw -ErrorAction SilentlyContinue
    if ($existingKnownHosts -and $existingKnownHosts -match 'github\.com') {
        $hasGithubHostKey = $true
    }
}
if ($hasGithubHostKey) {
    Write-Host '    [OK] github.com already present in known_hosts -- skipping ssh-keyscan.'
} else {
    $out = Invoke-Native { ssh-keyscan -t ed25519 github.com 2>$null }
    if (-not $out) {
        Write-Host '[WARN] ssh-keyscan could not reach github.com (no network yet?) -- continuing. StrictHostKeyChecking accept-new will verify/accept the host key on the first real connection instead.' -ForegroundColor Yellow
    } else {
        Add-Content -Path $knownHostsPath -Value $out
        Write-Host '    [OK] github.com ED25519 host key added to known_hosts.'
    }
}

# Verify the key actually authenticates before attempting to clone --
# fail clearly now rather than letting `git clone` fail with a more
# confusing generic permission-denied error later.
#
# GitHub's -T handshake always writes "successfully authenticated" to
# stderr (never stdout), even on success. In PS5, stderr from a native
# executable creates error objects in the pipeline regardless of where
# it's redirected to (even `2>$tmpFile` doesn't avoid this -- PowerShell
# intercepts stderr before the redirection applies), and those surface as
# a NativeCommandError under $ErrorActionPreference = 'Stop', halting the
# script. Start-Process avoids this entirely: it runs the executable
# outside the PowerShell pipeline, so stdout/stderr go straight to the
# redirected files with no error-object involvement at all.
Write-Step 'Testing SSH authentication against GitHub...'
$tmpOut = [System.IO.Path]::GetTempFileName()
$tmpErr = [System.IO.Path]::GetTempFileName()
$proc = Start-Process -FilePath 'ssh' `
    -ArgumentList '-i', $deployKeyDest, '-T', 'git@github.com' `
    -RedirectStandardOutput $tmpOut `
    -RedirectStandardError $tmpErr `
    -NoNewWindow -Wait -PassThru
$sshTest = (Get-Content $tmpErr -Raw -ErrorAction SilentlyContinue) +
           (Get-Content $tmpOut -Raw -ErrorAction SilentlyContinue)
Remove-Item $tmpOut, $tmpErr -Force -ErrorAction SilentlyContinue
$sshTest | Write-Host
if ($sshTest -notmatch 'successfully authenticated') {
    Write-Host '[FAIL] SSH authentication to github.com did not succeed.' -ForegroundColor Red
    Write-Host '       Ensure the deploy key public key is added to github.com -> amrin78-smb/secvault -> Settings -> Deploy keys' -ForegroundColor Red
    exit 1
}
Write-Host '    [OK] SSH authentication succeeded.'

# -----------------------------------------------------------------------
# 3. Clone (or verify) the SecVault application repo into $InstallRoot
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
    $out = Invoke-Native { & git clone $SecVaultGitUrl $InstallRoot 2>&1 }
    $out | Write-Host
    if ($LASTEXITCODE -ne 0) {
        Fail "git clone failed with exit code $LASTEXITCODE. SSH authentication just succeeded above, so this is most likely a network issue reaching github.com -- check connectivity and retry."
    }
    # Mark the repo safe for the SYSTEM account (services/update jobs may run
    # git as SYSTEM) -- same reasoning as the NocVault suite installer.
    Invoke-Native { & git config --system --add safe.directory ($InstallRoot -replace '\\', '/') 2>$null } | Out-Null
    Write-Step 'SecVault cloned.'
}

New-Item -ItemType Directory -Force -Path $LogDir | Out-Null

# -----------------------------------------------------------------------
# 4. Visual C++ Redistributable (silent, best-effort)
# -----------------------------------------------------------------------
Write-Step 'Installing Visual C++ Redistributable...'
if (Test-Path $VcRedist) {
    $out = Start-Process -Wait -PassThru -FilePath $VcRedist -ArgumentList '/install', '/quiet', '/norestart'
    Write-Step "VC++ Redistributable installer exited with code $($out.ExitCode) (0 or 3010 = success; 3010 = reboot recommended, not required)."
} else {
    Write-Host '[WARN] VC_redist.x64.exe not present -- skipping.' -ForegroundColor Yellow
}

# -----------------------------------------------------------------------
# 5. Node.js v20 (from bundled MSI, skip if already installed)
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
# 6. Git (from bundled installer, skip if already installed)
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
# 7. PostgreSQL 16 (from bundled installer, skip if already installed)
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
# 8. NSSM (extracted from bundled zip into the install root -- not required
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
# 9. Create database + user via psql
# -----------------------------------------------------------------------
Write-Step 'Creating database and user...'

$env:PGPASSWORD = $PgAdminPassword

# A nonzero psql exit code here isn't always "already exists" -- it's just
# as often "wrong -PgAdminPassword", which used to get silently lumped in
# with the harmless case and produce three confusing, misleading warnings
# before failing on GRANT with no real explanation. If PostgreSQL was
# already installed on this server (step 1d skipped a fresh install), its
# superuser password was set whenever it was FIRST installed here -- not
# necessarily the current -PgAdminPassword default -- so check for this
# specific failure and fail immediately with an actionable message instead
# of repeating the same wrong password two more times.
$out = Invoke-Native { & "$PgBin\psql.exe" -U postgres -h localhost -c "CREATE DATABASE secvault" 2>&1 }
$out | Write-Host
if (($out -join "`n") -match 'password authentication failed') {
    Fail @"
PostgreSQL rejected -PgAdminPassword ('$PgAdminPassword') for the 'postgres' superuser.
PostgreSQL was already installed on this server (step 1d skipped a fresh install), so its
superuser password was set whenever it was FIRST installed here, not necessarily the current
-PgAdminPassword default. Re-run with the actual password: -PgAdminPassword '<actual password>'.
If this server previously had the NocVault Suite installed, its installer's default PostgreSQL
superuser password is 'NocV@ult_Pg#2026' -- try that first. If the real password is unknown,
reset it manually (e.g. via a temporary trust connection in pg_hba.conf) before retrying.
"@
}
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
    Write-Host "[WARN] CREATE DATABASE exited with code $LASTEXITCODE (may already exist) -- continuing." -ForegroundColor Yellow
}

$createUserSql = "CREATE USER secvault_user WITH PASSWORD '$DbPassword'"
$out = Invoke-Native { & "$PgBin\psql.exe" -U postgres -h localhost -c $createUserSql 2>&1 }
$out | Write-Host
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
    Write-Host "[WARN] CREATE USER exited with code $LASTEXITCODE (may already exist) -- continuing." -ForegroundColor Yellow
}

$out = Invoke-Native { & "$PgBin\psql.exe" -U postgres -h localhost -c "GRANT ALL PRIVILEGES ON DATABASE secvault TO secvault_user" 2>&1 }
$out | Write-Host
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
    Fail "GRANT ALL PRIVILEGES failed with exit code $LASTEXITCODE."
}

Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue

Write-Step 'Database and user provisioned.'

# -----------------------------------------------------------------------
# 10. Configure .env.local
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
# 11. npm ci
# -----------------------------------------------------------------------
Write-Step 'Installing dependencies (npm ci)...'

Push-Location $repoRoot
$out = Invoke-Native { & npm ci 2>&1 }
$out | Write-Host
if ($LASTEXITCODE -ne 0) {
    Pop-Location
    Fail "npm ci failed with exit code $LASTEXITCODE."
}
Pop-Location

# -----------------------------------------------------------------------
# 12. Run schema migration (tables -- as secvault_user, via node)
# -----------------------------------------------------------------------
Write-Step 'Running schema migration (node lib/migrate.js)...'

Push-Location $repoRoot
$out = Invoke-Native { & node lib\migrate.js 2>&1 }
$out | Write-Host
if ($LASTEXITCODE -ne 0) {
    Pop-Location
    Fail "Schema migration failed with exit code $LASTEXITCODE."
}
Pop-Location

# -----------------------------------------------------------------------
# 13. Apply readonly diagnostic grants (lib/schema-grants.sql -- postgres superuser)
# -----------------------------------------------------------------------
# CREATE ROLE requires superuser/CREATEROLE, which secvault_user does not have,
# so this cannot be part of lib/migrate.js -- see CLAUDE.md "Readonly Access for
# Diagnostics". Best-effort: a failure here must never fail the overall install,
# these roles are diagnostic-only and not required for the app to function.
Write-Step 'Applying readonly diagnostic grants (lib/schema-grants.sql)...'

$env:PGPASSWORD = $PgAdminPassword
$grantsPath = Join-Path $repoRoot 'lib\schema-grants.sql'
$out = Invoke-Native { & "$PgBin\psql.exe" -U postgres -h localhost -d secvault -f $grantsPath 2>&1 }
$out | Write-Host
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
    Write-Host "[WARN] Readonly grants script exited with code $LASTEXITCODE -- claude_readonly/nocvault_readonly may not be fully configured. This does not affect application function." -ForegroundColor Yellow
}
Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue

# -----------------------------------------------------------------------
# 14. Build
# -----------------------------------------------------------------------
Write-Step 'Building application (npm run build)...'

Push-Location $repoRoot
$out = Invoke-Native { & npm run build 2>&1 }
$out | Write-Host
if ($LASTEXITCODE -ne 0) {
    Pop-Location
    Fail "npm run build failed with exit code $LASTEXITCODE."
}
Pop-Location

# -----------------------------------------------------------------------
# 15. Register NSSM services
# -----------------------------------------------------------------------
Write-Step 'Registering NSSM services...'

# NOTE: casing of C:\Apps\SecVault below is deliberately kept identical
# everywhere it appears in this script -- CLAUDE.md documents an NSSM bug
# where mismatched AppEnvironmentExtra path casing silently causes duplicate
# React instances.

Invoke-Native { & $NssmExe stop SecVault-App confirm 2>&1 } | Out-Null
Invoke-Native { & $NssmExe remove SecVault-App confirm 2>&1 } | Out-Null

$out = Invoke-Native { & $NssmExe install SecVault-App node 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-App AppParameters "node_modules\.bin\next start -p $AppPort" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-App AppDirectory "C:\Apps\SecVault" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-App AppEnvironmentExtra "NODE_ENV=production" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-App DisplayName "SecVault - Firewall Security Platform" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-App Start SERVICE_AUTO_START 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-App DependOnService $PgSvcName 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-App AppStdout "$LogDir\app.log" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-App AppStderr "$LogDir\app-error.log" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-App AppRotateFiles 1 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-App AppRotateBytes 10485760 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-App AppRotateOnline 1 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-App AppRestartDelay 3000 2>&1 }
$out | Write-Host

Invoke-Native { & $NssmExe stop SecVault-Engine confirm 2>&1 } | Out-Null
Invoke-Native { & $NssmExe remove SecVault-Engine confirm 2>&1 } | Out-Null

$out = Invoke-Native { & $NssmExe install SecVault-Engine node 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Engine AppParameters "services\engine-worker.js" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Engine AppDirectory "C:\Apps\SecVault" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Engine AppEnvironmentExtra "NODE_ENV=production" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Engine DisplayName "SecVault - Engine (scheduled jobs)" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Engine Start SERVICE_AUTO_START 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Engine DependOnService $PgSvcName 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Engine AppStdout "$LogDir\engine-stdout.log" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Engine AppStderr "$LogDir\engine-stderr.log" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Engine AppRotateFiles 1 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Engine AppRotateBytes 10485760 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Engine AppRotateOnline 1 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Engine AppRestartDelay 3000 2>&1 }
$out | Write-Host

Write-Step 'NSSM services registered.'

# -----------------------------------------------------------------------
# 16. Firewall rule
# -----------------------------------------------------------------------
Write-Step 'Configuring firewall...'
$ruleName = "SecVault Port $AppPort"
if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $AppPort -Action Allow | Out-Null
}
Write-Step "Firewall rule added for port $AppPort"

# -----------------------------------------------------------------------
# 17. Start services (sc.exe only -- never Start-Service)
# -----------------------------------------------------------------------
Write-Step 'Starting services...'

$out = sc.exe start SecVault-App
$out | Write-Host

$out = sc.exe start SecVault-Engine
$out | Write-Host

# -----------------------------------------------------------------------
# 18. Success banner
# -----------------------------------------------------------------------
Write-Host ''
Write-Host '=================================================='
Write-Host ' SecVault installed successfully.'
Write-Host " URL: http://$($ServerIp):$($AppPort)"
Write-Host ' Default login: admin / changeme (change immediately via Settings)'
Write-Host '=================================================='
