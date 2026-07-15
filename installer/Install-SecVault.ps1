#Requires -RunAsAdministrator
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

    Note: there is deliberately no -PgAdminPassword parameter. The
    PostgreSQL `postgres` superuser password is never hardcoded and never
    supplied by a human -- it's generated fresh by this script every run
    (same pattern as NEXTAUTH_SECRET/CREDENTIAL_KEY) and persisted to
    .env.local as PG_ADMIN_PASSWORD purely for later reference; the app
    itself never uses it (it only ever connects as secvault_user). If
    PostgreSQL is already installed on this server, its password is reset
    to the freshly generated value via a temporary trust-auth window --
    see step 1d below.

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

    # Alphanumeric-only, deliberately: these get embedded in a single combined
    # -ArgumentList string passed to Start-Process for msiexec/the PostgreSQL
    # installer. '@', '#', quotes, etc. risk being mis-parsed by the child
    # process's own command-line/properties handling (BitRock-based
    # installers in particular treat '#' as a comment delimiter in some
    # internal config paths) -- silently setting a DIFFERENT actual password
    # than what this script thinks it set, with no error at install time.
    [string]$DbPassword = 'NVAdmin2026Secure',

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

# `sc.exe start`/`sc.exe stop` return as soon as the SCM accepts the
# request, not once the service has actually reached the target state --
# polling avoids racing a fixed sleep against however long this specific
# service actually takes. Read-only Get-Service polling here, not
# Start-Service/Stop-Service -- CLAUDE.md's "never use PowerShell service
# cmdlets" is about the state-changing ones (they can hang under WinRM);
# querying .Status is the same safe pattern already used to detect
# $PgSvcName elsewhere in this script.
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
# The postgres superuser password is never hardcoded and never something a
# human passes in -- generated fresh right here, every run (same reasoning
# as NEXTAUTH_SECRET/CREDENTIAL_KEY in step 10 below), alphanumeric-only
# (see the -DbPassword comment above for why). It's persisted to .env.local
# as PG_ADMIN_PASSWORD purely for later manual reference -- the app itself
# never uses it, only ever connecting as secvault_user.
# .NET Framework's RNGCryptoServiceProvider.GetBytes only has the
# GetBytes(byte[]) overload -- it fills a pre-allocated array in place and
# returns void. Passing an int (as if calling a GetBytes(count) that
# returns a new array) gets PowerShell to coerce it into a 1-element byte
# array and silently return $null -- allocate the array explicitly first.
$pgPassBytes = New-Object byte[] 24
(New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($pgPassBytes)
$PgAdminPassword = (([Convert]::ToBase64String($pgPassBytes) -replace '[^a-zA-Z0-9]', '') + 'Aa1Bb2').Substring(0, 24)
$PgDataDir = 'C:\Program Files\PostgreSQL\16\data'

$psqlCmd = Get-Command psql -ErrorAction SilentlyContinue
if (-not $psqlCmd) {
    if (Test-Path 'C:\Program Files\PostgreSQL\16\bin\psql.exe') {
        $env:Path += ';C:\Program Files\PostgreSQL\16\bin'
        $psqlCmd = Get-Command psql -ErrorAction SilentlyContinue
    }
}
$pgAlreadyInstalled = [bool]$psqlCmd
$PgInstaller = (Get-ChildItem (Join-Path $DepsDir 'postgresql-16*windows-x64.exe') -ErrorAction SilentlyContinue | Select-Object -First 1).FullName
if ($pgAlreadyInstalled) {
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

$PgSvcName = (Get-Service | Where-Object { $_.Name -like 'postgresql*' } | Select-Object -First 1).Name
if (-not $PgSvcName) { $PgSvcName = 'postgresql-x64-16' }

if ($pgAlreadyInstalled) {
    # PostgreSQL was already here -- this script did NOT just set its
    # superuser password via --superpassword, so whatever it currently is
    # doesn't matter and is never guessed at. Force it to the freshly
    # generated value above via a temporary trust-auth window in
    # pg_hba.conf, so this script is always the sole source of truth for
    # what the postgres superuser password currently is.
    Write-Step "Resetting PostgreSQL superuser password (service: $PgSvcName)..."

    $pgHbaPath = Join-Path $PgDataDir 'pg_hba.conf'
    if (-not (Test-Path $pgHbaPath)) {
        Fail "pg_hba.conf not found at $pgHbaPath -- cannot reset the superuser password automatically. If this server's PostgreSQL uses a non-default data directory, this script needs updating."
    }
    $pgHbaBackup = Join-Path $PgDataDir 'pg_hba.conf.secvault-installer-backup'
    Copy-Item -Path $pgHbaPath -Destination $pgHbaBackup -Force

    $trustRules = "host    all             all             127.0.0.1/32            trust`r`nhost    all             all             ::1/128                 trust`r`n"
    $originalHba = Get-Content -Path $pgHbaBackup -Raw
    Set-Content -Path $pgHbaPath -Value ($trustRules + $originalHba) -NoNewline

    $resetOk = $false
    try {
        Invoke-Native { sc.exe stop $PgSvcName } | Out-Null
        Wait-ServiceStatus -ServiceName $PgSvcName -Status 'Stopped' -TimeoutSeconds 30 | Out-Null
        Invoke-Native { sc.exe start $PgSvcName } | Out-Null
        if (-not (Wait-ServiceStatus -ServiceName $PgSvcName -Status 'Running' -TimeoutSeconds 30)) {
            Fail "$PgSvcName did not reach the Running state within 30s after restart -- cannot proceed with the password reset."
        }

        # Service state 'Running' and the listener actually accepting TCP
        # connections aren't quite the same instant -- retry the
        # connection a few times with a short backoff rather than a single
        # fixed sleep-then-try.
        $escapedPassword = $PgAdminPassword.Replace("'", "''")
        for ($attempt = 1; $attempt -le 5; $attempt++) {
            $out = Invoke-Native { & psql -U postgres -h 127.0.0.1 -c "ALTER USER postgres WITH PASSWORD '$escapedPassword'" 2>&1 }
            if ($LASTEXITCODE -eq 0) {
                $resetOk = $true
                break
            }
            Start-Sleep -Seconds 2
        }
        $out | Write-Host
    } finally {
        # Always restore the original pg_hba.conf and restart, whether or
        # not the reset succeeded -- never leave the server open to trust
        # auth on loopback.
        Copy-Item -Path $pgHbaBackup -Destination $pgHbaPath -Force
        Remove-Item -Path $pgHbaBackup -Force -ErrorAction SilentlyContinue
        Invoke-Native { sc.exe stop $PgSvcName } | Out-Null
        Wait-ServiceStatus -ServiceName $PgSvcName -Status 'Stopped' -TimeoutSeconds 30 | Out-Null
        Invoke-Native { sc.exe start $PgSvcName } | Out-Null
        if (-not (Wait-ServiceStatus -ServiceName $PgSvcName -Status 'Running' -TimeoutSeconds 30)) {
            Write-Host "[WARN] $PgSvcName did not report Running within 30s after the final restart -- check its status manually." -ForegroundColor Yellow
        }
    }

    if (-not $resetOk) {
        Fail "Failed to reset the existing PostgreSQL installation's superuser password via trust auth. pg_hba.conf has been restored to its original state and the service restarted -- check the psql output above for the actual error."
    }
    $env:PGPASSWORD = $PgAdminPassword
    Write-Host '    [OK] PostgreSQL superuser password reset.'
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
# as often "wrong password". In practice this specific check should never
# trigger -- step 1d already proved $PgAdminPassword authenticates before
# reaching this point -- but it's kept as a defensive safety net in case
# Postgres was somehow reconfigured in between.
$out = Invoke-Native { & "$PgBin\psql.exe" -U postgres -h localhost -c "CREATE DATABASE secvault" 2>&1 }
$out | Write-Host
if (($out -join "`n") -match 'password authentication failed') {
    Fail "PostgreSQL rejected -PgAdminPassword ('$PgAdminPassword') for the 'postgres' superuser, despite step 1d having authenticated successfully with it moments ago. Something reconfigured PostgreSQL's auth in between -- investigate before retrying."
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

# See the $pgPassBytes comment in step 1d above: GetBytes needs a
# pre-allocated array, not an int -- passing an int silently yields $null.
$credKeyBytes = New-Object byte[] 32
(New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($credKeyBytes)
$credKey = [System.BitConverter]::ToString($credKeyBytes).Replace('-', '').ToLower()

$secretBytes = New-Object byte[] 32
(New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($secretBytes)
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
$envContent = $envContent -replace '(?m)^PG_ADMIN_PASSWORD=.*$', "PG_ADMIN_PASSWORD=$PgAdminPassword"

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
