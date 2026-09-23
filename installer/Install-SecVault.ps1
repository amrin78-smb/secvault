#Requires -RunAsAdministrator
<#
.SYNOPSIS
    Installs SecVault: provisions all prerequisites (Git, Node.js, PostgreSQL,
    NSSM, VC++ Redistributable) from a bundled dependencies folder, configures
    SSH authentication to GitHub via a bundled deploy key, clones the private
    secvault repo, then provisions the database, configures .env.local,
    builds the app, and registers the NSSM services.

    ⛔ THIS SERVER MUST HAVE INTERNET ACCESS. The PREREQUISITES are bundled
    and install offline, but the APPLICATION is cloned from GitHub and its
    dependencies come from the npm registry. That requirement is checked FIRST,
    before anything is installed, so an air-gapped server is told at once
    rather than after PostgreSQL, Node, Git and NSSM are already on it.

.DESCRIPTION
    Written for PowerShell 5.1 (Windows Server) -- see CLAUDE.md "PowerShell
    (PS5 compatibility)". Do not introduce PS7-only syntax:
      - No `try { cmd | Write-Host } catch {}` -- always `$out = cmd; $out | Write-Host`.
      - No `-Parallel` on ForEach-Object, no `-TimeoutSeconds` on Test-Connection.
      - Never use `$PID` (reserved) -- use `$procPid`.
      - Service state changes are `sc.exe` only -- never Start-Service/Stop-Service
        (they can hang a WinRM session). Read-only Get-Service polling (`.Status`
        checks only, e.g. Wait-ServiceStatus below) is fine and used deliberately --
        it doesn't change service state and doesn't carry that hang risk.

    Follows the same bundled-dependencies convention as the NocVault suite
    installer (Install-NocVault-Suite.ps1): required prerequisite installers
    live in a `dependencies\` folder next to this script, are installed
    silently/unattended from those local files (no internet download required
    for prerequisites), and are skipped if the tool is already present on the
    server. See `installer\dependencies\README.txt` for exactly what to place
    there before running this script.

.PARAMETER ServerIp
    Optional. The address a BROWSER uses to reach the console -- it goes into
    NEXTAUTH_URL, the certificate SAN and the closing banner. Blank means
    detect it from the default-route interface and offer it for confirmation.
    ⛔ It is NOT the database host: DATABASE_URL is always loopback.

.PARAMETER AcceptServerIp
    Accept a -ServerIp that is not an address on this machine, without the
    confirmation prompt. For a server behind NAT, or one whose address is
    added later.

.PARAMETER SkipConnectivityCheck
    Skip the raw TCP reachability PROBE -- never the internet requirement
    itself. Only for a proxied network where the probe fails while git and npm
    themselves work.

.PARAMETER Unattended
    Answer every prompt from its default. For a scripted or imaged deployment.

.PARAMETER DbPassword
    Password to assign to the secvault_user PostgreSQL role.

    Note: there is deliberately no -PgAdminPassword parameter. The
    PostgreSQL `postgres` superuser password is never hardcoded and never
    supplied by a human -- it's generated fresh by this script every run
    (same pattern as NEXTAUTH_SECRET/CREDENTIAL_KEY) and persisted to
    .env.local as PG_ADMIN_PASSWORD; the SecVault APP itself never uses it
    (it only ever connects as secvault_user) -- it's read back only by
    Update-SecVault.ps1, to reapply lib\schema-grants.sql non-interactively
    on every update (see CLAUDE.md "Schema Migration"). If PostgreSQL is
    already installed on this server, its password is reset to the freshly
    generated value via a temporary trust-auth window -- see step 1d below.

.PARAMETER AppPort
    Port for the SecVault-App (Next.js) service.

.PARAMETER EnableTls
    Mint a self-signed certificate and bring the console up on HTTPS (default
    $true). The PORT DOES NOT CHANGE -- the console is still reached on
    -AppPort, it is simply TLS there -- so nothing an operator has written down
    stops working. Pass -EnableTls $false to install on plain HTTP.

    Note this is a FRESH-INSTALL default only. Update-SecVault.ps1 deliberately
    never switches an existing installation's transport on its own; it acts on
    the ENABLE_TLS=true this script writes.

.PARAMETER HttpRedirectPort
    Plain-HTTP listener that answers with a 301 to the https console. Only used
    when -EnableTls is on.

.PARAMETER NetVaultUrl
    Optional. If set, NETVAULT_URL is written to .env.local for optional SSO
    federation (disabled by default -- see CLAUDE.md "Optional Suite Integration").
#>

[CmdletBinding()]
param(
    # The address a BROWSER will use to reach this console. Blank = detect it.
    #
    # ⛔ NOT Mandatory, AND THE REASON IS A REAL FIRST-INSTALL FAILURE.
    # PowerShell's own mandatory-parameter prompt is a bare
    #   "Supply values for the following parameters: ServerIp:"
    # with no explanation, no default, no list of this machine's addresses and
    # no validation. On the first genuine fresh-install test it took a
    # one-digit typo -- 192.168.21.230 for a machine whose address is
    # 192.168.31.230 -- and nothing rejected it. That value goes into
    # NEXTAUTH_URL, so the install COMPLETES and then every sign-in bounces
    # back to the login page with no error anywhere (CLAUDE.md documents that
    # exact symptom), leaving the console unreachable by the person who just
    # installed it. Settings -> Console address exists to repair this, and it
    # is behind the sign-in that is broken.
    #
    # ⛔ THE DATABASE IS NOT AFFECTED -- DATABASE_URL is loopback by design.
    # This value is ONLY the console's address.
    [string]$ServerIp = '',

    # Skip the confirmation when -ServerIp is not an address on this machine.
    # ⛔ A wrong address is not refused outright: a server behind NAT, or one
    # whose address is added later, is a real shape. It is CONFIRMED instead --
    # the same call the console-address setting makes in the app (409 +
    # needsConfirmation rather than a refusal).
    [switch]$AcceptServerIp,

    # Skip the raw TCP reachability PROBE, never the requirement itself. Only
    # for a proxied network where the probe fails but git and npm work.
    [switch]$SkipConnectivityCheck,

    # Answer every prompt from defaults. For a scripted/imaged deployment.
    [switch]$Unattended,

    # Alphanumeric-only, deliberately: these get embedded in a single combined
    # -ArgumentList string passed to Start-Process for msiexec/the PostgreSQL
    # installer. '@', '#', quotes, etc. risk being mis-parsed by the child
    # process's own command-line/properties handling (BitRock-based
    # installers in particular treat '#' as a comment delimiter in some
    # internal config paths) -- silently setting a DIFFERENT actual password
    # than what this script thinks it set, with no error at install time.
    #
    # ⛔ THE "ALPHANUMERIC-ONLY" RULE ABOVE WAS DOCUMENTED AND NOT ENFORCED,
    # and both ways of breaking it fail SILENTLY rather than loudly:
    #   - a single quote ends the string literal in
    #     "CREATE USER secvault_user WITH PASSWORD '$DbPassword'", so the
    #     statement errors, the step only WARNS ("may already exist") and
    #     continues, and the install proceeds with a role whose password is
    #     not what DATABASE_URL says it is;
    #   - '$&' / '$`' / '$+' are .NET regex SUBSTITUTIONS in the replacement
    #     half of -replace, so the value written into .env.local would differ
    #     from the value handed to PostgreSQL.
    # Refuse it at the parameter instead of discovering it at first login.
    [ValidatePattern('^[A-Za-z0-9]{8,}$')]
    [string]$DbPassword = 'NVAdmin2026Secure',

    [int]$AppPort = 3010,

    # Durable spool for the syslog collector. Written and fsync-ed BEFORE
    # each DB insert and replayed on restart, so it must be on a volume that
    # exists and has room. Defaults under the install root; point it at a
    # data volume on busy fleets (this one runs ~1,400 events/sec).
    [string]$SpoolDir = 'C:\Apps\SecVault\spool',

    # Syslog listener ports. A LIST, because ManageEngine Firewall Analyzer
    # -- which SecVault replaced on the reference deployment -- listened on
    # BOTH, and most firewalls in that fleet were configured to 1514. A
    # collector bound only to 514 receives almost nothing and reports itself
    # perfectly healthy while doing so.
    [string]$SyslogPorts = '514,1514',

    # TLS on by default for NEW installations. See the .PARAMETER block above:
    # the port is unchanged, so this is a transport upgrade, not a move.
    [bool]$EnableTls = $true,

    [int]$HttpRedirectPort = 3080,

    [string]$NetVaultUrl = ''
)

$ErrorActionPreference = 'Stop'

$InstallRoot = 'C:\Apps\SecVault'
$LogDir = 'C:\Apps\SecVault\logs'

# ⛔ THE DATABASE HOST IS LOOPBACK, NOT -ServerIp, AND THAT IS A FRESH-INSTALL
# CORRECTNESS FIX, NOT A PREFERENCE. DATABASE_URL used to be written as
# postgresql://secvault_user:...@<ServerIp>:5432/secvault. All three services
# run on THIS machine, so a connection to the box's own LAN address leaves and
# re-enters through the NIC and arrives at PostgreSQL with that LAN address as
# its source -- and a stock PostgreSQL pg_hba.conf permits exactly two hosts,
# 127.0.0.1/32 and ::1/128. Nothing in this repo (verified: pg_hba appears in
# no other file) ever widens it. So on a genuinely clean server every
# connection the application makes is refused with "no pg_hba.conf entry for
# host", starting with lib/migrate.js. Loopback needs no pg_hba edit, needs no
# firewall rule, and does not expose 5432 to the network. SERVER_IP and
# NEXTAUTH_URL still carry -ServerIp: they are what a BROWSER must reach.
$DbHost = '127.0.0.1'

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
    # ⛔ $LASTEXITCODE IS STALE, NOT EMPTY, WHEN A COMMAND NEVER RAN. If the
    # executable inside $Command cannot be resolved (psql at a path that does
    # not exist on this server, npm missing from a PATH this process never
    # refreshed), PowerShell raises CommandNotFoundException -- which
    # 'Continue' above downgrades to a printed error -- and LEAVES
    # $LASTEXITCODE holding the previous command's value. That is almost
    # always 0, so every caller below reads "exit code 0" and reports the step
    # as successful when it did not happen at all: a failed read recorded as a
    # fact, the bug class CLAUDE.md names most often, in the installer.
    # Seeding 9009 (cmd.exe's own "command not found") makes the un-run case
    # fail the `-ne 0` checks at every call site instead of passing them.
    $global:LASTEXITCODE = 9009
    try {
        & $Command
    } finally {
        $ErrorActionPreference = $prevEAP
    }
}

# Upsert one KEY=VALUE inside an in-memory copy of .env.local.
#
# ⛔ THE REPLACEMENT IS LITERAL, NOT A -replace PATTERN. PowerShell's
# -replace runs the RIGHT-hand side through .NET's regex substitution engine,
# where '$&', '$`', "$'" and '$+' are all expansions -- so a password or a
# hostname containing one would write a DIFFERENT value into .env.local than
# the one this script handed to PostgreSQL, with nothing to notice it. A
# MatchEvaluator returns the string verbatim. Same shape as
# Set-SecVaultEnvValue in SecVault-Tls.ps1, kept here because .env.local is
# written in step 10, before the TLS helpers are dot-sourced.
#
# ⛔ A MISSING KEY IS APPENDED, NEVER DROPPED. -replace on a key that is not
# in the file is a silent no-op: the value simply never reaches .env.local and
# the app falls back to a default nobody chose. Appending means template drift
# (a key added to .env.local.example, or a re-run against an older file)
# degrades to a correctly-written line instead of a missing one.
function Set-EnvLine {
    param(
        [Parameter(Mandatory = $true)][string]$Text,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )
    $pattern = '(?m)^' + [regex]::Escape($Key) + '=.*$'
    $line = "$Key=$Value"
    if ($Text -match $pattern) {
        return [regex]::Replace($Text, $pattern, [System.Text.RegularExpressions.MatchEvaluator] { param($m) $line })
    }
    $sep = ''
    if (-not $Text.EndsWith("`n")) { $sep = "`r`n" }
    return $Text + $sep + $line + "`r`n"
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

# ── Console address: detect, offer, validate ─────────────────────────────
#
# ⛔ DETECTION IS BY DEFAULT ROUTE, NOT "the first IPv4 on the box".
# The NocVault suite installer does
#   Get-NetIPAddress -AddressFamily IPv4 | Where ... | Select -First 1
# and on any machine with WSL or Hyper-V that picks a VIRTUAL SWITCH: measured
# on the first SecVault test machine it returns 172.24.160.1 (WSL) in
# preference to the real 192.168.31.230. An installer that auto-fills a wrong
# answer is worse than one that asks, because nobody checks a filled field.
#
# The interface carrying the default route is the one that can actually carry
# a browser to this console, so that is the one offered.
function Get-SecVaultCandidateIps {
    $all = @(Get-NetIPAddress -AddressFamily IPv4 -ErrorAction SilentlyContinue |
        Where-Object {
            $_.IPAddress -notmatch '^(127\.|169\.254\.)' -and
            $_.PrefixOrigin -ne 'WellKnown'
        })

    # Virtual switches answer on this host and are reachable from nothing else.
    $virtualAlias = '(WSL|Hyper-V|Default Switch|vEthernet|Loopback|VirtualBox|VMware|Bluetooth|Docker)'
    $physical = @($all | Where-Object { $_.InterfaceAlias -notmatch $virtualAlias })

    $preferred = $null
    try {
        $route = Get-NetRoute -DestinationPrefix '0.0.0.0/0' -ErrorAction Stop |
            Sort-Object RouteMetric, ifMetric | Select-Object -First 1
        if ($route) {
            $preferred = ($all | Where-Object { $_.InterfaceIndex -eq $route.ifIndex } |
                Select-Object -First 1)
        }
    } catch {
        # No default route (an isolated/air-gapped server is a normal shape
        # here). Fall through to the physical-interface list.
    }

    $ordered = @()
    if ($preferred) { $ordered += $preferred }
    foreach ($a in $physical) { if (-not ($ordered | Where-Object { $_.IPAddress -eq $a.IPAddress })) { $ordered += $a } }
    foreach ($a in $all)      { if (-not ($ordered | Where-Object { $_.IPAddress -eq $a.IPAddress })) { $ordered += $a } }
    return $ordered
}

$candidates = Get-SecVaultCandidateIps
$detected = if ($candidates.Count -gt 0) { $candidates[0].IPAddress } else { '' }

if (-not $ServerIp) {
    Write-Host ''
    Write-Host '  Console address' -ForegroundColor Cyan
    Write-Host '  ---------------' -ForegroundColor Cyan
    Write-Host '  The address people will type in a browser to reach SecVault.'
    Write-Host '  (The database is not affected by this -- it always uses loopback.)'
    Write-Host ''
    if ($candidates.Count -gt 0) {
        Write-Host '  Addresses found on this machine:'
        $i = 0
        foreach ($c in $candidates) {
            $i += 1
            $tag = if ($i -eq 1) { '  <- suggested (default route)' } else { '' }
            Write-Host ("    [{0}] {1,-16} {2}{3}" -f $i, $c.IPAddress, $c.InterfaceAlias, $tag)
        }
        Write-Host ''
    }
    if ($Unattended) {
        # ⛔ Unattended must never sit at a prompt nobody will answer.
        $ServerIp = $detected
        Write-Host "  Unattended: using $ServerIp"
    } else {
        $hint = if ($detected) { "[$detected]" } else { '(none detected -- type one)' }
        $answer = Read-Host "  Address, or a number from the list, or Enter for $hint"
        $answer = ($answer + '').Trim()
        if (-not $answer) {
            $ServerIp = $detected
        } elseif ($answer -match '^\d+$' -and [int]$answer -ge 1 -and [int]$answer -le $candidates.Count) {
            $ServerIp = $candidates[[int]$answer - 1].IPAddress
        } else {
            $ServerIp = $answer
        }
    }
}

if (-not $ServerIp) {
    Fail 'No console address was given and none could be detected. Re-run with -ServerIp <address>.'
}

# ⛔ VALIDATE, BECAUSE THIS IS THE FIELD THAT LOCKS PEOPLE OUT.
# An address that is not on this machine produces a NEXTAUTH_URL no browser can
# complete a sign-in against, and the repair lives behind that sign-in.
$isLocal = [bool]($candidates | Where-Object { $_.IPAddress -eq $ServerIp })
if (-not $isLocal -and $ServerIp -ne 'localhost' -and $ServerIp -notmatch '^127\.') {
    Write-Host ''
    Write-Host "  [WARN] $ServerIp is not an address on this machine." -ForegroundColor Yellow
    if ($candidates.Count -gt 0) {
        Write-Host ("         This machine answers on: {0}" -f (($candidates | ForEach-Object { $_.IPAddress }) -join ', ')) -ForegroundColor Yellow
    }
    Write-Host '         That is legitimate behind NAT or a load balancer, and it is also' -ForegroundColor Yellow
    Write-Host '         exactly what a typo looks like. If it is wrong, sign-in will fail' -ForegroundColor Yellow
    Write-Host '         with no error and the fix is behind that sign-in.' -ForegroundColor Yellow
    Write-Host ''
    if ($AcceptServerIp -or $Unattended) {
        Write-Host '         Accepted (-AcceptServerIp / -Unattended).' -ForegroundColor Yellow
    } else {
        $ok = Read-Host '         Type YES to use it anyway, or Enter to choose again'
        if ($ok -ne 'YES') {
            Fail "Stopped before changing anything. Re-run and pick an address from the list, or pass -ServerIp <address> -AcceptServerIp if $ServerIp really is correct."
        }
    }
}

$SecVaultGitUrl = 'git@github.com:amrin78-smb/secvault.git'

# The application repo is cloned into $InstallRoot itself (CLAUDE.md: "Install
# path: C:\Apps\SecVault\" IS the repo root -- unlike some other suite apps
# there is no separate "\app" subfolder). This installer is a standalone
# distributable (dependencies bundled alongside it, e.g. C:\SecVault-Installer\)
# and is NOT expected to already be sitting inside a clone of the repo -- do
# not derive $repoRoot from $PSScriptRoot.
# ── Is the application source already sitting beside this script? ────────
#
# ⛔ THIS IS THE OTHER HALF OF installer\Build-SecVaultPackage.ps1, AND IT WAS
# MISSING. That script bundles the whole source tree and node_modules into the
# setup .exe precisely so an install needs no GitHub and no npm registry -- and
# this installer went on requiring a deploy key and running `git clone`
# regardless. The packaged .exe therefore unpacked a complete, correct tree and
# then FAILED on "dependencies\secvault_deploy not found", with the source it
# needed already on disk one directory up. Found on the first real fresh-install
# run. A feature built at one end and not wired at the other is worse than one
# not started: it ships, it looks finished, and it fails at the customer.
#
# The stub runs <tree>\installer\Install-SecVault.ps1, so the tree is this
# script's parent. It is only trusted when it actually looks like SecVault --
# a package.json NAMING secvault, plus lib\schema.sql -- because copying an
# arbitrary neighbouring folder into C:\Apps\SecVault would be worse than
# cloning.
# ── Internet access is REQUIRED, and it is checked BEFORE anything is built ──
#
# ⛔ THIS INSTALLER CLONES ITS SOURCE AND RUNS `npm ci`, so a server with no
# egress cannot complete an install -- by design, decided 2026-09-23. An
# earlier build shipped the application inside the package to avoid that; it
# was dropped because a bundled tree carries no .git, so the installation could
# never update itself, and "cannot ever update" is a worse property for a
# security product than "needs internet once".
#
# ⛔ CHECKED FIRST, NOT DISCOVERED LATE. Without this the run installs
# PostgreSQL, Node, Git and NSSM -- minutes of work and real changes to the
# machine -- and only then fails at the clone or at npm ci. Finding out at the
# end what could have been known at the start is the difference between "not
# supported here" and "a half-provisioned server".
#
# ⛔ A RAW TCP PROBE, because none of the tools exist yet at this point: git
# is one of the prerequisites this step runs ahead of. Reachability is not
# authentication -- the deploy key is proven separately, later, by an actual
# ssh handshake.
function Test-SecVaultEndpoint {
    param([string]$Target, [int]$Port, [int]$TimeoutMs = 6000)
    $client = New-Object System.Net.Sockets.TcpClient
    try {
        $async = $client.BeginConnect($Target, $Port, $null, $null)
        if (-not $async.AsyncWaitHandle.WaitOne($TimeoutMs, $false)) { return $false }
        $client.EndConnect($async)
        return $true
    } catch {
        return $false
    } finally {
        $client.Close()
    }
}

Write-Step 'Checking the internet access this installer requires...'
$requiredEndpoints = @(
    @{ Host = 'github.com';          Port = 22;  Why = 'to clone the application source' },
    @{ Host = 'registry.npmjs.org';  Port = 443; Why = 'to install its dependencies (npm ci)' }
)
$unreachable = @()
foreach ($ep in $requiredEndpoints) {
    if (Test-SecVaultEndpoint -Target $ep.Host -Port $ep.Port) {
        Write-Host ("    [OK] {0}:{1} reachable -- {2}" -f $ep.Host, $ep.Port, $ep.Why)
    } else {
        $unreachable += $ep
        Write-Host ("    [FAIL] {0}:{1} NOT reachable -- needed {2}" -f $ep.Host, $ep.Port, $ep.Why) -ForegroundColor Red
    }
}
if ($unreachable.Count -gt 0) {
    if ($SkipConnectivityCheck) {
        # ⛔ The switch skips the PROBE, never the requirement. A proxy can
        # make a raw TCP test fail while git and npm work perfectly, which is
        # the only reason this exists -- it is not a way to install offline.
        Write-Host '    [WARN] -SkipConnectivityCheck was passed, so the install continues. If these are genuinely unreachable it will fail later, at the clone or at npm ci.' -ForegroundColor Yellow
    } else {
        Write-Host ''
        Write-Host '  SecVault REQUIRES internet access to install:' -ForegroundColor Red
        Write-Host '    github.com:22          the application source is cloned, not bundled' -ForegroundColor Red
        Write-Host '    registry.npmjs.org:443 npm ci installs the runtime dependencies' -ForegroundColor Red
        Write-Host ''
        Write-Host '  Nothing has been installed or changed on this machine.' -ForegroundColor Red
        Write-Host '  Open egress for the above and re-run. If a proxy makes the raw' -ForegroundColor Red
        Write-Host '  connection test fail while git and npm themselves work, re-run with' -ForegroundColor Red
        Write-Host '  -SkipConnectivityCheck.' -ForegroundColor Red
        exit 1
    }
}

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
# as PG_ADMIN_PASSWORD -- the SecVault app itself never uses it (only ever
# connecting as secvault_user), but Update-SecVault.ps1 reads it back to
# reapply lib\schema-grants.sql non-interactively on every update.
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
            if ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1) {
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
    Write-Host '       SecVault clones its source from a private repository, so this key is' -ForegroundColor Red
    Write-Host '       REQUIRED. Place the ed25519 private key (no passphrase, no extension) at:' -ForegroundColor Red
    Write-Host "         $DeployKeySource" -ForegroundColor Red
    Write-Host '       (github.com -> amrin78-smb/secvault -> Settings -> Deploy keys)' -ForegroundColor Red
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

# ⛔ Bug fixed 2026-07-19, found in a follow-up bug sweep: the deploy key
# used to be copied ONLY to $env:USERPROFILE\.ssh\ -- the profile of
# whichever admin runs this installer interactively. That's fine for a
# manual "& Update-SecVault.ps1" run by that same admin, but the in-app
# updater (Settings -> Updates -> "Update Now") schedules Update-SecVault.ps1
# as a Windows Scheduled Task running as SYSTEM, and SYSTEM's own
# $env:USERPROFILE resolves to a completely different, unrelated profile
# with no copy of this key at all -- confirmed live (see the long comment
# chain in Update-SecVault.ps1 around $deployKeyRepoRelative/
# $deployKeyUserProfile). Also copy the key to a machine-wide location under
# C:\ProgramData -- readable by any account on the box, including SYSTEM,
# by default -- so the "Update Now" path has a location it can actually
# reach regardless of which admin originally ran this installer.
# Update-SecVault.ps1 checks this path FIRST, ahead of the repo-relative and
# user-profile fallbacks that predate this fix.
$machineKeyDir = 'C:\ProgramData\SecVault\ssh'
if (-not (Test-Path $machineKeyDir)) {
    New-Item -ItemType Directory -Force -Path $machineKeyDir | Out-Null
}
$machineKeyDest = Join-Path $machineKeyDir 'secvault_deploy'
if (Test-Path $machineKeyDest) {
    $out = Invoke-Native { icacls $machineKeyDest /reset 2>&1 }
}
Copy-Item -Path $DeployKeySource -Destination $machineKeyDest -Force
# Lock down to SYSTEM + local Administrators, read-only, inheritance removed
# -- same posture as the user-profile copy above, just for the two accounts
# that actually need to read it (the scheduled task runs as SYSTEM; an
# interactive admin re-running this script or troubleshooting needs it too).
$out = Invoke-Native { icacls $machineKeyDest /inheritance:r /grant:r 'SYSTEM:R' /grant:r 'BUILTIN\Administrators:R' 2>&1 }
$out | Write-Host
if ($LASTEXITCODE -ne 0) {
    Write-Host "[WARN] icacls exited with code $LASTEXITCODE while locking down $machineKeyDest -- the SYSTEM-scheduled update path may fail to authenticate as a result." -ForegroundColor Yellow
} else {
    Write-Host "    [OK] Deploy key also placed at $machineKeyDest (SYSTEM-readable, for the in-app updater's scheduled-task path)."
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
    # ⛔ $PgInstaller comes from a NARROWER glob than step 1d used
    # ('postgresql-16*windows-x64.exe' vs 'postgresql-*.exe') and is left $null
    # when step 1d took its "already installed" branch. Start-Process with a
    # null -FilePath throws a raw ParameterBindingValidationException, which
    # under $ErrorActionPreference = 'Stop' ends the install with a .NET
    # message that says nothing about PostgreSQL. Say what is actually wrong.
    if (-not $PgInstaller) {
        Fail "PostgreSQL is not present at $PgBin and no bundled installer matching dependencies\postgresql-16*windows-x64.exe was found. Either place one there, or -- if this server already runs PostgreSQL from a different path/version -- install PostgreSQL 16 to the default location first; every psql call below is hardcoded to $PgBin."
    }
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

# ⛔ EVERY psql CALL BELOW IS "$PgBin\psql.exe", HARDCODED TO THE POSTGRESQL 16
# DEFAULT PATH. If this server runs PostgreSQL from anywhere else (a 15
# install that satisfied step 1d's PATH lookup, a non-default directory), that
# file does not exist -- and a missing executable does not fail loudly here:
# it raises CommandNotFoundException inside Invoke-Native, which runs at
# 'Continue', so the script carries on. Before the $LASTEXITCODE sentinel
# added to Invoke-Native above, every one of those steps then read the
# PREVIOUS command's exit code and reported CREATE DATABASE / CREATE USER /
# GRANT as successful against a database that was never touched. Prove the
# binary exists once, here, rather than relying on the sentinel to catch it
# five times with a less useful message each time.
if (-not (Test-Path (Join-Path $PgBin 'psql.exe'))) {
    Fail "psql.exe was not found at $PgBin. This script addresses PostgreSQL through that exact path for database creation, grants and the readonly roles. Install PostgreSQL 16 to the default location, or update `$PgBin in this script, and retry."
}

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
    Fail "PostgreSQL rejected the generated PostgreSQL superuser password for the 'postgres' superuser, despite step 1d having authenticated successfully with it moments ago. Something reconfigured PostgreSQL's auth in between -- investigate before retrying (check the psql output above)."
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

# ⛔ "MAY ALREADY EXIST" IS THE DANGEROUS HALF OF THAT WARNING. CREATE USER
# does NOTHING to an existing role's password, and DATABASE_URL further down
# is written from $DbPassword unconditionally. So on any re-run -- or on a
# cluster that already carried a secvault_user -- the connection string would
# carry a password the role does not have, and every service would fail
# authentication with an error that reads like a broken build rather than a
# wrong password. ALTER makes this script the single source of truth for the
# role's password, exactly as step 1d already does for the superuser, and it
# is FATAL rather than a warning because the value is about to be baked into
# .env.local as though it were true.
$alterUserSql = "ALTER USER secvault_user WITH PASSWORD '$DbPassword'"
$out = Invoke-Native { & "$PgBin\psql.exe" -U postgres -h localhost -c $alterUserSql 2>&1 }
$out | Write-Host
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
    Fail "ALTER USER secvault_user failed with exit code $LASTEXITCODE -- the password about to be written into DATABASE_URL would not be the role's actual password."
}

$out = Invoke-Native { & "$PgBin\psql.exe" -U postgres -h localhost -c "GRANT ALL PRIVILEGES ON DATABASE secvault TO secvault_user" 2>&1 }
$out | Write-Host
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
    Fail "GRANT ALL PRIVILEGES failed with exit code $LASTEXITCODE."
}

# GRANT ALL PRIVILEGES ON DATABASE (above) does NOT include CREATE on the
# public schema -- PostgreSQL 15+ revoked that default PUBLIC grant on the
# public schema for security, so a role that isn't the schema owner gets
# "permission denied for schema public" the moment it tries CREATE TABLE
# (exactly what lib/migrate.js does). Schema privileges are per-database,
# so this must run with -d secvault specifically, not the cluster-level
# connection above. GRANT is idempotent -- safe to run on every install.
$out = Invoke-Native { & "$PgBin\psql.exe" -U postgres -h localhost -d secvault -c "GRANT ALL ON SCHEMA public TO secvault_user" 2>&1 }
$out | Write-Host
if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
    Fail "GRANT ALL ON SCHEMA public failed with exit code $LASTEXITCODE."
}

Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue

# ⛔ PROVE THE APPLICATION'S OWN CREDENTIAL WORKS, AS THE APPLICATION'S OWN
# USER, BEFORE ANYTHING DEPENDS ON IT. Everything above authenticated as the
# POSTGRES SUPERUSER; nothing has yet shown that secvault_user can connect at
# all. The first thing that does is `node lib/migrate.js`, several minutes and
# one npm ci later, and it reports the failure as a node stack trace that says
# nothing about which of the three plausible causes it was (wrong password,
# no pg_hba entry for the host in DATABASE_URL, database not created).
$env:PGPASSWORD = $DbPassword
$out = Invoke-Native { & "$PgBin\psql.exe" -U secvault_user -h $DbHost -d secvault -c "SELECT 1" 2>&1 }
$out | Write-Host
$dbConnectOk = ($LASTEXITCODE -eq 0 -or $LASTEXITCODE -eq -1)
Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
if (-not $dbConnectOk) {
    Fail "secvault_user could not connect to the secvault database on $DbHost (psql exit code $LASTEXITCODE). This is the exact connection DATABASE_URL describes, so nothing downstream can work. Check the psql output above -- 'no pg_hba.conf entry' means PostgreSQL is not accepting connections from that address; 'password authentication failed' means the role password and -DbPassword disagree."
}
Write-Host "    [OK] secvault_user authenticated against the secvault database on $DbHost."

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

# ⛔ AN EXISTING .env.local IS NEVER OVERWRITTEN WITH THE TEMPLATE. This was
# an unconditional `Copy-Item -Force`, and step 3 above deliberately does NOT
# exit when it finds an existing deployment ("skipping clone") -- it carries
# on into this step. So re-running this installer over a working SecVault, the
# obvious thing to do after a partial failure, blanked the file and then wrote
# a FRESH CREDENTIAL_KEY over the old one. That key is the AES-256-GCM key for
# device_credentials and it exists nowhere else on the machine: every SMC API
# key and SSH password already stored becomes permanently undecryptable, with
# no error -- collection just starts failing device by device as though the
# firewalls had changed their passwords. A new NEXTAUTH_SECRET additionally
# invalidates every session, and the copy discarded every operator-set value
# in the file (retention windows, licence key, TLS paths, SMOKE_*).
#
# Fresh install: copy the template, as before. Re-run: keep the file, back it
# up, and upsert only the keys this script owns.
$envExisted = Test-Path $envLocalPath
$existingCredKey = ''
$existingNextAuthSecret = ''
if ($envExisted) {
    $envBackupPath = "$envLocalPath.pre-install-" + (Get-Date).ToString('yyyyMMdd-HHmmss')
    Copy-Item -Path $envLocalPath -Destination $envBackupPath -Force
    $existingEnvRaw = Get-Content -Path $envLocalPath -Raw
    if ($existingEnvRaw -match '(?m)^CREDENTIAL_KEY=(.*)$')  { $existingCredKey = $matches[1].Trim() }
    if ($existingEnvRaw -match '(?m)^NEXTAUTH_SECRET=(.*)$') { $existingNextAuthSecret = $matches[1].Trim() }
    Write-Host "    [OK] Existing .env.local kept in place (backed up to $envBackupPath)."
} else {
    Copy-Item -Path $envExamplePath -Destination $envLocalPath -Force
}

# See the $pgPassBytes comment in step 1d above: GetBytes needs a
# pre-allocated array, not an int -- passing an int silently yields $null.
if ($existingCredKey) {
    $credKey = $existingCredKey
    Write-Host '    [OK] Existing CREDENTIAL_KEY preserved -- stored device credentials stay decryptable.'
} else {
    $credKeyBytes = New-Object byte[] 32
    (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($credKeyBytes)
    $credKey = [System.BitConverter]::ToString($credKeyBytes).Replace('-', '').ToLower()
}

if ($existingNextAuthSecret) {
    $nextAuthSecret = $existingNextAuthSecret
    Write-Host '    [OK] Existing NEXTAUTH_SECRET preserved -- signed-in sessions survive.'
} else {
    $secretBytes = New-Object byte[] 32
    (New-Object Security.Cryptography.RNGCryptoServiceProvider).GetBytes($secretBytes)
    $nextAuthSecret = [Convert]::ToBase64String($secretBytes)
}

$databaseUrl = "postgresql://secvault_user:$DbPassword@${DbHost}:5432/secvault"
$nextAuthUrl = "http://$($ServerIp):$($AppPort)"

$envContent = Get-Content -Path $envLocalPath -Raw

$envContent = Set-EnvLine -Text $envContent -Key 'SERVER_IP'          -Value $ServerIp
$envContent = Set-EnvLine -Text $envContent -Key 'APP_PORT'           -Value "$AppPort"
$envContent = Set-EnvLine -Text $envContent -Key 'DATABASE_URL'       -Value $databaseUrl
$envContent = Set-EnvLine -Text $envContent -Key 'NEXTAUTH_URL'       -Value $nextAuthUrl
$envContent = Set-EnvLine -Text $envContent -Key 'NEXTAUTH_SECRET'    -Value $nextAuthSecret
$envContent = Set-EnvLine -Text $envContent -Key 'CREDENTIAL_KEY'     -Value $credKey
$envContent = Set-EnvLine -Text $envContent -Key 'PG_ADMIN_PASSWORD'  -Value $PgAdminPassword
$envContent = Set-EnvLine -Text $envContent -Key 'SYSLOG_SPOOL_DIR'   -Value $SpoolDir
$envContent = Set-EnvLine -Text $envContent -Key 'SYSLOG_UDP_PORT'    -Value $SyslogPorts
$envContent = Set-EnvLine -Text $envContent -Key 'SYSLOG_TCP_PORT'    -Value $SyslogPorts

if ($NetVaultUrl) {
    $envContent = Set-EnvLine -Text $envContent -Key 'NETVAULT_URL' -Value $NetVaultUrl
}

Set-Content -Path $envLocalPath -Value $envContent -NoNewline

# ⛔ VERIFY WHAT WAS ACTUALLY WRITTEN. A -replace that matches nothing is not
# an error in PowerShell -- it returns the string unchanged -- so a key that
# drifted out of .env.local.example would have been silently dropped here and
# the first symptom would be the app failing to decrypt a credential or
# NextAuth refusing to start. Set-EnvLine now appends a missing key rather
# than losing it, and this read-back proves the three secrets that cannot be
# regenerated from anywhere else are present in the file on disk.
$writtenEnv = Get-Content -Path $envLocalPath -Raw
foreach ($mustHave in @('CREDENTIAL_KEY', 'NEXTAUTH_SECRET', 'DATABASE_URL', 'PG_ADMIN_PASSWORD')) {
    if ($writtenEnv -notmatch ('(?m)^' + [regex]::Escape($mustHave) + '=\S')) {
        Fail "$mustHave is missing or empty in $envLocalPath after writing it. Refusing to continue -- an install that proceeds from here looks healthy and cannot decrypt a credential or sign anyone in."
    }
}

Write-Step ".env.local written to $envLocalPath"

# -----------------------------------------------------------------------
# 11. npm ci
# -----------------------------------------------------------------------
Write-Step 'Installing dependencies...'

# ⛔ npm ci ALWAYS RUNS, AND IT NEEDS registry.npmjs.org. An earlier build
# shipped node_modules inside the package and skipped this when a version-
# matched marker was present. That was dropped with the bundled source: the
# install is online by design now, and a skip path that can never fire is a
# guard that reads as handled and does nothing. Reachability was proven in the
# preflight above, so a failure here is a real npm failure, not a surprise.
Push-Location $repoRoot
$out = Invoke-Native { & npm ci 2>&1 }
$out | Write-Host
if ($LASTEXITCODE -ne 0) {
    Pop-Location
    Fail "npm ci failed with exit code $LASTEXITCODE. registry.npmjs.org answered the preflight check, so this is an npm or package problem rather than plain connectivity -- read the output above."
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
# 14b. TLS -- certificate, .env.local keys, service entry point
# -----------------------------------------------------------------------
# ⛔ THIS STEP USED NOT TO EXIST, AND ITS ABSENCE WAS INVISIBLE. Every other
# piece of the TLS feature was written and shipped -- installer\SecVault-Tls.ps1
# described itself as "dot-sourced by BOTH installer scripts" (it had one
# caller), and Update-SecVault.ps1's opt-in comment said "fresh installs set
# this, so new deployments are HTTPS by default" (nothing set it). So a new
# customer got plain HTTP, on a firewall-management console, with no route to
# HTTPS except hand-editing .env.local -- while both scripts' comments asserted
# the opposite. Two true-sounding sentences and no code.
#
# ⛔ THE PORT DOES NOT CHANGE. HTTPS is served on -AppPort, the same port the
# banner, the firewall rule and every future bookmark use. server.js answers a
# plaintext request on that port with a redirect rather than a protocol error,
# so an http:// URL typed out of habit still lands.
#
# ⛔ EVERY FAILURE HERE LEAVES A PLAIN-HTTP INSTALL, NOT A BROKEN ONE. TLS is
# an upgrade to a working console; a half-applied switch is an outage on a
# product whose whole job is to be reachable when something is wrong.
# -----------------------------------------------------------------------
Write-Step 'Configuring TLS...'

# ⛔ The entry point is a VARIABLE from here down. Step 15 registers whatever
# this holds, so the TLS decision is taken in exactly ONE place -- a second
# nssm set somewhere below is how the two halves of this would drift.
$appEntryPoint = "node_modules\next\dist\bin\next start -p $AppPort"
$tlsEnabled = $false

# ⛔ DOT-SOURCED UNCONDITIONALLY, NOT INSIDE THE TLS BRANCH. SecVault-Tls.ps1
# carries Test-SecVaultResponding as well as the certificate helpers, and that
# probe is the ONLY evidence this script ever gets that the console actually
# serves -- "Service Running" is not "app serving", because NSSM restarts a
# crash-looping process forever. Loading it only on the TLS path meant a
# -EnableTls $false install (and every TLS failure that fell back to HTTP)
# reached the success banner on service state alone. Step 18b uses it on both
# paths now.
#
# Prefer the CLONED copy over the one next to this script: this installer may
# be run from a distribution package that is older than the repo it just
# checked out, and the helpers are the half that touches certificates.
$tlsHelpers = Join-Path $repoRoot 'installer\SecVault-Tls.ps1'
if (-not (Test-Path -LiteralPath $tlsHelpers)) {
    $tlsHelpers = Join-Path $PSScriptRoot 'SecVault-Tls.ps1'
}
$tlsHelpersLoaded = $false
if (Test-Path -LiteralPath $tlsHelpers) {
    try {
        . $tlsHelpers
        $tlsHelpersLoaded = $true
    } catch {
        Write-Host "[WARN] SecVault-Tls.ps1 could not be loaded: $($_.Exception.Message)" -ForegroundColor Yellow
    }
}
if (-not $tlsHelpersLoaded) {
    Write-Host "[WARN] SecVault-Tls.ps1 was not found or failed to load (looked in $repoRoot\installer and $PSScriptRoot). TLS cannot be enabled and the console cannot be probed -- the banner will say so rather than claiming a pass." -ForegroundColor Yellow
}

if (-not $EnableTls) {
    Write-Step "TLS: skipped (-EnableTls was `$false). The console will serve plain HTTP on port $AppPort."
} elseif (-not $tlsHelpersLoaded) {
    Write-Step "TLS: skipped -- SecVault-Tls.ps1 is unavailable. The console will serve plain HTTP on port $AppPort."
} else {
    try {
        # ⛔ NEVER OVERWRITES AN EXISTING PAIR -- New-SecVaultCertificate returns
        # the existing one untouched. Re-running this installer over a deployment
        # that already has a real corporate certificate must not replace it with a
        # self-signed one. SANs are minted by the helper and are mandatory:
        # browsers ignore the CN entirely, so a certificate without them is
        # REJECTED, not merely untrusted.
        $cert = New-SecVaultCertificate `
            -CertDir (Join-Path $repoRoot 'certs') `
            -ServerIp $ServerIp `
            -LogFile (Join-Path $LogDir 'tls-openssl.log')

        if (-not $cert.Success) { throw $cert.Message }
        Write-Step "TLS: $($cert.Message)"

        # ⛔ Upserted one key at a time via Set-SecVaultEnvValue, never by
        # rewriting .env.local from the template. CREDENTIAL_KEY, NEXTAUTH_SECRET
        # and PG_ADMIN_PASSWORD were generated minutes ago and exist nowhere else;
        # losing any of them orphans every credential this box will ever store.
        Set-SecVaultEnvValue -EnvPath $envLocalPath -Key 'ENABLE_TLS' -Value 'true' | Out-Null
        Set-SecVaultEnvValue -EnvPath $envLocalPath -Key 'TLS_CERT_PATH' -Value $cert.CertPath | Out-Null
        Set-SecVaultEnvValue -EnvPath $envLocalPath -Key 'TLS_KEY_PATH' -Value $cert.KeyPath | Out-Null
        Set-SecVaultEnvValue -EnvPath $envLocalPath -Key 'HTTP_REDIRECT_PORT' -Value "$HttpRedirectPort" | Out-Null

        # ⛔ NEXTAUTH_URL MUST FOLLOW THE SCHEME. NextAuth builds its callback
        # from it; left on http:// while the server speaks https, the cookie is
        # issued for an origin the browser is not on and EVERY sign-in bounces
        # back to the login page with no error in any log. A brand-new install
        # where nobody can log in reads as "the product does not work".
        Set-SecVaultEnvValue -EnvPath $envLocalPath -Key 'NEXTAUTH_URL' `
            -Value ("https://{0}:{1}" -f $ServerIp, $AppPort) | Out-Null

        # ⛔ next start CANNOT SERVE TLS. There is no flag for it, in any
        # version, so the service entry point becomes server.js -- the same Next
        # request handler wrapped in https.createServer.
        $appEntryPoint = 'server.js'
        $tlsEnabled = $true
        Write-Step "TLS: enabled. SecVault-App will run server.js and serve HTTPS on port $AppPort."
    } catch {
        Write-Host "[WARN] TLS setup failed: $($_.Exception.Message) -- installing on plain HTTP instead." -ForegroundColor Yellow
        Write-Host "[WARN] .env.local keeps ENABLE_TLS=false; fix the cause and re-run installer\Update-SecVault.ps1 with ENABLE_TLS=true to turn TLS on later." -ForegroundColor Yellow
        $appEntryPoint = "node_modules\next\dist\bin\next start -p $AppPort"
        $tlsEnabled = $false
    }
}

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
# ⛔ `nssm install` FAILS IF THE SERVICE STILL EXISTS, and the `remove` above
# is not guaranteed to have taken: a service with an open handle (services.msc
# left open, a stopping process) goes to DELETE_PENDING instead of vanishing.
# Nothing downstream would notice -- every `nssm set` that follows would fail
# too, each printing to a stream the script does not read -- and the service
# would keep running its PREVIOUS configuration, including the previous
# AppParameters. On a TLS install that is a certificate on disk, ENABLE_TLS=true
# in .env.local, and a service still executing `next start`, which cannot serve
# it. Fail here, where the cause is still on screen.
if ($LASTEXITCODE -ne 0) {
    Fail "nssm install SecVault-App failed with exit code $LASTEXITCODE. If the service already exists, it is most likely pending deletion -- close any open Services window, confirm with 'sc.exe query SecVault-App', and re-run."
}
# NOT node_modules\.bin\next -- that's npm's generated POSIX shell-script
# wrapper (`basedir=$(dirname ...)`, actual bash, not JavaScript). `node`
# tries to parse it as JS and crashes immediately with a SyntaxError on
# every start attempt (NSSM then marks the service Paused after enough
# rapid failures). node_modules\next\dist\bin\next is the real Next.js CLI
# entry point -- an actual JS file with a #!/usr/bin/env node shebang --
# safe to run directly with node, bypassing the wrapper entirely.
#
# ⛔ Set from $appEntryPoint (step 14b), which holds either that same next
# CLI path or 'server.js' when TLS was enabled. DO NOT HARDCODE IT HERE. Two
# places deciding the entry point is how an install ends up with a certificate
# on disk, ENABLE_TLS=true in .env.local, and a service still running
# `next start` that cannot serve it -- a configuration that reads as correct in
# every single file and is plain HTTP in the browser.
$out = Invoke-Native { & $NssmExe set SecVault-App AppParameters $appEntryPoint 2>&1 }
$out | Write-Host
# ⛔ THE ONE SETTING WHOSE FAILURE IS INVISIBLE. A service registered with no
# AppParameters starts `node` with no script: the process exits immediately,
# NSSM restarts it forever, and sc.exe reports Running the whole time. The
# probe in step 18b would eventually catch it, but on the TLS path it would be
# read as "HTTPS did not come up" and trigger a rollback that cannot help.
if ($LASTEXITCODE -ne 0) {
    Fail "nssm set SecVault-App AppParameters failed with exit code $LASTEXITCODE -- the service would start node with no script and crash-loop while reporting Running."
}
$out = Invoke-Native { & $NssmExe set SecVault-App AppDirectory "C:\Apps\SecVault" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-App AppEnvironmentExtra "NODE_ENV=production" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-App DisplayName "SecVault - Firewall Intelligence Platform" 2>&1 }
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
# Same reasoning as SecVault-App above: an install that silently did not
# happen leaves every `nssm set` below it operating on nothing.
if ($LASTEXITCODE -ne 0) {
    Fail "nssm install SecVault-Engine failed with exit code $LASTEXITCODE. Check whether the service already exists ('sc.exe query SecVault-Engine') and re-run."
}
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

Invoke-Native { & $NssmExe stop SecVault-Collector confirm 2>&1 } | Out-Null
Invoke-Native { & $NssmExe remove SecVault-Collector confirm 2>&1 } | Out-Null

$out = Invoke-Native { & $NssmExe install SecVault-Collector node 2>&1 }
$out | Write-Host
# Same reasoning again. A collector registered with no AppParameters binds
# nothing and reports itself perfectly healthy while receiving no syslog at
# all -- the failure shape the firewall rules below exist to avoid.
if ($LASTEXITCODE -ne 0) {
    Fail "nssm install SecVault-Collector failed with exit code $LASTEXITCODE. Check whether the service already exists ('sc.exe query SecVault-Collector') and re-run."
}
$out = Invoke-Native { & $NssmExe set SecVault-Collector AppParameters "services\collector.js" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Collector AppDirectory "C:\Apps\SecVault" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Collector AppEnvironmentExtra "NODE_ENV=production" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Collector DisplayName "SecVault - Collector (syslog listener)" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Collector Start SERVICE_AUTO_START 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Collector DependOnService $PgSvcName 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Collector AppStdout "$LogDir\collector-stdout.log" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Collector AppStderr "$LogDir\collector-stderr.log" 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Collector AppRotateFiles 1 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Collector AppRotateBytes 10485760 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Collector AppRotateOnline 1 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Collector AppRestartDelay 3000 2>&1 }
$out | Write-Host
# Give the collector time to DRAIN on stop. Its shutdown handler flushes the
# in-memory buffer to the spool and then to the DB. A hard kill is still SAFE
# -- the spool is fsync-ed before the insert and replayed on restart -- but a
# clean drain avoids a duplicate replay on every service restart.
$out = Invoke-Native { & $NssmExe set SecVault-Collector AppStopMethodConsole 15000 2>&1 }
$out | Write-Host
$out = Invoke-Native { & $NssmExe set SecVault-Collector AppStopMethodWindow 5000 2>&1 }
$out | Write-Host

Write-Step 'NSSM services registered.'

# -----------------------------------------------------------------------
# 16. Firewall rule
# -----------------------------------------------------------------------
Write-Step 'Creating the syslog spool directory...'
# Must exist before the collector starts; it writes here BEFORE the database.
if (-not (Test-Path $SpoolDir)) {
    New-Item -ItemType Directory -Path $SpoolDir -Force | Out-Null
}
Write-Step "Spool directory ready at $SpoolDir"

Write-Step 'Configuring firewall...'
$ruleName = "SecVault Port $AppPort"
if (-not (Get-NetFirewallRule -DisplayName $ruleName -ErrorAction SilentlyContinue)) {
    New-NetFirewallRule -DisplayName $ruleName -Direction Inbound -Protocol TCP -LocalPort $AppPort -Action Allow | Out-Null
}
Write-Step "Firewall rule added for port $AppPort"

# ⛔ The redirect listener needs its OWN rule. Without it an operator who
# reaches the plain-HTTP port gets a dropped connection rather than a redirect,
# and Windows drops those packets before anything in SecVault can see or log
# them -- every health signal green, and the door quietly bricked up. Same
# failure shape as the syslog ports below.
if ($tlsEnabled) {
    $redirectRuleName = "SecVault HTTP redirect $HttpRedirectPort"
    if (-not (Get-NetFirewallRule -DisplayName $redirectRuleName -ErrorAction SilentlyContinue)) {
        New-NetFirewallRule -DisplayName $redirectRuleName -Direction Inbound -Protocol TCP -LocalPort $HttpRedirectPort -Action Allow | Out-Null
    }
    Write-Step "Firewall rule added for the HTTP-to-HTTPS redirect on port $HttpRedirectPort"
}

# Inbound syslog. Without these the collector binds successfully, reports
# itself healthy, and receives nothing -- Windows drops the datagrams before
# they ever reach the socket, with no error anywhere to notice.
foreach ($sp in ($SyslogPorts -split ',')) {
    $p = $sp.Trim()
    if ($p -notmatch '^\d+$') { continue }
    foreach ($proto in @('UDP', 'TCP')) {
        $sysRule = "SecVault Syslog $proto/$p"
        if (-not (Get-NetFirewallRule -DisplayName $sysRule -ErrorAction SilentlyContinue)) {
            New-NetFirewallRule -DisplayName $sysRule -Direction Inbound -Protocol $proto -LocalPort $p -Action Allow | Out-Null
            Write-Step "Firewall rule added for syslog $proto/$p"
        }
    }
}

# -----------------------------------------------------------------------
# 17. Start services (sc.exe only -- never Start-Service)
# -----------------------------------------------------------------------
Write-Step 'Starting services...'

$out = sc.exe start SecVault-App
$out | Write-Host

$out = sc.exe start SecVault-Engine
$out | Write-Host

$out = sc.exe start SecVault-Collector
$out | Write-Host

# -----------------------------------------------------------------------
# 18. Verify the services actually stayed running
# -----------------------------------------------------------------------
# `sc.exe start` returns as soon as the SCM accepts the request, not once
# the process has actually stayed up -- a process that starts then
# immediately crashes (misconfiguration, missing dependency, etc.) still
# shows as briefly START_PENDING/RUNNING right after the start call. Don't
# declare success on that; poll for a few seconds and check what's
# actually true before printing the final banner.
Write-Step 'Verifying services stayed running...'
$appRunning = Wait-ServiceStatus -ServiceName 'SecVault-App' -Status 'Running' -TimeoutSeconds 15
$engineRunning = Wait-ServiceStatus -ServiceName 'SecVault-Engine' -Status 'Running' -TimeoutSeconds 15
$collectorRunning = Wait-ServiceStatus -ServiceName 'SecVault-Collector' -Status 'Running' -TimeoutSeconds 15

# -----------------------------------------------------------------------
# 18b. Prove the console answers OVER HTTPS -- and roll back if it does not
# -----------------------------------------------------------------------
# ⛔ "SERVICE RUNNING" IS NOT "APP SERVING". NSSM restarts a crashing
# process, so step 18 above can report Running while node crash-loops forever.
# Only a real HTTP response proves the console came back, and this is the safety
# net for the entry-point change made in step 14b: a fresh install that ends
# with a dark console and a green banner is the worst outcome available here,
# because nobody is watching a machine they have just finished installing.
#
# ⛔ A FALSE NEGATIVE HERE WOULD BE WORSE THAN NO CHECK AT ALL -- it
# would tear down a working HTTPS install. Test-SecVaultResponding is the shared
# helper precisely so this probe cannot drift from Update-SecVault.ps1's: it
# trusts any certificate (a self-signed one MUST pass -- we are asking whether
# the app answers, not whether a browser would trust it) via ICertificatePolicy
# rather than ServerCertificateValidationCallback, which silently never works
# under PowerShell 5.1 and cost two production outages.
#
# ⛔ The rollback value is a LITERAL, never read back from nssm.
# `nssm get` returns UTF-16 with embedded NULs; feeding that back into
# `nssm set` truncated AppParameters to "n" and left a service that could not
# start at all -- a safety net becoming the outage it exists to prevent. On a
# fresh install the correct value is known here without asking anyone.
#
# ⛔ THE PLAIN-HTTP PATH IS PROBED TOO, AND USED NOT TO BE. This whole block
# was gated on $tlsEnabled, so an install run with -EnableTls $false -- or any
# install whose TLS setup failed and fell back -- printed "SecVault installed
# successfully" on the strength of Get-Service alone. That is precisely the
# reading NSSM makes untrustworthy. A failed probe does not roll anything back
# on this path (there is nothing to roll back to) but it DOES clear
# $appRunning, so the banner reports a degraded install instead of a green one.
if ($tlsEnabled -and $appRunning -and $tlsHelpersLoaded) {
    Write-Step 'Verifying the console answers over HTTPS...'
    if (Test-SecVaultResponding -Port $AppPort -UseHttps -TimeoutSeconds 90) {
        Write-Step "Console is answering on https://$($ServerIp):$($AppPort)"
    } else {
        Write-Host '[ERROR] The console did NOT answer over HTTPS within 90s. Rolling back to plain HTTP.' -ForegroundColor Yellow
        try {
            $out = Invoke-Native { & $NssmExe set SecVault-App AppParameters "node_modules\next\dist\bin\next start -p $AppPort" 2>&1 }
            $out | Write-Host

            # Clear the whole TLS configuration, not just the entry point. A
            # half-cleared state would send the next Update-SecVault.ps1 run
            # straight back into the TLS step (ENABLE_TLS / TLS_CERT_PATH are
            # what gate it), to fail the same probe and roll back again -- an
            # outage window on every deploy, with nothing recording that it has
            # already failed once.
            Set-SecVaultEnvValue -EnvPath $envLocalPath -Key 'ENABLE_TLS' -Value 'false' | Out-Null
            Set-SecVaultEnvValue -EnvPath $envLocalPath -Key 'TLS_CERT_PATH' -Value '' | Out-Null
            Set-SecVaultEnvValue -EnvPath $envLocalPath -Key 'TLS_KEY_PATH' -Value '' | Out-Null

            # ⛔ NEXTAUTH_URL BACK TO http://, or sign-in fails silently on
            # a console that is otherwise working perfectly.
            Set-SecVaultEnvValue -EnvPath $envLocalPath -Key 'NEXTAUTH_URL' `
                -Value ("http://{0}:{1}" -f $ServerIp, $AppPort) | Out-Null

            $out = sc.exe stop SecVault-App
            $out | Write-Host
            Start-Sleep -Seconds 4
            $out = sc.exe start SecVault-App
            $out | Write-Host

            $tlsEnabled = $false
            $appRunning = Wait-ServiceStatus -ServiceName 'SecVault-App' -Status 'Running' -TimeoutSeconds 15

            if (Test-SecVaultResponding -Port $AppPort -TimeoutSeconds 90) {
                Write-Step 'Rolled back. The console is answering over plain HTTP; TLS is OFF.'
            } else {
                # ⛔ The banner must not call this a success. Without clearing
                # $appRunning, a console that answers on NEITHER transport still
                # printed "SecVault installed successfully" because the service
                # object said Running.
                $appRunning = $false
                Write-Host "[ERROR] The console is not answering after the rollback either -- check $LogDir\app-error.log." -ForegroundColor Red
            }
        } catch {
            # ⛔ Never rethrow out of a rollback. $ErrorActionPreference is
            # 'Stop' in this script, and an exception here would abort before the
            # banner, leaving the operator with no summary of what state the
            # machine was actually left in.
            Write-Host "[ERROR] TLS rollback failed: $($_.Exception.Message)" -ForegroundColor Red
            $tlsEnabled = $false
            $appRunning = $false
        }
    }
} elseif ($appRunning -and $tlsHelpersLoaded) {
    # The plain-HTTP case: no rollback is possible or needed, but the console
    # still has to be shown to ANSWER before the banner claims an install.
    Write-Step 'Verifying the console answers over HTTP...'
    if (Test-SecVaultResponding -Port $AppPort -TimeoutSeconds 90) {
        Write-Step "Console is answering on http://$($ServerIp):$($AppPort)"
    } else {
        $appRunning = $false
        Write-Host "[ERROR] SecVault-App reports Running but the console did not answer on http://127.0.0.1:$AppPort within 90s. NSSM keeps restarting a process that crashes on startup, so 'Running' is not 'serving' -- check $LogDir\app-error.log." -ForegroundColor Red
    }
} elseif ($appRunning) {
    Write-Host '[WARN] The console was NOT probed (SecVault-Tls.ps1 unavailable), so the banner below reports service state only, not that the app is serving.' -ForegroundColor Yellow
}

# -----------------------------------------------------------------------
# 18c. Daily backup task
# -----------------------------------------------------------------------
# ⛔ MOVED OUT OF THE BANNER SECTION. This block used to sit BETWEEN the
# banner's opening '=====' line and the banner text itself, so its [OK]/[WARN]
# lines printed inside the summary box -- and its leading comment had been
# spliced into the middle of the banner's own comment, leaving two unrelated
# explanations reading as one. Nothing functional, but the banner is the only
# thing most operators read.
#
# ⛔ A SYSTEM-scheduled task, not a service and not a job inside the engine. The
# engine runs as a limited service account; pg_dump has to write outside the
# install tree, and a backup that dies whenever the engine restarts mid-deploy
# is not a backup. Same reasoning as the updater task.
#
# ⛔ Best effort: a machine where this cannot be registered still has a working
# SecVault. It warns rather than failing the install, and the script can always
# be run by hand.
# ⛔ $InstallDir DOES NOT EXIST IN THIS SCRIPT -- the variable is $InstallRoot.
# Join-Path refuses a null -Path with a ParameterBindingValidationException,
# which is TERMINATING under this script's $ErrorActionPreference = 'Stop', and
# this line sits OUTSIDE the try below. So every install -- including a
# completely successful one -- died here, three lines before the success
# banner: no URL, no default-login line, no backup task, and a red .NET error
# as the last thing the operator sees on a machine that is in fact working.
# (Verified locally under PS 5.1: "Cannot bind argument to parameter 'Path'
# because it is null.")
$backupScript = Join-Path $InstallRoot 'installer\Backup-SecVault.ps1'
if (Test-Path $backupScript) {
    try {
        $tr = 'powershell.exe -NonInteractive -ExecutionPolicy Bypass -File "' + $backupScript + '"'
        & schtasks /create /tn 'SecVaultBackup' /tr $tr /sc daily /st 02:30 /f /ru SYSTEM | Out-Null
        if ($LASTEXITCODE -eq 0) {
            Write-Host '    [OK] Daily backup task registered: SecVaultBackup at 02:30.'
        } else {
            Write-Host '    [WARN] Could not register the SecVaultBackup task. Run installer\Backup-SecVault.ps1 by hand or schedule it yourself.' -ForegroundColor Yellow
        }
    } catch {
        Write-Host "    [WARN] Could not register the SecVaultBackup task: $($_.Exception.Message)" -ForegroundColor Yellow
    }
} else {
    Write-Host '    [WARN] installer\Backup-SecVault.ps1 not found -- no backup task registered.' -ForegroundColor Yellow
}

# -----------------------------------------------------------------------
# 19. Success banner
# -----------------------------------------------------------------------
Write-Host ''
Write-Host '=================================================='
# ⛔ PRINT THE SCHEME THE CONSOLE IS ACTUALLY ON. This line said
# http:// unconditionally. Once the installer can enable TLS, a hardcoded
# scheme is a URL that fails in the operator's browser on the very first
# click -- and, worse, a plaintext request into a TLS listener is a protocol
# error, not a redirect, so it fails with no explanation at all. (server.js
# handles that case on the app port; the banner should still be right.)
$consoleScheme = 'http'
if ($tlsEnabled) { $consoleScheme = 'https' }

if ($appRunning -and $engineRunning -and $collectorRunning) {
    Write-Host ' SecVault installed successfully.'
    Write-Host " URL: $($consoleScheme)://$($ServerIp):$($AppPort)"
    if ($tlsEnabled) {
        # ⛔ SAY THAT IT IS SELF-SIGNED. The first visit shows a browser
        # warning, and an operator meeting an unexplained security warning on a
        # brand-new security product reasonably concludes the install is broken.
        Write-Host ' TLS: ON (self-signed certificate -- your browser will warn until you install your own via Settings -> Certificate).'
        Write-Host " Plain HTTP on port $HttpRedirectPort redirects here."
    } else {
        Write-Host ' TLS: OFF -- the console is serving PLAIN HTTP. Set ENABLE_TLS=true in .env.local and run installer\Update-SecVault.ps1 to turn it on.'
    }
    Write-Host ' Default login: admin / changeme (change immediately via Settings)'
    # A SKIP IS STATED, NEVER SILENT -- the same rule .env.local.example states
    # for this pair. Update-SecVault.ps1 runs the page-render sweep only when
    # both are set; left blank, every future deploy logs a SKIP that nobody
    # here was told to expect, and the deploy that ships a blank page looks
    # exactly like the deploy that does not.
    if ($envContent -match '(?m)^SMOKE_USER=\s*$') {
        Write-Host ' Note: SMOKE_USER/SMOKE_PASS are unset, so the deploy-time page-render sweep will be SKIPPED on every update.'
        Write-Host '       Set them in .env.local to a dedicated local account WITHOUT MFA to turn it on.'
    }
} else {
    Write-Host ' SecVault installed, but one or more services did not stay running.' -ForegroundColor Yellow
    if (-not $appRunning) {
        Write-Host " SecVault-App is NOT running -- check $LogDir\app-error.log for the actual startup error." -ForegroundColor Yellow
    }
    if (-not $engineRunning) {
        Write-Host " SecVault-Engine is NOT running -- check $LogDir\engine-stderr.log for the actual startup error." -ForegroundColor Yellow
    }
    if (-not $collectorRunning) {
        Write-Host " SecVault-Collector is NOT running -- check $LogDir\collector-stderr.log. The most common causes are another process already holding a syslog port, or $SpoolDir not being writable." -ForegroundColor Yellow
    }
    Write-Host " Everything else (dependencies, database, build) completed successfully -- this is a runtime startup issue, not an install issue." -ForegroundColor Yellow
}
Write-Host '=================================================='
