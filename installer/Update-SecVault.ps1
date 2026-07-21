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
      5b. lib\schema-grants.sql    (readonly diagnostic grants -- best-effort)
      6. npm run build
      7. sc.exe start SecVault-Engine
      8. sc.exe start SecVault-App

    Written for PowerShell 5.1  -  see CLAUDE.md "PowerShell (PS5 compatibility)".
    Service state changes (start/stop) are sc.exe only  -  never Start-Service/
    Stop-Service (they can hang a WinRM session). Read-only Get-Service polling
    (`.Status` checks only, e.g. Wait-ServiceStatus below) is fine and used
    deliberately  -  it doesn't change service state and doesn't carry that hang risk.
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

# ⛔ Bug fixed 2026-07-19, found in a follow-up bug sweep: this ran before
# Write-Log exists (it's defined below) with $ErrorActionPreference already
# 'Stop' -- a failure here (e.g. C:\Apps\SecVault not yet created, a
# permissions issue under the SYSTEM-scheduled-task path) was an uncaught
# terminating error with no Write-Log line and no guaranteed console/stderr
# visibility when launched non-interactively via schtasks. Wrapped so the
# failure is at least reported via Write-Warning (visible in Get-ScheduledTaskInfo/
# Event Viewer's PowerShell log even with no transcript yet) before exiting,
# instead of silently vanishing.
try {
    New-Item -ItemType Directory -Force -Path $LogDir | Out-Null
} catch {
    Write-Warning "Could not create log directory $LogDir -- $($_.Exception.Message)"
    exit 1
}

# The in-app updater (Settings -> Updates, POST /api/system/update) is
# fire-and-forget: it schedules this script as a SYSTEM scheduled task and
# immediately returns { started: true } to the browser, with no live output
# stream. Without a transcript, a run triggered that way leaves NO durable
# record of what happened beyond the plain-text $LogFile below (which only
# captures what Write-Log is explicitly given, not raw native-command output
# that some steps below write straight to Write-Host). Start it as early as
# possible so even an early failure is captured. This is a SEPARATE file from
# $LogFile ('update.log') -- keep both. Mirrors the 2026-07-14 hardening pass
# already applied to the sibling NocVault apps' equivalent scripts (e.g.
# netvault's Update-NetVault.ps1). Best-effort: a transcript that fails to
# start must never block the actual update, and Write-Log isn't defined yet
# at this point in the script, so a start failure is reported via Write-Warning.
$transcriptPath = Join-Path $LogDir "update-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
try { Start-Transcript -Path $transcriptPath -Append | Out-Null } catch { Write-Warning "Could not start transcript: $($_.Exception.Message)" }

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

# The in-app updater (POST /api/system/update) now sometimes launches this
# script via a Windows Scheduled Task running as SYSTEM, and SYSTEM has never
# run git in this repo's working copy before (only whichever interactive
# account originally cloned it has). Git >= 2.35.2 (CVE-2022-24765) refuses to
# operate in a repo it doesn't consider "owned" by the current account:
# "fatal: detected dubious ownership in repository at '...'". Register this
# repo as safe for whichever account is running right now (idempotent -- safe
# to add the same path twice) so step 3's git pull can't hit this. Best-effort:
# a failure here must never abort the update -- mirrors the 2026-07-14
# hardening pass already applied to the sibling NocVault apps' equivalent
# scripts (e.g. netvault's Update-NetVault.ps1).
try {
    $null = & git config --global --add safe.directory $repoRoot 2>&1
} catch {
    Write-Log "  [WARN] Could not register safe.directory for $repoRoot -- $($_.Exception.Message)"
}

# ⛔ Account-mismatch bug fixed 2026-07-17 -- same family as the
# safe.directory fix above, and the SAME bug already found and fixed in
# lib\updateCheck.js (the in-app updater's read-only status check), just
# never ported here to the script that actually performs the update.
#
# secvault is a private repo -- git pull (step 3 below) needs an SSH deploy
# key. This USED to point at $env:USERPROFILE\.ssh\secvault_deploy -- the
# profile of whichever admin ran Install-SecVault.ps1 interactively. That
# works fine when THIS script is also run interactively by that same admin
# ("& Update-SecVault.ps1" per CLAUDE.md's "Deploy After Commit"), which is
# almost certainly why manual updates have been working throughout this
# session's debugging. But the in-app updater (Settings -> Updates ->
# "Update Now", POST /api/system/update) schedules this script as a Windows
# Scheduled Task running as SYSTEM -- and $env:USERPROFILE for SYSTEM
# resolves to a completely different, unrelated profile path with no copy of
# the key at all. That path was never actually exercised/confirmed working
# in this session (all confirmed successful deploys were manual, interactive
# runs) -- it would fail this exact check and exit 1 here, before touching
# any service (safe, but silently never actually updates).
#
# ⛔ Correction (2026-07-17, same day): the fix above assumed
# installer\dependencies\secvault_deploy persists on disk after install --
# CLAUDE.md's own installer documentation describes it as the source file
# Install-SecVault.ps1 copies FROM, gitignored so a `git pull`/`reset --hard`
# can't delete it, and this repo's own earlier research (this session) never
# found anything that explicitly removes it. But that assumption was never
# actually verified against a real deployed server, and it was wrong: a live
# run failed immediately with "SSH deploy key not found:
# ...\installer\dependencies\secvault_deploy" -- confirming that file
# genuinely does not exist at that path on this install (possibly cleaned up
# post-install, or never placed there in the first place on this server).
#
# ⛔ Bug fixed 2026-07-19, found in a follow-up bug sweep: neither location
# checked below is reliably readable by SYSTEM (the account the in-app
# updater's scheduled task actually runs as -- see the long comment chain
# above). Install-SecVault.ps1 now ALSO places a copy at
# C:\ProgramData\SecVault\ssh\secvault_deploy, locked down to SYSTEM +
# BUILTIN\Administrators, specifically so this path has a location that
# works regardless of which account is running. Checked FIRST -- it's the
# only one of the three that is guaranteed correct for both the manual and
# SYSTEM-scheduled invocation paths on any install that's re-run
# Install-SecVault.ps1 since this fix landed. The other two remain as
# fallbacks for an install that hasn't been re-run yet.
$deployKeyMachineWide = 'C:\ProgramData\SecVault\ssh\secvault_deploy'
$deployKeyRepoRelative = Join-Path $repoRoot 'installer\dependencies\secvault_deploy'
$deployKeyUserProfile = "$env:USERPROFILE\.ssh\secvault_deploy"
if (Test-Path $deployKeyMachineWide) {
    $deployKey = $deployKeyMachineWide
} elseif (Test-Path $deployKeyRepoRelative) {
    $deployKey = $deployKeyRepoRelative
} elseif (Test-Path $deployKeyUserProfile) {
    $deployKey = $deployKeyUserProfile
} else {
    Write-Host "  [FAIL] SSH deploy key not found at any of:"
    Write-Host "         $deployKeyMachineWide"
    Write-Host "         $deployKeyRepoRelative"
    Write-Host "         $deployKeyUserProfile"
    Write-Host "         Re-run Install-SecVault.ps1 to configure SSH credentials"
    # ⛔ Bug fixed 2026-07-19, found in a follow-up bug sweep: this was the
    # only exit point in the whole script that skipped Stop-Transcript --
    # every other path falls through to the try/Stop-Transcript/catch at the
    # bottom. Under the SYSTEM-scheduled-task path (see the long comment
    # above), this is also the single most likely real-world failure -- and
    # it left the transcript file open/unflushed indefinitely (until the next
    # script run's Start-Transcript implicitly closes it, if PowerShell even
    # allows that), the exact run that most needed a durable record per this
    # script's own transcript comment at the top.
    try { Stop-Transcript | Out-Null } catch {}
    exit 1
}

# ⛔ Self-heal added 2026-07-18, found live on a real server (thaiunion
# deployment): a server installed/last-Install-SecVault.ps1'd before the
# machine-wide-copy fix above landed never gets it retroactively --
# Install-SecVault.ps1 only places $deployKeyMachineWide at INSTALL time,
# and nothing re-runs that step on update. This server hit exactly that
# gap: `& Update-SecVault.ps1` run manually/interactively worked fine (the
# admin's own profile had a working fallback copy), while the in-app
# "Update Now" button's SYSTEM-scheduled run failed silently on the exact
# check above (SYSTEM has no access to either fallback) -- confirmed via
# Test-Path directly on the server. Fixed by hand once on that server; this
# self-heal exists so no OTHER already-deployed server (or this one again,
# if the file is ever lost) needs the same manual one-off fix. Whenever a
# fallback key resolved instead of the machine-wide one, copy it up now,
# locked down the exact same way Install-SecVault.ps1 does. Best-effort --
# a failure here must not block THIS run (it already has a working key via
# the fallback), only logged so it stays visible.
if ($deployKey -ne $deployKeyMachineWide) {
    Write-Log "  [INFO] Machine-wide deploy key missing -- self-healing from $deployKey"
    try {
        $machineKeyDir = Split-Path $deployKeyMachineWide -Parent
        if (-not (Test-Path $machineKeyDir)) {
            New-Item -ItemType Directory -Force -Path $machineKeyDir | Out-Null
        }
        if (Test-Path $deployKeyMachineWide) {
            icacls $deployKeyMachineWide /reset | Out-Null
        }
        Copy-Item -Path $deployKey -Destination $deployKeyMachineWide -Force
        $out = icacls $deployKeyMachineWide /inheritance:r /grant:r 'SYSTEM:R' /grant:r 'BUILTIN\Administrators:R' 2>&1
        $out | Write-Host
        Write-Log "  [OK] Deploy key self-healed to $deployKeyMachineWide -- future SYSTEM-scheduled updates will find it directly."
    } catch {
        Write-Log "  [WARN] Could not self-heal machine-wide deploy key: $($_.Exception.Message) -- this run continues fine using $deployKey, but the in-app SYSTEM-scheduled update path may still fail until this is resolved."
    }
}

# Route git's SSH transport straight at this key file via a per-invocation
# core.sshCommand override (step 3 below), instead of relying on whichever
# account's ~/.ssh/config happens to reference it -- same fix, same
# reasoning as lib\updateCheck.js's sshCommandOverride(). UserKnownHostsFile
# points at $env:TEMP rather than anywhere under the running account's
# profile or the repo tree -- $env:TEMP is set and writable for every
# Windows account, including SYSTEM, unconditionally; ssh's default
# known_hosts location (under the account's own profile) is exactly the
# class of account-specific path already responsible for two of this
# session's three updater failures. Not pre-seeded with a hardcoded host
# key -- StrictHostKeyChecking=accept-new still performs its own
# first-connect trust-and-persist, just now with somewhere it can actually
# write the result. BatchMode=yes: never hang on an interactive prompt.
# No quoting around the paths themselves -- git parses core.sshCommand's
# value with its own space-splitting, same as a plain shell command line,
# and (matching this codebase's existing assumption elsewhere for this exact
# class of path, e.g. lib\updateCheck.js's identical override) neither
# $repoRoot nor $env:TEMP contains a space on the current install layout.
# Deliberately avoids nesting quotes inside the already-quoted `-c` argument
# below, which is fragile to reason about correctly across PowerShell's own
# string interpolation, git's config-value parsing, AND git's re-invocation
# of ssh with this string as ITS command line -- three layers, and this
# script cannot be executed/tested outside a real Windows host to verify a
# nested-quoting scheme actually survives all three intact.
$knownHostsPath = Join-Path $env:TEMP 'secvault-update-known_hosts'

# ⛔ Root cause found 2026-07-21, via a diagnostic -v pass captured from a
# real SYSTEM-scheduled run (this file's own git history has the temporary
# diagnostic block that produced it). This was never a key, ACL, or
# profile-loading problem -- it's that bare "ssh" is PATH-resolved, and
# resolves to a DIFFERENT BINARY depending on which account's PATH is in
# effect:
#   - An interactive admin's PATH resolves "ssh" to Windows' own OpenSSH
#     client (C:\Windows\System32\OpenSSH\ssh.exe -- "OpenSSH_for_Windows
#     9.5p1, LibreSSL", reads %USERPROFILE%\.ssh\config). This handles a
#     native Windows path like C:\ProgramData\...\secvault_deploy passed to
#     -i correctly -- confirmed live, authenticated cleanly with zero
#     warnings.
#   - The SYSTEM-scheduled task's PATH instead resolves "ssh" to GIT'S OWN
#     BUNDLED ssh.exe (MSYS2-based -- "OpenSSH_10.3p1, OpenSSL", reads
#     /etc/ssh/ssh_config, an entirely separate build). Confirmed live via
#     -v: it printed "Identity file ... not accessible" for our -i path and
#     NEVER attempted it as a candidate at all -- it silently fell straight
#     to its own default identities (id_rsa/id_ecdsa/id_ed25519 under the
#     SYSTEM profile, none of which exist), then reported "No more
#     authentication methods to try." The machine-wide key, its ACL, and
#     $env:TEMP/$env:USERPROFILE were all confirmed fine in the same pass --
#     none of that was ever the problem.
# Fix: stop relying on PATH resolution entirely -- invoke Windows' own
# OpenSSH client by its full, deterministic path, so both the interactive
# and SYSTEM-scheduled contexts use the SAME, known-working binary
# regardless of which account's PATH ordering would otherwise pick the
# other one. Falls back to bare "ssh" (prior behavior) if that exact path
# doesn't exist on some future install, rather than hard-failing here --
# the identical rationale as this file's other install-path checks.
$win32Ssh = 'C:\Windows\System32\OpenSSH\ssh.exe'
$sshBinary = if (Test-Path $win32Ssh) { $win32Ssh } else { 'ssh' }
$sshCommand = "$sshBinary -i $deployKey -o IdentitiesOnly=yes -o StrictHostKeyChecking=accept-new -o UserKnownHostsFile=$knownHostsPath -o BatchMode=yes"

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
    $out = Invoke-Native { git -c "core.sshCommand=$sshCommand" pull origin main 2>&1 }
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
# ⛔ Bug fixed 2026-07-19: this step's result was previously discarded (only
# $script:hadFailure was set on failure, which has no gating effect until the
# final summary log line, printed AFTER services are already restarted -- see
# CLAUDE.md's own audit_findings.matched_rule_ids incident for the exact class
# of "column ... does not exist" runtime failure this allowed). npm run build
# does NOT require the DB schema to be current (every DB-hitting route is
# force-dynamic specifically to avoid build-time DB access), so a failed
# migration could still be followed by a successful build and, without this
# capture, an app restart (step 8) against the old/incomplete schema. Captured
# so step 8 can gate on it alongside $buildSucceeded.
$migrateSucceeded = Invoke-Step 'node lib\migrate.js' {
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
# 5b. lib\schema-grants.sql  (readonly diagnostic grants -- best-effort)
# -----------------------------------------------------------------------
# CREATE ROLE requires postgres superuser, which secvault_user does not have
# (see CLAUDE.md "Readonly Access for Diagnostics"), so this cannot be part of
# lib\migrate.js above -- same reason Install-SecVault.ps1 applies it as a
# separate step. This step was previously ONLY run by Install-SecVault.ps1,
# which meant every new table added to schema.sql needed a manual
# `psql -U postgres -d secvault -f lib\schema-grants.sql` after every update --
# easy to forget, and CLAUDE.md had to carry a standing reminder about it.
#
# What makes running it here safe: Install-SecVault.ps1 already persists the
# postgres superuser password into .env.local as PG_ADMIN_PASSWORD (see its
# own comment: originally "purely for later manual reference" -- this is that
# reference, used programmatically). schema-grants.sql's own CREATE ROLE
# statements are already guarded with `IF NOT EXISTS` and every GRANT is
# idempotent, so re-running the whole file on every update is always safe,
# not just when a new table was actually added.
#
# Best-effort by design, same as Install-SecVault.ps1's tolerance: a failure
# here (missing .env.local, empty PG_ADMIN_PASSWORD, wrong password after a
# manual PostgreSQL password change, psql.exe not found) must NEVER fail the
# overall update -- these roles are diagnostic-only and not required for the
# app to function. Everything in this step is wrapped so it can only ever
# warn, never throw, regardless of what goes wrong.
Invoke-Step 'lib\schema-grants.sql (readonly grants)' {
    try {
        $envLocalPath = Join-Path $repoRoot '.env.local'
        if (-not (Test-Path $envLocalPath)) {
            Write-Log '  [WARN] .env.local not found -- skipping readonly grants (not fatal).'
            return
        }

        $envContent = Get-Content -Path $envLocalPath -Raw
        $pgAdminPassword = $null
        if ($envContent -match '(?m)^PG_ADMIN_PASSWORD=(.*)$') {
            $pgAdminPassword = $matches[1].Trim()
        }

        if ([string]::IsNullOrEmpty($pgAdminPassword)) {
            Write-Log '  [WARN] PG_ADMIN_PASSWORD not set in .env.local -- skipping readonly grants (not fatal). Run lib\schema-grants.sql manually with the postgres superuser password if needed.'
            return
        }

        $PgBin = 'C:\Program Files\PostgreSQL\16\bin'
        $grantsPath = Join-Path $repoRoot 'lib\schema-grants.sql'
        if (-not (Test-Path $grantsPath)) {
            Write-Log "  [WARN] $grantsPath not found -- skipping readonly grants (not fatal)."
            return
        }

        $env:PGPASSWORD = $pgAdminPassword
        $out = Invoke-Native { & "$PgBin\psql.exe" -U postgres -h localhost -d secvault -f $grantsPath 2>&1 }
        Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
        $out | Write-Host
        Add-Content -Path $LogFile -Value ($out -join "`n")

        if ($LASTEXITCODE -ne 0 -and $LASTEXITCODE -ne -1) {
            Write-Log "  [WARN] schema-grants.sql exited with code $LASTEXITCODE -- claude_readonly/nocvault_readonly may be out of date. This does not affect application function."
        }
    } catch {
        Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
        Write-Log "  [WARN] Applying readonly grants threw an unexpected error -- $($_.Exception.Message). This does not affect application function."
    }
}

# -----------------------------------------------------------------------
# 6. npm run build
# -----------------------------------------------------------------------
# ⛔ Bug fixed 2026-07-19, found in a follow-up bug sweep: Invoke-Step's
# return value (true/false) was never captured anywhere -- every step,
# including this one, ran as a fire-and-forget "best effort recovery"
# regardless of outcome, per the script's own top-of-file doc comment. That's
# a defensible default for most steps (stopping/starting services, the
# best-effort readonly-grants step) but NOT for this one: SecVault-App
# (step 8) runs `next start` directly against .next\ on disk. A failed
# `npm run build` can leave .next\ from a stale PREVIOUS successful build, a
# half-written/corrupted one from the failed run, or (on a fresh install with
# no prior build) missing entirely -- in every case, starting SecVault-App
# afterward either serves stale code silently (looks like a successful
# deploy; isn't) or crash-loops. Capturing the result here so step 8 below
# can gate on it specifically -- SecVault-Engine (step 7) is intentionally
# NOT gated the same way, since engine-worker.js runs directly under `node`
# and has no dependency on the Next.js build output.
$buildSucceeded = Invoke-Step 'npm run build' {
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
# 8. Start SecVault-App -- gated on step 5 (node lib\migrate.js) AND step 6
# (npm run build) actually succeeding. See the $migrateSucceeded comment above
# step 5 and the $buildSucceeded comment above step 6 for why starting this
# service against a failed migration or a failed build is worse than leaving
# it stopped.
# -----------------------------------------------------------------------
$appStartSkipped = $false
if ($buildSucceeded -and $migrateSucceeded) {
    Invoke-Step 'sc.exe start SecVault-App' {
        $out = sc.exe start SecVault-App
        $out | Write-Host
        Add-Content -Path $LogFile -Value ($out -join "`n")
        if (-not (Wait-ServiceStatus -ServiceName 'SecVault-App' -Status 'Running' -TimeoutSeconds 15)) {
            Write-Log '  [WARN] SecVault-App did not reach Running state within 15s -- check logs\app-error.log.'
        }
    }
} else {
    $script:hadFailure = $true
    $appStartSkipped = $true
    $skipReason = if (-not $migrateSucceeded) { 'node lib\migrate.js failed above' } else { 'npm run build failed above' }
    Write-Log "  [SKIP] sc.exe start SecVault-App -- $skipReason. Refusing to (re)start the app against a broken/stale build or an incomplete schema. Fix the error, then either re-run this script or start the service manually: sc.exe start SecVault-App"
}

Write-Log '=================================================='
if ($script:hadFailure) {
    # ⛔ Bug fixed 2026-07-19: this line used to unconditionally claim "Both
    # services were still (re)started" even when step 8 above was deliberately
    # SKIPPED (build or migration failure) -- directly contradicting the SKIP
    # line just logged and telling an operator tailing update.log that
    # SecVault-App was restarted when it was deliberately left stopped.
    if ($appStartSkipped) {
        Write-Log 'SecVault update completed WITH ERRORS  -  see steps above. SecVault-App was NOT (re)started (see SKIP above); SecVault-Engine was still started as a best-effort recovery.'
    } else {
        Write-Log 'SecVault update completed WITH ERRORS  -  see steps above. Both services were still (re)started as a best-effort recovery.'
    }
} else {
    Write-Log 'SecVault update completed successfully.'
}
Write-Log '=================================================='

# Best-effort -- if Start-Transcript never succeeded (see top of script), this
# throws harmlessly; never let it mask the update's own success/failure above.
try { Stop-Transcript | Out-Null } catch {}
