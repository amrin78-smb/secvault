<#
.SYNOPSIS
    Removes SecVault from this server: services, scheduled tasks, firewall
    rules, deploy keys, and -- only when asked -- the database and the install
    directory.

.DESCRIPTION
    Written for PowerShell 5.1 -- see CLAUDE.md "PowerShell (PS5 compatibility)".
    Never uses Start-Service/Stop-Service/Get-Service -- sc.exe only.
    Never pipes directly out of try/catch -- always `$out = cmd; $out | Write-Host`.

    Services are removed via `sc.exe delete` (not `nssm remove`) -- once a
    service is registered with NSSM, the Windows Service Control Manager can
    remove it directly with no dependency on locating nssm.exe, matching the
    pattern used by the NocVault suite uninstaller.

    ### ⛔ EVERY STEP REPORTS WHAT IT VERIFIED, NOT WHAT IT ATTEMPTED

    An uninstaller is read once, quickly, usually while decommissioning a host,
    and its output is believed. This one used to print "Database and user
    dropped." after a psql that was never found, and "$InstallRoot deleted."
    after a Remove-Item that had failed on a file node.exe still held. Both are
    this codebase's most-repeated bug -- a failed step recorded as an
    affirmative fact -- and on an uninstaller they leave credentials and an
    exposed listener on a machine somebody believes is clean.

    ### ⛔ THE TWO OPPOSITE FAILURES THIS SCRIPT IS CAREFUL ABOUT

      * LEAVING SECRETS BEHIND. The deploy SSH key (private key for a private
        repository, at C:\ProgramData\SecVault\ssh and in the installing admin's
        profile) and the backup directory (which holds CREDENTIAL_KEY beside the
        AES-256-GCM ciphertext it decrypts) both outlive a naive uninstall.
      * DELETING THE ONLY COPY. That same backup directory, and the syslog
        archive, are frequently on a different volume and are the only remaining
        record of the fleet. Nothing here deletes either one, ever, at any
        switch -- their locations are PRINTED so the decision is a person's.

.PARAMETER InstallRoot
    SecVault install directory. Default C:\Apps\SecVault.

.PARAMETER DropDatabase
    Also drop the SecVault database and its owning role.

.PARAMETER PgAdminPassword
    PostgreSQL `postgres` superuser password, for -DropDatabase. Blank = read
    PG_ADMIN_PASSWORD out of the deployed .env.local, which is where
    Install-SecVault.ps1 writes the value it GENERATED at install time.

.PARAMETER KeepDeployKeys
    Leave the git deploy SSH keys on disk. They are removed by default.

.PARAMETER RemoveInstallDir
    Delete the install directory without prompting. Implies -Yes for that step.

.PARAMETER Yes
    Answer the confirmation prompt. Required for a non-interactive run --
    without it Read-Host reads EOF, which is treated as "no" and aborts.
#>

[CmdletBinding()]
param(
    [string]$InstallRoot = 'C:\Apps\SecVault',
    [switch]$DropDatabase,
    [string]$PgAdminPassword = '',
    [switch]$KeepDeployKeys,
    [switch]$RemoveInstallDir,
    [switch]$Yes
)

# ⛔ NOT 'Stop'. This script must keep going and keep reporting through a
# half-removed installation -- a service that is not there, a task that was
# never registered, a database already gone. Every step below judges itself on
# EVIDENCE instead, so nothing needs an exception to notice a failure.
$ErrorActionPreference = 'Continue'

$problems = @()
$leftBehind = @()

function Write-Step {
    param([string]$Message)
    $ts = (Get-Date).ToString('yyyy-MM-ddTHH:mm:ss')
    Write-Host "[$ts] $Message"
}
function Write-Warn {
    param([string]$Message)
    Write-Host "  [WARN] $Message" -ForegroundColor Yellow
    $script:problems += $Message
}

function Invoke-Native {
    param([Parameter(Mandatory = $true)][scriptblock]$Command)
    $prevEAP = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    # ⛔ $LASTEXITCODE IS STALE, NOT EMPTY, WHEN A COMMAND NEVER RAN.
    # Same seed and same reason as Install-SecVault.ps1's copy of this helper:
    # an unresolvable executable raises CommandNotFoundException, which
    # 'Continue' downgrades to a printed error, and leaves $LASTEXITCODE holding
    # the PREVIOUS command's value -- almost always 0. Every caller then reads
    # "exit code 0" for a step that did not happen. 9009 is cmd.exe's own
    # "command not found", so the un-run case fails a `-ne 0` check instead of
    # passing it.
    $global:LASTEXITCODE = 9009
    try { & $Command } finally { $ErrorActionPreference = $prevEAP }
}

# Is this process elevated? The deploy-key removal and `sc.exe delete` both
# need it, and a non-elevated run fails them one at a time with errors that
# each look like something else.
function Test-IsElevated {
    try {
        $id = [Security.Principal.WindowsIdentity]::GetCurrent()
        return (New-Object Security.Principal.WindowsPrincipal($id)).IsInRole(
            [Security.Principal.WindowsBuiltInRole]::Administrator)
    } catch { return $false }
}

# sc.exe only. Returns the state word, or '' when the service is not installed.
function Get-SvcState {
    param([Parameter(Mandatory = $true)][string]$Name)
    $out = Invoke-Native { & sc.exe query $Name 2>&1 }
    $text = ($out | Out-String)
    if ($text -match 'STATE\s+:\s+\d+\s+([A-Z_]+)') { return $Matches[1] }
    return ''
}

Write-Host '=================================================='
Write-Host ' SecVault Uninstaller'
Write-Host '=================================================='

# -----------------------------------------------------------------------
# 0. Read the configuration BEFORE anything destructive
#
# ⛔ ORDER IS LOAD-BEARING. The database name, the spool directory and the
# syslog archive directory are only knowable from .env.local, and step 5 may
# delete it. Reading afterwards would mean the closing inventory could not name
# the paths an operator has to go and deal with by hand.
# -----------------------------------------------------------------------
$EnvFile = Join-Path $InstallRoot '.env.local'
$dbName = 'secvault'
$dbUser = 'secvault_user'
$spoolDir = ''
$archiveDir = ''
$backupDirGuess = ''
$envText = ''
if (Test-Path $EnvFile) {
    $envText = Get-Content $EnvFile -Raw -Encoding UTF8
    # Host and port are OPTIONAL and the reference deployment omits both
    # (postgresql://secvault_user:<pass>@/secvault) -- see the long note in
    # Backup-SecVault.ps1 for why [System.Uri] cannot be used on that form.
    if ($envText -match '(?m)^DATABASE_URL=postgres(?:ql)?://([^:@/]+)(?::[^@]*)?@[^:/]*(?::\d+)?/(.+)$') {
        $dbUser = $Matches[1].Trim()
        $dbName = $Matches[2].Trim()
    } else {
        # ⛔ Said out loud. Falling back to the defaults silently is how
        # -DropDatabase drops the wrong thing, or reports dropping a database
        # this installation never used.
        Write-Warn "DATABASE_URL in $EnvFile could not be parsed. Falling back to database 'secvault' / role 'secvault_user' -- verify before using -DropDatabase."
    }
    if ($envText -match '(?m)^SYSLOG_SPOOL_DIR=(.*)$')   { $spoolDir   = $Matches[1].Trim() }
    if ($envText -match '(?m)^SYSLOG_ARCHIVE_DIR=(.*)$') { $archiveDir = $Matches[1].Trim() }
    if (-not $PgAdminPassword -and $envText -match '(?m)^PG_ADMIN_PASSWORD=(.*)$') {
        # ⛔ Install-SecVault.ps1 has NO -PgAdminPassword parameter: it GENERATES
        # the superuser password at install time and writes it here. This script
        # used to default to a hardcoded literal that no current installation
        # has ever used, so -DropDatabase authenticated-failed every time --
        # and then printed "Database and user dropped." anyway.
        $PgAdminPassword = $Matches[1].Trim()
    }
    Write-Step "Read configuration from $EnvFile (database '$dbName', role '$dbUser')."
} else {
    Write-Warn "$EnvFile not found -- falling back to the default database name 'secvault'. If this installation used another, drop it by hand."
}
if (-not $spoolDir) { $spoolDir = Join-Path $InstallRoot 'spool' }
if ($archiveDir) {
    $q = Split-Path $archiveDir -Qualifier -ErrorAction SilentlyContinue
    if ($q) { $backupDirGuess = Join-Path $q 'SecVaultBackup' }
}
if (-not $backupDirGuess) { $backupDirGuess = Join-Path $InstallRoot 'backup' }

# -----------------------------------------------------------------------
# 1. Confirmation prompt
# -----------------------------------------------------------------------
if (-not $Yes) {
    $confirm = Read-Host 'This will remove SecVault. Continue? [y/N]'
    if (-not ($confirm -eq 'y' -or $confirm -eq 'Y')) {
        Write-Host 'Aborted. No changes made.'
        exit 0
    }
}

$services = @('SecVault-App', 'SecVault-Engine', 'SecVault-Collector')

# -----------------------------------------------------------------------
# 2. Stop services (sc.exe only -- never Start-Service/Stop-Service)
# -----------------------------------------------------------------------
Write-Step 'Stopping services...'

# ⛔ The collector was registered by Install-SecVault.ps1 with
# Start SERVICE_AUTO_START and AppRestartDelay 3000. Leaving it behind means an
# uninstalled machine keeps an auto-starting LocalSystem service crash-looping
# `node services\collector.js` against a deleted directory, restarting every
# 3 seconds, forever.
foreach ($svc in $services) {
    $out = Invoke-Native { & sc.exe stop $svc 2>&1 }
    $out | Write-Host
}

# ⛔ WAIT FOR STOPPED RATHER THAN SLEEPING. `sc.exe stop` only REQUESTS a stop.
# Deleting a service that is still running marks it for deletion until the next
# REBOOT -- sc.exe reports success, the service stays in the SCM, and a
# reinstall then fails with "The specified service has been marked for
# deletion" for a reason nothing in this transcript explains. It also keeps
# node.exe alive holding files under $InstallRoot, which is what makes step 5's
# delete fail.
foreach ($svc in $services) {
    $deadline = (Get-Date).AddSeconds(60)
    $state = Get-SvcState -Name $svc
    while ($state -and $state -ne 'STOPPED' -and (Get-Date) -lt $deadline) {
        Start-Sleep -Seconds 2
        $state = Get-SvcState -Name $svc
    }
    if ($state -and $state -ne 'STOPPED') {
        Write-Warn "$svc is still $state after 60s. Deleting it now would only mark it for deletion until the next reboot."
    }
}

# -----------------------------------------------------------------------
# 3. Remove services (sc.exe delete -- no nssm.exe dependency)
# -----------------------------------------------------------------------
Write-Step 'Removing services...'

foreach ($svc in $services) {
    $out = Invoke-Native { & sc.exe delete $svc 2>&1 }
    $out | Write-Host
    # ⛔ VERIFIED, not assumed. sc.exe delete returns 1060 ("service does not
    # exist") for an already-absent service, which is success here, and 1072
    # ("marked for deletion") for one that is still running, which is NOT --
    # and both print a line that scrolls past. Re-querying is the only thing
    # that distinguishes them.
    $state = Get-SvcState -Name $svc
    if ($state) {
        Write-Warn "$svc is STILL REGISTERED (state $state) after sc.exe delete. Reboot and re-run this script, or a reinstall will fail with 'marked for deletion'."
    } else {
        Write-Step "  $svc removed."
    }
}

# -----------------------------------------------------------------------
# 3b. Scheduled tasks
#
# ⛔ BOTH TASKS, AND NEITHER WAS BEING REMOVED. SecVaultBackup is registered by
# Install-SecVault.ps1 to run DAILY at 02:30 as SYSTEM; SecVaultUpdate is
# registered by the in-app updater (app/api/system/update/route.js). Left
# behind on a decommissioned host they run forever against a deleted script --
# and, worse, if the install directory is kept while the database is dropped,
# the backup task fails silently every night against something an operator
# still believes is being backed up.
# -----------------------------------------------------------------------
Write-Step 'Removing scheduled tasks...'
foreach ($task in @('SecVaultBackup', 'SecVaultUpdate')) {
    $out = Invoke-Native { & schtasks /delete /tn $task /f 2>&1 }
    $out | Write-Host
    $check = Invoke-Native { & schtasks /query /tn $task 2>&1 }
    # A missing task makes schtasks /query exit non-zero -- that is the
    # confirmation. Reading the /delete exit code alone would not distinguish
    # "deleted" from "was not there" from "access denied".
    if ($LASTEXITCODE -eq 0) {
        Write-Warn "Scheduled task '$task' still exists. Remove it by hand: schtasks /delete /tn $task /f"
    } else {
        Write-Step "  Scheduled task '$task' is gone."
    }
}

# -----------------------------------------------------------------------
# 3c. Firewall rules
#
# ⛔ ALL OF THEM, not just syslog. Install-SecVault.ps1 opens FOUR kinds:
# "SecVault Port <AppPort>", "SecVault HTTP redirect <port>" and
# "SecVault Syslog UDP/<p>" + "SecVault Syslog TCP/<p>" for every syslog port.
# This step only ever matched the syslog ones, so an uninstalled host kept the
# console port permanently open inbound -- the exposure an uninstall is
# supposed to remove. Matching on the 'SecVault ' prefix covers every rule the
# installer creates without this script having to know which ports were chosen.
# -----------------------------------------------------------------------
Write-Step 'Removing firewall rules...'
# ⛔ "The cmdlet is not available" must not render as "there are no rules".
# Get-NetFirewallRule comes from the NetSecurity module; on a host where it
# cannot be loaded, -ErrorAction SilentlyContinue does NOT suppress a
# CommandNotFoundException at resolution time, the pipeline yields nothing, and
# an empty array then reads as a clean result -- a console port left open
# inbound, reported as removed.
if (-not (Get-Command Get-NetFirewallRule -ErrorAction SilentlyContinue)) {
    Write-Warn 'Get-NetFirewallRule is not available on this host, so the SecVault firewall rules were NOT removed and NOT checked. Remove them by hand: netsh advfirewall firewall delete rule name=all | findstr SecVault'
    $fwRules = @()
} else {
    $fwRules = @(Get-NetFirewallRule -DisplayName 'SecVault *' -ErrorAction SilentlyContinue)
}
if ($fwRules.Count -eq 0) {
    Write-Step '  No SecVault firewall rules to remove.'
} else {
    foreach ($r in $fwRules) {
        try {
            Remove-NetFirewallRule -Name $r.Name -ErrorAction Stop
            Write-Step "  Removed firewall rule: $($r.DisplayName)"
        } catch {
            Write-Warn "Could not remove firewall rule '$($r.DisplayName)': $($_.Exception.Message)"
        }
    }
    $remaining = @(Get-NetFirewallRule -DisplayName 'SecVault *' -ErrorAction SilentlyContinue)
    if ($remaining.Count -gt 0) {
        Write-Warn "$($remaining.Count) SecVault firewall rule(s) remain: $(($remaining | ForEach-Object { $_.DisplayName }) -join ', ')"
    }
}

# -----------------------------------------------------------------------
# 4. Optionally drop database + role
# -----------------------------------------------------------------------
if ($DropDatabase) {
    Write-Step "Dropping database '$dbName' and role '$dbUser'..."

    # ⛔ psql IS RESOLVED AND CHECKED. A bare `& psql` on a host where it is not
    # on PATH raises CommandNotFoundException and LEAVES $LASTEXITCODE AT ITS
    # PREVIOUS VALUE (verified on PS 5.1.26100 -- it stayed 0), so the old
    # exit-code test passed and the script printed "Database and user dropped."
    # having run nothing. The database survived an uninstall that said it had
    # not.
    $psql = ''
    $pgBin = 'C:\Program Files\PostgreSQL\16\bin'
    if (Test-Path (Join-Path $pgBin 'psql.exe')) { $psql = Join-Path $pgBin 'psql.exe' }
    else {
        $cmd = Get-Command psql -ErrorAction SilentlyContinue
        if ($cmd) { $psql = $cmd.Source }
    }

    # Identifiers are interpolated into SQL below, so they are constrained to
    # what a PostgreSQL identifier may be. These come from our own .env.local,
    # not from a user, but the rule in CLAUDE.md is absolute and costs one line.
    $identOk = ($dbName -match '^[A-Za-z_][A-Za-z0-9_]*$') -and ($dbUser -match '^[A-Za-z_][A-Za-z0-9_]*$')

    if (-not $psql) {
        Write-Warn "psql.exe not found (looked in $pgBin and on PATH). THE DATABASE WAS NOT DROPPED. Drop it by hand: DROP DATABASE $dbName; DROP USER $dbUser;"
        $leftBehind += "the '$dbName' database and the '$dbUser' role"
    } elseif (-not $PgAdminPassword) {
        Write-Warn "No postgres superuser password available (PG_ADMIN_PASSWORD absent from .env.local and -PgAdminPassword not given). THE DATABASE WAS NOT DROPPED."
        $leftBehind += "the '$dbName' database and the '$dbUser' role"
    } elseif (-not $identOk) {
        Write-Warn "Refusing to build SQL from '$dbName'/'$dbUser' -- not plain identifiers. THE DATABASE WAS NOT DROPPED."
        $leftBehind += "the '$dbName' database and the '$dbUser' role"
    } else {
        $dropped = $false
        try {
            $env:PGPASSWORD = $PgAdminPassword

            # ⛔ Terminate first. DROP DATABASE FAILS while any backend is
            # connected ("is being accessed by other users"), and a stray
            # node.exe or an operator's own psql session is enough. Without this
            # the drop failed for a reason the transcript did not explain.
            $out = Invoke-Native {
                & $psql -U postgres -h localhost -d postgres -c `
                    "SELECT pg_terminate_backend(pid) FROM pg_stat_activity WHERE datname = '$dbName' AND pid <> pg_backend_pid()" 2>&1
            }
            $out | Write-Host

            $out = Invoke-Native { & $psql -U postgres -h localhost -d postgres -c "DROP DATABASE IF EXISTS $dbName" 2>&1 }
            $out | Write-Host
            $dropDbExit = $LASTEXITCODE

            $out = Invoke-Native { & $psql -U postgres -h localhost -d postgres -c "DROP USER IF EXISTS $dbUser" 2>&1 }
            $out | Write-Host
            $dropUserExit = $LASTEXITCODE

            # VERIFY, rather than trusting two exit codes.
            $still = Invoke-Native { & $psql -U postgres -h localhost -d postgres -t -A -c "SELECT count(*) FROM pg_database WHERE datname = '$dbName'" 2>&1 }
            $stillExit = $LASTEXITCODE
            if ($stillExit -eq 0 -and (($still | Select-Object -First 1) -eq '0')) {
                $dropped = $true
                Write-Step "  Database '$dbName' is gone (confirmed by query)."
            } else {
                Write-Warn "Database '$dbName' may still exist (DROP DATABASE exit $dropDbExit, DROP USER exit $dropUserExit, verification exit $stillExit). Check by hand."
                $leftBehind += "possibly the '$dbName' database"
            }
        } catch {
            Write-Warn "Dropping the database threw: $($_.Exception.Message)"
        } finally {
            # ⛔ try/finally: the POSTGRES SUPERUSER password must not survive
            # this step into any later child process or transcript.
            Remove-Item Env:\PGPASSWORD -ErrorAction SilentlyContinue
        }
        if ($dropped) { Write-Step '  Database and role removed.' }
    }

    # ⛔ THE READONLY ROLES ARE DELIBERATELY NOT DROPPED. claude_readonly and
    # nocvault_readonly are CLUSTER-wide roles created by lib\schema-grants.sql,
    # and 'nocvault_readonly' is a suite-wide name that a sibling NocVault app
    # on the same PostgreSQL instance may also be using. Dropping it here would
    # break another product to tidy up this one. They are reported instead.
    $leftBehind += "the cluster roles claude_readonly / nocvault_readonly (shared with other NocVault apps -- drop by hand if this cluster hosts nothing else)"
} else {
    Write-Step 'Skipping database removal (-DropDatabase not specified).'
    $leftBehind += "the '$dbName' database, with every device credential still in it (encrypted)"
}

# -----------------------------------------------------------------------
# 4b. Deploy SSH keys
#
# ⛔ THIS IS A PRIVATE KEY FOR A PRIVATE GIT REPOSITORY, and it is deliberately
# placed OUTSIDE the install tree so the SYSTEM-scheduled updater can reach it.
# Deleting $InstallRoot therefore does not remove it: an uninstalled,
# decommissioned, possibly repurposed machine keeps working credentials to the
# source repository indefinitely.
#
# Only the KEY FILES are removed. The ~\.ssh\config Host entry and the
# known_hosts line are left alone: they are inert without the key, they live in
# a human's own configuration, and rewriting someone's ssh config with a
# -replace -- which does not error when it matches nothing -- is exactly the
# kind of silent half-edit this codebase warns about.
# -----------------------------------------------------------------------
if ($KeepDeployKeys) {
    Write-Step 'Leaving the git deploy keys in place (-KeepDeployKeys).'
    $leftBehind += 'the git deploy SSH private keys (C:\ProgramData\SecVault\ssh\secvault_deploy and %USERPROFILE%\.ssh\secvault_deploy)'
} else {
    Write-Step 'Removing git deploy keys...'
    $keyPaths = @(
        'C:\ProgramData\SecVault\ssh\secvault_deploy',
        (Join-Path $env:USERPROFILE '.ssh\secvault_deploy')
    )
    foreach ($kp in $keyPaths) {
        if (Test-Path -LiteralPath $kp) {
            # ⛔ THE INSTALLER'S OWN HARDENING CAN DEFEAT THIS DELETE, and
            # the thing left behind is a PRIVATE REPOSITORY KEY. Install-SecVault.ps1
            # locks each key with
            #     icacls <key> /inheritance:r /grant:r "<principal>:R"
            # which strips every other ACE and grants READ ONLY -- no DELETE, for
            # anyone. Measured 2026-09-24: both Remove-Item calls failed with
            # "Access to the path is denied" and the uninstaller exited 1 having
            # left the key on a machine it had just declared decommissioned.
            #
            # ⛔ THE ESCALATION IS TRIED ONLY AFTER A PLAIN DELETE FAILS, AND
            # IT IS NOT `icacls /reset`. Two reasons, and the second is the
            # important one:
            #
            #  1. An ELEVATED run usually deletes the file with no help at all --
            #     the parent directories grant FILE_DELETE_CHILD (the installer
            #     hardens the FILES, never the directories), so the unconditional
            #     takeown+icacls was doing nothing on the path that already worked.
            #     The reported failure is only consistent with a NON-ELEVATED run,
            #     where takeown fails for the very same reason the delete did --
            #     so the old remedy could not have helped the case it was written
            #     for. That case is now DETECTED and named instead.
            #
            #  2. ⛔ `/reset` DISCARDS THE HARDENED DACL AND INHERITS THE PARENT'S.
            #     For C:\ProgramData\SecVault\ssh that parent is C:\ProgramData,
            #     whose default ACL includes BUILTIN\Users: Read & Execute. Running
            #     it UNCONDITIONALLY and BEFORE the delete meant that if the delete
            #     then failed for any other reason -- a handle held by the SYSTEM
            #     update task's ssh.exe, AV, a locked profile -- the private key was
            #     left READABLE BY EVERY LOCAL USER, where a moment earlier it had
            #     been SYSTEM + Administrators only. The remedy hardened the path
            #     that already worked and weakened the exact one it was written for.
            #
            # So: delete; if that fails, take ownership and grant DELETE to THIS
            # user alone (/grant:r touches only that principal and leaves
            # /inheritance:r intact, so no new principal is admitted); delete
            # again; and if it is STILL there, PUT THE HARDENING BACK before
            # warning, so a failed uninstall never leaves the key more exposed
            # than it found it.
            $removed = $false
            $escalated = $false
            try {
                Remove-Item -LiteralPath $kp -Force -ErrorAction Stop
                $removed = $true
            } catch {
                $firstErr = $_.Exception.Message
                if (-not (Test-IsElevated)) {
                    Write-Warn ("Could not remove the deploy key at ${kp}: $firstErr. This uninstaller is NOT RUNNING ELEVATED, " +
                                "so it cannot take ownership either. Re-run it as Administrator. A private key for the source repository is still on this machine.")
                } else {
                    $escalated = $true
                    $me = "${env:USERDOMAIN}\${env:USERNAME}"
                    $toOut = Invoke-Native { & takeown.exe /F $kp 2>&1 }
                    $toExit = $LASTEXITCODE
                    if ($toExit -ne 0) { Write-Warn "takeown failed on ${kp} (exit $toExit): $($toOut -join ' ')" }
                    $icOut = Invoke-Native { & icacls.exe $kp /grant:r "${me}:(D,WDAC,RC)" 2>&1 }
                    $icExit = $LASTEXITCODE
                    if ($icExit -ne 0) { Write-Warn "icacls grant failed on ${kp} (exit $icExit): $($icOut -join ' ')" }
                    try {
                        Remove-Item -LiteralPath $kp -Force -ErrorAction Stop
                        $removed = $true
                    } catch {
                        Write-Warn ("Could not remove the deploy key at ${kp}: $($_.Exception.Message). " +
                                    "A private key for the source repository is still on this machine. Remove it by hand with takeown /F, " +
                                    "icacls /grant:r for your own account, then del.")
                    }
                }
            }
            # ⛔ VERIFY, THEN RE-HARDEN IF IT SURVIVED. Remove-Item can
            # report success and leave the file (a pending-delete handle), so the
            # answer is Test-Path, not the absence of an exception.
            if ($removed -and -not (Test-Path -LiteralPath $kp)) {
                Write-Step "  Removed $kp"
            } else {
                if ($removed) { Write-Warn "Deploy key still present at $kp despite a successful delete call" }
                if ($escalated -and (Test-Path -LiteralPath $kp)) {
                    # Put back exactly what Install-SecVault.ps1 set, so the
                    # failure path leaves the key no more readable than before.
                    if ($kp -like 'C:\ProgramData\*') {
                        Invoke-Native { & icacls.exe $kp /inheritance:r /grant:r 'SYSTEM:R' /grant:r 'BUILTIN\Administrators:R' 2>&1 } | Out-Null
                    } else {
                        Invoke-Native { & icacls.exe $kp /inheritance:r /grant:r "${env:USERNAME}:R" 2>&1 } | Out-Null
                    }
                    Write-Warn "Re-applied the read-only ACL to $kp -- it could not be deleted, so it must not be left carrying the widened permissions used to try."
                }
            }
        }
    }
    $machineKeyDir = 'C:\ProgramData\SecVault\ssh'
    if ((Test-Path $machineKeyDir) -and (@(Get-ChildItem -LiteralPath $machineKeyDir -Force -ErrorAction SilentlyContinue).Count -eq 0)) {
        Remove-Item -LiteralPath $machineKeyDir -Force -ErrorAction SilentlyContinue
    }
    Write-Step '  Note: the "Host github.com" entry in ~\.ssh\config and the github.com known_hosts line were left alone -- both are inert without the key.'
}

# -----------------------------------------------------------------------
# 5. Optionally delete install directory (includes the bundled NSSM copy)
# -----------------------------------------------------------------------
$doDelete = $RemoveInstallDir
if (-not $doDelete -and -not $Yes) {
    $deleteConfirm = Read-Host "Also delete $InstallRoot entirely? This is IRREVERSIBLE DATA LOSS (logs, config, .env.local, bundled NSSM). [y/N]"
    $doDelete = ($deleteConfirm -eq 'y' -or $deleteConfirm -eq 'Y')
}

if ($doDelete) {
    Write-Step "Deleting $InstallRoot..."
    if (Test-Path $InstallRoot) {
        # ⛔ NOT -ErrorAction SilentlyContinue, AND THE RESULT IS RE-TESTED.
        # Remove-Item stops at the first file another process still holds and
        # leaves the rest -- with $ErrorActionPreference at Continue it prints
        # one red line that scrolls away and carries on to the success message.
        # The old code then printed "$InstallRoot deleted." over a directory
        # that still contained .env.local, i.e. CREDENTIAL_KEY in cleartext on a
        # machine somebody now believes is clean.
        try { Remove-Item -Recurse -Force -Confirm:$false -Path $InstallRoot -ErrorAction Stop }
        catch { Write-Warn "Remove-Item reported: $($_.Exception.Message)" }

        if (Test-Path $InstallRoot) {
            $stragglers = @(Get-ChildItem -LiteralPath $InstallRoot -Recurse -Force -File -ErrorAction SilentlyContinue)
            Write-Warn "$InstallRoot STILL EXISTS with $($stragglers.Count) file(s). Usually a node.exe still holding a file, or an open log. Reboot and delete it by hand."
            if (Test-Path (Join-Path $InstallRoot '.env.local')) {
                # ⛔ NO NON-ASCII GLYPH INSIDE A DOUBLE-QUOTED STRING IN A .ps1.
                # PowerShell 5.1 reads a BOM-less script as the system ANSI code
                # page, and the third UTF-8 byte of the no-entry sign decodes to
                # U+201D -- a character PowerShell ACCEPTS AS A CLOSING DOUBLE
                # QUOTE. The string terminates mid-sentence and the whole file
                # fails to parse. (Verified: it broke this file.) The glyph is
                # safe in comments and in single-quoted strings; this file also
                # carries a UTF-8 BOM so it decodes correctly either way, and
                # this line does not depend on that.
                Write-Warn 'STOP: .env.local IS STILL THERE. It contains CREDENTIAL_KEY, the database password and the postgres superuser password in cleartext. Delete it before this machine leaves your control.'
            }
            $leftBehind += "$InstallRoot (deletion did not complete)"
        } else {
            Write-Step "$InstallRoot deleted (confirmed)."
        }
    } else {
        Write-Step "$InstallRoot does not exist -- nothing to delete."
    }
} else {
    Write-Step "Leaving $InstallRoot in place."
    $leftBehind += "$InstallRoot, including .env.local -- which holds CREDENTIAL_KEY, the database password and the postgres superuser password in cleartext"
}

# -----------------------------------------------------------------------
# 6. ⛔ THE CLOSING INVENTORY -- what this uninstall did NOT remove
#
# These are on other volumes, are frequently the only surviving copy of the
# fleet's data, and are NEVER deleted here at any switch. An uninstaller that
# silently took them would be unrecoverable; one that silently left them would
# leave the credential-encryption key sitting beside the credentials it
# decrypts. Printing them is the only honest option.
# -----------------------------------------------------------------------
if (Test-Path $backupDirGuess) {
    $sets = @(Get-ChildItem -Path $backupDirGuess -Filter 'secvault-*.dump' -ErrorAction SilentlyContinue)
    # See the note in step 5: no non-ASCII glyph inside a double-quoted string.
    $leftBehind += "$backupDirGuess -- $($sets.Count) backup set(s). WARNING: these contain a copy of .env.local (CREDENTIAL_KEY) and possibly the TLS PRIVATE KEY, beside the encrypted credentials they decrypt. They are also the ONLY remaining copy of this installation's data. Keep them somewhere ACL'd, or destroy them deliberately -- nothing here touched them."
}
if ($archiveDir -and (Test-Path $archiveDir)) {
    $leftBehind += "$archiveDir -- the compressed raw syslog archive (hundreds of GB typically). Not touched."
}
if ($spoolDir -and (Test-Path $spoolDir) -and ($spoolDir -notlike "$InstallRoot*")) {
    $leftBehind += "$spoolDir -- the syslog spool, outside the install tree. Not touched."
}

Write-Host ''
Write-Host '=================================================='
if ($problems.Count -gt 0) {
    Write-Host ' SecVault uninstall finished WITH PROBLEMS:' -ForegroundColor Yellow
    foreach ($p in $problems) { Write-Host "   - $p" -ForegroundColor Yellow }
} else {
    Write-Host ' SecVault uninstall complete.'
}
if ($leftBehind.Count -gt 0) {
    Write-Host ''
    Write-Host ' STILL ON THIS MACHINE (deliberately -- decide about each):'
    foreach ($l in $leftBehind) { Write-Host "   - $l" }
}
Write-Host '=================================================='

# ⛔ A non-zero exit is the only signal available to whatever ran this. Ending 0
# over a service still registered or an .env.local still on disk would report a
# clean decommission that did not happen.
if ($problems.Count -gt 0) { exit 1 }
exit 0
