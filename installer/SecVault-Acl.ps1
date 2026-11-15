#requires -Version 5.1
<#
    SecVault-Acl.ps1 -- ONE definition of "lock this data directory down to
    SYSTEM and Administrators", dot-sourced by Install-SecVault.ps1 and
    Update-SecVault.ps1.

    ── ⛔ WHY THIS FILE EXISTS ──────────────────────────────────────────────

    ⛔ v2.225.3 FIXED ONE OF THREE SECVAULT-CREATED DATA DIRECTORIES, AND
    CLAUDE.md's OWN SENTENCE -- '"ACL IT" WAS A DOCUMENTED REQUIREMENT WITH NO
    CODE BEHIND IT' -- BECAME TRUE AGAIN FOR THE OTHER TWO. That release
    hardened `E:\SecVaultBackup` and verified it; `icacls` then appeared in
    exactly one installer script. The spool and the archive are created with a
    bare `New-Item` and have never been restricted at all.

    ⛔ MEASURED ON PRODUCTION 2026-11-15, read-only, before anything was
    changed:

        E:\                    BUILTIN\Users:(OI)(CI)(RX)   <- still permissive
                               Everyone:(RX)
                               BUILTIN\Users:(CI)(AD)       <- create files
                               BUILTIN\Users:(CI)(WD)       <- create folders

        E:\SecVaultBackup      inheritance broken     (v2.225.3)   OK
        E:\SecVault_Backups    inheritance broken     (by hand)    OK
        E:\PostgreSQL\16\data  inheritance broken     (installer)  OK
        E:\SecVaultArchive     BUILTIN\Users:(I)(OI)(CI)(RX)       EXPOSED
        E:\SecVaultSpool       BUILTIN\Users:(I)(OI)(CI)(RX)+AD+WD EXPOSED

    Confirmed on a real file, not just the container:
    `E:\SecVaultArchive\syslog-20261001.log.gz` grants `BUILTIN\Users:(I)(RX)`.

    ⛔ THE ARCHIVE IS NOT A CACHE, IT IS THE ONLY COPY. With
    `SYSLOG_RAW_MESSAGE=security` the database keeps the raw line for ~11% of
    rows, and the compressed archive is the sole remaining copy of the rest --
    the threat/vpn/utm/denied events specifically, i.e. the ones carrying
    usernames, internal addresses and URLs. 211 GB of the fleet's security
    telemetry, readable by every local non-admin account.

    ⛔ AND THE SPOOL IS A WRITE VECTOR, WHICH IS WORSE THAN A READ. The volume
    root's `(CI)(AD)`/`(CI)(WD)` reach it, so a non-admin can CREATE files in
    the spool tree -- and `services/collector.js` REPLAYS any `.ready` file it
    finds there at startup. That is arbitrary injection into `syslog_events`,
    i.e. into the evidence behind `log_hit` (decision rule 2 of the CVE
    priority tree, above CVSS 9.0), `hit_count` and every rule-usage finding.
    Fabricated evidence is a worse outcome than leaked evidence.

    ⛔ IT IS THE WINDOWS DEFAULT FOR A NON-SYSTEM VOLUME ROOT, WHICH IS EXACTLY
    WHY IT NEEDS CODE. Nothing misconfigured this server; `New-Item` on `E:\`
    inherits that ACL and SecVault never narrowed it. The same will happen on
    every customer volume that is not `C:`.

    ── ⛔ THE RULES, each learned the expensive way ─────────────────────────

    ⛔ `/inheritance:r` IS WHAT DOES THE WORK, NOT THE GRANTS. Every offending
    ACE is INHERITED (`(I)`), so granting rights without breaking inheritance
    changes nothing at all.

    ⛔ IT RUNS ON EVERY INSTALL *AND EVERY UPDATE*, NOT ONLY AT CREATION. Every
    deployed server already has these directories, so a create-time fix reaches
    FRESH INSTALLS ONLY -- the `CREATE TABLE IF NOT EXISTS` trap, where the diff
    looks correct and no installation in the field is ever repaired. That is the
    single most important property here, because the backup directory got its
    fix on a nightly job that self-repairs and these two have no such job.
    icacls is idempotent, so the healthy case is one cheap call.

    ⛔ VERIFIED, NOT ASSUMED. A zero exit says icacls RAN, not that the
    resulting ACL is what was asked for. The only fact that matters is whether
    a non-admin principal can still reach the directory, so the result is
    re-read and matched.

    ⛔ IT WARNS AND KEEPS GOING; IT NEVER THROWS. For the spool this is not a
    preference: refusing to proceed would stop the collector, and while it is
    down the datagrams are not queued, they are GONE (nothing is listening on
    514 and UDP has no retry). Trading a conditional read exposure for certain,
    permanent loss of security events is the wrong way round. Callers surface
    the failure instead -- the page-sweep precedent in Update-SecVault.ps1.

    ⛔ SYSTEM KEEPS FULL CONTROL, so nothing SecVault does is lost: all three
    services run as LocalSystem (`sc.exe qc` -- corrected in CLAUDE.md
    2026-10-19, they are NOT limited accounts).

    ⛔ IT DOES NOT CREATE THE DIRECTORY. An absent path is reported and skipped:
    creating one here would mask a wrong `SYSLOG_SPOOL_DIR` by silently making
    an empty directory look healthy, and the installer's own `-SpoolDir`
    handling is where creation belongs.

    ⛔ NOT MIGRATED: Backup-SecVault.ps1 KEEPS ITS INLINE COPY, deliberately.
    `tests/backupScripts.test.js` pins that block by TEXT -- `'/inheritance:r'`
    as a literal, `$aclCheck = Invoke-Native`, and its ORDER relative to the
    pg_dump and the CREDENTIAL_KEY copy. Routing it through this file would
    break those assertions, and weakening a guard that protects
    `CREDENTIAL_KEY` to accommodate a refactor is the wrong trade. The
    duplication is named here and in that file rather than left to be
    discovered; unifying it means converting that guard to a behavioural one
    first, which is its own piece of work (roadmap row 68).
#>

# ⛔ DOT-SOURCED, SO IT DELIBERATELY DOES NOT DEFINE ITS OWN Invoke-Native --
# one copy, two callers, so they cannot drift. Same contract as
# SecVault-Tls.ps1, and tests/installerNativeCalls.test.js exempts both from
# the "defines its own helper" assertion for exactly this reason while still
# requiring the ROUTING below.

function Protect-SecVaultDirectory {
    <#
    .SYNOPSIS
        Restrict a SecVault data directory to SYSTEM and Administrators.
    .OUTPUTS
        $true  -- the directory is restricted and that was VERIFIED
        $false -- it is not (absent, icacls failed, or a non-admin ACE survived)
    #>
    [CmdletBinding()]
    param(
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Path,
        [Parameter(Mandatory = $true)][string]$Label,
        [Parameter(Mandatory = $true)][scriptblock]$Logger
    )

    $say = { param($m) & $Logger $m }

    if ([string]::IsNullOrWhiteSpace($Path)) {
        & $say "  [WARN] $Label directory is not configured -- nothing to restrict."
        return $false
    }
    if (-not (Test-Path -LiteralPath $Path)) {
        # Not an error on a fresh install that has not started the collector yet.
        & $say "  $Label directory does not exist yet at $Path -- nothing to restrict."
        return $false
    }

    $aclArgs = @(
        $Path, '/inheritance:r',
        '/grant:r', 'NT AUTHORITY\SYSTEM:(OI)(CI)F',
        '/grant:r', 'BUILTIN\Administrators:(OI)(CI)F'
    )
    $aclOut = Invoke-Native { & icacls.exe @aclArgs 2>&1 }
    $aclExit = $LASTEXITCODE
    if ($aclExit -ne 0) {
        & $say "  [FAIL] Could not restrict $Label at $Path (icacls exit $aclExit): $($aclOut -join ' ')"
        return $false
    }

    # ⛔ VERIFY. See the header: a zero exit means icacls ran.
    $aclCheck = Invoke-Native { & icacls.exe $Path 2>&1 }
    $aclText = ($aclCheck -join ' ')
    if ($aclText -match 'BUILTIN\\Users|\bEveryone\b|Authenticated Users|\bINTERACTIVE\b') {
        # ⛔ AN EXPLICIT ACE SURVIVES THIS AND IS NAMED RATHER THAN GUESSED AT.
        # `/inheritance:r` removes INHERITED ACEs and `/grant:r` only replaces
        # the grants for the principals it names, so a non-admin ACE set
        # DIRECTLY on this directory outlives both. Found 2026-11-15 by
        # exercising this function on Windows rather than by reading it: the
        # first draft of its test granted `BUILTIN\Users` explicitly, the
        # lockdown reported FAIL, and the verify step was the only reason that
        # was visible at all.
        #
        # ⛔ IT IS REPORTED, NOT STRIPPED. Removing every unrecognised principal
        # would be determinate but could silently cut off something a customer
        # legitimately granted -- a backup agent's service account, a monitoring
        # reader -- and breaking a customer's backup to tidy an ACL is the wrong
        # trade. Production's exposure is entirely INHERITED (`(I)` on every
        # offending ACE, measured), which this DOES fix; an explicit grant is
        # somebody's decision and needs a human to reverse it.
        $explicit = @()
        foreach ($p in @('BUILTIN\Users', 'Everyone', 'Authenticated Users', 'INTERACTIVE')) {
            # An `(I)` prefix marks an inherited ACE; anything still here after
            # /inheritance:r without one was set directly.
            $escaped = [regex]::Escape($p)
            if ($aclText -match ($escaped + ':\(')) { $explicit += $p }
        }
        $who = '(could not parse the principals)'
        if ($explicit.Count -gt 0) { $who = ($explicit -join ', ') }
        & $say "  [FAIL] $Label at $Path STILL grants a non-admin principal after lockdown: $who"
        & $say "         These are EXPLICIT ACEs, not inherited ones, so breaking inheritance did not remove them. Review and remove deliberately, e.g.  icacls `"$Path`" /remove:g `"BUILTIN\Users`"  -- check first that nothing legitimate depends on the access."
        & $say "         Full ACL: $aclText"
        return $false
    }

    & $say "  $Label restricted to SYSTEM and Administrators, inheritance broken ($Path)."
    return $true
}
