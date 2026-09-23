<#
.SYNOPSIS
    Builds the SecVault distribution FOLDER an operator copies to a server.

.DESCRIPTION
    Produces dist\SecVault-Installer-v<version>\ :

        Install-SecVault.cmd      double-click; elevates, then runs the installer
        SecVault-Setup.exe        the same, for operators who expect an .exe
        installer\*.ps1           installer, updater, backup, restore, TLS helper
        installer\dependencies\   the bundled prerequisite installers
        app\                      the application source, including node_modules

    ⛔ A FOLDER, NOT A SINGLE SELF-EXTRACTING .exe, AND THE REASON IS MEASURED.
    The previous design embedded a ~500 MB payload as a managed resource inside
    a compiled stub. It worked, and it cost 555 MB, ~12 minutes, a 750 MB
    staging copy and a csc process at 1.4 GB working set -- and TWO consecutive
    builds were killed by the host for memory pressure, one of them leaving a
    555 MB file 436 bytes short of a valid assembly that threw
    BadImageFormatException on load. An artifact that looks finished and is not
    is the worst thing a release step can produce.

    It is also the shape the NocVault suite already ships
    (C:\NocVault-Suite-v1.2): scripts and small launchers beside a
    dependencies\ directory. Following it costs nothing and gains consistency.

    ⛔ WHAT THIS DOES DIFFERENTLY FROM THE SUITE, DELIBERATELY: the suite
    `git clone`s each app at install time, so it needs network access and a
    credential for a private repo. This ships app\ inside the folder, so an
    install needs neither -- CLAUDE.md names segmented and air-gapped networks
    as the TARGET customer, not an edge case. Install-SecVault.ps1 detects a
    bundled tree and installs from it.

    ⛔ NO DEPLOY KEY IS INCLUDED unless you put one in dependencies\ yourself.
    Anyone holding a copy would have permanent read access to the private
    repository, and a key cannot be un-distributed. The consequence -- no git
    remote, so no in-place update -- is printed by the installer and written
    into the folder's README rather than left to be discovered.

.PARAMETER OutputPath
    Folder to create. Defaults to dist\SecVault-Installer-v<version>.

.PARAMETER DependenciesPath
    Where the prerequisite installers live. Defaults to installer\dependencies.

.PARAMETER IncludeNodeModules
    Default $true. $false makes a much smaller folder that REQUIRES the target
    to reach registry.npmjs.org.

.PARAMETER AllowDirty
    Build from a working tree with uncommitted changes, or one whose commit
    cannot be determined. Off by default: an artifact nobody can tie back to a
    commit cannot be supported.

.PARAMETER Zip
    Also produce a .zip of the folder. OFF BY DEFAULT -- compressing ~750 MB is
    the most memory-hungry thing this script can do, and it is exactly what got
    the old design killed mid-build. Copy the folder instead, or zip it when
    the machine is quiet.

.EXAMPLE
    .\installer\Build-SecVaultPackage.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$DependenciesPath,
    [bool]$IncludeNodeModules = $true,
    [switch]$AllowDirty,
    [switch]$SkipDependencyCheck,
    [switch]$Zip
)

$ErrorActionPreference = 'Stop'

$script:StepNo = 0
function Write-Step {
    param([string]$Message)
    $script:StepNo += 1
    Write-Host ("[{0}] {1}" -f $script:StepNo, $Message) -ForegroundColor Cyan
}
function Write-Note { param([string]$m) Write-Host "    $m" -ForegroundColor DarkGray }
function Write-Warn { param([string]$m) Write-Host "    [WARN] $m" -ForegroundColor Yellow }
function Fail {
    param([string]$Message)
    Write-Host ''
    Write-Host "BUILD FAILED: $Message" -ForegroundColor Red
    Write-Host ''
    exit 1
}

# ⛔ A native call under $ErrorActionPreference='Stop' throws on ordinary stderr
# output even when the command exited 0, and git writes progress to stderr
# routinely. Same helper, same reason, as Update-SecVault.ps1.
function Invoke-Native {
    param([scriptblock]$Command)
    $prev = $ErrorActionPreference
    $ErrorActionPreference = 'Continue'
    try { & $Command } finally { $ErrorActionPreference = $prev }
}

$repoRoot = Split-Path -Parent $PSScriptRoot
if (-not (Test-Path (Join-Path $repoRoot 'package.json'))) {
    Fail "package.json not found above $PSScriptRoot -- run this from inside the repo."
}

Write-Host ''
Write-Host '===============================================================' -ForegroundColor White
Write-Host '  SecVault -- build the installer distribution folder' -ForegroundColor White
Write-Host '===============================================================' -ForegroundColor White
Write-Host ''

# -----------------------------------------------------------------------
Write-Step 'Reading version and commit'
# -----------------------------------------------------------------------
$pkg = Get-Content (Join-Path $repoRoot 'package.json') -Raw | ConvertFrom-Json
$version = $pkg.version
if (-not $version) { Fail 'package.json has no version.' }

# ⛔ git is RESOLVED, never invoked as a bare name, and its absence is not
# fatal. `& git` raises CommandNotFoundException when it cannot be resolved,
# and that once aborted a whole build at step 1 on a machine where git WAS
# installed and in the MACHINE path -- just not in the already-open shell's
# copy of it, which is the normal state of any console opened before a
# provisioning run. Same approach as Find-SecVaultOpenSsl.
function Find-SecVaultGit {
    foreach ($candidate in @(
        'C:\Program Files\Git\cmd\git.exe',
        'C:\Program Files\Git\bin\git.exe',
        'C:\Program Files (x86)\Git\cmd\git.exe'
    )) {
        if (Test-Path $candidate) { return $candidate }
    }
    $onPath = Get-Command git -ErrorAction SilentlyContinue
    if ($onPath) { return $onPath.Source }
    return $null
}

$commit = 'unknown'
$dirty = $false
$gitExe = Find-SecVaultGit
if (-not $gitExe) {
    Write-Warn 'git not found, so the commit cannot be recorded; it will be stamped "unknown".'
} else {
    Push-Location $repoRoot
    try {
        $rev = Invoke-Native { & $gitExe rev-parse --short HEAD 2>$null }
        if ($LASTEXITCODE -eq 0 -and $rev) { $commit = ($rev | Select-Object -First 1).ToString().Trim() }
        $status = Invoke-Native { & $gitExe status --porcelain 2>$null }
        if ($LASTEXITCODE -eq 0 -and $status) { $dirty = $true }
    } catch {
        Write-Warn "git could not report the commit ($($_.Exception.Message)); stamping 'unknown'."
    } finally { Pop-Location }
}

Write-Note "version : $version"
Write-Note "commit  : $commit"

# ⛔ An artifact that cannot be tied to a commit cannot be supported: when the
# customer reports a fault there is no way to know what they are running.
if (($dirty -or $commit -eq 'unknown') -and -not $AllowDirty) {
    Fail 'The working tree is dirty, or the commit could not be determined. Commit your changes (or install git), or pass -AllowDirty and accept an artifact that matches no commit.'
}
if ($dirty) { Write-Warn 'Working tree is DIRTY -- this package matches no commit.' }

# -----------------------------------------------------------------------
Write-Step 'Checking the build host matches the target'
# -----------------------------------------------------------------------
# ⛔ node_modules is COPIED, not reinstalled, so the tree must already be the
# right platform. A macOS or Linux tree carries a different @next/swc binary
# and Next fails at startup naming neither this script nor the real cause.
if ($IncludeNodeModules) {
    $nmPath = Join-Path $repoRoot 'node_modules'
    if (-not (Test-Path $nmPath)) {
        Fail "node_modules not found. Run 'npm ci' first, or pass -IncludeNodeModules:`$false."
    }
    if (-not (Test-Path (Join-Path $nmPath '@next\swc-win32-x64-msvc'))) {
        Fail "node_modules does not contain @next/swc-win32-x64-msvc, so it was not installed on Windows x64. Re-run 'npm ci' on a Windows x64 host, or pass -IncludeNodeModules:`$false."
    }
    $nodeV = Invoke-Native { & node -v 2>$null }
    if ($LASTEXITCODE -eq 0 -and $nodeV) {
        $nodeV = ($nodeV | Select-Object -First 1).ToString().Trim()
        Write-Note "node on this host : $nodeV"
        if ($nodeV -notlike 'v20.*') {
            Write-Warn "node_modules was installed under $nodeV but the bundled runtime is Node 20."
        }
    }
}

# -----------------------------------------------------------------------
Write-Step 'Verifying the prerequisite bundle'
# -----------------------------------------------------------------------
if (-not $DependenciesPath) { $DependenciesPath = Join-Path $PSScriptRoot 'dependencies' }
if (-not (Test-Path $DependenciesPath)) { Fail "Dependencies folder not found: $DependenciesPath" }

# Patterns, not exact names: the versions move, the roles do not.
$required = @(
    @{ Role = 'Node.js runtime';      Pattern = 'node-v*-x64.msi';               Required = $true },
    @{ Role = 'PostgreSQL 16';        Pattern = 'postgresql-16*windows-x64.exe'; Required = $true },
    @{ Role = 'NSSM service manager'; Pattern = 'nssm-*.zip';                    Required = $true },
    @{ Role = 'Git for Windows';      Pattern = 'Git-*-64-bit.exe';              Required = $true },
    @{ Role = 'VC++ runtime';         Pattern = 'VC_redist.x64.exe';             Required = $false }
)

$missing = @()
$found = @()
foreach ($r in $required) {
    $hit = Get-ChildItem -Path $DependenciesPath -Filter $r.Pattern -File -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($hit) {
        $found += $hit
        Write-Note ("ok       {0,-22} {1} ({2:N0} MB)" -f $r.Role, $hit.Name, ($hit.Length / 1MB))
    } elseif ($r.Required) {
        $missing += $r
        Write-Host ("    MISSING  {0,-22} expected {1}" -f $r.Role, $r.Pattern) -ForegroundColor Red
    } else {
        Write-Warn ("optional {0,-22} not present -- the installer skips it" -f $r.Role)
    }
}
if ($missing.Count -gt 0) {
    # ⛔ A PACKAGE MISSING A PREREQUISITE IS WORSE THAN NO PACKAGE: it ships, it
    # runs, and it fails partway through provisioning a customer's server.
    if ($SkipDependencyCheck) {
        Write-Warn 'SkipDependencyCheck: building an INCOMPLETE folder that WILL fail on a clean server.'
    } else {
        Write-Host ''
        Write-Host '  Copy them from the NocVault-Suite distribution; see' -ForegroundColor Yellow
        Write-Host "  $DependenciesPath\README.txt for the list." -ForegroundColor Yellow
        Fail "$($missing.Count) required prerequisite installer(s) missing from $DependenciesPath"
    }
}

$deployKey = Join-Path $DependenciesPath 'secvault_deploy'
$hasDeployKey = Test-Path $deployKey

# -----------------------------------------------------------------------
Write-Step 'Creating the distribution folder'
# -----------------------------------------------------------------------
if (-not $OutputPath) {
    $OutputPath = Join-Path $repoRoot ("dist\SecVault-Installer-v{0}" -f $version)
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)

# ⛔ Refuse to write into a folder holding something else: a partial overlay of
# two versions is a package nobody can reason about afterwards.
if (Test-Path $OutputPath) {
    $existing = @(Get-ChildItem $OutputPath -Force -ErrorAction SilentlyContinue)
    if ($existing.Count -gt 0) {
        if (-not (Test-Path (Join-Path $OutputPath 'installer\Install-SecVault.ps1'))) {
            Fail "$OutputPath is not empty and does not look like a SecVault package. Refusing to overwrite it."
        }
        Write-Note 'replacing the previous build of this version...'
        Remove-Item $OutputPath -Recurse -Force
    }
}
New-Item -ItemType Directory -Path $OutputPath -Force | Out-Null
$appDir = Join-Path $OutputPath 'app'
$instDest = Join-Path $OutputPath 'installer'

# ⛔ NEVER PACKAGE THESE. `.env.local` holds CREDENTIAL_KEY, the database
# password and NEXTAUTH_SECRET; certs\ holds a private key. Shipping any of them
# turns one server's secrets into every customer's. A scan below re-checks the
# result, because an exclusion list is only as good as the next person's edit.
$excludeDirs = @('node_modules', '.next', '.git', 'certs', 'logs', 'spool', 'archive', 'dist', 'coverage')
$excludeFiles = @('.env.local', '.env', '*.pfx', '*.key', '*.pem', 'secvault_deploy', 'secvault_deploy.pub')

Write-Note 'copying application source...'
# ⛔ robocopy, NOT `Get-ChildItem -Recurse | Copy-Item`: the latter enumerates
# the WHOLE tree before any filter runs, so it walks every node_modules entry
# just to discard it, and raises a MAX_PATH failure that aborts under 'Stop'.
# ⛔ robocopy exit codes BELOW 8 ARE SUCCESS (1 = copied, 2 = extras, 3 = both);
# treating any non-zero as failure would fail every build that did something.
$xd = @()
foreach ($d in $excludeDirs) { $xd += (Join-Path $repoRoot $d) }
$xd += (Join-Path $repoRoot 'installer\dependencies')
$roboArgs = @($repoRoot, $appDir, '/E', '/NFL', '/NDL', '/NJH', '/NJS', '/NC', '/NS', '/NP', '/R:1', '/W:1')
$roboArgs += '/XD'; $roboArgs += $xd
$roboArgs += '/XF'; $roboArgs += $excludeFiles
Invoke-Native { & robocopy @roboArgs } | Out-Null
if ($LASTEXITCODE -ge 8) { Fail "robocopy failed copying the source tree (exit $LASTEXITCODE)." }
Write-Note ("  {0:N0} source files" -f (Get-ChildItem $appDir -Recurse -File -Force -ErrorAction SilentlyContinue).Count)

if ($IncludeNodeModules) {
    Write-Note 'copying node_modules (this takes a minute)...'
    $nmDest = Join-Path $appDir 'node_modules'
    Invoke-Native { & robocopy (Join-Path $repoRoot 'node_modules') $nmDest /E /NFL /NDL /NJH /NJS /NC /NS /NP /R:1 /W:1 } | Out-Null
    if ($LASTEXITCODE -ge 8) { Fail "robocopy failed copying node_modules (exit $LASTEXITCODE)." }
    Write-Note ("  {0:N0} files" -f (Get-ChildItem $nmDest -Recurse -File -ErrorAction SilentlyContinue).Count)

    # ⛔ THE MARKER IS WHAT MAKES THE OFFLINE INSTALL REAL. Install-SecVault.ps1
    # skips `npm ci` ONLY when this file is present and its version matches the
    # package.json beside it, so shipping node_modules without it buys nothing.
    # The version match stops one build's tree being used against another
    # build's source, which resolves, starts, and runs the wrong code.
    $marker = @(
        "# Written by installer\Build-SecVaultPackage.ps1. Do not edit.",
        "# Install-SecVault.ps1 skips 'npm ci' when version= matches its package.json.",
        "version=$version",
        "commit=$commit",
        "built=$((Get-Date).ToString('o'))"
    ) -join "`r`n"
    Set-Content -Path (Join-Path $nmDest '.secvault-bundled') -Value $marker -Encoding ASCII
    Write-Note "  offline marker written (version $version)"
}

Write-Note 'copying the installer scripts...'
New-Item -ItemType Directory -Path $instDest -Force | Out-Null
Get-ChildItem $PSScriptRoot -Filter '*.ps1' -File | ForEach-Object {
    Copy-Item $_.FullName (Join-Path $instDest $_.Name) -Force
}

Write-Note 'copying the prerequisite installers...'
$depDest = Join-Path $instDest 'dependencies'
New-Item -ItemType Directory -Path $depDest -Force | Out-Null
foreach ($f in $found) { Copy-Item $f.FullName $depDest -Force }
$readmeSrc = Join-Path $DependenciesPath 'README.txt'
if (Test-Path $readmeSrc) { Copy-Item $readmeSrc $depDest -Force }
if ($hasDeployKey) {
    Copy-Item $deployKey $depDest -Force
    Write-Warn 'secvault_deploy (a PRIVATE repo key) IS included. Do not hand this folder to a customer.'
}

# -----------------------------------------------------------------------
Write-Step 'Scanning the package for secrets'
# -----------------------------------------------------------------------
# ⛔ THIS IS THE POINT OF THE EXCLUSION LIST, NOT A DUPLICATE OF IT. The list
# above is what we MEANT to exclude; this is what actually landed. Handing a
# folder to somebody is irreversible, so the check runs against the result.
$leaks = @()
Get-ChildItem $appDir -Recurse -File -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\node_modules\\' } | ForEach-Object {
        $n = $_.Name
        if ($n -eq '.env.local' -or $n -eq '.env' -or $n -eq 'secvault_deploy' -or
            $n -like '*.pem' -or $n -like '*.pfx' -or $n -like '*.key') {
            $leaks += $_.FullName.Substring($OutputPath.Length)
        }
    }
if ($leaks.Count -gt 0) {
    $leaks | ForEach-Object { Write-Host "    LEAK  $_" -ForegroundColor Red }
    Fail "$($leaks.Count) secret-bearing file(s) reached the package. Refusing to ship it."
}
Write-Note 'no secret-bearing files in the package.'

# -----------------------------------------------------------------------
Write-Step 'Writing the launchers'
# -----------------------------------------------------------------------
# ⛔ THE .cmd SELF-ELEVATES rather than telling the operator to. This registers
# services, installs MSIs and opens firewall rules; a non-elevated run gets
# most of the way in and fails on the first service call, leaving a half-built
# machine and an error naming none of that.
$cmdText = @"
@echo off
setlocal
title SecVault Setup $version

net session >nul 2>nul
if errorlevel 1 (
  echo.
  echo  Requesting administrator rights...
  powershell -NoProfile -ExecutionPolicy Bypass -Command "Start-Process -FilePath '%~f0' -Verb RunAs"
  exit /b
)

echo.
echo  ===============================================================
echo    SecVault Setup   version $version   commit $commit
echo  ===============================================================
echo.

powershell -NoProfile -ExecutionPolicy Bypass -File "%~dp0installer\Install-SecVault.ps1" %*
set RC=%ERRORLEVEL%
echo.
if not "%RC%"=="0" echo  Setup exited with code %RC%.
echo.
pause
exit /b %RC%
"@
Set-Content -Path (Join-Path $OutputPath 'Install-SecVault.cmd') -Value $cmdText -Encoding ASCII

# A small .exe beside it for operators who expect one. It carries NO payload --
# it only starts the .cmd -- so it compiles in about a second and costs no
# memory, unlike the embedded-resource design this replaced.
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (Test-Path $csc) {
    $stub = @'
using System;
using System.Diagnostics;
using System.IO;
using System.Reflection;
static class SecVaultSetup {
    static int Main(string[] args) {
        string dir = Path.GetDirectoryName(Assembly.GetExecutingAssembly().Location);
        string cmd = Path.Combine(dir, "Install-SecVault.cmd");
        if (!File.Exists(cmd)) {
            Console.WriteLine("Install-SecVault.cmd is missing from " + dir + ".");
            Console.WriteLine("Keep this .exe inside the SecVault installer folder.");
            Console.Write("Press Enter to close..."); Console.ReadLine();
            return 1;
        }
        string pass = ""; foreach (string a in args) pass += " \"" + a + "\"";
        var psi = new ProcessStartInfo("cmd.exe", "/c \"" + cmd + "\"" + pass);
        psi.UseShellExecute = false; psi.WorkingDirectory = dir;
        using (Process p = Process.Start(psi)) { p.WaitForExit(); return p.ExitCode; }
    }
}
'@
    $stubPath = Join-Path $env:TEMP ("secvault-stub-" + [Guid]::NewGuid().ToString('N').Substring(0, 8) + '.cs')
    Set-Content -Path $stubPath -Value $stub -Encoding UTF8
    $exeOut = Join-Path $OutputPath 'SecVault-Setup.exe'
    Invoke-Native { & $csc '/nologo' '/target:exe' '/platform:anycpu' ('/out:"{0}"' -f $exeOut) ('"{0}"' -f $stubPath) } | Out-Null
    Remove-Item $stubPath -Force -ErrorAction SilentlyContinue
    if (Test-Path $exeOut) {
        Write-Note ("SecVault-Setup.exe ({0:N0} KB)" -f ((Get-Item $exeOut).Length / 1KB))
    } else {
        Write-Warn 'the .exe launcher did not build; Install-SecVault.cmd works on its own.'
    }
} else {
    Write-Warn 'csc.exe not found; shipping Install-SecVault.cmd without an .exe launcher.'
}

# ⛔ A DEPLOY KEY DOES NOT MAKE IN-PLACE UPDATES WORK, AND SAYING SO WOULD BE
# A DOCUMENTED CONTROL THAT DOES NOT EXIST. This README used to claim that a
# bundled key enabled Settings -> Update. It does not: $excludeDirs drops
# .git, so a packaged installation has NO REPOSITORY AT ALL, and
# Update-SecVault.ps1 step 3 is Already up to date.. A key without a repo
# to pull into changes nothing. The key is still worth shipping internally --
# it is what a later Reinitialized existing Git repository in C:/Users/amrin/Documents/Nocvault/secvault/.git// would need -- but on its own it
# buys no update path, and an operator told otherwise finds out when they need
# the update most.
$updateLine = if ($hasDeployKey) {
    "  A deploy key IS included -- do not hand this folder to a customer.
  It does NOT by itself enable in-place updates: this package ships no
  .git directory, so there is no repository for Update-SecVault.ps1 to
  pull into. Update by running a newer copy of this installer folder,
  or clone the repo over the install and then use the updater."
} else {
    "  No deploy key is included, and this package ships no .git directory,
  so the installation has no repository to pull into: Settings -> Update
  and installer\Update-SecVault.ps1 cannot fetch a new version.
  Update it by running a newer copy of this installer folder."
}

$readmeText = @"
SecVault $version   (commit $commit)
===============================================================

TO INSTALL
  Copy this WHOLE FOLDER to the server, then run Install-SecVault.cmd
  (or SecVault-Setup.exe). It asks for administrator rights itself.

  It offers this machine's own addresses for the console and lets you
  pick one from a list -- you do not need to know it in advance.

WHAT IS IN HERE
  app\                      the application, including node_modules
  installer\                installer, updater, backup, restore, TLS helper
  installer\dependencies\   Node, PostgreSQL, NSSM, Git, VC++ runtime

OFFLINE
  Nothing here needs the internet: the application and all of its
  dependencies are included.

UPDATES
$updateLine

UNATTENDED
  Install-SecVault.cmd -ServerIp 10.0.0.10 -SyslogPorts 514 -Unattended

BEFORE THE FIRST RUN
  Read app\docs\FRESH-INSTALL-CHECKLIST.md -- section 0 covers two
  decisions that are awkward to reverse afterwards (where PostgreSQL
  keeps its data, and syslog sizing).
"@
Set-Content -Path (Join-Path $OutputPath 'README.txt') -Value $readmeText -Encoding UTF8

# -----------------------------------------------------------------------
Write-Step 'Verifying the package'
# -----------------------------------------------------------------------
# ⛔ "The steps ran" is not "the package is usable" -- the same distinction
# Update-SecVault.ps1 draws between a service reporting Running and the console
# actually answering. Check the files that have to be there.
$mustHave = @(
    'Install-SecVault.cmd',
    'README.txt',
    'installer\Install-SecVault.ps1',
    'installer\Update-SecVault.ps1',
    'app\package.json',
    'app\lib\schema.sql',
    'app\services\engine-worker.js'
)
if ($IncludeNodeModules) {
    $mustHave += 'app\node_modules\.secvault-bundled'
    $mustHave += 'app\node_modules\next\package.json'
    $mustHave += 'app\node_modules\@next\swc-win32-x64-msvc'
}
$absent = @()
foreach ($m in $mustHave) { if (-not (Test-Path (Join-Path $OutputPath $m))) { $absent += $m } }
if (-not $SkipDependencyCheck) {
    foreach ($r in $required) {
        if (-not $r.Required) { continue }
        if (-not (Get-ChildItem $depDest -Filter $r.Pattern -ErrorAction SilentlyContinue)) {
            $absent += "installer\dependencies\$($r.Pattern)"
        }
    }
}
if ($absent.Count -gt 0) {
    $absent | ForEach-Object { Write-Host "    MISSING  $_" -ForegroundColor Red }
    Fail 'The package is incomplete. Do not ship it.'
}

$total = Get-ChildItem $OutputPath -Recurse -File -Force -ErrorAction SilentlyContinue |
    Measure-Object -Property Length -Sum
Write-Note ("{0:N0} files, {1:N0} MB" -f $total.Count, ($total.Sum / 1MB))

if ($Zip) {
    # ⛔ Off by default: compressing ~750 MB is the most memory-hungry thing
    # here, and it is what got the previous design killed mid-build twice.
    Write-Step 'Compressing (requested with -Zip)'
    Add-Type -AssemblyName System.IO.Compression.FileSystem
    $zipPath = "$OutputPath.zip"
    if (Test-Path $zipPath) { Remove-Item $zipPath -Force }
    [System.IO.Compression.ZipFile]::CreateFromDirectory(
        $OutputPath, $zipPath, [System.IO.Compression.CompressionLevel]::Fastest, $true)
    Write-Note ("{0} ({1:N0} MB)" -f (Split-Path -Leaf $zipPath), ((Get-Item $zipPath).Length / 1MB))
}

Write-Host ''
Write-Host '===============================================================' -ForegroundColor Green
Write-Host '  Package built' -ForegroundColor Green
Write-Host '===============================================================' -ForegroundColor Green
Write-Host ("  folder   : {0}" -f $OutputPath)
Write-Host ("  size     : {0:N0} MB in {1:N0} files" -f ($total.Sum / 1MB), $total.Count)
Write-Host ("  version  : {0}   commit {1}{2}" -f $version, $commit, $(if ($dirty) { ' (DIRTY)' } else { '' }))
Write-Host ("  offline  : {0}" -f $(if ($IncludeNodeModules) { 'yes -- no npm registry needed' } else { 'NO -- the target must reach registry.npmjs.org' }))
Write-Host ("  updates  : {0}" -f $(if ($hasDeployKey) { 'in-place (deploy key included -- internal use only)' } else { 'by running a newer installer folder (no deploy key)' }))
Write-Host ''
Write-Host '  Copy the WHOLE folder to the server and run Install-SecVault.cmd.' -ForegroundColor White
Write-Host '  It elevates itself and offers the server address from a list.' -ForegroundColor White
Write-Host ''
