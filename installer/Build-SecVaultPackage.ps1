<#
.SYNOPSIS
    Builds the SecVault installer distribution FOLDER.

.DESCRIPTION
    Produces dist\SecVault-Installer-v<version>\ :

        Install-SecVault.cmd      double-click; elevates, then runs the installer
        SecVault-Setup.exe        the same, for operators who expect an .exe
        README.txt                generated, including the internet requirement
        installer\*.ps1           installer, updater, backup, restore, TLS helper
        installer\dependencies\   prerequisite installers + the git deploy key

    ⛔ THE APPLICATION SOURCE IS NOT IN HERE. The installer CLONES it, and then
    runs `npm ci`, so a target server MUST have internet access. That is a
    deliberate decision (2026-09-23), and it reverses an earlier design that
    shipped the source and node_modules inside the package.

    Why it was reversed: a bundled tree carries no .git, so
    Update-SecVault.ps1 and Settings -> Update had nothing to pull into and
    that installation could NEVER update itself. For a firewall-security
    product, "can never update" is a worse property than "needs internet once",
    and it fails silently -- the update button simply does nothing.

    ⛔ THE REQUIREMENT IS ENFORCED EARLY, NOT DISCOVERED LATE.
    Install-SecVault.ps1 probes github.com:22 and registry.npmjs.org:443 BEFORE
    installing anything, so an air-gapped server is told at once rather than
    after PostgreSQL, Node, Git and NSSM have been installed.

    ⛔ THE DEPLOY KEY IS REQUIRED and travels in this folder. The repository is
    private, so the clone cannot work without it. That makes this folder
    SENSITIVE: anyone holding a copy has read access to the whole repository,
    and a key cannot be un-distributed. It is for internal deployment, not for
    handing to a customer.

    Shape follows the NocVault suite (C:\NocVault-Suite-v1.2): scripts and
    small launchers beside a dependencies\ directory.

.PARAMETER OutputPath
    Folder to create. Defaults to dist\SecVault-Installer-v<version>.

.PARAMETER DependenciesPath
    Where the prerequisite installers and the deploy key live. Defaults to
    installer\dependencies.

.PARAMETER AllowDirty
    Build from a working tree with uncommitted changes, or one whose commit
    cannot be determined. Off by default: an artifact nobody can tie back to a
    commit cannot be supported.

.PARAMETER Zip
    Also produce a .zip of the folder.

.EXAMPLE
    .\installer\Build-SecVaultPackage.ps1
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$DependenciesPath,
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
# fatal here. `& git` raises CommandNotFoundException when it cannot be
# resolved, and that once aborted a whole build at step 1 on a machine where
# git WAS installed and in the MACHINE path -- just not in the already-open
# shell's copy of it, which is the normal state of any console opened before a
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
#
# ⛔ AND THE VERSION IN THIS FOLDER IS ONLY THE INSTALLER'S. The application it
# clones comes from origin/main at install time, so a server installed next
# month gets whatever main holds then, not this build. That is the point of
# cloning, and it is stated in the README so nobody reads the folder name as
# the version they will be running.
if (($dirty -or $commit -eq 'unknown') -and -not $AllowDirty) {
    Fail 'The working tree is dirty, or the commit could not be determined. Commit your changes (or install git), or pass -AllowDirty and accept an artifact that matches no commit.'
}
if ($dirty) { Write-Warn 'Working tree is DIRTY -- this package matches no commit.' }

# -----------------------------------------------------------------------
Write-Step 'Verifying the prerequisite bundle'
# -----------------------------------------------------------------------
if (-not $DependenciesPath) { $DependenciesPath = Join-Path $PSScriptRoot 'dependencies' }
if (-not (Test-Path $DependenciesPath)) { Fail "Dependencies folder not found: $DependenciesPath" }

# Patterns, not exact names: the versions move, the roles do not.
# ⛔ THE DEPLOY KEY IS REQUIRED. The repository is private and the installer
# clones from it, so a package without the key cannot install anything. It was
# optional while the source was bundled; it is not optional now.
$required = @(
    @{ Role = 'Node.js runtime';      Pattern = 'node-v*-x64.msi';               Required = $true },
    @{ Role = 'PostgreSQL 16';        Pattern = 'postgresql-16*windows-x64.exe'; Required = $true },
    @{ Role = 'NSSM service manager'; Pattern = 'nssm-*.zip';                    Required = $true },
    @{ Role = 'Git for Windows';      Pattern = 'Git-*-64-bit.exe';              Required = $true },
    @{ Role = 'GitHub deploy key';    Pattern = 'secvault_deploy';               Required = $true },
    @{ Role = 'VC++ runtime';         Pattern = 'VC_redist.x64.exe';             Required = $false }
)

$missing = @()
$found = @()
foreach ($r in $required) {
    $hit = Get-ChildItem -Path $DependenciesPath -Filter $r.Pattern -File -ErrorAction SilentlyContinue |
        Select-Object -First 1
    if ($hit) {
        $found += $hit
        $size = if ($hit.Length -ge 1MB) { "{0:N0} MB" -f ($hit.Length / 1MB) } else { "{0:N0} KB" -f ($hit.Length / 1KB) }
        Write-Note ("ok       {0,-22} {1} ({2})" -f $r.Role, $hit.Name, $size)
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
        Write-Host "  See $DependenciesPath\README.txt for what belongs there." -ForegroundColor Yellow
        Write-Host '  The prerequisite installers come from the NocVault-Suite distribution;' -ForegroundColor Yellow
        Write-Host '  secvault_deploy is the repo deploy key (Settings -> Deploy keys).' -ForegroundColor Yellow
        Fail "$($missing.Count) required item(s) missing from $DependenciesPath"
    }
}

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
$instDest = Join-Path $OutputPath 'installer'
New-Item -ItemType Directory -Path $instDest -Force | Out-Null

Write-Note 'copying the installer scripts...'
Get-ChildItem $PSScriptRoot -Filter '*.ps1' -File | ForEach-Object {
    Copy-Item $_.FullName (Join-Path $instDest $_.Name) -Force
}

Write-Note 'copying the prerequisites and the deploy key...'
$depDest = Join-Path $instDest 'dependencies'
New-Item -ItemType Directory -Path $depDest -Force | Out-Null
foreach ($f in $found) { Copy-Item $f.FullName $depDest -Force }
$readmeSrc = Join-Path $DependenciesPath 'README.txt'
if (Test-Path $readmeSrc) { Copy-Item $readmeSrc $depDest -Force }

# The checklist travels with the package: it is the document the operator is
# told to read, and a link to a repo they cannot yet clone would be useless.
$checklist = Join-Path $repoRoot 'docs\FRESH-INSTALL-CHECKLIST.md'
if (Test-Path $checklist) {
    Copy-Item $checklist (Join-Path $OutputPath 'FRESH-INSTALL-CHECKLIST.md') -Force
    Write-Note 'included docs\FRESH-INSTALL-CHECKLIST.md'
}

# -----------------------------------------------------------------------
Write-Step 'Checking what the package carries'
# -----------------------------------------------------------------------
# ⛔ THE DEPLOY KEY IS SUPPOSED TO BE HERE, AND THAT MAKES THIS FOLDER
# SENSITIVE. It is stated loudly at build time rather than only in a README,
# because the person who builds it is the person who decides where it goes.
$keyInPackage = Test-Path (Join-Path $depDest 'secvault_deploy')
if ($keyInPackage) {
    Write-Host '    This folder contains secvault_deploy, a PRIVATE repository key.' -ForegroundColor Yellow
    Write-Host '    Anyone who obtains it can read the whole repository, permanently.' -ForegroundColor Yellow
    Write-Host '    Treat the folder as a credential: internal distribution only.' -ForegroundColor Yellow
} elseif (-not $SkipDependencyCheck) {
    Fail 'The deploy key did not reach the package, so the install could not clone. Refusing to ship it.'
}

# ⛔ Nothing else secret may ride along. The app source is not copied at all
# now, so there is no .env.local to leak -- but the check stays, because the
# next person to add a copy step will not remember that.
$leaks = @()
Get-ChildItem $OutputPath -Recurse -File -Force -ErrorAction SilentlyContinue | ForEach-Object {
    $n = $_.Name
    if ($n -eq '.env.local' -or $n -eq '.env' -or $n -like '*.pem' -or $n -like '*.pfx' -or $n -like '*.key') {
        $leaks += $_.FullName.Substring($OutputPath.Length)
    }
}
if ($leaks.Count -gt 0) {
    $leaks | ForEach-Object { Write-Host "    LEAK  $_" -ForegroundColor Red }
    Fail "$($leaks.Count) unexpected secret-bearing file(s) reached the package. Refusing to ship it."
}
Write-Note 'no unexpected secret-bearing files.'

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
echo    SecVault Setup   installer $version   commit $commit
echo  ===============================================================
echo.
echo  This server needs internet access: the application is cloned from
echo  GitHub and its dependencies are installed with npm.
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
# memory, unlike the 555 MB embedded-resource design this replaced.
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

$readmeText = @"
SecVault installer $version   (built from commit $commit)
===============================================================

⛔ THIS SERVER MUST HAVE INTERNET ACCESS.
  The application is CLONED at install time and its dependencies are
  installed with npm. Without egress the install cannot complete, and
  it will tell you so BEFORE it changes anything on the machine.

  Required:
    github.com:22            to clone the application
    registry.npmjs.org:443   to install its dependencies

⛔ THIS FOLDER IS A CREDENTIAL.
  installer\dependencies\secvault_deploy is a private repository key.
  Anyone who obtains this folder can read the whole repository, and a
  key cannot be un-distributed. Internal distribution only.

TO INSTALL
  Copy this WHOLE FOLDER to the server, then run Install-SecVault.cmd
  (or SecVault-Setup.exe). It asks for administrator rights itself.

  It offers this machine's own addresses for the console and lets you
  pick one from a list -- you do not need to know it in advance.

WHICH VERSION YOU GET
  $version is the version of THIS INSTALLER. The application comes from
  the main branch at the moment you install, so a server built later
  gets whatever main holds then.

UPDATES
  This installs a real git clone, so Settings -> Update and
  installer\Update-SecVault.ps1 both work and pull in place.

UNATTENDED
  Install-SecVault.cmd -ServerIp 10.0.0.10 -SyslogPorts 514 -Unattended

BEFORE THE FIRST RUN
  Read FRESH-INSTALL-CHECKLIST.md in this folder -- section 0 covers two
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
    'installer\SecVault-Tls.ps1',
    'installer\Backup-SecVault.ps1',
    'installer\Restore-SecVault.ps1'
)
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
Write-Host ("  folder    : {0}" -f $OutputPath)
Write-Host ("  size      : {0:N0} MB in {1:N0} files" -f ($total.Sum / 1MB), $total.Count)
Write-Host ("  installer : {0}   commit {1}{2}" -f $version, $commit, $(if ($dirty) { ' (DIRTY)' } else { '' }))
Write-Host '  app source: CLONED at install time -- the target needs internet' -ForegroundColor White
Write-Host '  updates   : in place (a real git clone, so the updater works)'
Write-Host ''
if ($keyInPackage) {
    Write-Host '  ⛔ Contains a private repository key. Internal distribution only.' -ForegroundColor Yellow
    Write-Host ''
}
Write-Host '  Copy the WHOLE folder to the server and run Install-SecVault.cmd.' -ForegroundColor White
Write-Host ''
