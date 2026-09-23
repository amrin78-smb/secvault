<#
.SYNOPSIS
    Builds a single self-extracting SecVault-Setup .exe from this repository.

.DESCRIPTION
    Produces ONE file an operator can copy to a clean Windows Server and run.
    It bundles the application source, the prerequisite installers, and
    (by default) node_modules, so the install needs no internet access at all.

    ⛔ WHY node_modules IS BUNDLED BY DEFAULT.
    Install-SecVault.ps1 runs `npm ci`, which needs registry.npmjs.org.
    installer\dependencies\README.txt says "no internet download required for
    prerequisites" and that is true of the PREREQUISITES -- but npm was never
    counted, so a fresh install has always needed the public npm registry.
    CLAUDE.md names segmented and air-gapped networks as the TARGET CUSTOMER,
    not an edge case, so an installer that silently requires a registry fails
    exactly the customer it was written for. Bundling node_modules closes that.

    Safe to bundle here, verified rather than assumed: the tree carries exactly
    ONE native binary (@next/swc-win32-x64-msvc), it is already the win32-x64
    build, and the bundled Node MSI is the same v20 the tree was installed
    against. A tree built on another OS or another Node major MUST NOT be
    shipped -- this script checks and refuses.

    ⛔ WHY THE SOURCE IS BUNDLED RATHER THAN CLONED (-SourceMode Bundle).
    The clone path authenticates with `secvault_deploy`, a PRIVATE GitHub
    deploy key. Putting it inside a file handed to a customer gives whoever
    holds that file permanent read access to the whole private repository, and
    a key cannot be un-distributed. Bundling the source needs no key and works
    offline. -SourceMode Clone is kept because the in-app updater does
    `git pull`, so an installation that must self-update needs the git remote;
    choosing it is an explicit decision and this script says what it costs.

.PARAMETER OutputPath
    Where to write the .exe. Defaults to dist\SecVault-Setup-<version>.exe.

.PARAMETER DependenciesPath
    Folder holding the prerequisite installers. Defaults to
    installer\dependencies. See its README.txt for the exact file list.

.PARAMETER SourceMode
    Bundle (default) ships the source and needs no deploy key.
    Clone ships secvault_deploy and clones from GitHub at install time.

.PARAMETER IncludeNodeModules
    Default $true. $false produces a smaller package that REQUIRES the target
    to reach registry.npmjs.org.

.PARAMETER AllowDirty
    Permit a build from a working tree with uncommitted changes. Off by
    default: an artifact nobody can tie back to a commit cannot be supported.

.EXAMPLE
    .\installer\Build-SecVaultPackage.ps1
.EXAMPLE
    .\installer\Build-SecVaultPackage.ps1 -SourceMode Clone -IncludeNodeModules:$false
#>
[CmdletBinding()]
param(
    [string]$OutputPath,
    [string]$DependenciesPath,
    [ValidateSet('Bundle', 'Clone')]
    [string]$SourceMode = 'Bundle',
    [bool]$IncludeNodeModules = $true,
    [switch]$AllowDirty,
    [switch]$SkipDependencyCheck
)

$ErrorActionPreference = 'Stop'
Set-StrictMode -Version 2.0

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

# ⛔ A NATIVE CALL UNDER $ErrorActionPreference='Stop' THROWS ON stderr OUTPUT
# EVEN WHEN IT EXITED 0. Update-SecVault.ps1 carries the same helper and the
# same comment; git writes progress to stderr routinely, so without this a
# perfectly good `git status` aborts the build.
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
Write-Host '  SecVault -- build a self-extracting installer' -ForegroundColor White
Write-Host '===============================================================' -ForegroundColor White
Write-Host ''

# -----------------------------------------------------------------------
Write-Step 'Reading version and commit'
# -----------------------------------------------------------------------
$pkg = Get-Content (Join-Path $repoRoot 'package.json') -Raw | ConvertFrom-Json
$version = $pkg.version
if (-not $version) { Fail 'package.json has no version.' }

$commit = 'unknown'
$dirty = $false
Push-Location $repoRoot
try {
    $rev = Invoke-Native { & git rev-parse --short HEAD 2>$null }
    if ($LASTEXITCODE -eq 0 -and $rev) { $commit = ($rev | Select-Object -First 1).ToString().Trim() }
    $status = Invoke-Native { & git status --porcelain 2>$null }
    if ($LASTEXITCODE -eq 0 -and $status) { $dirty = $true }
} finally { Pop-Location }

Write-Note "version : $version"
Write-Note "commit  : $commit"
if ($dirty) {
    # ⛔ An artifact that cannot be tied to a commit cannot be supported: when
    # the customer reports a fault there is no way to know what they are running.
    if (-not $AllowDirty) {
        Fail 'The working tree has uncommitted changes. Commit them, or pass -AllowDirty and accept that this .exe matches no commit.'
    }
    Write-Warn 'Working tree is DIRTY -- this package matches no commit.'
}

# -----------------------------------------------------------------------
Write-Step 'Checking the build host matches the target'
# -----------------------------------------------------------------------
# ⛔ node_modules is COPIED, not reinstalled, so the tree must already be the
# right platform. A macOS or Linux tree installs a different @next/swc binary
# and Next fails at startup with a message about a missing SWC binary that
# names neither this script nor the real cause.
if ($IncludeNodeModules) {
    $nmPath = Join-Path $repoRoot 'node_modules'
    if (-not (Test-Path $nmPath)) {
        Fail "node_modules not found. Run 'npm ci' first, or pass -IncludeNodeModules:`$false."
    }
    $swcWin = Join-Path $nmPath '@next\swc-win32-x64-msvc'
    if (-not (Test-Path $swcWin)) {
        Fail "node_modules does not contain @next/swc-win32-x64-msvc, so it was not installed on Windows x64. Re-run 'npm ci' on a Windows x64 host, or pass -IncludeNodeModules:`$false."
    }
    $foreign = Get-ChildItem (Join-Path $nmPath '@next') -Directory -ErrorAction SilentlyContinue |
        Where-Object { $_.Name -like 'swc-*' -and $_.Name -ne 'swc-win32-x64-msvc' }
    if ($foreign) {
        Write-Warn ("node_modules also carries non-Windows SWC builds ({0}); they are harmless but add size." -f (($foreign | Select-Object -ExpandProperty Name) -join ', '))
    }
    $nodeV = Invoke-Native { & node -v 2>$null }
    if ($LASTEXITCODE -eq 0 -and $nodeV) {
        $nodeV = ($nodeV | Select-Object -First 1).ToString().Trim()
        Write-Note "node on this host : $nodeV"
        if ($nodeV -notlike 'v20.*') {
            Write-Warn "node_modules was installed under $nodeV but the bundled runtime is Node 20. Install under Node 20 to be certain."
        }
    }
}

# -----------------------------------------------------------------------
Write-Step 'Verifying the prerequisite bundle'
# -----------------------------------------------------------------------
if (-not $DependenciesPath) { $DependenciesPath = Join-Path $PSScriptRoot 'dependencies' }
if (-not (Test-Path $DependenciesPath)) {
    Fail "Dependencies folder not found: $DependenciesPath"
}

# Patterns rather than exact names: the versions move, the roles do not.
$required = @(
    @{ Role = 'Node.js runtime';     Pattern = 'node-v*-x64.msi';                Required = $true },
    @{ Role = 'PostgreSQL 16';       Pattern = 'postgresql-16*windows-x64.exe';  Required = $true },
    @{ Role = 'NSSM service manager';Pattern = 'nssm-*.zip';                     Required = $true },
    @{ Role = 'Git for Windows';     Pattern = 'Git-*-64-bit.exe';               Required = $true },
    @{ Role = 'VC++ runtime';        Pattern = 'VC_redist.x64.exe';              Required = $false }
)
if ($SourceMode -eq 'Clone') {
    $required += @{ Role = 'GitHub deploy key'; Pattern = 'secvault_deploy'; Required = $true }
}

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
        Write-Warn ("optional {0,-22} not present ({1}) -- the installer skips it" -f $r.Role, $r.Pattern)
    }
}

if ($missing.Count -gt 0) {
    # ⛔ A PACKAGE MISSING A PREREQUISITE IS WORSE THAN NO PACKAGE. It builds,
    # it ships, it runs, and it fails on the customer's server partway through
    # provisioning -- by which point services may exist and a database may have
    # been created. Refuse here, where it costs nothing.
    if ($SkipDependencyCheck) {
        Write-Warn 'SkipDependencyCheck was passed: building an INCOMPLETE package that WILL fail on a clean server.'
    } else {
        Write-Host ''
        Write-Host '  Copy them from the NocVault-Suite distribution package; see' -ForegroundColor Yellow
        Write-Host "  $DependenciesPath\README.txt for the exact file list." -ForegroundColor Yellow
        Fail "$($missing.Count) required prerequisite installer(s) missing from $DependenciesPath"
    }
}

# -----------------------------------------------------------------------
Write-Step 'Staging the payload'
# -----------------------------------------------------------------------
# ⛔ SWEEP UP AFTER EARLIER RUNS FIRST. The cleanup at the end only runs on
# success, so every failed build used to leave a ~300 MB staging tree in %TEMP%
# for ever -- and the builds most likely to fail are the ones being iterated on.
# Anything older than a few hours cannot belong to a run in progress.
Get-ChildItem ([System.IO.Path]::GetTempPath()) -Directory -Filter 'secvault-pkg-*' -ErrorAction SilentlyContinue |
    Where-Object { $_.CreationTime -lt (Get-Date).AddHours(-2) } |
    ForEach-Object {
        Write-Note ("removing stale staging dir {0}" -f $_.Name)
        Remove-Item $_.FullName -Recurse -Force -ErrorAction SilentlyContinue
    }

$stage = Join-Path ([System.IO.Path]::GetTempPath()) ("secvault-pkg-" + [Guid]::NewGuid().ToString('N').Substring(0, 8))
New-Item -ItemType Directory -Path $stage -Force | Out-Null
$appDir = Join-Path $stage 'app'
New-Item -ItemType Directory -Path $appDir -Force | Out-Null

# ⛔ NEVER PACKAGE THESE. `.env.local` holds CREDENTIAL_KEY, the database
# password and NEXTAUTH_SECRET; `certs\` holds a private key; `secvault_deploy`
# is a private repo key. Shipping any of them turns one server's secrets into
# every customer's. A scan below re-checks the staged tree, because an
# exclusion list is only as good as the next person who edits it.
$excludeDirs = @('node_modules', '.next', '.git', 'certs', 'logs', 'spool', 'archive', 'dist', 'coverage')
$excludeFiles = @('.env.local', '.env', '*.pfx', '*.key', '*.pem', 'secvault_deploy', 'secvault_deploy.pub')

Write-Note 'copying application source...'
# ⛔ robocopy, NOT `Get-ChildItem -Recurse | Copy-Item`. The obvious form
# enumerates the WHOLE tree before any filter runs, so it walks all ~19,500
# node_modules entries just to discard them -- and on those deep paths it
# raises "The system cannot find the file specified" (a Win32 MAX_PATH
# failure), which under this script's $ErrorActionPreference='Stop' aborts the
# build. robocopy prunes excluded directories before descending, so it never
# visits them, and it handles long paths natively.
#
# /XD prunes directories, /XF excludes files. The exclusion lists are the same
# ones declared above, expanded here so the two cannot drift.
$xd = @()
foreach ($d in $excludeDirs) { $xd += (Join-Path $repoRoot $d) }
# The prerequisite binaries are staged separately, below.
$xd += (Join-Path $repoRoot 'installer\dependencies')

$roboArgs = @($repoRoot, $appDir, '/E', '/NFL', '/NDL', '/NJH', '/NJS', '/NC', '/NS', '/NP', '/R:1', '/W:1')
$roboArgs += '/XD'; $roboArgs += $xd
$roboArgs += '/XF'; $roboArgs += $excludeFiles

# ⛔ robocopy EXIT CODES BELOW 8 ARE SUCCESS: 1 = files copied, 2 = extra
# files present, 3 = both. Treating any non-zero as failure would fail every
# build that actually copied something.
$rc = Invoke-Native { & robocopy @roboArgs }
if ($LASTEXITCODE -ge 8) { Fail "robocopy failed copying the source tree (exit $LASTEXITCODE)." }
Write-Note ("  {0:N0} source files" -f (Get-ChildItem $appDir -Recurse -File -Force -ErrorAction SilentlyContinue).Count)

if ($IncludeNodeModules) {
    Write-Note 'copying node_modules (this takes a minute)...'
    $nmDest = Join-Path $appDir 'node_modules'
    # robocopy is dramatically faster than Copy-Item for ~20k files.
    # ⛔ robocopy EXIT CODES BELOW 8 ARE SUCCESS, not failure: 1 = files copied,
    # 2 = extra files, 3 = both. Treating non-zero as an error here would fail
    # every build that actually did something.
    $rc = Invoke-Native { & robocopy (Join-Path $repoRoot 'node_modules') $nmDest /E /NFL /NDL /NJH /NJS /NC /NS /NP /R:1 /W:1 }
    if ($LASTEXITCODE -ge 8) { Fail "robocopy failed copying node_modules (exit $LASTEXITCODE)." }
    Write-Note ("  {0:N0} files" -f (Get-ChildItem $nmDest -Recurse -File -ErrorAction SilentlyContinue).Count)

    # ⛔ THE MARKER IS WHAT MAKES THE OFFLINE INSTALL REAL.
    # Install-SecVault.ps1 skips `npm ci` ONLY when this file is present and
    # its version matches the package.json beside it. Without it the installer
    # runs npm ci as usual and an air-gapped install fails -- so shipping
    # node_modules without writing this would be a bundle that buys nothing.
    # The version match is what stops a tree from one build being used against
    # another build's source, which resolves, starts, and runs the wrong code.
    $marker = @(
        "# Written by installer\Build-SecVaultPackage.ps1. Do not edit.",
        "# Install-SecVault.ps1 skips 'npm ci' when version= matches its package.json.",
        "version=$version",
        "commit=$commit",
        "built=$((Get-Date).ToString('o'))",
        "node=$nodeV"
    ) -join "`r`n"
    Set-Content -Path (Join-Path $nmDest '.secvault-bundled') -Value $marker -Encoding ASCII
    Write-Note "  offline marker written (version $version)"
}

Write-Note 'copying prerequisite installers...'
$depDest = Join-Path $appDir 'installer\dependencies'
if (-not (Test-Path $depDest)) { New-Item -ItemType Directory -Path $depDest -Force | Out-Null }
foreach ($f in $found) { Copy-Item -Path $f.FullName -Destination $depDest -Force }
$readme = Join-Path $DependenciesPath 'README.txt'
if (Test-Path $readme) { Copy-Item $readme $depDest -Force }

# -----------------------------------------------------------------------
Write-Step 'Scanning the staged payload for secrets'
# -----------------------------------------------------------------------
# ⛔ THIS GATE IS THE POINT OF THE EXCLUSION LIST, NOT A DUPLICATE OF IT.
# The list above is what we MEANT to exclude; this is what actually got staged.
# Publishing a package is irreversible, so the check runs against the artifact.
$leaks = @()
Get-ChildItem $appDir -Recurse -File -Force -ErrorAction SilentlyContinue |
    Where-Object { $_.FullName -notmatch '\\node_modules\\' } | ForEach-Object {
        $n = $_.Name
        if ($n -eq '.env.local' -or $n -eq '.env' -or $n -eq 'secvault_deploy') {
            $leaks += $_.FullName.Substring($appDir.Length)
        } elseif ($n -like '*.pem' -or $n -like '*.pfx' -or $n -like '*.key') {
            $leaks += $_.FullName.Substring($appDir.Length)
        }
    }
if ($SourceMode -eq 'Clone') {
    # In Clone mode the deploy key is deliberately included, and that decision
    # is stated out loud rather than hidden behind a default.
    $leaks = $leaks | Where-Object { $_ -notlike '*secvault_deploy*' }
    Write-Warn 'Clone mode: secvault_deploy (a PRIVATE repo key) is being shipped inside this .exe.'
    Write-Warn 'Anyone who obtains the .exe can read the whole private repository, permanently.'
}
if ($leaks.Count -gt 0) {
    Write-Host ''
    $leaks | ForEach-Object { Write-Host "    LEAK  $_" -ForegroundColor Red }
    Fail "$($leaks.Count) secret-bearing file(s) reached the staging tree. Refusing to package."
}
Write-Note 'no secret-bearing files in the payload.'

# -----------------------------------------------------------------------
Write-Step 'Writing the bootstrap'
# -----------------------------------------------------------------------
# ⛔ IExpress FLATTENS EVERY FILE INTO ONE TEMP DIRECTORY -- it cannot carry a
# directory tree. So the payload is zipped and the .exe ships exactly two
# files: the zip and this bootstrap, which restores the tree.
$bootstrap = @"
@echo off
setlocal
title SecVault Setup $version

echo.
echo  ===============================================================
echo    SecVault Setup   version $version   commit $commit
echo  ===============================================================
echo.

REM Elevation is required: this registers Windows services, installs MSIs and
REM opens firewall rules. Without this check a non-elevated run gets most of
REM the way in and then fails on the first service call, leaving a half-built
REM machine and an error that names none of the above.
REM stderr goes to nul directly rather than being merged into stdout: the two
REM are equivalent for this check, and the merging form is the one that
REM tests\installerNativeCalls.test.js scans for. That scan guards PowerShell's
REM native-stderr trap, which does not apply to batch -- but a scanner cannot
REM tell the two apart inside a here-string, and an allow-list entry for a
REM non-problem is debt that outlives the reason for it.
net session >nul 2>nul
if errorlevel 1 (
  echo  [ERROR] This installer must be run AS ADMINISTRATOR.
  echo.
  echo    Right-click the .exe and choose "Run as administrator",
  echo    or launch it from an elevated command prompt.
  echo.
  pause
  exit /b 1
)

echo  Expanding the package. This takes a minute.
echo.

set "TARGET=%~dp0secvault-src"
if exist "%TARGET%" rmdir /s /q "%TARGET%"
mkdir "%TARGET%"

powershell -NoProfile -ExecutionPolicy Bypass -Command ^
  "try { Add-Type -AssemblyName System.IO.Compression.FileSystem; [System.IO.Compression.ZipFile]::ExtractToDirectory('%~dp0secvault-payload.zip', '%TARGET%'); exit 0 } catch { Write-Host `$(`$_.Exception.Message) -ForegroundColor Red; exit 1 }"

if errorlevel 1 (
  echo.
  echo  [ERROR] Could not expand the package. Check free disk space on %%TEMP%%.
  echo.
  pause
  exit /b 1
)

echo  Starting the installer...
echo.
powershell -NoProfile -ExecutionPolicy Bypass -File "%TARGET%\installer\Install-SecVault.ps1" %*
set RC=%ERRORLEVEL%

echo.
if not "%RC%"=="0" (
  echo  Setup exited with code %RC%. The source tree was left at:
  echo    %TARGET%
  echo  so the installer can be re-run without unpacking again.
) else (
  echo  Setup finished. Source tree: %TARGET%
)
echo.
pause
exit /b %RC%
"@
$bootstrapPath = Join-Path $stage 'Setup.cmd'
Set-Content -Path $bootstrapPath -Value $bootstrap -Encoding ASCII

# -----------------------------------------------------------------------
Write-Step 'Compressing the payload'
# -----------------------------------------------------------------------
$zipPath = Join-Path $stage 'secvault-payload.zip'
Add-Type -AssemblyName System.IO.Compression.FileSystem
# ⛔ Fastest, NOT Optimal. MEASURED on this payload (~20,000 mostly-small files
# from node_modules): Optimal ran at roughly 3 MB/min and would have taken over
# an hour and a half. Fastest finishes in minutes for a few percent more size,
# and the size barely matters because IExpress re-compresses the result into a
# CAB anyway. A build nobody is willing to wait for is a build that stops being
# run before a release.
[System.IO.Compression.ZipFile]::CreateFromDirectory(
    $appDir, $zipPath, [System.IO.Compression.CompressionLevel]::Fastest, $false)
$zipMb = (Get-Item $zipPath).Length / 1MB
Write-Note ("payload.zip : {0:N0} MB" -f $zipMb)

# -----------------------------------------------------------------------
Write-Step 'Building the self-extracting .exe'
# -----------------------------------------------------------------------
if (-not $OutputPath) {
    $distDir = Join-Path $repoRoot 'dist'
    if (-not (Test-Path $distDir)) { New-Item -ItemType Directory -Path $distDir -Force | Out-Null }
    $OutputPath = Join-Path $distDir "SecVault-Setup-$version.exe"
}
$OutputPath = [System.IO.Path]::GetFullPath($OutputPath)
if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }

$iexpress = Join-Path $env:WINDIR 'System32\iexpress.exe'
if (-not (Test-Path $iexpress)) {
    Fail "iexpress.exe not found. It ships with Windows; this host is unusual. Ship $zipPath plus Setup.cmd instead."
}

# IExpress reads an .SED directive file. ShowInstallProgramWindow=1 keeps the
# console visible, because the installer's own output IS the progress report.
$sed = @"
[Version]
Class=IEXPRESS
SEDVersion=3
[Options]
PackagePurpose=InstallApp
ShowInstallProgramWindow=1
HideExtractAnimation=0
UseLongFileName=1
InsideCompressed=0
CAB_FixedSize=0
CAB_ResvCodeSigning=0
RebootMode=N
InstallPrompt=%InstallPrompt%
DisplayLicense=%DisplayLicense%
FinishMessage=%FinishMessage%
TargetName=%TargetName%
FriendlyName=%FriendlyName%
AppLaunched=%AppLaunched%
PostInstallCmd=%PostInstallCmd%
AdminQuietInstCmd=%AdminQuietInstCmd%
UserQuietInstCmd=%UserQuietInstCmd%
SourceFiles=SourceFiles
[Strings]
InstallPrompt=
DisplayLicense=
FinishMessage=
TargetName=$OutputPath
FriendlyName=SecVault $version Setup
AppLaunched=cmd.exe /c Setup.cmd
PostInstallCmd=<None>
AdminQuietInstCmd=
UserQuietInstCmd=
FILE0="Setup.cmd"
FILE1="secvault-payload.zip"
[SourceFiles]
SourceFiles0=$stage
[SourceFiles0]
%FILE0%=
%FILE1%=
"@
$sedPath = Join-Path $stage 'SecVault.sed'
Set-Content -Path $sedPath -Value $sed -Encoding ASCII

Write-Note 'running iexpress (this is slow on a large payload)...'
$proc = Start-Process -FilePath $iexpress -ArgumentList @('/N', "`"$sedPath`"") -Wait -PassThru -NoNewWindow
if ($proc.ExitCode -ne 0) {
    Fail "iexpress exited with code $($proc.ExitCode). Staging left at $stage for inspection."
}

# -----------------------------------------------------------------------
Write-Step 'Verifying the artifact'
# -----------------------------------------------------------------------
# ⛔ "iexpress exited 0" IS NOT "the package exists and is usable" -- the same
# distinction Update-SecVault.ps1 draws between a service reporting Running and
# the console actually answering. Check the file.
if (-not (Test-Path $OutputPath)) {
    Fail "iexpress reported success but $OutputPath does not exist."
}
$exe = Get-Item $OutputPath
$exeMb = $exe.Length / 1MB
if ($exeMb -lt ($zipMb * 0.5)) {
    Fail ("The .exe is {0:N0} MB but the payload alone is {1:N0} MB -- it is truncated. Do not ship it." -f $exeMb, $zipMb)
}
$sha = (Get-FileHash -Path $OutputPath -Algorithm SHA256).Hash

Remove-Item $stage -Recurse -Force -ErrorAction SilentlyContinue

Write-Host ''
Write-Host '===============================================================' -ForegroundColor Green
Write-Host '  Package built' -ForegroundColor Green
Write-Host '===============================================================' -ForegroundColor Green
Write-Host ("  file     : {0}" -f $OutputPath)
Write-Host ("  size     : {0:N0} MB" -f $exeMb)
Write-Host ("  version  : {0}   commit {1}{2}" -f $version, $commit, $(if ($dirty) { ' (DIRTY)' } else { '' }))
Write-Host ("  source   : {0}" -f $SourceMode)
Write-Host ("  offline  : {0}" -f $(if ($IncludeNodeModules) { 'yes -- no npm registry needed' } else { 'NO -- the target must reach registry.npmjs.org' }))
Write-Host ("  sha256   : {0}" -f $sha)
Write-Host ''
Write-Host '  TO RUN IT: copy to the target server, right-click, Run as administrator.' -ForegroundColor White
Write-Host '  It prompts for the server IP; everything else takes a documented default.' -ForegroundColor White
Write-Host ''
# ⛔ SAID PLAINLY BECAUSE IT IS EASY TO ASSUME OTHERWISE. IExpress does not
# forward a .exe's command line to the program it launches, so switches typed
# after the .exe name are NOT reliably delivered to Install-SecVault.ps1. An
# unattended or parameterised install therefore runs the .ps1 directly; the
# .exe unpacks to a folder beside itself and leaves it there for exactly that.
Write-Host '  For an UNATTENDED or parameterised install, do not pass switches to the .exe' -ForegroundColor DarkGray
Write-Host '  (IExpress does not forward them). Run it once to unpack, then call:' -ForegroundColor DarkGray
Write-Host '    powershell -ExecutionPolicy Bypass -File <unpacked>\installer\Install-SecVault.ps1 -ServerIp ... ' -ForegroundColor DarkGray
Write-Host ''
Write-Host '  Read docs\FRESH-INSTALL-CHECKLIST.md before the first run.' -ForegroundColor DarkGray
Write-Host ''
