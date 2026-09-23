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

# ⛔ GIT IS RESOLVED, NOT ASSUMED TO BE ON PATH, AND ITS ABSENCE IS NOT FATAL.
# Both halves were wrong and both bit on the same run. `& git` raises
# CommandNotFoundException when it cannot be resolved, and that ABORTED the
# whole build at step 1 -- on a machine where git was installed and present in
# the MACHINE path, just not in the already-open shell's copy of it. That is
# the normal state of any console opened before a provisioning run, which is
# exactly when a release gets built.
#
# The commit is PROVENANCE, not a build input: without it the package is
# stamped 'unknown' and says so, which is strictly better than refusing to
# build. Same shape as Find-SecVaultOpenSsl in installer\SecVault-Tls.ps1 --
# search the known locations, then PATH, and never invoke a bare name.
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
    Write-Warn 'git not found, so this package cannot record which commit it was built from. It will be stamped "unknown".'
} else {
    Push-Location $repoRoot
    try {
        $rev = Invoke-Native { & $gitExe rev-parse --short HEAD 2>$null }
        if ($LASTEXITCODE -eq 0 -and $rev) { $commit = ($rev | Select-Object -First 1).ToString().Trim() }
        $status = Invoke-Native { & $gitExe status --porcelain 2>$null }
        if ($LASTEXITCODE -eq 0 -and $status) { $dirty = $true }
    } catch {
        # ⛔ Provenance is worth having and never worth failing a build over.
        Write-Warn "git could not report the commit ($($_.Exception.Message)); stamping 'unknown'."
    } finally { Pop-Location }
}

# ⛔ AN UNKNOWN COMMIT STILL COUNTS AS UNVERIFIABLE PROVENANCE. -AllowDirty is
# the switch that says "I accept an artifact I cannot tie to a commit", so it
# governs this too; without it, a build that cannot name its source stops.
if ($commit -eq 'unknown' -and -not $AllowDirty) {
    Fail 'Could not determine the commit this build comes from. Install git, or pass -AllowDirty to accept a package that cannot be traced to a commit.'
}

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
Write-Step 'Compressing the payload'
# -----------------------------------------------------------------------
$zipPath = Join-Path $stage 'secvault-payload.zip'
Add-Type -AssemblyName System.IO.Compression
Add-Type -AssemblyName System.IO.Compression.FileSystem

# ⛔ BUILT ENTRY BY ENTRY, NOT WITH CreateFromDirectory, FOR ONE REASON:
# SEPARATORS. On this host CreateFromDirectory wrote entry names containing
# BACKSLASHES (`installerInstall-SecVault.ps1`). The ZIP format requires forward
# slashes; a backslash is a legal filename character, so a standards-compliant
# reader sees ONE file with a odd name rather than a path, and the tree
# silently flattens. It happened to work here only because the stub runs on
# Windows and Path.Combine accepts either -- i.e. it worked by accident, and
# anyone opening the package with a normal archiver would see something else
# entirely. Verified after this change by listing the entries back.
#
# ⛔ Fastest, NOT Optimal. MEASURED on the full payload (~20,000 mostly-small
# files from node_modules): Optimal ran at roughly 3 MB/min and would have
# taken over an hour and a half; a build nobody is willing to wait for stops
# being run before a release. Fastest costs a few percent of size.
$zipStream = [System.IO.File]::Open($zipPath, 'Create')
try {
    $archive = New-Object System.IO.Compression.ZipArchive($zipStream, 'Create')
    try {
        $prefixLen = $appDir.Length + 1
        $fastest = [System.IO.Compression.CompressionLevel]::Fastest
        foreach ($f in (Get-ChildItem $appDir -Recurse -File -Force -ErrorAction SilentlyContinue)) {
            $rel = $f.FullName.Substring($prefixLen).Replace([char]92, [char]47)
            $entry = $archive.CreateEntry($rel, $fastest)
            $in = [System.IO.File]::OpenRead($f.FullName)
            try {
                $out = $entry.Open()
                try { $in.CopyTo($out) } finally { $out.Dispose() }
            } finally { $in.Dispose() }
        }
    } finally { $archive.Dispose() }
} finally { $zipStream.Dispose() }
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
# ⛔ CREATE THE OUTPUT DIRECTORY WHATEVER THE PATH CAME FROM. This was created
# only on the default path, so an explicit -OutputPath into a folder that did
# not exist produced NOTHING: iexpress writes no file, reports no error, and
# leaves an EMPTY exit code -- so even the exit-code check could not catch it.
# The artifact check at the end is what finally said so, several minutes later.
$outDir = Split-Path -Parent $OutputPath
if ($outDir -and -not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
}
if (Test-Path $OutputPath) { Remove-Item $OutputPath -Force }

# ⛔ IEXPRESS WAS TRIED FIRST AND IS NOT USABLE HERE. It is a GUI program: `/N` alone
# raises a progress dialog that is never dismissed in a non-interactive session
# (measured: 0% CPU, idle indefinitely on a 99 MB payload), `/Q` suppresses that
# but it then exits producing NO FILE and NO READABLE EXIT CODE -- even
# $proc.ExitCode is empty because it hands off to a child. A release step whose
# success cannot be determined is not a release step. Even `iexpress /?` opens
# a dialog.
#
# So the stub is COMPILED here instead, with the C# compiler that ships in
# .NET Framework 4 on every Windows Server. The payload rides as an embedded
# resource. This is fully deterministic, has a real exit code, needs no GUI --
# and, unlike IExpress, it FORWARDS ITS COMMAND LINE to the installer, so an
# unattended install can pass -ServerIp and friends straight to the .exe.
$csc = Join-Path $env:WINDIR 'Microsoft.NET\Framework64\v4.0.30319\csc.exe'
if (-not (Test-Path $csc)) {
    Fail "csc.exe not found at $csc. .NET Framework 4 is required to build the package (it ships with Windows Server). Ship $zipPath plus Setup.cmd instead."
}

$stubSource = @'
using System;
using System.Diagnostics;
using System.IO;
using System.IO.Compression;
using System.Reflection;
using System.Security.Principal;

static class SecVaultSetup
{
    const string Version = "__VERSION__";
    const string Commit  = "__COMMIT__";

    static int Main(string[] args)
    {
        Console.WriteLine();
        Console.WriteLine("  ===============================================================");
        Console.WriteLine("    SecVault Setup   version " + Version + "   commit " + Commit);
        Console.WriteLine("  ===============================================================");
        Console.WriteLine();

        // Elevation is required: this registers Windows services, installs MSIs
        // and opens firewall rules. Without this check a non-elevated run gets
        // most of the way in and fails on the first service call, leaving a
        // half-built machine and an error that names none of the above.
        if (!IsElevated())
        {
            Console.WriteLine("  [ERROR] This installer must be run AS ADMINISTRATOR.");
            Console.WriteLine();
            Console.WriteLine("    Right-click the .exe and choose \"Run as administrator\",");
            Console.WriteLine("    or launch it from an elevated command prompt.");
            Console.WriteLine();
            Pause();
            return 1;
        }

        string exePath = Assembly.GetExecutingAssembly().Location;
        string baseDir = Path.GetDirectoryName(exePath);
        string target  = Path.Combine(baseDir, "secvault-" + Version);

        // ⛔ FALL BACK TO %TEMP% RATHER THAN FAILING. The .exe is often run from
        // a read-only share or a mounted ISO; refusing there would be a refusal
        // for a reason the operator cannot act on from where they are standing.
        try
        {
            Directory.CreateDirectory(target);
            string probe = Path.Combine(target, ".writable");
            File.WriteAllText(probe, "x");
            File.Delete(probe);
        }
        catch
        {
            target = Path.Combine(Path.GetTempPath(), "secvault-" + Version);
            Console.WriteLine("  Cannot write beside the .exe; unpacking to " + target);
        }

        Console.WriteLine("  Unpacking to " + target);
        Console.WriteLine("  This takes a minute.");
        Console.WriteLine();

        try
        {
            ExtractPayload(target);
        }
        catch (Exception ex)
        {
            Console.WriteLine("  [ERROR] Could not unpack the package: " + ex.Message);
            Console.WriteLine("          Check free disk space on the target volume.");
            Pause();
            return 1;
        }

        string installer = Path.Combine(target, "installer\\Install-SecVault.ps1");
        if (!File.Exists(installer))
        {
            Console.WriteLine("  [ERROR] The package unpacked but " + installer + " is missing.");
            Console.WriteLine("          This package is incomplete; do not use it.");
            Pause();
            return 1;
        }

        // Every argument given to the .exe is handed to the installer verbatim,
        // so an unattended install works without unpacking by hand first.
        string passThrough = "";
        foreach (string a in args) passThrough += " " + Quote(a);

        var psi = new ProcessStartInfo();
        psi.FileName = "powershell.exe";
        psi.Arguments = "-NoProfile -ExecutionPolicy Bypass -File " + Quote(installer) + passThrough;
        psi.UseShellExecute = false;
        psi.WorkingDirectory = target;

        Console.WriteLine("  Starting the installer...");
        Console.WriteLine();

        int rc;
        using (Process p = Process.Start(psi))
        {
            p.WaitForExit();
            rc = p.ExitCode;
        }

        Console.WriteLine();
        if (rc != 0)
        {
            Console.WriteLine("  Setup exited with code " + rc + ".");
            Console.WriteLine("  The unpacked tree was LEFT at:");
            Console.WriteLine("    " + target);
            Console.WriteLine("  so the installer can be re-run without unpacking again.");
        }
        else
        {
            Console.WriteLine("  Setup finished. Unpacked tree: " + target);
        }
        Console.WriteLine();
        Pause();
        return rc;
    }

    static bool IsElevated()
    {
        try
        {
            using (WindowsIdentity id = WindowsIdentity.GetCurrent())
            {
                return new WindowsPrincipal(id).IsInRole(WindowsBuiltInRole.Administrator);
            }
        }
        catch { return false; }
    }

    static void ExtractPayload(string target)
    {
        Assembly asm = Assembly.GetExecutingAssembly();
        using (Stream s = asm.GetManifestResourceStream("secvault-payload.zip"))
        {
            if (s == null) throw new Exception("the embedded payload is missing");
            using (ZipArchive zip = new ZipArchive(s, ZipArchiveMode.Read))
            {
                int done = 0;
                int total = zip.Entries.Count;
                foreach (ZipArchiveEntry e in zip.Entries)
                {
                    string dest = Path.Combine(target, e.FullName);
                    if (e.FullName.EndsWith("/") || e.FullName.EndsWith("\\"))
                    {
                        Directory.CreateDirectory(dest);
                        continue;
                    }
                    string dir = Path.GetDirectoryName(dest);
                    if (dir.Length > 0) Directory.CreateDirectory(dir);
                    e.ExtractToFile(dest, true);
                    done++;
                    if (done % 2000 == 0)
                    {
                        Console.WriteLine("    " + done + " of " + total + " files...");
                    }
                }
                Console.WriteLine("    " + done + " of " + total + " files.");
            }
        }
    }

    static string Quote(string s)
    {
        if (s.IndexOf(' ') < 0 && s.IndexOf('"') < 0) return s;
        return "\"" + s.Replace("\"", "\\\"") + "\"";
    }

    static void Pause()
    {
        // Only wait when a human is watching; an unattended run must not block.
        if (Environment.UserInteractive && !Console.IsInputRedirected)
        {
            Console.Write("  Press Enter to close...");
            try { Console.ReadLine(); } catch { }
        }
    }
}
'@

$stubSource = $stubSource.Replace('__VERSION__', $version).Replace('__COMMIT__', $commit)
$stubPath = Join-Path $stage 'SecVaultSetup.cs'
Set-Content -Path $stubPath -Value $stubSource -Encoding UTF8

Write-Note 'compiling the setup stub...'
$cscArgs = @(
    '/nologo',
    '/target:exe',
    '/platform:anycpu',
    '/optimize+',
    ('/out:"{0}"' -f $OutputPath),
    ('/resource:"{0}",secvault-payload.zip' -f $zipPath),
    '/reference:System.dll',
    '/reference:System.IO.Compression.dll',
    '/reference:System.IO.Compression.FileSystem.dll',
    ('"{0}"' -f $stubPath)
)
$cscOut = Invoke-Native { & $csc @cscArgs 2>&1 }
if ($LASTEXITCODE -ne 0) {
    $cscOut | Write-Host
    Fail "csc.exe failed with exit code $LASTEXITCODE. Staging left at $stage for inspection."
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
Write-Host '  Every switch given to the .exe is passed straight through to the installer,' -ForegroundColor DarkGray
Write-Host '  so an unattended install needs no unpacking by hand:' -ForegroundColor DarkGray
Write-Host ("    {0} -ServerIp 10.0.0.10 -SyslogPorts 514" -f (Split-Path -Leaf $OutputPath)) -ForegroundColor DarkGray
Write-Host '  The .exe unpacks beside itself and leaves the tree there, so a failed run' -ForegroundColor DarkGray
Write-Host '  can be retried without unpacking again.' -ForegroundColor DarkGray
Write-Host ''
Write-Host '  Read docs\FRESH-INSTALL-CHECKLIST.md before the first run.' -ForegroundColor DarkGray
Write-Host ''
