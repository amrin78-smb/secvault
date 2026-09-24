<#
    SecVault-Tls.ps1 — shared TLS helpers, dot-sourced by BOTH installer scripts.

    ⛔ ONE COPY, TWO CALLERS. Install-SecVault.ps1 and Update-SecVault.ps1 both
    need to mint a certificate, edit .env.local and probe the running app.
    Duplicating that logic is how the two scripts drift until a fresh install and
    an upgraded install end up in different states — which is exactly the class
    of bug this product's own notes warn about for its two vendor registries.

    PowerShell 5.1 throughout: no ternary, no '&&', no piping directly out of a
    try/catch. Service state changes are sc.exe only.
#>

# ─────────────────────────────────────────────────────────────────────────────
# OpenSSL
#
# ⛔ New-SelfSignedCertificate CANNOT be used here. On Windows PowerShell 5.1 it
# can only export a PFX — .NET Framework has no PKCS#8 private-key export — and
# node's https.createServer is being handed PEM. Git for Windows is already a
# hard dependency of this suite and bundles OpenSSL 3.x, which is the same
# reasoning (and the same path list) the NocVault suite installer uses for its
# agent-ingest certificates.
# ─────────────────────────────────────────────────────────────────────────────
function Find-SecVaultOpenSsl {
    $paths = @(
        "$env:ProgramFiles\Git\usr\bin\openssl.exe",
        "$env:ProgramFiles\Git\mingw64\bin\openssl.exe",
        "${env:ProgramFiles(x86)}\Git\usr\bin\openssl.exe",
        "C:\Program Files\PostgreSQL\16\bin\openssl.exe"
    )
    foreach ($p in $paths) {
        if ($p -and (Test-Path -LiteralPath $p)) { return $p }
    }
    # PATH last, and via Get-Command — a bare '& openssl' THROWS on a machine
    # that does not have it, which would take down the caller.
    $cmd = Get-Command openssl.exe -ErrorAction SilentlyContinue
    if ($cmd) { return $cmd.Source }
    return $null
}

<#
    Mint a self-signed certificate for this server, if one is not already there.

    ⛔ NEVER OVERWRITES AN EXISTING CERTIFICATE. An operator who has installed a
    real corporate certificate must not have it silently replaced by a
    self-signed one on the next upgrade — that would turn a working, trusted
    console into a browser warning, on a schedule nobody chose.

    ⛔ SANs ARE MANDATORY, NOT OPTIONAL. Every current browser ignores the CN and
    validates against subjectAltName only, so a certificate without SANs is
    rejected outright rather than merely untrusted. Both the IP and the hostname
    go in, because operators reach this console by both.
#>
function New-SecVaultCertificate {
    param(
        [Parameter(Mandatory = $true)][string]$CertDir,
        [Parameter(Mandatory = $true)][string]$ServerIp,
        [string]$LogFile
    )

    $result = [ordered]@{
        Success  = $false
        CertPath = Join-Path $CertDir 'secvault.crt'
        KeyPath  = Join-Path $CertDir 'secvault.key'
        Created  = $false
        Message  = ''
    }

    if ((Test-Path -LiteralPath $result.CertPath) -and (Test-Path -LiteralPath $result.KeyPath)) {
        $result.Success = $true
        $result.Message = 'Existing certificate left untouched.'
        return [pscustomobject]$result
    }

    $openssl = Find-SecVaultOpenSsl
    if (-not $openssl) {
        $result.Message = 'OpenSSL not found (expected with Git for Windows). TLS cannot be enabled.'
        return [pscustomobject]$result
    }

    if (-not (Test-Path -LiteralPath $CertDir)) {
        New-Item -ItemType Directory -Force -Path $CertDir | Out-Null
    }

    $hostName = $env:COMPUTERNAME
    $fqdn = $hostName
    try {
        $ipProps = [System.Net.NetworkInformation.IPGlobalProperties]::GetIPGlobalProperties()
        if ($ipProps.DomainName) { $fqdn = "$hostName.$($ipProps.DomainName)" }
    } catch {
        # Not domain-joined, or the lookup failed. The short name is still valid.
        $fqdn = $hostName
    }

    $sanParts = @("DNS:$hostName", "DNS:localhost", 'IP:127.0.0.1')
    if ($fqdn -ne $hostName) { $sanParts += "DNS:$fqdn" }
    if ($ServerIp) { $sanParts += "IP:$ServerIp" }
    $san = 'subjectAltName=' + ($sanParts -join ',')

    # ⛔ 3650 days. A self-signed certificate that expires turns a working
    # console into a browser wall on a date nobody has written down, and there is
    # no renewal process on an air-gapped box. An operator replacing this with a
    # real certificate chooses their own lifetime.
    # ⛔ NOT $args. That is PowerShell's AUTOMATIC arguments variable. Assigning
    # to it happens to work in a plain function today and becomes a hard error
    # the moment anyone adds [CmdletBinding()] to this function — a failure that
    # would land on whoever touches it next, in the middle of the TLS path, for a
    # reason that has nothing to do with what they changed.
    $opensslArgs = @(
        'req', '-x509', '-newkey', 'rsa:2048', '-nodes',
        '-keyout', $result.KeyPath,
        '-out', $result.CertPath,
        '-days', '3650',
        '-subj', "/CN=$fqdn",
        '-addext', $san
    )

    # ⛔ DO NOT USE `2>&1` ON A NATIVE EXECUTABLE HERE. CLAUDE.md documents this
    # and it still caught me: in PowerShell 5.1, redirecting a native command's
    # stderr into the pipeline wraps every line in an ErrorRecord and sets $? to
    # $false even when the exe exits 0. OpenSSL writes its key-generation
    # PROGRESS ('+++++...') to stderr, so with $ErrorActionPreference = 'Stop'
    # — which Update-SecVault.ps1 sets deliberately — a perfectly successful
    # keygen threw into the catch below and was reported as "OpenSSL failed",
    # with the progress dots as the error message. No certificate was written
    # and the step still logged "succeeded".
    #
    # So: stderr is captured with the preference relaxed, and success is judged
    # by the EXIT CODE and the FILES ON DISK, never by $? or by an exception.
    $out = ''
    $code = 0
    $prevEap = $ErrorActionPreference
    try {
        $ErrorActionPreference = 'Continue'
        $out = & $openssl @opensslArgs 2>&1
        $code = $LASTEXITCODE
    } catch {
        $result.Message = "OpenSSL could not be run: $($_.Exception.Message)"
        $ErrorActionPreference = $prevEap
        return [pscustomobject]$result
    }
    $ErrorActionPreference = $prevEap

    if ($LogFile) { Add-Content -Path $LogFile -Value ($out -join "`n") }

    if ($code -ne 0) {
        $result.Message = "OpenSSL exited with code $code; no certificate was created."
        return [pscustomobject]$result
    }

    if ((Test-Path -LiteralPath $result.CertPath) -and (Test-Path -LiteralPath $result.KeyPath)) {
        $result.Success = $true
        $result.Created = $true
        $result.Message = "Self-signed certificate created for $($sanParts -join ', ')"

        # ⛔ The private key must not be world-readable. It is the whole secret.
        try {
            $acl = Get-Acl -Path $result.KeyPath
            $acl.SetAccessRuleProtection($true, $false)
            # ⛔ WELL-KNOWN SIDs, NEVER THE ENGLISH ACCOUNT NAMES. 'SYSTEM' and
            # 'Administrators' are LOCALISED account names: on a German, French or
            # Japanese Windows they do not resolve, New-Object throws
            # IdentityNotMappedException, and the catch below downgrades that to a
            # cheerful "(NOTE: could not tighten ACL on the key)".
            #
            # ⛔ That is worse than it sounds, because SetAccessRuleProtection has
            # ALREADY stripped inheritance by then. The failure mode is not "a bit
            # looser than intended" -- it is a PRIVATE KEY whose ACL carries no
            # usable grants at all, produced silently, on a host whose language
            # nobody here chose.
            #   S-1-5-18      Local System -- the account the NSSM services run as
            #   S-1-5-32-544  the local Administrators group
            # Both are identical on every Windows installation in every language.
            foreach ($sidValue in @('S-1-5-18', 'S-1-5-32-544')) {
                $sid = New-Object System.Security.Principal.SecurityIdentifier($sidValue)
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $sid,
                    [System.Security.AccessControl.FileSystemRights]::FullControl,
                    [System.Security.AccessControl.AccessControlType]::Allow)
                $acl.AddAccessRule($rule)
            }
            Set-Acl -Path $result.KeyPath -AclObject $acl
        } catch {
            # Not fatal: the key exists and works. Say so rather than fail.
            $result.Message += " (NOTE: could not tighten ACL on the key: $($_.Exception.Message))"
        }
    } else {
        $result.Message = 'OpenSSL reported success but no certificate files were produced.'
    }

    return [pscustomobject]$result
}

<#
    Upsert one KEY=VALUE in .env.local, preserving everything else.

    ⛔ NEVER REWRITES THE WHOLE FILE FROM A TEMPLATE. .env.local holds
    CREDENTIAL_KEY, NEXTAUTH_SECRET and PG_ADMIN_PASSWORD; losing any of them
    orphans every stored credential on the box. Read, replace or append the one
    line, write back.
#>
function Set-SecVaultEnvValue {
    param(
        [Parameter(Mandatory = $true)][string]$EnvPath,
        [Parameter(Mandatory = $true)][string]$Key,
        [Parameter(Mandatory = $true)][AllowEmptyString()][string]$Value
    )

    if (-not (Test-Path -LiteralPath $EnvPath)) { return $false }

    # ⛔ A TRIPWIRE, BECAUSE THE FAILURE ABOVE WAS SILENT AND CUMULATIVE.
    # A real .env.local is a couple of kilobytes. Anything far larger is not
    # configuration, it is corruption -- and rewriting it would launder the
    # corruption into a new file that looks freshly written. Refusing here
    # stops the doubling at the first pass rather than the twentieth, and says
    # what to do about it.
    $envSize = (Get-Item -LiteralPath $EnvPath).Length
    if ($envSize -gt 1MB) {
        Write-Host "[FAIL] $EnvPath is $([int]($envSize / 1MB)) MB. A real .env.local is a few KB, so this file is corrupt and will NOT be rewritten." -ForegroundColor Red
        Write-Host '       Recover the KEY=VALUE lines from it (they are usually intact) or from a .env.local.bak-* beside it, then re-run.' -ForegroundColor Red
        return $false
    }

    # ⛔ -Encoding UTF8 IS LOAD-BEARING, AND ITS ABSENCE COST A PRODUCTION
    # OUTAGE. In Windows PowerShell 5.1 `Get-Content` decodes with the ANSI
    # CODEPAGE, not UTF-8. This function then writes the result back as UTF-8
    # (see the long note below on why the write side is hand-rolled). So every
    # non-ASCII byte is read as a separate cp1252 character and re-encoded as
    # 1-2 bytes -- each character ROUGHLY DOUBLES on every pass, and this runs
    # once per deploy.
    #
    # Measured 2026-09-24 on the reference deployment: the em-dash in the
    # `# Auth (standalone -- ...)` COMMENT that .env.local.example seeds had
    # grown into a single 2.2 GB line. node then refused the file outright
    # (ERR_STRING_TOO_LONG: "Cannot create a string longer than 0x1fffffe8
    # characters"), so NO environment loaded at all and server.js fell back to
    # `TLS: not configured -- serving plain HTTP`. The console came up on
    # PLAINTEXT with no CREDENTIAL_KEY, and every health signal said Running.
    #
    # ⛔ The previous author reasoned carefully about the WRITE encoding and
    # never looked at the READ. An encoding is a ROUND TRIP; checking one half
    # of it proves nothing.
    $raw = Get-Content -Path $EnvPath -Raw -Encoding UTF8
    $pattern = '(?m)^' + [regex]::Escape($Key) + '=.*$'
    $line = "$Key=$Value"

    if ($raw -match $pattern) {
        $updated = [regex]::Replace($raw, $pattern, [System.Text.RegularExpressions.MatchEvaluator] { param($m) $line })
    } else {
        $sep = ''
        if (-not $raw.EndsWith("`n")) { $sep = "`r`n" }
        $updated = $raw + $sep + $line + "`r`n"
    }

    # ⛔ BOM-FREE UTF-8, WRITTEN VIA .NET RATHER THAN `Set-Content -Encoding utf8`.
    # In Windows PowerShell 5.1 `-Encoding utf8` ALWAYS emits a byte-order mark
    # (measured: the file's first three bytes become EF BB BF), and this function
    # rewrites the WHOLE file, so one call stamps a BOM on .env.local permanently.
    #
    # It is harmless only by accident today: .env.local.example happens to open
    # with a `# Server` COMMENT, so the mangled first line is one nothing parses.
    # The moment a KEY is the first line -- a reorder, a hand-edited file, a
    # customer's own .env.local -- that key's NAME silently becomes
    # "﻿DATABASE_URL" and the app reads it as ABSENT. Neither the Next env
    # loader, dotenv, nor lib/envFile.js strips a BOM, and lib/envFile.js's
    # verify-after-write would then compare two equally-mangled copies and pass.
    #
    # A missing DATABASE_URL or CREDENTIAL_KEY is exactly the failure this product
    # is worst at diagnosing: the service starts, sc.exe reports Running, and the
    # cause is three invisible bytes. Do not "simplify" this back to Set-Content.
    #
    # ⛔ Convert-Path FIRST. .NET resolves a RELATIVE path against the process's
    # own current directory, which PowerShell's Set-Location does not change --
    # so a relative $EnvPath would write a second .env.local somewhere else and
    # report success. The file is known to exist (checked above), so this cannot
    # throw here.
    $fullEnvPath = (Convert-Path -LiteralPath $EnvPath)
    [System.IO.File]::WriteAllText(
        $fullEnvPath,
        $updated,
        (New-Object System.Text.UTF8Encoding($false)))
    return $true
}

function Get-SecVaultEnvValue {
    param(
        [Parameter(Mandatory = $true)][string]$EnvPath,
        [Parameter(Mandatory = $true)][string]$Key
    )
    if (-not (Test-Path -LiteralPath $EnvPath)) { return $null }
    # ⛔ UTF8 for the same reason as the writer above: without it a value
    # containing any non-ASCII character is returned mojibake, and a caller
    # comparing it against the real value decides they differ.
    $raw = Get-Content -Path $EnvPath -Raw -Encoding UTF8
    $pattern = '(?m)^' + [regex]::Escape($Key) + '=(.*)$'
    if ($raw -match $pattern) { return $matches[1].Trim() }
    return $null
}

<#
    Probe the running console over HTTP or HTTPS.

    ⛔ THIS EXISTS BECAUSE "SERVICE RUNNING" IS NOT "APP SERVING". NSSM restarts a
    crashing process, so sc.exe reports Running while node crash-loops forever.
    Only an actual HTTP response proves the console came back, and that is what
    the rollback in Update-SecVault.ps1 keys off.

    Any HTTP status counts as alive — /api/health answers 401 when
    unauthenticated, and a 401 is proof the app is serving.
#>
function Test-SecVaultResponding {
    param(
        [Parameter(Mandatory = $true)][int]$Port,
        [switch]$UseHttps,
        [int]$TimeoutSeconds = 60
    )

    $scheme = 'http'
    if ($UseHttps) { $scheme = 'https' }
    $url = "${scheme}://127.0.0.1:${Port}/api/health"

    # A self-signed certificate must not fail this probe: we are checking that
    # the app answers, not that a browser would trust it.
    #
    # ⛔ DO NOT USE `ServerCertificateValidationCallback = { $true }`. It looks
    # right, it is the answer in every search result, and in PowerShell 5.1 it
    # DOES NOT WORK: .NET invokes that delegate on a background thread with no
    # PowerShell runspace, so the scriptblock throws
    #   "There is no Runspace available to run scripts in this thread"
    # and the connection dies with "The underlying connection was closed: An
    # unexpected error occurred on a send."
    #
    # This cost two production outages. The probe ALWAYS returned false over
    # HTTPS, so the updater concluded the console had not come back and rolled
    # back a deployment that had in fact worked — the app log said
    # "TLS: ACTIVE ... listening on https://0.0.0.0:3010" at the very moment the
    # updater decided it was dead. A false negative in a health check is worse
    # than no health check, because it actively destroys a good deployment.
    #
    # ICertificatePolicy is the PS 5.1-compatible route: a real .NET type, whose
    # method runs on the calling thread and needs no runspace.
    if (-not ('SecVaultTrustAllCerts' -as [type])) {
        Add-Type -TypeDefinition @'
using System.Net;
using System.Security.Cryptography.X509Certificates;
public class SecVaultTrustAllCerts : ICertificatePolicy {
    public bool CheckValidationResult(ServicePoint sp, X509Certificate cert, WebRequest req, int problem) {
        return true;
    }
}
'@
    }
    # ⛔ CertificatePolicy IS PROCESS-GLOBAL, AND MUST BE RESTORED IN A finally.
    #
    # Setting it disables certificate validation for EVERY outbound .NET web
    # request in this PowerShell process, not just this probe. Restoring it on
    # the last line -- which is what this did -- only works when nothing in
    # between throws. Update-SecVault.ps1 runs with $ErrorActionPreference =
    # 'Stop', so an Invoke-WebRequest failure that is NOT a WebException (a DNS
    # failure, a malformed URL, an Add-Type problem) escapes this function and
    # leaves the REST of the update -- every later HTTPS call it or anything it
    # dot-sources makes -- silently trusting any certificate presented to it, on
    # a security product, with no trace in the log.
    #
    # The probe is bounded, so the window is short. A leak is not.
    $originalPolicy = [System.Net.ServicePointManager]::CertificatePolicy
    $originalProtocol = [System.Net.ServicePointManager]::SecurityProtocol
    $alive = $false
    try {
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object SecVaultTrustAllCerts
        try {
            [System.Net.ServicePointManager]::SecurityProtocol =
                [System.Net.SecurityProtocolType]::Tls12
        } catch {
            # Older .NET on this host; the default protocol list will have to do.
        }

        $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
        while ((Get-Date) -lt $deadline) {
            try {
                $resp = Invoke-WebRequest -Uri $url -UseBasicParsing -TimeoutSec 10
                if ($resp.StatusCode) { $alive = $true; break }
            } catch {
                # An HTTP error response still proves the app is serving.
                $webResp = $null
                if ($_.Exception -and $_.Exception.Response) { $webResp = $_.Exception.Response }
                if ($webResp) { $alive = $true; break }
            }
            Start-Sleep -Seconds 3
        }
    } finally {
        [System.Net.ServicePointManager]::CertificatePolicy = $originalPolicy
        try {
            [System.Net.ServicePointManager]::SecurityProtocol = $originalProtocol
        } catch {
            # Nothing useful to do here, and a restore failure must not be
            # allowed to mask whatever threw out of the try block above.
        }
    }
    return $alive
}
