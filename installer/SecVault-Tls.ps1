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
    $args = @(
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
        $out = & $openssl @args 2>&1
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
            foreach ($who in @('SYSTEM', 'Administrators')) {
                $rule = New-Object System.Security.AccessControl.FileSystemAccessRule(
                    $who, 'FullControl', 'Allow')
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

    $raw = Get-Content -Path $EnvPath -Raw
    $pattern = '(?m)^' + [regex]::Escape($Key) + '=.*$'
    $line = "$Key=$Value"

    if ($raw -match $pattern) {
        $updated = [regex]::Replace($raw, $pattern, [System.Text.RegularExpressions.MatchEvaluator] { param($m) $line })
    } else {
        $sep = ''
        if (-not $raw.EndsWith("`n")) { $sep = "`r`n" }
        $updated = $raw + $sep + $line + "`r`n"
    }

    Set-Content -Path $EnvPath -Value $updated -Encoding utf8 -NoNewline
    return $true
}

function Get-SecVaultEnvValue {
    param(
        [Parameter(Mandatory = $true)][string]$EnvPath,
        [Parameter(Mandatory = $true)][string]$Key
    )
    if (-not (Test-Path -LiteralPath $EnvPath)) { return $null }
    $raw = Get-Content -Path $EnvPath -Raw
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
    $originalCallback = [System.Net.ServicePointManager]::ServerCertificateValidationCallback
    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    try {
        [System.Net.ServicePointManager]::SecurityProtocol =
            [System.Net.SecurityProtocolType]::Tls12
    } catch {
        # Older .NET on this host; the default protocol list will have to do.
    }

    $deadline = (Get-Date).AddSeconds($TimeoutSeconds)
    $alive = $false
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

    [System.Net.ServicePointManager]::ServerCertificateValidationCallback = $originalCallback
    return $alive
}
