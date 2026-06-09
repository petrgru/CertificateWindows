<#
.SYNOPSIS
    Downloads ACME/Let's Encrypt certificates from OPNsense via REST API and
    installs them into the Windows Local Machine certificate store.

.DESCRIPTION
    Uses the OPNsense REST API to search, download, and install certificates
    from the Trust Store into the Windows certificate store.

    No SSH required -- uses HTTP(S) + API key authentication.

    All parameters can be set via .env file (copy .env from .env.example),
    command-line arguments override .env values.

    API endpoints used:
      GET /api/trust/cert/search               List certificates
      GET /api/trust/cert/get/{uuid}            Get certificate details + PEM content
      GET /api/trust/cert/generate_file?uuid=   Download certificate/key file (fallback)

.PARAMETER OpnsenseUrl
    OPNsense base URL (e.g. "http://10.0.0.1" or "https://opnsense.example.com").
    Script appends "/api" automatically.

.PARAMETER ApiKey
    OPNsense API key. Generate from System → Access → Users → Edit user → API keys.

.PARAMETER ApiSecret
    OPNsense API secret. Only shown once when the key is created.

.PARAMETER CertName
    Name (common name) or description pattern to match the certificate.
    If omitted, the script lists available certificates and exits.

.PARAMETER Insecure
    Skip SSL certificate validation (use for self-signed OPNsense certs).

.PARAMETER OutputDir
    Local directory to save downloaded certificate files (default: current directory).

.PARAMETER StoreLocation
    Windows store location: LocalMachine (default) or CurrentUser.

.PARAMETER StoreName
    Windows store name: Root (default, Trusted Root), CA (Intermediate), My (Personal).

.PARAMETER IncludePrivateKey
    Also download and install the private key (packaged as PFX).

.PARAMETER PfxPassword
    Password for PFX (required with -IncludePrivateKey if not provided interactively).

.PARAMETER EnvPath
    Path to the .env file. Default: looks for .env in the script directory, then current directory.

.EXAMPLE
    # List all certificates in the trust store (using .env)
    .\Get-OpnSenseCert-API.ps1

.EXAMPLE
    # Find and download a cert by common name (using .env)
    .\Get-OpnSenseCert-API.ps1 -CertName "*.example.com"

.EXAMPLE
    # Override .env values on command line
    .\Get-OpnSenseCert-API.ps1 -OpnsenseUrl "http://10.0.0.1" -ApiKey $key -ApiSecret $secret -CertName "mail.example.com"

.EXAMPLE
    # Download cert + private key as PFX into LocalMachine\My (Personal store)
    .\Get-OpnSenseCert-API.ps1 -CertName "mail.example.com" -IncludePrivateKey -StoreName My -Insecure

.NOTES
    Requires: PowerShell 5.1+ (Windows), Administrator for LocalMachine store.
    OPNsense API key must have "System: Certificate Manager" privilege.
#>

param(
    [Parameter(Mandatory = $false)]
    [string]$OpnsenseUrl,

    [Parameter(Mandatory = $false)]
    [string]$ApiKey,

    [Parameter(Mandatory = $false)]
    [string]$ApiSecret,

    [Parameter(Mandatory = $false)]
    [string]$CertName,

    [Parameter(Mandatory = $false)]
    [switch]$Insecure,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir,

    [Parameter(Mandatory = $false)]
    [ValidateSet("LocalMachine", "CurrentUser")]
    [string]$StoreLocation,

    [Parameter(Mandatory = $false)]
    [ValidateSet("Root", "CA", "My")]
    [string]$StoreName,

    [Parameter(Mandatory = $false)]
    [switch]$IncludePrivateKey,

    [Parameter(Mandatory = $false)]
    [SecureString]$PfxPassword,

    [Parameter(Mandatory = $false)]
    [string]$EnvPath
)

# ──────────────────────────────────────
# .env loader
# ──────────────────────────────────────
function Read-EnvFile {
    param([string]$Path)
    if (-not (Test-Path $Path)) { return @{} }

    $envVars = @{}
    Get-Content $Path | ForEach-Object {
        $line = $_.Trim()
        if ($line -and $line -notmatch '^\s*#') {
            $parts = $line -split '=', 2
            if ($parts.Count -eq 2) {
                $key = $parts[0].Trim()
                $val = $parts[1].Trim()
                # Strip surrounding quotes if present
                $val = $val -replace '^["'']|["'']$', ''
                $envVars[$key] = $val
            }
        }
    }
    return $envVars
}

# ──────────────────────────────────────
# Load .env (script directory first, then current directory)
# ──────────────────────────────────────
if (-not $EnvPath) {
    $scriptDir = Split-Path -Parent $MyInvocation.MyCommand.Path
    $candidates = @(
        Join-Path $scriptDir ".env"
        Join-Path (Get-Location) ".env"
    )
    foreach ($cand in $candidates) {
        if (Test-Path $cand) { $EnvPath = $cand; break }
    }
}

$envSettings = @{}
if ($EnvPath) {
    $envSettings = Read-EnvFile -Path $EnvPath
    Write-Host "[OK] Loaded env: $EnvPath" -ForegroundColor Green
}

# ──────────────────────────────────────
# Apply .env defaults, CLI overrides
# ──────────────────────────────────────
# Helper: use env value if param is $null/empty
function Use-EnvOrDefault {
    param($ParamValue, $EnvKey, $Default = $null)
    if ($ParamValue -and (-not [string]::IsNullOrEmpty("$ParamValue"))) { return $ParamValue }
    if ($envSettings.ContainsKey($EnvKey) -and $envSettings[$EnvKey]) { return $envSettings[$EnvKey] }
    return $Default
}

$script:OpnsenseUrl   = Use-EnvOrDefault $OpnsenseUrl   "OPNSENSE_URL"
$script:ApiKey        = Use-EnvOrDefault $ApiKey        "OPNSENSE_API_KEY"
$script:ApiSecret     = Use-EnvOrDefault $ApiSecret      "OPNSENSE_API_SECRET"
$script:CertName      = Use-EnvOrDefault $CertName       "OPNSENSE_CERT_NAME"
$script:OutputDir     = Use-EnvOrDefault $OutputDir      "OPNSENSE_OUTPUT_DIR" "."
$script:StoreLocation = Use-EnvOrDefault $StoreLocation  "OPNSENSE_STORE_LOCATION" "LocalMachine"
$script:StoreName     = Use-EnvOrDefault $StoreName      "OPNSENSE_STORE_NAME" "Root"

# Env booleans: treat "true"/"1"/"yes" as true
$envInsecure          = Use-EnvOrDefault $null           "OPNSENSE_INSECURE"
if (-not $Insecure -and $envInsecure) {
    $Insecure = $envInsecure -match '^(true|1|yes)$'
}
$envIncludeKey        = Use-EnvOrDefault $null           "OPNSENSE_INCLUDE_PRIVATE_KEY"
if (-not $IncludePrivateKey -and $envIncludeKey) {
    $IncludePrivateKey = $envIncludeKey -match '^(true|1|yes)$'
}

# Normalize URL: ensure it has scheme, strip trailing slash
if ($script:OpnsenseUrl) {
    $script:OpnsenseUrl = $script:OpnsenseUrl.TrimEnd('/')
    if ($script:OpnsenseUrl -notmatch '^https?://') {
        Write-Warning "No scheme in URL '$script:OpnsenseUrl'. Defaulting to https://"
        $script:OpnsenseUrl = "https://$script:OpnsenseUrl"
    }
}

# Validate required params
$missing = @()
if (-not $script:OpnsenseUrl) { $missing += "OpnsenseUrl (or OPNSENSE_URL in .env)" }
if (-not $script:ApiKey)      { $missing += "ApiKey (or OPNSENSE_API_KEY in .env)" }
if (-not $script:ApiSecret)   { $missing += "ApiSecret (or OPNSENSE_API_SECRET in .env)" }
if ($missing.Count -gt 0) {
    Write-Error "Missing required parameters: $($missing -join ', ')"
    Write-Host "`nProvide via command line or create a .env file:" -ForegroundColor Yellow
    Write-Host "  OPNSENSE_URL=http(s)://your-opnsense-host" -ForegroundColor Yellow
    Write-Host "  OPNSENSE_API_KEY=your_key" -ForegroundColor Yellow
    Write-Host "  OPNSENSE_API_SECRET=your_secret" -ForegroundColor Yellow
    exit 1
}

# ──────────────────────────────────────
# TLS / SSL configuration (global, before any API calls)
# ──────────────────────────────────────
$psMajor = $PSVersionTable.PSVersion.Major
Write-Host "[SETUP] PowerShell $($PSVersionTable.PSVersion.ToString()), URL: $script:OpnsenseUrl" -ForegroundColor DarkGray

# Enable TLS 1.2+ (needed by most OPNsense versions)
[System.Net.ServicePointManager]::SecurityProtocol = `
    [System.Net.SecurityProtocolType]::Tls12 -bor `
    [System.Net.SecurityProtocolType]::Tls13 -bor `
    [System.Net.SecurityProtocolType]::Tls11 -bor `
    [System.Net.SecurityProtocolType]::Tls

# Bypass SSL certificate validation if -Insecure or OPNSENSE_INSECURE=true
if ($Insecure -and $script:OpnsenseUrl -match '^https://') {
    if ($psMajor -ge 6) {
        Write-Host "[SETUP] Insecure mode: using Invoke-RestMethod -SkipCertificateCheck" -ForegroundColor Yellow
    }
    else {
        Write-Host "[SETUP] Insecure mode: using ServicePointManager callback" -ForegroundColor Yellow
        Add-Type -TypeDefinition @"
            using System.Net;
            using System.Security.Cryptography.X509Certificates;
            public class TrustAllPolicy : ICertificatePolicy {
                public bool CheckValidationResult(ServicePoint sp, X509Certificate c, WebRequest r, int p) { return true; }
            }
"@ -ErrorAction SilentlyContinue | Out-Null
        [System.Net.ServicePointManager]::CertificatePolicy = New-Object TrustAllPolicy
        [System.Net.ServicePointManager]::ServerCertificateValidationCallback = { $true }
    }
}
else {
    Write-Host "[SETUP] Secure mode: SSL cert validation enabled" -ForegroundColor DarkGray
}

# ──────────────────────────────────────
# Helper functions
# ──────────────────────────────────────
function Test-CommandAvailable {
    param([string]$Command)
    $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

# Build the Authorization header value
function New-BasicAuthHeader {
    $credBytes = [Text.Encoding]::ASCII.GetBytes("${script:ApiKey}:${script:ApiSecret}")
    $credBase64 = [Convert]::ToBase64String($credBytes)
    return "Basic $credBase64"
}

# Detect whether an exception is an SSL/certificate error
function Test-SslError {
    param($Exception)
    $msg = $Exception.Message
    if ($Exception.InnerException) { $msg += " " + $Exception.InnerException.Message }
    # Common SSL error keywords across locales
    $keywords = @("certificate", "ssl", "tls", "authentication", "schannel",
                  "certifikát", "certificado", "zertifikat", "certificat",
                  "chain", "trust", "remoteserver")
    foreach ($kw in $keywords) {
        if ($msg -match $kw) { return $true }
    }
    return $false
}

# Make an API request using curl.exe (for SSL-bypass scenarios where Invoke-RestMethod fails)
function Invoke-CurlApiRequest {
    param(
        [string]$Method = "GET",
        [string]$Url,
        [string]$AuthHeader
    )
    Write-Host "  [curl] Invoke-RestMethod failed, retrying with curl.exe ..." -ForegroundColor DarkYellow

    # Write to temp file to avoid PowerShell pipeline encoding corruption (esp. on Windows)
    $tmpFile = [System.IO.Path]::GetTempFileName()
    $outArgs = @("-s", "-X", $Method) + @("-u", "${script:ApiKey}:${script:ApiSecret}")
    if ($Insecure) { $outArgs += "-k" }
    $outArgs += @("--output", $tmpFile, $Url)
    try {
        & "curl.exe" @outArgs 2>$null
        if ($LASTEXITCODE -ne 0) {
            throw "curl exit code $LASTEXITCODE"
        }
        $rawJson = [System.IO.File]::ReadAllText($tmpFile).Trim()
        if (-not $rawJson) {
            throw "curl returned empty response"
        }
        return ($rawJson | ConvertFrom-Json)
    }
    catch {
        throw "curl returned invalid JSON: $rawJson"
    }
    finally {
        if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force }
    }
}

# Download a file using curl.exe (SSL-bypass fallback)
function Invoke-CurlApiDownload {
    param(
        [string]$Url,
        [string]$OutputPath
    )
    $curlArgs = @("-s", "-o", $OutputPath) + @("-u", "${script:ApiKey}:${script:ApiSecret}")
    if ($Insecure) { $curlArgs += "-k" }
    $curlArgs += $Url

    Write-Host "  [curl] Invoke-RestMethod failed, retrying with curl.exe ..." -ForegroundColor DarkYellow
    & "curl.exe" @curlArgs 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) {
        throw "curl download failed with exit code $LASTEXITCODE"
    }
    if ((Test-Path $OutputPath) -and ((Get-Item $OutputPath).Length -gt 0)) {
        return $true
    }
    throw "curl download produced empty file"
}

function New-OpnsenseApiRequest {
    param(
        [string]$Method = "GET",
        [string]$Endpoint,
        [hashtable]$QueryParams = @{}
    )
    $baseUrl = "$script:OpnsenseUrl/api"
    $url = "$baseUrl$Endpoint"
    if ($QueryParams.Count -gt 0) {
        $pairs = $QueryParams.Keys | ForEach-Object { "$_=$([Uri]::EscapeDataString($QueryParams[$_]))" }
        $url += "?" + ($pairs -join "&")
    }

    $authHeader = New-BasicAuthHeader
    $headers = @{
        Authorization = $authHeader
        Accept        = "application/json"
    }

    $params = @{
        Uri         = $url
        Method      = $Method
        Headers     = $headers
        ContentType = "application/json"
    }

    # PS 6+ uses -SkipCertificateCheck
    if ($Insecure -and $url -match '^https://' -and $psMajor -ge 6) {
        $params.SkipCertificateCheck = $true
    }

    try {
        return (Invoke-RestMethod @params)
    }
    catch {
        $ex = $_.Exception

        # Check if it's a response-level error (got HTTP response with error code)
        if ($ex.Response) {
            $statusCode = ""
            $statusDesc = ""
            $body = ""
            try {
                $statusCode = $ex.Response.StatusCode.value__
                $statusDesc = $ex.Response.StatusCode
                $reader = New-Object System.IO.StreamReader($ex.Response.GetResponseStream())
                $body = $reader.ReadToEnd()
                $reader.Close()
            }
            catch { }
            throw "API $Method $Endpoint returned $statusCode ($statusDesc)`n$body"
        }

        # SSL / connection error — try curl fallback
        if ($Insecure -and $url -match '^https://' -and (Test-CommandAvailable "curl.exe")) {
            return (Invoke-CurlApiRequest -Method $Method -Url $url -AuthHeader $authHeader)
        }

        # Generic error, no fallback available
        $innerMsg = if ($ex.InnerException) { $ex.InnerException.Message } else { "" }
        if ($innerMsg) { throw "API $Method $Endpoint failed - $innerMsg" }
        else { throw "API $Method $Endpoint failed - $($ex.Message)" }
    }
}

function New-OpnsenseApiDownload {
    param(
        [string]$Endpoint,
        [hashtable]$QueryParams = @{},
        [string]$OutputPath
    )
    $baseUrl = "$script:OpnsenseUrl/api"
    $url = "$baseUrl$Endpoint"
    if ($QueryParams.Count -gt 0) {
        $pairs = $QueryParams.Keys | ForEach-Object { "$_=$([Uri]::EscapeDataString($QueryParams[$_]))" }
        $url += "?" + ($pairs -join "&")
    }

    $authHeader = New-BasicAuthHeader
    $headers = @{
        Authorization = $authHeader
        Accept        = "*/*"
    }

    $dlParams = @{
        Uri     = $url
        Method  = "GET"
        Headers = $headers
        OutFile = $OutputPath
    }
    # PS 6+ uses -SkipCertificateCheck
    if ($Insecure -and $url -match '^https://' -and $psMajor -ge 6) {
        $dlParams.SkipCertificateCheck = $true
    }

    try {
        Invoke-RestMethod @dlParams
        return $true
    }
    catch {
        $ex = $_.Exception

        # Response-level error (non-SSL) — give up
        if ($ex.Response) {
            return $_
        }

        # SSL / connection error — try curl fallback
        if ($Insecure -and $url -match '^https://' -and (Test-CommandAvailable "curl.exe")) {
            return (Invoke-CurlApiDownload -Url $url -OutputPath $OutputPath)
        }

        return $_
    }
}

# ──────────────────────────────────────
# STEP 0: Preflight checks
# ──────────────────────────────────────
Write-Host "=== Get-OpnSenseCert-API ===" -ForegroundColor Cyan
Write-Host "URL: $script:OpnsenseUrl" -ForegroundColor DarkGray

# Admin check for LocalMachine
if ($script:StoreLocation -eq "LocalMachine") {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "LocalMachine cert store requires Administrator. Restart as Admin."
        exit 1
    }
    Write-Host "[OK] Running as Administrator" -ForegroundColor Green
}

# ──────────────────────────────────────
# STEP 1: Test API connectivity
# ──────────────────────────────────────
Write-Host "`nTest: Connecting to OPNsense API ..." -ForegroundColor Yellow
try {
    $result = New-OpnsenseApiRequest -Endpoint "/core/firmware/status"
    Write-Host "[OK] Connected to OPNsense" -ForegroundColor Green
}
catch {
    Write-Error "Cannot reach OPNsense API: $_"
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Verify the URL is correct (hostname:port)"
    Write-Host "  2. Check API credentials (System → Access → Users → Edit user → API keys)"
    Write-Host "  3. Use -Insecure if OPNsense has a self-signed certificate"
    Write-Host "  4. Test manually: curl -k -u `"key:secret`" $script:OpnsenseUrl/api/core/firmware/status"
    exit 1
}

# ──────────────────────────────────────
# STEP 2: List certificates from trust store
# ──────────────────────────────────────
Write-Host "`nFetch: Certificate list from trust store ..." -ForegroundColor Yellow
try {
    $certs = New-OpnsenseApiRequest -Endpoint "/trust/cert/search"
}
catch {
    Write-Error "Failed to list certificates: $_"
    Write-Host "Ensure the API user has 'System: Certificate Manager' privilege." -ForegroundColor Yellow
    exit 1
}

if (-not $certs.rows -or $certs.rows.Count -eq 0) {
    Write-Error "No certificates found in the trust store."
    exit 1
}

# ──────────────────────────────────────
# STEP 3: Discovery mode or find target cert
# ──────────────────────────────────────
if (-not $script:CertName) {
    # Discovery mode
    Write-Host "`n=== Available Certificates (Total: $($certs.total)) ===" -ForegroundColor Cyan
    Write-Host "  {0,-38} {1,-30} {2,-20}" -f "UUID", "Common Name", "Description" -ForegroundColor White
    Write-Host "  " + ("-" * 90) -ForegroundColor DarkGray

    foreach ($row in $certs.rows) {
        $cn = if ($row.commonname) { $row.commonname } else { "(no CN)" }
        $desc = if ($row.descr) { $row.descr } else { "" }
        Write-Host "  {0,-38} {1,-30} {2,-20}" -f $row.uuid, $cn, $desc
    }

    Write-Host "`nTo download a certificate, re-run with -CertName '<commonname>'" -ForegroundColor Yellow
    Write-Host "  or set OPNSENSE_CERT_NAME in .env" -ForegroundColor Yellow
    Write-Host "  e.g. -CertName '*.example.com'  (matches common name)" -ForegroundColor Yellow
    Write-Host "  Tip: use -CertName '*' to see all certs with their UUIDs" -ForegroundColor Yellow
    exit 0
}
else {
    # Find matching certificate(s)
    $matchingCerts = @()
    foreach ($row in $certs.rows) {
        $cn = if ($row.commonname) { $row.commonname } else { "" }
        $desc = if ($row.descr) { $row.descr } else { "" }
        if ($cn -like $script:CertName -or $desc -like $script:CertName -or $row.uuid -like $script:CertName) {
            $matchingCerts += $row
        }
    }

    if ($matchingCerts.Count -eq 0) {
        Write-Error "No certificates matching '$script:CertName' found."
        Write-Host "Use the script without -CertName to list all available certs." -ForegroundColor Yellow
        exit 1
    }

    if ($matchingCerts.Count -gt 1) {
        Write-Host "[WARN] Multiple certificates match '$script:CertName':" -ForegroundColor Yellow
        $i = 0
        foreach ($match in $matchingCerts) {
            Write-Host "  [$i] UUID: $($match.uuid)  CN: $($match.commonname)  Desc: $($match.descr)"
            $i++
        }
        # Try to pick the best match -- prioritize ACME certs
        $acmeMatches = $matchingCerts | Where-Object { $_.descr -like "*ACME*" -or $_.descr -like "*Let's Encrypt*" }
        if ($acmeMatches.Count -eq 1) {
            $target = $acmeMatches
            Write-Host "[OK] Auto-selected ACME cert: $($target.commonname)" -ForegroundColor Green
        }
        else {
            Write-Error "Specify a more precise -CertName or use the UUID directly."
            exit 1
        }
    }
    else {
        $target = $matchingCerts[0]
    }
}

$certUuid = $target.uuid
$certCn = $target.commonname
Write-Host "[OK] Selected: $certCn (UUID: $certUuid)" -ForegroundColor Green

# ──────────────────────────────────────
# STEP 4: Get certificate details (PEM content)
# ──────────────────────────────────────
Write-Host "`nFetch: Certificate details ..." -ForegroundColor Yellow
try {
    $certDetail = New-OpnsenseApiRequest -Endpoint "/trust/cert/get/$certUuid"
    Write-Host "[OK] Got certificate details" -ForegroundColor Green
}
catch {
    Write-Error "Failed to get certificate details: $_"
    exit 1
}

# Extract PEM content -- the field name varies by OPNsense version
# Common names: crt_payload, crt, certificate, pem
$pemContent = $null
$keyContent = $null

# Try to find the certificate field
$certFields = $certDetail | Get-Member -MemberType Properties | Where-Object { $_.Name -ne "uuid" }
$certObj = $certDetail.($certFields[0].Name)  # Usually "cert"

$possibleCertFields = @("crt_payload", "crt", "certificate", "pem", "cert")
foreach ($field in $possibleCertFields) {
    if ($certObj.$field -and $certObj.$field -like "-----BEGIN*") {
        $pemContent = $certObj.$field
        Write-Host "[OK] Found certificate PEM in field 'cert.$field'" -ForegroundColor Green
        break
    }
}

if (-not $pemContent) {
    # Try generate_file as fallback
    Write-Host "PEM not found in API response. Trying generate_file endpoint..." -ForegroundColor Yellow
    $outDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($script:OutputDir)
    if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

    $fallbackPem = Join-Path $outDir "$certCn.pem"
    $result = New-OpnsenseApiDownload -Endpoint "/trust/cert/generate_file" -QueryParams @{uuid = $certUuid; type = "crt"} -OutputPath $fallbackPem

    if ($result -eq $true -and (Test-Path $fallbackPem) -and ((Get-Item $fallbackPem).Length -gt 0)) {
        $pemContent = Get-Content $fallbackPem -Raw
        Write-Host "[OK] Downloaded via generate_file: $fallbackPem" -ForegroundColor Green
    }
    else {
        Write-Error "Could not extract certificate PEM from API."
        Write-Host "  The 'get' endpoint response structure was:" -ForegroundColor Yellow
        $certDetail | ConvertTo-Json -Depth 2 | Write-Host -ForegroundColor DarkGray
        exit 1
    }
}

# Extract private key if needed
if ($IncludePrivateKey) {
    $possibleKeyFields = @("prv_payload", "prv", "private_key", "key", "privatekey")
    foreach ($field in $possibleKeyFields) {
        if ($certObj.$field -and $certObj.$field -like "-----BEGIN*") {
            $keyContent = $certObj.$field
            Write-Host "[OK] Found private key in field 'cert.$field'" -ForegroundColor Green
            break
        }
    }

    if (-not $keyContent) {
        Write-Host "Private key not in API response. Trying generate_file..." -ForegroundColor Yellow
        $fallbackKey = Join-Path $outDir "$certCn.key"
        $result = New-OpnsenseApiDownload -Endpoint "/trust/cert/generate_file" -QueryParams @{uuid = $certUuid; type = "prv"} -OutputPath $fallbackKey
        if ($result -eq $true -and (Test-Path $fallbackKey) -and ((Get-Item $fallbackKey).Length -gt 0)) {
            $keyContent = Get-Content $fallbackKey -Raw
            Write-Host "[OK] Downloaded private key via generate_file" -ForegroundColor Green
        }
        else {
            Write-Error "Private key not available from API. The cert is in the store without its key."
            exit 1
        }
    }
}

# ──────────────────────────────────────
# STEP 5: Save PEM files
# ──────────────────────────────────────
$outDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($script:OutputDir)
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

$safeName = $certCn -replace '[\*:]', '_'
$pemPath = Join-Path $outDir "$safeName.pem"
$pemContent | Set-Content $pemPath -NoNewline
Write-Host "[OK] Saved: $pemPath" -ForegroundColor Green

# ──────────────────────────────────────
# STEP 6: Import into Windows cert store
# ──────────────────────────────────────
if ($IncludePrivateKey -and $keyContent) {
    # Save key file
    $keyPath = Join-Path $outDir "$safeName.key"
    $keyContent | Set-Content $keyPath -NoNewline
    Write-Host "[OK] Saved: $keyPath" -ForegroundColor Green

    # Build PFX
    if (-not $PfxPassword) {
        $PfxPassword = Read-Host "Enter PFX password" -AsSecureString
        $confirm = Read-Host "Confirm PFX password" -AsSecureString
        $p1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword))
        $p2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirm))
        if ($p1 -ne $p2) { Write-Error "Passwords don't match."; exit 1 }
    }

    $pfxPath = Join-Path $outDir "$safeName.pfx"
    $plainPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword))

    Write-Host "`nCreate: PFX bundle ..." -ForegroundColor Yellow
    if (Test-CommandAvailable "openssl") {
        $args = @("pkcs12", "-export", "-out", $pfxPath, "-in", $pemPath, "-inkey", $keyPath, "-passout", "pass:$plainPass")
        $proc = Start-Process -FilePath "openssl" -ArgumentList $args -NoNewWindow -Wait -PassThru
        if ($proc.ExitCode -ne 0) { throw "openssl failed (exit $($proc.ExitCode))" }
    }
    elseif (Test-CommandAvailable "certutil") {
        $args = @("-mergepfx", "$pemPath,$keyPath", $pfxPath, $plainPass)
        $proc = Start-Process -FilePath "certutil" -ArgumentList $args -NoNewWindow -Wait -PassThru
        if ($proc.ExitCode -ne 0) { throw "certutil failed (exit $($proc.ExitCode))" }
    }
    else {
        Write-Error "Need openssl or certutil to create PFX. Install one and retry."
        exit 1
    }

    Write-Host "[OK] PFX: $pfxPath" -ForegroundColor Green
    Write-Host "`nImport: PFX -> $script:StoreLocation\$script:StoreName ..." -ForegroundColor Yellow
    Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\$script:StoreLocation\$script:StoreName" -Password $PfxPassword -Exportable | Out-Null
    Write-Host "[OK] Imported to $script:StoreLocation\$script:StoreName" -ForegroundColor Green
}
else {
    Write-Host "`nImport: PEM -> $script:StoreLocation\$script:StoreName ..." -ForegroundColor Yellow
    try {
        Import-Certificate -FilePath $pemPath -CertStoreLocation "Cert:\$script:StoreLocation\$script:StoreName" | Out-Null
        Write-Host "[OK] Imported to $script:StoreLocation\$script:StoreName" -ForegroundColor Green
    }
    catch {
        Write-Error "Import failed: $_"
        Write-Host "  Tip: If cert is already trusted, try -StoreName CA instead of Root." -ForegroundColor Yellow
        exit 1
    }
}

# ──────────────────────────────────────
# STEP 7: Verify
# ──────────────────────────────────────
Write-Host "`nVerify: Installed certificate ..." -ForegroundColor Yellow
try {
    $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($pemPath)
    $thumbprint = $x509.Thumbprint
    $installed = Get-ChildItem "Cert:\$script:StoreLocation\$script:StoreName" | Where-Object { $_.Thumbprint -eq $thumbprint }
    if ($installed) {
        $installed | ForEach-Object {
            Write-Host "  Subject: $($_.Subject)" -ForegroundColor Green
            Write-Host "  Thumbprint: $($_.Thumbprint)" -ForegroundColor Green
            Write-Host "  Not After: $($_.NotAfter)" -ForegroundColor Green
            Write-Host "  Has Private Key: $($_.HasPrivateKey)" -ForegroundColor Green
        }
    }
    else {
        Write-Warning "Certificate not found in store (unexpected)."
    }
}
catch {
    $dump = & certutil -dump $pemPath 2>&1 | Out-String
    $match = [regex]::Match($dump, 'Cert Hash\(sha1\):\s+([\w\d]+)')
    if ($match.Success) {
        $tp = $match.Groups[1].Value
        $installed = Get-ChildItem "Cert:\$script:StoreLocation\$script:StoreName" | Where-Object { $_.Thumbprint -eq $tp }
        if ($installed) {
            $installed | ForEach-Object { Write-Host "  Subject: $($_.Subject)`n  Thumbprint: $($_.Thumbprint)" -ForegroundColor Green }
        }
    }
    else {
        Write-Warning "Could not verify: $_"
    }
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan
Write-Host "Certificate: $pemPath" -ForegroundColor Green
Write-Host "Store: $script:StoreLocation\$script:StoreName" -ForegroundColor Green
