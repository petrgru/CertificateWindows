<#
.SYNOPSIS
    Downloads certificate + private key from OPNsense via REST API.

.DESCRIPTION
    Downloads certificate PEM and private key from OPNsense trust store
    and saves them as .crt and .key files. No certificate store import.

    No SSH required -- uses HTTP(S) + API key authentication.

    All parameters can be set via .env file (copy .env from .env.example),
    command-line arguments override .env values.

    API endpoints used:
      GET /api/trust/cert/search                      List certificates
      GET /api/trust/cert/generate_file/{uuid}/{type}  Download cert (type=crt) or key (type=key)

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
    Directory to save .crt and .key files (default: current directory).

.PARAMETER EnvPath
    Path to the .env file. Default: looks for .env in the script directory, then current directory.

.EXAMPLE
    # List all certificates in the trust store (using .env)
    .\Get-OpnSenseCert-API.ps1

.EXAMPLE
    # Find and download a cert by common name
    .\Get-OpnSenseCert-API.ps1 -CertName "*.example.com"

.EXAMPLE
    # Override .env values on command line
    .\Get-OpnSenseCert-API.ps1 -OpnsenseUrl "http://10.0.0.1" -ApiKey $key -ApiSecret $secret -CertName "mail.example.com"

.NOTES
    Requires: PowerShell 5.1+ (Windows)
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
function Use-EnvOrDefault {
    param($ParamValue, $EnvKey, $Default = $null)
    if ($ParamValue -and (-not [string]::IsNullOrEmpty("$ParamValue"))) { return $ParamValue }
    if ($envSettings.ContainsKey($EnvKey) -and $envSettings[$EnvKey]) { return $envSettings[$EnvKey] }
    return $Default
}

$script:OpnsenseUrl  = Use-EnvOrDefault $OpnsenseUrl   "OPNSENSE_URL"
$script:ApiKey       = Use-EnvOrDefault $ApiKey        "OPNSENSE_API_KEY"
$script:ApiSecret    = Use-EnvOrDefault $ApiSecret      "OPNSENSE_API_SECRET"
$script:CertName     = Use-EnvOrDefault $CertName       "OPNSENSE_CERT_NAME"
$script:OutputDir    = Use-EnvOrDefault $OutputDir      "OPNSENSE_OUTPUT_DIR" "."

$envInsecure = Use-EnvOrDefault $null "OPNSENSE_INSECURE"
if (-not $Insecure -and $envInsecure) {
    $Insecure = $envInsecure -match '^(true|1|yes)$'
}

# Normalize URL
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
# TLS / SSL configuration
# ──────────────────────────────────────
$psMajor = $PSVersionTable.PSVersion.Major
Write-Host "[SETUP] PowerShell $($PSVersionTable.PSVersion.ToString()), URL: $script:OpnsenseUrl" -ForegroundColor DarkGray

[System.Net.ServicePointManager]::SecurityProtocol = `
    [System.Net.SecurityProtocolType]::Tls12 -bor `
    [System.Net.SecurityProtocolType]::Tls13 -bor `
    [System.Net.SecurityProtocolType]::Tls11 -bor `
    [System.Net.SecurityProtocolType]::Tls

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

function New-BasicAuthHeader {
    $credBytes = [Text.Encoding]::ASCII.GetBytes("${script:ApiKey}:${script:ApiSecret}")
    $credBase64 = [Convert]::ToBase64String($credBytes)
    return "Basic $credBase64"
}

function Invoke-CurlApiRequest {
    param(
        [string]$Method = "GET",
        [string]$Url
    )
    Write-Host "  [curl] Invoke-RestMethod failed, retrying with curl.exe ..." -ForegroundColor DarkYellow

    $tmpFile = [System.IO.Path]::GetTempFileName()
    $outArgs = @("-s", "-X", $Method) + @("-u", "${script:ApiKey}:${script:ApiSecret}")
    if ($Insecure) { $outArgs += "-k" }
    $outArgs += @("--output", $tmpFile, $Url)
    try {
        & "curl.exe" @outArgs 2>$null
        if ($LASTEXITCODE -ne 0) { throw "curl exit code $LASTEXITCODE" }
        $rawJson = [System.IO.File]::ReadAllText($tmpFile).Trim()
        if (-not $rawJson) { throw "curl returned empty response" }
        try { return (ConvertFrom-Json -InputObject $rawJson) }
        catch {
            Add-Type -AssemblyName System.Web.Extensions -ErrorAction Stop
            $js = New-Object System.Web.Script.Serialization.JavaScriptSerializer
            $js.MaxJsonLength = $rawJson.Length + 1
            return $js.DeserializeObject($rawJson)
        }
    }
    catch { throw "curl returned invalid JSON: $rawJson" }
    finally { if (Test-Path $tmpFile) { Remove-Item $tmpFile -Force } }
}

function Invoke-CurlFileDownload {
    param([string]$Url, [string]$OutputPath)
    $curlArgs = @("-s", "-o", $OutputPath) + @("-u", "${script:ApiKey}:${script:ApiSecret}")
    if ($Insecure) { $curlArgs += "-k" }
    $curlArgs += $Url
    Write-Host "  [curl] Downloading file ..." -ForegroundColor DarkYellow
    & "curl.exe" @curlArgs 2>&1 | Out-Null
    if ($LASTEXITCODE -ne 0) { throw "curl download failed with exit code $LASTEXITCODE" }
    if ((Test-Path $OutputPath) -and ((Get-Item $OutputPath).Length -gt 0)) { return }
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
    $headers = @{ Authorization = $authHeader; Accept = "application/json" }
    $params = @{ Uri = $url; Method = $Method; Headers = $headers; ContentType = "application/json" }

    if ($Insecure -and $url -match '^https://' -and $psMajor -ge 6) {
        $params.SkipCertificateCheck = $true
    }

    try { return (Invoke-RestMethod @params) }
    catch {
        $ex = $_.Exception
        if ($ex.Response) {
            $statusCode = ""; $statusDesc = ""; $body = ""
            try {
                $statusCode = $ex.Response.StatusCode.value__
                $statusDesc = $ex.Response.StatusCode
                $reader = New-Object System.IO.StreamReader($ex.Response.GetResponseStream())
                $body = $reader.ReadToEnd(); $reader.Close()
            } catch { }
            throw "API $Method $Endpoint returned $statusCode ($statusDesc)`n$body"
        }
        if ($Insecure -and $url -match '^https://' -and (Test-CommandAvailable "curl.exe")) {
            return (Invoke-CurlApiRequest -Method $Method -Url $url)
        }
        $innerMsg = if ($ex.InnerException) { $ex.InnerException.Message } else { "" }
        if ($innerMsg) { throw "API $Method $Endpoint failed - $innerMsg" }
        else { throw "API $Method $Endpoint failed - $($ex.Message)" }
    }
}

function Save-OpnsenseFileDownload {
    param([string]$Endpoint, [string]$OutputPath)
    $url = "$script:OpnsenseUrl/api$Endpoint"

    $headers = @{ Authorization = New-BasicAuthHeader; Accept = "*/*" }
    $params = @{ Uri = $url; Method = "GET"; Headers = $headers; OutFile = $OutputPath }

    if ($Insecure -and $url -match '^https://' -and $psMajor -ge 6) {
        $params.SkipCertificateCheck = $true
    }

    try {
        Invoke-RestMethod @params
        if ((Get-Item $OutputPath).Length -gt 0) { return }
        throw "downloaded file is empty"
    }
    catch {
        $ex = $_.Exception
        if ($ex.Response) { throw "API $Endpoint returned HTTP error" }
        if ($Insecure -and $url -match '^https://' -and (Test-CommandAvailable "curl.exe")) {
            Invoke-CurlFileDownload -Url $url -OutputPath $OutputPath
            return
        }
        throw "Download failed: $_"
    }
}

# ──────────────────────────────────────
# STEP 1: Test API connectivity
# ──────────────────────────────────────
Write-Host "=== Get-OpnSenseCert-API ===" -ForegroundColor Cyan
Write-Host "URL: $script:OpnsenseUrl" -ForegroundColor DarkGray

Write-Host "`nTest: Connecting to OPNsense API ..." -ForegroundColor Yellow
try {
    $result = New-OpnsenseApiRequest -Endpoint "/core/firmware/status"
    Write-Host "[OK] Connected to OPNsense" -ForegroundColor Green
}
catch {
    Write-Error "Cannot reach OPNsense API: $_"
    Write-Host "Troubleshooting:" -ForegroundColor Yellow
    Write-Host "  1. Verify the URL is correct"
    Write-Host "  2. Check API credentials (System → Access → Users → Edit user → API keys)"
    Write-Host "  3. Use -Insecure if OPNsense has a self-signed certificate"
    exit 1
}

# ──────────────────────────────────────
# STEP 2: List certificates from trust store
# ──────────────────────────────────────
Write-Host "`nFetch: Certificate list ..." -ForegroundColor Yellow
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
    Write-Host "`n=== Available Certificates (Total: $($certs.total)) ===" -ForegroundColor Cyan
    Write-Host "  {0,-38} {1,-30} {2,-20}" -f "UUID", "Common Name", "Description" -ForegroundColor White
    Write-Host "  " + ("-" * 90) -ForegroundColor DarkGray
    foreach ($row in $certs.rows) {
        $cn = if ($row.commonname) { $row.commonname } else { "(no CN)" }
        $desc = if ($row.descr) { $row.descr } else { "" }
        Write-Host "  {0,-38} {1,-30} {2,-20}" -f $row.uuid, $cn, $desc
    }
    Write-Host "`nRe-run with -CertName '<commonname>' to download" -ForegroundColor Yellow
    Write-Host "  or set OPNSENSE_CERT_NAME in .env" -ForegroundColor Yellow
    exit 0
}
else {
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
        exit 1
    }
    if ($matchingCerts.Count -gt 1) {
        Write-Host "[WARN] Multiple matches:" -ForegroundColor Yellow
        $i = 0
        foreach ($match in $matchingCerts) {
            Write-Host "  [$i] UUID: $($match.uuid)  CN: $($match.commonname)  Desc: $($match.descr)"
            $i++
        }
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
    else { $target = $matchingCerts[0] }
}

$certUuid = $target.uuid
$certCn   = $target.commonname
$safeName = $certCn -replace '[\*:]', '_'
Write-Host "[OK] Selected: $certCn (UUID: $certUuid)" -ForegroundColor Green

# ──────────────────────────────────────
# STEP 4: Download .crt and .key files
# ──────────────────────────────────────
$outDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($script:OutputDir)
if (-not (Test-Path $outDir)) { New-Item -ItemType Directory -Path $outDir -Force | Out-Null }

$crtPath = Join-Path $outDir "$safeName.crt"
$keyPath = Join-Path $outDir "$safeName.key"

Write-Host "`nDownload: Certificate ..." -ForegroundColor Yellow
try {
    Save-OpnsenseFileDownload -Endpoint "/trust/cert/generate_file/$certUuid/crt" -OutputPath $crtPath
    Write-Host "[OK] Saved: $crtPath" -ForegroundColor Green
}
catch {
    Write-Error "Failed to download certificate: $_"
    exit 1
}

Write-Host "`nDownload: Private key ..." -ForegroundColor Yellow
try {
    Save-OpnsenseFileDownload -Endpoint "/trust/cert/generate_file/$certUuid/key" -OutputPath $keyPath
    Write-Host "[OK] Saved: $keyPath" -ForegroundColor Green
}
catch {
    Write-Warning "Failed to download private key: $_"
    Write-Host "  The certificate was saved, but the private key could not be downloaded." -ForegroundColor Yellow
}

Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan
