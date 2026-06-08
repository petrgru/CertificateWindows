<#
.SYNOPSIS
    Downloads ACME/Let's Encrypt certificates from OPNsense via SCP/SSH and
    installs them into the Windows Local Machine certificate store.

.DESCRIPTION
    Connects to an OPNsense firewall via SSH (using key-based auth), discovers
    available ACME certificates, downloads the PEM files, and imports them
    into the Windows Local Machine certificate store.

    OPNsense stores ACME certificates at:
      /var/etc/acme-client/certs/<UUID>/fullchain.pem
      /var/etc/acme-client/certs/<UUID>/chain.pem
      /var/etc/acme-client/keys/<UUID>/private.key

.PARAMETER OpnsenseHost
    Hostname or IP address of the OPNsense firewall.

.PARAMETER OpnsenseUser
    SSH username for OPNsense (default: root).

.PARAMETER SshKeyPath
    Path to the SSH private key (id_rsa) for authentication.

.PARAMETER SshPort
    SSH port (default: 22).

.PARAMETER CertUUID
    The UUID of the ACME certificate on OPNsense (e.g. "0123456789abcd.12345678").
    If omitted, the script lists available certificates and exits.

.PARAMETER OutputDir
    Local directory to store downloaded certificate files (default: current directory).

.PARAMETER StoreLocation
    Windows certificate store location (default: LocalMachine).
    Options: LocalMachine, CurrentUser.

.PARAMETER StoreName
    Windows certificate store name (default: Root).
    Options: Root (Trusted Root), CA (Intermediate), My (Personal).

.PARAMETER IncludePrivateKey
    Switch to also download the private key and import it with the cert.
    When set, the cert+key are combined into a PFX and imported.

.PARAMETER PfxPassword
    Password for the generated PFX file (only used with -IncludePrivateKey).
    If not provided but -IncludePrivateKey is set, you will be prompted.

.PARAMETER Overwrite
    Switch to overwrite existing files in OutputDir without prompting.

.EXAMPLE
    # List available ACME certificates on OPNsense
    .\Get-OpnSenseCert.ps1 -OpnsenseHost 10.0.0.1 -OpnsenseUser root -SshKeyPath C:\.ssh\id_rsa

.EXAMPLE
    # Download fullchain to temp dir and install into LocalMachine\Trusted Root
    .\Get-OpnSenseCert.ps1 -OpnsenseHost opnsense.example.com -OpnsenseUser root `
        -SshKeyPath C:\.ssh\id_rsa -CertUUID "0123456789abcd.12345678"

.EXAMPLE
    # Download cert + private key, package as PFX, install into LocalMachine\My (Personal)
    .\Get-OpnSenseCert.ps1 -OpnsenseHost 10.0.0.1 -OpnsenseUser root `
        -SshKeyPath C:\.ssh\id_rsa -CertUUID "0123456789abcd.12345678" `
        -IncludePrivateKey -StoreName My -PfxPassword (ConvertTo-SecureString "s3cr3t" -AsPlainText -Force)

.NOTES
    Requires: Windows 10 1809+ / Windows Server 2019+ (for built-in OpenSSH).
    The script must be run as Administrator when using -StoreLocation LocalMachine.
#>

[CmdletBinding(DefaultParameterSetName = "Install")]
param(
    [Parameter(Mandatory = $true)]
    [string]$OpnsenseHost,

    [Parameter(Mandatory = $true)]
    [string]$OpnsenseUser,

    [Parameter(Mandatory = $false)]
    [string]$SshKeyPath = "$env:USERPROFILE\.ssh\id_rsa",

    [Parameter(Mandatory = $false)]
    [int]$SshPort = 22,

    [Parameter(Mandatory = $false)]
    [string]$CertUUID,

    [Parameter(Mandatory = $false)]
    [string]$OutputDir = ".",

    [Parameter(Mandatory = $false)]
    [ValidateSet("LocalMachine", "CurrentUser")]
    [string]$StoreLocation = "LocalMachine",

    [Parameter(Mandatory = $false)]
    [ValidateSet("Root", "CA", "My")]
    [string]$StoreName = "Root",

    [Parameter(Mandatory = $false)]
    [switch]$IncludePrivateKey,

    [Parameter(Mandatory = $false)]
    [SecureString]$PfxPassword,

    [Parameter(Mandatory = $false)]
    [switch]$Overwrite
)

# ──────────────────────────────────────
# Helper: check if a command is available
# ──────────────────────────────────────
function Test-CommandAvailable {
    param([string]$Command)
    $null -ne (Get-Command $Command -ErrorAction SilentlyContinue)
}

# ──────────────────────────────────────
# Helper: get a unique temp file path with cleanup
# ──────────────────────────────────────
$script:TempFiles = @()
function Get-TempFilePath {
    param([string]$Suffix = "tmp")
    $path = Join-Path $env:TEMP "opnsense_cert_$PID`_$([IO.Path]::GetRandomFileName()).$Suffix"
    $script:TempFiles += $path
    return $path
}
function Clear-TempFiles {
    foreach ($f in $script:TempFiles) {
        Remove-Item $f -ErrorAction SilentlyContinue
    }
}

# ──────────────────────────────────────
# Helper: run SSH command and return output
# ──────────────────────────────────────
function Invoke-OpnsenseSsh {
    param([string]$Command, [int]$TimeoutSeconds = 15)
    $sshArgs = @(
        "-o", "BatchMode=yes"
        "-o", "StrictHostKeyChecking=accept-new"
        "-o", "ConnectTimeout=$([Math]::Min($TimeoutSeconds, 10))"
        "-o", "ServerAliveInterval=5"
        "-i", "$SshKeyPath"
        "-p", "$SshPort"
        "$OpnsenseUser@$OpnsenseHost"
        $Command
    )
    $stdoutFile = Get-TempFilePath "stdout"
    $stderrFile = Get-TempFilePath "stderr"
    $proc = Start-Process -FilePath "ssh" -ArgumentList $sshArgs -NoNewWindow `
        -RedirectStandardOutput $stdoutFile -RedirectStandardError $stderrFile -Wait -PassThru
    $stdout = Get-Content $stdoutFile -Raw
    $stderr = Get-Content $stderrFile -Raw
    if ($proc.ExitCode -ne 0) {
        throw "SSH command failed (exit $($proc.ExitCode)): $stderr"
    }
    return ($stdout -replace "`r`n?", "`n").Trim()
}

# ──────────────────────────────────────
# Helper: SCP a file from OPNsense
# ──────────────────────────────────────
function Copy-OpnsenseFile {
    param([string]$RemotePath, [string]$LocalPath)
    $scpArgs = @(
        "-o", "BatchMode=yes"
        "-o", "StrictHostKeyChecking=accept-new"
        "-o", "ConnectTimeout=10"
        "-i", "$SshKeyPath"
        "-P", "$SshPort"
        "$OpnsenseUser@$OpnsenseHost`:$RemotePath"
        "$LocalPath"
    )
    Write-Verbose "SCP: $RemotePath -> $LocalPath"
    $errFile = Get-TempFilePath "scp_err"
    $proc = Start-Process -FilePath "scp" -ArgumentList $scpArgs -NoNewWindow `
        -RedirectStandardError $errFile -Wait -PassThru
    $err = Get-Content $errFile -Raw
    if ($proc.ExitCode -ne 0) {
        throw "SCP failed for $RemotePath (exit $($proc.ExitCode)): $err"
    }
}

# ──────────────────────────────────────
# STEP 0: Preflight checks
# ──────────────────────────────────────
Write-Host "=== Get-OpnSenseCert ===" -ForegroundColor Cyan
Write-Host ""

# Check for OpenSSH client
if (-not (Test-CommandAvailable "ssh")) {
    Write-Error "OpenSSH client not found. Install it from Windows Features or 'Add-WindowsCapability -Online -Name OpenSSH.Client*'"
    exit 1
}
if (-not (Test-CommandAvailable "scp")) {
    Write-Error "SCP not found. Install the OpenSSH client first."
    exit 1
}
Write-Host "[OK] OpenSSH client available" -ForegroundColor Green

# Check SSH key exists
if (-not (Test-Path $SshKeyPath)) {
    Write-Error "SSH key not found at: $SshKeyPath"
    exit 1
}
Write-Host "[OK] SSH key: $SshKeyPath" -ForegroundColor Green

# Check admin rights for LocalMachine store
if ($StoreLocation -eq "LocalMachine") {
    $identity = [Security.Principal.WindowsIdentity]::GetCurrent()
    $principal = New-Object Security.Principal.WindowsPrincipal($identity)
    if (-not $principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)) {
        Write-Error "LocalMachine certificate store requires Administrator privileges. Restart PowerShell as Admin."
        exit 1
    }
    Write-Host "[OK] Running as Administrator" -ForegroundColor Green
}

# ──────────────────────────────────────
# STEP 1: Connectivity test
# ──────────────────────────────────────
Write-Host "`nTest: Connecting to $OpnsenseUser@$OpnsenseHost ..." -ForegroundColor Yellow
try {
    $hostname = Invoke-OpnsenseSsh -Command "hostname" -TimeoutSeconds 10
    Write-Host "[OK] Connected to $hostname" -ForegroundColor Green
}
catch {
    Write-Error "Cannot connect to OPNsense: $_"
    Write-Host "Troubleshooting tips:" -ForegroundColor Yellow
    Write-Host "  1. Test manually: ssh -i `"$SshKeyPath`" $OpnsenseUser@$OpnsenseHost"
    Write-Host "  2. Ensure the key is in authorized_keys on OPNsense"
    Write-Host "  3. Check hostname resolution and firewall rules (port $SshPort)"
    exit 1
}

# ──────────────────────────────────────
# STEP 2: Discover or validate cert UUID
# ──────────────────────────────────────
$certsDir = "/var/etc/acme-client/certs"
$keysDir = "/var/etc/acme-client/keys"

if (-not $CertUUID) {
    # Discovery mode: list available certs
    Write-Host "`n--- Available ACME Certificates on $OpnsenseHost ---" -ForegroundColor Cyan
    try {
        $certs = Invoke-OpnsenseSsh -Command "ls -1 $certsDir 2>/dev/null"
        if ([string]::IsNullOrWhiteSpace($certs)) {
            Write-Host "No ACME certificates found in $certsDir" -ForegroundColor Red
            Write-Host "Check that os-acme-client is installed and certificates have been issued." -ForegroundColor Yellow
            exit 1
        }
        $certList = $certs -split "`n" | Where-Object { $_ -ne "" }
        foreach ($uuid in $certList) {
            Write-Host "`nUUID: $uuid" -ForegroundColor White
            # Get cert details (issuer/subject from the cert itself)
            try {
                $subject = Invoke-OpnsenseSsh -Command "openssl x509 -in $certsDir/$uuid/fullchain.pem -noout -subject -issuer -dates 2>/dev/null || openssl x509 -in $certsDir/$uuid/cert.pem -noout -subject -issuer -dates 2>/dev/null || echo '(cannot parse)'"
                Write-Host "  $subject" -ForegroundColor Gray
            }
            catch {
                Write-Host "  (cert files not readable)" -ForegroundColor Gray
            }
            # List files
            try {
                $files = Invoke-OpnsenseSsh -Command "ls -la $certsDir/$uuid/"
                $files -split "`n" | ForEach-Object { Write-Host "  $_" -ForegroundColor DarkGray }
            }
            catch { }
        }
    }
    catch {
        Write-Error "Could not list certificates: $_"
        exit 1
    }
    Write-Host "`nTo install a certificate, re-run with -CertUUID '<uuid>'" -ForegroundColor Yellow
    exit 0
}

# ──────────────────────────────────────
# STEP 3: Verify cert UUID exists
# ──────────────────────────────────────
Write-Host "`nCheck: Certificate UUID '$CertUUID' ..." -ForegroundColor Yellow
try {
    $check = Invoke-OpnsenseSsh -Command "test -d $certsDir/$CertUUID && echo OK || echo NOT_FOUND"
    if ($check -ne "OK") {
        Write-Error "Certificate directory '$certsDir/$CertUUID' not found on OPNsense."
        exit 1
    }
    Write-Host "[OK] Certificate exists" -ForegroundColor Green
}
catch {
    Write-Error "Could not verify cert path: $_"
    exit 1
}

# ──────────────────────────────────────
# STEP 4: Download certificate files
# ──────────────────────────────────────
# Resolve output directory
$outDir = $ExecutionContext.SessionState.Path.GetUnresolvedProviderPathFromPSPath($OutputDir)
if (-not (Test-Path $outDir)) {
    New-Item -ItemType Directory -Path $outDir -Force | Out-Null
    Write-Host "[OK] Created output directory: $outDir" -ForegroundColor Green
}

Write-Host "`nDownload: Certificate files ..." -ForegroundColor Yellow

$localCert = Join-Path $outDir "$CertUUID-fullchain.pem"
$localChain = Join-Path $outDir "$CertUUID-chain.pem"
$localKey = Join-Path $outDir "$CertUUID-private.key"

$remoteFullchain = "$certsDir/$CertUUID/fullchain.pem"
$remoteChain = "$certsDir/$CertUUID/chain.pem"
$remoteKey = "$keysDir/$CertUUID/private.key"

# Try fullchain first, fall back to cert.pem
try {
    Copy-OpnsenseFile -RemotePath $remoteFullchain -LocalPath $localCert
    Write-Host "  + fullchain.pem -> $localCert" -ForegroundColor Green
}
catch {
    Write-Warning "fullchain.pem not found, trying cert.pem..."
    try {
        $remoteCert = "$certsDir/$CertUUID/cert.pem"
        Copy-OpnsenseFile -RemotePath $remoteCert -LocalPath $localCert
        Write-Host "  + cert.pem -> $localCert" -ForegroundColor Green
    }
    catch {
        Write-Error "Could not download certificate: $_"
        exit 1
    }
}

# Download chain.pem (not strictly required for import, but useful)
try {
    Copy-OpnsenseFile -RemotePath $remoteChain -LocalPath $localChain
    Write-Host "  + chain.pem -> $localChain" -ForegroundColor Green
}
catch {
    Write-Warning "chain.pem not available (intermediate CA chain not downloaded)"
}

# Download private key if requested
if ($IncludePrivateKey) {
    try {
        Copy-OpnsenseFile -RemotePath $remoteKey -LocalPath $localKey
        Write-Host "  + private.key -> $localKey" -ForegroundColor Green
    }
    catch {
        Write-Error "Private key download failed: $_"
        exit 1
    }

    # Get or prompt for PFX password
    if (-not $PfxPassword) {
        $PfxPassword = Read-Host "Enter password for PFX file" -AsSecureString
        $confirm = Read-Host "Confirm password" -AsSecureString
        $p1 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword))
        $p2 = [Runtime.InteropServices.Marshal]::PtrToStringAuto([Runtime.InteropServices.Marshal]::SecureStringToBSTR($confirm))
        if ($p1 -ne $p2) {
            Write-Error "Passwords do not match."
            exit 1
        }
    }

    # Convert PEM cert + key → PFX
    Write-Host "`nCreating: PFX bundle ..." -ForegroundColor Yellow
    $pfxPath = Join-Path $outDir "$CertUUID.pfx"

    # Resolve PFX password to plaintext for openssl
    $plainPass = [Runtime.InteropServices.Marshal]::PtrToStringAuto(
        [Runtime.InteropServices.Marshal]::SecureStringToBSTR($PfxPassword)
    )

    try {
        if (-not (Test-CommandAvailable "openssl")) {
            # If openssl isn't available, try using certutil to combine and export
            # certutil -mergepfx can merge a PEM cert with its key
            Write-Warning "openssl not found. Trying certutil -mergepfx ..."
            $certutilArgs = @(
                "-mergepfx", "$localCert,$localKey"
                "$pfxPath"
                $plainPass
            )
            $proc = Start-Process -FilePath "certutil" -ArgumentList $certutilArgs -NoNewWindow -Wait -PassThru
            if ($proc.ExitCode -ne 0) {
                throw "certutil -mergepfx failed (exit $($proc.ExitCode)). Install OpenSSL for reliable PFX creation."
            }
            Write-Host "[OK] PFX created via certutil: $pfxPath" -ForegroundColor Green
        }
        else {
            # Use openssl to combine PEM + key into PFX
            $opensslArgs = @(
                "pkcs12", "-export"
                "-out", $pfxPath
                "-in", $localCert
                "-inkey", $localKey
                "-passout", "pass:$plainPass"
            )
            $proc = Start-Process -FilePath "openssl" -ArgumentList $opensslArgs -NoNewWindow -Wait -PassThru
            if ($proc.ExitCode -ne 0) {
                throw "openssl exit code $($proc.ExitCode)"
            }
            Write-Host "[OK] PFX created via openssl: $pfxPath" -ForegroundColor Green
        }
    }
    catch {
        Write-Error "PFX creation failed: $_"
        exit 1
    }

    # Import PFX into certificate store
    Write-Host "`nImport: PFX -> $StoreLocation\$StoreName ..." -ForegroundColor Yellow
    try {
        Import-PfxCertificate -FilePath $pfxPath -CertStoreLocation "Cert:\$StoreLocation\$StoreName" -Password $PfxPassword -Exportable
        Write-Host "[OK] Certificate imported to $StoreLocation\$StoreName" -ForegroundColor Green
    }
    catch {
        Write-Error "PFX import failed: $_"
        exit 1
    }
}
else {
    # No private key — import PEM directly into store
    Write-Host "`nImport: Certificate -> $StoreLocation\$StoreName ..." -ForegroundColor Yellow
    try {
        Import-Certificate -FilePath $localCert -CertStoreLocation "Cert:\$StoreLocation\$StoreName" | Out-Null
        Write-Host "[OK] Certificate imported to $StoreLocation\$StoreName" -ForegroundColor Green
    }
    catch {
        Write-Error "Certificate import failed: $_"
        Write-Host "  Tip: For Trusted Root (-StoreName Root), this is normal for LE certs that are already trusted." -ForegroundColor Yellow
        Write-Host "  Try: -StoreName CA (Intermediate store) if you want the chain cert." -ForegroundColor Yellow
        exit 1
    }
}

# ──────────────────────────────────────
# STEP 5: Done — show result
# ──────────────────────────────────────
Write-Host ""
Write-Host "=== Done ===" -ForegroundColor Cyan
Write-Host "Certificate files in: $outDir" -ForegroundColor Green
Get-ChildItem $outDir -Filter "$CertUUID*" | ForEach-Object {
    Write-Host "  $($_.Name) ($('{0:N0}' -f $_.Length) bytes)" -ForegroundColor Gray
}

if ($IncludePrivateKey) {
    Write-Host "Certificate with private key installed in: $StoreLocation\$StoreName" -ForegroundColor Green
}
else {
    Write-Host "Certificate (public-only) installed in: $StoreLocation\$StoreName" -ForegroundColor Green
    Write-Host "Note: Private key was NOT included. Use -IncludePrivateKey if you need it." -ForegroundColor Yellow
}

# ──────────────────────────────────────
# Cleanup temp files
# ──────────────────────────────────────
Clear-TempFiles

# Verify in cert store
Write-Host "`nVerify: Installed certificates in $StoreLocation\$StoreName ..." -ForegroundColor Yellow
try {
    # Extract thumbprint from PEM — try multiple methods
    $thumbprint = $null

    # Method 1: PowerShell 7+ can load PEM natively
    try {
        $x509 = [System.Security.Cryptography.X509Certificates.X509Certificate2]::new($localCert)
        $thumbprint = $x509.Thumbprint
    }
    catch {
        # Method 2: certutil -dump on older Windows/PowerShell
        $dump = & certutil -dump "$localCert" 2>&1 | Out-String
        $match = [regex]::Match($dump, 'Cert Hash\(sha1\):\s+([\w\d]+)')
        if ($match.Success) {
            $thumbprint = $match.Groups[1].Value
        }
    }

    if (-not $thumbprint) {
        Write-Warning "Could not extract thumbprint from PEM file for verification."
    }
    else {
        $installed = Get-ChildItem "Cert:\$StoreLocation\$StoreName" | Where-Object { $_.Thumbprint -eq $thumbprint }
        if ($installed) {
            $installed | ForEach-Object {
                Write-Host "  Subject: $($_.Subject)" -ForegroundColor Green
                Write-Host "  Thumbprint: $($_.Thumbprint)" -ForegroundColor Green
                Write-Host "  Not After: $($_.NotAfter)" -ForegroundColor Green
                Write-Host "  Has Private Key: $($_.HasPrivateKey)" -ForegroundColor Green
            }
        }
        else {
            Write-Warning "Certificate with thumbprint $thumbprint not found in $StoreLocation\$StoreName"
        }
    }
}
catch {
    Write-Warning "Could not verify in cert store: $_"
}
