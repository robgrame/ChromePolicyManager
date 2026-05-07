<#
.SYNOPSIS
    Chrome Policy Manager - Detection Script
    Checks whether Chrome policies on this device match the expected state from the central API.

.DESCRIPTION
    This script is deployed via Intune Proactive Remediation (Detection).
    It contacts the Chrome Policy Manager API to get the effective policy for this device,
    then compares it against the currently applied registry state.
    
    Exit 0 = Compliant (no remediation needed)
    Exit 1 = Non-compliant (remediation needed)

.NOTES
    Requires: 64-bit PowerShell execution
    Registry: HKLM\SOFTWARE\Policies\Google\Chrome
    Manifest: HKLM\SOFTWARE\ChromePolicyManager\Manifest
#>

#Requires -RunAsAdministrator

$ErrorActionPreference = "Stop"

# Configuration
# API Gateway (APIM) — device traffic goes through the gateway with mTLS client certificate auth
$ApiGatewayUrl = "https://cpm-dev-apim.azure-api.net"
# Direct backend (fallback if APIM not yet deployed)
$ApiDirectUrl = "https://cpm-dev-api.azurewebsites.net"
# Use APIM gateway when available
$ApiBaseUrl = if ($env:CPM_USE_DIRECT_API -eq "true") { $ApiDirectUrl } else { $ApiGatewayUrl }

# Client certificate configuration (issued by Intune PKCS/SCEP profile)
$CertIssuerMatch = "CN=CPM-Device-CA"  # Issuer CN of the Root CA that signs device certs
$CertSubjectPrefix = "CN="             # Device certs have CN=<deviceId>

# Retry/jitter settings for rate limiting (429) responses
$MaxRetries = 3
$BaseJitterSeconds = 5

# Paths
$ChromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$ChromeRecommendedPath = "HKLM:\SOFTWARE\Policies\Google\Chrome\Recommended"
$ManifestPath = "HKLM:\SOFTWARE\ChromePolicyManager"
$ManifestValueName = "PolicyHash"
$LogPath = "$env:ProgramData\ChromePolicyManager\detection.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $logDir = Split-Path $LogPath -Parent
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
}

function Get-DeviceId {
    # Get Entra device ID from dsregcmd
    try {
        $dsregOutput = dsregcmd /status 2>&1
        $deviceIdLine = $dsregOutput | Select-String "DeviceId\s*:\s*(.+)"
        if ($deviceIdLine) {
            return $deviceIdLine.Matches[0].Groups[1].Value.Trim()
        }
    }
    catch {
        Write-Log "Failed to get device ID from dsregcmd: $_" "ERROR"
    }
    return $null
}

function Get-ClientCertificate {
    # Find the client certificate issued by the CPM Root CA (deployed via Intune PKCS/SCEP)
    try {
        $cert = Get-ChildItem Cert:\LocalMachine\My |
            Where-Object { $_.Issuer -match $CertIssuerMatch -and $_.NotAfter -gt (Get-Date) } |
            Sort-Object NotAfter -Descending |
            Select-Object -First 1

        if ($cert) {
            Write-Log "Found client certificate: Subject=$($cert.Subject), Thumbprint=$($cert.Thumbprint), Expires=$($cert.NotAfter)"
            return $cert
        }
        Write-Log "No valid client certificate found (issuer: $CertIssuerMatch)" "WARN"
    }
    catch {
        Write-Log "Error searching for client certificate: $_" "ERROR"
    }
    return $null
}

function Get-CurrentPolicyHash {
    # Read the stored hash of last applied policy
    try {
        if (Test-Path $ManifestPath) {
            return (Get-ItemProperty -Path $ManifestPath -Name $ManifestValueName -ErrorAction SilentlyContinue).$ManifestValueName
        }
    }
    catch { }
    return $null
}

# Main detection logic
try {
    Write-Log "Detection script started"
    
    $deviceId = Get-DeviceId
    if (-not $deviceId) {
        Write-Log "Cannot determine device ID - device may not be Entra joined" "ERROR"
        Write-Output "Cannot determine device ID"
        exit 1
    }
    Write-Log "Device ID: $deviceId"
    
    # Get client certificate for mTLS authentication
    $clientCert = Get-ClientCertificate
    if (-not $clientCert) {
        Write-Log "Cannot find client certificate - device may not have the CPM cert profile applied" "WARN"
        # If we can't authenticate, check if we have any policy applied locally
        $localHash = Get-CurrentPolicyHash
        if ($localHash) {
            Write-Log "Local policy hash exists: $localHash - assuming compliant"
            Write-Output "Compliant (offline - using cached state)"
            exit 0
        }
        else {
            Write-Log "No local policy hash - non-compliant"
            Write-Output "Non-compliant (no policies applied and cannot authenticate)"
            exit 1
        }
    }
    
    # Call API to get effective policy (with ETag for bandwidth optimization)
    $headers = @{
        "Content-Type" = "application/json"
    }
    
    # If we have a local hash, send it as ETag — API returns 304 if nothing changed
    $localHash = Get-CurrentPolicyHash
    if ($localHash) {
        $headers["If-None-Match"] = "`"$localHash`""
    }
    
    # Add initial jitter to avoid thundering herd (randomize check-in window)
    $jitter = Get-Random -Minimum 0 -Maximum $BaseJitterSeconds
    Start-Sleep -Seconds $jitter
    
    $retryCount = 0
    $response = $null
    $effectivePolicy = $null
    
    while ($retryCount -le $MaxRetries) {
        try {
            $response = Invoke-WebRequest -Uri "$ApiBaseUrl/api/devices/$deviceId/effective-policy" -Headers $headers -Method GET -UseBasicParsing -Certificate $clientCert
            
            if ($response.StatusCode -eq 304) {
                # Policy hasn't changed — device is compliant
                Write-Log "304 Not Modified - device is compliant (Hash: $localHash)"
                Write-Output "Compliant (Hash: $localHash, cached)"
                exit 0
            }
            
            $effectivePolicy = $response.Content | ConvertFrom-Json
            break  # Success — exit retry loop
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            
            if ($statusCode -eq 304) {
                Write-Log "304 Not Modified - device is compliant (Hash: $localHash)"
                Write-Output "Compliant (Hash: $localHash, cached)"
                exit 0
            }
            elseif ($statusCode -eq 429) {
                # Rate limited by APIM gateway — respect Retry-After header
                $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                if (-not $retryAfter) { $retryAfter = 60 }
                $backoff = [int]$retryAfter + (Get-Random -Minimum 1 -Maximum 10)
                Write-Log "Rate limited (429). Retry $($retryCount + 1)/$MaxRetries after ${backoff}s" "WARN"
                $retryCount++
                if ($retryCount -gt $MaxRetries) {
                    Write-Log "Max retries exceeded after 429 responses" "ERROR"
                    # Fall back to cached state
                    if ($localHash) {
                        Write-Output "Compliant (offline - rate limited, using cached state)"
                        exit 0
                    }
                    exit 1
                }
                Start-Sleep -Seconds $backoff
            }
            else {
                throw
            }
        }
    }
    
    if (-not $effectivePolicy -or (-not $effectivePolicy.mandatoryPolicies -and -not $effectivePolicy.recommendedPolicies)) {
        Write-Log "No policies assigned to this device"
        Write-Output "No policies assigned"
        exit 0
    }
    
    # Compare server hash with local hash
    $serverHash = $effectivePolicy.hash
    
    if ($serverHash -eq $localHash) {
        Write-Log "Policy hash matches - device is compliant (Hash: $serverHash)"
        Write-Output "Compliant (Hash: $serverHash)"
        exit 0
    }
    else {
        Write-Log "Policy hash mismatch - Server: $serverHash, Local: $localHash" "WARN"
        Write-Output "Non-compliant (Server: $serverHash, Local: $localHash)"
        exit 1
    }
}
catch {
    Write-Log "Detection script error: $_" "ERROR"
    Write-Output "Error during detection: $_"
    exit 1
}
