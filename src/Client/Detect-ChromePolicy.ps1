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
$ApiGatewayUrl = "https://cpm-dev-apim2.azure-api.net"
# Direct backend (fallback if APIM not yet deployed)
$ApiDirectUrl = "https://cpm-dev-api.azurewebsites.net"
# Use APIM gateway when available
$ApiBaseUrl = if ($env:CPM_USE_DIRECT_API -eq "true") { $ApiDirectUrl } else { $ApiGatewayUrl }

# Client certificate configuration (issued by Intune PKCS/SCEP profile)
$CertIssuerMatch = "CN=MSLABS-SUBCA01"  # Issuer CN of the Sub CA that signs device certs
$CertSubjectPrefix = "CN="              # Device certs have CN=<deviceId>

# Retry/jitter settings for rate limiting (429) responses
$MaxRetries = 3
$BaseJitterSeconds = 5

# Paths
$ChromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$ChromeRecommendedPath = "HKLM:\SOFTWARE\Policies\Google\Chrome\Recommended"
$ManifestPath = "HKLM:\SOFTWARE\ChromePolicyManager"
$ManifestValueName = "PolicyHash"
$LogPath = "$env:ProgramData\ChromePolicyManager\detection.log"
$MaxLogSizeMB = 5

# Log buffer for batch upload
$script:LogBuffer = [System.Collections.Generic.List[hashtable]]::new()

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    
    # Write to local file
    $logDir = Split-Path $LogPath -Parent
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    # Rotate if over max size
    if ((Test-Path $LogPath) -and ((Get-Item $LogPath).Length / 1MB) -gt $MaxLogSizeMB) {
        $archivePath = $LogPath -replace '\.log$', "-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
        Rename-Item $LogPath $archivePath -ErrorAction SilentlyContinue
    }
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
    
    # Buffer for batch upload
    $script:LogBuffer.Add(@{
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        level     = $Level
        message   = $Message
    })
}

function Send-LogBatch {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ClientCert,
        [string]$DeviceId
    )
    if ($script:LogBuffer.Count -eq 0) { return }
    try {
        $body = @{
            deviceName = $env:COMPUTERNAME
            scriptType = "Detection"
            entries    = @($script:LogBuffer)
        } | ConvertTo-Json -Depth 3 -Compress

        Invoke-RestMethod -Uri "$ApiBaseUrl/api/devices/$DeviceId/logs" `
            -Method POST -Body $body -ContentType "application/json" `
            -Certificate $ClientCert -TimeoutSec 10 -ErrorAction Stop | Out-Null
    }
    catch {
        # Log upload failure is non-fatal — already persisted locally
        Add-Content -Path $LogPath -Value "[$(Get-Date -Format 'yyyy-MM-dd HH:mm:ss')] [WARN] Log batch upload failed: $_" -ErrorAction SilentlyContinue
    }
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
$script:ExitCode = 1
$script:ClientCertForLog = $null
$script:DeviceIdForLog = $null

try {
    Write-Log "Detection script started"
    
    $deviceId = Get-DeviceId
    $script:DeviceIdForLog = $deviceId
    if (-not $deviceId) {
        Write-Log "Cannot determine device ID - device may not be Entra joined" "ERROR"
        Write-Output "Cannot determine device ID"
        $script:ExitCode = 1; return
    }
    Write-Log "Device ID: $deviceId"
    
    # Get client certificate for mTLS authentication
    $clientCert = Get-ClientCertificate
    $script:ClientCertForLog = $clientCert
    if (-not $clientCert) {
        Write-Log "Cannot find client certificate - device may not have the CPM cert profile applied" "WARN"
        # If we can't authenticate, check if we have any policy applied locally
        $localHash = Get-CurrentPolicyHash
        if ($localHash) {
            Write-Log "Local policy hash exists: $localHash - assuming compliant"
            Write-Output "Compliant (offline - using cached state)"
            $script:ExitCode = 0; return
        }
        else {
            Write-Log "No local policy hash - non-compliant"
            Write-Output "Non-compliant (no policies applied and cannot authenticate)"
            $script:ExitCode = 1; return
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
                Write-Log "304 Not Modified - device is compliant (Hash: $localHash)"
                Write-Output "Compliant (Hash: $localHash, cached)"
                $script:ExitCode = 0; return
            }
            
            $effectivePolicy = $response.Content | ConvertFrom-Json
            Write-Log "Effective policy received from API"
            break
        }
        catch {
            $statusCode = $_.Exception.Response.StatusCode.value__
            
            if ($statusCode -eq 304) {
                Write-Log "304 Not Modified - device is compliant (Hash: $localHash)"
                Write-Output "Compliant (Hash: $localHash, cached)"
                $script:ExitCode = 0; return
            }
            elseif ($statusCode -eq 429) {
                $retryAfter = $_.Exception.Response.Headers["Retry-After"]
                if (-not $retryAfter) { $retryAfter = 60 }
                $backoff = [int]$retryAfter + (Get-Random -Minimum 1 -Maximum 10)
                Write-Log "Rate limited (429). Retry $($retryCount + 1)/$MaxRetries after ${backoff}s" "WARN"
                $retryCount++
                if ($retryCount -gt $MaxRetries) {
                    Write-Log "Max retries exceeded after 429 responses" "ERROR"
                    if ($localHash) {
                        Write-Output "Compliant (offline - rate limited, using cached state)"
                        $script:ExitCode = 0; return
                    }
                    $script:ExitCode = 1; return
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
        $script:ExitCode = 0; return
    }
    
    # Compare server hash with local hash
    $serverHash = $effectivePolicy.hash
    
    if ($serverHash -eq $localHash) {
        Write-Log "Policy hash matches - device is compliant (Hash: $serverHash)"
        Write-Output "Compliant (Hash: $serverHash)"
        $script:ExitCode = 0; return
    }
    else {
        Write-Log "Policy hash mismatch - Server: $serverHash, Local: $localHash" "WARN"
        Write-Output "Non-compliant (Server: $serverHash, Local: $localHash)"
        $script:ExitCode = 1; return
    }
}
catch {
    Write-Log "Detection script error: $_" "ERROR"
    Write-Output "Error during detection: $_"
    $script:ExitCode = 1
}
finally {
    # Always send logs to server (best-effort)
    if ($script:ClientCertForLog -and $script:DeviceIdForLog) {
        Send-LogBatch -ClientCert $script:ClientCertForLog -DeviceId $script:DeviceIdForLog
    }
    Write-Log "Detection script finished (exit: $($script:ExitCode))"
}
exit $script:ExitCode
