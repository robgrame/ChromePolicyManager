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
# API Gateway (APIM) — device traffic goes through the gateway for auth/rate-limiting
$ApiGatewayUrl = "https://cpm-dev-apim.azure-api.net"
# Direct backend (fallback if APIM not yet deployed)
$ApiDirectUrl = "https://cpm-dev-api.azurewebsites.net"
# Use APIM gateway when available
$ApiBaseUrl = if ($env:CPM_USE_DIRECT_API -eq "true") { $ApiDirectUrl } else { $ApiGatewayUrl }
$TenantId = "46b06a5e-8f7a-467b-bc9a-e776011fbb57"
$ClientId = "91c07a6b-d678-48d0-b3fa-f0828aca761b"  # App registration for device auth
$Scope = "api://633d147e-7e43-42b1-abd7-15853f4a8b4b/.default"

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

function Get-AccessToken {
    # Acquire token using device identity (MSAL.PS or certificate-based)
    try {
        # Method 1: Try using the device certificate from Entra join
        $certThumbprint = (Get-ChildItem Cert:\LocalMachine\My | 
            Where-Object { $_.Subject -match "CN=.*" -and $_.Issuer -match "MS-Organization-Access" } |
            Select-Object -First 1).Thumbprint

        if ($certThumbprint) {
            # Use MSAL with certificate
            $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            
            $cert = Get-ChildItem "Cert:\LocalMachine\My\$certThumbprint"
            $base64Thumbprint = [Convert]::ToBase64String($cert.GetCertHash())
            
            # Create JWT assertion for client credentials with cert
            $now = [DateTimeOffset]::UtcNow
            $header = @{ alg = "RS256"; typ = "JWT"; x5t = $base64Thumbprint } | ConvertTo-Json -Compress
            $payload = @{
                aud = $tokenEndpoint
                iss = $ClientId
                sub = $ClientId
                jti = [Guid]::NewGuid().ToString()
                nbf = $now.ToUnixTimeSeconds()
                exp = $now.AddMinutes(10).ToUnixTimeSeconds()
            } | ConvertTo-Json -Compress
            
            $headerB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($header)).TrimEnd('=').Replace('+','-').Replace('/','_')
            $payloadB64 = [Convert]::ToBase64String([Text.Encoding]::UTF8.GetBytes($payload)).TrimEnd('=').Replace('+','-').Replace('/','_')
            $dataToSign = "$headerB64.$payloadB64"
            
            $rsaProvider = $cert.PrivateKey
            $signedBytes = $rsaProvider.SignData([Text.Encoding]::UTF8.GetBytes($dataToSign), [Security.Cryptography.HashAlgorithmName]::SHA256, [Security.Cryptography.RSASignaturePadding]::Pkcs1)
            $signatureB64 = [Convert]::ToBase64String($signedBytes).TrimEnd('=').Replace('+','-').Replace('/','_')
            
            $clientAssertion = "$dataToSign.$signatureB64"
            
            $body = @{
                client_id = $ClientId
                scope = $Scope
                client_assertion_type = "urn:ietf:params:oauth:client-assertion-type:jwt-bearer"
                client_assertion = $clientAssertion
                grant_type = "client_credentials"
            }
            
            $response = Invoke-RestMethod -Uri $tokenEndpoint -Method POST -Body $body -ContentType "application/x-www-form-urlencoded"
            return $response.access_token
        }
    }
    catch {
        Write-Log "Certificate-based auth failed: $_" "WARN"
    }
    
    # Method 2: Fallback to managed identity if running in Azure/hybrid
    try {
        $imdsUrl = "http://169.254.169.254/metadata/identity/oauth2/token?api-version=2018-02-01&resource=api://chrome-policy-manager"
        $response = Invoke-RestMethod -Uri $imdsUrl -Headers @{Metadata="true"} -ErrorAction Stop
        return $response.access_token
    }
    catch {
        Write-Log "Managed identity auth not available: $_" "WARN"
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
    
    # Get access token
    $token = Get-AccessToken
    if (-not $token) {
        Write-Log "Cannot acquire access token - skipping API check, using local manifest" "WARN"
        # If we can't reach the API, check if we have any policy applied
        $localHash = Get-CurrentPolicyHash
        if ($localHash) {
            Write-Log "Local policy hash exists: $localHash - assuming compliant"
            Write-Output "Compliant (offline - using cached state)"
            exit 0
        }
        else {
            Write-Log "No local policy hash - non-compliant"
            Write-Output "Non-compliant (no policies applied and cannot reach API)"
            exit 1
        }
    }
    
    # Call API to get effective policy (with ETag for bandwidth optimization)
    $headers = @{
        Authorization = "Bearer $token"
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
            $response = Invoke-WebRequest -Uri "$ApiBaseUrl/api/devices/$deviceId/effective-policy" -Headers $headers -Method GET -UseBasicParsing
            
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
