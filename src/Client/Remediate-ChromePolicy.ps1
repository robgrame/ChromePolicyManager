<#
.SYNOPSIS
    Chrome Policy Manager - Remediation Script
    Applies Chrome policies from the central API to the local registry.

.DESCRIPTION
    This script is deployed via Intune Proactive Remediation (Remediation).
    It contacts the Chrome Policy Manager API, retrieves the effective policy for this device,
    writes the policies to the Chrome policy registry path, manages stale policy removal,
    and reports compliance status back to the API.

    Registry paths managed:
    - HKLM:\SOFTWARE\Policies\Google\Chrome (mandatory)
    - HKLM:\SOFTWARE\Policies\Google\Chrome\Recommended (recommended)
    
    Local manifest stored at:
    - HKLM:\SOFTWARE\ChromePolicyManager

.NOTES
    Requires: 64-bit PowerShell, Administrator privileges
    Chrome will pick up changes within 15 minutes (periodic refresh) or immediately via chrome://policy reload
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
$ClientId = "91c07a6b-d678-48d0-b3fa-f0828aca761b"
$Scope = "api://633d147e-7e43-42b1-abd7-15853f4a8b4b/.default"

# Retry/jitter settings
$MaxRetries = 3
$BaseJitterSeconds = 5

# Registry paths
$ChromePolicyPath = "HKLM:\SOFTWARE\Policies\Google\Chrome"
$ChromeRecommendedPath = "HKLM:\SOFTWARE\Policies\Google\Chrome\Recommended"
$ManifestPath = "HKLM:\SOFTWARE\ChromePolicyManager"
$ManifestKeysValue = "ManagedKeys"       # JSON list of keys we own
$ManifestHashValue = "PolicyHash"        # Hash of applied policy
$ManifestVersionValue = "PolicyVersion"  # Version string
$ManifestTimestamp = "LastApplied"       # Last application timestamp
$LogPath = "$env:ProgramData\ChromePolicyManager\remediation.log"

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    $logDir = Split-Path $LogPath -Parent
    if (-not (Test-Path $logDir)) { New-Item -ItemType Directory -Path $logDir -Force | Out-Null }
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
}

function Get-DeviceId {
    try {
        $dsregOutput = dsregcmd /status 2>&1
        $deviceIdLine = $dsregOutput | Select-String "DeviceId\s*:\s*(.+)"
        if ($deviceIdLine) {
            return $deviceIdLine.Matches[0].Groups[1].Value.Trim()
        }
    }
    catch {
        Write-Log "Failed to get device ID: $_" "ERROR"
    }
    return $null
}

function Get-DeviceName {
    return $env:COMPUTERNAME
}

function Get-ChromeVersion {
    try {
        $chromePath = "HKLM:\SOFTWARE\Microsoft\Windows\CurrentVersion\App Paths\chrome.exe"
        if (Test-Path $chromePath) {
            $exePath = (Get-ItemProperty $chromePath).'(default)'
            if ($exePath -and (Test-Path $exePath)) {
                return (Get-Item $exePath).VersionInfo.ProductVersion
            }
        }
    }
    catch { }
    return "Unknown"
}

function Get-AccessToken {
    # Same auth logic as detection script
    try {
        $certThumbprint = (Get-ChildItem Cert:\LocalMachine\My | 
            Where-Object { $_.Subject -match "CN=.*" -and $_.Issuer -match "MS-Organization-Access" } |
            Select-Object -First 1).Thumbprint

        if ($certThumbprint) {
            $tokenEndpoint = "https://login.microsoftonline.com/$TenantId/oauth2/v2.0/token"
            $cert = Get-ChildItem "Cert:\LocalMachine\My\$certThumbprint"
            $base64Thumbprint = [Convert]::ToBase64String($cert.GetCertHash())
            
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
    return $null
}

function Get-ManagedKeys {
    # Read the list of registry keys we previously wrote
    try {
        if (Test-Path $ManifestPath) {
            $json = (Get-ItemProperty -Path $ManifestPath -Name $ManifestKeysValue -ErrorAction SilentlyContinue).$ManifestKeysValue
            if ($json) {
                return ($json | ConvertFrom-Json)
            }
        }
    }
    catch { }
    return @{ mandatory = @(); recommended = @() }
}

function Set-ManagedKeys {
    param([hashtable]$Keys)
    if (-not (Test-Path $ManifestPath)) {
        New-Item -Path $ManifestPath -Force | Out-Null
    }
    $json = $Keys | ConvertTo-Json -Compress
    Set-ItemProperty -Path $ManifestPath -Name $ManifestKeysValue -Value $json
}

function Write-RegistryPolicy {
    param(
        [string]$BasePath,
        [string]$PolicyName,
        [object]$Value
    )
    
    # Ensure the base path exists
    if (-not (Test-Path $BasePath)) {
        New-Item -Path $BasePath -Force | Out-Null
    }
    
    # Determine registry value type and write accordingly
    if ($Value -is [bool]) {
        Set-ItemProperty -Path $BasePath -Name $PolicyName -Value ([int]$Value) -Type DWord
    }
    elseif ($Value -is [int] -or $Value -is [long]) {
        Set-ItemProperty -Path $BasePath -Name $PolicyName -Value ([int]$Value) -Type DWord
    }
    elseif ($Value -is [string]) {
        Set-ItemProperty -Path $BasePath -Name $PolicyName -Value $Value -Type String
    }
    elseif ($Value -is [array]) {
        # Chrome list policies use numbered subkeys: Chrome\PolicyName\1, Chrome\PolicyName\2, ...
        $listPath = Join-Path $BasePath $PolicyName
        if (Test-Path $listPath) {
            Remove-Item -Path $listPath -Recurse -Force
        }
        New-Item -Path $listPath -Force | Out-Null
        for ($i = 0; $i -lt $Value.Count; $i++) {
            Set-ItemProperty -Path $listPath -Name ($i + 1).ToString() -Value $Value[$i] -Type String
        }
    }
    elseif ($Value -is [hashtable] -or $Value -is [PSCustomObject]) {
        # Dictionary/complex policies stored as JSON string
        $jsonValue = $Value | ConvertTo-Json -Compress -Depth 10
        Set-ItemProperty -Path $BasePath -Name $PolicyName -Value $jsonValue -Type String
    }
    else {
        # Fallback: store as string
        Set-ItemProperty -Path $BasePath -Name $PolicyName -Value $Value.ToString() -Type String
    }
}

function Remove-StaleKeys {
    param(
        [string]$BasePath,
        [string[]]$PreviousKeys,
        [string[]]$CurrentKeys
    )
    
    $removed = 0
    $staleKeys = $PreviousKeys | Where-Object { $_ -notin $CurrentKeys }
    
    foreach ($key in $staleKeys) {
        try {
            $itemPath = Join-Path $BasePath $key
            # Check if it's a subkey (list policy) or a value
            if (Test-Path $itemPath) {
                Remove-Item -Path $itemPath -Recurse -Force
                $removed++
            }
            elseif (Test-Path $BasePath) {
                $existing = Get-ItemProperty -Path $BasePath -Name $key -ErrorAction SilentlyContinue
                if ($null -ne $existing.$key) {
                    Remove-ItemProperty -Path $BasePath -Name $key -Force
                    $removed++
                }
            }
            Write-Log "Removed stale policy: $key"
        }
        catch {
            Write-Log "Failed to remove stale key '$key': $_" "WARN"
        }
    }
    
    return $removed
}

function Send-ComplianceReport {
    param(
        [string]$Token,
        [string]$DeviceId,
        [string]$DeviceName,
        [string]$PolicyHash,
        [string]$Status,
        [string]$Errors,
        [int]$KeysWritten,
        [int]$KeysRemoved
    )
    
    try {
        $headers = @{
            Authorization = "Bearer $Token"
            "Content-Type" = "application/json"
        }
        
        $report = @{
            deviceId = $DeviceId
            deviceName = $DeviceName
            userPrincipalName = $null
            appliedPolicyHash = $PolicyHash
            status = $Status
            errors = $Errors
            chromeVersion = (Get-ChromeVersion)
            osVersion = [Environment]::OSVersion.Version.ToString()
            policyKeysWritten = $KeysWritten
            policyKeysRemoved = $KeysRemoved
        } | ConvertTo-Json
        
        Invoke-RestMethod -Uri "$ApiBaseUrl/api/devices/$DeviceId/report" -Headers $headers -Method POST -Body $report | Out-Null
        Write-Log "Compliance report sent successfully"
    }
    catch {
        Write-Log "Failed to send compliance report: $_" "WARN"
    }
}

# ============ Main Remediation Logic ============
try {
    Write-Log "=== Remediation script started ==="
    
    $deviceId = Get-DeviceId
    if (-not $deviceId) {
        Write-Log "Cannot determine device ID" "ERROR"
        Write-Output "FAILED: Cannot determine device ID"
        exit 1
    }
    $deviceName = Get-DeviceName
    Write-Log "Device: $deviceName ($deviceId)"
    
    # Authenticate
    $token = Get-AccessToken
    if (-not $token) {
        Write-Log "Cannot acquire access token" "ERROR"
        Write-Output "FAILED: Cannot acquire access token"
        exit 1
    }
    Write-Log "Authentication successful"
    
    # Get effective policy from API
    $headers = @{
        Authorization = "Bearer $token"
        "Content-Type" = "application/json"
    }
    
    $effectivePolicy = Invoke-RestMethod -Uri "$ApiBaseUrl/api/devices/$deviceId/effective-policy" -Headers $headers -Method GET
    
    if (-not $effectivePolicy) {
        Write-Log "No effective policy returned from API" "WARN"
        Write-Output "No policies assigned"
        exit 0
    }
    
    $serverHash = $effectivePolicy.hash
    Write-Log "Effective policy hash: $serverHash"
    
    # Get previously managed keys (for stale removal)
    $previousManaged = Get-ManagedKeys
    $previousMandatoryKeys = @($previousManaged.mandatory)
    $previousRecommendedKeys = @($previousManaged.recommended)
    
    $keysWritten = 0
    $keysRemoved = 0
    $errors = @()
    $currentMandatoryKeys = @()
    $currentRecommendedKeys = @()
    
    # Apply mandatory policies
    if ($effectivePolicy.mandatoryPolicies) {
        Write-Log "Applying mandatory policies..."
        $mandatoryPolicies = $effectivePolicy.mandatoryPolicies
        
        # Handle PSCustomObject from JSON
        if ($mandatoryPolicies -is [PSCustomObject]) {
            $mandatoryPolicies.PSObject.Properties | ForEach-Object {
                $policyName = $_.Name
                $policyValue = $_.Value
                try {
                    Write-RegistryPolicy -BasePath $ChromePolicyPath -PolicyName $policyName -Value $policyValue
                    $currentMandatoryKeys += $policyName
                    $keysWritten++
                    Write-Log "  Applied: $policyName"
                }
                catch {
                    $errors += "Failed to write mandatory policy '$policyName': $_"
                    Write-Log "  FAILED: $policyName - $_" "ERROR"
                }
            }
        }
    }
    
    # Apply recommended policies
    if ($effectivePolicy.recommendedPolicies) {
        Write-Log "Applying recommended policies..."
        $recommendedPolicies = $effectivePolicy.recommendedPolicies
        
        if ($recommendedPolicies -is [PSCustomObject]) {
            $recommendedPolicies.PSObject.Properties | ForEach-Object {
                $policyName = $_.Name
                $policyValue = $_.Value
                try {
                    Write-RegistryPolicy -BasePath $ChromeRecommendedPath -PolicyName $policyName -Value $policyValue
                    $currentRecommendedKeys += $policyName
                    $keysWritten++
                    Write-Log "  Applied: $policyName (Recommended)"
                }
                catch {
                    $errors += "Failed to write recommended policy '$policyName': $_"
                    Write-Log "  FAILED: $policyName - $_" "ERROR"
                }
            }
        }
    }
    
    # Remove stale policies (owned by us but no longer in effective policy)
    $keysRemoved += (Remove-StaleKeys -BasePath $ChromePolicyPath -PreviousKeys $previousMandatoryKeys -CurrentKeys $currentMandatoryKeys)
    $keysRemoved += (Remove-StaleKeys -BasePath $ChromeRecommendedPath -PreviousKeys $previousRecommendedKeys -CurrentKeys $currentRecommendedKeys)
    
    # Update local manifest
    Set-ManagedKeys -Keys @{
        mandatory = $currentMandatoryKeys
        recommended = $currentRecommendedKeys
    }
    
    # Update manifest metadata
    if (-not (Test-Path $ManifestPath)) { New-Item -Path $ManifestPath -Force | Out-Null }
    Set-ItemProperty -Path $ManifestPath -Name $ManifestHashValue -Value $serverHash
    Set-ItemProperty -Path $ManifestPath -Name $ManifestTimestamp -Value (Get-Date -Format "o")
    
    # Determine compliance status
    $status = if ($errors.Count -eq 0) { "Compliant" } 
              elseif ($keysWritten -gt 0) { "PartiallyApplied" }
              else { "Error" }
    
    # Report back to API
    $errorsJson = if ($errors.Count -gt 0) { $errors | ConvertTo-Json -Compress } else { $null }
    Send-ComplianceReport -Token $token -DeviceId $deviceId -DeviceName $deviceName `
        -PolicyHash $serverHash -Status $status -Errors $errorsJson `
        -KeysWritten $keysWritten -KeysRemoved $keysRemoved
    
    Write-Log "Remediation complete: $keysWritten written, $keysRemoved removed, Status: $status"
    Write-Output "SUCCESS: $keysWritten policies applied, $keysRemoved stale removed. Hash: $serverHash"
    exit 0
}
catch {
    Write-Log "Remediation script error: $_" "ERROR"
    Write-Output "FAILED: $_"
    exit 1
}
