<#
.SYNOPSIS
    Chrome Policy Manager - User-context policy application (HKCU).

.DESCRIPTION
    Applies Chrome *user-level* policies for the currently logged-on user.
    This script is the child component of ADR-002: it is launched by the SYSTEM
    remediation (Detect/Remediate-ChromePolicy.ps1) through a transient scheduled
    task that runs as the interactive user, so writes land in the *user's* HKCU
    hive without requiring elevation.

    Flow (ADR-002 §5.2):
      a. Resolve the user identity natively (whoami /upn, WindowsIdentity).
      b. Run dsregcmd /status to corroborate the Entra device + PRT binding
         (anti-spoofing correlation, ADR-002 §8) and send it for server logging.
      c. GET /api/v2/users/{upn}/effective-policy?deviceId={deviceId} (mTLS).
      d. Write HKCU\SOFTWARE\Policies\Google\Chrome[\Recommended].
      e. Write per-user manifest in HKCU\SOFTWARE\ChromePolicyManager.
      f. Remove stale HKCU keys (Remove-StaleKeys per-user, ADR-002 §7).
      g. Drop a result JSON in %LOCALAPPDATA% so the SYSTEM orchestrator can
         read the outcome cross-context.

    Registry paths managed (per-user):
      - HKCU:\SOFTWARE\Policies\Google\Chrome              (mandatory)
      - HKCU:\SOFTWARE\Policies\Google\Chrome\Recommended  (recommended)
    Local manifest:
      - HKCU:\SOFTWARE\ChromePolicyManager
    Outcome file (read by SYSTEM):
      - %LOCALAPPDATA%\ChromePolicyManager\user-result.json

.NOTES
    Runs as the interactive USER (NOT SYSTEM, NOT elevated).
    Requires the device client certificate (LocalMachine\My) to be readable by
    the user for mTLS: the SYSTEM orchestrator (WS5) grants temporary private-key
    read access before launching this task.
    Chrome picks up changes within 15 minutes or immediately via chrome://policy reload.
#>

[CmdletBinding()]
param(
    # Optional: Entra deviceId passed by the SYSTEM orchestrator. If empty the
    # script resolves it itself via dsregcmd (works because the user task can run
    # dsregcmd for its own session).
    [string]$DeviceId
)

$ErrorActionPreference = "Stop"

# ---------------------------------------------------------------------------
# Configuration (mirrors Remediate-ChromePolicy.ps1)
# ---------------------------------------------------------------------------
$ApiUrlEnvVar = "CPM_API_URL"
$ApiBaseUrl = $null
foreach ($scope in @("Machine", "Process", "User")) {
    $candidate = [Environment]::GetEnvironmentVariable($ApiUrlEnvVar, $scope)
    if (-not [string]::IsNullOrWhiteSpace($candidate)) { $ApiBaseUrl = $candidate; break }
}
if ([string]::IsNullOrWhiteSpace($ApiBaseUrl)) {
    Write-Host "FATAL: environment variable '$ApiUrlEnvVar' is not set."
    exit 1
}
$ApiBaseUrl = $ApiBaseUrl.TrimEnd('/')

$CertIssuerMatch = [Environment]::GetEnvironmentVariable("CPM_CERT_ISSUER_LIKE", "Machine")
if ([string]::IsNullOrWhiteSpace($CertIssuerMatch)) { $CertIssuerMatch = "CN=MSLABS-SUBCA01" }

# Registry paths (USER hive)
$ChromePolicyPath = "HKCU:\SOFTWARE\Policies\Google\Chrome"
$ChromeRecommendedPath = "HKCU:\SOFTWARE\Policies\Google\Chrome\Recommended"
$ManifestPath = "HKCU:\SOFTWARE\ChromePolicyManager"
$ManifestKeysValue = "ManagedKeys"
$ManifestHashValue = "PolicyHash"
$ManifestVersionValue = "PolicyVersion"
$ManifestTimestamp = "LastApplied"
$ManifestUpnValue = "UserPrincipalName"

# Cross-context outcome + log live in the user profile (readable by SYSTEM via the SID path).
$UserDataDir = Join-Path $env:LOCALAPPDATA "ChromePolicyManager"
$ResultPath = Join-Path $UserDataDir "user-result.json"
$LogPath = Join-Path $UserDataDir "user-remediation.log"
$MaxLogSizeMB = 5

$script:LogBuffer = [System.Collections.Generic.List[hashtable]]::new()

function Write-Log {
    param([string]$Message, [string]$Level = "INFO")
    $timestamp = Get-Date -Format "yyyy-MM-dd HH:mm:ss"
    $logEntry = "[$timestamp] [$Level] $Message"
    if (-not (Test-Path $UserDataDir)) { New-Item -ItemType Directory -Path $UserDataDir -Force | Out-Null }
    if ((Test-Path $LogPath) -and ((Get-Item $LogPath).Length / 1MB) -gt $MaxLogSizeMB) {
        $archivePath = $LogPath -replace '\.log$', "-$(Get-Date -Format 'yyyyMMdd-HHmmss').log"
        Rename-Item $LogPath $archivePath -ErrorAction SilentlyContinue
    }
    Add-Content -Path $LogPath -Value $logEntry -ErrorAction SilentlyContinue
    $script:LogBuffer.Add(@{
        timestamp = (Get-Date).ToUniversalTime().ToString("o")
        level     = $Level
        message   = $Message
    })
}

function Write-Result {
    # Persist the cross-context outcome read by the SYSTEM orchestrator.
    param([hashtable]$Result)
    try {
        if (-not (Test-Path $UserDataDir)) { New-Item -ItemType Directory -Path $UserDataDir -Force | Out-Null }
        ($Result | ConvertTo-Json -Depth 6) | Set-Content -Path $ResultPath -Encoding UTF8 -Force
    }
    catch { Write-Log "Failed to write result file: $_" "WARN" }
}

# ---------------------------------------------------------------------------
# Identity resolution (ADR-002 §5.2 step a / §8)
# ---------------------------------------------------------------------------
function Get-UserUpn {
    # Native, trustworthy because the task already runs as this user.
    try {
        $upn = (whoami /upn 2>$null)
        if (-not [string]::IsNullOrWhiteSpace($upn)) { return $upn.Trim() }
    }
    catch { }
    try {
        # Fallback: AzureAD\<UPN> or DOMAIN\<sam> from the current token.
        $id = [System.Security.Principal.WindowsIdentity]::GetCurrent().Name
        if ($id -match '\\') { return ($id -split '\\')[-1] }
        return $id
    }
    catch { }
    return $null
}

function Get-DeviceBinding {
    # Corroborates "user genuinely signed-in to Entra on this device" (ADR-002 §8):
    # extracts the Entra DeviceId and the PRT/SSO state from dsregcmd for server-side
    # validation/logging. Best-effort: never throws.
    $binding = @{ deviceId = $null; azureAdPrt = $null; azureAdJoined = $null; tenantId = $null }
    try {
        $dsreg = dsregcmd /status 2>&1
        $m = $dsreg | Select-String "DeviceId\s*:\s*(.+)"
        if ($m) { $binding.deviceId = $m.Matches[0].Groups[1].Value.Trim() }
        $m = $dsreg | Select-String "AzureAdPrt\s*:\s*(.+)"
        if ($m) { $binding.azureAdPrt = $m.Matches[0].Groups[1].Value.Trim() }
        $m = $dsreg | Select-String "AzureAdJoined\s*:\s*(.+)"
        if ($m) { $binding.azureAdJoined = $m.Matches[0].Groups[1].Value.Trim() }
        $m = $dsreg | Select-String "TenantId\s*:\s*(.+)"
        if ($m) { $binding.tenantId = $m.Matches[0].Groups[1].Value.Trim() }
    }
    catch { Write-Log "dsregcmd correlation failed: $_" "WARN" }
    return $binding
}

function Get-ClientCertificate {
    # Device client cert (LocalMachine\My) used for mTLS transport. The SYSTEM
    # orchestrator grants this user temporary read access to the private key.
    try {
        $cert = Get-ChildItem Cert:\LocalMachine\My -ErrorAction SilentlyContinue |
            Where-Object { $_.Issuer -match $CertIssuerMatch -and $_.NotAfter -gt (Get-Date) } |
            Sort-Object NotAfter -Descending |
            Select-Object -First 1
        if ($cert) {
            if (-not $cert.HasPrivateKey) {
                Write-Log "Client certificate found but private key not accessible in user context" "ERROR"
                return $null
            }
            Write-Log "Found client certificate: Subject=$($cert.Subject), Thumbprint=$($cert.Thumbprint)"
            return $cert
        }
        Write-Log "No valid client certificate found (issuer: $CertIssuerMatch)" "ERROR"
    }
    catch { Write-Log "Error searching for client certificate: $_" "ERROR" }
    return $null
}

# ---------------------------------------------------------------------------
# Manifest helpers (per-user)
# ---------------------------------------------------------------------------
function Get-ManagedKeys {
    try {
        if (Test-Path $ManifestPath) {
            $json = (Get-ItemProperty -Path $ManifestPath -Name $ManifestKeysValue -ErrorAction SilentlyContinue).$ManifestKeysValue
            if ($json) { return ($json | ConvertFrom-Json) }
        }
    }
    catch { }
    return @{ mandatory = @(); recommended = @() }
}

function Set-ManagedKeys {
    param([hashtable]$Keys)
    if (-not (Test-Path $ManifestPath)) { New-Item -Path $ManifestPath -Force | Out-Null }
    $json = $Keys | ConvertTo-Json -Compress
    Set-ItemProperty -Path $ManifestPath -Name $ManifestKeysValue -Value $json
}

# ---------------------------------------------------------------------------
# Chrome-faithful registry application (identical semantics to the machine script).
# ---------------------------------------------------------------------------
function Test-IsScalarValue {
    param([object]$Value)
    return ($Value -is [bool] -or $Value -is [string] -or $Value -is [int] -or
            $Value -is [long] -or $Value -is [int16] -or $Value -is [byte] -or
            $Value -is [double] -or $Value -is [single] -or $Value -is [decimal] -or
            $Value -is [uint16] -or $Value -is [uint32] -or $Value -is [sbyte])
}

function Test-IsListValue {
    param([object]$Value)
    return (($Value -is [System.Array]) -or
            (($Value -is [System.Collections.IEnumerable]) -and
             -not ($Value -is [string]) -and
             -not ($Value -is [System.Collections.IDictionary])))
}

function ConvertTo-ChromeScalar {
    param([object]$Value)
    if ($Value -is [bool]) { return @{ Type = 'DWord'; Data = [int][bool]$Value } }
    if ($Value -is [int] -or $Value -is [int16] -or $Value -is [byte] -or $Value -is [sbyte] -or $Value -is [uint16]) {
        return @{ Type = 'DWord'; Data = [int]$Value }
    }
    if ($Value -is [long] -or $Value -is [uint32]) {
        $l = [long]$Value
        if ($l -ge [int]::MinValue -and $l -le [int]::MaxValue) { return @{ Type = 'DWord'; Data = [int]$l } }
        return @{ Type = 'String'; Data = $l.ToString([System.Globalization.CultureInfo]::InvariantCulture) }
    }
    if ($Value -is [double] -or $Value -is [single] -or $Value -is [decimal]) {
        return @{ Type = 'String'; Data = ([double]$Value).ToString([System.Globalization.CultureInfo]::InvariantCulture) }
    }
    return @{ Type = 'String'; Data = [string]$Value }
}

function Remove-PolicyEntry {
    param([string]$BasePath, [string]$Name)
    $subPath = Join-Path $BasePath $Name
    if (Test-Path $subPath) { Remove-Item -Path $subPath -Recurse -Force -ErrorAction SilentlyContinue }
    if (Test-Path $BasePath) {
        $props = Get-ItemProperty -Path $BasePath -ErrorAction SilentlyContinue
        if ($props -and ($props.PSObject.Properties.Name -contains $Name)) {
            Remove-ItemProperty -Path $BasePath -Name $Name -Force -ErrorAction SilentlyContinue
        }
    }
}

function Write-RegistryPolicy {
    param([string]$BasePath, [string]$PolicyName, [object]$Value)
    if (-not (Test-Path $BasePath)) { New-Item -Path $BasePath -Force | Out-Null }
    Remove-PolicyEntry -BasePath $BasePath -Name $PolicyName
    if ($null -eq $Value) { return }

    if (Test-IsScalarValue $Value) {
        $s = ConvertTo-ChromeScalar $Value
        New-ItemProperty -Path $BasePath -Name $PolicyName -Value $s.Data -PropertyType $s.Type -Force | Out-Null
        return
    }
    if (Test-IsListValue $Value) {
        $items = @($Value)
        $allScalar = $true
        foreach ($it in $items) { if (-not (Test-IsScalarValue $it)) { $allScalar = $false; break } }
        if ($allScalar) {
            $listPath = Join-Path $BasePath $PolicyName
            New-Item -Path $listPath -Force | Out-Null
            for ($i = 0; $i -lt $items.Count; $i++) {
                $s = ConvertTo-ChromeScalar $items[$i]
                New-ItemProperty -Path $listPath -Name (($i + 1).ToString()) -Value $s.Data -PropertyType $s.Type -Force | Out-Null
            }
        }
        else {
            $json = ConvertTo-Json -InputObject $items -Compress -Depth 20
            New-ItemProperty -Path $BasePath -Name $PolicyName -Value $json -PropertyType String -Force | Out-Null
        }
        return
    }
    $json = $Value | ConvertTo-Json -Compress -Depth 20
    New-ItemProperty -Path $BasePath -Name $PolicyName -Value $json -PropertyType String -Force | Out-Null
}

function Remove-StaleKeys {
    param([string]$BasePath, [string[]]$PreviousKeys, [string[]]$CurrentKeys)
    $removed = 0
    $staleKeys = $PreviousKeys | Where-Object { $_ -notin $CurrentKeys }
    foreach ($key in $staleKeys) {
        try {
            $itemPath = Join-Path $BasePath $key
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
            Write-Log "Removed stale user policy: $key"
        }
        catch { Write-Log "Failed to remove stale key '$key': $_" "WARN" }
    }
    return $removed
}

function Remove-AllPolicies {
    # Full cleanup when the user is no longer in any User-target assignment.
    param([string]$BasePath, [string[]]$Keys)
    $removed = 0
    foreach ($key in $Keys) {
        try {
            $itemPath = Join-Path $BasePath $key
            if (Test-Path $itemPath) { Remove-Item -Path $itemPath -Recurse -Force; $removed++ }
            elseif (Test-Path $BasePath) {
                $existing = Get-ItemProperty -Path $BasePath -Name $key -ErrorAction SilentlyContinue
                if ($null -ne $existing.$key) { Remove-ItemProperty -Path $BasePath -Name $key -Force; $removed++ }
            }
        }
        catch { Write-Log "Failed to remove key '$key': $_" "WARN" }
    }
    return $removed
}

function Get-PolicyKeyNames {
    param([object]$Policies)
    if ($null -eq $Policies) { return @() }
    if ($Policies -is [System.Collections.IDictionary]) { return @($Policies.Keys) }
    return @($Policies.PSObject.Properties.Name)
}

function Apply-PolicyBucket {
    param([string]$BasePath, [object]$Policies)
    $applied = 0
    if ($null -eq $Policies) { return 0 }
    foreach ($name in (Get-PolicyKeyNames $Policies)) {
        $value = if ($Policies -is [System.Collections.IDictionary]) { $Policies[$name] } else { $Policies.$name }
        Write-RegistryPolicy -BasePath $BasePath -PolicyName $name -Value $value
        $applied++
    }
    return $applied
}

# ---------------------------------------------------------------------------
# Compliance report (per device + user) — ADR-002 §7
# ---------------------------------------------------------------------------
function Send-UserComplianceReport {
    param(
        [System.Security.Cryptography.X509Certificates.X509Certificate2]$ClientCert,
        [string]$DeviceId, [string]$Upn, [string]$PolicyHash,
        [string]$Status, [string]$Errors, [int]$KeysWritten, [int]$KeysRemoved,
        [hashtable]$Binding
    )
    try {
        $headers = @{ "Content-Type" = "application/json" }
        $report = @{
            deviceId          = $DeviceId
            userPrincipalName = $Upn
            target            = "User"
            appliedPolicyHash = $PolicyHash
            status            = $Status
            errors            = $Errors
            policyKeysWritten = $KeysWritten
            policyKeysRemoved = $KeysRemoved
            azureAdPrt        = $Binding.azureAdPrt
        } | ConvertTo-Json
        Invoke-RestMethod -Uri "$ApiBaseUrl/api/v2/users/$Upn/report" -Headers $headers -Method POST -Body $report -Certificate $ClientCert | Out-Null
        Write-Log "User compliance report sent"
    }
    catch { Write-Log "Failed to send user compliance report: $_" "WARN" }
}

# ===========================================================================
#  Main
# ===========================================================================
$status = "Success"
$errorMsg = ""
$keysWritten = 0
$keysRemoved = 0
$userHash = ""

try {
    Write-Log "=== User Chrome policy application started ==="

    $upn = Get-UserUpn
    if ([string]::IsNullOrWhiteSpace($upn)) {
        throw "Could not resolve the current user's UPN"
    }
    Write-Log "User: $upn"

    $binding = Get-DeviceBinding
    if ([string]::IsNullOrWhiteSpace($DeviceId)) { $DeviceId = $binding.deviceId }
    Write-Log "Device binding: deviceId=$($binding.deviceId), AzureAdPrt=$($binding.azureAdPrt), AzureAdJoined=$($binding.azureAdJoined)"

    $clientCert = Get-ClientCertificate
    if ($null -eq $clientCert) {
        throw "No usable device client certificate for mTLS"
    }

    # Fetch user effective policy (HKCU buckets). deviceId is sent for server-side
    # correlation/logging (anti-spoofing, ADR-002 §8).
    $uri = "$ApiBaseUrl/api/v2/users/$upn/effective-policy"
    if (-not [string]::IsNullOrWhiteSpace($DeviceId)) { $uri += "?deviceId=$DeviceId" }
    $headers = @{ "Content-Type" = "application/json" }
    Write-Log "GET $uri"
    $effective = Invoke-RestMethod -Uri $uri -Headers $headers -Method GET -Certificate $clientCert

    $userHash = $effective.userHash
    $mandatory = $effective.userMandatory
    $recommended = $effective.userRecommended

    $currentMandatoryKeys = @(Get-PolicyKeyNames $mandatory)
    $currentRecommendedKeys = @(Get-PolicyKeyNames $recommended)

    $previous = Get-ManagedKeys
    $previousMandatoryKeys = @($previous.mandatory)
    $previousRecommendedKeys = @($previous.recommended)

    if ($currentMandatoryKeys.Count -eq 0 -and $currentRecommendedKeys.Count -eq 0) {
        # User not a member of any User-target assignment → remove any stale keys (ADR-002 §5.2.1).
        Write-Log "No user policies assigned; cleaning up any previously-applied HKCU keys"
        $keysRemoved += (Remove-AllPolicies -BasePath $ChromePolicyPath -Keys $previousMandatoryKeys)
        $keysRemoved += (Remove-AllPolicies -BasePath $ChromeRecommendedPath -Keys $previousRecommendedKeys)
        Set-ManagedKeys -Keys @{ mandatory = @(); recommended = @() }
    }
    else {
        $keysWritten += (Apply-PolicyBucket -BasePath $ChromePolicyPath -Policies $mandatory)
        $keysWritten += (Apply-PolicyBucket -BasePath $ChromeRecommendedPath -Policies $recommended)

        $keysRemoved += (Remove-StaleKeys -BasePath $ChromePolicyPath -PreviousKeys $previousMandatoryKeys -CurrentKeys $currentMandatoryKeys)
        $keysRemoved += (Remove-StaleKeys -BasePath $ChromeRecommendedPath -PreviousKeys $previousRecommendedKeys -CurrentKeys $currentRecommendedKeys)

        Set-ManagedKeys -Keys @{ mandatory = $currentMandatoryKeys; recommended = $currentRecommendedKeys }
    }

    # Update manifest metadata.
    if (-not (Test-Path $ManifestPath)) { New-Item -Path $ManifestPath -Force | Out-Null }
    Set-ItemProperty -Path $ManifestPath -Name $ManifestHashValue -Value ([string]$userHash)
    Set-ItemProperty -Path $ManifestPath -Name $ManifestUpnValue -Value $upn
    Set-ItemProperty -Path $ManifestPath -Name $ManifestTimestamp -Value ((Get-Date).ToUniversalTime().ToString("o"))
    if ($effective.appliedAssignments) {
        $versions = ($effective.appliedAssignments | ForEach-Object { $_.version }) -join ","
        Set-ItemProperty -Path $ManifestPath -Name $ManifestVersionValue -Value $versions
    }

    Write-Log "Applied user policies: written=$keysWritten removed=$keysRemoved hash=$userHash"

    Send-UserComplianceReport -ClientCert $clientCert -DeviceId $DeviceId -Upn $upn `
        -PolicyHash $userHash -Status $status -Errors $errorMsg `
        -KeysWritten $keysWritten -KeysRemoved $keysRemoved -Binding $binding
}
catch {
    $status = "Failed"
    $errorMsg = "$_"
    Write-Log "User policy application failed: $_" "ERROR"
}

Write-Result -Result @{
    upn          = (Get-UserUpn)
    deviceId     = $DeviceId
    status       = $status
    error        = $errorMsg
    userHash     = $userHash
    keysWritten  = $keysWritten
    keysRemoved  = $keysRemoved
    timestamp    = (Get-Date).ToUniversalTime().ToString("o")
}

Write-Log "=== User Chrome policy application finished: $status ==="
if ($status -eq "Success") { exit 0 } else { exit 1 }
