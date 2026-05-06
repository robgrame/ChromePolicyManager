# Chrome Policy Manager

## Overview

Chrome policies deployed via Intune Settings Catalog **fail on Entra ID-only (Azure AD joined) devices** because the ADMX ingestion/GP registry mirroring chain is broken without traditional domain join.

**ChromePolicyManager** bypasses the broken pipeline by writing Chrome policies directly to the Windows registry (`HKLM\SOFTWARE\Policies\Google\Chrome`) via a PowerShell remediation script, with central management through a .NET 10 Web API.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     Azure Cloud                                   │
│                                                                   │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────────┐   │
│  │ Azure APIM   │───▶│ .NET 10 API  │───▶│  Azure SQL       │   │
│  │ (Gateway)    │    │ (App Service)│    │  (Data Store)    │   │
│  └──────┬───────┘    └──────┬───────┘    └──────────────────┘   │
│         │                   │                                     │
│         │            ┌──────┴───────┐    ┌──────────────────┐   │
│         │            │ MS Graph     │    │ App Configuration│   │
│         │            │ (Groups)     │    │ (Settings)       │   │
│         │            └──────────────┘    └──────────────────┘   │
└─────────┼───────────────────────────────────────────────────────┘
          │
          │ HTTPS (device auth)
          │
┌─────────┴───────────────────────────────────────────────────────┐
│  Windows Device (Entra ID Joined)                                │
│                                                                   │
│  ┌──────────────────────────────────────────────────────────┐   │
│  │  Intune Proactive Remediation                             │   │
│  │  ┌─────────────────┐    ┌───────────────────────────┐   │   │
│  │  │ Detection Script │    │ Remediation Script         │   │   │
│  │  │ (hash compare)   │    │ (fetch policy, write reg) │   │   │
│  │  └─────────────────┘    └───────────────────────────┘   │   │
│  └──────────────────────────────────────────────────────────┘   │
│                                                                   │
│  Registry: HKLM\SOFTWARE\Policies\Google\Chrome\*                │
│  Manifest: HKLM\SOFTWARE\ChromePolicyManager\                    │
└─────────────────────────────────────────────────────────────────┘
```

## Components

### Server (`src/Server/ChromePolicyManager.Api`)
- **.NET 10 Minimal API** with Entity Framework Core
- **Policy Management**: Create policy sets with immutable versions (draft → active → archived)
- **Assignments**: Assign policy versions to Entra ID security groups with priority
- **Effective Policy Resolution**: Server-side group membership resolution via Microsoft Graph, conflict resolution by priority (lower number wins)
- **Device Monitoring**: Compliance reporting, offline detection, error tracking
- **Schema Validation**: Validates Chrome policy types (boolean, integer, string, list, dictionary)
- **Audit Logging**: Full audit trail of all operations

### Client (`src/Client/`)
- **Detect-ChromePolicy.ps1**: Detection script — compares local policy hash with server-expected hash
- **Remediate-ChromePolicy.ps1**: Remediation script — fetches effective policy, writes registry, removes stale keys, reports compliance

## Key Features

| Feature | Description |
|---------|-------------|
| **Versioning** | Immutable policy versions with draft/active/archived lifecycle and rollback |
| **Priority** | Lower number = higher priority. Same policy key from multiple groups → highest priority wins |
| **Scope** | Supports both Mandatory and Recommended Chrome policy paths |
| **Stale Removal** | Maintains local manifest of owned keys; removes keys no longer in policy |
| **Monitoring** | Tracks device check-ins, flags offline >24h, reports errors per device |
| **Validation** | Validates policy names, types, and values against Chrome's expected schema |
| **Audit** | Full audit trail: who changed what, when, with details |

## Infrastructure (Planned)

| Component | Purpose |
|-----------|---------|
| **Azure APIM** | Gateway: Management API (admin) + Device API (clients), rate limiting, auth |
| **Azure App Configuration** | Centralized config: feature flags, thresholds, URLs |
| **Azure App Service** | Host .NET 10 API (potentially split: management + device processing) |
| **Azure SQL** | Production database |
| **Azure Key Vault** | Secrets, certificates, connection strings |

## API Endpoints

### Management API (Admin)
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/policies` | List all policy sets |
| POST | `/api/policies` | Create policy set |
| GET | `/api/policies/{id}` | Get policy set with versions |
| POST | `/api/policies/{id}/versions` | Create new version (validated) |
| POST | `/api/policies/versions/{id}/promote` | Promote version to active |
| POST | `/api/policies/{id}/rollback/{versionId}` | Rollback to previous version |
| GET | `/api/assignments` | List assignments |
| POST | `/api/assignments` | Create assignment (group + priority) |
| PUT | `/api/assignments/{id}/priority` | Update priority |
| DELETE | `/api/assignments/{id}` | Remove assignment |
| GET | `/api/monitoring/dashboard` | Compliance overview |
| GET | `/api/monitoring/offline-devices` | Devices offline >N hours |
| GET | `/api/monitoring/error-devices` | Devices with errors |

### Device API (Client Scripts)
| Method | Path | Description |
|--------|------|-------------|
| GET | `/api/devices/{deviceId}/effective-policy` | Get merged effective policy |
| POST | `/api/devices/{deviceId}/report` | Submit compliance report |
| GET | `/api/devices/{deviceId}/history` | Get device report history |

## Getting Started

### Prerequisites
- .NET 10 SDK
- Azure subscription (for production)
- Entra ID tenant with app registration

### Local Development
```bash
cd src/Server/ChromePolicyManager.Api
dotnet run
```
The API starts with SQLite and auto-creates the database. Access OpenAPI at `https://localhost:5001/openapi/v1.json`.

### Deploy Client Scripts
1. Configure `$ApiBaseUrl`, `$TenantId`, `$ClientId` in both scripts
2. In Intune → Devices → Remediation:
   - Detection: `Detect-ChromePolicy.ps1`
   - Remediation: `Remediate-ChromePolicy.ps1`
   - Run as: System (64-bit)
   - Schedule: Every 1 hour (recommended)

### Create Your First Policy
```bash
# 1. Create a policy set
curl -X POST https://localhost:5001/api/policies \
  -H "Content-Type: application/json" \
  -d '{"name": "Security Baseline", "description": "Standard security policies for all devices"}'

# 2. Create a version with Chrome settings
curl -X POST https://localhost:5001/api/policies/{policySetId}/versions \
  -H "Content-Type: application/json" \
  -d '{
    "version": "1.0.0",
    "settingsJson": "{\"PasswordManagerEnabled\": false, \"SafeBrowsingProtectionLevel\": 2, \"SyncDisabled\": true, \"URLBlocklist\": [\"*://malware.example.com\"]}"
  }'

# 3. Promote the version
curl -X POST https://localhost:5001/api/policies/versions/{versionId}/promote

# 4. Assign to an Entra group
curl -X POST https://localhost:5001/api/assignments \
  -H "Content-Type: application/json" \
  -d '{
    "policySetVersionId": "{versionId}",
    "entraGroupId": "group-guid-from-entra",
    "groupName": "All Corporate Devices",
    "priority": 10,
    "scope": 0
  }'
```

## How It Works (Technical)

### Why Intune Settings Catalog Fails
1. Intune ADMX ingestion writes to `HKLM\SOFTWARE\Microsoft\PolicyManager\providers\{GUID}\...`
2. This relies on GP Client Service to mirror to `HKLM\SOFTWARE\Policies\Google\Chrome`
3. On Entra ID-only devices, GP Client mirroring is broken (no `RegisterGPNotification`, no domain join)
4. Chrome reads **only** from `HKLM\SOFTWARE\Policies\Google\Chrome` — policies never arrive

### Why Direct Registry Write Works
- Chrome's `PolicyLoaderWin` reads from `HKLM\SOFTWARE\Policies\Google\Chrome` **unconditionally**
- No domain-join check gates registry policy reading
- Chrome polls registry every 15 minutes (`kReloadInterval = base::Minutes(15)`)
- Entra ID-only devices get `FULLY_TRUSTED` management authority — no policy filtering

### Priority Resolution
When a device is in multiple groups with conflicting policies:
1. All assignments targeting device groups are collected
2. Sorted by priority (ascending — lower number = higher priority)
3. For each policy key, first writer wins
4. Result: deterministic, predictable policy merge

## License
Internal use only.
