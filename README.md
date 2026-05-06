# Chrome Policy Manager

> **Server-side Chrome policy delivery for Entra ID–only (Azure AD joined) devices — bypassing the Group Policy dependency that breaks ADMX-based Chrome settings on cloud-managed endpoints.**

[![.NET 9](https://img.shields.io/badge/.NET-9.0-purple)](https://dotnet.microsoft.com/)
[![Azure](https://img.shields.io/badge/Azure-Deployed-blue)](https://azure.microsoft.com/)
[![Intune](https://img.shields.io/badge/Intune-Proactive%20Remediation-green)](https://learn.microsoft.com/en-us/mem/intune/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)

## 🎯 The Problem

Chrome policies deployed via **Intune Settings Catalog** (ADMX-backed) **fail silently** on Entra ID–only joined devices. This happens because:

1. **GP Notification dependency** — Chrome's `PolicyLoaderWin` calls `RegisterGPNotification()` which requires a domain-joined machine
2. **Domain join gate** — `mdm_utils.cc` checks `IsEnrolledToDomain()` before applying policies
3. **ADMX registry mirroring** — Intune writes to `HKLM:\SOFTWARE\Microsoft\PolicyManager\providers\...` but the GP Client Service never mirrors them to `HKLM:\SOFTWARE\Policies\Google\Chrome` on cloud-only devices

This affects **ALL Chrome policies equally** on cloud-only joined devices — not just specific ones.

## 💡 The Solution

Chrome Policy Manager implements a **server-side policy resolution engine** that delivers Chrome policies directly to device registries via Intune Proactive Remediation scripts, completely bypassing the broken GP pipeline.

```
┌─────────────────────────────────────────────────────────────────┐
│                        ARCHITECTURE                              │
├─────────────────────────────────────────────────────────────────┤
│                                                                  │
│  ┌──────────┐    ┌───────────┐    ┌──────────────────────────┐  │
│  │  Admin   │───▶│  REST API │◀───│  Intune Remediation      │  │
│  │  UI      │    │  (.NET 9) │    │  (PowerShell scripts)    │  │
│  │ (Blazor) │    └─────┬─────┘    └──────────────────────────┘  │
│  └──────────┘          │                                         │
│                   ┌────┴────┐                                    │
│                   │ SQL DB  │  ← PolicySets, Versions,           │
│                   │  (S2)   │    Assignments, DeviceState         │
│                   └────┬────┘                                    │
│                        │                                         │
│              ┌─────────┼─────────┐                               │
│              │         │         │                               │
│         ┌────┴────┐ ┌──┴───┐ ┌──┴──────────┐                   │
│         │ MS Graph│ │ Svc  │ │ Graph Change │                   │
│         │ (delta) │ │ Bus  │ │ Webhooks     │                   │
│         └─────────┘ └──────┘ └─────────────┘                   │
│                                                                  │
└─────────────────────────────────────────────────────────────────┘
```

## ✨ Key Features

| Feature | Description |
|---------|-------------|
| **ADMX Catalog Ingestion** | Parse Chrome ADMX/ADML templates → browse 700+ policies with descriptions, types, categories |
| **PolicySet Versioning** | Immutable versions (Draft → Active → Archived) with hash-based change detection |
| **Group-Based Targeting** | Assign policies to Entra ID security groups with priority-based conflict resolution |
| **Mandatory & Recommended** | Support both Chrome policy scopes per assignment |
| **Effective Policy Resolution** | Server resolves device → groups → assignments → merged settings (lower priority wins) |
| **Device Observability** | Real-time compliance dashboard, offline detection, error tracking |
| **Intune Delivery** | Proactive Remediation hourly check → detect drift → apply policies via registry |
| **Audit Trail** | Full audit logging for all policy changes and device interactions |

## 🏗️ Project Structure

```
ChromePolicyManager/
├── src/
│   ├── Server/
│   │   ├── ChromePolicyManager.Api/        # REST API (.NET 9 Minimal API)
│   │   │   ├── Data/                       # EF Core DbContext + models
│   │   │   ├── Endpoints/                  # Policy, Assignment, Device, Catalog, Monitoring
│   │   │   ├── Models/                     # PolicySet, Version, Assignment, CatalogEntry
│   │   │   └── Services/                   # AdmxParser, EffectivePolicy, Graph, Reporting
│   │   └── ChromePolicyManager.Admin/      # Blazor Server Admin UI (MudBlazor)
│   │       └── Components/Pages/           # Dashboard, Catalog, Policies, Assignments, Devices
│   └── Client/
│       ├── Detect-ChromePolicy.ps1         # Intune detection script
│       └── Remediate-ChromePolicy.ps1      # Intune remediation script
├── infra/
│   └── Deploy-Infrastructure.ps1           # One-click Azure deployment
└── tools/                                  # ADMX template downloads (gitignored)
```

## 🚀 Quick Start

### Prerequisites

- .NET 9 SDK
- Azure subscription (with Intune license for remediation)
- `az` CLI authenticated
- `gh` CLI (optional, for repo operations)

### 1. Deploy Infrastructure

```powershell
cd infra
.\Deploy-Infrastructure.ps1
```

This creates: Resource Group, SQL Server (Entra-only auth), App Service Plan (B1), Web Apps (API + Admin), Key Vault, Service Bus, App Configuration.

### 2. Import Chrome Policy Catalog

Download the [Chrome ADMX templates](https://chromeenterprise.google/browser/download/#manage-policies-tab) and upload via the Admin UI or API:

```bash
# Via API (multipart upload)
curl -X POST https://your-api.azurewebsites.net/api/catalog/import \
  -F "admxZip=@policy_templates.zip" \
  -F "version=136.0"
```

### 3. Create Policy Sets

Use the Admin UI at `https://your-admin.azurewebsites.net/catalog` to:
1. Browse the catalog → filter by category/type → view descriptions
2. Select policies and configure values
3. Create PolicySets (e.g., "Security Baseline", "User Experience")
4. Add versions with specific settings
5. Assign to Entra ID groups with priority

### 4. Deploy Intune Remediation

The deployment script automatically creates a Proactive Remediation in Intune that:
- Runs **hourly** on targeted devices
- **Detects** drift by comparing local policy hash vs server hash
- **Remediates** by writing Chrome registry policies directly to `HKLM:\SOFTWARE\Policies\Google\Chrome`

## 🔧 API Endpoints

### Policy Catalog
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/catalog` | Browse policy catalog (filter: `?category=&search=&dataType=&recommended=`) |
| `GET` | `/api/catalog/categories` | List available categories |
| `GET` | `/api/catalog/stats` | Import statistics |
| `POST` | `/api/catalog/import` | Import ADMX zip (multipart/form-data) |

### Policy Management
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/policies` | List all PolicySets with versions |
| `POST` | `/api/policies` | Create new PolicySet |
| `POST` | `/api/policies/{id}/versions` | Add version with settings JSON |
| `POST` | `/api/policies/versions/{id}/promote` | Promote Draft → Active |
| `POST` | `/api/policies/{id}/rollback/{versionId}` | Rollback to previous version |

### Assignments
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/assignments` | List all assignments |
| `POST` | `/api/assignments` | Create group assignment (priority + scope) |
| `DELETE` | `/api/assignments/{id}` | Remove assignment |

### Device Operations
| Method | Endpoint | Description |
|--------|----------|-------------|
| `GET` | `/api/devices/{id}/effective-policy` | Resolve effective policy for device |
| `POST` | `/api/devices/{id}/report` | Device reports compliance status |
| `GET` | `/api/monitoring/dashboard` | Compliance dashboard data |
| `GET` | `/api/monitoring/offline` | Offline devices (>N hours) |
| `GET` | `/api/monitoring/errors` | Devices with errors |
| `GET` | `/health` | Health check |

## 📊 How Policy Resolution Works

```
Client Device → API: "What policies apply to me?" (GET /devices/{id}/effective-policy)
                      │
                      ▼
              MS Graph: devices/{id}/memberOf → [Group1, Group2, ...]
                      │
                      ▼
              Match groups → Active PolicyAssignments
                      │
                      ▼
              Sort by Priority (ascending: lower = higher priority)
                      │
                      ▼
              Merge settings (first-writer-wins per key, separated by scope)
                      │
                      ▼
              Return: { mandatory: {...}, recommended: {...}, hash: "abc123" }
```

## 🔬 Root Cause Analysis

### Why Intune Settings Catalog Fails for Chrome

1. **Intune ADMX ingestion** writes to `HKLM\SOFTWARE\Microsoft\PolicyManager\providers\{GUID}\...`
2. This relies on **GP Client Service** to mirror to `HKLM\SOFTWARE\Policies\Google\Chrome`
3. On Entra ID–only devices, GP Client mirroring is **broken** (no `RegisterGPNotification`, no domain join)
4. Chrome reads **only** from `HKLM\SOFTWARE\Policies\Google\Chrome` — policies never arrive

### Why Direct Registry Write Works

- Chrome's `PolicyLoaderWin` reads `HKLM\SOFTWARE\Policies\Google\Chrome` **unconditionally**
- No domain-join check gates registry policy reading
- Chrome polls registry every 15 minutes (`kReloadInterval = base::Minutes(15)`)
- Entra ID–only devices get `FULLY_TRUSTED` management authority — no policy filtering

### Source Code Evidence (Chromium)

- `PolicyLoaderWin::InitOnBackgroundThread()` — requires `RegisterGPNotification()` success
- `mdm_utils.cc::IsEnrolledToDomain()` — GP registry path check fails on cloud-only devices
- `WinGPOListProvider` — depends on Active Directory infrastructure not present on Entra-only devices

## 🛡️ Security

- **Entra ID authentication** for API and Admin UI
- **Managed Identity** for Azure resource access
- **Key Vault** for secrets (connection strings, client secrets)
- **Entra-only SQL auth** (no SQL passwords — MCAPS compliant)
- **Audit logging** for all policy changes and device interactions
- **CORS** restricted to Admin UI origin
- **Service Bus** for async device report processing (202 Accepted pattern)

## 📈 Scaling to 100k+ Devices

The solution is designed to handle large-scale enterprise environments (100,000+ devices) with minimal infrastructure cost. Three key optimizations make this possible:

### 1. ETag / 304 Not Modified

The `GET /devices/{id}/effective-policy` endpoint returns an `ETag` header containing the policy hash. On subsequent requests, the client sends `If-None-Match` with its cached hash:

```
Client → API: GET /effective-policy  (If-None-Match: "abc123")
API → Client: 304 Not Modified       ← No body, minimal compute

Only when policy actually changes:
Client → API: GET /effective-policy  (If-None-Match: "abc123")
API → Client: 200 OK + full payload  (ETag: "def456")
```

**Impact:** At 100k devices/hour with ~90% steady state → only ~10k full responses/hour carry a payload.

### 2. Graph Change Notifications (Webhooks)

Instead of calling Microsoft Graph for every device check-in (which would hit throttling limits at scale), the API subscribes to **real-time webhook notifications** for group membership changes:

```
┌─────────────┐     Webhook: "Group X changed"     ┌─────────────┐
│ Microsoft   │ ──────────────────────────────────▶ │  CPM API    │
│ Graph       │                                     │  (marks     │
└─────────────┘                                     │  group as   │
                                                    │  dirty)     │
                                                    └──────┬──────┘
                                                           │
Device check-in:                                           ▼
  - Device in Group X → Graph call (real-time, fresh data)
  - Device in Group Y (unchanged) → use cached membership
```

**Implementation:**
- `GroupChangeNotificationService` (BackgroundService) maintains subscriptions for all groups used in policy assignments
- Subscriptions auto-renew before the 4230-minute Graph limit (~3 days)
- `/api/webhooks/group-change` receives notifications and marks affected groups
- `WebhookEndpoints.HasGroupChanged()` allows the effective policy resolver to skip Graph calls for unchanged groups

**Impact:** Reduces Graph API calls from **100,000/hour** to **~50-100/hour** (only devices in groups that actually changed), while maintaining **zero-latency reactivity** — policy changes propagate within minutes, not hours like Intune.

### 3. Azure SQL S2 (50 DTU)

Upgraded from Basic (5 DTU) to Standard S2 to handle sustained write throughput:
- 100k device reports/hour = ~28 writes/sec sustained
- S2 provides 50 DTU → comfortable headroom for reads + writes + indexes

### Scaling Summary

| Metric | Without optimizations | With optimizations |
|--------|----------------------|-------------------|
| Graph API calls/hour | 100,000 (throttled) | 50-100 |
| Full policy responses/hour | 100,000 | ~10,000 |
| Network bandwidth/hour | ~500 MB | ~50 MB |
| SQL write pressure | 100k full reports | 100k lightweight + 10k full |
| Reactivity | N/A (was polling) | **Real-time** (webhook push) |

### Recommended SKUs for 100k+ Devices

| Component | SKU | Monthly Cost (est.) |
|-----------|-----|-------------------|
| App Service | S2 or P1v3 | €70-140 |
| Azure SQL | S2 (50 DTU) | €60-150 |
| Service Bus | Standard | €10 |
| Total | | **~€150-300/month** |

## 📦 Technology Stack

| Component | Technology |
|-----------|-----------|
| API | .NET 9, Minimal API, Entity Framework Core |
| Admin UI | Blazor Server, MudBlazor 8 |
| Database | Azure SQL S2, 50 DTU (Entra-only auth) |
| Auth | Microsoft Identity Web, MSAL, Device Certificates |
| Group Resolution | Microsoft Graph SDK + Change Notifications |
| Messaging | Azure Service Bus (async device reports) |
| Config | Azure App Configuration (Standard) |
| Secrets | Azure Key Vault |
| Hosting | Azure App Service (B1 → S2 at scale) |
| Client | PowerShell 5.1 (Intune Proactive Remediation) |
| Policy Catalog | Chrome ADMX/ADML parser (700+ policies) |

## 🤝 Contributing

1. Fork the repo
2. Create a feature branch (`git checkout -b feature/amazing-feature`)
3. Commit your changes
4. Push to the branch
5. Open a Pull Request

## 📄 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## 🏷️ Keywords

`chrome-policy`, `intune`, `entra-id`, `azure-ad-joined`, `admx`, `group-policy-workaround`, `chrome-enterprise`, `mdm`, `proactive-remediation`, `browser-management`, `endpoint-management`, `registry-policy`, `blazor`, `dotnet`, `azure`

---

**Built to solve a real-world enterprise pain point — Chrome policy delivery on modern cloud-only managed devices where ADMX-based Settings Catalog fails silently.**
