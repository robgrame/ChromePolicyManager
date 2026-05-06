using System.Net.Http.Json;
using System.Text.Json;
using System.Text.Json.Serialization;

namespace ChromePolicyManager.Admin.Services;

public class PolicyApiClient
{
    private readonly HttpClient _http;
    private static readonly JsonSerializerOptions JsonOptions = new()
    {
        PropertyNameCaseInsensitive = true,
        Converters = { new JsonStringEnumConverter() }
    };

    public PolicyApiClient(HttpClient http) => _http = http;

    // === Policies ===
    public async Task<List<PolicySetDto>> GetPoliciesAsync()
    {
        var response = await _http.GetAsync("/api/policies");
        response.EnsureSuccessStatusCode();
        var json = await response.Content.ReadAsStringAsync();
        return JsonSerializer.Deserialize<List<PolicySetDto>>(json, JsonOptions) ?? [];
    }

    public async Task<PolicySetDto> CreatePolicySetAsync(string name, string description)
    {
        var response = await _http.PostAsJsonAsync("/api/policies", new { name, description });
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<PolicySetDto>(JsonOptions))!;
    }

    public async Task<VersionResponseDto> CreateVersionAsync(Guid policySetId, string version, string settingsJson)
    {
        var response = await _http.PostAsJsonAsync($"/api/policies/{policySetId}/versions", 
            new { version, settingsJson });
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<VersionResponseDto>(JsonOptions))!;
    }

    public async Task<PolicySetVersionDto> PromoteVersionAsync(Guid versionId)
    {
        var response = await _http.PostAsync($"/api/policies/versions/{versionId}/promote", null);
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<PolicySetVersionDto>(JsonOptions))!;
    }

    // === Assignments ===
    public async Task<List<AssignmentDto>> GetAssignmentsAsync()
    {
        return await _http.GetFromJsonAsync<List<AssignmentDto>>("/api/assignments", JsonOptions) ?? [];
    }

    public async Task<AssignmentDto> CreateAssignmentAsync(Guid policySetVersionId, string entraGroupId, 
        string groupName, int priority, int scope)
    {
        var response = await _http.PostAsJsonAsync("/api/assignments", new
        {
            policySetVersionId, entraGroupId, groupName, priority, scope
        });
        response.EnsureSuccessStatusCode();
        return (await response.Content.ReadFromJsonAsync<AssignmentDto>(JsonOptions))!;
    }

    public async Task DeleteAssignmentAsync(Guid id)
    {
        var response = await _http.DeleteAsync($"/api/assignments/{id}");
        response.EnsureSuccessStatusCode();
    }

    // === Monitoring ===
    public async Task<MonitoringDashboardDto> GetDashboardAsync()
    {
        return await _http.GetFromJsonAsync<MonitoringDashboardDto>("/api/monitoring/dashboard", JsonOptions) 
            ?? new MonitoringDashboardDto();
    }

    public async Task<List<DeviceStateDto>> GetOfflineDevicesAsync(int hours = 24)
    {
        return await _http.GetFromJsonAsync<List<DeviceStateDto>>($"/api/monitoring/offline?hours={hours}", JsonOptions) ?? [];
    }

    public async Task<List<DeviceStateDto>> GetErrorDevicesAsync()
    {
        return await _http.GetFromJsonAsync<List<DeviceStateDto>>("/api/monitoring/errors", JsonOptions) ?? [];
    }
}

// === DTOs ===
public class PolicySetDto
{
    public Guid Id { get; set; }
    public string Name { get; set; } = "";
    public string Description { get; set; } = "";
    public DateTime CreatedAt { get; set; }
    public DateTime UpdatedAt { get; set; }
    public List<PolicySetVersionDto> Versions { get; set; } = [];
}

public class PolicySetVersionDto
{
    public Guid Id { get; set; }
    public Guid PolicySetId { get; set; }
    public string Version { get; set; } = "";
    public string SettingsJson { get; set; } = "{}";
    public string Hash { get; set; } = "";
    public PolicyVersionStatus Status { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class VersionResponseDto
{
    public PolicySetVersionDto? Version { get; set; }
    public ValidationResultDto? Validation { get; set; }
}

public class ValidationResultDto
{
    public bool IsValid { get; set; }
    public List<string> Errors { get; set; } = [];
    public List<string> Warnings { get; set; } = [];
}

public enum PolicyVersionStatus { Draft, Active, Archived }

public class AssignmentDto
{
    public Guid Id { get; set; }
    public Guid PolicySetVersionId { get; set; }
    public string EntraGroupId { get; set; } = "";
    public string GroupName { get; set; } = "";
    public int Priority { get; set; }
    public int Scope { get; set; } // 0=Mandatory, 1=Recommended
    public bool Enabled { get; set; }
    public DateTime CreatedAt { get; set; }
}

public class MonitoringDashboardDto
{
    public int TotalDevices { get; set; }
    public int CompliantDevices { get; set; }
    public int NonCompliantDevices { get; set; }
    public int ErrorDevices { get; set; }
    public int OfflineDevices { get; set; }
    public List<DeviceStateDto> RecentReports { get; set; } = [];
}

public class DeviceStateDto
{
    public string DeviceId { get; set; } = "";
    public string DeviceName { get; set; } = "";
    public string Status { get; set; } = "";
    public string? AppliedPolicyHash { get; set; }
    public string? Errors { get; set; }
    public string? ChromeVersion { get; set; }
    public string? OsVersion { get; set; }
    public DateTime LastContact { get; set; }
    public int PolicyKeysWritten { get; set; }
    public int PolicyKeysRemoved { get; set; }
}
