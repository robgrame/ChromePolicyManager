using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Models;

namespace ChromePolicyManager.Api.Services;

/// <summary>
/// Resolves the effective Chrome policy for a device based on its Entra group memberships and assignment priorities.
/// </summary>
public class EffectivePolicyService
{
    private readonly AppDbContext _db;
    private readonly IGraphService _graphService;

    public EffectivePolicyService(AppDbContext db, IGraphService graphService)
    {
        _db = db;
        _graphService = graphService;
    }

    /// <summary>
    /// Get the effective MACHINE policy for a device: Target=Machine assignments resolved by the
    /// device's Entra group memberships, merged by priority. Backwards-compatible v1 contract.
    /// </summary>
    public async Task<EffectivePolicyResult> GetEffectivePolicyAsync(string deviceId)
    {
        // Resolve device group memberships from Microsoft Graph (server-side, trusted)
        var groupIds = await _graphService.GetDeviceGroupMembershipsAsync(deviceId);
        var (mandatory, recommended, applied) = await ResolveBucketsAsync(groupIds, PolicyTarget.Machine);
        var hashInput = JsonSerializer.Serialize(mandatory) + JsonSerializer.Serialize(recommended);

        return new EffectivePolicyResult
        {
            DeviceId = deviceId,
            MandatoryPolicies = mandatory,
            RecommendedPolicies = recommended,
            Hash = ComputeHash(hashInput),
            AppliedAssignments = applied
        };
    }

    /// <summary>
    /// Get the effective USER policy for a signed-in user: Target=User assignments resolved by the
    /// user's Entra group memberships, merged by priority. Targets the HKCU hive on the client.
    /// </summary>
    public async Task<UserEffectivePolicyResult> GetUserEffectivePolicyAsync(string upn)
    {
        // Resolve user group memberships from Microsoft Graph (server-side, trusted)
        var groupIds = await _graphService.GetUserGroupMembershipsAsync(upn);
        var (mandatory, recommended, applied) = await ResolveBucketsAsync(groupIds, PolicyTarget.User);
        var hashInput = JsonSerializer.Serialize(mandatory) + JsonSerializer.Serialize(recommended);

        return new UserEffectivePolicyResult
        {
            Upn = upn,
            UserMandatory = mandatory,
            UserRecommended = recommended,
            UserHash = ComputeHash(hashInput),
            AppliedAssignments = applied
        };
    }

    /// <summary>
    /// Resolve and merge the mandatory/recommended buckets for a set of Entra groups and a given
    /// registry target. First writer wins per key (lowest Priority number).
    /// </summary>
    private async Task<(Dictionary<string, object> Mandatory, Dictionary<string, object> Recommended, List<AppliedAssignmentInfo> Applied)>
        ResolveBucketsAsync(List<string> groupIds, PolicyTarget target)
    {
        var mandatoryPolicies = new Dictionary<string, object>();
        var recommendedPolicies = new Dictionary<string, object>();
        var appliedAssignments = new List<AppliedAssignmentInfo>();

        if (groupIds.Count == 0)
            return (mandatoryPolicies, recommendedPolicies, appliedAssignments);

        // Find all active assignments for this target whose group the identity belongs to
        var assignments = await _db.PolicyAssignments
            .Include(a => a.PolicySetVersion)
                .ThenInclude(v => v.PolicySet)
            .Where(a => a.Enabled && a.Target == target && groupIds.Contains(a.EntraGroupId))
            .Where(a => a.PolicySetVersion.Status == PolicyVersionStatus.Active)
            .OrderBy(a => a.Priority)
            .ToListAsync();

        foreach (var assignment in assignments)
        {
            var settings = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(assignment.PolicySetVersion.SettingsJson)
                ?? new Dictionary<string, JsonElement>();

            var targetDict = assignment.Scope == PolicyScope.Mandatory ? mandatoryPolicies : recommendedPolicies;

            bool hadNewKeys = false;
            foreach (var kvp in settings)
            {
                // First writer wins (lowest priority number)
                if (!targetDict.ContainsKey(kvp.Key))
                {
                    targetDict[kvp.Key] = ConvertJsonElement(kvp.Value);
                    hadNewKeys = true;
                }
            }

            if (hadNewKeys || !settings.Any())
            {
                appliedAssignments.Add(new AppliedAssignmentInfo
                {
                    AssignmentId = assignment.Id,
                    PolicySetName = assignment.PolicySetVersion.PolicySet?.Name ?? "Unknown",
                    Version = assignment.PolicySetVersion.Version,
                    Priority = assignment.Priority,
                    Scope = assignment.Scope,
                    GroupName = assignment.GroupName
                });
            }
        }

        return (mandatoryPolicies, recommendedPolicies, appliedAssignments);
    }

    private static object ConvertJsonElement(JsonElement element)
    {
        return element.ValueKind switch
        {
            JsonValueKind.String => element.GetString()!,
            JsonValueKind.Number => element.TryGetInt64(out var l) ? l : element.GetDouble(),
            JsonValueKind.True => true,
            JsonValueKind.False => false,
            JsonValueKind.Array => element.EnumerateArray().Select(ConvertJsonElement).ToList(),
            JsonValueKind.Object => element.EnumerateObject().ToDictionary(p => p.Name, p => ConvertJsonElement(p.Value)),
            _ => element.GetRawText()
        };
    }

    private static string ComputeHash(string content)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(content));
        return Convert.ToHexStringLower(bytes);
    }
}

public class EffectivePolicyResult
{
    public string DeviceId { get; set; } = string.Empty;
    public Dictionary<string, object> MandatoryPolicies { get; set; } = new();
    public Dictionary<string, object> RecommendedPolicies { get; set; } = new();
    public string Hash { get; set; } = string.Empty;
    public List<AppliedAssignmentInfo> AppliedAssignments { get; set; } = new();
}

/// <summary>
/// v2 user-scoped effective policy (HKCU). Buckets are resolved from Target=User assignments
/// against the signed-in user's Entra group memberships.
/// </summary>
public class UserEffectivePolicyResult
{
    public string Upn { get; set; } = string.Empty;
    public Dictionary<string, object> UserMandatory { get; set; } = new();
    public Dictionary<string, object> UserRecommended { get; set; } = new();
    public string UserHash { get; set; } = string.Empty;
    public List<AppliedAssignmentInfo> AppliedAssignments { get; set; } = new();
}

public class AppliedAssignmentInfo
{
    public Guid AssignmentId { get; set; }
    public string PolicySetName { get; set; } = string.Empty;
    public string Version { get; set; } = string.Empty;
    public int Priority { get; set; }
    public PolicyScope Scope { get; set; }
    public string GroupName { get; set; } = string.Empty;
}
