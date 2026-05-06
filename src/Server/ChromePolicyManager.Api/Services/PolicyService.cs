using System.Security.Cryptography;
using System.Text;
using System.Text.Json;
using Microsoft.EntityFrameworkCore;
using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Models;

namespace ChromePolicyManager.Api.Services;

public class PolicyService
{
    private readonly AppDbContext _db;
    private readonly AuditService _audit;

    public PolicyService(AppDbContext db, AuditService audit)
    {
        _db = db;
        _audit = audit;
    }

    public async Task<PolicySet> CreatePolicySetAsync(string name, string description, string? actor = null)
    {
        var policySet = new PolicySet { Name = name, Description = description };
        _db.PolicySets.Add(policySet);
        await _db.SaveChangesAsync();
        await _audit.LogAsync("PolicySet.Created", actor, "PolicySet", policySet.Id.ToString(), $"Name: {name}");
        return policySet;
    }

    public async Task<List<PolicySet>> GetAllPolicySetsAsync()
    {
        return await _db.PolicySets
            .Include(p => p.Versions)
            .OrderBy(p => p.Name)
            .ToListAsync();
    }

    public async Task<PolicySet?> GetPolicySetAsync(Guid id)
    {
        return await _db.PolicySets
            .Include(p => p.Versions.OrderByDescending(v => v.CreatedAt))
            .FirstOrDefaultAsync(p => p.Id == id);
    }

    public async Task<PolicySetVersion> CreateVersionAsync(Guid policySetId, string version, string settingsJson, string? actor = null)
    {
        var hash = ComputeHash(settingsJson);
        var policyVersion = new PolicySetVersion
        {
            PolicySetId = policySetId,
            Version = version,
            SettingsJson = settingsJson,
            Hash = hash,
            Status = PolicyVersionStatus.Draft,
            CreatedBy = actor
        };
        _db.PolicySetVersions.Add(policyVersion);
        await _db.SaveChangesAsync();
        await _audit.LogAsync("PolicyVersion.Created", actor, "PolicySetVersion", policyVersion.Id.ToString(),
            $"Version: {version}, Hash: {hash}");
        return policyVersion;
    }

    public async Task<PolicySetVersion?> PromoteVersionAsync(Guid versionId, string? actor = null)
    {
        var version = await _db.PolicySetVersions.FindAsync(versionId);
        if (version == null) return null;

        // Archive any currently active version for this policy set
        var currentActive = await _db.PolicySetVersions
            .Where(v => v.PolicySetId == version.PolicySetId && v.Status == PolicyVersionStatus.Active)
            .ToListAsync();

        foreach (var active in currentActive)
        {
            active.Status = PolicyVersionStatus.Archived;
        }

        version.Status = PolicyVersionStatus.Active;
        await _db.SaveChangesAsync();
        await _audit.LogAsync("PolicyVersion.Promoted", actor, "PolicySetVersion", versionId.ToString(),
            $"Version {version.Version} promoted to Active");
        return version;
    }

    public async Task<PolicySetVersion?> RollbackVersionAsync(Guid policySetId, Guid targetVersionId, string? actor = null)
    {
        var target = await _db.PolicySetVersions.FindAsync(targetVersionId);
        if (target == null || target.PolicySetId != policySetId) return null;

        // Archive current active
        var currentActive = await _db.PolicySetVersions
            .Where(v => v.PolicySetId == policySetId && v.Status == PolicyVersionStatus.Active)
            .ToListAsync();
        foreach (var active in currentActive) active.Status = PolicyVersionStatus.Archived;

        target.Status = PolicyVersionStatus.Active;
        await _db.SaveChangesAsync();
        await _audit.LogAsync("PolicyVersion.Rollback", actor, "PolicySetVersion", targetVersionId.ToString(),
            $"Rolled back to version {target.Version}");
        return target;
    }

    private static string ComputeHash(string content)
    {
        var bytes = SHA256.HashData(Encoding.UTF8.GetBytes(content));
        return Convert.ToHexStringLower(bytes);
    }
}
