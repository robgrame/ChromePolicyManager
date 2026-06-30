namespace ChromePolicyManager.Api.Models;

/// <summary>
/// Compliance report for user-level (HKCU) Chrome policy application (ADR-002 §7).
/// Granularity is per (device, user): the same device can host multiple interactive
/// sessions, each receiving its own user-targeted policy set.
/// </summary>
public class UserPolicyReport
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public string DeviceId { get; set; } = string.Empty;          // Entra device ID (host)
    public string UserPrincipalName { get; set; } = string.Empty; // logged-on user
    public string AppliedPolicyHash { get; set; } = string.Empty; // userHash
    public DeviceComplianceStatus Status { get; set; }
    public string? Errors { get; set; }
    public int? PolicyKeysWritten { get; set; }
    public int? PolicyKeysRemoved { get; set; }
    public string? AzureAdPrt { get; set; }                       // dsregcmd correlation (ADR-002 §8)
    public DateTime ReportedAt { get; set; } = DateTime.UtcNow;
}

/// <summary>Latest user-policy state per (device, user) pair.</summary>
public class UserPolicyState
{
    public string DeviceId { get; set; } = string.Empty;
    public string UserPrincipalName { get; set; } = string.Empty;
    public string? LastAppliedPolicyHash { get; set; }
    public DeviceComplianceStatus LastStatus { get; set; }
    public DateTime? LastCheckIn { get; set; }
    public string? LastError { get; set; }
    public int? PolicyKeysWritten { get; set; }
    public int? PolicyKeysRemoved { get; set; }
    public bool IsOffline => LastCheckIn.HasValue && DateTime.UtcNow - LastCheckIn.Value > TimeSpan.FromHours(24);
}
