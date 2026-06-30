namespace ChromePolicyManager.Api.Models;

public class PolicyAssignment
{
    public Guid Id { get; set; } = Guid.NewGuid();
    public Guid PolicySetVersionId { get; set; }
    public string EntraGroupId { get; set; } = string.Empty;
    public string GroupName { get; set; } = string.Empty;
    public int Priority { get; set; } = 100; // Lower number = higher priority
    public PolicyScope Scope { get; set; } = PolicyScope.Mandatory;
    public PolicyTarget Target { get; set; } = PolicyTarget.Machine;
    public bool Enabled { get; set; } = true;
    public bool PushRemediationEnabled { get; set; } = false;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
    public string? CreatedBy { get; set; }

    public PolicySetVersion PolicySetVersion { get; set; } = null!;
}

public enum PolicyScope
{
    Mandatory,   // ...\Policies\Google\Chrome
    Recommended  // ...\Policies\Google\Chrome\Recommended
}

/// <summary>
/// Registry hive the policy targets. Orthogonal to <see cref="PolicyScope"/>:
/// the (Target, Scope) pair selects one of four registry destinations.
/// </summary>
public enum PolicyTarget
{
    Machine = 0, // HKLM\SOFTWARE\Policies\Google\Chrome[\Recommended] — resolved by device groups
    User    = 1  // HKCU\SOFTWARE\Policies\Google\Chrome[\Recommended] — resolved by the signed-in user's groups
}
