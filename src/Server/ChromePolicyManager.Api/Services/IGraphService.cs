namespace ChromePolicyManager.Api.Services;

/// <summary>
/// Interface for Microsoft Graph operations. Allows mocking in tests.
/// </summary>
public interface IGraphService
{
    /// <summary>
    /// Get the Entra ID group memberships for a device (server-side, trusted).
    /// </summary>
    Task<List<string>> GetDeviceGroupMembershipsAsync(string deviceId);
}
