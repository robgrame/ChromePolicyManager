using Microsoft.Graph;
using Microsoft.Graph.Models;

namespace ChromePolicyManager.Api.Services;

/// <summary>
/// Microsoft Graph implementation for resolving device group memberships.
/// </summary>
public class GraphService : IGraphService
{
    private readonly GraphServiceClient _graphClient;
    private readonly ILogger<GraphService> _logger;

    public GraphService(GraphServiceClient graphClient, ILogger<GraphService> logger)
    {
        _graphClient = graphClient;
        _logger = logger;
    }

    public async Task<List<string>> GetDeviceGroupMembershipsAsync(string deviceId)
    {
        try
        {
            var memberOf = await _graphClient.Devices[deviceId].MemberOf.GetAsync();
            var groupIds = new List<string>();

            if (memberOf?.Value != null)
            {
                foreach (var obj in memberOf.Value)
                {
                    if (obj is Group group && group.Id != null)
                    {
                        groupIds.Add(group.Id);
                    }
                }
            }

            // Handle pagination
            var pageIterator = PageIterator<DirectoryObject, DirectoryObjectCollectionResponse>
                .CreatePageIterator(_graphClient, memberOf!, (item) =>
                {
                    if (item is Group g && g.Id != null)
                        groupIds.Add(g.Id);
                    return true;
                });
            await pageIterator.IterateAsync();

            _logger.LogInformation("Device {DeviceId} is member of {Count} groups", deviceId, groupIds.Count);
            return groupIds.Distinct().ToList();
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to resolve group memberships for device {DeviceId}", deviceId);
            return new List<string>();
        }
    }
}
