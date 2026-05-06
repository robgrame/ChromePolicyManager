using ChromePolicyManager.Api.Services;

namespace ChromePolicyManager.Api.Endpoints;

public static class MonitoringEndpoints
{
    public static void MapMonitoringEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/monitoring").WithTags("Monitoring");

        group.MapGet("/dashboard", async (DeviceReportingService service) =>
        {
            var dashboard = await service.GetDashboardAsync();
            return Results.Ok(dashboard);
        }).WithName("GetDashboard");

        group.MapGet("/offline-devices", async (DeviceReportingService service, int? hoursThreshold) =>
        {
            var devices = await service.GetOfflineDevicesAsync(hoursThreshold ?? 24);
            return Results.Ok(devices);
        }).WithName("GetOfflineDevices");

        group.MapGet("/error-devices", async (DeviceReportingService service) =>
        {
            var devices = await service.GetDevicesWithErrorsAsync();
            return Results.Ok(devices);
        }).WithName("GetErrorDevices");
    }
}
