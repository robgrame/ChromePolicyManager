using Microsoft.AspNetCore.Mvc;
using ChromePolicyManager.Api.Services;

namespace ChromePolicyManager.Api.Endpoints;

public static class DeviceEndpoints
{
    public static void MapDeviceEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/devices").WithTags("Devices");

        // Get effective policy for a device (server-side resolution)
        group.MapGet("/{deviceId}/effective-policy", async (string deviceId, EffectivePolicyService service) =>
        {
            var result = await service.GetEffectivePolicyAsync(deviceId);
            return Results.Ok(result);
        }).WithName("GetEffectivePolicy");

        // Device reports compliance status
        group.MapPost("/{deviceId}/report", async (string deviceId, [FromBody] DeviceReportRequest request,
            DeviceReportingService service) =>
        {
            if (request.DeviceId != deviceId)
                return Results.BadRequest("DeviceId in URL must match body");

            var report = await service.SubmitReportAsync(request);
            return Results.Ok(new { ReportId = report.Id, Received = report.ReportedAt });
        }).WithName("SubmitDeviceReport");

        // Get device compliance history
        group.MapGet("/{deviceId}/history", async (string deviceId, DeviceReportingService service, int? count) =>
        {
            var history = await service.GetDeviceHistoryAsync(deviceId, count ?? 20);
            return Results.Ok(history);
        }).WithName("GetDeviceHistory");
    }
}
