using Microsoft.AspNetCore.Mvc;
using ChromePolicyManager.Api.Services;

namespace ChromePolicyManager.Api.Endpoints;

public static class DeviceEndpoints
{
    public static void MapDeviceEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/devices").WithTags("Devices");

        // Get effective policy for a device (server-side resolution) - synchronous
        group.MapGet("/{deviceId}/effective-policy", async (string deviceId, EffectivePolicyService service) =>
        {
            var result = await service.GetEffectivePolicyAsync(deviceId);
            return Results.Ok(result);
        }).WithName("GetEffectivePolicy");

        // Device reports compliance status - async via Service Bus when available
        group.MapPost("/{deviceId}/report", async (string deviceId, [FromBody] DeviceReportRequest request,
            DeviceReportQueue queue, DeviceReportingService service) =>
        {
            if (request.DeviceId != deviceId)
                return Results.BadRequest("DeviceId in URL must match body");

            // Try async processing via Service Bus
            var enqueued = await queue.EnqueueReportAsync(request);
            if (enqueued)
            {
                return Results.Accepted(value: new { Status = "Accepted", Message = "Report queued for processing" });
            }

            // Fallback: process synchronously if Service Bus not configured
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
