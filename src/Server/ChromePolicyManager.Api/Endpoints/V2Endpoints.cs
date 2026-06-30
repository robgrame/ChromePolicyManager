using ChromePolicyManager.Api.Services;

namespace ChromePolicyManager.Api.Endpoints;

/// <summary>
/// v2 effective-policy contract (ADR-002): machine policies (HKLM) and user policies (HKCU)
/// are served by dedicated, independently-cacheable endpoints with separate ETags.
/// </summary>
public static class V2Endpoints
{
    public static void MapV2Endpoints(this WebApplication app)
    {
        // ----- Machine (HKLM) -----
        var devices = app.MapGroup("/api/v2/devices").WithTags("Devices (v2)");

        // Machine-scoped effective policy: Target=Machine assignments resolved by device groups.
        devices.MapGet("/{deviceId}/effective-policy", async (string deviceId, HttpContext httpContext, EffectivePolicyService service) =>
        {
            var result = await service.GetEffectivePolicyAsync(deviceId);
            var etag = $"\"{result.Hash}\"";

            var ifNoneMatch = httpContext.Request.Headers.IfNoneMatch.FirstOrDefault();
            if (!string.IsNullOrEmpty(ifNoneMatch) && ifNoneMatch == etag)
            {
                httpContext.Response.Headers.ETag = etag;
                return Results.StatusCode(304);
            }

            httpContext.Response.Headers.ETag = etag;
            httpContext.Response.Headers.CacheControl = "no-cache";
            return Results.Ok(new DeviceEffectivePolicyV2
            {
                DeviceId = result.DeviceId,
                MachineMandatory = result.MandatoryPolicies,
                MachineRecommended = result.RecommendedPolicies,
                MachineHash = result.Hash,
                AppliedAssignments = result.AppliedAssignments
            });
        }).WithName("GetMachineEffectivePolicyV2");

        // ----- User (HKCU) -----
        var users = app.MapGroup("/api/v2/users").WithTags("Users (v2)");

        // User-scoped effective policy: Target=User assignments resolved by the user's groups.
        // Optional deviceId is logged for device↔user correlation (anti-spoofing, ADR-002 §8).
        users.MapGet("/{upn}/effective-policy", async (string upn, string? deviceId, HttpContext httpContext,
            EffectivePolicyService service, ILoggerFactory loggerFactory) =>
        {
            var logger = loggerFactory.CreateLogger("V2.UserEffectivePolicy");
            logger.LogInformation("User effective-policy requested for {Upn} (deviceId={DeviceId})", upn, deviceId ?? "n/a");

            var result = await service.GetUserEffectivePolicyAsync(upn);
            var etag = $"\"{result.UserHash}\"";

            var ifNoneMatch = httpContext.Request.Headers.IfNoneMatch.FirstOrDefault();
            if (!string.IsNullOrEmpty(ifNoneMatch) && ifNoneMatch == etag)
            {
                httpContext.Response.Headers.ETag = etag;
                return Results.StatusCode(304);
            }

            httpContext.Response.Headers.ETag = etag;
            httpContext.Response.Headers.CacheControl = "no-cache";
            return Results.Ok(result);
        }).WithName("GetUserEffectivePolicyV2");

        // User compliance ingestion (per device,user) — ADR-002 §7.
        users.MapPost("/{upn}/report", async (string upn, UserPolicyReportRequest request,
            DeviceReportingService service) =>
        {
            if (string.IsNullOrWhiteSpace(request.UserPrincipalName))
                request.UserPrincipalName = upn;
            else if (!string.Equals(request.UserPrincipalName, upn, StringComparison.OrdinalIgnoreCase))
                return Results.BadRequest("UPN in URL must match body");

            var report = await service.SubmitUserReportAsync(request);
            return Results.Ok(new { ReportId = report.Id, Received = report.ReportedAt });
        }).WithName("SubmitUserReportV2");

        // Per-user compliance history.
        users.MapGet("/{upn}/history", async (string upn, DeviceReportingService service, int? count) =>
        {
            var history = await service.GetUserHistoryAsync(upn, count ?? 20);
            return Results.Ok(history);
        }).WithName("GetUserHistoryV2");

        // Dashboard: latest user-policy state per (device,user).
        users.MapGet("/states", async (DeviceReportingService service) =>
        {
            var states = await service.GetUserStatesAsync();
            return Results.Ok(states);
        }).WithName("GetUserStatesV2");
    }
}

/// <summary>v2 machine-scoped effective policy (HKLM).</summary>
public class DeviceEffectivePolicyV2
{
    public string DeviceId { get; set; } = string.Empty;
    public Dictionary<string, object> MachineMandatory { get; set; } = new();
    public Dictionary<string, object> MachineRecommended { get; set; } = new();
    public string MachineHash { get; set; } = string.Empty;
    public List<AppliedAssignmentInfo> AppliedAssignments { get; set; } = new();
}
