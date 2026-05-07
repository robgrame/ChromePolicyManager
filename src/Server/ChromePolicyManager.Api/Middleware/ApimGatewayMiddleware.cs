using Microsoft.Identity.Web;

namespace ChromePolicyManager.Api.Middleware;

/// <summary>
/// Middleware that enforces APIM managed identity authentication on device-facing endpoints.
/// Device endpoints (/api/devices/*) require requests to come through APIM,
/// validated by the APIM managed identity token.
/// Admin/management endpoints use standard Entra ID JWT auth directly.
/// </summary>
public class ApimGatewayMiddleware
{
    private readonly RequestDelegate _next;
    private readonly IConfiguration _configuration;
    private readonly ILogger<ApimGatewayMiddleware> _logger;

    // Paths that require APIM gateway authentication (device-facing)
    private static readonly string[] ProtectedDevicePaths = ["/api/devices"];

    // Paths exempt from gateway check (webhooks, health)
    private static readonly string[] ExemptPaths = ["/health", "/api/webhooks"];

    public ApimGatewayMiddleware(RequestDelegate next, IConfiguration configuration, ILogger<ApimGatewayMiddleware> logger)
    {
        _next = next;
        _configuration = configuration;
        _logger = logger;
    }

    public async Task InvokeAsync(HttpContext context)
    {
        var path = context.Request.Path.Value ?? "";

        // Skip if not a device endpoint
        if (!IsDeviceEndpoint(path))
        {
            await _next(context);
            return;
        }

        // Skip if exempt
        if (IsExemptPath(path))
        {
            await _next(context);
            return;
        }

        // Validate APIM gateway identity
        var apimClientId = _configuration["ApimGateway:ClientId"];
        var apimPrincipalId = _configuration["ApimGateway:PrincipalId"];
        if (string.IsNullOrEmpty(apimClientId))
        {
            // APIM not configured — allow direct access (dev/test scenarios)
            _logger.LogWarning("APIM gateway not configured (ApimGateway:ClientId missing). Allowing direct access.");
            await _next(context);
            return;
        }

        // Verify the request comes from APIM managed identity.
        // Check azp (v2) / appid (v1) for client app ID, with oid/sub fallback for principal ID.
        var isApimIdentity = false;
        var appId = context.User?.FindFirst("azp")?.Value
                    ?? context.User?.FindFirst("appid")?.Value;

        if (appId == apimClientId)
        {
            isApimIdentity = true;
        }
        else if (!string.IsNullOrEmpty(apimPrincipalId))
        {
            // Fallback: match by service principal object ID (oid/sub)
            var oid = context.User?.FindFirst("oid")?.Value
                      ?? context.User?.FindFirst("http://schemas.microsoft.com/identity/claims/objectidentifier")?.Value;
            var sub = context.User?.FindFirst("sub")?.Value
                      ?? context.User?.FindFirst("http://schemas.xmlsoap.org/ws/2005/05/identity/claims/nameidentifier")?.Value;

            if (oid == apimPrincipalId || sub == apimPrincipalId)
            {
                isApimIdentity = true;
            }
        }

        if (!isApimIdentity)
        {
            _logger.LogWarning(
                "Device endpoint called without valid APIM identity. Path: {Path}, IsAuthenticated: {IsAuth}",
                path, context.User?.Identity?.IsAuthenticated ?? false);

            context.Response.StatusCode = StatusCodes.Status403Forbidden;
            await context.Response.WriteAsJsonAsync(new
            {
                Error = "Forbidden",
                Message = "Device endpoints must be accessed through the API Gateway"
            });
            return;
        }

        // APIM forwards trusted device identity extracted from the validated device JWT
        var forwardedDeviceId = context.Request.Headers["X-Forwarded-Device-Id"].FirstOrDefault();
        if (!string.IsNullOrEmpty(forwardedDeviceId))
        {
            context.Items["TrustedDeviceId"] = forwardedDeviceId;
        }

        _logger.LogDebug("APIM gateway validated for device endpoint: {Path}", path);
        await _next(context);
    }

    private static bool IsDeviceEndpoint(string path) =>
        ProtectedDevicePaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase));

    private static bool IsExemptPath(string path) =>
        ExemptPaths.Any(p => path.StartsWith(p, StringComparison.OrdinalIgnoreCase));
}

/// <summary>
/// Extension methods for APIM gateway middleware registration.
/// </summary>
public static class ApimGatewayMiddlewareExtensions
{
    public static IApplicationBuilder UseApimGateway(this IApplicationBuilder app)
    {
        return app.UseMiddleware<ApimGatewayMiddleware>();
    }
}
