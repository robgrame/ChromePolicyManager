using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Identity.Web;
using Microsoft.Graph;
using Azure.Identity;
using Azure.Monitor.OpenTelemetry.AspNetCore;
using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Services;
using ChromePolicyManager.Api.Endpoints;
using ChromePolicyManager.Api.Middleware;


var builder = WebApplication.CreateBuilder(args);

// Application Insights via OpenTelemetry
builder.Services.AddOpenTelemetry().UseAzureMonitor();

// Database - SQL Server when connection string is configured, SQLite as fallback for local dev
var sqlConnectionString = builder.Configuration.GetConnectionString("DefaultConnection");
if (!string.IsNullOrEmpty(sqlConnectionString))
{
    builder.Services.AddDbContext<AppDbContext>(options =>
        options.UseSqlServer(sqlConnectionString));
}
else
{
    builder.Services.AddDbContext<AppDbContext>(options =>
        options.UseSqlite("Data Source=chromepolicymanager.db"));
}

// Microsoft Identity / Auth — accept both v1 and v2 tokens from MI and interactive flows
var tenantId = builder.Configuration["AzureAd:TenantId"];
var clientId = builder.Configuration["AzureAd:ClientId"];
builder.Services.AddMicrosoftIdentityWebApiAuthentication(builder.Configuration, "AzureAd");
// PostConfigure runs AFTER Microsoft.Identity.Web's PostConfigure, ensuring our overrides stick
builder.Services.PostConfigure<Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerOptions>(
    Microsoft.AspNetCore.Authentication.JwtBearer.JwtBearerDefaults.AuthenticationScheme,
    options =>
    {
        // Accept both v1 and v2 issuers (MI tokens may use either)
        options.TokenValidationParameters.ValidIssuers = new[]
        {
            $"https://sts.windows.net/{tenantId}/",
            $"https://login.microsoftonline.com/{tenantId}/v2.0"
        };
        // Accept both audience formats: v2 tokens use bare clientId, v1 use Application ID URI
        options.TokenValidationParameters.ValidAudiences = new[]
        {
            clientId,
            $"api://{clientId}"
        };
    });

// Microsoft Graph client (uses Managed Identity in Azure, falls back to CLI locally)
builder.Services.AddSingleton(sp =>
{
    var credential = new DefaultAzureCredential();
    return new GraphServiceClient(credential, new[] { "https://graph.microsoft.com/.default" });
});

// Application services
builder.Services.AddScoped<AuditService>();
builder.Services.AddScoped<PolicyService>();
builder.Services.AddScoped<AssignmentService>();
builder.Services.AddScoped<PushRemediationService>();
builder.Services.AddScoped<EffectivePolicyService>();
builder.Services.AddScoped<DeviceReportingService>();
builder.Services.AddScoped<IGraphService, GraphService>();
builder.Services.AddSingleton<ChromePolicyValidator>();
builder.Services.AddSingleton<AdmxParserService>();
builder.Services.AddHttpClient(); // For ADMX download from Google

// Service Bus - async device report processing
builder.Services.AddSingleton<DeviceReportQueue>();
builder.Services.AddHostedService<DeviceReportProcessor>();

// Graph change notifications - webhook subscription management
builder.Services.AddHostedService<GroupChangeNotificationService>();

// OpenAPI / Swagger
builder.Services.AddOpenApi();

// JSON serialization - handle EF Core circular references
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
    options.SerializerOptions.Converters.Add(new JsonStringEnumConverter());
});

// CORS for management UI
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowManagementUI", policy =>
        policy.WithOrigins(builder.Configuration.GetSection("Cors:Origins").Get<string[]>() ?? Array.Empty<string>())
            .AllowAnyMethod()
            .AllowAnyHeader());
});

// Increase request size limit for ADMX zip upload
builder.WebHost.ConfigureKestrel(options =>
{
    options.Limits.MaxRequestBodySize = 200 * 1024 * 1024; // 200MB
});

var app = builder.Build();

// Auto-migrate database schema additions
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    if (app.Environment.IsDevelopment())
    {
        db.Database.EnsureCreated();
    }
    // Add columns that may not exist yet (idempotent)
    try
    {
        await db.Database.ExecuteSqlRawAsync(@"
            IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('DeviceStates') AND name = 'ScriptVersion')
                ALTER TABLE DeviceStates ADD ScriptVersion NVARCHAR(50) NULL;
            IF NOT EXISTS (SELECT 1 FROM sys.columns WHERE object_id = OBJECT_ID('DeviceReports') AND name = 'ScriptVersion')
                ALTER TABLE DeviceReports ADD ScriptVersion NVARCHAR(50) NULL;
        ");
    }
    catch { /* Column may already exist or DB not ready */ }
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseCors("AllowManagementUI");
app.UseAuthentication();
app.UseAuthorization();

// APIM gateway enforcement: device endpoints require APIM managed identity
app.UseApimGateway();

// Map API endpoints
app.MapPolicyEndpoints();
app.MapAssignmentEndpoints();
app.MapDeviceEndpoints();
app.MapMonitoringEndpoints();
app.MapCatalogEndpoints();
app.MapWebhookEndpoints();

// Health check
app.MapGet("/health", () => Results.Ok(new { Status = "Healthy", Timestamp = DateTime.UtcNow }))
    .WithName("HealthCheck")
    .WithTags("System");

app.Run();
