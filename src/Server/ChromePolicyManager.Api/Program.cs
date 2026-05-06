using System.Text.Json.Serialization;
using Microsoft.EntityFrameworkCore;
using Microsoft.Identity.Web;
using Microsoft.Graph;
using Azure.Identity;
using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Services;
using ChromePolicyManager.Api.Endpoints;

var builder = WebApplication.CreateBuilder(args);

// Database - SQLite for development, SQL Server for production
if (builder.Environment.IsDevelopment())
{
    builder.Services.AddDbContext<AppDbContext>(options =>
        options.UseSqlite("Data Source=chromepolicymanager.db"));
}
else
{
    builder.Services.AddDbContext<AppDbContext>(options =>
        options.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection")));
}

// Microsoft Identity / Auth
builder.Services.AddMicrosoftIdentityWebApiAuthentication(builder.Configuration, "AzureAd");

// Microsoft Graph client
builder.Services.AddSingleton(sp =>
{
    var config = builder.Configuration.GetSection("AzureAd");
    var credential = new ClientSecretCredential(
        config["TenantId"],
        config["ClientId"],
        config["ClientSecret"]);
    return new GraphServiceClient(credential, new[] { "https://graph.microsoft.com/.default" });
});

// Application services
builder.Services.AddScoped<AuditService>();
builder.Services.AddScoped<PolicyService>();
builder.Services.AddScoped<AssignmentService>();
builder.Services.AddScoped<EffectivePolicyService>();
builder.Services.AddScoped<DeviceReportingService>();
builder.Services.AddScoped<IGraphService, GraphService>();
builder.Services.AddSingleton<ChromePolicyValidator>();
builder.Services.AddSingleton<AdmxParserService>();

// Service Bus - async device report processing
builder.Services.AddSingleton<DeviceReportQueue>();
builder.Services.AddHostedService<DeviceReportProcessor>();

// OpenAPI / Swagger
builder.Services.AddOpenApi();

// JSON serialization - handle EF Core circular references
builder.Services.ConfigureHttpJsonOptions(options =>
{
    options.SerializerOptions.ReferenceHandler = ReferenceHandler.IgnoreCycles;
    options.SerializerOptions.DefaultIgnoreCondition = JsonIgnoreCondition.WhenWritingNull;
});

// CORS for management UI
builder.Services.AddCors(options =>
{
    options.AddPolicy("AllowManagementUI", policy =>
        policy.WithOrigins(builder.Configuration.GetSection("Cors:Origins").Get<string[]>() ?? Array.Empty<string>())
            .AllowAnyMethod()
            .AllowAnyHeader());
});

var app = builder.Build();

// Auto-migrate database in development
if (app.Environment.IsDevelopment())
{
    using var scope = app.Services.CreateScope();
    var db = scope.ServiceProvider.GetRequiredService<AppDbContext>();
    db.Database.EnsureCreated();
}

if (app.Environment.IsDevelopment())
{
    app.MapOpenApi();
}

app.UseHttpsRedirection();
app.UseCors("AllowManagementUI");

// Map API endpoints
app.MapPolicyEndpoints();
app.MapAssignmentEndpoints();
app.MapDeviceEndpoints();
app.MapMonitoringEndpoints();
app.MapCatalogEndpoints();

// Health check
app.MapGet("/health", () => Results.Ok(new { Status = "Healthy", Timestamp = DateTime.UtcNow }))
    .WithName("HealthCheck")
    .WithTags("System");

app.Run();
