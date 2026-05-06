using ChromePolicyManager.Admin.Components;
using ChromePolicyManager.Admin.Services;
using MudBlazor.Services;

var builder = WebApplication.CreateBuilder(args);

// Add services
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

builder.Services.AddMudServices();

// Increase SignalR message size for large file uploads (ADMX zip ~113MB)
builder.Services.AddSignalR(options =>
{
    options.MaximumReceiveMessageSize = 200 * 1024 * 1024; // 200MB
});

// API client with extended timeout for large file uploads (ADMX zip ~113MB)
var apiBaseUrl = builder.Configuration["ApiBaseUrl"] ?? "https://cpm-dev-api.azurewebsites.net";
builder.Services.AddHttpClient<PolicyApiClient>(client =>
{
    client.BaseAddress = new Uri(apiBaseUrl);
    client.DefaultRequestHeaders.Add("Accept", "application/json");
    client.Timeout = TimeSpan.FromMinutes(10); // ADMX upload can be slow
});

var app = builder.Build();

if (!app.Environment.IsDevelopment())
{
    app.UseExceptionHandler("/Error", createScopeForErrors: true);
    app.UseHsts();
}

app.UseHttpsRedirection();
app.UseAntiforgery();

app.MapStaticAssets();
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
