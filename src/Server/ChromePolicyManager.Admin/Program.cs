using System.Security.Claims;
using Azure.Monitor.OpenTelemetry.AspNetCore;
using ChromePolicyManager.Admin.Components;
using ChromePolicyManager.Admin.Services;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.OpenIdConnect;
using Microsoft.AspNetCore.Authorization;
using Microsoft.Identity.Web;
using Microsoft.Identity.Web.UI;

var builder = WebApplication.CreateBuilder(args);

// Application Insights via OpenTelemetry
builder.Services.AddOpenTelemetry().UseAzureMonitor();

// ============================================================
// Authentication - Entra ID (Microsoft Entra) via OpenID Connect.
// The whole portal is gated: every page requires an authenticated user
// holding at least one PolicyManager.* app role (see FallbackPolicy below).
// ============================================================
builder.Services.AddAuthentication(OpenIdConnectDefaults.AuthenticationScheme)
    .AddMicrosoftIdentityWebApp(builder.Configuration.GetSection("AzureAd"));

// When an unauthenticated user hits a protected endpoint, or an authenticated
// user lacks the required role, route them to the friendly /access-denied page
// (which is [AllowAnonymous]) instead of an opaque redirect or a raw 403.
builder.Services.Configure<CookieAuthenticationOptions>(
    CookieAuthenticationDefaults.AuthenticationScheme, o =>
    {
        o.AccessDeniedPath = "/access-denied";
        o.LoginPath = "/access-denied";
    });
// Route implicit challenges through the cookie scheme so unauthenticated users
// land on the courtesy page (with an explicit "Accedi" button) rather than
// being auto-redirected to Entra.
builder.Services.Configure<AuthenticationOptions>(o =>
{
    o.DefaultChallengeScheme = CookieAuthenticationDefaults.AuthenticationScheme;
});

// App-role names defined on the cpm-dev-admin app registration.
string[] readRoles =
{
    "PolicyManager.Administrator",
    "PolicyManager.Operator",
    "PolicyManager.Reader"
};
static bool HasRole(ClaimsPrincipal user, string role) => user.Claims.Any(c =>
    (c.Type == "roles" || c.Type == "role" || c.Type == ClaimTypes.Role) &&
    string.Equals(c.Value, role, StringComparison.OrdinalIgnoreCase));

builder.Services.AddAuthorization(options =>
{
    // Any role grants read access to the portal.
    options.AddPolicy("CanRead", p => p
        .RequireAuthenticatedUser()
        .RequireAssertion(ctx => readRoles.Any(r => HasRole(ctx.User, r))));

    // Administrator-only: create/edit/delete policies, versions, assignments.
    options.AddPolicy("CanWrite", p => p
        .RequireAuthenticatedUser()
        .RequireAssertion(ctx => HasRole(ctx.User, "PolicyManager.Administrator")));

    // Administrator or Operator: trigger device remediation.
    options.AddPolicy("CanOperate", p => p
        .RequireAuthenticatedUser()
        .RequireAssertion(ctx =>
            HasRole(ctx.User, "PolicyManager.Administrator") ||
            HasRole(ctx.User, "PolicyManager.Operator")));

    // Gate the entire portal: unauthenticated or role-less users are kicked out.
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .RequireAssertion(ctx => readRoles.Any(r => HasRole(ctx.User, r)))
        .Build();
});

// Add services
builder.Services.AddRazorComponents()
    .AddInteractiveServerComponents();

// MVC controllers host the Microsoft.Identity.Web sign-in/sign-out callbacks.
builder.Services.AddControllersWithViews()
    .AddMicrosoftIdentityUI();

// Flow the authentication state to Blazor components (AuthorizeView, etc.).
builder.Services.AddCascadingAuthenticationState();

// UI notification + confirmation services (Bootstrap-based, replaces MudBlazor)
builder.Services.AddScoped<ToastService>();
builder.Services.AddScoped<ConfirmService>();

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

app.UseAuthentication();
app.UseAuthorization();
app.UseAntiforgery();

app.MapStaticAssets();
app.MapControllers(); // Microsoft.Identity.Web sign-in/out callbacks
app.MapRazorComponents<App>()
    .AddInteractiveServerRenderMode();

app.Run();
