using System.IO.Compression;
using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Models;
using ChromePolicyManager.Api.Services;
using Microsoft.EntityFrameworkCore;

namespace ChromePolicyManager.Api.Endpoints;

public static class CatalogEndpoints
{
    public static void MapCatalogEndpoints(this WebApplication app)
    {
        var group = app.MapGroup("/api/catalog").WithTags("Policy Catalog");

        // GET /api/catalog - Get all catalog entries (lightweight, no description/enum)
        // Defaults to the Active ADMX template; pass ?version=X to query a specific imported version.
        group.MapGet("/", async (AppDbContext db, AdmxCatalogService catalog, string? version, string? category, string? dataType, string? search, bool? recommended) =>
        {
            var templateId = await catalog.ResolveTemplateIdAsync(version);
            if (templateId is null) return Results.Ok(Array.Empty<object>());

            var query = db.PolicyCatalog.Where(e => e.AdmxTemplateId == templateId.Value);

            if (!string.IsNullOrEmpty(category))
                query = query.Where(e => e.Category == category);

            if (!string.IsNullOrEmpty(dataType))
                query = query.Where(e => e.DataType == dataType);

            if (recommended.HasValue)
                query = query.Where(e => e.IsRecommended == recommended.Value);

            if (!string.IsNullOrEmpty(search))
                query = query.Where(e =>
                    e.Name.Contains(search) ||
                    e.DisplayName.Contains(search) ||
                    e.Description.Contains(search));

            var entries = await query
                .OrderBy(e => e.Category).ThenBy(e => e.Name)
                .Select(e => new
                {
                    e.Id, e.Name, e.DisplayName, e.Category,
                    e.DataType, e.IsRecommended, e.PolicyClass,
                    e.RegistryKey, e.RegistryValueName, e.TemplateVersion
                })
                .ToListAsync();
            return Results.Ok(entries);
        }).WithName("GetCatalog");

        // GET /api/catalog/{id} - Get full details for a single policy
        group.MapGet("/{id:guid}", async (AppDbContext db, Guid id) =>
        {
            var entry = await db.PolicyCatalog.FindAsync(id);
            return entry is not null ? Results.Ok(entry) : Results.NotFound();
        }).WithName("GetCatalogEntry");

        // GET /api/catalog/categories - Get distinct categories (for the Active template)
        group.MapGet("/categories", async (AppDbContext db, AdmxCatalogService catalog, string? version) =>
        {
            var templateId = await catalog.ResolveTemplateIdAsync(version);
            if (templateId is null) return Results.Ok(Array.Empty<string>());

            var categories = await db.PolicyCatalog
                .Where(e => e.AdmxTemplateId == templateId.Value && !e.IsRecommended)
                .Select(e => e.Category)
                .Distinct()
                .OrderBy(c => c)
                .ToListAsync();
            return Results.Ok(categories);
        }).WithName("GetCatalogCategories");


        // GET /api/catalog/stats - Import statistics (for the Active template)
        group.MapGet("/stats", async (AppDbContext db, AdmxCatalogService catalog) =>
        {
            var active = await catalog.GetActiveTemplateAsync();
            if (active is null)
            {
                return Results.Ok(new
                {
                    TotalEntries = 0,
                    MandatoryPolicies = 0,
                    RecommendedPolicies = 0,
                    Categories = 0,
                    TemplateVersion = "none",
                    LastImport = (DateTime?)null
                });
            }

            return Results.Ok(new
            {
                TotalEntries = active.PolicyCount,
                MandatoryPolicies = active.MandatoryCount,
                RecommendedPolicies = active.RecommendedCount,
                Categories = active.CategoryCount,
                TemplateVersion = active.Version,
                LastImport = (DateTime?)active.ImportedAt
            });
        }).WithName("GetCatalogStats");

        // GET /api/catalog/templates - List all imported ADMX template versions
        group.MapGet("/templates", async (AppDbContext db) =>
        {
            var templates = await db.AdmxTemplates
                .OrderByDescending(t => t.Status == AdmxTemplateStatus.Active)
                .ThenByDescending(t => t.ImportedAt)
                .Select(t => new
                {
                    t.Id, t.Version, t.DisplayName, t.Source,
                    Status = t.Status.ToString(),
                    t.PolicyCount, t.MandatoryCount, t.RecommendedCount, t.CategoryCount,
                    t.ImportedAt, t.Notes
                })
                .ToListAsync();
            return Results.Ok(templates);
        }).WithName("GetAdmxTemplates");

        // POST /api/catalog/templates/{id}/activate - Make this version the default for authoring
        group.MapPost("/templates/{id:guid}/activate", async (Guid id, AdmxCatalogService catalog) =>
        {
            var t = await catalog.ActivateAsync(id);
            return t is null ? Results.NotFound() : Results.Ok(new { t.Id, t.Version, Status = t.Status.ToString() });
        }).WithName("ActivateAdmxTemplate");

        // POST /api/catalog/templates/{id}/retire - Mark a non-active version as retired
        group.MapPost("/templates/{id:guid}/retire", async (Guid id, AdmxCatalogService catalog) =>
        {
            var (ok, error) = await catalog.RetireAsync(id);
            return ok ? Results.Ok() : Results.BadRequest(new { error });
        }).WithName("RetireAdmxTemplate");

        // DELETE /api/catalog/templates/{id} - Delete a version (guarded against Active + Draft refs)
        group.MapDelete("/templates/{id:guid}", async (Guid id, AdmxCatalogService catalog) =>
        {
            var (ok, error) = await catalog.DeleteAsync(id);
            return ok ? Results.NoContent() : Results.BadRequest(new { error });
        }).WithName("DeleteAdmxTemplate");

        // POST /api/catalog/import - Import from ADMX zip upload
        group.MapPost("/import", async (HttpRequest request, AppDbContext db, AdmxParserService parser, AdmxCatalogService catalog) =>
        {
            if (!request.HasFormContentType)
                return Results.BadRequest("Expected multipart/form-data with ADMX zip file");

            var form = await request.ReadFormAsync();
            var file = form.Files.GetFile("admxZip") ?? form.Files.FirstOrDefault();

            if (file is null || file.Length == 0)
                return Results.BadRequest("No file uploaded. Upload a zip containing chrome.admx + en-US/chrome.adml");

            var version = form["version"].FirstOrDefault() ?? "unknown";
            var activate = form["activate"].FirstOrDefault()?.Equals("true", StringComparison.OrdinalIgnoreCase) ?? false;

            using var zipStream = file.OpenReadStream();
            using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);

            // Find chrome.admx and chrome.adml in the zip
            var admxEntry = archive.Entries.FirstOrDefault(e =>
                e.FullName.EndsWith("chrome.admx", StringComparison.OrdinalIgnoreCase) &&
                !e.FullName.Contains("__MACOSX"));
            var admlEntry = archive.Entries.FirstOrDefault(e =>
                e.FullName.EndsWith("chrome.adml", StringComparison.OrdinalIgnoreCase) &&
                e.FullName.Contains("en-US", StringComparison.OrdinalIgnoreCase) &&
                !e.FullName.Contains("__MACOSX"));

            if (admxEntry is null)
                return Results.BadRequest("chrome.admx not found in zip");
            if (admlEntry is null)
                return Results.BadRequest("en-US/chrome.adml not found in zip");

            // Prefer the real version embedded in the zip's root VERSION file;
            // fall back to whatever the user typed in the "Version Label" field.
            var effectiveVersion = ResolveVersion(version, ExtractVersionFromArchive(archive));

            using var admxStream = admxEntry.Open();
            using var admlStream = admlEntry.Open();

            var result = parser.Parse(admxStream, admlStream, effectiveVersion);
            var importResult = await catalog.ImportAsync(result, "upload", activate);
            return Results.Ok(ToImportResponse(importResult));
        }).WithName("ImportCatalog")
        .DisableAntiforgery();

        // POST /api/catalog/import-from-url - Download ADMX directly from Google and import
        group.MapPost("/import-from-url", async (string? version, bool? activate, AppDbContext db, AdmxParserService parser, AdmxCatalogService catalog, IHttpClientFactory httpFactory) =>
        {
            var googleAdmxUrl = "https://dl.google.com/dl/edgedl/chrome/policy/policy_templates.zip";

            using var httpClient = httpFactory.CreateClient();
            httpClient.Timeout = TimeSpan.FromMinutes(5);

            HttpResponseMessage response;
            try
            {
                response = await httpClient.GetAsync(googleAdmxUrl);
                response.EnsureSuccessStatusCode();
            }
            catch (Exception ex)
            {
                return Results.Problem($"Failed to download from Google: {ex.Message}");
            }

            using var zipStream = await response.Content.ReadAsStreamAsync();
            using var archive = new ZipArchive(zipStream, ZipArchiveMode.Read);

            var admxEntry = archive.Entries.FirstOrDefault(e =>
                e.FullName.EndsWith("chrome.admx", StringComparison.OrdinalIgnoreCase) &&
                !e.FullName.Contains("__MACOSX"));
            var admlEntry = archive.Entries.FirstOrDefault(e =>
                e.FullName.EndsWith("chrome.adml", StringComparison.OrdinalIgnoreCase) &&
                e.FullName.Contains("en-US", StringComparison.OrdinalIgnoreCase) &&
                !e.FullName.Contains("__MACOSX"));

            if (admxEntry is null)
                return Results.BadRequest("chrome.admx not found in downloaded zip");
            if (admlEntry is null)
                return Results.BadRequest("en-US/chrome.adml not found in downloaded zip");

            using var admxStream = admxEntry.Open();
            using var admlStream = admlEntry.Open();

            // Prefer the real version embedded in the zip's root VERSION file.
            var effectiveVersion = ResolveVersion(version, ExtractVersionFromArchive(archive));

            var result = parser.Parse(admxStream, admlStream, effectiveVersion);
            var importResult = await catalog.ImportAsync(result, "url", activate ?? false);
            return Results.Ok(ToImportResponse(importResult));
        }).WithName("ImportCatalogFromUrl")
        .DisableAntiforgery();

        // POST /api/catalog/import-local - Import from server-local ADMX files (for CLI/automation)
        group.MapPost("/import-local", async (ImportLocalRequest request, AppDbContext db, AdmxParserService parser, AdmxCatalogService catalog) =>
        {
            if (!File.Exists(request.AdmxPath))
                return Results.BadRequest($"ADMX file not found: {request.AdmxPath}");
            if (!File.Exists(request.AdmlPath))
                return Results.BadRequest($"ADML file not found: {request.AdmlPath}");

            using var admxStream = File.OpenRead(request.AdmxPath);
            using var admlStream = File.OpenRead(request.AdmlPath);

            var result = parser.Parse(admxStream, admlStream, request.Version ?? "local");
            var importResult = await catalog.ImportAsync(result, "local", activate: true);
            return Results.Ok(ToImportResponse(importResult));
        }).WithName("ImportCatalogLocal");

        // GET /api/catalog/latest-available - Compare the imported catalog version
        // against the latest stable Chrome version published by Google, so the UI
        // can surface an "update available" hint and offer a one-click re-import.
        group.MapGet("/latest-available", async (AppDbContext db, AdmxCatalogService catalog, IHttpClientFactory httpFactory) =>
        {
            var active = await catalog.GetActiveTemplateAsync();
            var imported = active?.Version;

            string? latest = null;
            string? error = null;
            try
            {
                using var http = httpFactory.CreateClient();
                http.Timeout = TimeSpan.FromSeconds(20);
                // Chrome VersionHistory API — latest stable release for Windows.
                const string url = "https://versionhistory.googleapis.com/v1/chrome/platforms/win/channels/stable/versions?order_by=version%20desc&pageSize=1";
                using var doc = System.Text.Json.JsonDocument.Parse(await http.GetStringAsync(url));
                if (doc.RootElement.TryGetProperty("versions", out var versions) &&
                    versions.GetArrayLength() > 0 &&
                    versions[0].TryGetProperty("version", out var v))
                {
                    latest = v.GetString();
                }
            }
            catch (Exception ex)
            {
                error = ex.Message;
            }

            return Results.Ok(new
            {
                Imported = string.IsNullOrWhiteSpace(imported) ? null : imported,
                Latest = latest,
                UpdateAvailable = IsNewer(latest, imported),
                Error = error
            });
        }).WithName("GetLatestAvailableVersion");
    }

    /// <summary>
    /// Picks the version to store: the user-supplied label wins when it is a real
    /// value, otherwise we fall back to the version detected inside the zip.
    /// </summary>
    private static string ResolveVersion(string? userSupplied, string? detected)
    {
        var u = userSupplied?.Trim();
        bool userIsPlaceholder = string.IsNullOrWhiteSpace(u) ||
            u.Equals("unknown", StringComparison.OrdinalIgnoreCase) ||
            u.Equals("latest", StringComparison.OrdinalIgnoreCase);

        if (!userIsPlaceholder)
            return u!;
        return !string.IsNullOrWhiteSpace(detected) ? detected! : (u ?? "unknown");
    }

    /// <summary>
    /// Reads the root VERSION file shipped inside Google's policy_templates.zip and
    /// turns the MAJOR/MINOR/BUILD/PATCH key-value pairs into a dotted version string
    /// (e.g. "149.0.7827.197"). Returns null when no usable VERSION file is present.
    /// </summary>
    private static string? ExtractVersionFromArchive(ZipArchive archive)
    {
        var versionEntry = archive.Entries.FirstOrDefault(e =>
            e.Name.Equals("VERSION", StringComparison.OrdinalIgnoreCase) &&
            !e.FullName.Contains("__MACOSX"));
        if (versionEntry is null)
            return null;

        try
        {
            using var reader = new StreamReader(versionEntry.Open());
            var map = new Dictionary<string, string>(StringComparer.OrdinalIgnoreCase);
            string? line;
            while ((line = reader.ReadLine()) is not null)
            {
                var idx = line.IndexOf('=');
                if (idx <= 0) continue;
                map[line[..idx].Trim()] = line[(idx + 1)..].Trim();
            }

            if (map.TryGetValue("MAJOR", out var major) && !string.IsNullOrEmpty(major))
            {
                map.TryGetValue("MINOR", out var minor);
                map.TryGetValue("BUILD", out var build);
                map.TryGetValue("PATCH", out var patch);
                return $"{major}.{minor ?? "0"}.{build ?? "0"}.{patch ?? "0"}";
            }
        }
        catch
        {
            // Malformed VERSION file — treat as not present.
        }
        return null;
    }

    /// <summary>
    /// Returns true when <paramref name="latest"/> represents a newer release than
    /// <paramref name="imported"/>. Compares as dotted numeric versions when possible,
    /// otherwise falls back to a case-insensitive string difference.
    /// </summary>
    private static bool IsNewer(string? latest, string? imported)
    {
        if (string.IsNullOrWhiteSpace(latest)) return false;
        if (string.IsNullOrWhiteSpace(imported)) return true;

        if (Version.TryParse(latest, out var l) && Version.TryParse(imported, out var i))
            return l > i;

        // Fall back to comparing leading major numbers, then raw strings.
        if (int.TryParse(latest.Split('.')[0], out var lm) &&
            int.TryParse(imported.Split('.')[0], out var im))
            return lm > im;

        return !string.Equals(latest, imported, StringComparison.OrdinalIgnoreCase);
    }

    /// <summary>
    /// Maps the service import summary into the response shape the Admin UI consumes.
    /// </summary>
    private static object ToImportResponse(AdmxCatalogService.ImportSummary s)
    {
        var statusNote = s.Activated ? "active" : s.Status.ToString().ToLowerInvariant();
        return new
        {
            Message = $"Imported {s.TotalParsed} policy definitions for ADMX {s.TemplateVersion} ({statusNote})",
            TemplateVersion = s.TemplateVersion,
            TotalParsed = s.TotalParsed,
            Mandatory = s.Mandatory,
            Recommended = s.Recommended,
            Categories = s.Categories,
            Added = s.TotalParsed,
            Updated = 0,
            Removed = 0,
            TemplateId = s.TemplateId,
            Status = s.Status.ToString(),
            Activated = s.Activated,
            Warnings = s.Warnings
        };
    }
}

public record ImportLocalRequest(string AdmxPath, string AdmlPath, string? Version);

