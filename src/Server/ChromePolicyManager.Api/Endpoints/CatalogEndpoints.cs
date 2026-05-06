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

        // GET /api/catalog - Get all catalog entries with optional filters
        group.MapGet("/", async (AppDbContext db, string? category, string? dataType, string? search, bool? recommended) =>
        {
            var query = db.PolicyCatalog.AsQueryable();

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

            var entries = await query.OrderBy(e => e.Category).ThenBy(e => e.Name).ToListAsync();
            return Results.Ok(entries);
        }).WithName("GetCatalog");

        // GET /api/catalog/categories - Get distinct categories
        group.MapGet("/categories", async (AppDbContext db) =>
        {
            var categories = await db.PolicyCatalog
                .Where(e => !e.IsRecommended)
                .Select(e => e.Category)
                .Distinct()
                .OrderBy(c => c)
                .ToListAsync();
            return Results.Ok(categories);
        }).WithName("GetCatalogCategories");

        // GET /api/catalog/{id} - Get single catalog entry
        group.MapGet("/{id:guid}", async (Guid id, AppDbContext db) =>
        {
            var entry = await db.PolicyCatalog.FindAsync(id);
            return entry is null ? Results.NotFound() : Results.Ok(entry);
        }).WithName("GetCatalogEntry");

        // GET /api/catalog/stats - Import statistics
        group.MapGet("/stats", async (AppDbContext db) =>
        {
            var total = await db.PolicyCatalog.CountAsync();
            var mandatory = await db.PolicyCatalog.CountAsync(e => !e.IsRecommended);
            var recommended = await db.PolicyCatalog.CountAsync(e => e.IsRecommended);
            var categories = await db.PolicyCatalog.Where(e => !e.IsRecommended).Select(e => e.Category).Distinct().CountAsync();
            var version = await db.PolicyCatalog.Select(e => e.TemplateVersion).FirstOrDefaultAsync() ?? "none";

            return Results.Ok(new
            {
                TotalEntries = total,
                MandatoryPolicies = mandatory,
                RecommendedPolicies = recommended,
                Categories = categories,
                TemplateVersion = version,
                LastImport = await db.PolicyCatalog.MaxAsync(e => (DateTime?)e.ImportedAt)
            });
        }).WithName("GetCatalogStats");

        // POST /api/catalog/import - Import from ADMX zip upload
        group.MapPost("/import", async (HttpRequest request, AppDbContext db, AdmxParserService parser) =>
        {
            if (!request.HasFormContentType)
                return Results.BadRequest("Expected multipart/form-data with ADMX zip file");

            var form = await request.ReadFormAsync();
            var file = form.Files.GetFile("admxZip") ?? form.Files.FirstOrDefault();

            if (file is null || file.Length == 0)
                return Results.BadRequest("No file uploaded. Upload a zip containing chrome.admx + en-US/chrome.adml");

            var version = form["version"].FirstOrDefault() ?? "unknown";

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

            using var admxStream = admxEntry.Open();
            using var admlStream = admlEntry.Open();

            var result = parser.Parse(admxStream, admlStream, version);

            // Replace all existing catalog entries (full refresh)
            db.PolicyCatalog.RemoveRange(db.PolicyCatalog);
            await db.PolicyCatalog.AddRangeAsync(result.Entries);
            await db.SaveChangesAsync();

            return Results.Ok(new
            {
                Message = $"Imported {result.TotalParsed} policy definitions",
                result.TemplateVersion,
                result.TotalParsed,
                Mandatory = result.Entries.Count(e => !e.IsRecommended),
                Recommended = result.Entries.Count(e => e.IsRecommended),
                Categories = result.Entries.Where(e => !e.IsRecommended).Select(e => e.Category).Distinct().Count(),
                result.Warnings
            });
        }).WithName("ImportCatalog")
        .DisableAntiforgery();

        // POST /api/catalog/import-local - Import from server-local ADMX files (for CLI/automation)
        group.MapPost("/import-local", async (ImportLocalRequest request, AppDbContext db, AdmxParserService parser) =>
        {
            if (!File.Exists(request.AdmxPath))
                return Results.BadRequest($"ADMX file not found: {request.AdmxPath}");
            if (!File.Exists(request.AdmlPath))
                return Results.BadRequest($"ADML file not found: {request.AdmlPath}");

            using var admxStream = File.OpenRead(request.AdmxPath);
            using var admlStream = File.OpenRead(request.AdmlPath);

            var result = parser.Parse(admxStream, admlStream, request.Version ?? "local");

            db.PolicyCatalog.RemoveRange(db.PolicyCatalog);
            await db.PolicyCatalog.AddRangeAsync(result.Entries);
            await db.SaveChangesAsync();

            return Results.Ok(new
            {
                Message = $"Imported {result.TotalParsed} policy definitions",
                result.TemplateVersion,
                result.TotalParsed,
                result.Warnings
            });
        }).WithName("ImportCatalogLocal");
    }
}

public record ImportLocalRequest(string AdmxPath, string AdmlPath, string? Version);
