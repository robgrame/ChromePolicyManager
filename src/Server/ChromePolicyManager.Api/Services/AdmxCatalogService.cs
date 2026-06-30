using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Models;
using Microsoft.EntityFrameworkCore;

namespace ChromePolicyManager.Api.Services;

/// <summary>
/// Manages the first-class ADMX template registry (Option B): importing template versions
/// that coexist side by side, promoting exactly one to Active, retiring/deleting versions,
/// and resolving the catalog entries for a given (or the active) version.
/// </summary>
public class AdmxCatalogService
{
    private readonly AppDbContext _db;
    private readonly AuditService _audit;

    public AdmxCatalogService(AppDbContext db, AuditService audit)
    {
        _db = db;
        _audit = audit;
    }

    public record ImportSummary(
        Guid TemplateId,
        string TemplateVersion,
        AdmxTemplateStatus Status,
        int TotalParsed,
        int Mandatory,
        int Recommended,
        int Categories,
        bool Activated,
        List<string> Warnings);

    /// <summary>
    /// Imports a parsed ADMX result as a template version. Replaces only the catalog entries
    /// that belong to this version (other versions are untouched). The first template ever
    /// imported becomes Active automatically; otherwise it lands as Staged unless
    /// <paramref name="activate"/> is true.
    /// </summary>
    public async Task<ImportSummary> ImportAsync(
        AdmxParserService.AdmxParseResult result,
        string source,
        bool activate,
        string? actor = null)
    {
        var version = string.IsNullOrWhiteSpace(result.TemplateVersion) ? "unknown" : result.TemplateVersion;

        var template = await _db.AdmxTemplates.FirstOrDefaultAsync(t => t.Version == version);
        var isNewTemplate = template is null;
        if (template is null)
        {
            template = new AdmxTemplate { Version = version, Source = source, Status = AdmxTemplateStatus.Staged };
            _db.AdmxTemplates.Add(template);
            await _db.SaveChangesAsync(); // materialize Id for FK assignment
        }
        else
        {
            template.Source = source;
            template.ImportedAt = DateTime.UtcNow;
        }

        // Replace-within-template: drop the existing entries for this template, insert the fresh set.
        var existing = _db.PolicyCatalog.Where(e => e.AdmxTemplateId == template.Id);
        _db.PolicyCatalog.RemoveRange(existing);

        var deduped = result.Entries
            .GroupBy(e => $"{e.Name}|{e.IsRecommended}", StringComparer.OrdinalIgnoreCase)
            .Select(g => g.First())
            .ToList();
        foreach (var entry in deduped)
        {
            entry.AdmxTemplateId = template.Id;
            entry.TemplateVersion = version;
        }
        await _db.PolicyCatalog.AddRangeAsync(deduped);

        // Recompute counts on the template row.
        template.PolicyCount = deduped.Count;
        template.MandatoryCount = deduped.Count(e => !e.IsRecommended);
        template.RecommendedCount = deduped.Count(e => e.IsRecommended);
        template.CategoryCount = deduped.Where(e => !e.IsRecommended).Select(e => e.Category).Distinct().Count();
        if (result.Warnings.Count > 0)
            template.Notes = $"{result.Warnings.Count} warning(s) at last import";

        await _db.SaveChangesAsync();

        // Activation: first template ever, or explicit request.
        var anyActive = await _db.AdmxTemplates.AnyAsync(t => t.Status == AdmxTemplateStatus.Active);
        var shouldActivate = activate || (isNewTemplate && !anyActive);
        if (shouldActivate)
            await ActivateInternalAsync(template, actor);

        await _audit.LogAsync("AdmxTemplate.Imported", actor, "AdmxTemplate", template.Id.ToString(),
            $"Version: {version}, Source: {source}, Policies: {deduped.Count}, Activated: {shouldActivate}");

        return new ImportSummary(
            template.Id, version, template.Status, deduped.Count,
            template.MandatoryCount, template.RecommendedCount, template.CategoryCount,
            shouldActivate, result.Warnings);
    }

    /// <summary>Promotes a template to Active, demoting the previously Active one to Retired.</summary>
    public async Task<AdmxTemplate?> ActivateAsync(Guid templateId, string? actor = null)
    {
        var template = await _db.AdmxTemplates.FindAsync(templateId);
        if (template is null) return null;
        await ActivateInternalAsync(template, actor);
        await _db.SaveChangesAsync();
        return template;
    }

    private async Task ActivateInternalAsync(AdmxTemplate template, string? actor)
    {
        var currentlyActive = await _db.AdmxTemplates
            .Where(t => t.Status == AdmxTemplateStatus.Active && t.Id != template.Id)
            .ToListAsync();
        foreach (var t in currentlyActive)
            t.Status = AdmxTemplateStatus.Retired;

        template.Status = AdmxTemplateStatus.Active;
        await _audit.LogAsync("AdmxTemplate.Activated", actor, "AdmxTemplate", template.Id.ToString(),
            $"Version: {template.Version}");
    }

    /// <summary>Retires a template (cannot retire the only/Active default without another taking over).</summary>
    public async Task<(bool Ok, string? Error)> RetireAsync(Guid templateId, string? actor = null)
    {
        var template = await _db.AdmxTemplates.FindAsync(templateId);
        if (template is null) return (false, "Template not found");

        if (template.Status == AdmxTemplateStatus.Active)
            return (false, "Cannot retire the Active template. Activate another version first.");

        template.Status = AdmxTemplateStatus.Retired;
        await _db.SaveChangesAsync();
        await _audit.LogAsync("AdmxTemplate.Retired", actor, "AdmxTemplate", template.Id.ToString(),
            $"Version: {template.Version}");
        return (true, null);
    }

    /// <summary>
    /// Deletes a template and its catalog entries. Blocked when the template is Active or when a
    /// Draft policy version was authored against it (Active/Archived policies are autonomous via
    /// their stored SettingsJson and therefore never block deletion).
    /// </summary>
    public async Task<(bool Ok, string? Error)> DeleteAsync(Guid templateId, string? actor = null)
    {
        var template = await _db.AdmxTemplates.FindAsync(templateId);
        if (template is null) return (false, "Template not found");

        if (template.Status == AdmxTemplateStatus.Active)
            return (false, "Cannot delete the Active template. Activate another version first.");

        var draftRef = await _db.PolicySetVersions
            .AnyAsync(v => v.Status == PolicyVersionStatus.Draft && v.AdmxVersion == template.Version);
        if (draftRef)
            return (false, $"Cannot delete: a Draft policy version references ADMX {template.Version}. Publish or delete that draft first.");

        var entries = _db.PolicyCatalog.Where(e => e.AdmxTemplateId == template.Id);
        _db.PolicyCatalog.RemoveRange(entries);
        _db.AdmxTemplates.Remove(template);
        await _db.SaveChangesAsync();
        await _audit.LogAsync("AdmxTemplate.Deleted", actor, "AdmxTemplate", template.Id.ToString(),
            $"Version: {template.Version}");
        return (true, null);
    }

    /// <summary>Returns the Active template, or null when none is active.</summary>
    public Task<AdmxTemplate?> GetActiveTemplateAsync() =>
        _db.AdmxTemplates.FirstOrDefaultAsync(t => t.Status == AdmxTemplateStatus.Active);

    /// <summary>
    /// Resolves the template Id to query catalog entries for: an explicit version when supplied
    /// and known, otherwise the Active template. Returns null when nothing matches.
    /// </summary>
    public async Task<Guid?> ResolveTemplateIdAsync(string? version)
    {
        if (!string.IsNullOrWhiteSpace(version))
        {
            var byVersion = await _db.AdmxTemplates
                .Where(t => t.Version == version)
                .Select(t => (Guid?)t.Id)
                .FirstOrDefaultAsync();
            if (byVersion is not null) return byVersion;
        }
        return await _db.AdmxTemplates
            .Where(t => t.Status == AdmxTemplateStatus.Active)
            .Select(t => (Guid?)t.Id)
            .FirstOrDefaultAsync();
    }
}
