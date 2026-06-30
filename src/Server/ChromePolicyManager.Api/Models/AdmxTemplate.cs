namespace ChromePolicyManager.Api.Models;

/// <summary>
/// Lifecycle state of an imported Chrome ADMX template version.
/// Exactly one template is <see cref="Active"/> at a time — it is the default version
/// used when authoring policies without an explicit version selection.
/// </summary>
public enum AdmxTemplateStatus
{
    /// <summary>Imported but not yet promoted; available for authoring only when picked explicitly.</summary>
    Staged = 0,

    /// <summary>The current default template used for authoring and for catalog/stats defaults.</summary>
    Active = 1,

    /// <summary>Superseded by a newer Active template; kept for history and existing drafts.</summary>
    Retired = 2
}

/// <summary>
/// First-class registry entry for an imported Chrome ADMX template version (Option B).
/// Each <see cref="PolicyCatalogEntry"/> belongs to exactly one template, so multiple ADMX
/// versions can coexist and an admin can choose which one a policy is built against.
/// </summary>
public class AdmxTemplate
{
    public Guid Id { get; set; } = Guid.NewGuid();

    /// <summary>Dotted Chrome version, e.g. "149.0.7827.197". Unique across templates.</summary>
    public string Version { get; set; } = string.Empty;

    /// <summary>Optional friendly label shown in the UI (defaults to Version when empty).</summary>
    public string? DisplayName { get; set; }

    /// <summary>How the template was imported: "url", "upload", or "local".</summary>
    public string Source { get; set; } = "url";

    public AdmxTemplateStatus Status { get; set; } = AdmxTemplateStatus.Staged;

    public int PolicyCount { get; set; }
    public int MandatoryCount { get; set; }
    public int RecommendedCount { get; set; }
    public int CategoryCount { get; set; }

    public DateTime ImportedAt { get; set; } = DateTime.UtcNow;

    /// <summary>Free-text notes (e.g. import warnings count, provenance).</summary>
    public string? Notes { get; set; }
}
