using Microsoft.EntityFrameworkCore;
using ChromePolicyManager.Api.Data;
using ChromePolicyManager.Api.Models;

namespace ChromePolicyManager.Api.Services;

public class AssignmentService
{
    private readonly AppDbContext _db;
    private readonly AuditService _audit;
    private readonly PushRemediationService _pushRemediation;

    public AssignmentService(AppDbContext db, AuditService audit, PushRemediationService pushRemediation)
    {
        _db = db;
        _audit = audit;
        _pushRemediation = pushRemediation;
    }

    public async Task<PolicyAssignment> CreateAssignmentAsync(
        Guid policySetVersionId, string entraGroupId, string groupName,
        int priority, PolicyScope scope = PolicyScope.Mandatory,
        bool pushRemediationEnabled = false, string? actor = null)
    {
        var assignment = new PolicyAssignment
        {
            PolicySetVersionId = policySetVersionId,
            EntraGroupId = entraGroupId,
            GroupName = groupName,
            Priority = priority,
            Scope = scope,
            PushRemediationEnabled = pushRemediationEnabled,
            CreatedBy = actor
        };
        _db.PolicyAssignments.Add(assignment);
        await _db.SaveChangesAsync();
        await _audit.LogAsync("Assignment.Created", actor, "PolicyAssignment", assignment.Id.ToString(),
            $"Group: {groupName}, Priority: {priority}, Scope: {scope}, PushRemediationEnabled: {pushRemediationEnabled}");

        if (pushRemediationEnabled)
        {
            await _pushRemediation.DispatchToAssignmentAsync(assignment, "Assignment created", actor);
        }
        return assignment;
    }

    public async Task<List<PolicyAssignment>> GetAssignmentsAsync(Guid? policySetVersionId = null)
    {
        var query = _db.PolicyAssignments
            .Include(a => a.PolicySetVersion)
            .ThenInclude(v => v.PolicySet)
            .AsQueryable();

        if (policySetVersionId.HasValue)
            query = query.Where(a => a.PolicySetVersionId == policySetVersionId.Value);

        return await query.OrderBy(a => a.Priority).ToListAsync();
    }

    public async Task<bool> DeleteAssignmentAsync(Guid assignmentId, string? actor = null)
    {
        var assignment = await _db.PolicyAssignments.FindAsync(assignmentId);
        if (assignment == null) return false;

        _db.PolicyAssignments.Remove(assignment);
        await _db.SaveChangesAsync();
        await _audit.LogAsync("Assignment.Deleted", actor, "PolicyAssignment", assignmentId.ToString(),
            $"Group: {assignment.GroupName}");
        return true;
    }

    public async Task<PolicyAssignment?> UpdateAssignmentAsync(
        Guid assignmentId, string? entraGroupId, string? groupName,
        int? priority, PolicyScope? scope, string? actor = null)
    {
        var assignment = await _db.PolicyAssignments.FindAsync(assignmentId);
        if (assignment == null) return null;

        var changes = new List<string>();
        if (entraGroupId != null && entraGroupId != assignment.EntraGroupId)
        {
            changes.Add($"Group: {assignment.GroupName} → {groupName}");
            assignment.EntraGroupId = entraGroupId;
            assignment.GroupName = groupName ?? entraGroupId;
        }
        if (priority.HasValue && priority.Value != assignment.Priority)
        {
            changes.Add($"Priority: {assignment.Priority} → {priority.Value}");
            assignment.Priority = priority.Value;
        }
        if (scope.HasValue && scope.Value != assignment.Scope)
        {
            changes.Add($"Scope: {assignment.Scope} → {scope.Value}");
            assignment.Scope = scope.Value;
        }

        if (changes.Count > 0)
        {
            await _db.SaveChangesAsync();
            await _audit.LogAsync("Assignment.Updated", actor, "PolicyAssignment", assignmentId.ToString(),
                string.Join("; ", changes));
        }
        return assignment;
    }

    public async Task<PolicyAssignment?> UpdatePriorityAsync(Guid assignmentId, int newPriority, string? actor = null)
    {
        var assignment = await _db.PolicyAssignments.FindAsync(assignmentId);
        if (assignment == null) return null;

        var oldPriority = assignment.Priority;
        assignment.Priority = newPriority;
        await _db.SaveChangesAsync();
        await _audit.LogAsync("Assignment.PriorityChanged", actor, "PolicyAssignment", assignmentId.ToString(),
            $"Priority: {oldPriority} → {newPriority}");
        return assignment;
    }

    public async Task<PolicyAssignment?> UpdatePushRemediationAsync(Guid assignmentId, bool enabled, bool triggerNow, string? actor = null)
    {
        var assignment = await _db.PolicyAssignments.FindAsync(assignmentId);
        if (assignment == null) return null;

        assignment.PushRemediationEnabled = enabled;
        await _db.SaveChangesAsync();
        await _audit.LogAsync("Assignment.PushRemediationChanged", actor, "PolicyAssignment", assignmentId.ToString(),
            $"PushRemediationEnabled: {enabled}, TriggerNow: {triggerNow}");

        if (enabled && triggerNow)
        {
            await _pushRemediation.DispatchToAssignmentAsync(assignment, "Push remediation enabled from assignment management", actor);
        }

        return assignment;
    }

    public async Task<PushRemediationDispatchResult?> TriggerPushRemediationAsync(Guid assignmentId, string? actor = null)
    {
        var assignment = await _db.PolicyAssignments.FindAsync(assignmentId);
        if (assignment == null) return null;
        return await _pushRemediation.DispatchToAssignmentAsync(assignment, "Manual trigger from assignment management", actor);
    }
}
