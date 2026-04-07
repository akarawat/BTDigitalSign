using DigitalSign.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace DigitalSign.Data.Repositories;

public interface ISignatureAuditRepository
{
    Task AddAsync(SignatureAudit audit);
    Task<SignatureAudit?>         GetByIdAsync(long id);
    Task<List<SignatureAudit>>    GetByReferenceIdAsync(string referenceId);
    Task<List<SignatureAudit>>    GetByUserAsync(string username, int page = 1, int pageSize = 20);
    Task<List<SignatureAudit>>    GetByWebSourceAsync(string webSource, int page = 1, int pageSize = 20);
    Task<List<SignatureAudit>>    GetByDateRangeAsync(DateTime from, DateTime to, int page = 1, int pageSize = 50);
    Task<List<SignatureAudit>>    SearchAsync(AuditSearchQuery query);
    Task<int>                     CountByUserAsync(string username);
    Task<int>                     CountByWebSourceAsync(string webSource);
    Task<bool>                    RevokeAsync(long id, string reason);
}

public class AuditSearchQuery
{
    public string? ReferenceId  { get; set; }
    public string? SignedByUser { get; set; }
    public string? SignerRole   { get; set; }
    public string? WebSource    { get; set; }
    public string? DocumentType { get; set; }
    public DateTime? From       { get; set; }
    public DateTime? To         { get; set; }
    public int Page             { get; set; } = 1;
    public int PageSize         { get; set; } = 50;
}

public class SignatureAuditRepository : ISignatureAuditRepository
{
    private readonly DigitalSignDbContext _db;

    public SignatureAuditRepository(DigitalSignDbContext db) => _db = db;

    public async Task AddAsync(SignatureAudit audit)
    {
        await _db.SignatureAudits.AddAsync(audit);
        await _db.SaveChangesAsync();
    }

    public async Task<SignatureAudit?> GetByIdAsync(long id)
        => await _db.SignatureAudits.FindAsync(id);

    public async Task<List<SignatureAudit>> GetByReferenceIdAsync(string referenceId)
        => await _db.SignatureAudits
            .Where(x => x.ReferenceId == referenceId)
            .OrderByDescending(x => x.SignedAt)
            .ToListAsync();

    public async Task<List<SignatureAudit>> GetByUserAsync(string username, int page = 1, int pageSize = 20)
        => await _db.SignatureAudits
            .Where(x => x.SignedByUser == username)
            .OrderByDescending(x => x.SignedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

    public async Task<List<SignatureAudit>> GetByWebSourceAsync(string webSource, int page = 1, int pageSize = 20)
        => await _db.SignatureAudits
            .Where(x => x.WebSource == webSource)
            .OrderByDescending(x => x.SignedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

    public async Task<List<SignatureAudit>> GetByDateRangeAsync(DateTime from, DateTime to, int page = 1, int pageSize = 50)
        => await _db.SignatureAudits
            .Where(x => x.SignedAt >= from && x.SignedAt <= to)
            .OrderByDescending(x => x.SignedAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .ToListAsync();

    public async Task<List<SignatureAudit>> SearchAsync(AuditSearchQuery q)
    {
        var query = _db.SignatureAudits.AsQueryable();

        if (!string.IsNullOrEmpty(q.ReferenceId))
            query = query.Where(x => x.ReferenceId.Contains(q.ReferenceId));

        if (!string.IsNullOrEmpty(q.SignedByUser))
            query = query.Where(x => x.SignedByUser.Contains(q.SignedByUser));

        if (!string.IsNullOrEmpty(q.SignerRole))
            query = query.Where(x => x.SignerRole == q.SignerRole);

        if (!string.IsNullOrEmpty(q.WebSource))
            query = query.Where(x => x.WebSource == q.WebSource);

        if (!string.IsNullOrEmpty(q.DocumentType))
            query = query.Where(x => x.DocumentType == q.DocumentType);

        if (q.From.HasValue)
            query = query.Where(x => x.SignedAt >= q.From.Value);

        if (q.To.HasValue)
            query = query.Where(x => x.SignedAt <= q.To.Value);

        return await query
            .OrderByDescending(x => x.SignedAt)
            .Skip((q.Page - 1) * q.PageSize)
            .Take(q.PageSize)
            .ToListAsync();
    }

    public async Task<int> CountByUserAsync(string username)
        => await _db.SignatureAudits.CountAsync(x => x.SignedByUser == username);

    public async Task<int> CountByWebSourceAsync(string webSource)
        => await _db.SignatureAudits.CountAsync(x => x.WebSource == webSource);

    public async Task<bool> RevokeAsync(long id, string reason)
    {
        var audit = await _db.SignatureAudits.FindAsync(id);
        if (audit == null) return false;

        audit.IsRevoked       = true;
        audit.RevokedAt       = DateTime.UtcNow;
        audit.RevocationReason = reason;

        await _db.SaveChangesAsync();
        return true;
    }
}
