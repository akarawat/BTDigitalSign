using DigitalSign.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace DigitalSign.Data.Repositories;

public interface ISignatureAuditRepository
{
    Task AddAsync(SignatureAudit audit);
    Task<SignatureAudit?> GetByIdAsync(long id);
    Task<List<SignatureAudit>> GetByReferenceIdAsync(string referenceId);
    Task<List<SignatureAudit>> GetByUserAsync(string username, int page = 1, int pageSize = 20);
    Task<bool> RevokeAsync(long id, string reason);
    Task<int> CountByUserAsync(string username);
}

public class SignatureAuditRepository : ISignatureAuditRepository
{
    private readonly DigitalSignDbContext _db;

    public SignatureAuditRepository(DigitalSignDbContext db)
    {
        _db = db;
    }

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

    public async Task<bool> RevokeAsync(long id, string reason)
    {
        var audit = await _db.SignatureAudits.FindAsync(id);
        if (audit == null) return false;

        audit.IsRevoked        = true;
        audit.RevokedAt        = DateTime.UtcNow;
        audit.RevocationReason = reason;
        await _db.SaveChangesAsync();
        return true;
    }

    public async Task<int> CountByUserAsync(string username)
        => await _db.SignatureAudits.CountAsync(x => x.SignedByUser == username);
}
