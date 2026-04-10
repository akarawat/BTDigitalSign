using DigitalSign.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace DigitalSign.Data.Repositories;

public interface ISignatureRegistryRepository
{
    Task<SignatureRegistry?>       GetByUserAsync(string samAccountName);
    Task<SignatureRegistry?>       GetByIdAsync(long id);
    Task<List<SignatureRegistry>>  GetAllAsync(bool approvedOnly = false, int page = 1, int pageSize = 50);
    Task<int>                      CountAsync(bool approvedOnly = false);
    Task                           UpsertAsync(SignatureRegistry entity);
    Task<bool>                     ApproveAsync(long id, string approvedBy);
    Task<bool>                     DeactivateAsync(long id, string updatedBy);
}

public class SignatureRegistryRepository : ISignatureRegistryRepository
{
    private readonly DigitalSignDbContext _db;

    public SignatureRegistryRepository(DigitalSignDbContext db) => _db = db;

    public async Task<SignatureRegistry?> GetByUserAsync(string samAccountName)
        => await _db.SignatureRegistries
            .Where(x => x.SamAccountName == samAccountName && x.IsActive)
            .OrderByDescending(x => x.RegisteredAt)
            .FirstOrDefaultAsync();

    public async Task<SignatureRegistry?> GetByIdAsync(long id)
        => await _db.SignatureRegistries.FindAsync(id);

    public async Task<List<SignatureRegistry>> GetAllAsync(bool approvedOnly = false, int page = 1, int pageSize = 50)
    {
        var q = _db.SignatureRegistries.Where(x => x.IsActive);
        if (approvedOnly) q = q.Where(x => x.IsApproved);
        return await q
            .OrderByDescending(x => x.RegisteredAt)
            .Skip((page - 1) * pageSize)
            .Take(pageSize)
            .Select(x => new SignatureRegistry   // ไม่ดึง binary image ใน list
            {
                Id             = x.Id,
                SamAccountName = x.SamAccountName,
                FullNameTH     = x.FullNameTH,
                FullNameEN     = x.FullNameEN,
                Position       = x.Position,
                Department     = x.Department,
                Email          = x.Email,
                ImageMimeType  = x.ImageMimeType,
                ImageFileName  = x.ImageFileName,
                ImageSizeBytes = x.ImageSizeBytes,
                IsActive       = x.IsActive,
                IsApproved     = x.IsApproved,
                ApprovedBy     = x.ApprovedBy,
                ApprovedAt     = x.ApprovedAt,
                RegisteredAt   = x.RegisteredAt,
                UpdatedAt      = x.UpdatedAt,
                SignatureImage = []  // ไม่โหลดมา
            })
            .ToListAsync();
    }

    public async Task<int> CountAsync(bool approvedOnly = false)
    {
        var q = _db.SignatureRegistries.Where(x => x.IsActive);
        if (approvedOnly) q = q.Where(x => x.IsApproved);
        return await q.CountAsync();
    }

    public async Task UpsertAsync(SignatureRegistry entity)
    {
        var existing = await _db.SignatureRegistries
            .FirstOrDefaultAsync(x => x.SamAccountName == entity.SamAccountName && x.IsActive);

        if (existing == null)
        {
            await _db.SignatureRegistries.AddAsync(entity);
        }
        else
        {
            // อัปเดตข้อมูลเดิม
            existing.FullNameTH     = entity.FullNameTH;
            existing.FullNameEN     = entity.FullNameEN;
            existing.Position       = entity.Position;
            existing.Department     = entity.Department;
            existing.Email          = entity.Email;
            existing.SignatureImage = entity.SignatureImage;
            existing.ImageMimeType  = entity.ImageMimeType;
            existing.ImageFileName  = entity.ImageFileName;
            existing.ImageSizeBytes = entity.ImageSizeBytes;
            existing.IsApproved     = false;   // ต้องอนุมัติใหม่เมื่ออัปเดต
            existing.ApprovedBy     = null;
            existing.ApprovedAt     = null;
            existing.UpdatedAt      = DateTime.UtcNow;
            existing.UpdatedBy      = entity.UpdatedBy;
        }

        await _db.SaveChangesAsync();
    }

    public async Task<bool> ApproveAsync(long id, string approvedBy)
    {
        var entity = await _db.SignatureRegistries.FindAsync(id);
        if (entity == null) return false;

        entity.IsApproved  = true;
        entity.ApprovedBy  = approvedBy;
        entity.ApprovedAt  = DateTime.UtcNow;
        await _db.SaveChangesAsync();
        return true;
    }

    public async Task<bool> DeactivateAsync(long id, string updatedBy)
    {
        var entity = await _db.SignatureRegistries.FindAsync(id);
        if (entity == null) return false;

        entity.IsActive   = false;
        entity.UpdatedAt  = DateTime.UtcNow;
        entity.UpdatedBy  = updatedBy;
        await _db.SaveChangesAsync();
        return true;
    }
}
