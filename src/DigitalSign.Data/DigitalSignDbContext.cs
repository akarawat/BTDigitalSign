using DigitalSign.Data.Entities;
using Microsoft.EntityFrameworkCore;

namespace DigitalSign.Data;

public class DigitalSignDbContext : DbContext
{
    public DigitalSignDbContext(DbContextOptions<DigitalSignDbContext> options)
        : base(options) { }

    public DbSet<SignatureAudit>    SignatureAudits    { get; set; }
    public DbSet<SignatureTemplate> SignatureTemplates { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        base.OnModelCreating(modelBuilder);

        modelBuilder.Entity<SignatureAudit>(e =>
        {
            e.HasIndex(x => x.ReferenceId).HasDatabaseName("IX_SignAudit_ReferenceId");
            e.HasIndex(x => x.SignedByUser).HasDatabaseName("IX_SignAudit_SignedByUser");
            e.HasIndex(x => x.SignedAt).HasDatabaseName("IX_SignAudit_SignedAt");
            e.HasIndex(x => x.CertThumbprint).HasDatabaseName("IX_SignAudit_Thumbprint");
            e.Property(x => x.SignedAt).HasDefaultValueSql("GETUTCDATE()");
        });

        // Seed: default template
        modelBuilder.Entity<SignatureTemplate>().HasData(
            new SignatureTemplate
            {
                Id              = 1,
                Name            = "Default Bottom-Left",
                Description     = "Standard signature position at bottom-left of page 1",
                SignatureX      = 36f,
                SignatureY      = 36f,
                SignatureWidth  = 200f,
                SignatureHeight = 60f,
                SignaturePage   = 1,
                DefaultReason   = "Approved",
                IsActive        = true,
                CreatedAt       = new DateTime(2025, 1, 1, 0, 0, 0, DateTimeKind.Utc)
            });
    }
}
