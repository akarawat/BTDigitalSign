// ── เพิ่มบรรทัดนี้ใน DigitalSignDbContext.cs ─────────────────────────────────
// ต่อจาก DbSet<SignatureTemplate>

public DbSet<SignatureRegistry> SignatureRegistries { get; set; }

// ── เพิ่มใน OnModelCreating() ─────────────────────────────────────────────────
modelBuilder.Entity<SignatureRegistry>(e =>
{
    e.HasIndex(x => x.SamAccountName)
     .HasFilter("[IsActive] = 1")
     .IsUnique()
     .HasDatabaseName("IX_SignatureRegistry_SamAccount");

    e.HasIndex(x => new { x.IsApproved, x.IsActive })
     .HasDatabaseName("IX_SignatureRegistry_Status");
});
