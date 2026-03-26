using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace DigitalSign.Data.Entities;

[Table("SignatureAudit")]
public class SignatureAudit
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public long Id { get; set; }

    [Required, MaxLength(200)]
    public string ReferenceId { get; set; } = string.Empty;

    [Required, MaxLength(500)]
    public string SignedByUser { get; set; } = string.Empty;

    [Required, MaxLength(1000)]
    public string SignedByCert { get; set; } = string.Empty;

    public DateTime SignedAt { get; set; } = DateTime.UtcNow;

    [MaxLength(200)]
    public string? Purpose { get; set; }

    [MaxLength(200)]
    public string? Department { get; set; }

    [MaxLength(500)]
    public string? Remarks { get; set; }

    [Required, MaxLength(64)]
    public string DataHash { get; set; } = string.Empty;

    [Required, MaxLength(64)]
    public string SignatureHash { get; set; } = string.Empty;

    [Required, MaxLength(100)]
    public string CertThumbprint { get; set; } = string.Empty;

    public DateTime CertExpiry { get; set; }

    [MaxLength(50)]
    public string SignatureType { get; set; } = "RSA-SHA256";

    [MaxLength(100)]
    public string? IpAddress { get; set; }

    public bool IsRevoked { get; set; } = false;

    public DateTime? RevokedAt { get; set; }

    [MaxLength(500)]
    public string? RevocationReason { get; set; }
}

[Table("SignatureTemplate")]
public class SignatureTemplate
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public int Id { get; set; }

    [Required, MaxLength(200)]
    public string Name { get; set; } = string.Empty;

    [MaxLength(500)]
    public string? Description { get; set; }

    public float SignatureX { get; set; } = 36f;
    public float SignatureY { get; set; } = 36f;
    public float SignatureWidth { get; set; } = 200f;
    public float SignatureHeight { get; set; } = 60f;
    public int   SignaturePage { get; set; } = 1;

    [MaxLength(200)]
    public string DefaultReason { get; set; } = "Approved";

    public bool IsActive { get; set; } = true;
    public DateTime CreatedAt { get; set; } = DateTime.UtcNow;
}
