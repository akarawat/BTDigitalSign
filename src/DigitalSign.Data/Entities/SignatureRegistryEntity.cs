using System.ComponentModel.DataAnnotations;
using System.ComponentModel.DataAnnotations.Schema;

namespace DigitalSign.Data.Entities;

[Table("SignatureRegistry")]
public class SignatureRegistry
{
    [Key]
    [DatabaseGenerated(DatabaseGeneratedOption.Identity)]
    public long Id { get; set; }

    // ── ข้อมูลพนักงาน ─────────────────────────────────────────────────────────
    [Required, MaxLength(200)]
    public string SamAccountName { get; set; } = string.Empty;  // sakulchai.p

    [Required, MaxLength(500)]
    public string FullNameTH     { get; set; } = string.Empty;  // สกุลชัย ปานวิลัย

    [Required, MaxLength(500)]
    public string FullNameEN     { get; set; } = string.Empty;  // Sakulchai Panwilai

    [MaxLength(300)]
    public string? Position      { get; set; }  // Senior IT Officer

    [MaxLength(300)]
    public string? Department    { get; set; }  // Information Technology

    [MaxLength(300)]
    public string? Email         { get; set; }  // sakulchai.p@berninathailand.com

    // ── ไฟล์ลายเซ็น ──────────────────────────────────────────────────────────
    [Required]
    public byte[] SignatureImage { get; set; } = [];     // PNG binary

    [Required, MaxLength(50)]
    public string ImageMimeType  { get; set; } = "image/png";

    [MaxLength(300)]
    public string? ImageFileName { get; set; }

    public int? ImageSizeBytes   { get; set; }

    // ── สถานะ ─────────────────────────────────────────────────────────────────
    public bool    IsActive    { get; set; } = true;
    public bool    IsApproved  { get; set; } = false;   // รออนุมัติจาก Admin

    [MaxLength(200)]
    public string? ApprovedBy  { get; set; }

    public DateTime? ApprovedAt { get; set; }

    // ── Timestamps ────────────────────────────────────────────────────────────
    public DateTime  RegisteredAt { get; set; } = DateTime.UtcNow;
    public DateTime? UpdatedAt    { get; set; }

    [MaxLength(200)]
    public string? UpdatedBy      { get; set; }
}
