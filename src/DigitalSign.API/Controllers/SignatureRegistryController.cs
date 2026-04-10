using DigitalSign.Core.Models;
using DigitalSign.Data.Entities;
using DigitalSign.Data.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DigitalSign.API.Controllers;

/// <summary>
/// Signature Registry — ลงทะเบียนลายเซ็นพนักงาน
/// </summary>
[ApiController]
[Route("api/signature-registry")]
[Authorize]
[Produces("application/json")]
public class SignatureRegistryController : ControllerBase
{
    private readonly ISignatureRegistryRepository _repo;
    private readonly ILogger<SignatureRegistryController> _logger;

    private const int MaxImageSizeBytes = 2 * 1024 * 1024; // 2 MB

    public SignatureRegistryController(
        ISignatureRegistryRepository repo,
        ILogger<SignatureRegistryController> logger)
    {
        _repo   = repo;
        _logger = logger;
    }

    // ── GET /api/signature-registry/me ───────────────────────────────────────
    // ดูลายเซ็นของตัวเอง
    [HttpGet("me")]
    public async Task<IActionResult> GetMy()
    {
        var sam    = GetSamAccount();
        var record = await _repo.GetByUserAsync(sam);

        if (record == null)
            return Ok(ApiResponse<object>.Ok(null, "No signature registered yet."));

        return Ok(ApiResponse<object>.Ok(new
        {
            record.Id,
            record.SamAccountName,
            record.FullNameTH,
            record.FullNameEN,
            record.Position,
            record.Department,
            record.Email,
            record.ImageMimeType,
            record.ImageFileName,
            record.ImageSizeBytes,
            record.IsApproved,
            record.ApprovedBy,
            record.ApprovedAt,
            record.RegisteredAt,
            record.UpdatedAt,
            // คืน Base64 image สำหรับ preview
            SignatureImageBase64 = Convert.ToBase64String(record.SignatureImage)
        }));
    }

    // ── GET /api/signature-registry/user/{samAccount} ────────────────────────
    // ดูลายเซ็นของ user (สำหรับ Web อื่นดึงไปใช้)
    [HttpGet("user/{samAccount}")]
    public async Task<IActionResult> GetByUser(string samAccount)
    {
        var record = await _repo.GetByUserAsync(samAccount);

        if (record == null || !record.IsApproved)
            return NotFound(ApiResponse<object>.Fail($"No approved signature found for '{samAccount}'."));

        return Ok(ApiResponse<object>.Ok(new
        {
            record.Id,
            record.SamAccountName,
            record.FullNameTH,
            record.FullNameEN,
            record.Position,
            record.Department,
            record.ImageMimeType,
            record.RegisteredAt,
            SignatureImageBase64 = Convert.ToBase64String(record.SignatureImage)
        }));
    }

    // ── GET /api/signature-registry/image/{samAccount} ───────────────────────
    // คืนไฟล์ลายเซ็นโดยตรง (สำหรับ <img src="..."> )
    [HttpGet("image/{samAccount}")]
    [AllowAnonymous]  // ให้ Web อื่น embed ได้ โดยไม่ต้อง Auth
    public async Task<IActionResult> GetImage(string samAccount)
    {
        var record = await _repo.GetByUserAsync(samAccount);

        if (record == null || !record.IsApproved || record.SignatureImage.Length == 0)
            return NotFound();

        return File(record.SignatureImage, record.ImageMimeType);
    }

    // ── POST /api/signature-registry/register ────────────────────────────────
    // ลงทะเบียน / อัปเดตลายเซ็น
    [HttpPost("register")]
    [Consumes("multipart/form-data")]
    public async Task<IActionResult> Register([FromForm] RegisterSignatureRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ApiResponse<object>.Fail("Invalid request."));

        // Validate image
        if (request.SignatureFile == null || request.SignatureFile.Length == 0)
            return BadRequest(ApiResponse<object>.Fail("Signature image is required."));

        if (request.SignatureFile.Length > MaxImageSizeBytes)
            return BadRequest(ApiResponse<object>.Fail("Image size must not exceed 2 MB."));

        var allowedTypes = new[] { "image/png", "image/jpeg", "image/jpg" };
        if (!allowedTypes.Contains(request.SignatureFile.ContentType.ToLower()))
            return BadRequest(ApiResponse<object>.Fail("Only PNG and JPG images are supported."));

        // อ่านไฟล์
        using var ms = new MemoryStream();
        await request.SignatureFile.CopyToAsync(ms);
        var imageBytes = ms.ToArray();

        var sam    = GetSamAccount();
        var entity = new SignatureRegistry
        {
            SamAccountName = sam,
            FullNameTH     = request.FullNameTH,
            FullNameEN     = request.FullNameEN,
            Position       = request.Position,
            Department     = request.Department,
            Email          = request.Email,
            SignatureImage = imageBytes,
            ImageMimeType  = request.SignatureFile.ContentType,
            ImageFileName  = request.SignatureFile.FileName,
            ImageSizeBytes = (int)request.SignatureFile.Length,
            UpdatedBy      = sam
        };

        await _repo.UpsertAsync(entity);

        _logger.LogInformation("Signature registered. User={User}, Name={Name}",
            sam, request.FullNameEN);

        return Ok(ApiResponse<object>.Ok(new { sam, registered = true },
            "Signature registered successfully. Pending admin approval."));
    }

    // ── GET /api/signature-registry/admin/list ────────────────────────────────
    // Admin: ดูรายการทั้งหมด
    [HttpGet("admin/list")]
    public async Task<IActionResult> AdminList(
        [FromQuery] bool approvedOnly = false,
        [FromQuery] int  page         = 1,
        [FromQuery] int  pageSize     = 50)
    {
        var records = await _repo.GetAllAsync(approvedOnly, page, pageSize);
        var total   = await _repo.CountAsync(approvedOnly);

        return Ok(ApiResponse<object>.Ok(new
        {
            records = records.Select(r => new
            {
                r.Id,
                r.SamAccountName,
                r.FullNameTH,
                r.FullNameEN,
                r.Position,
                r.Department,
                r.Email,
                r.ImageFileName,
                r.ImageSizeBytes,
                r.IsApproved,
                r.ApprovedBy,
                r.ApprovedAt,
                r.RegisteredAt,
                r.UpdatedAt
            }),
            total,
            page,
            pageSize,
            pages = (int)Math.Ceiling((double)total / pageSize)
        }));
    }

    // ── POST /api/signature-registry/admin/{id}/approve ──────────────────────
    // Admin: อนุมัติลายเซ็น
    [HttpPost("admin/{id:long}/approve")]
    public async Task<IActionResult> Approve(long id)
    {
        var approvedBy = GetSamAccount();
        var success    = await _repo.ApproveAsync(id, approvedBy);

        if (!success)
            return NotFound(ApiResponse<object>.Fail($"Record {id} not found."));

        _logger.LogInformation("Signature approved. Id={Id}, ApprovedBy={By}", id, approvedBy);

        return Ok(ApiResponse<object>.Ok(new { id, approved = true, approvedBy }));
    }

    // ── DELETE /api/signature-registry/admin/{id} ────────────────────────────
    // Admin: ลบลายเซ็น
    [HttpDelete("admin/{id:long}")]
    public async Task<IActionResult> Deactivate(long id)
    {
        var updatedBy = GetSamAccount();
        var success   = await _repo.DeactivateAsync(id, updatedBy);

        if (!success)
            return NotFound(ApiResponse<object>.Fail($"Record {id} not found."));

        _logger.LogInformation("Signature deactivated. Id={Id}, By={By}", id, updatedBy);

        return Ok(ApiResponse<object>.Ok(new { id, deactivated = true }));
    }

    // ── Helper ────────────────────────────────────────────────────────────────
    private string GetSamAccount()
    {
        var name = User.Identity?.Name ?? "unknown";
        return name.Contains('\\') ? name.Split('\\').Last() : name;
    }
}

// ── Request Model ─────────────────────────────────────────────────────────────
public class RegisterSignatureRequest
{
    [System.ComponentModel.DataAnnotations.Required]
    public string FullNameTH { get; set; } = string.Empty;

    [System.ComponentModel.DataAnnotations.Required]
    public string FullNameEN { get; set; } = string.Empty;

    public string? Position   { get; set; }
    public string? Department { get; set; }
    public string? Email      { get; set; }

    [System.ComponentModel.DataAnnotations.Required]
    public IFormFile? SignatureFile { get; set; }
}
