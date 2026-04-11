using DigitalSign.Core.Models;
using DigitalSign.Data.Entities;
using DigitalSign.Data.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DigitalSign.API.Controllers;

[ApiController]
[Route("api/signature-registry")]
[Produces("application/json")]
public class SignatureRegistryController : ControllerBase
{
    private readonly ISignatureRegistryRepository _repo;
    private readonly IConfiguration _config;
    private readonly ILogger<SignatureRegistryController> _logger;

    private const int MaxImageSizeBytes = 2 * 1024 * 1024; // 2 MB

    public SignatureRegistryController(
        ISignatureRegistryRepository repo,
        IConfiguration config,
        ILogger<SignatureRegistryController> logger)
    {
        _repo = repo;
        _config = config;
        _logger = logger;
    }

    // ── ตรวจสอบ API Key จาก Header X-Api-Key ──────────────────────────────────
    private bool IsValidApiKey()
    {
        var expectedKey = _config["InternalApiKey"];
        if (string.IsNullOrEmpty(expectedKey)) return false;

        Request.Headers.TryGetValue("X-Api-Key", out var providedKey);
        return providedKey == expectedKey;
    }

    // ── Helper: ดึง SAM จาก Windows Auth ถ้ามี ────────────────────────────────
    private string GetSamAccount()
    {
        var name = User.Identity?.Name ?? "unknown";
        return name.Contains('\\') ? name.Split('\\').Last() : name;
    }

    // ── GET /api/signature-registry/me ───────────────────────────────────────
    [HttpGet("me")]
    [AllowAnonymous]
    public async Task<IActionResult> GetMy()
    {
        if (!IsValidApiKey())
            return Unauthorized(ApiResponse<object>.Fail("Invalid or missing API Key."));

        // ดึง SAM จาก Header ที่ Web App ส่งมา
        Request.Headers.TryGetValue("X-Sam-Account", out var sam);
        if (string.IsNullOrEmpty(sam))
            return BadRequest(ApiResponse<object>.Fail("X-Sam-Account header is required."));

        var record = await _repo.GetByUserAsync(sam!);

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
            SignatureImageBase64 = Convert.ToBase64String(record.SignatureImage)
        }));
    }

    // ── GET /api/signature-registry/user/{samAccount} ────────────────────────
    [HttpGet("user/{samAccount}")]
    [AllowAnonymous]
    public async Task<IActionResult> GetByUser(string samAccount)
    {
        if (!IsValidApiKey())
            return Unauthorized(ApiResponse<object>.Fail("Invalid or missing API Key."));

        var record = await _repo.GetByUserAsync(samAccount);

        if (record == null || !record.IsApproved)
            return NotFound(ApiResponse<object>.Fail($"No approved signature for '{samAccount}'."));

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
    //[HttpGet("image/{samAccount}")]
    //[AllowAnonymous]
    //public async Task<IActionResult> GetImage(string samAccount)
    //{
    //    // Image endpoint ไม่ต้องการ API Key เพื่อให้ embed ได้ง่าย
    //    var record = await _repo.GetByUserAsync(samAccount);

    //    if (record == null || !record.IsApproved || record.SignatureImage.Length == 0)
    //        return NotFound();

    //    return File(record.SignatureImage, record.ImageMimeType);
    //}
    [HttpGet("image/{samAccount}")]
    [AllowAnonymous]
    public async Task<IActionResult> GetImage(string samAccount)
    {
        if (!IsValidApiKey())
            return Unauthorized();

        var record = await _repo.GetByUserAsync(samAccount);

        // ✅ แก้ — ลบ !record.IsApproved ออก ให้ดูได้แม้ยัง Pending
        if (record == null || record.SignatureImage.Length == 0)
            return NotFound();

        return File(record.SignatureImage, record.ImageMimeType);
    }

    // ── POST /api/signature-registry/register ────────────────────────────────
    [HttpPost("register")]
    [AllowAnonymous]
    [Consumes("multipart/form-data")]
    public async Task<IActionResult> Register([FromForm] RegisterSignatureRequest request)
    {
        if (!IsValidApiKey())
            return Unauthorized(ApiResponse<object>.Fail("Invalid or missing API Key."));

        if (!ModelState.IsValid)
            return BadRequest(ApiResponse<object>.Fail("Invalid request."));

        if (request.SignatureFile == null || request.SignatureFile.Length == 0)
            return BadRequest(ApiResponse<object>.Fail("Signature image is required."));

        if (request.SignatureFile.Length > MaxImageSizeBytes)
            return BadRequest(ApiResponse<object>.Fail("Image size must not exceed 2 MB."));

        var allowedTypes = new[] { "image/png", "image/jpeg", "image/jpg" };
        if (!allowedTypes.Contains(request.SignatureFile.ContentType.ToLower()))
            return BadRequest(ApiResponse<object>.Fail("Only PNG and JPG images are supported."));

        // ดึง SAM จาก Header
        Request.Headers.TryGetValue("X-Sam-Account", out var sam);
        if (string.IsNullOrEmpty(sam))
            return BadRequest(ApiResponse<object>.Fail("X-Sam-Account header is required."));

        using var ms = new MemoryStream();
        await request.SignatureFile.CopyToAsync(ms);
        var imageBytes = ms.ToArray();

        var entity = new SignatureRegistry
        {
            SamAccountName = sam!,
            FullNameTH = request.FullNameTH,
            FullNameEN = request.FullNameEN,
            Position = request.Position,
            Department = request.Department,
            Email = request.Email,
            SignatureImage = imageBytes,
            ImageMimeType = request.SignatureFile.ContentType,
            ImageFileName = request.SignatureFile.FileName,
            ImageSizeBytes = (int)request.SignatureFile.Length,
            UpdatedBy = sam
        };

        await _repo.UpsertAsync(entity);

        _logger.LogInformation("Signature registered. SAM={Sam}, Name={Name}", sam, request.FullNameEN);

        return Ok(ApiResponse<object>.Ok(
            new { sam, registered = true },
            "Signature registered successfully. Pending admin approval."));
    }

    // ── GET /api/signature-registry/admin/list ────────────────────────────────
    [HttpGet("admin/list")]
    [AllowAnonymous]
    public async Task<IActionResult> AdminList(
        [FromQuery] bool approvedOnly = false,
        [FromQuery] int page = 1,
        [FromQuery] int pageSize = 50)
    {
        if (!IsValidApiKey())
            return Unauthorized(ApiResponse<object>.Fail("Invalid or missing API Key."));

        var records = await _repo.GetAllAsync(approvedOnly, page, pageSize);
        var total = await _repo.CountAsync(approvedOnly);

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
    [HttpPost("admin/{id:long}/approve")]
    [AllowAnonymous]
    public async Task<IActionResult> Approve(long id)
    {
        if (!IsValidApiKey())
            return Unauthorized(ApiResponse<object>.Fail("Invalid or missing API Key."));

        Request.Headers.TryGetValue("X-Sam-Account", out var approvedBy);
        var success = await _repo.ApproveAsync(id, approvedBy.ToString() ?? "admin");

        if (!success)
            return NotFound(ApiResponse<object>.Fail($"Record {id} not found."));

        return Ok(ApiResponse<object>.Ok(new { id, approved = true }));
    }

    // ── DELETE /api/signature-registry/admin/{id} ─────────────────────────────
    [HttpDelete("admin/{id:long}")]
    [AllowAnonymous]
    public async Task<IActionResult> Deactivate(long id)
    {
        if (!IsValidApiKey())
            return Unauthorized(ApiResponse<object>.Fail("Invalid or missing API Key."));

        Request.Headers.TryGetValue("X-Sam-Account", out var updatedBy);
        var success = await _repo.DeactivateAsync(id, updatedBy.ToString() ?? "admin");

        if (!success)
            return NotFound(ApiResponse<object>.Fail($"Record {id} not found."));

        return Ok(ApiResponse<object>.Ok(new { id, deactivated = true }));
    }
}

public class RegisterSignatureRequest
{
    [System.ComponentModel.DataAnnotations.Required]
    public string FullNameTH { get; set; } = string.Empty;

    [System.ComponentModel.DataAnnotations.Required]
    public string FullNameEN { get; set; } = string.Empty;

    public string? Position { get; set; }
    public string? Department { get; set; }
    public string? Email { get; set; }

    [System.ComponentModel.DataAnnotations.Required]
    public IFormFile? SignatureFile { get; set; }
}
