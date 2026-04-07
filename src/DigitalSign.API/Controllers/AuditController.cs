using DigitalSign.Core.Models;
using DigitalSign.Data.Entities;
using DigitalSign.Data.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DigitalSign.API.Controllers;

[ApiController]
[Route("api/audit")]
[Authorize]
public class AuditController : ControllerBase
{
    private readonly ISignatureAuditRepository _repo;
    private readonly ILogger<AuditController>  _logger;

    public AuditController(ISignatureAuditRepository repo, ILogger<AuditController> logger)
    {
        _repo   = repo;
        _logger = logger;
    }

    // ── GET /api/audit/my ─────────────────────────────────────────────────────
    // ประวัติของ user ที่ login อยู่
    [HttpGet("my")]
    public async Task<IActionResult> GetMy([FromQuery] int page = 1, [FromQuery] int pageSize = 20)
    {
        var username = User.Identity?.Name ?? string.Empty;
        var records  = await _repo.GetByUserAsync(username, page, pageSize);
        var total    = await _repo.CountByUserAsync(username);

        return Ok(ApiResponse<object>.Ok(new
        {
            records  = records.Select(ToDto),
            total,
            page,
            pageSize,
            pages = (int)Math.Ceiling((double)total / pageSize)
        }));
    }

    // ── GET /api/audit/reference/{referenceId} ────────────────────────────────
    // ดู audit ตาม Document Reference เช่น DAR-2026-00018
    [HttpGet("reference/{referenceId}")]
    public async Task<IActionResult> GetByReference(string referenceId)
    {
        var records = await _repo.GetByReferenceIdAsync(referenceId);

        _logger.LogInformation("Audit query: ReferenceId={Ref}, Count={Count}, By={User}",
            referenceId, records.Count, User.Identity?.Name);

        return Ok(ApiResponse<object>.Ok(new
        {
            referenceId,
            records = records.Select(ToDto),
            total   = records.Count
        }));
    }

    // ── GET /api/audit/user/{username} ────────────────────────────────────────
    // ดู audit ตาม SAM Account เช่น sakulchai.p
    [HttpGet("user/{username}")]
    public async Task<IActionResult> GetByUser(
        string username,
        [FromQuery] int page     = 1,
        [FromQuery] int pageSize = 20)
    {
        var records = await _repo.GetByUserAsync(username, page, pageSize);
        var total   = await _repo.CountByUserAsync(username);

        return Ok(ApiResponse<object>.Ok(new
        {
            username,
            records  = records.Select(ToDto),
            total,
            page,
            pageSize,
            pages = (int)Math.Ceiling((double)total / pageSize)
        }));
    }

    // ── GET /api/audit/web/{webSource} ────────────────────────────────────────
    // ดู audit ตาม Web ที่เรียกใช้ เช่น bt_qc-d.berninathailand.com
    [HttpGet("web/{webSource}")]
    public async Task<IActionResult> GetByWebSource(
        string webSource,
        [FromQuery] int page     = 1,
        [FromQuery] int pageSize = 20)
    {
        var records = await _repo.GetByWebSourceAsync(webSource, page, pageSize);
        var total   = await _repo.CountByWebSourceAsync(webSource);

        return Ok(ApiResponse<object>.Ok(new
        {
            webSource,
            records  = records.Select(ToDto),
            total,
            page,
            pageSize,
            pages = (int)Math.Ceiling((double)total / pageSize)
        }));
    }

    // ── GET /api/audit/report ─────────────────────────────────────────────────
    // Search + Filter สำหรับ Audit Report
    // GET /api/audit/report?from=2026-04-01&to=2026-04-30&webSource=bt_qc-d...&role=Reviewer
    [HttpGet("report")]
    public async Task<IActionResult> GetReport(
        [FromQuery] string?   referenceId  = null,
        [FromQuery] string?   username     = null,
        [FromQuery] string?   role         = null,
        [FromQuery] string?   webSource    = null,
        [FromQuery] string?   documentType = null,
        [FromQuery] DateTime? from         = null,
        [FromQuery] DateTime? to           = null,
        [FromQuery] int       page         = 1,
        [FromQuery] int       pageSize     = 50)
    {
        var query = new AuditSearchQuery
        {
            ReferenceId  = referenceId,
            SignedByUser = username,
            SignerRole   = role,
            WebSource    = webSource,
            DocumentType = documentType,
            From         = from,
            To           = to ?? DateTime.UtcNow,
            Page         = page,
            PageSize     = Math.Min(pageSize, 200) // max 200 per page
        };

        var records = await _repo.SearchAsync(query);

        _logger.LogInformation("Audit report: Filters={@Query}, Count={Count}, By={User}",
            query, records.Count, User.Identity?.Name);

        return Ok(ApiResponse<object>.Ok(new
        {
            filters = query,
            records = records.Select(ToDto),
            total   = records.Count,
            page,
            pageSize
        }));
    }

    // ── GET /api/audit/{id} ───────────────────────────────────────────────────
    // ดูรายละเอียด Audit record ตาม ID
    [HttpGet("{id:long}")]
    public async Task<IActionResult> GetById(long id)
    {
        var record = await _repo.GetByIdAsync(id);
        if (record == null)
            return NotFound(ApiResponse<object>.Fail($"Audit record {id} not found."));

        return Ok(ApiResponse<object>.Ok(ToDto(record)));
    }

    // ── POST /api/audit/{id}/revoke ───────────────────────────────────────────
    // ยกเลิกลายเซ็น (Revoke)
    [HttpPost("{id:long}/revoke")]
    public async Task<IActionResult> Revoke(long id, [FromBody] RevokeRequest request)
    {
        if (string.IsNullOrEmpty(request.Reason))
            return BadRequest(ApiResponse<object>.Fail("Revocation reason is required."));

        var success = await _repo.RevokeAsync(id, request.Reason);
        if (!success)
            return NotFound(ApiResponse<object>.Fail($"Audit record {id} not found."));

        _logger.LogWarning("Signature revoked. Id={Id}, Reason={Reason}, By={User}",
            id, request.Reason, User.Identity?.Name);

        return Ok(ApiResponse<object>.Ok(new { id, revoked = true, reason = request.Reason }));
    }

    // ── Mapper ────────────────────────────────────────────────────────────────
    private static object ToDto(SignatureAudit r) => new
    {
        r.Id,
        r.ReferenceId,
        r.SignedByUser,
        r.SignerFullName,
        r.SignerRole,
        r.SignedByCert,
        r.CertThumbprint,
        r.CertExpiry,
        r.SignedAt,
        r.DataHash,
        r.SignatureType,
        r.Purpose,
        r.Department,
        r.Remarks,
        r.DocumentType,
        r.WebSource,
        r.IpAddress,
        r.IsRevoked,
        r.RevokedAt,
        r.RevocationReason
    };
}

public class RevokeRequest
{
    public string Reason { get; set; } = string.Empty;
}
