using DigitalSign.Core.Models;
using DigitalSign.Data.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DigitalSign.API.Controllers;

/// <summary>
/// Signature Audit Log — ประวัติการ Sign ทั้งหมด
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
[Produces("application/json")]
public class AuditController : ControllerBase
{
    private readonly ISignatureAuditRepository _auditRepo;
    private readonly ILogger<AuditController> _logger;

    public AuditController(ISignatureAuditRepository auditRepo, ILogger<AuditController> logger)
    {
        _auditRepo = auditRepo;
        _logger    = logger;
    }

    /// <summary>ดูประวัติ Sign จาก ReferenceId</summary>
    [HttpGet("reference/{referenceId}")]
    public async Task<IActionResult> GetByReference(string referenceId)
    {
        var records = await _auditRepo.GetByReferenceIdAsync(referenceId);
        return Ok(ApiResponse<object>.Ok(records));
    }

    /// <summary>ดูประวัติ Sign ของ User ที่ Login อยู่ (paged)</summary>
    [HttpGet("my")]
    public async Task<IActionResult> GetMy([FromQuery] int page = 1, [FromQuery] int pageSize = 20)
    {
        var username = User.Identity?.Name ?? "";
        var records  = await _auditRepo.GetByUserAsync(username, page, pageSize);
        var total    = await _auditRepo.CountByUserAsync(username);

        return Ok(ApiResponse<object>.Ok(new
        {
            Records  = records,
            Total    = total,
            Page     = page,
            PageSize = pageSize,
            Pages    = (int)Math.Ceiling((double)total / pageSize)
        }));
    }

    /// <summary>ดูรายละเอียด Audit record จาก Id</summary>
    [HttpGet("{id:long}")]
    public async Task<IActionResult> GetById(long id)
    {
        var record = await _auditRepo.GetByIdAsync(id);
        if (record == null)
            return NotFound(ApiResponse<object>.Fail($"Audit record {id} not found."));

        return Ok(ApiResponse<object>.Ok(record));
    }

    /// <summary>Revoke signature (ยกเลิก / ไม่ลบ)</summary>
    [HttpPost("{id:long}/revoke")]
    public async Task<IActionResult> Revoke(long id, [FromBody] RevokeRequest request)
    {
        var success = await _auditRepo.RevokeAsync(id, request.Reason);
        if (!success)
            return NotFound(ApiResponse<object>.Fail($"Audit record {id} not found."));

        _logger.LogWarning("Signature {Id} revoked by {User}. Reason: {Reason}",
            id, User.Identity?.Name, request.Reason);

        return Ok(ApiResponse<object>.Ok(new { Revoked = true, Id = id }));
    }
}

public class RevokeRequest
{
    public string Reason { get; set; } = string.Empty;
}
