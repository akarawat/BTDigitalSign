using DigitalSign.Core.Models;
using DigitalSign.Core.Services;
using DigitalSign.Data.Entities;
using DigitalSign.Data.Repositories;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DigitalSign.API.Controllers;

[ApiController]
[Route("api/[controller]")]
[Authorize]
[Produces("application/json")]
public class PdfController : ControllerBase
{
    private readonly IPdfSignService _pdfSignService;
    private readonly ISignatureAuditRepository _auditRepo;
    private readonly ILogger<PdfController> _logger;

    public PdfController(IPdfSignService pdfSignService,
    ISignatureAuditRepository auditRepo,
    ILogger<PdfController> logger)
    {
        _pdfSignService = pdfSignService;
        _auditRepo = auditRepo;
        _logger = logger;
    }

    /// <summary>ฝัง Digital Signature ลงใน PDF (รับ/คืน Base64)</summary>
    [HttpPost("sign")]
    [ProducesResponseType(typeof(ApiResponse<PdfSignResult>), 200)]
    [ProducesResponseType(400)]
    [RequestSizeLimit(52_428_800)] // 50 MB
    public async Task<IActionResult> SignPdf([FromBody] PdfSignRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ApiResponse<PdfSignResult>.Fail("Invalid request parameters."));

        var username = User.Identity?.Name ?? "unknown";
        var result = await _pdfSignService.SignPdfAsync(request, username);

        if (!result.IsSuccess)
            return StatusCode(500, ApiResponse<PdfSignResult>.Fail(result.ErrorMessage ?? "PDF signing failed."));
        await SaveAuditAsync(request, result, username);

        return Ok(ApiResponse<PdfSignResult>.Ok(result, "PDF signed successfully."));
    }

    /// <summary>ฝัง Digital Signature และคืน PDF file โดยตรง (download)</summary>
    [HttpPost("sign/download")]
    [ProducesResponseType(typeof(FileContentResult), 200)]
    [ProducesResponseType(400)]
    [RequestSizeLimit(52_428_800)]
    public async Task<IActionResult> SignPdfDownload([FromBody] PdfSignRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest("Invalid request parameters.");

        var username = User.Identity?.Name ?? "unknown";
        var result = await _pdfSignService.SignPdfAsync(request, username);

        if (!result.IsSuccess)
            return StatusCode(500, result.ErrorMessage);
        await SaveAuditAsync(request, result, username);
        var bytes = Convert.FromBase64String(result.PdfBase64);
        var fileName = $"signed_{request.DocumentName}_{DateTime.Now:yyyyMMddHHmmss}.pdf";

        return File(bytes, "application/pdf", fileName);
    }

    /// <summary>ตรวจสอบ Digital Signature ใน PDF</summary>
    [HttpPost("verify")]
    [ProducesResponseType(typeof(ApiResponse<VerifyResult>), 200)]
    [ProducesResponseType(400)]
    [RequestSizeLimit(52_428_800)]
    public async Task<IActionResult> VerifyPdf([FromBody] VerifyPdfRequest request)
    {
        if (string.IsNullOrEmpty(request.PdfBase64))
            return BadRequest(ApiResponse<VerifyResult>.Fail("PdfBase64 is required."));

        var result = await _pdfSignService.VerifyPdfSignatureAsync(request.PdfBase64);
        return Ok(ApiResponse<VerifyResult>.Ok(result,
            result.IsSignatureValid ? "PDF signature is valid." : "PDF signature is invalid."));
    }
    // ── Private: Save Audit Log ───────────────────────────────────────────────
    private async Task SaveAuditAsync(PdfSignRequest request, PdfSignResult result, string username)
    {
        try
        {
            // ดึง IP Address จาก Request
            var ip = HttpContext.Connection.RemoteIpAddress?.ToString();

            // ใช้ SignerUsername จาก request ถ้ามี (Double-Hop fix)
            var effectiveUser = !string.IsNullOrEmpty(request.SignerUsername)
                ? request.SignerUsername
                : username;

            var audit = new SignatureAudit
            {
                ReferenceId = request.ReferenceId,
                SignedByUser = effectiveUser,
                SignerFullName = request.SignerFullName,   // Sakulchai Panwilai
                SignerRole = request.SignerRole,       // Reviewer, Approver
                SignedByCert = result.SignedBy,
                CertThumbprint = request.CertThumbprint ?? string.Empty,
                CertExpiry = result.SignedAt.AddYears(2), // fallback
                SignedAt = result.SignedAt,
                DataHash = result.ReferenceId,       // ใช้ ReferenceId เป็น hash key
                SignatureHash = result.ReferenceId,
                SignatureType = "PDF-RSA-SHA256",
                Purpose = request.Reason,
                DocumentType = request.DocumentType,    // WorkInstruction, PO, DAR
                WebSource = request.WebSource,       // bt_qc-d.berninathailand.com
                IpAddress = ip
            };

            await _auditRepo.AddAsync(audit);

            _logger.LogInformation(
                "PDF Audit saved. Ref={Ref}, User={User}, Role={Role}, Web={Web}, Doc={Doc}",
                request.ReferenceId, effectiveUser,
                request.SignerRole, request.WebSource, request.DocumentType);
        }
        catch (Exception ex)
        {
            // Log แต่ไม่ throw — signing สำเร็จแล้ว audit ล้มเหลวไม่ควรทำให้ response fail
            _logger.LogError(ex, "Failed to save PDF audit. Ref={Ref}", request.ReferenceId);
        }
    }
}

public class VerifyPdfRequest
{
    public string PdfBase64 { get; set; } = string.Empty;
}
