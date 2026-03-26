using DigitalSign.Core.Models;
using DigitalSign.Core.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DigitalSign.API.Controllers;

/// <summary>
/// PDF Digital Signature — Sign and Verify PDF documents
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
[Produces("application/json")]
public class PdfController : ControllerBase
{
    private readonly IPdfSignService _pdfSignService;
    private readonly ILogger<PdfController> _logger;

    public PdfController(IPdfSignService pdfSignService, ILogger<PdfController> logger)
    {
        _pdfSignService = pdfSignService;
        _logger         = logger;
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
        var result   = await _pdfSignService.SignPdfAsync(request, username);

        if (!result.IsSuccess)
            return StatusCode(500, ApiResponse<PdfSignResult>.Fail(result.ErrorMessage ?? "PDF signing failed."));

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
        var result   = await _pdfSignService.SignPdfAsync(request, username);

        if (!result.IsSuccess)
            return StatusCode(500, result.ErrorMessage);

        var bytes    = Convert.FromBase64String(result.PdfBase64);
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
}

public class VerifyPdfRequest
{
    public string PdfBase64 { get; set; } = string.Empty;
}
