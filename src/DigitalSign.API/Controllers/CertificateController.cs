using DigitalSign.Core.Models;
using DigitalSign.Core.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DigitalSign.API.Controllers;

/// <summary>
/// Certificate Management — ดูข้อมูล Certificate ที่ใช้งาน
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
[Produces("application/json")]
public class CertificateController : ControllerBase
{
    private readonly ICertificateService _certService;
    private readonly ILogger<CertificateController> _logger;

    public CertificateController(ICertificateService certService, ILogger<CertificateController> logger)
    {
        _certService = certService;
        _logger      = logger;
    }

    /// <summary>ดูข้อมูล Certificate ที่ configure ไว้ (default thumbprint)</summary>
    [HttpGet("info")]
    [ProducesResponseType(typeof(ApiResponse<CertificateInfo>), 200)]
    public IActionResult GetInfo()
    {
        try
        {
            var info = _certService.GetCertificateInfo();
            return Ok(ApiResponse<CertificateInfo>.Ok(info));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get certificate info.");
            return StatusCode(500, ApiResponse<CertificateInfo>.Fail(ex.Message));
        }
    }

    /// <summary>ดูข้อมูล Certificate จาก thumbprint ที่ระบุ</summary>
    [HttpGet("info/{thumbprint}")]
    [ProducesResponseType(typeof(ApiResponse<CertificateInfo>), 200)]
    [ProducesResponseType(404)]
    public IActionResult GetInfoByThumbprint(string thumbprint)
    {
        try
        {
            var info = _certService.GetCertificateInfo(thumbprint);
            return Ok(ApiResponse<CertificateInfo>.Ok(info));
        }
        catch (CertificateNotFoundException)
        {
            return NotFound(ApiResponse<CertificateInfo>.Fail($"Certificate '{thumbprint}' not found."));
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Failed to get certificate by thumbprint {Thumbprint}.", thumbprint);
            return StatusCode(500, ApiResponse<CertificateInfo>.Fail(ex.Message));
        }
    }

    /// <summary>ตรวจสอบว่า Certificate ยังใช้งานได้หรือไม่</summary>
    [HttpGet("health")]
    [AllowAnonymous]
    [ProducesResponseType(200)]
    [ProducesResponseType(503)]
    public IActionResult Health()
    {
        try
        {
            var info = _certService.GetCertificateInfo();
            if (!info.IsValid)
                return StatusCode(503, new { status = "unhealthy", reason = "Certificate is expired.", expiry = info.NotAfter });

            if (info.DaysUntilExpiry <= 30)
                return Ok(new { status = "warning", reason = $"Certificate expires in {info.DaysUntilExpiry} days.", expiry = info.NotAfter });

            return Ok(new { status = "healthy", expiry = info.NotAfter, daysRemaining = info.DaysUntilExpiry });
        }
        catch (Exception ex)
        {
            return StatusCode(503, new { status = "unhealthy", reason = ex.Message });
        }
    }
}
