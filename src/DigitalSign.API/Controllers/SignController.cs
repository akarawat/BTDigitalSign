using DigitalSign.Core.Models;
using DigitalSign.Core.Services;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;

namespace DigitalSign.API.Controllers;

/// <summary>
/// Digital Signature — Sign and Verify data
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Authorize]
[Produces("application/json")]
public class SignController : ControllerBase
{
    private readonly ISigningService _signingService;
    private readonly ILogger<SignController> _logger;

    public SignController(ISigningService signingService, ILogger<SignController> logger)
    {
        _signingService = signingService;
        _logger         = logger;
    }

    /// <summary>สร้าง Digital Signature จาก string data</summary>
    [HttpPost]
    [ProducesResponseType(typeof(ApiResponse<SignResult>), 200)]
    [ProducesResponseType(400)]
    [ProducesResponseType(401)]
    public async Task<IActionResult> Sign([FromBody] SignRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ApiResponse<SignResult>.Fail("Invalid request parameters."));

        var username = User.Identity?.Name ?? "unknown";
        var result   = await _signingService.SignDataAsync(request, username);

        if (!result.IsSuccess)
            return StatusCode(500, ApiResponse<SignResult>.Fail(result.ErrorMessage ?? "Signing failed."));

        return Ok(ApiResponse<SignResult>.Ok(result, "Signed successfully."));
    }

    /// <summary>ตรวจสอบ Digital Signature</summary>
    [HttpPost("verify")]
    [ProducesResponseType(typeof(ApiResponse<VerifyResult>), 200)]
    [ProducesResponseType(400)]
    public IActionResult Verify([FromBody] VerifyRequest request)
    {
        if (!ModelState.IsValid)
            return BadRequest(ApiResponse<VerifyResult>.Fail("Invalid request parameters."));

        var result = _signingService.VerifySignature(request);
        return Ok(ApiResponse<VerifyResult>.Ok(result,
            result.IsOverallValid ? "Signature is valid." : "Signature verification failed."));
    }
}
