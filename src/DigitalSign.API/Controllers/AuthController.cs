using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using DigitalSign.Core.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;

namespace DigitalSign.API.Controllers;

/// <summary>
/// Auth — ออก JWT Token สำหรับ Intranet (ใช้แทน Azure AD ในกรณีที่ไม่มี)
/// </summary>
[ApiController]
[Route("api/[controller]")]
[Produces("application/json")]
public class AuthController : ControllerBase
{
    private readonly IConfiguration _config;
    private readonly ILogger<AuthController> _logger;

    // !! ใน Production ให้เชื่อมกับ AD / database แทน hard-coded list !!
    private static readonly Dictionary<string, string> _devUsers = new()
    {
        { "admin",    "Admin@1234" },
        { "signuser", "Sign@1234"  }
    };

    public AuthController(IConfiguration config, ILogger<AuthController> logger)
    {
        _config = config;
        _logger = logger;
    }

    /// <summary>
    /// ขอ JWT Token (สำหรับ Development / Intranet ที่ไม่ใช้ Azure AD)
    /// ใน Production ให้ใช้ AddMicrosoftIdentityWebApi แทน
    /// </summary>
    [HttpPost("token")]
    [AllowAnonymous]
    [ProducesResponseType(typeof(ApiResponse<TokenResult>), 200)]
    [ProducesResponseType(401)]
    public IActionResult GetToken([FromBody] TokenRequest request)
    {
        // ตรวจสอบ user (Dev mode — ใน Prod เชื่อม AD)
        if (!_devUsers.TryGetValue(request.Username, out var expectedPwd)
            || expectedPwd != request.Password)
        {
            _logger.LogWarning("Failed login attempt for user: {User}", request.Username);
            return Unauthorized(ApiResponse<TokenResult>.Fail("Invalid username or password."));
        }

        var token = GenerateJwtToken(request.Username);
        _logger.LogInformation("Token issued for user: {User}", request.Username);

        return Ok(ApiResponse<TokenResult>.Ok(token, "Token issued successfully."));
    }

    /// <summary>ตรวจสอบว่า Token ยังใช้งานได้ (ping)</summary>
    [HttpGet("ping")]
    [Authorize]
    public IActionResult Ping()
        => Ok(new { user = User.Identity?.Name, valid = true, time = DateTime.UtcNow });

    private TokenResult GenerateJwtToken(string username)
    {
        var jwtConfig  = _config.GetSection("Jwt");
        var secretKey  = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtConfig["SecretKey"]!));
        var creds      = new SigningCredentials(secretKey, SecurityAlgorithms.HmacSha256);
        var expiryMins = int.TryParse(jwtConfig["ExpiryMinutes"], out var m) ? m : 480;
        var expiry     = DateTime.UtcNow.AddMinutes(expiryMins);

        var claims = new[]
        {
            new Claim(ClaimTypes.Name,           username),
            new Claim(ClaimTypes.NameIdentifier, username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
            new Claim(JwtRegisteredClaimNames.Iat,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64)
        };

        var token = new JwtSecurityToken(
            issuer:             jwtConfig["Issuer"],
            audience:           jwtConfig["Audience"],
            claims:             claims,
            notBefore:          DateTime.UtcNow,
            expires:            expiry,
            signingCredentials: creds);

        return new TokenResult
        {
            AccessToken = new JwtSecurityTokenHandler().WriteToken(token),
            Expiry      = expiry,
            TokenType   = "Bearer"
        };
    }
}
