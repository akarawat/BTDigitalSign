using System.ComponentModel.DataAnnotations;

namespace DigitalSign.Core.Models;

// ── Request Models ────────────────────────────────────────────────────────────
public class SignRequest
{
    [Required]
    public string DataToSign { get; set; } = string.Empty;

    [Required]
    public string ReferenceId { get; set; } = string.Empty;

    public string? CertThumbprint { get; set; }

    [Required]
    public string Purpose { get; set; } = string.Empty;

    public string? Department { get; set; }
    public string? Remarks { get; set; }
}

public class VerifyRequest
{
    [Required]
    public string OriginalData { get; set; } = string.Empty;

    [Required]
    public string SignatureBase64 { get; set; } = string.Empty;

    [Required]
    public string CertThumbprint { get; set; } = string.Empty;
}

public class PdfSignRequest
{
    [Required] public string PdfBase64 { get; set; } = string.Empty;
    [Required] public string DocumentName { get; set; } = string.Empty;
    [Required] public string ReferenceId { get; set; } = string.Empty;
    public string? CertThumbprint { get; set; }
    public string Reason { get; set; } = "Approved";
    public string Location { get; set; } = "Bangkok, Thailand";
    public string? SignerUsername { get; set; } // ← username จาก Web App (Double-Hop fix)
    public int SignaturePage { get; set; } = 1;
    public float SignatureX { get; set; } = 36f;
    public float SignatureY { get; set; } = 36f;
    public float SignatureWidth { get; set; } = 200f;
    public float SignatureHeight { get; set; } = 60f;
    public string? SignerFullName { get; set; }  // "Sakulchai Panwilai"
    public string? SignerRole { get; set; }  // "Reviewer"
    public string? WebSource { get; set; }  // "bt_qc-d.berninathailand.com"
    public string? DocumentType { get; set; }  // "WorkInstruction"

}

public class TokenRequest
{
    [Required]
    public string Username { get; set; } = string.Empty;

    [Required]
    public string Password { get; set; } = string.Empty;
}

// ── Response Models ────────────────────────────────────────────────────────────

public class SignResult
{
    public bool IsSuccess { get; set; }
    public string SignatureBase64 { get; set; } = string.Empty;
    public string SignedBy { get; set; } = string.Empty;
    public DateTime SignedAt { get; set; }
    public string CertThumbprint { get; set; } = string.Empty;
    public DateTime CertExpiry { get; set; }
    public string DataHash { get; set; } = string.Empty;
    public string ReferenceId { get; set; } = string.Empty;
    public string? ErrorMessage { get; set; }
}

public class VerifyResult
{
    public bool IsSignatureValid { get; set; }
    public bool IsCertificateValid { get; set; }
    public bool IsOverallValid => IsSignatureValid && IsCertificateValid;
    public string SignedBy { get; set; } = string.Empty;
    public DateTime CertExpiry { get; set; }
    public DateTime VerifiedAt { get; set; }
    public string? ErrorMessage { get; set; }
}

public class PdfSignResult
{
    public bool IsSuccess { get; set; }
    public string PdfBase64 { get; set; } = string.Empty;
    public string DocumentName { get; set; } = string.Empty;
    public string ReferenceId { get; set; } = string.Empty;
    public string SignedBy { get; set; } = string.Empty;
    public DateTime SignedAt { get; set; }
    public string? ErrorMessage { get; set; }
}

public class TokenResult
{
    public string AccessToken { get; set; } = string.Empty;
    public DateTime Expiry { get; set; }
    public string TokenType { get; set; } = "Bearer";
}

public class CertificateInfo
{
    public string Subject { get; set; } = string.Empty;
    public string Thumbprint { get; set; } = string.Empty;
    public string Issuer { get; set; } = string.Empty;
    public DateTime NotBefore { get; set; }
    public DateTime NotAfter { get; set; }
    public bool IsValid { get; set; }
    public int DaysUntilExpiry => (int)(NotAfter - DateTime.UtcNow).TotalDays;
    public string KeyAlgorithm { get; set; } = string.Empty;
    public int KeySize { get; set; }
}

public class ApiResponse<T>
{
    public bool Success { get; set; }
    public T? Data { get; set; }
    public string? Message { get; set; }
    public DateTime Timestamp { get; set; } = DateTime.UtcNow;

    public static ApiResponse<T> Ok(T data, string? message = null)
        => new() { Success = true, Data = data, Message = message };

    public static ApiResponse<T> Fail(string message)
        => new() { Success = false, Message = message };
}