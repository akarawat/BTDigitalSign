using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DigitalSign.Core.Models;
using DigitalSign.Data.Entities;
using DigitalSign.Data.Repositories;
using Microsoft.Extensions.Logging;

namespace DigitalSign.Core.Services;

public interface ISigningService
{
    Task<SignResult>  SignDataAsync(SignRequest request, string signerUsername);
    VerifyResult      VerifySignature(VerifyRequest request);
}

public class SigningService : ISigningService
{
    private readonly ICertificateService      _certService;
    private readonly ISignatureAuditRepository _auditRepo;
    private readonly ILogger<SigningService>  _logger;

    public SigningService(
        ICertificateService certService,
        ISignatureAuditRepository auditRepo,
        ILogger<SigningService> logger)
    {
        _certService = certService;
        _auditRepo   = auditRepo;
        _logger      = logger;
    }

    public async Task<SignResult> SignDataAsync(SignRequest request, string signerUsername)
    {
        try
        {
            var cert = _certService.GetSigningCertificate(request.CertThumbprint);

            // ตรวจสอบ private key
            using var rsa = cert.GetRSAPrivateKey()
                ?? throw new InvalidOperationException("Certificate does not contain a private key.");

            // สร้าง Digital Signature: RSA + SHA-256 + PKCS1
            var dataBytes  = Encoding.UTF8.GetBytes(request.DataToSign);
            var signature  = rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            var dataHash   = ComputeSha256Hex(dataBytes);
            var sigHash    = ComputeSha256Hex(signature);

            var result = new SignResult
            {
                IsSuccess       = true,
                SignatureBase64 = Convert.ToBase64String(signature),
                SignedBy        = cert.Subject,
                SignedAt        = DateTime.UtcNow,
                CertThumbprint  = cert.Thumbprint,
                CertExpiry      = cert.NotAfter,
                DataHash        = dataHash,
                ReferenceId     = request.ReferenceId
            };

            // บันทึก Audit Log
            await _auditRepo.AddAsync(new SignatureAudit
            {
                ReferenceId    = request.ReferenceId,
                SignedByUser   = signerUsername,
                SignedByCert   = cert.Subject,
                SignedAt       = result.SignedAt,
                Purpose        = request.Purpose,
                Department     = request.Department,
                Remarks        = request.Remarks,
                DataHash       = dataHash,
                SignatureHash  = sigHash,
                CertThumbprint = cert.Thumbprint,
                CertExpiry     = cert.NotAfter,
                SignatureType  = "RSA-SHA256",
                IsRevoked      = false
            });

            _logger.LogInformation("Signed successfully. Ref={ReferenceId}, By={User}", request.ReferenceId, signerUsername);
            return result;
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Signing failed. Ref={ReferenceId}", request.ReferenceId);
            return new SignResult { IsSuccess = false, ErrorMessage = ex.Message, ReferenceId = request.ReferenceId };
        }
    }

    public VerifyResult VerifySignature(VerifyRequest request)
    {
        try
        {
            var cert = _certService.GetSigningCertificate(request.CertThumbprint);
            using var rsa = cert.GetRSAPublicKey()
                ?? throw new InvalidOperationException("Cannot get public key from certificate.");

            var dataBytes = Encoding.UTF8.GetBytes(request.OriginalData);
            var sigBytes  = Convert.FromBase64String(request.SignatureBase64);

            bool sigValid  = rsa.VerifyData(dataBytes, sigBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
            bool certValid = _certService.IsCertificateValid(cert);

            _logger.LogInformation("Verify: SigValid={SigValid}, CertValid={CertValid}", sigValid, certValid);

            return new VerifyResult
            {
                IsSignatureValid   = sigValid,
                IsCertificateValid = certValid,
                SignedBy           = cert.Subject,
                CertExpiry         = cert.NotAfter,
                VerifiedAt         = DateTime.UtcNow
            };
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "Verification failed.");
            return new VerifyResult
            {
                IsSignatureValid   = false,
                IsCertificateValid = false,
                ErrorMessage       = ex.Message,
                VerifiedAt         = DateTime.UtcNow
            };
        }
    }

    private static string ComputeSha256Hex(byte[] data)
        => Convert.ToHexString(SHA256.HashData(data)).ToLowerInvariant();
}
