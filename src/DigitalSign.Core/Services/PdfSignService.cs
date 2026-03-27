using System.Security.Cryptography;                    // RSA, GetRSAPrivateKey()
using System.Security.Cryptography.X509Certificates;  // X509Certificate2

using DigitalSign.Core.Models;
using iText.Bouncycastle.Crypto;        // PrivateKeyBC
using iText.Bouncycastle.X509;         // X509CertificateBC
using iText.Commons.Bouncycastle.Cert; // IX509Certificate
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Security;       // DotNetUtilities

namespace DigitalSign.Core.Services;

public interface IPdfSignService
{
    Task<PdfSignResult> SignPdfAsync(PdfSignRequest request, string signerUsername);
    Task<VerifyResult>  VerifyPdfSignatureAsync(string pdfBase64);
}

public class PdfSignService : IPdfSignService
{
    private readonly ICertificateService     _certService;
    private readonly ILogger<PdfSignService> _logger;

    public PdfSignService(ICertificateService certService, ILogger<PdfSignService> logger)
    {
        _certService = certService;
        _logger      = logger;
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Sign PDF
    // ─────────────────────────────────────────────────────────────────────────
    public async Task<PdfSignResult> SignPdfAsync(PdfSignRequest request, string signerUsername)
    {
        try
        {
            var pdfBytes = Convert.FromBase64String(request.PdfBase64);

            // ระบุ type ชัดเจนเพื่อหลีกเลี่ยง namespace conflict กับ iText.Bouncycastle.X509
            System.Security.Cryptography.X509Certificates.X509Certificate2 cert
                = _certService.GetSigningCertificate(request.CertThumbprint);

            // .NET X509Certificate2 → BouncyCastle
            var bcCert = DotNetUtilities.FromX509Certificate(cert);

            // ดึง RSA private key — ต้องมี using System.Security.Cryptography จึงเจอ method นี้
            using RSA rsa        = cert.GetRSAPrivateKey()
                ?? throw new InvalidOperationException("Certificate has no RSA private key.");
            var privateKey       = DotNetUtilities.GetKeyPair(rsa).Private;

            IExternalSignature pks   = new PrivateKeySignature(new PrivateKeyBC(privateKey), DigestAlgorithms.SHA256);
            IX509Certificate[] chain = [new X509CertificateBC(bcCert)];

            using var inputMs  = new MemoryStream(pdfBytes);
            using var outputMs = new MemoryStream();

            var reader = new PdfReader(inputMs);
            var signer = new PdfSigner(reader, outputMs, new StampingProperties().UseAppendMode());

            var appearance = signer.GetSignatureAppearance();
            appearance
                .SetReason(request.Reason)
                .SetLocation(request.Location)
                .SetPageNumber(request.SignaturePage)
                .SetPageRect(new Rectangle(
                    request.SignatureX,
                    request.SignatureY,
                    request.SignatureWidth,
                    request.SignatureHeight));

            signer.SetFieldName($"Sig_{request.ReferenceId}_{DateTime.UtcNow:yyyyMMddHHmmss}");
            signer.SetCertificationLevel(PdfSigner.NOT_CERTIFIED);
            signer.SignDetached(pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);

            _logger.LogInformation("PDF signed. Doc={Doc}, Ref={Ref}, By={User}",
                request.DocumentName, request.ReferenceId, signerUsername);

            return await Task.FromResult(new PdfSignResult
            {
                IsSuccess    = true,
                PdfBase64    = Convert.ToBase64String(outputMs.ToArray()),
                DocumentName = request.DocumentName,
                ReferenceId  = request.ReferenceId,
                SignedBy     = cert.Subject,
                SignedAt     = DateTime.UtcNow
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PDF signing failed. Ref={Ref}", request.ReferenceId);
            return new PdfSignResult
            {
                IsSuccess    = false,
                ReferenceId  = request.ReferenceId,
                ErrorMessage = ex.Message
            };
        }
    }

    // ─────────────────────────────────────────────────────────────────────────
    // Verify PDF
    // ─────────────────────────────────────────────────────────────────────────
    public async Task<VerifyResult> VerifyPdfSignatureAsync(string pdfBase64)
    {
        try
        {
            var pdfBytes = Convert.FromBase64String(pdfBase64);

            using var ms     = new MemoryStream(pdfBytes);
            using var reader = new PdfReader(ms);
            using var pdfDoc = new PdfDocument(reader);

            var signUtil = new SignatureUtil(pdfDoc);
            var sigNames = signUtil.GetSignatureNames();

            if (sigNames.Count == 0)
                return new VerifyResult
                {
                    IsSignatureValid = false,
                    ErrorMessage     = "No digital signatures found in this PDF.",
                    VerifiedAt       = DateTime.UtcNow
                };

            var  sigName  = sigNames[0];
            var  pkcs7    = signUtil.ReadSignatureData(sigName);
            bool sigValid = pkcs7.VerifySignatureIntegrityAndAuthenticity();

            // cast IX509Certificate → X509CertificateBC → Org.BouncyCastle.X509.X509Certificate
            // เพื่อเข้าถึง .NotAfter, .IsValid(), .SubjectDN
            var signerCertI = pkcs7.GetSigningCertificate();
            var bcX509      = ((X509CertificateBC)signerCertI).GetCertificate();

            bool certValid  = bcX509.IsValid(DateTime.UtcNow);
            var  certExpiry = bcX509.NotAfter;
            var  signedBy   = bcX509.SubjectDN.ToString();

            _logger.LogInformation(
                "PDF verify: Sig={Name}, SigOK={SigValid}, CertOK={CertValid}, By={By}",
                sigName, sigValid, certValid, signedBy);

            return await Task.FromResult(new VerifyResult
            {
                IsSignatureValid   = sigValid,
                IsCertificateValid = certValid,
                SignedBy           = signedBy,
                CertExpiry         = certExpiry,
                VerifiedAt         = DateTime.UtcNow
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PDF verify failed.");
            return new VerifyResult
            {
                IsSignatureValid = false,
                ErrorMessage     = ex.Message,
                VerifiedAt       = DateTime.UtcNow
            };
        }
    }
}
