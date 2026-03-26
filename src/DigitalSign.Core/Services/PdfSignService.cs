using DigitalSign.Core.Models;
using iText.Bouncycastle.Crypto;        // PrivateKeyBC  ← ชื่อที่ถูกต้อง
using iText.Bouncycastle.X509;         // X509CertificateBC
using iText.Commons.Bouncycastle.Cert; // IX509Certificate
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Security;

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

    public async Task<PdfSignResult> SignPdfAsync(PdfSignRequest request, string signerUsername)
    {
        try
        {
            var pdfBytes   = Convert.FromBase64String(request.PdfBase64);
            var cert       = _certService.GetSigningCertificate(request.CertThumbprint);

            // แปลง .NET X509Certificate2 → BouncyCastle
            var bcCert     = DotNetUtilities.FromX509Certificate(cert);
            var privateKey = DotNetUtilities.GetKeyPair(cert.GetRSAPrivateKey()!).Private;

            // PrivateKeyBC รับ ICipherParameters (AsymmetricKeyParameter implement ICipherParameters อยู่แล้ว)
            IExternalSignature pks   = new PrivateKeySignature(new PrivateKeyBC(privateKey), DigestAlgorithms.SHA256);
            IX509Certificate[] chain = [new X509CertificateBC(bcCert)];

            using var inputMs  = new MemoryStream(pdfBytes);
            using var outputMs = new MemoryStream();

            var reader = new PdfReader(inputMs);
            var signer = new PdfSigner(reader, outputMs, new StampingProperties().UseAppendMode());

            // กำหนดรูปแบบ signature ที่แสดงบนหน้า PDF
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

            // ฝัง Digital Signature แบบ CMS
            signer.SignDetached(pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);

            var signedBytes = outputMs.ToArray();

            _logger.LogInformation("PDF signed. Doc={Doc}, Ref={Ref}, By={User}",
                request.DocumentName, request.ReferenceId, signerUsername);

            return await Task.FromResult(new PdfSignResult
            {
                IsSuccess    = true,
                PdfBase64    = Convert.ToBase64String(signedBytes),
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

            // IX509Certificate ไม่มี property NotAfter / method IsValid() โดยตรง
            // ต้อง cast → X509CertificateBC แล้ว .GetCertificate()
            // เพื่อได้ Org.BouncyCastle.X509.X509Certificate ซึ่งมี .NotAfter, .IsValid(), .SubjectDN
            var signerCertI = pkcs7.GetSigningCertificate();
            var bcX509      = ((X509CertificateBC)signerCertI).GetCertificate();

            bool certValid  = bcX509.IsValid(DateTime.UtcNow);
            var  certExpiry = bcX509.NotAfter;
            var  signedBy   = bcX509.SubjectDN.ToString();

            _logger.LogInformation(
                "PDF verify: SigName={Name}, SigValid={SigValid}, CertValid={CertValid}, By={By}",
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
