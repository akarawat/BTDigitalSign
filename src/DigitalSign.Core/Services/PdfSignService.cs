using System.Security.Cryptography.X509Certificates;
using DigitalSign.Core.Models;
using iText.Bouncycastle.Crypto;
using iText.Bouncycastle.X509;
using iText.Commons.Bouncycastle.Cert;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Pkcs;
using Org.BouncyCastle.Security;

namespace DigitalSign.Core.Services;

public interface IPdfSignService
{
    Task<PdfSignResult>  SignPdfAsync(PdfSignRequest request, string signerUsername);
    Task<VerifyResult>   VerifyPdfSignatureAsync(string pdfBase64);
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
            var pdfBytes = Convert.FromBase64String(request.PdfBase64);
            var cert     = _certService.GetSigningCertificate(request.CertThumbprint);

            // แปลง .NET X509 → BouncyCastle
            var bcCert     = DotNetUtilities.FromX509Certificate(cert);
            var privateKey = DotNetUtilities.GetKeyPair(cert.GetRSAPrivateKey()!).Private;

            // ห่อให้ itext7 เข้าใจ
            IExternalSignature pks   = new PrivateKeySignature(
                new BouncyCastleKey(privateKey), DigestAlgorithms.SHA256);

            IX509Certificate[] chain = [new X509CertificateBC(bcCert)];

            using var inputMs  = new MemoryStream(pdfBytes);
            using var outputMs = new MemoryStream();

            var reader  = new PdfReader(inputMs);
            var writer  = new PdfWriter(outputMs);
            var pdfDoc  = new PdfDocument(reader);
            var signer  = new PdfSigner(reader, outputMs, new StampingProperties().UseAppendMode());

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

            pdfDoc.Close();

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

            var signUtil  = new SignatureUtil(pdfDoc);
            var sigNames  = signUtil.GetSignatureNames();

            if (sigNames.Count == 0)
                return new VerifyResult
                {
                    IsSignatureValid = false,
                    ErrorMessage     = "No digital signatures found in this PDF.",
                    VerifiedAt       = DateTime.UtcNow
                };

            // ตรวจสอบ signature แรกที่พบ
            var sigName = sigNames[0];
            var pkcs7   = signUtil.ReadSignatureData(sigName);
            bool sigValid = pkcs7.VerifySignatureIntegrityAndAuthenticity();

            // ดึงข้อมูล certificate จาก signature
            var signerCert  = pkcs7.GetSigningCertificate();
            bool certValid  = signerCert.IsValid(DateTime.UtcNow);
            var  certExpiry = signerCert.NotAfter;
            var  signedBy   = signerCert.SubjectDN.ToString();

            _logger.LogInformation(
                "PDF verify: SigName={Name}, Valid={Valid}, Cert={Cert}",
                sigName, sigValid, signedBy);

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
