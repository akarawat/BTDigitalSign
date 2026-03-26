using DigitalSign.Core.Models;
using iTextSharp.text;
using iTextSharp.text.pdf;
using iTextSharp.text.pdf.security;
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
    private readonly ICertificateService    _certService;
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
            // แปลง Base64 → byte[]
            var pdfBytes = Convert.FromBase64String(request.PdfBase64);

            var cert = _certService.GetSigningCertificate(request.CertThumbprint);

            // แปลง .NET cert → BouncyCastle format
            var bcCert     = DotNetUtilities.FromX509Certificate(cert);
            var privateKey = DotNetUtilities.GetKeyPair(cert.GetRSAPrivateKey()!).Private;
            var chain      = new[] { bcCert };

            using var inputMs  = new MemoryStream(pdfBytes);
            using var outputMs = new MemoryStream();

            var reader  = new PdfReader(inputMs);
            var stamper = PdfStamper.CreateSignature(reader, outputMs, '\0', null, true);

            // กำหนดลักษณะ Signature ที่แสดงบน PDF
            var appearance = stamper.SignatureAppearance;
            appearance.Reason   = request.Reason;
            appearance.Location = request.Location;
            appearance.SignatureCreator = $"BTDigitalSign - {signerUsername}";

            // ตำแหน่งกล่อง signature (หน่วย: points, 1 pt = 1/72 นิ้ว)
            appearance.SetVisibleSignature(
                new iTextSharp.text.Rectangle(
                    request.SignatureX,
                    request.SignatureY,
                    request.SignatureX + request.SignatureWidth,
                    request.SignatureY + request.SignatureHeight),
                request.SignaturePage,
                $"Signature_{request.ReferenceId}");

            // ฝัง Digital Signature แบบ CMS/PAdES
            IExternalSignature pks = new PrivateKeySignature(privateKey, DigestAlgorithms.SHA256);
            MakeSignature.SignDetached(
                appearance, pks, chain,
                null, null, null, 0,
                CryptoStandard.CMS);

            stamper.Close();
            reader.Close();

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
                IsSuccess   = false,
                ReferenceId = request.ReferenceId,
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

            var af      = reader.AcroFields;
            var sigNames = af.GetSignatureNames();

            if (sigNames.Count == 0)
                return new VerifyResult { IsSignatureValid = false, ErrorMessage = "No signatures found in PDF." };

            // ตรวจสอบ signature แรก
            var sigName = sigNames[0];
            var pkcs7   = af.VerifySignature(sigName);

            bool sigValid  = pkcs7.Verify();
            var  cert      = pkcs7.SigningCertificate;
            bool certValid = cert.IsValid(DateTime.UtcNow.ToUniversalTime().Ticks);

            return await Task.FromResult(new VerifyResult
            {
                IsSignatureValid   = sigValid,
                IsCertificateValid = certValid,
                SignedBy           = cert.SubjectDN.ToString(),
                CertExpiry         = cert.NotAfter,
                VerifiedAt         = DateTime.UtcNow
            });
        }
        catch (Exception ex)
        {
            _logger.LogError(ex, "PDF verify failed.");
            return new VerifyResult { IsSignatureValid = false, ErrorMessage = ex.Message };
        }
    }
}
