using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;

using DigitalSign.Core.Models;
using iText.Bouncycastle.X509;
using iText.Commons.Bouncycastle.Cert;
using iText.Kernel.Geom;
using iText.Kernel.Pdf;
using iText.Signatures;
using Microsoft.Extensions.Logging;
using Org.BouncyCastle.Security;

namespace DigitalSign.Core.Services;

// ─────────────────────────────────────────────────────────────────────────────
// Custom IExternalSignature — ใช้ .NET RSA โดยตรง ไม่ต้อง export private key
// ─────────────────────────────────────────────────────────────────────────────
internal sealed class DotNetRsaSignature : IExternalSignature
{
    private readonly RSA _rsa;
    public DotNetRsaSignature(RSA rsa) => _rsa = rsa;

    public string GetDigestAlgorithmName()                            => DigestAlgorithms.SHA256;
    public string GetSignatureAlgorithmName()                         => "RSA";
    public ISignatureMechanismParams? GetSignatureMechanismParameters() => null;

    public byte[] Sign(byte[] message)
        => _rsa.SignData(message, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);
}

// ─────────────────────────────────────────────────────────────────────────────

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
            var pdfBytes = Convert.FromBase64String(request.PdfBase64);

            System.Security.Cryptography.X509Certificates.X509Certificate2 cert
                = _certService.GetSigningCertificate(request.CertThumbprint);

            var bcCert = DotNetUtilities.FromX509Certificate(cert);
            IX509Certificate[] chain = [new X509CertificateBC(bcCert)];

            using RSA rsa = cert.GetRSAPrivateKey()
                ?? throw new InvalidOperationException("Certificate has no RSA private key.");

            IExternalSignature pks = new DotNetRsaSignature(rsa);

            // รัน iText7 signing ใน background thread — ป้องกัน deadlock กับ ASP.NET
            var signedBytes = await Task.Run(() => SignPdfInternal(pdfBytes, pks, chain, request));

            _logger.LogInformation("PDF signed. Doc={Doc}, Ref={Ref}, By={User}, Size={Size}bytes",
                request.DocumentName, request.ReferenceId, signerUsername, signedBytes.Length);

            return new PdfSignResult
            {
                IsSuccess    = true,
                PdfBase64    = Convert.ToBase64String(signedBytes),
                DocumentName = request.DocumentName,
                ReferenceId  = request.ReferenceId,
                SignedBy     = cert.Subject,
                SignedAt     = DateTime.UtcNow
            };
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

    // ─── sync method ทำงานใน Task.Run ────────────────────────────────────────
    private static byte[] SignPdfInternal(
        byte[]             pdfBytes,
        IExternalSignature pks,
        IX509Certificate[] chain,
        PdfSignRequest     request)
    {
        var outputMs = new MemoryStream();
        try
        {
            // ไม่ใช้ using กับ inputMs — PdfSigner จะ dispose ให้
            var inputMs = new MemoryStream(pdfBytes);
            var reader  = new PdfReader(inputMs);
            var signer  = new PdfSigner(reader, outputMs, new StampingProperties().UseAppendMode());

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

            // หลัง register BouncyCastleFactory ใน Program.cs แล้ว จะไม่มี NullRef อีก
            signer.SignDetached(pks, chain, null, null, null, 0, PdfSigner.CryptoStandard.CMS);

            return outputMs.ToArray();
        }
        finally
        {
            outputMs.Dispose();
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

            var signerCertI = pkcs7.GetSigningCertificate();
            var bcX509      = ((X509CertificateBC)signerCertI).GetCertificate();

            bool certValid  = bcX509.IsValid(DateTime.UtcNow);
            var  certExpiry = bcX509.NotAfter;
            var  signedBy   = bcX509.SubjectDN.ToString();

            _logger.LogInformation(
                "PDF verify: Sig={Name}, SigOK={SigValid}, CertOK={CertValid}, By={By}",
                sigName, sigValid, certValid, signedBy);

            return new VerifyResult
            {
                IsSignatureValid   = sigValid,
                IsCertificateValid = certValid,
                SignedBy           = signedBy,
                CertExpiry         = certExpiry,
                VerifiedAt         = DateTime.UtcNow
            };
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
