using System.Security.Cryptography.X509Certificates;
using DigitalSign.Core.Models;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging;

namespace DigitalSign.Core.Services;

public interface ICertificateService
{
    X509Certificate2 GetSigningCertificate(string? thumbprint = null);
    X509Certificate2 LoadFromPfx(string path, string password);
    CertificateInfo GetCertificateInfo(string? thumbprint = null);
    bool IsCertificateValid(X509Certificate2 cert);
}

public class CertificateService : ICertificateService
{
    private readonly IConfiguration _config;
    private readonly ILogger<CertificateService> _logger;

    public CertificateService(IConfiguration config, ILogger<CertificateService> logger)
    {
        _config = config;
        _logger = logger;
    }

    public X509Certificate2 GetSigningCertificate(string? thumbprint = null)
    {
        thumbprint ??= _config["Certificate:Thumbprint"];

        // ── ลำดับที่ 1: โหลดจาก PFX file (Dev / ไม่ต้องการ admin) ────────────
        var pfxPath = _config["Certificate:PfxPath"];

        if (!string.IsNullOrEmpty(pfxPath))
        {
            // แปลง relative path → absolute path เทียบกับ working directory จริง
            // รองรับทั้ง "certs/dev-sign.pfx" และ absolute path
            var resolvedPath = Path.IsPathRooted(pfxPath)
                ? pfxPath
                : Path.GetFullPath(Path.Combine(AppContext.BaseDirectory, pfxPath));

            if (File.Exists(resolvedPath))
            {
                _logger.LogInformation("Loading certificate from PFX: {Path}", resolvedPath);
                return LoadFromPfx(resolvedPath, _config["Certificate:PfxPassword"] ?? "");
            }

            _logger.LogWarning("PFX file not found at: {Path} (resolved from: {Original})", resolvedPath, pfxPath);
        }

        // ── ลำดับที่ 2: โหลดจาก Windows Certificate Store (Production) ────────
        if (string.IsNullOrEmpty(thumbprint))
            throw new InvalidOperationException(
                "Certificate not found: PfxPath file missing and Thumbprint not configured.");

        var storeLocation = Enum.Parse<StoreLocation>(
            _config["Certificate:StoreLocation"] ?? "LocalMachine");
        var storeName = Enum.Parse<StoreName>(
            _config["Certificate:StoreName"] ?? "My");

        using var store = new X509Store(storeName, storeLocation);
        store.Open(OpenFlags.ReadOnly);

        var certs = store.Certificates.Find(
            X509FindType.FindByThumbprint,
            thumbprint.Replace(" ", "").ToUpperInvariant(),
            validOnly: false);

        if (certs.Count == 0)
            throw new CertificateNotFoundException(
                $"Certificate with thumbprint '{thumbprint}' not found in {storeLocation}/{storeName}.");

        var cert = certs[0];
        _logger.LogInformation("Loaded from Store: {Subject}, Expiry: {Expiry}", cert.Subject, cert.NotAfter);

        if (!IsCertificateValid(cert))
            _logger.LogWarning("Certificate {Thumbprint} is expired or not yet valid.", thumbprint);

        return cert;
    }

    public X509Certificate2 LoadFromPfx(string path, string password)
    {
        if (!File.Exists(path))
            throw new FileNotFoundException($"PFX file not found: {path}");

        // ใช้ Exportable เท่านั้น — ไม่ใช้ PersistKeySet เพราะต้องการสิทธิ์ Admin
        // EphemeralKeySet: key อยู่ใน memory ไม่เขียนลง disk → ไม่ต้องการ admin
        return new X509Certificate2(
            path,
            password,
            X509KeyStorageFlags.Exportable | X509KeyStorageFlags.EphemeralKeySet);
    }

    public CertificateInfo GetCertificateInfo(string? thumbprint = null)
    {
        var cert = GetSigningCertificate(thumbprint);
        var rsa = cert.GetRSAPublicKey();

        return new CertificateInfo
        {
            Subject = cert.Subject,
            Thumbprint = cert.Thumbprint,
            Issuer = cert.Issuer,
            NotBefore = cert.NotBefore,
            NotAfter = cert.NotAfter,
            IsValid = IsCertificateValid(cert),
            KeyAlgorithm = rsa != null ? "RSA" : "ECDSA",
            KeySize = rsa?.KeySize ?? 0
        };
    }

    public bool IsCertificateValid(X509Certificate2 cert)
        => cert.NotBefore <= DateTime.Now && cert.NotAfter >= DateTime.Now;
}

public class CertificateNotFoundException : Exception
{
    public CertificateNotFoundException(string message) : base(message) { }
}
