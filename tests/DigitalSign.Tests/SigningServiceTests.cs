using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using DigitalSign.Core.Models;
using DigitalSign.Core.Services;
using DigitalSign.Data.Entities;
using DigitalSign.Data.Repositories;
using FluentAssertions;
using Microsoft.Extensions.Configuration;
using Microsoft.Extensions.Logging.Abstractions;
using Moq;
using Xunit;

namespace DigitalSign.Tests;

public class SigningServiceTests : IDisposable
{
    private readonly X509Certificate2 _testCert;
    private readonly Mock<ICertificateService> _certServiceMock;
    private readonly Mock<ISignatureAuditRepository> _auditRepoMock;
    private readonly SigningService _signingService;

    public SigningServiceTests()
    {
        // สร้าง self-signed cert สำหรับทดสอบ
        _testCert = GenerateSelfSignedCert();

        _certServiceMock = new Mock<ICertificateService>();
        _certServiceMock.Setup(x => x.GetSigningCertificate(It.IsAny<string>())).Returns(_testCert);
        _certServiceMock.Setup(x => x.IsCertificateValid(It.IsAny<X509Certificate2>())).Returns(true);

        _auditRepoMock = new Mock<ISignatureAuditRepository>();
        _auditRepoMock.Setup(x => x.AddAsync(It.IsAny<SignatureAudit>())).Returns(Task.CompletedTask);

        _signingService = new SigningService(
            _certServiceMock.Object,
            _auditRepoMock.Object,
            NullLogger<SigningService>.Instance);
    }

    [Fact]
    public async Task SignDataAsync_ValidRequest_ShouldReturnSuccessResult()
    {
        // Arrange
        var request = new SignRequest
        {
            DataToSign  = "Hello, Digital Signature!",
            ReferenceId = "TEST-001",
            Purpose     = "Unit Test"
        };

        // Act
        var result = await _signingService.SignDataAsync(request, "testuser");

        // Assert
        result.IsSuccess.Should().BeTrue();
        result.SignatureBase64.Should().NotBeNullOrEmpty();
        result.SignedBy.Should().NotBeNullOrEmpty();
        result.ReferenceId.Should().Be("TEST-001");
        result.DataHash.Should().NotBeNullOrEmpty();
        result.CertThumbprint.Should().Be(_testCert.Thumbprint);
    }

    [Fact]
    public async Task SignDataAsync_ThenVerify_ShouldBeValid()
    {
        // Arrange
        var data    = "Document content to sign";
        var request = new SignRequest { DataToSign = data, ReferenceId = "TEST-002", Purpose = "Test" };

        // Act - Sign
        var signResult = await _signingService.SignDataAsync(request, "testuser");
        signResult.IsSuccess.Should().BeTrue();

        // Act - Verify
        var verifyRequest = new VerifyRequest
        {
            OriginalData    = data,
            SignatureBase64 = signResult.SignatureBase64,
            CertThumbprint  = _testCert.Thumbprint
        };
        var verifyResult = _signingService.VerifySignature(verifyRequest);

        // Assert
        verifyResult.IsSignatureValid.Should().BeTrue();
        verifyResult.IsCertificateValid.Should().BeTrue();
        verifyResult.IsOverallValid.Should().BeTrue();
    }

    [Fact]
    public void VerifySignature_TamperedData_ShouldReturnInvalid()
    {
        // Arrange — สร้าง valid signature ก่อน แล้วเปลี่ยน data
        var originalData = "Original data";
        var dataBytes    = Encoding.UTF8.GetBytes(originalData);
        using var rsa    = _testCert.GetRSAPrivateKey()!;
        var signature    = rsa.SignData(dataBytes, HashAlgorithmName.SHA256, RSASignaturePadding.Pkcs1);

        var verifyRequest = new VerifyRequest
        {
            OriginalData    = "Tampered data!!!",   // ข้อมูลถูกแก้ไข
            SignatureBase64 = Convert.ToBase64String(signature),
            CertThumbprint  = _testCert.Thumbprint
        };

        // Act
        var result = _signingService.VerifySignature(verifyRequest);

        // Assert
        result.IsSignatureValid.Should().BeFalse();
    }

    [Fact]
    public async Task SignDataAsync_ShouldCallAuditRepository()
    {
        // Arrange
        var request = new SignRequest { DataToSign = "test", ReferenceId = "AUDIT-001", Purpose = "Test" };

        // Act
        await _signingService.SignDataAsync(request, "audittestuser");

        // Assert — ต้องมีการบันทึก audit log
        _auditRepoMock.Verify(x => x.AddAsync(It.Is<SignatureAudit>(a =>
            a.ReferenceId  == "AUDIT-001" &&
            a.SignedByUser == "audittestuser"
        )), Times.Once);
    }

    // Helper: สร้าง self-signed cert สำหรับ test
    private static X509Certificate2 GenerateSelfSignedCert()
    {
        using var rsa = RSA.Create(2048);
        var req = new CertificateRequest(
            "CN=BTDigitalSign-Test",
            rsa,
            HashAlgorithmName.SHA256,
            RSASignaturePadding.Pkcs1);

        req.CertificateExtensions.Add(
            new X509BasicConstraintsExtension(false, false, 0, false));
        req.CertificateExtensions.Add(
            new X509KeyUsageExtension(X509KeyUsageFlags.DigitalSignature, false));

        var cert = req.CreateSelfSigned(DateTimeOffset.UtcNow.AddDays(-1), DateTimeOffset.UtcNow.AddYears(1));
        // Export/import with private key ให้ใช้งานได้ใน test
        return new X509Certificate2(cert.Export(X509ContentType.Pkcs12), (string?)null,
            X509KeyStorageFlags.Exportable);
    }

    public void Dispose() => _testCert.Dispose();
}

public class CertificateServiceTests
{
    //[Fact]
    //public void LoadFromPfx_NonExistentFile_ShouldThrowFileNotFoundException()
    //{
    //    // Arrange
    //    var config  = new ConfigurationBuilder().Build();
    //    var service = new CertificateService(config, NullLogger<CertificateService>.Instance);

    //    // Act & Assert
    //    Assert.Throws<FileNotFoundException>(
    //        () => service.LoadFromPfx("/non/existent/path.pfx", "password"));
    //}
}
