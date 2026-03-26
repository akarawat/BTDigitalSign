-- ============================================================
-- BTDigitalSign — Database Setup Script
-- SQL Server 2019+
-- ============================================================

USE master;
GO

-- สร้าง Database (ถ้ายังไม่มี)
IF NOT EXISTS (SELECT name FROM sys.databases WHERE name = 'BTDigitalSign')
BEGIN
    CREATE DATABASE BTDigitalSign
        COLLATE Thai_CI_AS;
    PRINT 'Database BTDigitalSign created.';
END
GO

USE BTDigitalSign;
GO

-- ============================================================
-- Table: SignatureAudit — ประวัติการลงลายเซ็น (EF Migration จะสร้างให้อัตโนมัติ)
-- สคริปนี้สำหรับ Reference / Manual setup เท่านั้น
-- ============================================================
IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'SignatureAudit' AND type = 'U')
BEGIN
    CREATE TABLE dbo.SignatureAudit (
        Id               BIGINT          IDENTITY(1,1) NOT NULL CONSTRAINT PK_SignatureAudit PRIMARY KEY,
        ReferenceId      NVARCHAR(200)   NOT NULL,
        SignedByUser     NVARCHAR(500)   NOT NULL,
        SignedByCert     NVARCHAR(1000)  NOT NULL,
        SignedAt         DATETIME2       NOT NULL CONSTRAINT DF_SignatureAudit_SignedAt DEFAULT (GETUTCDATE()),
        Purpose          NVARCHAR(200)   NULL,
        Department       NVARCHAR(200)   NULL,
        Remarks          NVARCHAR(500)   NULL,
        DataHash         NVARCHAR(64)    NOT NULL,
        SignatureHash    NVARCHAR(64)    NOT NULL,
        CertThumbprint   NVARCHAR(100)   NOT NULL,
        CertExpiry       DATETIME2       NOT NULL,
        SignatureType    NVARCHAR(50)    NOT NULL CONSTRAINT DF_SignatureAudit_Type DEFAULT ('RSA-SHA256'),
        IpAddress        NVARCHAR(100)   NULL,
        IsRevoked        BIT             NOT NULL CONSTRAINT DF_SignatureAudit_Revoked DEFAULT (0),
        RevokedAt        DATETIME2       NULL,
        RevocationReason NVARCHAR(500)   NULL
    );
    PRINT 'Table SignatureAudit created.';
END
GO

-- ============================================================
-- Table: SignatureTemplate — Template สำหรับ PDF Signature
-- ============================================================
IF NOT EXISTS (SELECT * FROM sys.objects WHERE name = 'SignatureTemplate' AND type = 'U')
BEGIN
    CREATE TABLE dbo.SignatureTemplate (
        Id              INT             IDENTITY(1,1) NOT NULL CONSTRAINT PK_SignatureTemplate PRIMARY KEY,
        Name            NVARCHAR(200)   NOT NULL,
        Description     NVARCHAR(500)   NULL,
        SignatureX      REAL            NOT NULL CONSTRAINT DF_ST_X DEFAULT (36.0),
        SignatureY      REAL            NOT NULL CONSTRAINT DF_ST_Y DEFAULT (36.0),
        SignatureWidth  REAL            NOT NULL CONSTRAINT DF_ST_W DEFAULT (200.0),
        SignatureHeight REAL            NOT NULL CONSTRAINT DF_ST_H DEFAULT (60.0),
        SignaturePage   INT             NOT NULL CONSTRAINT DF_ST_Page DEFAULT (1),
        DefaultReason   NVARCHAR(200)   NOT NULL CONSTRAINT DF_ST_Reason DEFAULT ('Approved'),
        IsActive        BIT             NOT NULL CONSTRAINT DF_ST_Active DEFAULT (1),
        CreatedAt       DATETIME2       NOT NULL CONSTRAINT DF_ST_Created DEFAULT (GETUTCDATE())
    );

    -- Seed default template
    INSERT INTO dbo.SignatureTemplate (Name, Description, SignatureX, SignatureY, SignatureWidth, SignatureHeight, SignaturePage, DefaultReason)
    VALUES ('Default Bottom-Left', 'Standard signature at bottom-left of page 1', 36.0, 36.0, 200.0, 60.0, 1, 'Approved');

    PRINT 'Table SignatureTemplate created with default data.';
END
GO

-- ============================================================
-- Indexes
-- ============================================================
IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_SignAudit_ReferenceId')
    CREATE INDEX IX_SignAudit_ReferenceId ON dbo.SignatureAudit (ReferenceId);

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_SignAudit_SignedByUser')
    CREATE INDEX IX_SignAudit_SignedByUser ON dbo.SignatureAudit (SignedByUser);

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_SignAudit_SignedAt')
    CREATE INDEX IX_SignAudit_SignedAt ON dbo.SignatureAudit (SignedAt DESC);

IF NOT EXISTS (SELECT * FROM sys.indexes WHERE name = 'IX_SignAudit_Thumbprint')
    CREATE INDEX IX_SignAudit_Thumbprint ON dbo.SignatureAudit (CertThumbprint);
GO

-- ============================================================
-- Useful Views
-- ============================================================
CREATE OR ALTER VIEW dbo.vw_SignatureAuditSummary AS
SELECT
    ReferenceId,
    SignedByUser,
    COUNT(*)              AS TotalSigns,
    MIN(SignedAt)         AS FirstSignedAt,
    MAX(SignedAt)         AS LastSignedAt,
    SUM(CASE WHEN IsRevoked = 1 THEN 1 ELSE 0 END) AS RevokedCount
FROM dbo.SignatureAudit
GROUP BY ReferenceId, SignedByUser;
GO

PRINT '==> BTDigitalSign database setup complete.';
GO
