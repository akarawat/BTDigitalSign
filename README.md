# BTDigitalSign

**Digital Signature Web API Service** สำหรับระบบ Intranet ภายในบริษัท  
พัฒนาด้วย ASP.NET Core 8 + SQL Server + IIS

---

## โครงสร้าง Project

```
BTDigitalSign/
├── src/
│   ├── DigitalSign.API/          ← Web API (entry point)
│   │   ├── Controllers/
│   │   │   ├── AuthController.cs       JWT token
│   │   │   ├── SignController.cs       Sign / Verify data
│   │   │   ├── PdfController.cs        Sign / Verify PDF
│   │   │   ├── CertificateController.cs  Certificate info
│   │   │   └── AuditController.cs      Audit log
│   │   ├── appsettings.json
│   │   ├── Program.cs
│   │   └── web.config                  IIS config
│   │
│   ├── DigitalSign.Core/         ← Business Logic
│   │   ├── Services/
│   │   │   ├── CertificateService.cs   X.509 / Windows Cert Store
│   │   │   ├── SigningService.cs       RSA-SHA256 sign & verify
│   │   │   └── PdfSignService.cs       iTextSharp PDF signing
│   │   └── Models/
│   │       └── SignModels.cs           Request / Response models
│   │
│   └── DigitalSign.Data/         ← Data layer
│       ├── DigitalSignDbContext.cs
│       ├── Entities/
│       └── Repositories/
│
├── tests/
│   └── DigitalSign.Tests/        ← xUnit tests
│
└── sql/
    ├── 01_setup_database.sql     ← Manual DB setup
    └── create-dev-cert.ps1       ← สร้าง dev certificate
```

---

## เริ่มต้นใช้งาน

### 1. Requirements

| ซอฟต์แวร์ | เวอร์ชัน |
|-----------|---------|
| Visual Studio | 2022 |
| .NET SDK | 8.0 |
| SQL Server | 2019+ หรือ LocalDB |
| IIS | 10+ (production) |

---

### 2. Clone & Build

```bash
git clone https://github.com/akarawat/BTDigitalSign.git
cd BTDigitalSign
dotnet restore
dotnet build
```

---

### 3. ตั้งค่า Development Certificate

```powershell
# รัน PowerShell ในฐานะ Administrator
.\sql\create-dev-cert.ps1
```

Script จะ:
- สร้าง Self-Signed Certificate ใน `Cert:\LocalMachine\My`
- Export เป็น `.pfx` ที่ `src/DigitalSign.API/certs/dev-sign.pfx`
- แสดง Thumbprint สำหรับใส่ใน `appsettings.json`

---

### 4. แก้ไข `appsettings.json`

```json
{
  "ConnectionStrings": {
    "DefaultConnection": "Server=(localdb)\\mssqllocaldb;Database=BTDigitalSign_Dev;Trusted_Connection=True;"
  },
  "Jwt": {
    "SecretKey": "YOUR_STRONG_SECRET_MIN_32_CHARS_HERE"
  },
  "Certificate": {
    "PfxPath": "certs/dev-sign.pfx",
    "PfxPassword": "dev_password_123"
  }
}
```

---

### 5. รัน API

```bash
dotnet run --project src/DigitalSign.API
```

เปิด Swagger UI: `http://localhost:5210`

---

## API Endpoints

| Method | Path | Description |
|--------|------|-------------|
| `POST` | `/api/auth/token` | ขอ JWT Token |
| `GET`  | `/api/auth/ping` | ทดสอบ auth |
| `POST` | `/api/sign` | Sign ข้อมูล |
| `POST` | `/api/sign/verify` | ตรวจสอบ signature |
| `POST` | `/api/pdf/sign` | Sign PDF (Base64 in/out) |
| `POST` | `/api/pdf/sign/download` | Sign PDF (download file) |
| `POST` | `/api/pdf/verify` | ตรวจสอบ PDF signature |
| `GET`  | `/api/certificate/info` | ข้อมูล certificate |
| `GET`  | `/api/certificate/health` | สถานะ certificate |
| `GET`  | `/api/audit/my` | ประวัติ sign ของ user |
| `GET`  | `/api/audit/reference/{id}` | ประวัติตาม reference |
| `POST` | `/api/audit/{id}/revoke` | Revoke signature |

---

## ตัวอย่าง API Call

### Sign Data
```http
POST /api/sign
Authorization: Bearer {token}
Content-Type: application/json

{
  "dataToSign": "สัญญาเลขที่ PO-2025-001",
  "referenceId": "PO-2025-001",
  "purpose": "Approve Purchase Order",
  "department": "Procurement"
}
```

### Sign PDF
```http
POST /api/pdf/sign
Authorization: Bearer {token}
Content-Type: application/json

{
  "pdfBase64": "JVBERi0xLjQ...",
  "documentName": "PurchaseOrder_2025",
  "referenceId": "PO-2025-001",
  "reason": "Approved",
  "location": "Bangkok, Thailand",
  "signaturePage": 1,
  "signatureX": 36,
  "signatureY": 36,
  "signatureWidth": 200,
  "signatureHeight": 60
}
```

---

## Deploy บน IIS

```powershell
# 1. Publish
dotnet publish src/DigitalSign.API -c Release -o C:\inetpub\BTDigitalSign

# 2. สร้าง Application Pool ใน IIS Manager
#    - Name: BTDigitalSign
#    - .NET CLR version: No Managed Code
#    - Identity: LocalSystem (หรือ Service Account ที่มีสิทธิ์ Cert Store)

# 3. สร้าง Website / Application ชี้ที่ C:\inetpub\BTDigitalSign
```

---

## Tech Stack

| Layer | Technology |
|-------|-----------|
| Framework | ASP.NET Core 8 |
| Auth | JWT Bearer / Azure AD (MSAL) |
| PDF Signing | iTextSharp.LGPLv2.Core + BouncyCastle |
| Crypto | System.Security.Cryptography (RSA-SHA256) |
| ORM | Entity Framework Core 8 |
| Database | SQL Server |
| Logging | Serilog |
| Testing | xUnit + Moq + FluentAssertions |
| Docs | Swagger / OpenAPI |

---

## License

Internal use only — BT Company
