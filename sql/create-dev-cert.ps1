# ============================================================
# BTDigitalSign — Create Self-Signed Dev Certificate
# รัน script นี้ใน PowerShell (Run as Administrator)
# ============================================================

$certName    = "BTDigitalSign-Dev"
$outputPath  = "$PSScriptRoot\..\src\DigitalSign.API\certs"
$pfxPassword = "dev_password_123"
$pfxFile     = "$outputPath\dev-sign.pfx"

Write-Host "Creating development certificate: $certName" -ForegroundColor Cyan

# สร้าง certs folder ถ้ายังไม่มี
if (-not (Test-Path $outputPath)) {
    New-Item -ItemType Directory -Path $outputPath | Out-Null
}

# สร้าง Self-Signed Certificate
$cert = New-SelfSignedCertificate `
    -Subject "CN=$certName, O=BT Company, C=TH" `
    -KeyAlgorithm RSA `
    -KeyLength 2048 `
    -HashAlgorithm SHA256 `
    -KeyUsage DigitalSignature, NonRepudiation `
    -NotBefore (Get-Date) `
    -NotAfter  (Get-Date).AddYears(2) `
    -CertStoreLocation "Cert:\LocalMachine\My" `
    -FriendlyName "BTDigitalSign Development Certificate"

Write-Host "Certificate created!" -ForegroundColor Green
Write-Host "  Subject    : $($cert.Subject)"
Write-Host "  Thumbprint : $($cert.Thumbprint)"
Write-Host "  Expiry     : $($cert.NotAfter.ToString('yyyy-MM-dd'))"

# Export เป็น .pfx
$secPwd = ConvertTo-SecureString $pfxPassword -AsPlainText -Force
Export-PfxCertificate -Cert $cert -FilePath $pfxFile -Password $secPwd | Out-Null

Write-Host ""
Write-Host "PFX exported to: $pfxFile" -ForegroundColor Yellow
Write-Host "PFX password   : $pfxPassword"
Write-Host ""
Write-Host "Copy thumbprint below into appsettings.json:" -ForegroundColor Cyan
Write-Host "  `"Thumbprint`": `"$($cert.Thumbprint)`"" -ForegroundColor White
Write-Host ""
Write-Host "Done!" -ForegroundColor Green
