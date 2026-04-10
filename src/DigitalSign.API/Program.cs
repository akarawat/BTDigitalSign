using DigitalSign.Core.Services;
using DigitalSign.Data;
using DigitalSign.Data.Repositories;
using iText.Bouncycastle;          // BouncyCastleFactory — from itext7.bouncy-castle-adapter (in Core)
using iText.Commons.Bouncycastle;  // BouncyCastleFactoryCreator
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Serilog;

// ── Force โหลด iText7 BouncyCastle Factory ───────────────────────────────────
// ใช้ adapter (itext7.bouncy-castle-adapter) ที่อยู่ใน DigitalSign.Core แล้ว
// RunClassConstructor บังคับให้ static constructor ทำงาน → register factory
var adapterType = typeof(BouncyCastleFactory);
System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(adapterType.TypeHandle);
//BouncyCastleFactoryCreator.SetFactory(new BouncyCastleFactory());

var builder = WebApplication.CreateBuilder(args);

// ── Serilog ───────────────────────────────────────────────────────────────────
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .WriteTo.File("logs/digitalsign-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

builder.Host.UseSerilog();

// ── Windows Authentication ────────────────────────────────────────────────────
builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
    .AddNegotiate();

// ใช้ AddAuthorizationBuilder (แนะนำสำหรับ .NET 8)
builder.Services.AddAuthorizationBuilder()
    .SetFallbackPolicy(new Microsoft.AspNetCore.Authorization.AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build());

// ── Database ──────────────────────────────────────────────────────────────────
builder.Services.AddDbContext<DigitalSignDbContext>(opts =>
    opts.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"),
        x => x.MigrationsAssembly("DigitalSign.Data")));

// ── Services ──────────────────────────────────────────────────────────────────
builder.Services.AddScoped<ICertificateService,       CertificateService>();
builder.Services.AddScoped<ISigningService,           SigningService>();
builder.Services.AddScoped<IPdfSignService,           PdfSignService>();
builder.Services.AddScoped<ISignatureAuditRepository, SignatureAuditRepository>();
builder.Services.AddScoped<ISignatureRegistryRepository, SignatureRegistryRepository>();

builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// ── Swagger ───────────────────────────────────────────────────────────────────
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title       = "BTDigitalSign API",
        Version     = "v1",
        Description = "Digital Signature Web API — berninathailand.com (Windows SSO)"
    });
});

// ── CORS (Intranet) ───────────────────────────────────────────────────────────
builder.Services.AddCors(options =>
{
    options.AddPolicy("IntranetPolicy", policy =>
    {
        var origins = builder.Configuration
            .GetSection("Cors:AllowedOrigins").Get<string[]>() ?? ["http://localhost"];
        policy.WithOrigins(origins).AllowAnyHeader().AllowAnyMethod().AllowCredentials();
    });
});

var app = builder.Build();

// ── Middleware Pipeline ───────────────────────────────────────────────────────
if (app.Environment.IsDevelopment())
{
    app.UseSwagger();
    app.UseSwaggerUI(c =>
    {
        c.SwaggerEndpoint("/swagger/v1/swagger.json", "BTDigitalSign API v1");
        c.RoutePrefix = string.Empty;
    });
}

app.UseSerilogRequestLogging();
app.UseHttpsRedirection();
app.UseCors("IntranetPolicy");
app.UseAuthentication();
app.UseAuthorization();
app.MapControllers();

// Auto-migrate on startup
using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<DigitalSignDbContext>();
    db.Database.Migrate();
}

app.Run();
