using DigitalSign.Core.Services;
using DigitalSign.Data;
using DigitalSign.Data.Repositories;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Serilog;

// ── Force โหลด iText7 bouncy-castle-connector ────────────────────────────────
// การอ้างถึง Type บังคับให้ assembly โหลดทันที
// connector มี ModuleInitializer ที่ register BouncyCastleFactory อัตโนมัติ
// ถ้าไม่ทำนี้ assembly จะโหลด lazy และ factory ไม่ถูก register ก่อน sign
var connectorType = typeof(iText.Bouncycastleconnector.BouncyCastleFactoryCreator);
System.Runtime.CompilerServices.RuntimeHelpers.RunClassConstructor(connectorType.TypeHandle);

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

builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// ── Database ──────────────────────────────────────────────────────────────────
builder.Services.AddDbContext<DigitalSignDbContext>(opts =>
    opts.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"),
        x => x.MigrationsAssembly("DigitalSign.Data")));

// ── Services ──────────────────────────────────────────────────────────────────
builder.Services.AddScoped<ICertificateService,       CertificateService>();
builder.Services.AddScoped<ISigningService,           SigningService>();
builder.Services.AddScoped<IPdfSignService,           PdfSignService>();
builder.Services.AddScoped<ISignatureAuditRepository, SignatureAuditRepository>();

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

// ── CORS ──────────────────────────────────────────────────────────────────────
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

using (var scope = app.Services.CreateScope())
{
    var db = scope.ServiceProvider.GetRequiredService<DigitalSignDbContext>();
    db.Database.Migrate();
}

app.Run();
