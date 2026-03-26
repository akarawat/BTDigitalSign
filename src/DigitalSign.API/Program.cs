using DigitalSign.Core.Services;
using DigitalSign.Data;
using DigitalSign.Data.Repositories;
using Microsoft.AspNetCore.Authentication.Negotiate;
using Microsoft.AspNetCore.Authorization;
using Microsoft.EntityFrameworkCore;
using Microsoft.OpenApi.Models;
using Serilog;

var builder = WebApplication.CreateBuilder(args);

// ── Serilog ───────────────────────────────────────────────────────────────────
Log.Logger = new LoggerConfiguration()
    .ReadFrom.Configuration(builder.Configuration)
    .Enrich.FromLogContext()
    .WriteTo.Console()
    .WriteTo.File("logs/digitalsign-.txt", rollingInterval: RollingInterval.Day)
    .CreateLogger();

builder.Host.UseSerilog();

// ── Windows Authentication (Kerberos / NTLM) ─────────────────────────────────
// รองรับ Domain Login ของ @berninathailand.com อัตโนมัติ
// User.Identity.Name จะได้ค่า BERNINATHAILAND\username
builder.Services.AddAuthentication(NegotiateDefaults.AuthenticationScheme)
    .AddNegotiate();

// บังคับ authenticate ทุก endpoint (ยกเว้นที่ระบุ [AllowAnonymous])
builder.Services.AddAuthorization(options =>
{
    options.FallbackPolicy = new AuthorizationPolicyBuilder()
        .RequireAuthenticatedUser()
        .Build();
});

// ── Database (SQL Server) ─────────────────────────────────────────────────────
builder.Services.AddDbContext<DigitalSignDbContext>(opts =>
    opts.UseSqlServer(builder.Configuration.GetConnectionString("DefaultConnection"),
        x => x.MigrationsAssembly("DigitalSign.Data")));

// ── Application Services ──────────────────────────────────────────────────────
builder.Services.AddScoped<ICertificateService, CertificateService>();
builder.Services.AddScoped<ISigningService,     SigningService>();
builder.Services.AddScoped<IPdfSignService,     PdfSignService>();
builder.Services.AddScoped<ISignatureAuditRepository, SignatureAuditRepository>();

// ── Controllers ───────────────────────────────────────────────────────────────
builder.Services.AddControllers();
builder.Services.AddEndpointsApiExplorer();

// ── Swagger ───────────────────────────────────────────────────────────────────
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo
    {
        Title       = "BTDigitalSign API",
        Version     = "v1",
        Description = "Digital Signature Web API — berninathailand.com (Windows SSO)",
        Contact     = new OpenApiContact { Name = "BT Dev Team" }
    });
});

// ── CORS (Intranet) ───────────────────────────────────────────────────────────
builder.Services.AddCors(options =>
{
    options.AddPolicy("IntranetPolicy", policy =>
    {
        var origins = builder.Configuration
            .GetSection("Cors:AllowedOrigins")
            .Get<string[]>() ?? ["http://localhost"];

        policy.WithOrigins(origins)
              .AllowAnyHeader()
              .AllowAnyMethod()
              .AllowCredentials(); // จำเป็นสำหรับ Windows Auth
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

// Windows Auth ต้องมาก่อน Authorization เสมอ
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
