using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Refit;

var builder = WebApplication.CreateBuilder(args);

// Config
var jwtKey = Environment.GetEnvironmentVariable("JWT_KEY") ?? builder.Configuration["Jwt:Key"];
var aiBase = Environment.GetEnvironmentVariable("AI_BASE_URL") ?? builder.Configuration["AiBaseUrl"];

// EF Core (SQLite) for simple metadata
builder.Services.AddDbContext<MetaDb>(opt => 
    opt.UseSqlite(builder.Configuration.GetConnectionString("MetaDb")));

// JWT auth
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey!)),
            ValidateIssuer = false,
            ValidateAudience = false,
            ClockSkew = TimeSpan.Zero
        };
    });

builder.Services.AddAuthorization();

// Refit AI client
builder.Services.AddRefitClient<IAiClient>()
    .ConfigureHttpClient(c => c.BaseAddress = new Uri(aiBase));

builder.Services.AddEndpointsApiExplorer();
builder.Services.AddSwaggerGen(c =>
{
    c.SwaggerDoc("v1", new OpenApiInfo { Title = "NovaRAG Gateway", Version = "v1" });
    var jwtScheme = new OpenApiSecurityScheme
    {
        Name = "Authorization",
        Type = SecuritySchemeType.Http,
        Scheme = "bearer",
        BearerFormat = "JWT",
        In = ParameterLocation.Header,
        Description = "JWT Authorization header using the Bearer scheme."
    };
    c.AddSecurityDefinition("Bearer", jwtScheme);
    c.AddSecurityRequirement(new OpenApiSecurityRequirement
    {
        { jwtScheme, new List<string>() }
    });
});

builder.Services.AddCors(options =>
{
    options.AddPolicy("PagesPolicy", p =>
        p.WithOrigins(
            "https://keerthi11123.github.io",
            "https://keerthi11123.github.io/novarag/"
        )
        .AllowAnyHeader()
        .AllowAnyMethod());
});

public record IngestDto(string doc_id, string text, int chunk_size = 700);

public interface IAiClient
{
    [Post("/query")]
    Task<object> QueryAsync([Body] QueryRequest request);

    [Post("/ingest")]
    Task<object> IngestAsync([Body] IngestDto request);
}

var app = builder.Build();

app.UseCors("PagesPolicy");
app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthentication();
app.UseAuthorization();

app.MapGet("/api/health", () => Results.Ok(new { status = "ok" }));

// Dev-only: basic credential to JWT
app.MapGet("/api/auth/token", (HttpContext ctx) =>
{
    // Basic auth for demo
    if (!ctx.Request.Headers.TryGetValue("Authorization", out var auth)) return Results.Unauthorized();
    var value = auth.ToString();
    if (!value.StartsWith("Basic ")) return Results.Unauthorized();
    var b64 = value["Basic ".Length..].Trim();
    var parts = Encoding.UTF8.GetString(Convert.FromBase64String(b64)).Split(':', 2);
    if (parts.Length != 2) return Results.Unauthorized();
    var user = parts[0]; var pass = parts[1];
    if (user != "demo" || pass != "demo") return Results.Unauthorized();

    var token = JwtTokenHelper.Issue(jwtKey!, "NovaRag", "NovaRagClients", user);
    return Results.Ok(new { token });
});

app.MapPost("/api/meta/docs", async (MetaDb db, DocMeta meta) =>
{
    meta.UploadedAt = DateTime.UtcNow;
    db.Docs.Add(meta);
    await db.SaveChangesAsync();
    return Results.Created($"/api/meta/docs/{meta.Id}", meta);
}).RequireAuthorization();

app.MapGet("/api/meta/docs", async (MetaDb db) =>
{
    var list = await db.Docs.OrderByDescending(d => d.UploadedAt).ToListAsync();
    return Results.Ok(list);
}).RequireAuthorization();

app.MapPost("/api/query", async (IAiClient ai, QueryRequest req) =>
{
    var res = await ai.QueryAsync(req);
    return Results.Ok(res);
}).RequireAuthorization();

app.MapPost("/api/ingest", async (IAiClient ai, IngestDto req) =>
{
    var res = await ai.IngestAsync(req);
    return Results.Ok(res);
}).RequireAuthorization();

app.Run();

// --- EF Core types ---
public class MetaDb : DbContext
{
    public MetaDb(DbContextOptions<MetaDb> options) : base(options) { }
    public DbSet<DocMeta> Docs => Set<DocMeta>();
}
public class DocMeta
{
    public int Id { get; set; }
    public string Name { get; set; } = default!;
    public string? DocId { get; set; }
    public DateTime UploadedAt { get; set; }
}

// --- DTOs & Refit ---
public record QueryRequest(string query, int k = 4, string? doc_id = null);
public interface IAiClient
{
    [Post("/query")]
    Task<object> QueryAsync([Body] QueryRequest request);
}

// --- JWT helper ---
public static class JwtTokenHelper
{
    public static string Issue(string key, string issuer, string audience, string username)
    {
        var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
        var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: new[] { new System.Security.Claims.Claim("sub", username) },
            expires: DateTime.UtcNow.AddHours(6),
            signingCredentials: credentials
        );
        return handler.WriteToken(token);
    }
}
