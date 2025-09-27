using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Refit;

var builder = WebApplication.CreateBuilder(args);

// ---------- Services ----------
builder.Services.AddControllers();

// Refit client for AI service
builder.Services.AddRefitClient<IAiClient>()
    .ConfigureHttpClient(c =>
    {
        // AI service URL comes from env (default: http://localhost:8000)
        var aiUrl = Environment.GetEnvironmentVariable("AI_SERVICE_URL") ?? "http://localhost:8000";
        c.BaseAddress = new Uri(aiUrl);
        c.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    });

// Authentication
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(options =>
    {
        options.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuer = false,
            ValidateAudience = false,
            ValidateLifetime = true,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(
                Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("JWT_SECRET") ?? "supersecretkey"))
        };
    });

// ---- CORS (demo-friendly) ----
builder.Services.AddCors(options =>
{
    options.AddPolicy("PagesPolicy", p => p
        .SetIsOriginAllowed(_ => true)   // allow all origins (for GitHub Pages, etc.)
        .AllowAnyHeader()
        .AllowAnyMethod());
});

var app = builder.Build();

// ---------- Middleware ----------
app.UseCors("PagesPolicy"); // must come early
app.UseAuthentication();
app.UseAuthorization();

// ---------- Routes ----------

// Health check
app.MapGet("/api/health", () => Results.Json(new { status = "ok" }));

// Demo auth endpoint
app.MapGet("/api/auth/token", (HttpContext ctx) =>
{
    var authHeader = ctx.Request.Headers["Authorization"].FirstOrDefault();
    if (authHeader == null || !authHeader.StartsWith("Basic "))
        return Results.Unauthorized();

    var encoded = authHeader.Substring("Basic ".Length).Trim();
    var decoded = Encoding.UTF8.GetString(Convert.FromBase64String(encoded));
    var parts = decoded.Split(':');
    if (parts.Length != 2) return Results.Unauthorized();

    var username = parts[0];
    var password = parts[1];

    // demo/demo login
    if (username == "demo" && password == "demo")
    {
        var token = JwtHelper.GenerateToken(username);
        return Results.Json(new { token });
    }

    return Results.Unauthorized();
});

// Ingest docs
app.MapPost("/api/ingest", async (IngestRequest req, IAiClient ai, HttpContext ctx) =>
{
    try
    {
        var auth = ctx.Request.Headers["Authorization"].FirstOrDefault();
        if (auth == null) return Results.Unauthorized();

        var result = await ai.IngestAsync(req);
        return Results.Json(result);
    }
    catch (ApiException ex)
    {
        var content = await ex.GetContentAsStringAsync();
        return Results.Text(content ?? "AI service error", Encoding.UTF8, (int)ex.StatusCode);
    }
});

// Ask question
app.MapPost("/api/ask", async (AskRequest req, IAiClient ai, HttpContext ctx) =>
{
    try
    {
        var auth = ctx.Request.Headers["Authorization"].FirstOrDefault();
        if (auth == null) return Results.Unauthorized();

        var result = await ai.AskAsync(req);
        return Results.Json(result);
    }
    catch (ApiException ex)
    {
        var content = await ex.GetContentAsStringAsync();
        return Results.Text(content ?? "AI service error", Encoding.UTF8, (int)ex.StatusCode);
    }
});

app.Run();

// ---------- DTOs & Interfaces ----------
public record IngestRequest(string doc_id, string text, int chunk_size);
public record AskRequest(string query, int top_k);

public interface IAiClient
{
    [Post("/ingest")]
    Task<object> IngestAsync([Body] IngestRequest request);

    [Post("/ask")]
    Task<object> AskAsync([Body] AskRequest request);
}

// ---------- JWT Helper ----------
public static class JwtHelper
{
    public static string GenerateToken(string username)
    {
        var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(
            Environment.GetEnvironmentVariable("JWT_SECRET") ?? "supersecretkey"));
        var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);

        var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
            claims: new[] { new System.Security.Claims.Claim("sub", username) },
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: creds);

        return new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler().WriteToken(token);
    }
}
