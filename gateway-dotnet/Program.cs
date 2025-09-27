using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Refit;

// ---------------------- Service setup ----------------------
var builder = WebApplication.CreateBuilder(args);

// Config
string AiBase = (Environment.GetEnvironmentVariable("AI_BASE_URL") ?? "http://localhost:8000").TrimEnd('/');
string JwtKey = Environment.GetEnvironmentVariable("JWT_KEY") ?? "dev_super_secret_key_change_me";

// Auth (JWT)
builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
    .AddJwtBearer(o =>
    {
        o.TokenValidationParameters = new TokenValidationParameters
        {
            ValidateIssuerSigningKey = true,
            IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(JwtKey)),
            ValidateIssuer = false,
            ValidateAudience = false,
            ClockSkew = TimeSpan.Zero
        };
    });
builder.Services.AddAuthorization();

// CORS (demo-friendly)
builder.Services.AddCors(options =>
{
    options.AddPolicy("PagesPolicy", p => p
        .SetIsOriginAllowed(_ => true)   // allow all (tighten later)
        .AllowAnyHeader()
        .AllowAnyMethod());
});

// Refit client to AI service
builder.Services.AddRefitClient<IAiClient>()
    .ConfigureHttpClient(c =>
    {
        c.BaseAddress = new Uri(AiBase);
        c.Timeout = TimeSpan.FromSeconds(60);
        c.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    });

var app = builder.Build();

// ---------------------- Middleware ----------------------
app.UseCors("PagesPolicy");          // must be before auth
app.UseAuthentication();
app.UseAuthorization();

// ---------------------- Endpoints ----------------------

// Health
app.MapGet("/api/health", () => Results.Ok(new { status = "ok" }));

// Demo token: GET /api/auth/token  (Basic demo:demo)
app.MapGet("/api/auth/token", (HttpContext ctx) =>
{
    if (!ctx.Request.Headers.TryGetValue("Authorization", out var auth))
        return Results.Unauthorized();

    var value = auth.ToString();
    if (!value.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase))
        return Results.Unauthorized();

    try
    {
        var b64 = value["Basic ".Length..].Trim();
        var parts = Encoding.UTF8.GetString(Convert.FromBase64String(b64)).Split(':', 2);
        if (parts.Length != 2) return Results.Unauthorized();
        if (parts[0] != "demo" || parts[1] != "demo") return Results.Unauthorized();
    }
    catch { return Results.Unauthorized(); }

    var token = JwtTokenHelper.Issue(JwtKey, "NovaRag", "NovaRagClients", "demo");
    return Results.Ok(new { token });
});

// POST /api/ingest  -> AI /ingest
app.MapPost("/api/ingest", async (IAiClient ai, IngestDto req) =>
{
    try
    {
        var res = await ai.IngestAsync(req);
        return Results.Ok(res);
    }
    catch (ApiException ex)
    {
        var body = ex.Content; // body string from Refit
        return Results.Text(
            string.IsNullOrWhiteSpace(body) ? ex.Message : body,
            "application/json",
            Encoding.UTF8,
            (int)ex.StatusCode
        );
    }
    catch (Exception ex)
    {
        return Results.Problem(ex.Message, statusCode: 500);
    }
}).RequireAuthorization();

// POST /api/query   -> AI /query
app.MapPost("/api/query", async (IAiClient ai, QueryRequest req) =>
{
    try
    {
        var res = await ai.QueryAsync(req);
        return Results.Ok(res);
    }
    catch (ApiException ex)
    {
        var body = ex.Content; // body string from Refit
        return Results.Text(
            string.IsNullOrWhiteSpace(body) ? ex.Message : body,
            "application/json",
            Encoding.UTF8,
            (int)ex.StatusCode
        );
    }
    catch (Exception ex)
    {
        return Results.Problem(ex.Message, statusCode: 500);
    }
}).RequireAuthorization();

app.Run();

// ---------------------- Types ----------------------
public record IngestDto(string doc_id, string text, int chunk_size = 700);
public record QueryRequest(string query, int k = 4, string? doc_id = null);

public interface IAiClient
{
    [Post("/ingest")]
    Task<object> IngestAsync([Body] IngestDto request);

    [Post("/query")]
    Task<object> QueryAsync([Body] QueryRequest request);
}

public static class JwtTokenHelper
{
    public static string Issue(string key, string issuer, string audience, string username)
    {
        var sk = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
        var cred = new SigningCredentials(sk, SecurityAlgorithms.HmacSha256);
        var handler = new System.IdentityModel.Tokens.Jwt.JwtSecurityTokenHandler();
        var token = new System.IdentityModel.Tokens.Jwt.JwtSecurityToken(
            issuer: issuer,
            audience: audience,
            claims: new[] { new System.Security.Claims.Claim("sub", username) },
            expires: DateTime.UtcNow.AddHours(6),
            signingCredentials: cred
        );
        return handler.WriteToken(token);
    }
}
