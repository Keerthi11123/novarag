using System.Net.Http.Headers;
using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Refit;

namespace NovaRag.Gateway;

public class Program
{
    public static void Main(string[] args)
    {
        var builder = WebApplication.CreateBuilder(args);

        // ---- Config ----
        var jwtKey = Env("JWT_KEY", builder.Configuration["Jwt:Key"], "dev_super_secret_key_change_me");
        var aiBase = Env("AI_BASE_URL", builder.Configuration["AiBaseUrl"], "http://localhost:8000").TrimEnd('/');

        // ---- Auth (JWT) ----
        builder.Services.AddAuthentication(JwtBearerDefaults.AuthenticationScheme)
            .AddJwtBearer(o =>
            {
                o.TokenValidationParameters = new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(jwtKey)),
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                };
            });
        builder.Services.AddAuthorization();

        // ---- CORS (GitHub Pages) ----
        const string PagesOrigin = "https://keerthi11123.github.io";
        builder.Services.AddCors(options =>
        {
            options.AddPolicy("PagesPolicy", p => p.WithOrigins(PagesOrigin).AllowAnyHeader().AllowAnyMethod());
        });

        // ---- Refit client to AI service (with timeouts) ----
        builder.Services.AddRefitClient<IAiClient>()
            .ConfigureHttpClient(c =>
            {
                c.BaseAddress = new Uri(aiBase);
                c.Timeout = TimeSpan.FromSeconds(60);
                c.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
            });

        // ---- Swagger ----
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
                In = ParameterLocation.Header
            };
            c.AddSecurityDefinition("Bearer", jwtScheme);
            c.AddSecurityRequirement(new OpenApiSecurityRequirement { { jwtScheme, new List<string>() } });
        });

        var app = builder.Build();

        // ---- Order: CORS before auth ----
        app.UseCors("PagesPolicy");
        app.UseSwagger();
        app.UseSwaggerUI();
        app.UseAuthentication();
        app.UseAuthorization();

        // ---- Health ----
        app.MapGet("/api/health", () => Results.Ok(new { status = "ok" }));

        // ---- Dev token (demo:demo) ----
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

            var token = JwtTokenHelper.Issue(jwtKey, "NovaRag", "NovaRagClients", "demo");
            return Results.Ok(new { token });
        });

        // ---- Proxy: /api/query -> AI /query (surface upstream errors) ----
        app.MapPost("/api/query", async (IAiClient ai, QueryRequest req) =>
        {
            try
            {
                var res = await ai.QueryAsync(req);
                return Results.Ok(res);
            }
            catch (ApiException ex)
            {
                var body = ex.Content; // Refit error body as string
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

        // ---- Proxy: /api/ingest -> AI /ingest (surface upstream errors) ----
        app.MapPost("/api/ingest", async (IAiClient ai, IngestDto req) =>
        {
            try
            {
                var res = await ai.IngestAsync(req);
                return Results.Ok(res);
            }
            catch (ApiException ex)
            {
                var body = ex.Content; // Refit error body as string
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
    }

    private static string Env(string key, params string?[] fallbacks)
    {
        foreach (var v in fallbacks)
        {
            var s = v is null ? Environment.GetEnvironmentVariable(key) : v;
            if (!string.IsNullOrWhiteSpace(s)) return s!;
        }
        return "";
    }
}

// ====== Types (keep below; no top-level stmts above) ======
public record QueryRequest(string query, int k = 4, string? doc_id = null);
public record IngestDto(string doc_id, string text, int chunk_size = 700);

public interface IAiClient
{
    [Post("/query")]
    Task<object> QueryAsync([Body] QueryRequest request);

    [Post("/ingest")]
    Task<object> IngestAsync([Body] IngestDto request);
}

public static class JwtTokenHelper
{
    public static string Issue(string key, string issuer, string audience, string username)
    {
        var sk = new Microsoft.IdentityModel.Tokens.SymmetricSecurityKey(Encoding.UTF8.GetBytes(key));
        var cred = new Microsoft.IdentityModel.Tokens.SigningCredentials(sk, Microsoft.IdentityModel.Tokens.SecurityAlgorithms.HmacSha256);
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
