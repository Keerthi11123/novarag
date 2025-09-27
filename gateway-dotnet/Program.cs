using System.Net.Http.Headers;
using System.Text;
using System.Text.RegularExpressions;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http.Features;
using Microsoft.IdentityModel.Tokens;
using Refit;
using UglyToad.PdfPig;

var builder = WebApplication.CreateBuilder(args);

// -------- Config --------
string AiBase = (Environment.GetEnvironmentVariable("AI_BASE_URL") ?? "http://localhost:8000").TrimEnd('/');
string JwtKey = Environment.GetEnvironmentVariable("JWT_KEY") ?? "dev_super_secret_key_change_me";

// Allow larger uploads (PDFs)
builder.Services.Configure<FormOptions>(o =>
{
    o.MultipartBodyLengthLimit = 50 * 1024 * 1024; // 50MB
});

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

// CORS (demo-friendly; tighten later if you want)
builder.Services.AddCors(options =>
{
    options.AddPolicy("PagesPolicy", p => p
        .SetIsOriginAllowed(_ => true) // allow all origins for demo
        .AllowAnyHeader()
        .AllowAnyMethod());
});

// Refit client to AI service
builder.Services.AddRefitClient<IAiClient>()
    .ConfigureHttpClient(c =>
    {
        c.BaseAddress = new Uri(AiBase);
        c.Timeout = TimeSpan.FromSeconds(120); // headroom for bigger batches
        c.DefaultRequestHeaders.Accept.Add(new MediaTypeWithQualityHeaderValue("application/json"));
    });

var app = builder.Build();

// -------- Pipeline --------
app.UseCors("PagesPolicy"); // must come before auth
app.UseAuthentication();
app.UseAuthorization();

// -------- Endpoints --------

// Health
app.MapGet("/api/health", () => Results.Ok(new { status = "ok" }));

// Demo token (Basic demo:demo)
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

// Back-compat: JSON text ingest
app.MapPost("/api/ingest", async (IAiClient ai, IngestDto req) =>
{
    try
    {
        var (ok, payloads, reason) = PrepareBatches(req.doc_id, req.text, req.chunk_size);
        if (!ok) return Results.BadRequest(new { error = reason });

        var results = new List<object?>(payloads.Count);
        foreach (var p in payloads)
            results.Add(await ai.IngestAsync(p));

        return Results.Ok(new { batches = results.Count, results });
    }
    catch (ApiException ex)
    {
        var body = ex.Content;
        return Results.Text(string.IsNullOrWhiteSpace(body) ? ex.Message : body,
                           "application/json", Encoding.UTF8, (int)ex.StatusCode);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex.Message, statusCode: 500);
    }
}).RequireAuthorization();

// Explicit JSON text ingest
app.MapPost("/api/ingest-text", async (IAiClient ai, IngestDto req) =>
{
    try
    {
        var (ok, payloads, reason) = PrepareBatches(req.doc_id, req.text, req.chunk_size);
        if (!ok) return Results.BadRequest(new { error = reason });

        var results = new List<object?>(payloads.Count);
        foreach (var p in payloads)
            results.Add(await ai.IngestAsync(p));

        return Results.Ok(new { batches = results.Count, results });
    }
    catch (ApiException ex)
    {
        var body = ex.Content;
        return Results.Text(string.IsNullOrWhiteSpace(body) ? ex.Message : body,
                           "application/json", Encoding.UTF8, (int)ex.StatusCode);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex.Message, statusCode: 500);
    }
}).RequireAuthorization();

// NEW: multipart/form-data PDF or TXT ingest
app.MapPost("/api/ingest-file", async (HttpRequest request, IAiClient ai) =>
{
    try
    {
        if (!request.HasFormContentType)
            return Results.BadRequest(new { error = "Expected multipart/form-data." });

        var form = await request.ReadFormAsync();
        var docId = form["doc_id"].ToString();
        if (string.IsNullOrWhiteSpace(docId))
            return Results.BadRequest(new { error = "doc_id is required." });

        var chunkSize = 700;
        if (int.TryParse(form["chunk_size"].ToString(), out var cs) && cs > 0)
            chunkSize = cs;

        var file = form.Files.FirstOrDefault();
        if (file is null || file.Length == 0)
            return Results.BadRequest(new { error = "file is required." });

        string text;
        var filename = file.FileName?.ToLowerInvariant() ?? "";
        var contentType = file.ContentType?.ToLowerInvariant() ?? "";

        if (filename.EndsWith(".pdf") || contentType.Contains("application/pdf"))
        {
            text = await ExtractPdfTextAsync(file);
        }
        else if (filename.EndsWith(".txt") || contentType.StartsWith("text/"))
        {
            using var reader = new StreamReader(file.OpenReadStream(), Encoding.UTF8, detectEncodingFromByteOrderMarks: true);
            text = await reader.ReadToEndAsync();
        }
        else
        {
            return Results.StatusCode(415); // Unsupported Media Type
        }

        text = Sanitize(text);

        var (ok, payloads, reason) = PrepareBatches(docId, text, chunkSize);
        if (!ok) return Results.BadRequest(new { error = reason });

        var results = new List<object?>(payloads.Count);
        foreach (var p in payloads)
            results.Add(await ai.IngestAsync(p));

        return Results.Ok(new { batches = results.Count, results });
    }
    catch (ApiException ex)
    {
        var body = ex.Content;
        return Results.Text(string.IsNullOrWhiteSpace(body) ? ex.Message : body,
                           "application/json", Encoding.UTF8, (int)ex.StatusCode);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex.Message, statusCode: 500);
    }
}).RequireAuthorization();

// Query
app.MapPost("/api/query", async (IAiClient ai, QueryRequest req) =>
{
    try
    {
        var res = await ai.QueryAsync(req);
        return Results.Ok(res);
    }
    catch (ApiException ex)
    {
        var body = ex.Content;
        return Results.Text(string.IsNullOrWhiteSpace(body) ? ex.Message : body,
                           "application/json", Encoding.UTF8, (int)ex.StatusCode);
    }
    catch (Exception ex)
    {
        return Results.Problem(ex.Message, statusCode: 500);
    }
}).RequireAuthorization();

app.Run();

// -------- Helpers & contracts --------
static string Sanitize(string? s)
{
    if (string.IsNullOrEmpty(s)) return string.Empty;
    var sb = new StringBuilder(s.Length);
    foreach (var ch in s)
    {
        // keep printable + common whitespace
        if (ch == '\n' || ch == '\r' || ch == '\t' || (ch >= ' ' && ch != '\u007f'))
            sb.Append(ch);
    }
    var collapsed = Regex.Replace(sb.ToString(), "[ \t]{2,}", " ");          // collapse spaces
    collapsed = Regex.Replace(collapsed, @"(\r?\n){3,}", "\n\n");             // limit blank lines
    return collapsed.Trim();
}

static (bool ok, List<IngestDto> payloads, string reason) PrepareBatches(string docId, string text, int chunkSize)
{
    if (string.IsNullOrWhiteSpace(docId)) return (false, [], "doc_id required.");
    var clean = Sanitize(text);
    if (string.IsNullOrWhiteSpace(clean)) return (false, [], "No text to ingest.");

    // Clamp chunk size to sane bounds for embedding
    var chunk = Math.Max(300, Math.Min(chunkSize > 0 ? chunkSize : 700, 5000));
    const int GatewayMaxChars = 12000; // per-call cap to AI service

    var payloads = new List<IngestDto>();
    if (clean.Length <= GatewayMaxChars)
    {
        payloads.Add(new IngestDto(docId, clean, chunk));
        return (true, payloads, "");
    }

    foreach (var p in ChunkByLength(clean, GatewayMaxChars))
        payloads.Add(new IngestDto(docId, p, chunk));

    return (true, payloads, "");
}

static IEnumerable<string> ChunkByLength(string text, int maxLen)
{
    var blocks = text.Replace("\r\n", "\n").Split("\n\n"); // paragraph-ish
    var current = new StringBuilder(maxLen + 1024);
    foreach (var block in blocks)
    {
        if (current.Length + block.Length + 2 <= maxLen)
        {
            current.Append(block).Append("\n\n");
        }
        else
        {
            if (current.Length > 0)
            {
                yield return current.ToString();
                current.Clear();
            }
            if (block.Length <= maxLen)
            {
                current.Append(block).Append("\n\n");
            }
            else
            {
                // very large single block: hard-split
                for (int i = 0; i < block.Length; i += maxLen)
                    yield return block.Substring(i, Math.Min(maxLen, block.Length - i));
            }
        }
    }
    if (current.Length > 0) yield return current.ToString();
}

static async Task<string> ExtractPdfTextAsync(IFormFile file)
{
    using var ms = new MemoryStream();
    await file.OpenReadStream().CopyToAsync(ms);
    ms.Position = 0;

    var sb = new StringBuilder(64 * 1024);
    using var pdf = PdfDocument.Open(ms);
    foreach (var page in pdf.GetPages())
    {
        sb.AppendLine(page.Text);
        sb.AppendLine();
    }
    return sb.ToString();
}

// DTOs
public record IngestDto(string doc_id, string text, int chunk_size = 700);
public record QueryRequest(string query, int k = 4, string? doc_id = null);

// Refit
public interface IAiClient
{
    [Post("/ingest")]
    Task<object> IngestAsync([Body] IngestDto request);

    [Post("/query")]
    Task<object> QueryAsync([Body] QueryRequest request);
}

// JWT helper
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
