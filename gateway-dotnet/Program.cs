using System.Text;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.IdentityModel.Tokens;
using Microsoft.OpenApi.Models;
using Refit;
using NovaRag.Gateway.Models;
using NovaRag.Gateway.Clients;
using NovaRag.Gateway.Utils;

var builder = WebApplication.CreateBuilder(args);

// ---- Config (env first, then appsettings) ----
var jwtKey = Environment.GetEnvironmentVariable("JWT_KEY")
            ?? builder.Configuration["Jwt:Key"]
            ?? "dev_super_secret_key_change_me";

var aiBase = Environment.GetEnvironmentVariable("AI_BASE_URL")
            ?? builder.Configuration["AiBaseUrl"]
            ?? "http://localhost:8000";

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

// ---- CORS for GitHub Pages ----
const string PagesOrigin = "https://keerthi11123.github.io";
builder.Services.AddCors(options =>
{
    options.AddPolicy("PagesPolicy", p =>
        p.WithOrigins(PagesOrigin)
         .AllowAnyHeader()
         .AllowAnyMethod());
});

// ---- Refit HTTP client to AI service ----
builder.Services.AddRefitClient<IAiClient>()
    .ConfigureHttpClient(c => c.BaseAddress = new Uri(aiBase));

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
        In = ParameterLocation.Header,
        Description = "JWT Authorization header using the Bearer scheme."
    };
    c.AddSecurityDefinition("Bearer", jwtScheme);
    c.AddSecurityRequirement(new OpenApiSecurityRequirement { { jwtScheme, new List<string>() } });
});

var app = builder.Build();

// ---- Order: CORS BEFORE auth (for preflight) ----
app.UseCors("PagesPolicy");

app.UseSwagger();
app.UseSwaggerUI();

app.UseAuthentication();
app.UseAuthorization();

// ---- Health ----
app.MapGet("/api/health", () => Results.Ok(new { status = "ok" }));

// ---- Dev token (Basic demo:demo -> JWT) ----
app.MapGet("/api/auth/token", (HttpContext ctx) =>
{
    if (!ctx.Request.Headers.TryGetValue("Authorization", out var auth)) return Results.Unauthorized();
    var value = auth.ToString();
    if (!value.StartsWith("Basic ", StringComparison.OrdinalIgnoreCase)) return Results.Unauthorized();

    string user, pass;
    try
    {
        var b64 = value["Basic ".Length..].Trim();
        var parts = Encoding.UTF8.GetString(Convert.FromBase64String(b64)).Split(':', 2);
        if (parts.Length != 2) return Results.Unauthorized();
        user = parts[0]; pass = parts[1];
    }
    catch { return Results.Unauthorized(); }

    if (user != "demo" || pass != "demo") return Results.Unauthorized();

    var token = JwtTokenHelper.Issue(jwtKey, "NovaRag", "NovaRagClients", user);
    return Results.Ok(new { token });
});

// ---- Proxy: query ----
app.MapPost("/api/query", async (IAiClient ai, QueryRequest req) =>
{
    var res = await ai.QueryAsync(req);
    return Results.Ok(res);
}).RequireAuthorization();

// ---- Proxy: ingest ----
app.MapPost("/api/ingest", async (IAiClient ai, IngestDto req) =>
{
    var res = await ai.IngestAsync(req);
    return Results.Ok(res);
}).RequireAuthorization();

app.Run();
