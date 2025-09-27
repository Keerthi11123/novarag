# ===== Build stage =====
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# Build context is gateway-dotnet/, so copy from "."
COPY . .

RUN dotnet restore NovaRag.Gateway.csproj
RUN dotnet publish NovaRag.Gateway.csproj -c Release -o /app/publish

# ===== Runtime stage =====
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .

# Bind to Render's $PORT (falls back to 10000 locally)
ENV ASPNETCORE_URLS=http://0.0.0.0:${PORT:-10000}
EXPOSE 10000

ENTRYPOINT ["dotnet", "NovaRag.Gateway.dll"]
