# ===== Build stage =====
FROM mcr.microsoft.com/dotnet/sdk:8.0 AS build
WORKDIR /src

# The build context is already gateway-dotnet/, so copy from "."
COPY . .

# Restore & publish from the project file in this folder
RUN dotnet restore NovaRag.Gateway.csproj
RUN dotnet publish NovaRag.Gateway.csproj -c Release -o /app/publish

# ===== Runtime stage =====
FROM mcr.microsoft.com/dotnet/aspnet:8.0 AS runtime
WORKDIR /app
COPY --from=build /app/publish .

# Bind to Render's provided PORT (fallback 10000 locally)
ENV ASPNETCORE_URLS=http://0.0.0.0:${PORT:-10000}
EXPOSE 10000

ENTRYPOINT ["dotnet", "NovaRag.Gateway.dll"]
