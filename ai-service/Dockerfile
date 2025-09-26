# ===== Build/runtime in one (Python) =====
FROM python:3.11-slim

WORKDIR /app
# Copy only ai-service folder
COPY ai-service/ /app/

# Install deps
RUN pip install --no-cache-dir -r requirements.txt

# Render provides $PORT; default to 8000 locally
ENV PORT=${PORT:-8000}

EXPOSE 8000

# Uvicorn with workers=1 for free tier stability
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT}"]
