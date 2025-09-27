FROM python:3.11-slim

WORKDIR /app

# The build context is already ai-service/, so copy from "."
COPY . .

# Install deps
RUN pip install --no-cache-dir -r requirements.txt

# Render provides $PORT; default to 8000 locally
ENV PORT=${PORT:-8000}
EXPOSE 8000

# Single worker for free tier stability
CMD ["sh", "-c", "uvicorn app:app --host 0.0.0.0 --port ${PORT}"]
