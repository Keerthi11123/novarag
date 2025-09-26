# NovaRAG — .NET 8 Gateway + Python FastAPI RAG Service

A practical Retrieval-Augmented Generation (RAG) micro‑stack:
- **Gateway**: .NET 8 Minimal API (C#) with JWT auth, EF Core (SQLite) for document metadata, and a proxy to the AI service.
- **AI Service**: Python FastAPI using Sentence‑Transformers (`all-MiniLM-L6-v2`), ChromaDB vector store, and LangChain `RetrievalQA` with `google/flan-t5-base` via Hugging Face pipeline.
- **Docs (GitHub Pages)**: Static site under `/docs` you can deploy via GitHub Pages (project settings → Pages → branch: main, folder: `/docs`).

> GitHub Pages serves only static files. The docs site can call your gateway/AI APIs if you host them elsewhere (or locally during dev).

## Quick start (local)

### Prereqs
- .NET 8 SDK
- Docker + Docker Compose (optional but recommended)
- Python 3.10+

### Option A: Docker (recommended)

```bash
docker compose up --build
```
- Gateway: http://localhost:8080
- AI Service: http://localhost:8000

Get a JWT:
```bash
curl -s http://localhost:8080/api/auth/token -u demo:demo | jq
```
Ingest a document (plain text):
```bash
curl -X POST "http://localhost:8000/ingest" -H "Content-Type: application/json"   -d '{"doc_id":"demo-doc","text":"RAG is retrieval plus generation.", "chunk_size":500}'
```
Query:
```bash
TOKEN=$(curl -s http://localhost:8080/api/auth/token -u demo:demo | jq -r .token)
curl -X POST "http://localhost:8080/api/query" -H "Authorization: Bearer $TOKEN"   -H "Content-Type: application/json" -d '{"query":"What is RAG?", "k":3}'
```

### Option B: Run services separately

**AI service**
```bash
cd ai-service
python -m venv .venv && source .venv/bin/activate
pip install -r requirements.txt
uvicorn app:app --host 0.0.0.0 --port 8000 --reload
```

**Gateway**
```bash
cd gateway-dotnet
dotnet restore
dotnet ef database update  # optional: creates SQLite DB for metadata
dotnet run
```

## Project layout
```
NovaRAG/
  README.md
  docker-compose.yml
  gateway-dotnet/
    Program.cs
    NovaRag.Gateway.csproj
    appsettings.json
  ai-service/
    app.py
    rag_pipeline.py
    requirements.txt
  docs/
    index.html
    script.js
    styles.css
```

## Notes
- The AI service downloads models on first run. You can swap models in `rag_pipeline.py`.
- For production, store secrets (JWT key) in a secret manager. This sample uses dev defaults.
- EF Core + SQLite stores document metadata only (not vectors). Vectors live in the Chroma DB directory.
