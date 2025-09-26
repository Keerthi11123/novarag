from fastapi import FastAPI
from fastapi.middleware.cors import CORSMiddleware
from pydantic import BaseModel
from typing import Optional
from rag_pipeline import ingest_text, query_docs, IngestRequest, QueryRequest

app = FastAPI(title="NovaRAG AI Service", version="0.1.0")

app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

@app.get("/health")
def health():
    return {"status": "ok"}

@app.post("/ingest")
def ingest(req: IngestRequest):
    if req.text is None and not req.chunks:
        return {"error": "Provide text or chunks."}
    text = req.text if req.text else "\n".join(req.chunks)
    return ingest_text(req.doc_id, text, chunk_size=req.chunk_size)

@app.post("/query")
def query(req: QueryRequest):
    return query_docs(req.query, k=req.k, doc_id=req.doc_id)
