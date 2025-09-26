from typing import List, Optional, Dict, Any
import os
from pydantic import BaseModel
from langchain_community.embeddings import HuggingFaceEmbeddings
from langchain_community.vectorstores import Chroma
from langchain_community.llms import HuggingFacePipeline
from langchain.chains import RetrievalQA
from transformers import pipeline

EMBED_MODEL_NAME = "sentence-transformers/all-MiniLM-L6-v2"
GEN_MODEL_NAME = "google/flan-t5-base"
CHROMA_DIR = os.getenv("CHROMA_DB", "./chroma_db")

embeddings = HuggingFaceEmbeddings(model_name=EMBED_MODEL_NAME)

def get_vector_store(collection_name: str):
    return Chroma(collection_name=collection_name, embedding_function=embeddings, persist_directory=CHROMA_DIR)

class IngestRequest(BaseModel):
    doc_id: str
    text: Optional[str] = None
    chunks: Optional[List[str]] = None
    chunk_size: int = 500

class QueryRequest(BaseModel):
    query: str
    k: int = 4
    doc_id: Optional[str] = None

def chunk_text(text: str, size: int = 500) -> List[str]:
    tokens = text.split()
    chunks = []
    cur = []
    for t in tokens:
        cur.append(t)
        if len(cur) >= size:
            chunks.append(" ".join(cur))
            cur = []
    if cur:
        chunks.append(" ".join(cur))
    return chunks

def build_qa_chain(collection_name: str):
    gen_pipe = pipeline("text2text-generation", model=GEN_MODEL_NAME, max_new_tokens=256)
    llm = HuggingFacePipeline(pipeline=gen_pipe)
    vect = get_vector_store(collection_name)
    retriever = vect.as_retriever(search_type="similarity", search_kwargs={"k": 4})
    chain = RetrievalQA.from_chain_type(llm=llm, chain_type="stuff", retriever=retriever, return_source_documents=True)
    return chain

def ingest_text(doc_id: str, text: str, chunk_size: int = 500) -> Dict[str, Any]:
    vect = get_vector_store(doc_id)
    chunks = chunk_text(text, size=chunk_size)
    metadatas = [{"doc_id": doc_id, "chunk_idx": i} for i, _ in enumerate(chunks)]
    vect.add_texts(chunks, metadatas=metadatas)
    vect.persist()
    return {"doc_id": doc_id, "chunks_indexed": len(chunks)}

def query_docs(query: str, k: int = 4, doc_id: Optional[str] = None) -> Dict[str, Any]:
    collection = doc_id if doc_id else "default"
    chain = build_qa_chain(collection)
    result = chain({"query": query})
    answer = result.get("result", "")
    sources = [{"metadata": d.metadata, "snippet": d.page_content[:300]} for d in result.get("source_documents", [])]
    return {"answer": answer, "sources": sources}
