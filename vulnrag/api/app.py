from fastapi import FastAPI
from pydantic import BaseModel
from vulnrag.query.answer import answer


class QueryRequest(BaseModel):
    question: str
    lang: str | None = None


def create_app(*, store, embedder, llm, top_k: int = 8) -> FastAPI:
    app = FastAPI(title="Vulnerability RAG")

    @app.get("/health")
    def health():
        return {"status": "ok"}

    @app.get("/stats")
    def stats():
        return {"cve_count": store.count()}

    @app.post("/query")
    def query(req: QueryRequest):
        result = answer(req.question, embedder=embedder, store=store,
                        llm=llm, top_k=top_k)
        return {
            "verdict": result.verdict,
            "answer": result.answer_text,
            "cves": result.cves,
            "lang": result.lang,
        }

    return app
