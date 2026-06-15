from vulnrag.config import Settings
from vulnrag.factory import build_components
from vulnrag.api.app import create_app

_s = Settings()
_store, _embedder, _llm = build_components(_s)   # real Qdrant + Ollama
app = create_app(store=_store, embedder=_embedder, llm=_llm, top_k=_s.top_k)
