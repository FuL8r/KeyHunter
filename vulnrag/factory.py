from qdrant_client import QdrantClient
from vulnrag.config import Settings
from vulnrag.clients import OllamaEmbedder, OllamaLLM
from vulnrag.store import VulnStore


def build_components(settings: Settings | None = None):
    """Build (store, embedder, llm) wired to the real Qdrant server + Ollama.
    Used by the API server, the sync job, and notebooks so they all share the
    same real Qdrant — never the `:memory:` test instance."""
    s = settings or Settings()
    client = QdrantClient(host=s.qdrant_host, port=s.qdrant_port)
    store = VulnStore(client, s.collection, s.embed_dim)
    embedder = OllamaEmbedder(s.embed_model, s.ollama_host)
    llm = OllamaLLM(s.llm_model, s.ollama_host)
    return store, embedder, llm
