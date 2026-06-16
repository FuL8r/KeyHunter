from vulnrag.clients import EmbeddingClient
from vulnrag.store import VulnStore, Hit
from vulnrag.query.parse import extract_component_version


def retrieve(question: str, *, embedder: EmbeddingClient, store: VulnStore,
             top_k: int = 8, component: str | None = "__extract__") -> list[Hit]:
    if component == "__extract__":
        component, _ = extract_component_version(question)
    qvec = embedder.embed([question])[0]
    hits = store.search(qvec, product=component, top_k=top_k)
    if not hits and component is not None:
        hits = store.search(qvec, product=None, top_k=top_k)
    return hits
