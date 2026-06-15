from vulnrag.models import Vulnerability
from vulnrag.clients import EmbeddingClient
from vulnrag.store import VulnStore


def embedding_text(v: Vulnerability) -> str:
    products = ", ".join(sorted({a.product for a in v.affected})) or "unknown"
    return f"{v.cve_id} | products: {products} | {v.description}"


def index_vulnerabilities(vulns: list[Vulnerability], *, embedder: EmbeddingClient,
                          store: VulnStore, batch_size: int = 100):
    """Embed and upsert vulnerabilities in batches (idempotent by cve_id)."""
    for i in range(0, len(vulns), batch_size):
        batch = vulns[i:i + batch_size]
        vectors = embedder.embed([embedding_text(v) for v in batch])
        store.upsert(batch, vectors)
