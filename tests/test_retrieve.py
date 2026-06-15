from datetime import date
from qdrant_client import QdrantClient
from vulnrag.models import AffectedProduct, Vulnerability
from vulnrag.clients import StubEmbedder
from vulnrag.store import VulnStore
from vulnrag.index.embedder import index_vulnerabilities
from vulnrag.query.retrieve import retrieve


def _seed():
    client = QdrantClient(":memory:")
    store = VulnStore(client, "test", 1024)
    store.ensure_collection()
    emb = StubEmbedder(1024)
    vulns = [
        Vulnerability(cve_id="CVE-LOG", description="log4j jndi",
                      affected=[AffectedProduct(product="log4j", version_start="2.0",
                                version_end="2.15.0", version_start_incl=True)],
                      published=date(2021, 1, 1), last_modified=date(2021, 1, 1)),
        Vulnerability(cve_id="CVE-PY", description="python bug",
                      affected=[AffectedProduct(product="python")],
                      published=date(2021, 1, 1), last_modified=date(2021, 1, 1)),
    ]
    index_vulnerabilities(vulns, embedder=emb, store=store)
    return store, emb


def test_retrieve_filters_by_component():
    store, emb = _seed()
    hits = retrieve("Is log4j 2.14 safe?", embedder=emb, store=store, top_k=5)
    assert [h.cve_id for h in hits] == ["CVE-LOG"]


def test_retrieve_falls_back_to_semantic_when_component_unknown():
    store, emb = _seed()
    hits = retrieve("some generic question", embedder=emb, store=store, top_k=5)
    assert len(hits) >= 1
