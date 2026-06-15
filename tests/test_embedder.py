from datetime import date
from qdrant_client import QdrantClient
from vulnrag.models import AffectedProduct, Vulnerability
from vulnrag.clients import StubEmbedder
from vulnrag.store import VulnStore
from vulnrag.index.embedder import embedding_text, index_vulnerabilities


def test_embedding_text_includes_id_products_description():
    v = Vulnerability(cve_id="CVE-1", description="JNDI RCE",
                      affected=[AffectedProduct(product="log4j")],
                      published=date(2021, 1, 1), last_modified=date(2021, 1, 1))
    text = embedding_text(v)
    assert "CVE-1" in text and "log4j" in text and "JNDI RCE" in text


def test_index_vulnerabilities_writes_to_store():
    client = QdrantClient(":memory:")
    store = VulnStore(client, "test", 1024)
    store.ensure_collection()
    v = Vulnerability(cve_id="CVE-1", description="x",
                      affected=[AffectedProduct(product="log4j")],
                      published=date(2021, 1, 1), last_modified=date(2021, 1, 1))
    index_vulnerabilities([v], embedder=StubEmbedder(1024), store=store, batch_size=10)
    assert store.count() == 1
