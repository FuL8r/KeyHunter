from datetime import date
from qdrant_client import QdrantClient
from vulnrag.models import AffectedProduct, Vulnerability
from vulnrag.clients import StubEmbedder
from vulnrag.store import VulnStore


def _vuln(cve_id, product):
    return Vulnerability(cve_id=cve_id, description=f"{product} bug",
                         severity="HIGH", affected=[AffectedProduct(product=product)],
                         published=date(2021, 1, 1), last_modified=date(2021, 1, 1))


def _store():
    client = QdrantClient(":memory:")
    store = VulnStore(client, collection="test", dim=1024)
    store.ensure_collection()
    return store


def test_upsert_then_count_and_filter_search():
    store = _store()
    emb = StubEmbedder(dim=1024)
    vulns = [_vuln("CVE-1", "log4j"), _vuln("CVE-2", "python")]
    vectors = emb.embed([v.description for v in vulns])
    store.upsert(vulns, vectors)
    assert store.count() == 2

    qvec = emb.embed(["log4j problem"])[0]
    hits = store.search(qvec, product="log4j", top_k=5)
    assert [h.cve_id for h in hits] == ["CVE-1"]


def test_upsert_is_idempotent_by_cve_id():
    store = _store()
    emb = StubEmbedder(dim=1024)
    v = _vuln("CVE-1", "log4j")
    vec = emb.embed([v.description])
    store.upsert([v], vec)
    store.upsert([v], vec)
    assert store.count() == 1
