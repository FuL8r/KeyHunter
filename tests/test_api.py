from datetime import date
from fastapi.testclient import TestClient
from qdrant_client import QdrantClient
from vulnrag.models import AffectedProduct, Vulnerability
from vulnrag.clients import StubEmbedder, StubLLM
from vulnrag.store import VulnStore
from vulnrag.index.embedder import index_vulnerabilities
from vulnrag.api.app import create_app


def _client():
    qc = QdrantClient(":memory:")
    store = VulnStore(qc, "test", 1024)
    store.ensure_collection()
    emb = StubEmbedder(1024)
    v = Vulnerability(cve_id="CVE-2021-44228", description="log4j jndi",
                      severity="CRITICAL", fixed_versions=["2.15.0"],
                      affected=[AffectedProduct(product="log4j", version_start="2.0",
                                version_end="2.15.0", version_start_incl=True)],
                      published=date(2021, 1, 1), last_modified=date(2021, 1, 1))
    index_vulnerabilities([v], embedder=emb, store=store)
    app = create_app(store=store, embedder=emb,
                     llm=StubLLM(reply="Уязвимо: CVE-2021-44228"))
    return TestClient(app)


def test_health():
    assert _client().get("/health").json()["status"] == "ok"


def test_stats_reports_count():
    assert _client().get("/stats").json()["cve_count"] == 1


def test_query_returns_verdict_and_cves():
    resp = _client().post("/query", json={"question": "Безопасен ли log4j 2.14.1?"})
    body = resp.json()
    assert body["verdict"] == "vulnerable"
    assert body["cves"][0]["cve_id"] == "CVE-2021-44228"
    assert body["lang"] == "ru"
