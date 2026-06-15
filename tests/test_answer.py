from datetime import date
from qdrant_client import QdrantClient
from vulnrag.models import AffectedProduct, Vulnerability
from vulnrag.clients import StubEmbedder, StubLLM
from vulnrag.store import VulnStore
from vulnrag.index.embedder import index_vulnerabilities
from vulnrag.query.answer import answer


def _store():
    client = QdrantClient(":memory:")
    store = VulnStore(client, "test", 1024)
    store.ensure_collection()
    emb = StubEmbedder(1024)
    v = Vulnerability(cve_id="CVE-2021-44228", description="log4j jndi rce",
                      severity="CRITICAL", fixed_versions=["2.15.0"],
                      affected=[AffectedProduct(product="log4j", version_start="2.0",
                                version_end="2.15.0", version_start_incl=True)],
                      published=date(2021, 1, 1), last_modified=date(2021, 1, 1))
    index_vulnerabilities([v], embedder=emb, store=store)
    return store, emb


def test_answer_confirmed_builds_grounded_prompt_and_returns_result():
    store, emb = _store()
    llm = StubLLM(reply="Уязвимо: CVE-2021-44228. Обновить до 2.15.0.")
    result = answer("Безопасен ли log4j 2.14.1?", embedder=emb, store=store, llm=llm)
    assert result.verdict == "vulnerable"
    assert "CVE-2021-44228" in [c["cve_id"] for c in result.cves]
    assert result.lang == "ru"
    assert "CVE-2021-44228" in llm.last_prompt


def test_answer_empty_when_nothing_found():
    store, emb = _store()
    llm = StubLLM(reply="ignored")
    result = answer("Is brandnewlib 1.0 safe?", embedder=emb, store=store, llm=llm)
    assert result.verdict == "not_found"
    assert result.cves == []
