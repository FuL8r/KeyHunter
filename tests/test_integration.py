from qdrant_client import QdrantClient
from vulnrag.clients import StubEmbedder, StubLLM
from vulnrag.store import VulnStore
from vulnrag.ingest.sync import run_sync, SyncState
from vulnrag.query.answer import answer


def test_end_to_end_log4j(tmp_path, nvd_raw, kev_raw, osv_raw):
    client = QdrantClient(":memory:")
    store = VulnStore(client, "vulns", 1024)
    store.ensure_collection()
    emb = StubEmbedder(1024)
    state = SyncState(str(tmp_path / "s.json"))
    run_sync(store=store, embedder=emb, state=state,
             fetch_nvd=lambda since, mode: iter([nvd_raw]),
             fetch_kev=lambda: kev_raw,
             fetch_osv=lambda cve_ids: [osv_raw],
             now="2024-06-01T00:00:00")

    vulnerable = answer("Безопасен ли log4j 2.14.1?", embedder=emb, store=store,
                        llm=StubLLM(reply="Уязвимо"))
    assert vulnerable.verdict == "vulnerable"
    assert vulnerable.cves[0]["cve_id"] == "CVE-2021-44228"

    safe = answer("Is log4j 2.16.0 safe?", embedder=emb, store=store,
                  llm=StubLLM(reply="Safe"))
    assert safe.verdict in ("safe", "not_found")
