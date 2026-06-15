from datetime import date
from qdrant_client import QdrantClient
from vulnrag.clients import StubEmbedder
from vulnrag.store import VulnStore
from vulnrag.ingest.sync import run_sync, SyncState
from vulnrag.ingest.sources.nvd import fetch_nvd


def test_run_sync_normalizes_enriches_and_indexes(tmp_path, nvd_raw, kev_raw, osv_raw):
    client = QdrantClient(":memory:")
    store = VulnStore(client, "test", 1024)
    store.ensure_collection()
    state = SyncState(str(tmp_path / "state.json"))

    report = run_sync(
        store=store, embedder=StubEmbedder(1024), state=state,
        fetch_nvd=lambda since, mode: iter([nvd_raw]),
        fetch_kev=lambda: kev_raw,
        fetch_osv=lambda cve_ids: [osv_raw],
        now="2024-06-01T00:00:00",
    )
    assert report["indexed"] == 1
    assert store.count() == 1
    hit = store.search(StubEmbedder(1024).embed(["log4j"])[0], product="log4j", top_k=1)[0]
    assert hit.payload["is_kev"] is True
    assert hit.payload["fixed_versions"] == ["2.15.0"]
    assert state.last_sync("nvd") == "2024-06-01T00:00:00"
    assert state.last_sync("kev") == "2024-06-01T00:00:00"


def test_run_sync_source_failure_does_not_advance_that_source(tmp_path, nvd_raw):
    client = QdrantClient(":memory:")
    store = VulnStore(client, "test", 1024)
    store.ensure_collection()
    state = SyncState(str(tmp_path / "state.json"))

    def boom():
        raise RuntimeError("KEV down")

    report = run_sync(
        store=store, embedder=StubEmbedder(1024), state=state,
        fetch_nvd=lambda since, mode: iter([nvd_raw]),
        fetch_kev=boom,
        fetch_osv=lambda cve_ids: [],
        now="2024-06-01T00:00:00",
    )
    assert state.last_sync("nvd") == "2024-06-01T00:00:00"
    assert state.last_sync("kev") is None
    assert "kev" in report["errors"]
    assert store.count() == 1


def test_run_sync_passes_start_date_to_fetch_nvd(tmp_path, nvd_raw):
    client = QdrantClient(":memory:")
    store = VulnStore(client, "test", 1024)
    store.ensure_collection()
    state = SyncState(str(tmp_path / "state.json"))
    seen = {}

    def fake_fetch_nvd(since, mode):
        seen["since"] = since
        seen["mode"] = mode
        return iter([nvd_raw])

    run_sync(store=store, embedder=StubEmbedder(1024), state=state,
             fetch_nvd=fake_fetch_nvd, fetch_kev=lambda: {"vulnerabilities": []},
             fetch_osv=lambda cve_ids: [], now="2024-06-01T00:00:00",
             start_date="2025-01-01T00:00:00")
    assert seen["since"] == "2025-01-01T00:00:00"
    assert seen["mode"] == "pub"
