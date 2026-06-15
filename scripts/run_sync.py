"""Daily ingestion job: backfill on first run, delta afterwards."""
from datetime import datetime, timezone
from vulnrag.config import Settings
from vulnrag.factory import build_components
from vulnrag.ingest.sync import run_sync, SyncState
from vulnrag.ingest.sources.nvd import fetch_nvd
from vulnrag.ingest.sources.kev import fetch_kev
from vulnrag.ingest.sources.osv import fetch_osv


def main():
    s = Settings()
    store, embedder, _llm = build_components(s)   # real Qdrant + Ollama
    store.ensure_collection()
    state = SyncState(s.sync_state_path)
    now = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
    report = run_sync(
        store=store, embedder=embedder, state=state,
        fetch_nvd=lambda since, mode: fetch_nvd(since=since, mode=mode, api_key=s.nvd_api_key),
        fetch_kev=fetch_kev,
        fetch_osv=fetch_osv,
        now=now,
    )
    print(report)


if __name__ == "__main__":
    main()
