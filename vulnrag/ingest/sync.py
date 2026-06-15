import json
from pathlib import Path


class SyncState:
    def __init__(self, path: str):
        self.path = Path(path)
        self._data = json.loads(self.path.read_text()) if self.path.exists() else {}

    def last_sync(self, source: str) -> str | None:
        return self._data.get(source)

    def set_last_sync(self, source: str, when: str):
        self._data[source] = when
        self.path.write_text(json.dumps(self._data, indent=2))


from vulnrag.ingest.normalize import (
    normalize_nvd, kev_cve_ids, osv_fixed_versions, merge_enrichment,
)
from vulnrag.index.embedder import index_vulnerabilities


def run_sync(*, store, embedder, state, fetch_nvd, fetch_kev, fetch_osv, now):
    """Fetch NVD (backfill or delta), enrich with KEV/OSV, index. Each source's
    cursor advances only on its own success."""
    report = {"indexed": 0, "errors": {}}

    # --- NVD (required base) ---
    nvd_since = state.last_sync("nvd")
    mode = "mod" if nvd_since else "pub"
    since = nvd_since or "2019-01-01T00:00:00"
    try:
        vulns = [normalize_nvd(raw) for raw in fetch_nvd(since=since, mode=mode)]
    except Exception as e:
        report["errors"]["nvd"] = str(e)
        return report

    cve_ids = [v.cve_id for v in vulns]

    # --- KEV enrichment (optional) ---
    kev_ids: set[str] = set()
    try:
        kev_ids = kev_cve_ids(fetch_kev())
        state.set_last_sync("kev", now)
    except Exception as e:
        report["errors"]["kev"] = str(e)

    # --- OSV enrichment (optional) ---
    osv_fixed: dict[str, list[str]] = {}
    try:
        osv_fixed = osv_fixed_versions(fetch_osv(cve_ids))
        state.set_last_sync("osv", now)
    except Exception as e:
        report["errors"]["osv"] = str(e)

    vulns = [merge_enrichment(v, kev_ids=kev_ids, osv_fixed=osv_fixed) for v in vulns]

    index_vulnerabilities(vulns, embedder=embedder, store=store)
    report["indexed"] = len(vulns)
    state.set_last_sync("nvd", now)
    return report
