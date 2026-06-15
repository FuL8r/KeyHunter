import time
from datetime import datetime, timedelta, timezone
import httpx

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"
_WINDOW_DAYS = 120


def _parse_iso(s: str) -> datetime:
    return datetime.fromisoformat(s).replace(tzinfo=None)


def _now() -> datetime:
    return datetime.now(timezone.utc).replace(tzinfo=None)


def _fmt(dt: datetime) -> str:
    return dt.strftime("%Y-%m-%dT%H:%M:%S")


def fetch_nvd(since: str, *, until: str | None = None, mode: str = "pub",
              api_key: str | None = None, page_size: int = 2000, sleep=time.sleep):
    """Yield raw NVD CVE objects published (mode='pub') or modified (mode='mod')
    in [since, until]. The range is sliced into <=120-day windows because the
    NVD API rejects longer ranges. `until` defaults to now."""
    start_param = "pubStartDate" if mode == "pub" else "lastModStartDate"
    end_param = "pubEndDate" if mode == "pub" else "lastModEndDate"
    headers = {"apiKey": api_key} if api_key else {}

    window_start = _parse_iso(since)
    final_end = _parse_iso(until) if until else _now()

    while window_start < final_end:
        window_end = min(window_start + timedelta(days=_WINDOW_DAYS), final_end)
        start_index = 0
        while True:
            params = {
                start_param: _fmt(window_start),
                end_param: _fmt(window_end),
                "resultsPerPage": page_size,
                "startIndex": start_index,
            }
            resp = httpx.get(NVD_URL, params=params, headers=headers, timeout=60)
            resp.raise_for_status()
            data = resp.json()
            vulns = data.get("vulnerabilities", [])
            for item in vulns:
                yield item
            start_index += len(vulns)
            if start_index >= data.get("totalResults", 0) or not vulns:
                break
            sleep(6)
        window_start = window_end
        if window_start < final_end:
            sleep(6)
