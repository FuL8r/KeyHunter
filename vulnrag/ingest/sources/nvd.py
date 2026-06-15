import time
import httpx

NVD_URL = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def fetch_nvd(since: str, *, mode: str = "pub", api_key: str | None = None,
              page_size: int = 2000, sleep=time.sleep):
    """Yield raw NVD CVE objects modified/published on or after `since`
    (ISO-8601). `mode` is 'pub' (backfill) or 'mod' (delta)."""
    date_param = "pubStartDate" if mode == "pub" else "lastModStartDate"
    end_param = "pubEndDate" if mode == "pub" else "lastModEndDate"
    headers = {"apiKey": api_key} if api_key else {}
    start_index = 0
    while True:
        params = {
            date_param: since,
            end_param: _now_iso(),
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
        sleep(6)  # respect NVD rate limit (tighter without an API key)


def _now_iso():
    from datetime import datetime, timezone
    return datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%S")
