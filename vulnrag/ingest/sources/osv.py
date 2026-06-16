import httpx

# Base URL for the OSV "get vulnerability by id" endpoint: GET {OSV_URL}/{id}
OSV_URL = "https://api.osv.dev/v1/vulns"


def fetch_osv(cve_ids: list[str]) -> list[dict]:
    """Fetch OSV records by CVE id via GET /v1/vulns/{id}. 404 means OSV has no
    record for that CVE (skipped). Returns the raw OSV records."""
    out: list[dict] = []
    for cve_id in cve_ids:
        resp = httpx.get(f"{OSV_URL}/{cve_id}", timeout=60)
        if resp.status_code == 404:
            continue
        resp.raise_for_status()
        out.append(resp.json())
    return out
