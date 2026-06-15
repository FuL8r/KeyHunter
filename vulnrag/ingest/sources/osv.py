import httpx

OSV_URL = "https://api.osv.dev/v1/query"


def fetch_osv(cve_ids: list[str]) -> list[dict]:
    """Query OSV by CVE id. Returns raw OSV vuln records (deduped by id)."""
    seen: dict[str, dict] = {}
    for cve_id in cve_ids:
        resp = httpx.post(OSV_URL, json={"id": cve_id}, timeout=60)
        if resp.status_code == 404:
            continue
        resp.raise_for_status()
        for rec in resp.json().get("vulns", []):
            seen[rec["id"]] = rec
    return list(seen.values())
