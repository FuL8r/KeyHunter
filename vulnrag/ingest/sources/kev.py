import httpx

KEV_URL = "https://www.cisa.gov/sites/default/files/feeds/known_exploited_vulnerabilities.json"


def fetch_kev() -> dict:
    resp = httpx.get(KEV_URL, timeout=60)
    resp.raise_for_status()
    return resp.json()
