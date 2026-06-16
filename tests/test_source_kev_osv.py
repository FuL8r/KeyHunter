import httpx
import respx
from vulnrag.ingest.sources.kev import fetch_kev, KEV_URL
from vulnrag.ingest.sources.osv import fetch_osv, OSV_URL


@respx.mock
def test_fetch_kev():
    respx.get(KEV_URL).mock(return_value=httpx.Response(
        200, json={"vulnerabilities": [{"cveID": "CVE-X"}]}))
    assert fetch_kev() == {"vulnerabilities": [{"cveID": "CVE-X"}]}


@respx.mock
def test_fetch_osv_fetches_record_by_cve_id():
    respx.get(f"{OSV_URL}/CVE-X").mock(return_value=httpx.Response(
        200, json={"id": "CVE-X", "aliases": ["GHSA-1"], "affected": []}))
    out = fetch_osv(["CVE-X"])
    assert out[0]["id"] == "CVE-X"


@respx.mock
def test_fetch_osv_skips_404():
    respx.get(f"{OSV_URL}/CVE-NONE").mock(return_value=httpx.Response(404))
    assert fetch_osv(["CVE-NONE"]) == []
