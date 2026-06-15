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
def test_fetch_osv_queries_by_cve():
    respx.post(OSV_URL).mock(return_value=httpx.Response(
        200, json={"vulns": [{"id": "OSV-1", "aliases": ["CVE-X"]}]}))
    out = fetch_osv(["CVE-X"])
    assert out[0]["id"] == "OSV-1"
