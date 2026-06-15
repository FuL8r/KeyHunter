import httpx
import respx
from vulnrag.ingest.sources.nvd import fetch_nvd

NVD = "https://services.nvd.nist.gov/rest/json/cves/2.0"


@respx.mock
def test_fetch_nvd_paginates_and_passes_date():
    page1 = {"totalResults": 2, "resultsPerPage": 1, "startIndex": 0,
             "vulnerabilities": [{"cve": {"id": "CVE-A"}}]}
    page2 = {"totalResults": 2, "resultsPerPage": 1, "startIndex": 1,
             "vulnerabilities": [{"cve": {"id": "CVE-B"}}]}
    route = respx.get(NVD).mock(side_effect=[
        httpx.Response(200, json=page1),
        httpx.Response(200, json=page2),
    ])
    got = list(fetch_nvd(since="2019-01-01T00:00:00", page_size=1, sleep=lambda s: None))
    assert [r["cve"]["id"] for r in got] == ["CVE-A", "CVE-B"]
    assert "pubStartDate" in route.calls[0].request.url.params or \
           "lastModStartDate" in route.calls[0].request.url.params
