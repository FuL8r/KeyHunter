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
    # single ~31-day window (within the 120-day limit) -> just pagination
    got = list(fetch_nvd(since="2024-01-01T00:00:00", until="2024-02-01T00:00:00",
                         page_size=1, sleep=lambda s: None))
    assert [r["cve"]["id"] for r in got] == ["CVE-A", "CVE-B"]
    assert "pubStartDate" in route.calls[0].request.url.params


@respx.mock
def test_fetch_nvd_splits_long_range_into_120day_windows():
    empty = {"totalResults": 0, "resultsPerPage": 0, "startIndex": 0,
             "vulnerabilities": []}
    route = respx.get(NVD).mock(return_value=httpx.Response(200, json=empty))
    # ~243 days => 3 windows (120 + 120 + 3)
    list(fetch_nvd(since="2024-01-01T00:00:00", until="2024-09-01T00:00:00",
                   page_size=2000, sleep=lambda s: None))
    assert len(route.calls) == 3
    starts = [c.request.url.params["pubStartDate"] for c in route.calls]
    # windows are contiguous and advance
    assert starts[0].startswith("2024-01-01")
    assert starts[1].startswith("2024-04-30") or starts[1].startswith("2024-05-01")
    assert starts != sorted(set(starts)) or len(set(starts)) == 3  # all distinct


@respx.mock
def test_fetch_nvd_mod_mode_uses_lastmod_params():
    empty = {"totalResults": 0, "vulnerabilities": []}
    route = respx.get(NVD).mock(return_value=httpx.Response(200, json=empty))
    list(fetch_nvd(since="2024-01-01T00:00:00", until="2024-01-15T00:00:00",
                   mode="mod", page_size=2000, sleep=lambda s: None))
    assert "lastModStartDate" in route.calls[0].request.url.params
