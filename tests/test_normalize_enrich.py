from datetime import date
from vulnrag.models import Vulnerability
from vulnrag.ingest.normalize import kev_cve_ids, osv_fixed_versions, merge_enrichment


def _base():
    return Vulnerability(cve_id="CVE-2021-44228", description="x",
                         published=date(2021, 12, 10), last_modified=date(2021, 12, 11))


def test_kev_cve_ids(kev_raw):
    assert kev_cve_ids(kev_raw) == {"CVE-2021-44228"}


def test_osv_fixed_versions_by_cve(osv_raw):
    mapping = osv_fixed_versions([osv_raw])
    assert mapping["CVE-2021-44228"] == ["2.15.0"]


def test_osv_fixed_versions_keyed_by_record_id():
    rec = {"id": "CVE-2021-44228", "aliases": ["GHSA-1"],
           "affected": [{"ranges": [{"events": [{"introduced": "2.0"}, {"fixed": "2.15.0"}]}]}]}
    mapping = osv_fixed_versions([rec])
    assert mapping["CVE-2021-44228"] == ["2.15.0"]


def test_merge_sets_kev_and_fixed(kev_raw, osv_raw):
    v = merge_enrichment(_base(), kev_ids=kev_cve_ids(kev_raw),
                         osv_fixed=osv_fixed_versions([osv_raw]))
    assert v.is_kev is True
    assert v.fixed_versions == ["2.15.0"]
    assert "kev" in v.sources and "osv" in v.sources
