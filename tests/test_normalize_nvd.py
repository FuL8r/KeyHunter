from datetime import date
from vulnrag.ingest.normalize import normalize_nvd


def test_normalize_nvd_core_fields(nvd_raw):
    v = normalize_nvd(nvd_raw)
    assert v.cve_id == "CVE-2021-44228"
    assert "Log4j2" in v.description
    assert v.cvss_score == 10.0
    assert v.severity == "CRITICAL"
    assert v.published == date(2021, 12, 10)
    assert "nvd" in v.sources


def test_normalize_nvd_affected_ranges(nvd_raw):
    v = normalize_nvd(nvd_raw)
    assert len(v.affected) == 1
    ap = v.affected[0]
    assert ap.product == "log4j"
    assert ap.version_start == "2.0" and ap.version_start_incl is True
    assert ap.version_end == "2.15.0" and ap.version_end_incl is False
