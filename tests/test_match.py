from vulnrag.store import Hit
from vulnrag.query.match import classify


def _hit(cve_id, product, start=None, end=None, s_incl=True, e_incl=False):
    affected = [{"vendor": None, "product": product, "version_start": start,
                 "version_end": end, "version_start_incl": s_incl,
                 "version_end_incl": e_incl, "fixed_version": None}]
    return Hit(cve_id, 0.9, {"cve_id": cve_id, "products": [product],
                             "affected": affected})


def test_confirmed_when_version_in_range():
    hits = [_hit("CVE-LOG", "log4j", start="2.0", end="2.15.0")]
    result = classify(hits, component="log4j", version="2.14.1")
    assert [h.cve_id for h in result.confirmed] == ["CVE-LOG"]
    assert result.potential == []


def test_potential_when_no_version_given():
    hits = [_hit("CVE-LOG", "log4j", start="2.0", end="2.15.0")]
    result = classify(hits, component="log4j", version=None)
    assert [h.cve_id for h in result.potential] == ["CVE-LOG"]
    assert result.confirmed == []


def test_dropped_when_version_out_of_range():
    hits = [_hit("CVE-LOG", "log4j", start="2.0", end="2.15.0")]
    result = classify(hits, component="log4j", version="2.16.0")
    assert result.confirmed == [] and result.potential == []
