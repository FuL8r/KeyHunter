from datetime import date
from vulnrag.models import AffectedProduct, Vulnerability


def test_vulnerability_minimal_roundtrip():
    v = Vulnerability(
        cve_id="CVE-2021-44228",
        description="Log4j JNDI RCE",
        published=date(2021, 12, 10),
        last_modified=date(2021, 12, 11),
    )
    assert v.cve_id == "CVE-2021-44228"
    assert v.affected == []
    assert v.is_kev is False
    assert v.sources == []


def test_affected_product_defaults():
    ap = AffectedProduct(product="python")
    assert ap.vendor is None
    assert ap.version_start_incl is False
    assert ap.version_end_incl is False
    assert ap.fixed_version is None
