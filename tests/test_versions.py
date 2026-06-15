import pytest
from vulnrag.models import AffectedProduct
from vulnrag.ingest.versions import parse_version, in_range


@pytest.mark.parametrize("a,b,expected", [
    ("2.10", "3.0", True),    # 2.10 < 3.0
    ("2.10", "2.9", False),   # 2.10 > 2.9 (numeric, not lexical)
    ("1.1.1k", "1.1.1l", True),
])
def test_parse_version_ordering(a, b, expected):
    assert (parse_version(a) < parse_version(b)) is expected


def test_in_range_half_open():
    ap = AffectedProduct(product="python", version_start="2.0",
                         version_end="3.0", version_start_incl=True,
                         version_end_incl=False)
    assert in_range("2.10", ap) is True
    assert in_range("3.0", ap) is False
    assert in_range("1.9", ap) is False


def test_in_range_inclusive_end():
    ap = AffectedProduct(product="openssl", version_start="1.1.1",
                         version_end="1.1.1k", version_start_incl=True,
                         version_end_incl=True)
    assert in_range("1.1.1k", ap) is True
    assert in_range("1.1.1l", ap) is False


def test_in_range_no_bounds_means_all_versions():
    ap = AffectedProduct(product="foo")
    assert in_range("9.9.9", ap) is True


def test_in_range_unparseable_version_is_false():
    ap = AffectedProduct(product="foo", version_end="2.0", version_end_incl=False)
    assert in_range("not-a-version", ap) is False
