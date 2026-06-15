from vulnrag.ingest.cpe import parse_cpe23


def test_parse_cpe_extracts_vendor_product():
    vendor, product = parse_cpe23("cpe:2.3:a:python:python:*:*:*:*:*:*:*:*")
    assert vendor == "python"
    assert product == "python"


def test_parse_cpe_handles_multiword_product():
    vendor, product = parse_cpe23("cpe:2.3:a:apache:log4j:2.14.1:*:*:*:*:*:*:*")
    assert (vendor, product) == ("apache", "log4j")


def test_parse_cpe_invalid_returns_none():
    assert parse_cpe23("garbage") == (None, None)
