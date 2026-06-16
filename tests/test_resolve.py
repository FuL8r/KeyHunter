from vulnrag.query.resolve import resolve_component

PRODUCTS = {"samtools", "log4j", "openssl"}


def test_exact_match_unchanged():
    assert resolve_component("samtools", PRODUCTS) == "samtools"


def test_typo_snaps_to_closest():
    # "samtols" ratio vs "samtools" = 0.933 — safely above 0.85 cutoff
    assert resolve_component("samtols", PRODUCTS) == "samtools"
    # "openssi" ratio vs "openssl" = 0.857 — just above 0.85 cutoff
    assert resolve_component("openssi", PRODUCTS) == "openssl"


def test_unknown_component_unchanged():
    assert resolve_component("totally-made-up-lib", PRODUCTS) == "totally-made-up-lib"


def test_none_unchanged():
    assert resolve_component(None, PRODUCTS) is None
