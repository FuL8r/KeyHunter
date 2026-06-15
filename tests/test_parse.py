from vulnrag.query.parse import detect_lang, extract_component_version


def test_detect_lang():
    assert detect_lang("Безопасен ли Python 2.10?") == "ru"
    assert detect_lang("Is Python 2.10 safe?") == "en"


def test_extract_component_version_basic():
    assert extract_component_version("Is python 2.10 safe?") == ("python", "2.10")
    assert extract_component_version("Безопасен ли log4j 2.14.1?") == ("log4j", "2.14.1")


def test_extract_component_without_version():
    comp, ver = extract_component_version("Is openssl vulnerable?")
    assert comp == "openssl"
    assert ver is None
