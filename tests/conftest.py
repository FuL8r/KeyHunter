import json
from pathlib import Path
import pytest

FIXTURES = Path(__file__).parent / "fixtures"


def _load(name):
    return json.loads((FIXTURES / name).read_text())


@pytest.fixture
def nvd_raw():
    return _load("nvd_cve.json")


@pytest.fixture
def kev_raw():
    return _load("kev.json")


@pytest.fixture
def osv_raw():
    return _load("osv.json")
