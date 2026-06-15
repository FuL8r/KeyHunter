import re

_VERSION_RE = re.compile(r"\b(\d+(?:\.\d+){0,3}[a-z]?)\b")
_COMPONENT_RE = re.compile(r"\b([a-zA-Z][a-zA-Z0-9_\-\.\+]{1,40})\b")
_STOPWORDS = {"is", "safe", "vulnerable", "the", "a", "an", "in", "ли",
              "безопасен", "безопасно", "уязвим", "уязвима", "версия", "of"}


def detect_lang(text: str) -> str:
    return "ru" if re.search(r"[А-Яа-яЁё]", text) else "en"


def extract_component_version(question: str) -> tuple[str | None, str | None]:
    version = None
    m = _VERSION_RE.search(question)
    if m:
        version = m.group(1)
    component = None
    for token in _COMPONENT_RE.findall(question):
        low = token.lower()
        if low in _STOPWORDS or _VERSION_RE.fullmatch(token):
            continue
        component = low
        break
    return component, version
