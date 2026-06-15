from packaging.version import Version, InvalidVersion
from vulnrag.models import AffectedProduct


def parse_version(raw: str):
    """Return a comparable version. Falls back to a tuple of int/str segments
    for schemes packaging can't handle (e.g. '1.1.1k')."""
    try:
        return Version(raw)
    except (InvalidVersion, TypeError):
        segments = []
        for part in str(raw).replace("-", ".").split("."):
            num = "".join(c for c in part if c.isdigit())
            suffix = "".join(c for c in part if not c.isdigit())
            segments.append((int(num) if num else 0, suffix))
        return _Fallback(tuple(segments))


class _Fallback:
    def __init__(self, segs):
        self.segs = segs

    def _cmp_key(self):
        return self.segs

    def _coerce(self, other):
        """Coerce other to _Fallback for cross-type comparison."""
        if isinstance(other, _Fallback):
            return other
        # other is a packaging Version; re-parse its string representation
        return _str_to_fallback(str(other))

    def __lt__(self, other):
        return self._cmp_key() < self._coerce(other)._cmp_key()

    def __le__(self, other):
        return self._cmp_key() <= self._coerce(other)._cmp_key()

    def __gt__(self, other):
        return self._cmp_key() > self._coerce(other)._cmp_key()

    def __ge__(self, other):
        return self._cmp_key() >= self._coerce(other)._cmp_key()

    def __eq__(self, other):
        return isinstance(other, _Fallback) and self.segs == other.segs


def _str_to_fallback(raw: str) -> "_Fallback":
    """Build a _Fallback from a raw version string (used for coercion)."""
    segments = []
    for part in str(raw).replace("-", ".").split("."):
        num = "".join(c for c in part if c.isdigit())
        suffix = "".join(c for c in part if not c.isdigit())
        segments.append((int(num) if num else 0, suffix))
    return _Fallback(tuple(segments))


def in_range(version: str, ap: AffectedProduct) -> bool:
    """True if `version` falls inside the affected range described by `ap`.
    No bounds => the whole product is affected. Unparseable version => False."""
    try:
        v = parse_version(version)
    except Exception:
        return False
    if not _looks_like_version(version):
        return False

    if ap.version_start is not None:
        lo = parse_version(ap.version_start)
        if ap.version_start_incl:
            if v < lo:
                return False
        else:
            if v <= lo:
                return False
    if ap.version_end is not None:
        hi = parse_version(ap.version_end)
        if ap.version_end_incl:
            if v > hi:
                return False
        else:
            if v >= hi:
                return False
    return True


def _looks_like_version(raw: str) -> bool:
    return any(c.isdigit() for c in str(raw))
