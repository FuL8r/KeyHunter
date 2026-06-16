from dataclasses import dataclass, field
from vulnrag.models import AffectedProduct
from vulnrag.store import Hit
from vulnrag.ingest.versions import in_range


@dataclass
class MatchResult:
    confirmed: list[Hit] = field(default_factory=list)
    potential: list[Hit] = field(default_factory=list)


def classify(hits: list[Hit], *, component: str | None, version: str | None) -> MatchResult:
    result = MatchResult()
    for hit in hits:
        # When a component is asked for, only consider hits that actually concern it.
        # (Semantic fallback in retrieve can surface unrelated CVEs — drop them so an
        # unrelated open-ended range never produces a false "vulnerable".)
        if component is not None and component not in hit.payload.get("products", []):
            continue
        ranges = [AffectedProduct(**a) for a in hit.payload.get("affected", [])]
        if component is not None:
            ranges = [r for r in ranges if r.product == component]
        if version is None:
            result.potential.append(hit)
            continue
        if any(in_range(version, r) for r in ranges):
            result.confirmed.append(hit)
        # else: dropped (version provided but not in any affected range)
    return result
