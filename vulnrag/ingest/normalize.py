from datetime import date, datetime
from vulnrag.models import AffectedProduct, Vulnerability
from vulnrag.ingest.cpe import parse_cpe23


def _to_date(s: str) -> date:
    return datetime.fromisoformat(s.replace("Z", "")).date()


def _en_description(cve: dict) -> str:
    for d in cve.get("descriptions", []):
        if d.get("lang") == "en":
            return d["value"]
    return ""


def _cvss(cve: dict):
    metrics = cve.get("metrics", {})
    for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
        if metrics.get(key):
            data = metrics[key][0]["cvssData"]
            return data.get("baseScore"), data.get("baseSeverity")
    return None, None


def _affected(cve: dict) -> list[AffectedProduct]:
    out = []
    for cfg in cve.get("configurations", []):
        for node in cfg.get("nodes", []):
            for m in node.get("cpeMatch", []):
                vendor, product = parse_cpe23(m.get("criteria", ""))
                if not product:
                    continue
                start = m.get("versionStartIncluding") or m.get("versionStartExcluding")
                end = m.get("versionEndIncluding") or m.get("versionEndExcluding")
                out.append(AffectedProduct(
                    vendor=vendor, product=product,
                    version_start=start,
                    version_start_incl="versionStartIncluding" in m,
                    version_end=end,
                    version_end_incl="versionEndIncluding" in m,
                ))
    return out


def normalize_nvd(raw: dict) -> Vulnerability:
    cve = raw["cve"]
    score, severity = _cvss(cve)
    return Vulnerability(
        cve_id=cve["id"],
        description=_en_description(cve),
        cvss_score=score,
        severity=severity,
        affected=_affected(cve),
        references=[r["url"] for r in cve.get("references", [])],
        sources=["nvd"],
        published=_to_date(cve["published"]),
        last_modified=_to_date(cve["lastModified"]),
    )
