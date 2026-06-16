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
                    version_start_incl=m.get("versionStartIncluding") is not None,
                    version_end=end,
                    version_end_incl=m.get("versionEndIncluding") is not None,
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


def kev_cve_ids(kev_raw: dict) -> set[str]:
    return {e["cveID"] for e in kev_raw.get("vulnerabilities", [])}


def osv_fixed_versions(osv_records: list[dict]) -> dict[str, list[str]]:
    """Map each related CVE id -> list of 'fixed' versions from OSV ranges.
    The CVE may appear as the record's own `id` or among its `aliases`."""
    out: dict[str, list[str]] = {}
    for rec in osv_records:
        fixed = []
        for aff in rec.get("affected", []):
            for rng in aff.get("ranges", []):
                # Skip GIT ranges: their "fixed" events are commit hashes, not versions.
                if rng.get("type") == "GIT":
                    continue
                for ev in rng.get("events", []):
                    if "fixed" in ev:
                        fixed.append(ev["fixed"])
        cve_keys = set()
        rid = rec.get("id", "")
        if isinstance(rid, str) and rid.startswith("CVE-"):
            cve_keys.add(rid)
        for alias in rec.get("aliases", []):
            if isinstance(alias, str) and alias.startswith("CVE-"):
                cve_keys.add(alias)
        for key in cve_keys:
            out.setdefault(key, [])
            out[key].extend(f for f in fixed if f not in out[key])
    return out


def merge_enrichment(v: Vulnerability, kev_ids: set[str],
                     osv_fixed: dict[str, list[str]]) -> Vulnerability:
    sources = list(v.sources)
    if v.cve_id in kev_ids:
        v.is_kev = True
        if "kev" not in sources:
            sources.append("kev")
    if v.cve_id in osv_fixed:
        v.fixed_versions = list(dict.fromkeys(v.fixed_versions + osv_fixed[v.cve_id]))
        if "osv" not in sources:
            sources.append("osv")
    v.sources = sources
    return v
