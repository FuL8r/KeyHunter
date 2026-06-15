from dataclasses import dataclass, field
from vulnrag.clients import EmbeddingClient, LLMClient
from vulnrag.store import VulnStore
from vulnrag.query.parse import detect_lang, extract_component_version
from vulnrag.query.retrieve import retrieve
from vulnrag.query.match import classify

SYSTEM = (
    "You are a security assistant. Answer ONLY from the provided CVE context. "
    "Never invent CVE identifiers. If the context is empty, say no vulnerability "
    "was found in the database. Reply in the language requested. Structure: "
    "verdict (safe / vulnerable / unconfirmed), list of CVEs with severity, then remediation "
    "(upgrade to fixed version, mitigations from references)."
)


@dataclass
class QueryResult:
    verdict: str                       # "vulnerable" | "unconfirmed" | "safe" | "not_found"
    answer_text: str
    cves: list[dict] = field(default_factory=list)
    lang: str = "en"


def _context_block(hits) -> str:
    lines = []
    for h in hits:
        p = h.payload
        lines.append(
            f"- {p['cve_id']} (severity={p.get('severity')}, "
            f"fixed={p.get('fixed_versions')}): {p.get('description')} "
            f"refs={p.get('references')}"
        )
    return "\n".join(lines)


def answer(question: str, *, embedder: EmbeddingClient, store: VulnStore,
           llm: LLMClient, top_k: int = 8) -> QueryResult:
    lang = detect_lang(question)
    component, version = extract_component_version(question)
    hits = retrieve(question, embedder=embedder, store=store, top_k=top_k)
    result = classify(hits, component=component, version=version)
    relevant = result.confirmed + result.potential

    if not relevant:
        # No CVEs to ground on -> do NOT call the LLM (anti-hallucination).
        component_in_hits = (component is not None
                             and any(component in h.payload.get("products", [])
                                     for h in hits))
        if hits and version is not None and component_in_hits:
            verdict = "safe"
            text = ("По данным базы (CVE 2019+) указанная версия не входит "
                    "в известные уязвимые диапазоны."
                    if lang == "ru"
                    else "Per the database (CVE 2019+), the specified version is "
                         "not in any known affected range.")
        else:
            verdict = "not_found"
            text = ("В базе (CVE 2019+) ничего не найдено для этого запроса."
                    if lang == "ru"
                    else "Nothing found in the database (CVE 2019+) for this query.")
        return QueryResult(verdict=verdict, answer_text=text, cves=[], lang=lang)

    lang_instr = "Answer in Russian." if lang == "ru" else "Answer in English."
    prompt = (
        f"{lang_instr}\nQuestion: {question}\n\nCVE context:\n"
        f"{_context_block(relevant)}\n"
    )
    text = llm.complete(system=SYSTEM, prompt=prompt)
    verdict = "vulnerable" if result.confirmed else "unconfirmed"
    cves = [{"cve_id": h.payload["cve_id"], "severity": h.payload.get("severity"),
             "fixed_versions": h.payload.get("fixed_versions"),
             "references": h.payload.get("references")} for h in relevant]
    return QueryResult(verdict=verdict, answer_text=text, cves=cves, lang=lang)
