from __future__ import annotations
import uuid
from qdrant_client import QdrantClient, models as qm
from vulnrag.models import Vulnerability


def _point_id(cve_id: str) -> str:
    # Deterministic UUID so re-upserting the same CVE overwrites (idempotent).
    return str(uuid.uuid5(uuid.NAMESPACE_URL, cve_id))


class Hit:
    def __init__(self, cve_id: str, score: float, payload: dict):
        self.cve_id = cve_id
        self.score = score
        self.payload = payload


class VulnStore:
    def __init__(self, client: QdrantClient, collection: str, dim: int):
        self.client = client
        self.collection = collection
        self.dim = dim

    def ensure_collection(self):
        if not self.client.collection_exists(self.collection):
            self.client.create_collection(
                self.collection,
                vectors_config=qm.VectorParams(size=self.dim, distance=qm.Distance.COSINE),
            )

    def _payload(self, v: Vulnerability) -> dict:
        products = sorted({a.product for a in v.affected})
        return {
            "cve_id": v.cve_id,
            "description": v.description,
            "severity": v.severity,
            "cvss_score": v.cvss_score,
            "is_kev": v.is_kev,
            "year": v.published.year,
            "products": products,
            "fixed_versions": v.fixed_versions,
            "references": v.references,
            "affected": [a.model_dump() for a in v.affected],
            "sources": v.sources,
        }

    def upsert(self, vulns: list[Vulnerability], vectors: list[list[float]]):
        points = [
            qm.PointStruct(id=_point_id(v.cve_id), vector=vec, payload=self._payload(v))
            for v, vec in zip(vulns, vectors)
        ]
        self.client.upsert(self.collection, points=points)

    def count(self) -> int:
        return self.client.count(self.collection).count

    def search(self, vector: list[float], *, product: str | None = None,
               is_kev: bool | None = None, top_k: int = 8) -> list[Hit]:
        must = []
        if product:
            must.append(qm.FieldCondition(key="products", match=qm.MatchValue(value=product)))
        if is_kev is not None:
            must.append(qm.FieldCondition(key="is_kev", match=qm.MatchValue(value=is_kev)))
        flt = qm.Filter(must=must) if must else None
        res = self.client.query_points(
            self.collection, query=vector, query_filter=flt, limit=top_k,
            with_payload=True).points
        return [Hit(p.payload["cve_id"], p.score, p.payload) for p in res]
