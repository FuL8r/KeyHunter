from datetime import date
from pydantic import BaseModel, Field


class AffectedProduct(BaseModel):
    vendor: str | None = None
    product: str
    version_start: str | None = None
    version_end: str | None = None
    version_start_incl: bool = False
    version_end_incl: bool = False
    fixed_version: str | None = None


class Vulnerability(BaseModel):
    cve_id: str
    title: str | None = None
    description: str
    cvss_score: float | None = None
    severity: str | None = None
    affected: list[AffectedProduct] = Field(default_factory=list)
    references: list[str] = Field(default_factory=list)
    fixed_versions: list[str] = Field(default_factory=list)
    is_kev: bool = False
    epss: float | None = None
    sources: list[str] = Field(default_factory=list)
    published: date
    last_modified: date
