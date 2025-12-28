from pydantic import BaseModel, Field
from typing import List, Optional


class CVEAffectedRange(BaseModel):
    min: str
    max: str


class CVEEntry(BaseModel):
    cve_id: str
    title: str
    severity: str  # critical/high/medium/low

    platforms: List[str] = Field(default_factory=list)
    affected: CVEAffectedRange

    fixed_in: Optional[str] = None
    tags: List[str] = Field(default_factory=list)

    description: str
    workaround: Optional[str] = None
    advisory_url: Optional[str] = None

    confidence: str = "demo"  # demo | validated | partial

    # v0.3+ metadata (optional, SaaS-ready)
    source: Optional[str] = None  # local-json | cisco | nvd | tenable
    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe: Optional[str] = None
    published: Optional[str] = None
    last_modified: Optional[str] = None
    references: List[str] = Field(default_factory=list)
