from dataclasses import dataclass
from typing import List, Optional

from models.cve_model import CVEEntry, CVEAffectedRange


# -----------------------------
# Shared normalized record (internal)
# -----------------------------
@dataclass
class NormalizedCVE:
    """
    Internal normalized CVE representation.
    Importers convert external source documents into this format.
    Then we convert NormalizedCVE -> CVEEntry (our API schema).
    """
    cve_id: str
    title: str
    severity: str
    description: str

    platforms: List[str]
    affected_min: str
    affected_max: str
    fixed_in: Optional[str] = None

    advisory_url: Optional[str] = None
    workaround: Optional[str] = None

    cvss_score: Optional[float] = None
    cvss_vector: Optional[str] = None
    cwe: Optional[str] = None
    references: Optional[List[str]] = None

    published: Optional[str] = None
    last_modified: Optional[str] = None

    source: Optional[str] = None
    confidence: str = "partial"  # partial | validated | demo


def normalized_to_entry(n: NormalizedCVE) -> CVEEntry:
    """
    Convert NormalizedCVE into our stable public schema (CVEEntry).
    """
    return CVEEntry(
        cve_id=n.cve_id,
        title=n.title,
        severity=n.severity,
        platforms=n.platforms or [],
        affected=CVEAffectedRange(min=n.affected_min, max=n.affected_max),
        fixed_in=n.fixed_in,
        tags=[],  # tags can be derived later
        description=n.description,
        workaround=n.workaround,
        advisory_url=n.advisory_url,
        confidence=n.confidence,
        source=n.source,
        cvss_score=n.cvss_score,
        cvss_vector=n.cvss_vector,
        cwe=n.cwe,
        published=n.published,
        last_modified=n.last_modified,
        references=n.references or [],
    )


# -----------------------------
# Importer base
# -----------------------------
class ImporterBase:
    """
    Importers are pure transformation layers.
    Fetching/parsing is intentionally not implemented in v0.3.2.
    """
    source_name: str = "unknown"

    def parse(self, raw: object) -> List[NormalizedCVE]:
        raise NotImplementedError


# -----------------------------
# Cisco Security Advisories (stub)
# -----------------------------
class CiscoAdvisoryImporter(ImporterBase):
    source_name = "cisco-advisories"

    def parse(self, raw: object) -> List[NormalizedCVE]:
        """
        Future plan:
        - raw can be HTML (publicationListing) or JSON from Cisco APIs (if available)
        - extract CVE ID(s), affected releases, fixed releases, advisory URL, etc.

        v0.3.2: stub only.
        """
        return []


# -----------------------------
# NVD (stub)
# -----------------------------
class NvdImporter(ImporterBase):
    source_name = "nvd"

    def parse(self, raw: object) -> List[NormalizedCVE]:
        """
        Future plan:
        - raw will be NVD JSON objects
        - map CVSS v3.1, CWE, references, published/modified dates
        - map affected versions using CPE/CVE config (may require heuristics)

        v0.3.2: stub only.
        """
        return []


# -----------------------------
# Tenable (stub)
# -----------------------------
class TenableImporter(ImporterBase):
    source_name = "tenable"

    def parse(self, raw: object) -> List[NormalizedCVE]:
        """
        Future plan:
        - Tenable records can be used as enrichment:
          * CVSS score/vector
          * reference links
          * potentially product/platform hints

        v0.3.2: stub only.
        """
        return []
