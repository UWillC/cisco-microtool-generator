import json
import os
from abc import ABC, abstractmethod
from typing import List, Optional

from models.cve_model import CVEEntry, CVEAffectedRange
from services.cve_importers import NvdImporter
from services.http_client import http_get_json


class CVEProvider(ABC):
    name: str = "base"

    @abstractmethod
    def load(self) -> List[CVEEntry]:
        raise NotImplementedError


class LocalJsonProvider(CVEProvider):
    name = "local-json"

    def __init__(self, data_dir: str):
        self.data_dir = data_dir

    def _ensure_source(self, entry: CVEEntry) -> CVEEntry:
        if getattr(entry, "source", None):
            return entry
        if hasattr(entry, "model_copy"):
            return entry.model_copy(update={"source": self.name})
        return entry.copy(update={"source": self.name})  # type: ignore[attr-defined]

    def load(self) -> List[CVEEntry]:
        results: List[CVEEntry] = []
        if not os.path.isdir(self.data_dir):
            return results

        for filename in os.listdir(self.data_dir):
            if not filename.endswith(".json"):
                continue
            path = os.path.join(self.data_dir, filename)
            try:
                with open(path, "r", encoding="utf-8") as f:
                    data = json.load(f)
                entry = CVEEntry(**data)
                results.append(self._ensure_source(entry))
            except Exception as e:
                print(f"[WARN] Skipping invalid CVE file: {filename} ({e})")

        return results


# -----------------------------
# v0.3.3: NVD Enricher (REAL fetch)
# -----------------------------
class NvdEnricherProvider(CVEProvider):
    """
    Fetches CVE metadata from NVD by CVE ID.

    Notes:
    - This is enrichment only. We do NOT try to derive Cisco platform/version ranges from NVD.
    - You enable it via env: CVE_NVD_ENRICH=1
    - Rate limits may apply. Keep your local curated dataset small/curated.
    """

    name = "nvd"

    def __init__(self, cve_ids: Optional[List[str]] = None):
        # If None: provider will try to read CVE IDs from local dataset at runtime (not available here),
        # so default behaviour is: no IDs -> no-op.
        self.cve_ids = cve_ids or []
        self.importer = NvdImporter()

    def load(self) -> List[CVEEntry]:
        if not self.cve_ids:
            # Safe no-op if not provided any IDs
            print("[INFO] NVD enricher enabled but no CVE IDs provided; skipping.")
            return []

        out: List[CVEEntry] = []
        for cve_id in self.cve_ids:
            try:
                # NVD API v2
                url = f"https://services.nvd.nist.gov/rest/json/cves/2.0?cveId={cve_id}"
                data = http_get_json(url, timeout_seconds=10)
                normalized = self.importer.parse(data)

                # Expect 0 or 1 for cveId query, but handle list anyway
                for n in normalized:
                    # Create a "patch" CVEEntry with minimal required fields.
                    # affected/platforms are placeholders because we only merge metadata onto existing local entries.
                    out.append(
                        CVEEntry(
                            cve_id=n.cve_id,
                            title=n.title or cve_id,
                            severity=n.severity or "medium",
                            platforms=["IOS XE"],  # placeholder (won't be used if merging onto local)
                            affected=CVEAffectedRange(min="0.0.0", max="999.999.999"),
                            fixed_in=None,
                            tags=[],
                            description=n.description or "",
                            workaround=None,
                            advisory_url=None,
                            confidence="partial",
                            source="nvd",
                            cvss_score=n.cvss_score,
                            cvss_vector=n.cvss_vector,
                            cwe=n.cwe,
                            published=n.published,
                            last_modified=n.last_modified,
                            references=n.references or [],
                        )
                    )
            except Exception as e:
                print(f"[WARN] NVD enrich failed for {cve_id}: {e}")

        return out


# -----------------------------
# External providers (still stubs for now)
# -----------------------------
class CiscoAdvisoryProvider(CVEProvider):
    name = "cisco-advisories"

    def load(self) -> List[CVEEntry]:
        print("[INFO] Cisco provider stub (v0.3.3): not implemented yet.")
        return []


class TenableProvider(CVEProvider):
    name = "tenable"

    def load(self) -> List[CVEEntry]:
        print("[INFO] Tenable provider stub (v0.3.3): not implemented yet.")
        return []
