import json
import os
from abc import ABC, abstractmethod
from typing import List, Optional

from models.cve_model import CVEEntry
from services.cve_importers import (
    CiscoAdvisoryImporter,
    NvdImporter,
    TenableImporter,
)


class CVEProvider(ABC):
    """
    Provider interface (SaaS-ready).

    A provider is responsible for loading data from one source and returning a list of CVEEntry objects.
    """

    name: str = "base"

    @abstractmethod
    def load(self) -> List[CVEEntry]:
        raise NotImplementedError


class LocalJsonProvider(CVEProvider):
    """
    Default provider: loads curated CVE JSON files from a directory.

    v0.3.1+:
      - Ensures `source` is set (defaults to provider name).
    """

    name = "local-json"

    def __init__(self, data_dir: str):
        self.data_dir = data_dir

    def _ensure_source(self, entry: CVEEntry) -> CVEEntry:
        if getattr(entry, "source", None):
            return entry

        if hasattr(entry, "model_copy"):  # pydantic v2
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
# External providers (v0.3.2 stubs)
# -----------------------------
class ExternalProviderBase(CVEProvider):
    """
    v0.3.2: external providers are intentionally implemented as safe stubs:
      - They never raise during normal operation
      - They return [] until actual fetching/parsing is implemented
    """

    def __init__(self, enabled: bool = True):
        self.enabled = enabled

    def load(self) -> List[CVEEntry]:
        if not self.enabled:
            return []

        # Stubs return empty list for now (safe).
        print(f"[INFO] External provider enabled but not implemented: {self.name}")
        return []


class CiscoAdvisoryProvider(ExternalProviderBase):
    """
    Future:
      - Fetch Cisco Security Advisories
      - Parse advisory listing and map to CVEEntry (IOS XE focus)
    """
    name = "cisco-advisories"

    def __init__(self, enabled: bool = True, importer: Optional[CiscoAdvisoryImporter] = None):
        super().__init__(enabled=enabled)
        self.importer = importer or CiscoAdvisoryImporter()


class NvdProvider(ExternalProviderBase):
    """
    Future:
      - Query NVD API
      - Normalize NVD records into CVEEntry
    """
    name = "nvd"

    def __init__(self, enabled: bool = True, importer: Optional[NvdImporter] = None):
        super().__init__(enabled=enabled)
        self.importer = importer or NvdImporter()


class TenableProvider(ExternalProviderBase):
    """
    Future:
      - Use Tenable CVE search/feed for enrichment (CVSS, references, CPE hints)
    """
    name = "tenable"

    def __init__(self, enabled: bool = True, importer: Optional[TenableImporter] = None):
        super().__init__(enabled=enabled)
        self.importer = importer or TenableImporter()
