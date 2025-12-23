import json
import os
from abc import ABC, abstractmethod
from typing import List

from models.cve_model import CVEEntry


class CVEProvider(ABC):
    """
    Provider interface (SaaS-ready).
    Later you can implement:
      - Cisco Security Advisories provider
      - NVD provider
      - Tenable provider
    """

    name: str = "base"

    @abstractmethod
    def load(self) -> List[CVEEntry]:
        raise NotImplementedError


class LocalJsonProvider(CVEProvider):
    """
    Default provider: loads curated CVE JSON files from a directory.

    Expected file shape matches CVEEntry (Pydantic) schema.
    """

    name = "local-json"

    def __init__(self, data_dir: str):
        self.data_dir = data_dir

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
                results.append(CVEEntry(**data))
            except Exception as e:
                print(f"[WARN] Skipping invalid CVE file: {filename} ({e})")

        return results


# -----------------------------
# Future providers (stubs)
# -----------------------------
class CiscoAdvisoryProvider(CVEProvider):
    """
    Future:
      - Pull Cisco Security Advisories
      - Map advisories to CVE entries and version ranges
    """
    name = "cisco-advisories"

    def load(self) -> List[CVEEntry]:
        raise NotImplementedError("Cisco advisory provider is not implemented yet.")


class NvdProvider(CVEProvider):
    """
    Future:
      - Query NVD and normalize records into CVEEntry format.
    """
    name = "nvd"

    def load(self) -> List[CVEEntry]:
        raise NotImplementedError("NVD provider is not implemented yet.")


class TenableProvider(CVEProvider):
    """
    Future:
      - Use Tenable CVE search / feed to enrich metadata (CVSS, references).
    """
    name = "tenable"

    def load(self) -> List[CVEEntry]:
        raise NotImplementedError("Tenable provider is not implemented yet.")
