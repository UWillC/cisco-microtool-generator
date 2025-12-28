import json
import os
from abc import ABC, abstractmethod
from typing import List

from models.cve_model import CVEEntry


class CVEProvider(ABC):
    """
    Provider interface (SaaS-ready).
    Future providers:
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

    v0.3.1:
      - Ensures `source` is set (defaults to provider name).
      - Tolerates unknown fields in JSON as long as CVEEntry schema supports them.
    """

    name = "local-json"

    def __init__(self, data_dir: str):
        self.data_dir = data_dir

    def _ensure_source(self, entry: CVEEntry) -> CVEEntry:
        if getattr(entry, "source", None):
            return entry

        # Pydantic v2 uses model_copy; v1 uses copy
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
                entry = self._ensure_source(entry)
                results.append(entry)
            except Exception as e:
                print(f"[WARN] Skipping invalid CVE file: {filename} ({e})")

        return results


# -----------------------------
# Future providers (stubs)
# -----------------------------
class CiscoAdvisoryProvider(CVEProvider):
    name = "cisco-advisories"

    def load(self) -> List[CVEEntry]:
        raise NotImplementedError("Cisco advisory provider is not implemented yet.")


class NvdProvider(CVEProvider):
    name = "nvd"

    def load(self) -> List[CVEEntry]:
        raise NotImplementedError("NVD provider is not implemented yet.")


class TenableProvider(CVEProvider):
    name = "tenable"

    def load(self) -> List[CVEEntry]:
        raise NotImplementedError("Tenable provider is not implemented yet.")
