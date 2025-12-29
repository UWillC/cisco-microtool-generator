import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from models.cve_model import CVEEntry
from services.cve_sources import (
    CVEProvider,
    LocalJsonProvider,
    CiscoAdvisoryProvider,
    NvdProvider,
    TenableProvider,
)


# -----------------------------
# Version parsing & comparison (v0.3+)
# -----------------------------
def _tokenize_version(v: str) -> Tuple[int, ...]:
    """
    Convert versions like:
      - "17.5.1" -> (17, 5, 1)
      - "17.6.3a" -> (17, 6, 3)  (suffix ignored for now)
      - "16.12" -> (16, 12, 0)
    """
    v = (v or "").strip()
    if not v:
        return (0,)

    cleaned = []
    for ch in v:
        if ch.isdigit() or ch == ".":
            cleaned.append(ch)
        else:
            break

    s = "".join(cleaned).strip(".")
    if not s:
        return (0,)

    parts = s.split(".")
    nums: List[int] = []
    for p in parts:
        try:
            nums.append(int(p))
        except ValueError:
            nums.append(0)

    while len(nums) < 3:
        nums.append(0)

    return tuple(nums)


def compare_versions(a: str, b: str) -> int:
    ta = _tokenize_version(a)
    tb = _tokenize_version(b)

    max_len = max(len(ta), len(tb))
    ta = ta + (0,) * (max_len - len(ta))
    tb = tb + (0,) * (max_len - len(tb))

    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


# -----------------------------
# Platform normalization (v0.3+)
# -----------------------------
def normalize_platform(p: str) -> str:
    return (p or "").strip().lower()


def platform_matches(query_platform: str, cve_platforms: List[str]) -> bool:
    qp = normalize_platform(query_platform)
    if not qp:
        return False

    norm_list = [normalize_platform(x) for x in (cve_platforms or [])]

    if "ios xe" in qp:
        return True
    if "ios xe" in norm_list:
        return True

    for cp in norm_list:
        if not cp:
            continue
        if qp == cp:
            return True
        if qp in cp:
            return True
        if cp in qp:
            return True

    return False


# -----------------------------
# Engine configuration
# -----------------------------
@dataclass(frozen=True)
class CVEEngineConfig:
    engine_version: str = "0.3.2"
    data_dir: str = "cve_data/ios_xe"
    enable_external_providers: bool = False  # default OFF (safe)


class CVEEngine:
    """
    CVE Engine v0.3.2

    v0.3.2 focus:
    - keep Local JSON as deterministic default
    - add provider stubs + importer skeletons for:
        * Cisco Security Advisories
        * NVD
        * Tenable
      (currently disabled by default, and return [] safely)

    Enable external providers by:
      - setting CVE_EXTERNAL_PROVIDERS=1
      OR
      - passing config.enable_external_providers=True
    """

    def __init__(
        self,
        config: Optional[CVEEngineConfig] = None,
        providers: Optional[List[CVEProvider]] = None,
    ):
        self.config = config or CVEEngineConfig()

        env_flag = os.getenv("CVE_EXTERNAL_PROVIDERS", "").strip().lower()
        enable_external = self.config.enable_external_providers or env_flag in (
            "1",
            "true",
            "yes",
            "on",
        )

        if providers is not None:
            self.providers = providers
        else:
            base = [LocalJsonProvider(self.config.data_dir)]
            if enable_external:
                # Stubs: safe no-op providers for now (return empty list)
                base.extend(
                    [
                        CiscoAdvisoryProvider(),
                        NvdProvider(),
                        TenableProvider(),
                    ]
                )
            self.providers = base

        self.cves: List[CVEEntry] = []

    # -------------------------
    # Loading
    # -------------------------
    def load_all(self) -> None:
        loaded: List[CVEEntry] = []

        for provider in self.providers:
            try:
                loaded.extend(provider.load())
            except Exception as e:
                # Never crash API because one provider failed
                print(f"[WARN] CVE provider failed: {provider.name} ({e})")

        # Dedup by CVE ID (keep last occurrence)
        by_id: Dict[str, CVEEntry] = {}
        for entry in loaded:
            by_id[entry.cve_id] = entry

        self.cves = list(by_id.values())

    # -------------------------
    # Matching
    # -------------------------
    def match(self, platform: str, version: str) -> List[CVEEntry]:
        matched: List[CVEEntry] = []
        for cve in self.cves:
            if not platform_matches(platform, cve.platforms):
                continue

            if compare_versions(version, cve.affected.min) < 0:
                continue
            if compare_versions(version, cve.affected.max) > 0:
                continue

            matched.append(cve)

        severity_rank = {"critical": 0, "high": 1, "medium": 2, "low": 3}
        matched.sort(
            key=lambda x: (
                severity_rank.get((x.severity or "").lower(), 99),
                x.cve_id,
            )
        )
        return matched

    # -------------------------
    # Summary
    # -------------------------
    def summary(self, matched: List[CVEEntry]) -> Dict[str, int]:
        levels = {"critical": 0, "high": 0, "medium": 0, "low": 0}
        for cve in matched:
            sev = (cve.severity or "").lower()
            if sev in levels:
                levels[sev] += 1
        return levels

    # -------------------------
    # Recommended upgrade
    # -------------------------
    def recommended_upgrade(self, matched: List[CVEEntry]) -> Optional[str]:
        candidates: List[str] = []
        for cve in matched:
            if (cve.severity or "").lower() in ("critical", "high") and cve.fixed_in:
                candidates.append(cve.fixed_in)

        if not candidates:
            return None

        best = candidates[0]
        for v in candidates[1:]:
            if compare_versions(v, best) < 0:
                best = v
        return best
