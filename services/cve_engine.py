import os
from dataclasses import dataclass
from typing import Dict, List, Optional, Tuple

from models.cve_model import CVEEntry
from services.cve_sources import CVEProvider, LocalJsonProvider


# -----------------------------
# Version parsing & comparison (v0.3)
# -----------------------------
def _tokenize_version(v: str) -> Tuple[int, ...]:
    """
    Convert versions like:
      - "17.5.1" -> (17, 5, 1)
      - "17.6.3a" -> (17, 6, 3)  (suffix ignored for now)
      - "16.12" -> (16, 12, 0)
    Notes:
      - We intentionally keep this simple and deterministic for Cisco IOS/XE versions.
      - If you later need suffix-aware ordering, extend here.
    """
    v = (v or "").strip()
    if not v:
        return (0,)

    # Strip common suffixes (e.g. "17.6.3a", "17.6.3b", "17.6.3(1)")
    cleaned = []
    for ch in v:
        if ch.isdigit() or ch == ".":
            cleaned.append(ch)
        else:
            # stop at first non-digit/non-dot
            break

    s = "".join(cleaned).strip(".")
    if not s:
        return (0,)

    parts = s.split(".")
    nums: List[int] = []
    for p in parts:
        if p == "":
            nums.append(0)
        else:
            try:
                nums.append(int(p))
            except ValueError:
                nums.append(0)

    # Normalize length to 3 components for stable comparisons
    while len(nums) < 3:
        nums.append(0)

    return tuple(nums)


def compare_versions(a: str, b: str) -> int:
    """
    Return:
      -1 if a < b
       0 if a == b
       1 if a > b
    """
    ta = _tokenize_version(a)
    tb = _tokenize_version(b)

    # Extend to equal length
    max_len = max(len(ta), len(tb))
    ta = ta + (0,) * (max_len - len(ta))
    tb = tb + (0,) * (max_len - len(tb))

    if ta < tb:
        return -1
    if ta > tb:
        return 1
    return 0


# -----------------------------
# Platform normalization (v0.3)
# -----------------------------
def normalize_platform(p: str) -> str:
    """
    Normalize platform strings to improve matching stability.
    Examples:
      "ISR4451-X" -> "isr4451-x"
      "Catalyst 8200" -> "catalyst 8200"
      "IOS XE" -> "ios xe"
    """
    return (p or "").strip().lower()


def platform_matches(query_platform: str, cve_platforms: List[str]) -> bool:
    """
    v0.2 platform matching was too strict:
      - It required exact match in cve.platforms OR special 'ios xe' handling.
    v0.3 improves this:
      - Exact match OR substring match (both directions), after normalization.
      - 'ios xe' in either side is treated as a broad match.
    """
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
    engine_version: str = "0.3"
    data_dir: str = "cve_data/ios_xe"


class CVEEngine:
    """
    CVE Engine v0.3

    Goals:
    - Keep Local JSON dataset as the default (fast + deterministic).
    - Introduce provider architecture (SaaS-ready) so we can later plug:
        * Cisco Security Advisories
        * NVD
        * Tenable
      without rewriting the engine.

    For now: only LocalJsonProvider is enabled by default.
    """

    def __init__(
        self,
        config: Optional[CVEEngineConfig] = None,
        providers: Optional[List[CVEProvider]] = None,
    ):
        self.config = config or CVEEngineConfig()
        self.providers = providers or [LocalJsonProvider(self.config.data_dir)]
        self.cves: List[CVEEntry] = []

    # -------------------------
    # Loading
    # -------------------------
    def load_all(self) -> None:
        """
        Load CVEs from all configured providers.
        Providers can implement their own caching, etc.
        """
        loaded: List[CVEEntry] = []

        for provider in self.providers:
            try:
                loaded.extend(provider.load())
            except Exception as e:
                # Don't crash the API if one provider fails
                print(f"[WARN] CVE provider failed: {provider.name} ({e})")

        # Basic dedup by CVE ID (keep last occurrence)
        by_id: Dict[str, CVEEntry] = {}
        for entry in loaded:
            by_id[entry.cve_id] = entry

        self.cves = list(by_id.values())

    # -------------------------
    # Matching
    # -------------------------
    def match(self, platform: str, version: str) -> List[CVEEntry]:
        """
        Return CVEs that match:
          - platform (normalized match)
          - affected version range (min/max inclusive)
        """
        matched: List[CVEEntry] = []
        for cve in self.cves:
            if not platform_matches(platform, cve.platforms):
                continue

            # Version range inclusive
            if compare_versions(version, cve.affected.min) < 0:
                continue
            if compare_versions(version, cve.affected.max) > 0:
                continue

            matched.append(cve)

        # Sort by severity then CVE ID for stable UI ordering
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
        """
        Return minimal 'fixed_in' version among critical/high issues.
        """
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
