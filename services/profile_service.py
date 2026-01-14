import os
import json
from datetime import datetime, timezone
from typing import Dict, Any, List, Optional

from models.profile_model import (
    DeviceProfile,
    ProfileVulnerabilityResult,
    ProfileVulnerabilitySummary,
    ProfileVulnerabilitiesResponse,
    VulnerabilityStatus,
)
from models.security_score import (
    CVEScoreBreakdown,
    ProfileSecurityScore,
    SecurityScoreSummary,
    SecurityScoreResponse,
    SEVERITY_PENALTIES,
    MODIFIER_EXPLOITED,
    MODIFIER_PATCHED,
    MODIFIER_AGED,
    AGE_THRESHOLD_DAYS,
    get_score_label,
)
from models.cve_model import CVEEntry
from services.cve_engine import CVEEngine


class ProfileService:
    """
    Handles reading, listing and saving device profiles.
    Profiles are stored as JSON files inside profiles/ directory.
    """

    def __init__(self, profiles_dir: str = "profiles"):
        self.dir = profiles_dir
        os.makedirs(self.dir, exist_ok=True)

    def _path(self, name: str) -> str:
        """Generate full path for profile name."""
        if not name.endswith(".json"):
            name = name + ".json"
        return os.path.join(self.dir, name)

    def list_profiles(self) -> List[str]:
        """Return list of profiles (file names without .json)."""
        files = []
        for f in os.listdir(self.dir):
            if f.endswith(".json"):
                files.append(f.replace(".json", ""))
        return sorted(files)

    def load_profile(self, name: str) -> Dict[str, Any]:
        """Load profile JSON and return dict."""
        path = self._path(name)
        if not os.path.isfile(path):
            raise FileNotFoundError(f"Profile '{name}' not found.")

        with open(path, "r") as f:
            return json.load(f)

    def save_profile(self, profile: DeviceProfile) -> None:
        """Save DeviceProfile into JSON."""
        path = self._path(profile.name)

        with open(path, "w") as f:
            json.dump(profile.model_dump(), f, indent=2)

    def delete_profile(self, name: str) -> None:
        """Delete profile file."""
        path = self._path(name)
        if os.path.isfile(path):
            os.remove(path)

    # ------------------------------------------
    # v0.3.5: Profiles × CVE integration
    # ------------------------------------------
    def _determine_status(self, max_cvss: Optional[float]) -> VulnerabilityStatus:
        """Determine vulnerability status based on max CVSS score."""
        if max_cvss is None:
            return "clean"
        if max_cvss >= 9.0:
            return "critical"
        if max_cvss >= 7.0:
            return "high"
        if max_cvss >= 4.0:
            return "medium"
        if max_cvss > 0:
            return "low"
        return "clean"

    def check_all_vulnerabilities(self) -> ProfileVulnerabilitiesResponse:
        """
        Check all profiles against CVE database.

        v0.3.5: Profiles × CVE integration
        - Loads all profiles from profiles/ directory
        - For each profile with platform/version, runs CVE matching
        - Returns aggregated vulnerability response
        """
        # Load CVE database
        engine = CVEEngine()
        engine.load_all()

        profile_names = self.list_profiles()
        results: List[ProfileVulnerabilityResult] = []
        summary = ProfileVulnerabilitySummary()

        for name in profile_names:
            try:
                data = self.load_profile(name)
            except FileNotFoundError:
                continue

            platform = data.get("platform")
            version = data.get("version")

            # Profile without platform/version → unknown status
            if not platform or not version:
                result = ProfileVulnerabilityResult(
                    profile_name=name,
                    platform=platform,
                    version=version,
                    status="unknown",
                    cve_count=0,
                    max_cvss=None,
                    cves=[],
                )
                results.append(result)
                summary.unknown += 1
                continue

            # Run CVE matching
            matched = engine.match(platform, version)
            cve_ids = [cve.cve_id for cve in matched]

            # Calculate max CVSS
            max_cvss: Optional[float] = None
            for cve in matched:
                if cve.cvss_score is not None:
                    if max_cvss is None or cve.cvss_score > max_cvss:
                        max_cvss = cve.cvss_score

            status = self._determine_status(max_cvss)

            result = ProfileVulnerabilityResult(
                profile_name=name,
                platform=platform,
                version=version,
                status=status,
                cve_count=len(matched),
                max_cvss=max_cvss,
                cves=cve_ids,
            )
            results.append(result)

            # Update summary counters
            if status == "critical":
                summary.critical += 1
            elif status == "high":
                summary.high += 1
            elif status == "medium":
                summary.medium += 1
            elif status == "low":
                summary.low += 1
            elif status == "clean":
                summary.clean += 1

        timestamp = datetime.now(timezone.utc).isoformat()

        return ProfileVulnerabilitiesResponse(
            timestamp=timestamp,
            profiles_checked=len(results),
            summary=summary,
            results=results,
        )

    # ------------------------------------------
    # v0.4.0: Security Score
    # ------------------------------------------
    def _cve_age_days(self, cve: CVEEntry) -> Optional[int]:
        """Calculate CVE age in days from published date."""
        if not cve.published:
            return None
        try:
            # Handle ISO format: 2023-10-16T00:00:00
            published_str = cve.published.split("T")[0]
            published_date = datetime.strptime(published_str, "%Y-%m-%d")
            now = datetime.now()
            delta = now - published_date
            return delta.days
        except (ValueError, AttributeError):
            return None

    def _calculate_cve_breakdown(self, cve: CVEEntry) -> CVEScoreBreakdown:
        """Calculate penalty breakdown for a single CVE."""
        severity = cve.severity.lower() if cve.severity else "medium"
        base_penalty = SEVERITY_PENALTIES.get(severity, 8)

        modifiers_applied = []
        modifier_value = 1.0

        # Modifier: exploited-in-wild
        if cve.tags and "exploited-in-wild" in cve.tags:
            modifier_value *= MODIFIER_EXPLOITED
            modifiers_applied.append("exploited-in-wild")

        # Modifier: patch available
        if cve.fixed_in:
            modifier_value *= MODIFIER_PATCHED
            modifiers_applied.append("patch-available")

        # Modifier: aged (>365 days)
        age_days = self._cve_age_days(cve)
        if age_days is not None and age_days > AGE_THRESHOLD_DAYS:
            modifier_value *= MODIFIER_AGED
            modifiers_applied.append("aged")

        final_penalty = base_penalty * modifier_value

        return CVEScoreBreakdown(
            cve_id=cve.cve_id,
            cvss_score=cve.cvss_score,
            severity=severity,
            base_penalty=base_penalty,
            modifiers_applied=modifiers_applied,
            modifier_value=round(modifier_value, 2),
            final_penalty=round(final_penalty, 2),
        )

    def calculate_all_security_scores(self) -> SecurityScoreResponse:
        """
        Calculate security scores for all profiles.

        v0.4.0: Security Score feature
        - Base score: 100
        - Penalties per CVE based on severity
        - Modifiers: exploited-in-wild (×1.5), patch-available (×0.7), aged (×1.2)
        - Returns per-profile scores with CVE breakdown
        """
        engine = CVEEngine()
        engine.load_all()

        profile_names = self.list_profiles()
        results: List[ProfileSecurityScore] = []
        summary = SecurityScoreSummary()

        scores_for_avg: List[int] = []

        for name in profile_names:
            try:
                data = self.load_profile(name)
            except FileNotFoundError:
                continue

            platform = data.get("platform")
            version = data.get("version")

            # Profile without platform/version → unknown (null score)
            if not platform or not version:
                result = ProfileSecurityScore(
                    profile_name=name,
                    platform=platform,
                    version=version,
                    score=None,
                    label=None,
                    cve_count=0,
                    cve_breakdown=[],
                    total_base_penalty=0,
                    total_final_penalty=0,
                )
                results.append(result)
                summary.unknown += 1
                continue

            # Run CVE matching
            matched = engine.match(platform, version)

            # Calculate breakdowns
            breakdowns = [self._calculate_cve_breakdown(cve) for cve in matched]

            total_base = sum(b.base_penalty for b in breakdowns)
            total_final = sum(b.final_penalty for b in breakdowns)

            # Calculate score (floor at 0)
            score = max(0, round(100 - total_final))
            label = get_score_label(score)

            result = ProfileSecurityScore(
                profile_name=name,
                platform=platform,
                version=version,
                score=score,
                label=label,
                cve_count=len(matched),
                cve_breakdown=breakdowns,
                total_base_penalty=round(total_base, 2),
                total_final_penalty=round(total_final, 2),
            )
            results.append(result)
            scores_for_avg.append(score)

            # Update summary counters
            if score >= 90:
                summary.excellent += 1
            elif score >= 70:
                summary.good += 1
            elif score >= 50:
                summary.fair += 1
            elif score >= 25:
                summary.poor += 1
            else:
                summary.critical += 1

        # Calculate aggregates
        average_score = None
        lowest_score = None
        highest_score = None

        if scores_for_avg:
            average_score = round(sum(scores_for_avg) / len(scores_for_avg), 1)
            lowest_score = min(scores_for_avg)
            highest_score = max(scores_for_avg)

        timestamp = datetime.now(timezone.utc).isoformat()

        return SecurityScoreResponse(
            timestamp=timestamp,
            profiles_checked=len(results),
            average_score=average_score,
            lowest_score=lowest_score,
            highest_score=highest_score,
            summary=summary,
            results=results,
        )
