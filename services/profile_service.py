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
