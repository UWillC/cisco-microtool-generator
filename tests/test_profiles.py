import pytest

from services.profile_service import ProfileService
from models.profile_model import (
    ProfileVulnerabilitiesResponse,
    ProfileVulnerabilityResult,
    ProfileVulnerabilitySummary,
)


def test_profile_service_list():
    svc = ProfileService()
    profiles = svc.list_profiles()
    assert isinstance(profiles, list)


# ------------------------------------------
# v0.3.5: Profiles × CVE tests
# ------------------------------------------

class TestCheckAllVulnerabilities:
    """Tests for check_all_vulnerabilities() method."""

    def setup_method(self):
        self.svc = ProfileService()

    def test_returns_response_model(self):
        """Test that method returns ProfileVulnerabilitiesResponse."""
        result = self.svc.check_all_vulnerabilities()
        assert isinstance(result, ProfileVulnerabilitiesResponse)

    def test_response_has_timestamp(self):
        """Test that response includes ISO timestamp."""
        result = self.svc.check_all_vulnerabilities()
        assert result.timestamp is not None
        assert "T" in result.timestamp  # ISO format

    def test_response_has_summary(self):
        """Test that response includes summary with all status counts."""
        result = self.svc.check_all_vulnerabilities()
        assert isinstance(result.summary, ProfileVulnerabilitySummary)
        # All fields should be integers
        assert isinstance(result.summary.critical, int)
        assert isinstance(result.summary.high, int)
        assert isinstance(result.summary.medium, int)
        assert isinstance(result.summary.low, int)
        assert isinstance(result.summary.clean, int)
        assert isinstance(result.summary.unknown, int)

    def test_profiles_checked_matches_results(self):
        """Test that profiles_checked equals len(results)."""
        result = self.svc.check_all_vulnerabilities()
        assert result.profiles_checked == len(result.results)

    def test_result_has_required_fields(self):
        """Test that each result has all required fields."""
        result = self.svc.check_all_vulnerabilities()
        for r in result.results:
            assert isinstance(r, ProfileVulnerabilityResult)
            assert r.profile_name is not None
            assert r.status in ("critical", "high", "medium", "low", "clean", "unknown")
            assert isinstance(r.cve_count, int)
            assert isinstance(r.cves, list)

    def test_summary_counts_match_results(self):
        """Test that summary counts match actual result statuses."""
        result = self.svc.check_all_vulnerabilities()

        counted = {"critical": 0, "high": 0, "medium": 0, "low": 0, "clean": 0, "unknown": 0}
        for r in result.results:
            counted[r.status] += 1

        assert result.summary.critical == counted["critical"]
        assert result.summary.high == counted["high"]
        assert result.summary.medium == counted["medium"]
        assert result.summary.low == counted["low"]
        assert result.summary.clean == counted["clean"]
        assert result.summary.unknown == counted["unknown"]


class TestDetermineStatus:
    """Tests for _determine_status() helper method."""

    def setup_method(self):
        self.svc = ProfileService()

    def test_none_cvss_returns_clean(self):
        """Test that None CVSS returns 'clean' status."""
        assert self.svc._determine_status(None) == "clean"

    def test_critical_threshold(self):
        """Test CVSS >= 9.0 returns 'critical'."""
        assert self.svc._determine_status(9.0) == "critical"
        assert self.svc._determine_status(10.0) == "critical"
        assert self.svc._determine_status(9.5) == "critical"

    def test_high_threshold(self):
        """Test 7.0 <= CVSS < 9.0 returns 'high'."""
        assert self.svc._determine_status(7.0) == "high"
        assert self.svc._determine_status(8.9) == "high"
        assert self.svc._determine_status(7.5) == "high"

    def test_medium_threshold(self):
        """Test 4.0 <= CVSS < 7.0 returns 'medium'."""
        assert self.svc._determine_status(4.0) == "medium"
        assert self.svc._determine_status(6.9) == "medium"
        assert self.svc._determine_status(5.0) == "medium"

    def test_low_threshold(self):
        """Test 0 < CVSS < 4.0 returns 'low'."""
        assert self.svc._determine_status(0.1) == "low"
        assert self.svc._determine_status(3.9) == "low"
        assert self.svc._determine_status(2.0) == "low"

    def test_zero_cvss_returns_clean(self):
        """Test CVSS = 0 returns 'clean'."""
        assert self.svc._determine_status(0.0) == "clean"
