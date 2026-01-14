"""
Security Score models — v0.4.0

Numeric security assessment (0-100) for device profiles based on CVE analysis.
Higher score = more secure device.

See: docs/DESIGN_SECURITY_SCORE.md
"""

from pydantic import BaseModel
from typing import List, Literal, Optional


# Score categories
ScoreLabel = Literal["Excellent", "Good", "Fair", "Poor", "Critical"]


class CVEScoreBreakdown(BaseModel):
    """Per-CVE penalty breakdown."""

    cve_id: str
    cvss_score: Optional[float] = None
    severity: str  # critical/high/medium/low

    base_penalty: float
    modifiers_applied: List[str] = []  # ["exploited-in-wild", "patch-available", "aged"]
    modifier_value: float = 1.0  # e.g. 1.26 (1.5 * 0.7 * 1.2)
    final_penalty: float


class ProfileSecurityScore(BaseModel):
    """Security score result for a single profile."""

    profile_name: str
    platform: Optional[str] = None
    version: Optional[str] = None

    # Score (null if unknown profile)
    score: Optional[int] = None  # 0-100
    label: Optional[ScoreLabel] = None

    # CVE details
    cve_count: int = 0
    cve_breakdown: List[CVEScoreBreakdown] = []

    # Penalty totals
    total_base_penalty: float = 0.0
    total_final_penalty: float = 0.0


class SecurityScoreSummary(BaseModel):
    """Aggregated stats across all profiles."""

    excellent: int = 0  # 90-100
    good: int = 0  # 70-89
    fair: int = 0  # 50-69
    poor: int = 0  # 25-49
    critical: int = 0  # 0-24
    unknown: int = 0  # null score


class SecurityScoreResponse(BaseModel):
    """Response for GET /profiles/security-scores."""

    timestamp: str
    profiles_checked: int

    # Aggregated stats
    average_score: Optional[float] = None
    lowest_score: Optional[int] = None
    highest_score: Optional[int] = None

    summary: SecurityScoreSummary
    results: List[ProfileSecurityScore]


# ---------------------------------
# Constants for score calculation
# ---------------------------------

SEVERITY_PENALTIES = {
    "critical": 25,
    "high": 15,
    "medium": 8,
    "low": 3,
}

MODIFIER_EXPLOITED = 1.5
MODIFIER_PATCHED = 0.7
MODIFIER_AGED = 1.2
AGE_THRESHOLD_DAYS = 365

SCORE_THRESHOLDS = {
    "Excellent": 90,
    "Good": 70,
    "Fair": 50,
    "Poor": 25,
    "Critical": 0,
}


def get_score_label(score: Optional[int]) -> Optional[ScoreLabel]:
    """Convert numeric score to label."""
    if score is None:
        return None
    if score >= 90:
        return "Excellent"
    if score >= 70:
        return "Good"
    if score >= 50:
        return "Fair"
    if score >= 25:
        return "Poor"
    return "Critical"
