from pydantic import BaseModel
from typing import List, Literal, Optional


class SNMPProfile(BaseModel):
    host: Optional[str] = None
    user: Optional[str] = None
    group: Optional[str] = None
    auth_password: Optional[str] = None
    priv_password: Optional[str] = None


class NTPProfile(BaseModel):
    primary_server: Optional[str] = None
    secondary_server: Optional[str] = None
    timezone: Optional[str] = None


class AAAProfile(BaseModel):
    enable_secret: Optional[str] = None
    tacacs1_name: Optional[str] = None
    tacacs1_ip: Optional[str] = None
    tacacs1_key: Optional[str] = None
    tacacs2_name: Optional[str] = None
    tacacs2_ip: Optional[str] = None
    tacacs2_key: Optional[str] = None


class DeviceProfile(BaseModel):
    """Full multi-generator device profile V2"""
    name: str
    description: Optional[str] = None
    # v0.3.5: Device info for CVE matching
    platform: Optional[str] = None  # e.g., "ISR4451-X", "Catalyst 9300"
    version: Optional[str] = None   # e.g., "17.5.1", "17.9.4"
    snmp: SNMPProfile = SNMPProfile()
    ntp: NTPProfile = NTPProfile()
    aaa: AAAProfile = AAAProfile()


# -----------------------------
# v0.3.5: Profiles × CVE schemas
# -----------------------------

VulnerabilityStatus = Literal["critical", "high", "medium", "low", "clean", "unknown"]


class ProfileVulnerabilityResult(BaseModel):
    """CVE check result for a single profile."""
    profile_name: str
    platform: Optional[str] = None
    version: Optional[str] = None
    status: VulnerabilityStatus = "unknown"
    cve_count: int = 0
    max_cvss: Optional[float] = None
    cves: List[str] = []


class ProfileVulnerabilitySummary(BaseModel):
    """Summary of CVE check across all profiles."""
    critical: int = 0
    high: int = 0
    medium: int = 0
    low: int = 0
    clean: int = 0
    unknown: int = 0  # profiles without platform/version


class ProfileVulnerabilitiesResponse(BaseModel):
    """Response for GET /profiles/vulnerabilities."""
    timestamp: str
    profiles_checked: int
    summary: ProfileVulnerabilitySummary
    results: List[ProfileVulnerabilityResult]
