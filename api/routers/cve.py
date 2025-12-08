from fastapi import APIRouter
from pydantic import BaseModel
from typing import List, Optional
import datetime

router = APIRouter()


# -------------------------------------------------------------------
# Request / Response models
# -------------------------------------------------------------------
class CVEAnalyzeRequest(BaseModel):
    platform: str           # e.g. "ISR4451-X" or "IOS XE"
    version: str            # e.g. "17.9.3"
    include_suggestions: bool = True


class CVEItem(BaseModel):
    cve_id: str
    title: str
    severity: str
    description: str
    fixed_in: Optional[str] = None
    workaround: Optional[str] = None
    advisory_url: Optional[str] = None


class CVEAnalyzeResponse(BaseModel):
    platform: str
    version: str
    matched_cves: List[CVEItem]
    note: str
    timestamp: str
    recommended_action: Optional[str] = None


# -------------------------------------------------------------------
# Simple in-memory CVE "database" for MVP / demo
# IMPORTANT: This is only a demo dataset, not production-grade data.
# -------------------------------------------------------------------
CVE_DB = [
    {
        "cve_id": "CVE-DEMO-0001",
        "title": "Example privilege escalation in IOS XE web management",
        "severity": "critical",
        "platforms": ["IOS XE", "ISR4451-X"],
        "min_version": "17.3.1",
        "max_version": "17.6.9",
        "fixed_in": "17.7.1",
        "description": (
            "Demo CVE: unauthenticated attacker could exploit a bug in the web UI "
            "to gain elevated privileges."
        ),
        "workaround": "Disable HTTP/HTTPS management on WAN-facing interfaces.",
        "advisory_url": "https://example.com/cve-demo-0001",
    },
    {
        "cve_id": "CVE-DEMO-0002",
        "title": "Example DoS via malformed SNMP packets",
        "severity": "high",
        "platforms": ["IOS XE"],
        "min_version": "16.9.1",
        "max_version": "17.9.9",
        "fixed_in": "17.10.1",
        "description": (
            "Demo CVE: crafted SNMPv2 packets can cause high CPU utilization "
            "and temporary loss of management connectivity."
        ),
        "workaround": "Restrict SNMP access with ACLs and use SNMPv3 only.",
        "advisory_url": "https://example.com/cve-demo-0002",
    },
    {
        "cve_id": "CVE-DEMO-0003",
        "title": "Example information disclosure in SSH banner",
        "severity": "medium",
        "platforms": ["ISR4451-X", "ASR1001-X"],
        "min_version": "17.1.1",
        "max_version": "17.9.9",
        "fixed_in": None,
        "description": (
            "Demo CVE: SSH banner may leak device model and software details "
            "that can be used for targeted attacks."
        ),
        "workaround": "Configure a generic login banner and limit SSH exposure.",
        "advisory_url": "https://example.com/cve-demo-0003",
    },
]


def parse_version(version: str) -> List[int]:
    """
    Very simple version parser: split by dot and convert to ints.
    Non-numeric parts are ignored.
    Example: "17.9.3" -> [17, 9, 3]
    """
    parts = []
    for p in version.split("."):
        try:
            parts.append(int(p))
        except ValueError:
            break
    return parts


def version_in_range(version: str, min_version: str, max_version: str) -> bool:
    v = parse_version(version)
    v_min = parse_version(min_version)
    v_max = parse_version(max_version)

    if not v or not v_min or not v_max:
        return False

    def cmp(a, b):
        # compare lists lexicographically
        la, lb = len(a), len(b)
        for i in range(max(la, lb)):
            ai = a[i] if i < la else 0
            bi = b[i] if i < lb else 0
            if ai < bi:
                return -1
            if ai > bi:
                return 1
        return 0

    return cmp(v, v_min) >= 0 and cmp(v, v_max) <= 0


def find_matching_cves(platform: str, version: str) -> List[CVEItem]:
    platform_norm = platform.strip().lower()
    results: List[CVEItem] = []

    for entry in CVE_DB:
        platforms = [p.lower() for p in entry.get("platforms", [])]
        if platform_norm not in platforms and "ios xe" not in platform_norm:
            # Very simple matching: either exact platform or generic IOS XE match
            continue

        if not version_in_range(version, entry["min_version"], entry["max_version"]):
            continue

        results.append(
            CVEItem(
                cve_id=entry["cve_id"],
                title=entry["title"],
                severity=entry["severity"],
                description=entry["description"],
                fixed_in=entry.get("fixed_in"),
                workaround=entry.get("workaround"),
                advisory_url=entry.get("advisory_url"),
            )
        )

    return results


def build_recommendation(matched: List[CVEItem], platform: str, version: str) -> Optional[str]:
    if not matched:
        return None

    critical_or_high = [c for c in matched if c.severity in ("critical", "high")]

    if critical_or_high:
        # Simple heuristic recommendation
        fixed_versions = sorted(
            {c.fixed_in for c in critical_or_high if c.fixed_in},
            key=lambda x: parse_version(x) if x else [999],
        )
        if fixed_versions:
            return (
                "One or more critical/high issues affect this platform/version. "
                "Consider upgrading to at least IOS XE " + fixed_versions[0] + "."
            )
        return (
            "One or more critical/high issues affect this platform/version. "
            "Review the workarounds and plan an upgrade."
        )
    else:
        return (
            "Only medium/low demo issues matched. "
            "Still review the advisories and follow hardening best practices."
        )


# -------------------------------------------------------------------
# API Endpoint
# -------------------------------------------------------------------
@router.post("/cve", response_model=CVEAnalyzeResponse)
def analyze_cve(req: CVEAnalyzeRequest):
    matched = find_matching_cves(req.platform, req.version)

    note = (
        "This CVE data is a demo dataset for the Cisco Micro-Tool Generator MVP. "
        "Do not use it as a source of truth for production security decisions."
    )

    recommended_action = None
    if req.include_suggestions:
        recommended_action = build_recommendation(matched, req.platform, req.version)

    return CVEAnalyzeResponse(
        platform=req.platform,
        version=req.version,
        matched_cves=matched,
        note=note,
        timestamp=datetime.datetime.utcnow().isoformat() + "Z",
        recommended_action=recommended_action,
    )
