import datetime
import os
from typing import List, Optional

from fastapi import APIRouter, HTTPException
from pydantic import BaseModel

from services.cve_engine import CVEEngine, CVEEngineConfig
from services.cve_sources import NvdEnricherProvider
from models.cve_model import CVEEntry


router = APIRouter()


class CVEAnalyzeRequest(BaseModel):
    platform: str
    version: str
    include_suggestions: bool = True


class CVEAnalyzeResponse(BaseModel):
    platform: str
    version: str
    matched: List[CVEEntry]
    summary: dict
    recommended_upgrade: Optional[str]
    timestamp: str


class CVECheckResponse(BaseModel):
    cve_id: str
    found: bool
    entry: Optional[CVEEntry]
    timestamp: str


def _env_true(name: str) -> bool:
    v = os.getenv(name, "").strip().lower()
    return v in ("1", "true", "yes", "on")


@router.post("/cve", response_model=CVEAnalyzeResponse)
def analyze_cve(req: CVEAnalyzeRequest):
    # 1) Base run (local JSON only) to find which CVE IDs apply
    base_engine = CVEEngine(config=CVEEngineConfig(engine_version="0.3.3"))
    base_engine.load_all()
    matched_base = base_engine.match(req.platform, req.version)

    # 2) Optional enrichment from NVD for ONLY those CVEs (fast + cheap + avoids scanning the whole world)
    if _env_true("CVE_NVD_ENRICH") and matched_base:
        ids = [c.cve_id for c in matched_base]
        # Build a new engine with local + NVD enricher (IDs)
        enriched_engine = CVEEngine(
            config=CVEEngineConfig(engine_version="0.3.3", enable_nvd_enrichment=True),
            providers=[
                # Keep local base provider first (created internally)
                *base_engine.providers[:1],
                NvdEnricherProvider(cve_ids=ids),
            ],
        )
        enriched_engine.load_all()
        matched = enriched_engine.match(req.platform, req.version)
        summary = enriched_engine.summary(matched)
        recommendation = enriched_engine.recommended_upgrade(matched) if req.include_suggestions else None
    else:
        matched = matched_base
        summary = base_engine.summary(matched)
        recommendation = base_engine.recommended_upgrade(matched) if req.include_suggestions else None

    return CVEAnalyzeResponse(
        platform=req.platform,
        version=req.version,
        matched=matched,
        summary=summary,
        recommended_upgrade=recommendation,
        timestamp=datetime.datetime.utcnow().isoformat() + "Z",
    )


@router.get("/cve/{cve_id}", response_model=CVECheckResponse)
def check_cve(cve_id: str):
    """
    Check if a specific CVE exists in the local database.
    Optionally enriches with NVD data if CVE_NVD_ENRICH=1.
    """
    # Normalize CVE ID format
    cve_id_upper = cve_id.upper()
    if not cve_id_upper.startswith("CVE-"):
        cve_id_upper = f"CVE-{cve_id_upper}"

    # Load CVE database
    engine = CVEEngine(config=CVEEngineConfig(engine_version="0.3.3"))
    engine.load_all()

    # Find the CVE by ID
    entry = None
    for cve in engine.cves:
        if cve.cve_id.upper() == cve_id_upper:
            entry = cve
            break

    # Optional NVD enrichment for this specific CVE
    if entry and _env_true("CVE_NVD_ENRICH"):
        enriched_engine = CVEEngine(
            config=CVEEngineConfig(engine_version="0.3.3", enable_nvd_enrichment=True),
            providers=[
                *engine.providers[:1],
                NvdEnricherProvider(cve_ids=[cve_id_upper]),
            ],
        )
        enriched_engine.load_all()
        for cve in enriched_engine.cves:
            if cve.cve_id.upper() == cve_id_upper:
                entry = cve
                break

    return CVECheckResponse(
        cve_id=cve_id_upper,
        found=entry is not None,
        entry=entry,
        timestamp=datetime.datetime.utcnow().isoformat() + "Z",
    )
