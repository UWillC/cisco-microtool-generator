import datetime
import os
from typing import List, Optional

from fastapi import APIRouter
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
