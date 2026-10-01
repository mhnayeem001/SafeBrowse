from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.app.database import get_db
from backend.app.models import Domain, UrlReputation
from backend.app.schemas import ScanResponse, DomainScanRequest
from backend.app.engines.domain_intel import DomainIntelEngine
from backend.app.engines.typosquatting import TyposquattingEngine
from backend.app.services.threat_intel import threat_intel_service
from backend.app.services.cache_service import cache_service

router = APIRouter(prefix="/reputation", tags=["Domain Reputation"])
domain_intel = DomainIntelEngine()
typo_engine = TyposquattingEngine()

@router.get("/{domain}")
async def get_domain_reputation(domain: str, db: AsyncSession = Depends(get_db)):
    clean_domain = domain.lower().strip()
    cache_key = f"rep:domain:{clean_domain}"
    
    cached = await cache_service.get_json(cache_key)
    if cached:
        return cached

    analysis = domain_intel.analyze_domain(clean_domain)
    typo_res = typo_engine.analyze_domain(analysis.root_domain.split(".")[0], clean_domain)
    intel_res = await threat_intel_service.query_all(f"http://{clean_domain}", clean_domain)

    risk_score = analysis.risk_score
    if typo_res.is_spoofed:
        risk_score = max(risk_score, typo_res.similarity_score)
    if intel_res and intel_res.is_malicious:
        risk_score = 100.0

    verdict = "ALLOW"
    if risk_score >= 75.0:
        verdict = "BLOCK"
    elif risk_score >= 40.0:
        verdict = "WARN"

    rep_data = {
        "domain": clean_domain,
        "registered_domain": analysis.root_domain,
        "tld": analysis.suffix,
        "entropy": round(analysis.entropy, 2),
        "risk_score": round(risk_score, 1),
        "verdict": verdict,
        "is_spoofed": typo_res.is_spoofed,
        "matched_brand": typo_res.matched_brand,
        "reasons": analysis.reasons + (typo_res.reasons if typo_res.is_spoofed else [])
    }

    await cache_service.set_json(cache_key, rep_data, ttl_seconds=1800)
    return rep_data
