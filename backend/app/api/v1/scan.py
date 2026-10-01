import time
import uuid
from datetime import datetime
from typing import Optional
from fastapi import APIRouter, Depends, HTTPException, Request
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.app.config import settings
from backend.app.database import get_db
from backend.app.models import ScanEvent, ThreatEvent, Whitelist, Blacklist, Domain, UrlReputation, DownloadEvent
from backend.app.schemas import (
    UrlScanRequest, DomainScanRequest, PageScanRequest, DownloadScanRequest, ScanResponse
)
from backend.app.engines.url_normalizer import URLNormalizer
from backend.app.engines.domain_intel import DomainIntelEngine
from backend.app.engines.typosquatting import TyposquattingEngine
from backend.app.engines.phishing_engine import PhishingEngine
from backend.app.engines.download_engine import DownloadEngine
from backend.app.engines.adaptive_risk_engine import AdaptiveRiskEngine
from backend.app.engines.decision_engine import DecisionEngine
from backend.app.services.threat_intel import threat_intel_service
from backend.app.services.cache_service import cache_service
from backend.app.services.event_broadcaster import broadcaster

router = APIRouter(prefix="/scan", tags=["Threat Scanning"])
domain_intel = DomainIntelEngine()
typo_engine = TyposquattingEngine()

def generate_scan_id() -> str:
    timestamp = datetime.utcnow().strftime("%Y%m%d")
    random_part = uuid.uuid4().hex[:8]
    return f"sb_{timestamp}_{random_part}"

@router.post("/url", response_model=ScanResponse)
async def scan_url(req: UrlScanRequest, request: Request, db: AsyncSession = Depends(get_db)):
    start_time = time.perf_counter()
    scan_id = generate_scan_id()

    # 1. Normalize URL
    norm_res = URLNormalizer.normalize(req.url)
    cache_key = f"rep:url:{norm_res.normalized_url}"

    # 2. Check Cache
    cached_data = await cache_service.get_json(cache_key)
    if cached_data:
        elapsed_ms = (time.perf_counter() - start_time) * 1000
        cached_data["latency_ms"] = round(elapsed_ms, 2)
        cached_data["cached"] = True
        return ScanResponse(**cached_data)

    # 3. Check Whitelist & Blacklist in Database
    wl_stmt = select(Whitelist).where(
        (Whitelist.domain_or_url == norm_res.registered_domain) | 
        (Whitelist.domain_or_url == norm_res.hostname) |
        (Whitelist.domain_or_url == norm_res.normalized_url)
    ).where(Whitelist.is_active == True)
    wl_res = await db.execute(wl_stmt)
    is_whitelisted = wl_res.scalars().first() is not None

    bl_stmt = select(Blacklist).where(
        (Blacklist.domain_or_url == norm_res.registered_domain) | 
        (Blacklist.domain_or_url == norm_res.hostname) |
        (Blacklist.domain_or_url == norm_res.normalized_url)
    ).where(Blacklist.is_active == True)
    bl_res = await db.execute(bl_stmt)
    is_blacklisted = bl_res.scalars().first() is not None

    # 4. Domain & Brand Intelligence
    domain_analysis = domain_intel.analyze_domain(norm_res.hostname)
    typo_analysis = typo_engine.analyze_domain(domain_analysis.root_domain.split(".")[0], norm_res.registered_domain)

    # 5. Threat Intelligence Feeds
    intel_res = await threat_intel_service.query_all(norm_res.normalized_url, norm_res.hostname)

    # 6. Adaptive Risk & Decision Computation
    risk_calc = AdaptiveRiskEngine.calculate_risk(
        url_res=norm_res,
        domain_res=domain_analysis,
        typo_res=typo_analysis,
        phish_res=None,
        intel_res=intel_res,
        is_whitelisted=is_whitelisted,
        is_blacklisted=is_blacklisted,
        security_mode=settings.DEFAULT_SECURITY_MODE
    )

    decision_res = DecisionEngine.evaluate(risk_calc, settings.DEFAULT_SECURITY_MODE)
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    # 7. Persist Scan Event in Database
    client_ip = request.client.host if request.client else None
    scan_event = ScanEvent(
        scan_id=scan_id,
        url=norm_res.normalized_url,
        domain=norm_res.hostname,
        decision=decision_res.decision,
        risk_score=decision_res.risk_score,
        confidence=decision_res.confidence,
        threat_type=decision_res.threat_type,
        reasons=decision_res.reasons,
        latency_ms=round(elapsed_ms, 2),
        source=req.source or "extension",
        user_ip=client_ip
    )
    db.add(scan_event)

    # If dangerous, also record a ThreatEvent
    if decision_res.decision in ("BLOCK", "WARN"):
        threat_event = ThreatEvent(
            event_id=f"evt_{scan_id}",
            threat_type=decision_res.threat_type or "SUSPICIOUS_SITE",
            url=norm_res.normalized_url,
            domain=norm_res.hostname,
            risk_score=decision_res.risk_score,
            confidence=decision_res.confidence,
            severity="CRITICAL" if decision_res.decision == "BLOCK" else "HIGH",
            action_taken="BLOCKED" if decision_res.decision == "BLOCK" else "WARNED",
            reasons=decision_res.reasons,
            resolved=False
        )
        db.add(threat_event)

    await db.commit()

    # 8. Broadcast to Live Monitor
    await broadcaster.broadcast_event({
        "type": "SCAN_EVENT",
        "scan_id": scan_id,
        "timestamp": datetime.utcnow().isoformat(),
        "url": norm_res.normalized_url,
        "domain": norm_res.hostname,
        "decision": decision_res.decision,
        "risk_score": decision_res.risk_score,
        "confidence": decision_res.confidence,
        "threat_type": decision_res.threat_type,
        "reasons": decision_res.reasons,
        "latency_ms": round(elapsed_ms, 2)
    })

    response_payload = {
        "scan_id": scan_id,
        "original_url": req.url,
        "normalized_url": norm_res.normalized_url,
        "domain": norm_res.hostname,
        "registered_domain": norm_res.registered_domain,
        "decision": decision_res.decision,
        "risk_score": decision_res.risk_score,
        "confidence": decision_res.confidence,
        "threat_type": decision_res.threat_type,
        "reasons": decision_res.reasons,
        "latency_ms": round(elapsed_ms, 2),
        "cached": False,
        "matched_brand": typo_analysis.matched_brand,
        "brand_similarity_score": typo_analysis.similarity_score if typo_analysis.is_spoofed else None,
        "is_whitelisted": is_whitelisted,
        "is_blacklisted": is_blacklisted,
        "security_mode": settings.DEFAULT_SECURITY_MODE
    }

    # 9. Store in cache
    await cache_service.set_json(cache_key, response_payload, ttl_seconds=settings.DECISION_CACHE_TTL)
    return ScanResponse(**response_payload)

@router.post("/domain", response_model=ScanResponse)
async def scan_domain(req: DomainScanRequest, request: Request, db: AsyncSession = Depends(get_db)):
    url_req = UrlScanRequest(url=f"http://{req.domain}", source=req.source)
    return await scan_url(url_req, request, db)

@router.post("/page", response_model=ScanResponse)
async def scan_page(req: PageScanRequest, request: Request, db: AsyncSession = Depends(get_db)):
    start_time = time.perf_counter()
    scan_id = generate_scan_id()

    norm_res = URLNormalizer.normalize(req.url)
    domain_analysis = domain_intel.analyze_domain(norm_res.hostname)
    typo_analysis = typo_engine.analyze_domain(domain_analysis.root_domain.split(".")[0], norm_res.registered_domain)
    intel_res = await threat_intel_service.query_all(norm_res.normalized_url, norm_res.hostname)

    # Whitelist / Blacklist check
    wl_res = await db.execute(select(Whitelist).where(Whitelist.domain_or_url == norm_res.registered_domain).where(Whitelist.is_active == True))
    is_whitelisted = wl_res.scalars().first() is not None

    bl_res = await db.execute(select(Blacklist).where(Blacklist.domain_or_url == norm_res.registered_domain).where(Blacklist.is_active == True))
    is_blacklisted = bl_res.scalars().first() is not None

    # Phishing Engine DOM Evaluation
    phish_res = PhishingEngine.analyze_page_context(
        page_data=req,
        domain_risk=domain_analysis.risk_score,
        is_brand_spoof=typo_analysis.is_spoofed,
        matched_brand=typo_analysis.matched_brand
    )

    risk_calc = AdaptiveRiskEngine.calculate_risk(
        url_res=norm_res,
        domain_res=domain_analysis,
        typo_res=typo_analysis,
        phish_res=phish_res,
        intel_res=intel_res,
        is_whitelisted=is_whitelisted,
        is_blacklisted=is_blacklisted,
        security_mode=settings.DEFAULT_SECURITY_MODE
    )

    decision_res = DecisionEngine.evaluate(risk_calc, settings.DEFAULT_SECURITY_MODE)
    elapsed_ms = (time.perf_counter() - start_time) * 1000

    scan_event = ScanEvent(
        scan_id=scan_id,
        url=norm_res.normalized_url,
        domain=norm_res.hostname,
        decision=decision_res.decision,
        risk_score=decision_res.risk_score,
        confidence=decision_res.confidence,
        threat_type=decision_res.threat_type,
        reasons=decision_res.reasons,
        latency_ms=round(elapsed_ms, 2),
        source="page_content_analysis"
    )
    db.add(scan_event)
    await db.commit()

    return ScanResponse(
        scan_id=scan_id,
        original_url=req.url,
        normalized_url=norm_res.normalized_url,
        domain=norm_res.hostname,
        registered_domain=norm_res.registered_domain,
        decision=decision_res.decision,
        risk_score=decision_res.risk_score,
        confidence=decision_res.confidence,
        threat_type=decision_res.threat_type,
        reasons=decision_res.reasons,
        latency_ms=round(elapsed_ms, 2),
        cached=False,
        matched_brand=typo_analysis.matched_brand,
        brand_similarity_score=typo_analysis.similarity_score if typo_analysis.is_spoofed else None,
        is_whitelisted=is_whitelisted,
        is_blacklisted=is_blacklisted,
        security_mode=settings.DEFAULT_SECURITY_MODE
    )

@router.post("/download")
async def scan_download(req: DownloadScanRequest, db: AsyncSession = Depends(get_db)):
    norm_res = URLNormalizer.normalize(req.url)
    domain_analysis = domain_intel.analyze_domain(norm_res.hostname)
    
    result = DownloadEngine.analyze_download(req, source_domain_risk=domain_analysis.risk_score)
    
    # Save Download Event
    dl_event = DownloadEvent(
        filename=req.filename,
        file_extension=req.file_extension or "",
        url=norm_res.normalized_url,
        domain=norm_res.hostname,
        mime_type=req.mime_type,
        risk_score=result.risk_score,
        decision=result.decision,
        reasons=result.reasons
    )
    db.add(dl_event)
    await db.commit()

    return {
        "filename": req.filename,
        "decision": result.decision,
        "risk_score": result.risk_score,
        "confidence": result.confidence,
        "threat_type": result.threat_type,
        "reasons": result.reasons
    }
