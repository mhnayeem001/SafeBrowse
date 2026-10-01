from fastapi import APIRouter, Depends
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import func

from backend.app.database import get_db, engine
from backend.app.models import ScanEvent, ThreatEvent, FalsePositiveReport
from backend.app.schemas import StatsResponse
from backend.app.services.cache_service import cache_service

router = APIRouter(tags=["Metrics & Health"])

@router.get("/stats", response_model=StatsResponse)
async def get_system_stats(db: AsyncSession = Depends(get_db)):
    # Calculate real stats from database
    total_scans = await db.scalar(select(func.count(ScanEvent.id))) or 0
    threats_blocked = await db.scalar(select(func.count(ScanEvent.id)).where(ScanEvent.decision == "BLOCK")) or 0
    warnings_issued = await db.scalar(select(func.count(ScanEvent.id)).where(ScanEvent.decision == "WARN")) or 0
    safe_requests = await db.scalar(select(func.count(ScanEvent.id)).where(ScanEvent.decision == "ALLOW")) or 0

    phishing_detections = await db.scalar(select(func.count(ThreatEvent.id)).where(ThreatEvent.threat_type == "PHISHING")) or 0
    spoof_detections = await db.scalar(select(func.count(ThreatEvent.id)).where(ThreatEvent.threat_type == "BRAND_SPOOF")) or 0
    malicious_downloads = await db.scalar(select(func.count(ThreatEvent.id)).where(ThreatEvent.threat_type == "MALICIOUS_DOWNLOAD")) or 0

    avg_latency = await db.scalar(select(func.avg(ScanEvent.latency_ms))) or 0.0
    false_positives = await db.scalar(select(func.count(FalsePositiveReport.id))) or 0

    return StatsResponse(
        total_scans=total_scans,
        threats_blocked=threats_blocked,
        warnings_issued=warnings_issued,
        safe_requests=safe_requests,
        phishing_detections=phishing_detections,
        spoof_detections=spoof_detections,
        malicious_downloads=malicious_downloads,
        avg_latency_ms=round(float(avg_latency), 2),
        false_positive_reports=false_positives
    )

@router.get("/health")
async def health_check():
    # Database status
    db_status = "ONLINE"
    try:
        async with engine.connect() as conn:
            await conn.execute(select(1))
    except Exception:
        db_status = "DEGRADED"

    redis_status = "ONLINE" if cache_service.is_redis_connected else "STANDALONE_MEMORY_CACHE"

    return {
        "status": "HEALTHY" if db_status == "ONLINE" else "DEGRADED",
        "api": "ONLINE",
        "database": db_status,
        "redis": redis_status,
        "threat_intelligence": "ONLINE",
        "version": "1.0.0"
    }
