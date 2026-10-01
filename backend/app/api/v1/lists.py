import uuid
from datetime import datetime
from typing import List
from fastapi import APIRouter, Depends, HTTPException, status
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.app.database import get_db
from backend.app.models import Whitelist, Blacklist, FalsePositiveReport, User
from backend.app.schemas import (
    WhitelistCreate, WhitelistResponse,
    BlacklistCreate, BlacklistResponse,
    FalsePositiveCreate, FalsePositiveResponse
)
from backend.app.security.auth import get_current_user

router = APIRouter(tags=["Lists & Reports"])

# --- Whitelist ---
@router.get("/whitelist", response_model=List[WhitelistResponse])
async def get_whitelist(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Whitelist).where(Whitelist.is_active == True))
    return res.scalars().all()

@router.post("/whitelist", response_model=WhitelistResponse)
async def add_to_whitelist(
    item: WhitelistCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    clean_target = item.domain_or_url.lower().strip()
    res = await db.execute(select(Whitelist).where(Whitelist.domain_or_url == clean_target))
    existing = res.scalars().first()
    if existing:
        existing.is_active = True
        existing.reason = item.reason
        await db.commit()
        await db.refresh(existing)
        return existing

    new_entry = Whitelist(
        domain_or_url=clean_target,
        match_type=item.match_type,
        reason=item.reason,
        added_by=user.email if user else "user",
        is_permanent=item.is_permanent,
        expires_at=item.expires_at,
        is_active=True
    )
    db.add(new_entry)
    await db.commit()
    await db.refresh(new_entry)
    return new_entry

@router.delete("/whitelist/{id}")
async def delete_whitelist_entry(id: str, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Whitelist).where(Whitelist.id == id))
    entry = res.scalars().first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    await db.delete(entry)
    await db.commit()
    return {"status": "deleted", "id": id}

# --- Blacklist ---
@router.get("/blacklist", response_model=List[BlacklistResponse])
async def get_blacklist(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Blacklist).where(Blacklist.is_active == True))
    return res.scalars().all()

@router.post("/blacklist", response_model=BlacklistResponse)
async def add_to_blacklist(
    item: BlacklistCreate,
    db: AsyncSession = Depends(get_db),
    user: User = Depends(get_current_user)
):
    clean_target = item.domain_or_url.lower().strip()
    res = await db.execute(select(Blacklist).where(Blacklist.domain_or_url == clean_target))
    existing = res.scalars().first()
    if existing:
        existing.is_active = True
        existing.threat_type = item.threat_type
        existing.severity = item.severity
        existing.reason = item.reason
        await db.commit()
        await db.refresh(existing)
        return existing

    new_entry = Blacklist(
        domain_or_url=clean_target,
        match_type=item.match_type,
        threat_type=item.threat_type,
        severity=item.severity,
        reason=item.reason,
        added_by=user.email if user else "admin",
        is_active=True
    )
    db.add(new_entry)
    await db.commit()
    await db.refresh(new_entry)
    return new_entry

@router.delete("/blacklist/{id}")
async def delete_blacklist_entry(id: str, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(Blacklist).where(Blacklist.id == id))
    entry = res.scalars().first()
    if not entry:
        raise HTTPException(status_code=404, detail="Entry not found")
    await db.delete(entry)
    await db.commit()
    return {"status": "deleted", "id": id}

# --- False Positive Reports ---
@router.post("/reports", response_model=FalsePositiveResponse)
async def submit_false_positive(item: FalsePositiveCreate, db: AsyncSession = Depends(get_db)):
    report_id = f"fp_{uuid.uuid4().hex[:8]}"
    report = FalsePositiveReport(
        report_id=report_id,
        url=item.url,
        domain=item.domain,
        original_verdict=item.original_verdict,
        threat_type=item.threat_type,
        user_notes=item.user_notes,
        status="PENDING"
    )
    db.add(report)
    await db.commit()
    await db.refresh(report)
    return report

@router.get("/reports", response_model=List[FalsePositiveResponse])
async def list_false_positive_reports(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(FalsePositiveReport).order_by(FalsePositiveReport.created_at.desc()))
    return res.scalars().all()
