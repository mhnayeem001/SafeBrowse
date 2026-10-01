from typing import List, Dict, Any
from fastapi import APIRouter, Depends, HTTPException
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select

from backend.app.database import get_db
from backend.app.models import SecurityRule, SystemSetting

router = APIRouter(tags=["Security Rules & Settings"])

DEFAULT_RULES = [
    {
        "rule_code": "RUL-001",
        "rule_name": "Homoglyph Brand Impersonation Guard",
        "description": "Flags domains using character substitutions or visual homoglyphs resembling protected brands.",
        "rule_type": "HEURISTIC",
        "severity": "CRITICAL",
        "is_enabled": True
    },
    {
        "rule_code": "RUL-002",
        "rule_name": "Double Extension Executable Cloaking",
        "description": "Blocks downloads masking executables with document extensions (e.g. .pdf.exe).",
        "rule_type": "DOWNLOAD_SHIELD",
        "severity": "CRITICAL",
        "is_enabled": True
    },
    {
        "rule_code": "RUL-003",
        "rule_name": "Cross-Origin Credential Form Harvesting",
        "description": "Detects login forms posting user credentials to unauthorized third-party origins.",
        "rule_type": "PHISHING_GUARD",
        "severity": "HIGH",
        "is_enabled": True
    },
    {
        "rule_code": "RUL-004",
        "rule_name": "High Abuse Throwaway TLD Filter",
        "description": "Applies elevated scrutiny to domains on top phishing/malware distribution TLDs.",
        "rule_type": "DOMAIN_INTEL",
        "severity": "MEDIUM",
        "is_enabled": True
    },
    {
        "rule_code": "RUL-005",
        "rule_name": "Deceptive Notification Spam Defense",
        "description": "Flags fake verification/captcha prompts that abuse browser notification permissions.",
        "rule_type": "BEHAVIOR_SHIELD",
        "severity": "MEDIUM",
        "is_enabled": True
    }
]

@router.get("/rules")
async def get_security_rules(db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(SecurityRule))
    rules = res.scalars().all()
    if not rules:
        # Seed default rules
        for r in DEFAULT_RULES:
            new_r = SecurityRule(**r)
            db.add(new_r)
        await db.commit()
        res = await db.execute(select(SecurityRule))
        rules = res.scalars().all()
    return rules

@router.post("/rules/{rule_code}/toggle")
async def toggle_security_rule(rule_code: str, db: AsyncSession = Depends(get_db)):
    res = await db.execute(select(SecurityRule).where(SecurityRule.rule_code == rule_code))
    rule = res.scalars().first()
    if not rule:
        raise HTTPException(status_code=404, detail="Rule not found")
    rule.is_enabled = not rule.is_enabled
    await db.commit()
    await db.refresh(rule)
    return {"rule_code": rule.rule_code, "is_enabled": rule.is_enabled}
