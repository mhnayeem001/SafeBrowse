from typing import List, Optional
from fastapi import APIRouter, Depends, WebSocket, WebSocketDisconnect, Query
from sqlalchemy.ext.asyncio import AsyncSession
from sqlalchemy.future import select
from sqlalchemy import desc

from backend.app.database import get_db
from backend.app.models import ScanEvent, ThreatEvent
from backend.app.schemas import ScanEventResponse, ThreatEventResponse
from backend.app.services.event_broadcaster import broadcaster

router = APIRouter(prefix="/events", tags=["Security Events"])

@router.get("", response_model=List[ScanEventResponse])
async def list_recent_events(
    limit: int = Query(50, ge=1, le=200),
    offset: int = Query(0, ge=0),
    decision: Optional[str] = None,
    db: AsyncSession = Depends(get_db)
):
    query = select(ScanEvent).order_by(desc(ScanEvent.timestamp)).offset(offset).limit(limit)
    if decision:
        query = query.where(ScanEvent.decision == decision.upper())
    result = await db.execute(query)
    events = result.scalars().all()
    return events

@router.get("/threats", response_model=List[ThreatEventResponse])
async def list_threat_events(
    limit: int = Query(50, ge=1, le=200),
    db: AsyncSession = Depends(get_db)
):
    query = select(ThreatEvent).order_by(desc(ThreatEvent.timestamp)).limit(limit)
    result = await db.execute(query)
    threats = result.scalars().all()
    return threats

@router.websocket("/ws")
async def websocket_events_endpoint(websocket: WebSocket):
    await broadcaster.connect(websocket)
    try:
        while True:
            # Keep connection open and accept ping messages
            data = await websocket.receive_text()
            if data == "ping":
                await websocket.send_text('{"type": "pong"}')
    except WebSocketDisconnect:
        broadcaster.disconnect(websocket)
    except Exception:
        broadcaster.disconnect(websocket)
