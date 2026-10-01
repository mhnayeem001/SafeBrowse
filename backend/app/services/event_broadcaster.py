import asyncio
import json
from typing import Set, Dict, Any
from fastapi import WebSocket

class EventBroadcaster:
    def __init__(self):
        self.active_connections: Set[WebSocket] = set()

    async def connect(self, websocket: WebSocket):
        await websocket.accept()
        self.active_connections.add(websocket)

    def disconnect(self, websocket: WebSocket):
        self.active_connections.discard(websocket)

    async def broadcast_event(self, event_data: Dict[str, Any]):
        if not self.active_connections:
            return
        
        dead_connections = set()
        message_json = json.dumps(event_data)
        
        for conn in self.active_connections:
            try:
                await conn.send_text(message_json)
            except Exception:
                dead_connections.add(conn)

        for dead in dead_connections:
            self.active_connections.discard(dead)

broadcaster = EventBroadcaster()
