import json
import time
from typing import Optional, Any, Dict
from backend.app.config import settings

try:
    import redis.asyncio as aioredis
    HAS_REDIS = True
except ImportError:
    HAS_REDIS = False
    aioredis = None

class CacheService:
    def __init__(self):
        self.redis_client = None
        self.memory_cache: Dict[str, Dict[str, Any]] = {}
        self.is_redis_connected = False

    async def connect(self):
        if HAS_REDIS and settings.REDIS_URL:
            try:
                self.redis_client = aioredis.from_url(
                    settings.REDIS_URL,
                    encoding="utf-8",
                    decode_responses=True,
                    socket_connect_timeout=1.0
                )
                await self.redis_client.ping()
                self.is_redis_connected = True
            except Exception:
                self.is_redis_connected = False
                self.redis_client = None
        else:
            self.is_redis_connected = False
            self.redis_client = None

    async def get_json(self, key: str) -> Optional[Dict[str, Any]]:
        if self.is_redis_connected and self.redis_client:
            try:
                val = await self.redis_client.get(key)
                if val:
                    return json.loads(val)
            except Exception:
                pass

        # In-memory fallback
        if key in self.memory_cache:
            entry = self.memory_cache[key]
            if time.time() < entry["expires_at"]:
                return entry["data"]
            else:
                del self.memory_cache[key]
        return None

    async def set_json(self, key: str, data: Dict[str, Any], ttl_seconds: int = 600):
        val_str = json.dumps(data)
        if self.is_redis_connected and self.redis_client:
            try:
                await self.redis_client.setex(key, ttl_seconds, val_str)
                return
            except Exception:
                pass

        # In-memory fallback
        self.memory_cache[key] = {
            "data": data,
            "expires_at": time.time() + ttl_seconds
        }

    async def delete(self, key: str):
        if self.is_redis_connected and self.redis_client:
            try:
                await self.redis_client.delete(key)
            except Exception:
                pass
        self.memory_cache.pop(key, None)

    async def close(self):
        if self.redis_client:
            try:
                await self.redis_client.close()
            except Exception:
                pass

cache_service = CacheService()
