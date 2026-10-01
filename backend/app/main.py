import time
from contextlib import asynccontextmanager
from fastapi import FastAPI, Request, status
from fastapi.middleware.cors import CORSMiddleware
from fastapi.responses import JSONResponse

from backend.app.config import settings
from backend.app.database import init_db, AsyncSessionLocal
from backend.app.services.cache_service import cache_service
from backend.app.api.v1.auth import router as auth_router, ensure_default_admin
from backend.app.api.v1.scan import router as scan_router
from backend.app.api.v1.reputation import router as rep_router
from backend.app.api.v1.events import router as events_router
from backend.app.api.v1.stats import router as stats_router
from backend.app.api.v1.lists import router as lists_router
from backend.app.api.v1.rules import router as rules_router
from backend.app.api.v1.version import router as version_router

@asynccontextmanager
async def lifespan(app: FastAPI):
    # Startup
    await init_db()
    async with AsyncSessionLocal() as session:
        await ensure_default_admin(session)
    await cache_service.connect()
    yield
    # Shutdown
    await cache_service.close()

app = FastAPI(
    title=settings.APP_NAME,
    version=settings.APP_VERSION,
    description="Real-Time Defensive Browser Security & Threat Intelligence API",
    lifespan=lifespan,
    docs_url="/docs",
    redoc_url="/redoc"
)

# CORS configuration
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],  # Allows browser extension and dashboard
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Request Timing & Security Middleware
@app.middleware("http")
async def add_security_headers_and_timing(request: Request, call_next):
    start_time = time.perf_counter()
    response = await call_next(request)
    process_time = (time.perf_counter() - start_time) * 1000
    
    response.headers["X-Process-Time-Ms"] = f"{process_time:.2f}"
    response.headers["X-Content-Type-Options"] = "nosniff"
    response.headers["X-Frame-Options"] = "DENY"
    response.headers["X-XSS-Protection"] = "1; mode=block"
    return response

# Mount API V1 routers
api_v1_prefix = settings.API_V1_STR
app.include_router(auth_router, prefix=api_v1_prefix)
app.include_router(scan_router, prefix=api_v1_prefix)
app.include_router(rep_router, prefix=api_v1_prefix)
app.include_router(events_router, prefix=api_v1_prefix)
app.include_router(stats_router, prefix=api_v1_prefix)
app.include_router(lists_router, prefix=api_v1_prefix)
app.include_router(rules_router, prefix=api_v1_prefix)
app.include_router(version_router, prefix=api_v1_prefix)

@app.get("/")
async def root():
    return {
        "product": "SafeBrowse X",
        "status": "OPERATIONAL",
        "version": settings.APP_VERSION,
        "docs": "/docs",
        "health": f"{settings.API_V1_STR}/health"
    }
