import pytest
import pytest_asyncio
from httpx import AsyncClient, ASGITransport
from backend.app.main import app
from backend.app.database import init_db

@pytest_asyncio.fixture(autouse=True)
async def prepare_database():
    await init_db()

@pytest.mark.asyncio
async def test_health_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/health")
        assert response.status_code == 200
        data = response.json()
        assert data["status"] in ("HEALTHY", "DEGRADED")
        assert data["api"] == "ONLINE"

@pytest.mark.asyncio
async def test_scan_known_safe_domain():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/scan/url", json={
            "url": "https://www.google.com/search?q=cybersecurity",
            "source": "test"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] == "ALLOW"
        assert data["risk_score"] < 40.0

@pytest.mark.asyncio
async def test_scan_brand_spoof_threat():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.post("/api/v1/scan/url", json={
            "url": "http://paypa1-security-verification.xyz/account/login",
            "source": "test"
        })
        assert response.status_code == 200
        data = response.json()
        assert data["decision"] in ("BLOCK", "WARN")
        assert data["risk_score"] >= 70.0
        assert data["threat_type"] == "BRAND_SPOOF" or "paypal" in str(data["reasons"]).lower()

@pytest.mark.asyncio
async def test_stats_endpoint():
    transport = ASGITransport(app=app)
    async with AsyncClient(transport=transport, base_url="http://test") as client:
        response = await client.get("/api/v1/stats")
        assert response.status_code == 200
        data = response.json()
        assert "total_scans" in data
        assert "threats_blocked" in data
