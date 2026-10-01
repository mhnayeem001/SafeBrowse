from fastapi import APIRouter
from backend.app.config import settings
from backend.app.schemas import VersionCheckResponse

router = APIRouter(tags=["Versioning & Updates"])

@router.get("/version", response_model=VersionCheckResponse)
async def check_version(client_version: str = "1.0.0"):
    min_supported = "1.0.0"
    latest_ver = settings.APP_VERSION

    # Simple semver check
    update_recommended = client_version < latest_ver

    return VersionCheckResponse(
        current_backend_version=settings.APP_VERSION,
        minimum_supported_extension_version=min_supported,
        latest_extension_version=latest_ver,
        update_recommended=update_recommended,
        release_notes="SafeBrowse X 1.0.0 Production Release: Real-time Threat Intelligence, SSRF-guarded Pre-Navigation, Credential Guard, and Typosquatting Defense."
    )
