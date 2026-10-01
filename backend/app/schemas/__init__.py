from typing import List, Optional, Dict, Any
from datetime import datetime
from pydantic import BaseModel, Field, EmailStr, ConfigDict

# Auth Schemas
class UserLogin(BaseModel):
    email: EmailStr
    password: str

class UserRegister(BaseModel):
    email: EmailStr
    password: str
    full_name: Optional[str] = None

class Token(BaseModel):
    access_token: str
    token_type: str = "bearer"
    expires_in: int

class UserResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    email: EmailStr
    full_name: Optional[str] = None
    is_active: bool
    is_superuser: bool
    created_at: datetime
    last_login: Optional[datetime] = None

# Scan Schemas
class FormMetadata(BaseModel):
    action_url: Optional[str] = None
    method: Optional[str] = "POST"
    has_password: bool = False
    has_email_or_username: bool = False
    has_otp_or_token: bool = False
    has_credit_card: bool = False
    input_count: int = 0
    is_cross_origin: bool = False

class UrlScanRequest(BaseModel):
    url: str
    referrer: Optional[str] = None
    source: Optional[str] = "extension"
    client_version: Optional[str] = "1.0.0"

class DomainScanRequest(BaseModel):
    domain: str
    source: Optional[str] = "api"

class PageScanRequest(BaseModel):
    url: str
    title: Optional[str] = None
    forms: Optional[List[FormMetadata]] = []
    has_suspicious_prompts: bool = False
    notification_prompt_count: int = 0
    external_scripts: Optional[List[str]] = []
    iframes: Optional[List[str]] = []
    client_version: Optional[str] = "1.0.0"

class DownloadScanRequest(BaseModel):
    url: str
    filename: str
    file_extension: Optional[str] = None
    mime_type: Optional[str] = None
    file_size_bytes: Optional[int] = None
    referrer: Optional[str] = None

class ScanResponse(BaseModel):
    scan_id: str
    original_url: str
    normalized_url: str
    domain: str
    registered_domain: str
    decision: str  # ALLOW, WARN, BLOCK, REVIEW
    risk_score: float  # 0 to 100
    confidence: float  # 0 to 100
    threat_type: str  # NONE, PHISHING, BRAND_SPOOF, MALWARE_DOWNLOAD, SUSPICIOUS_REDIRECT, NOTIFICATION_ABUSE, BLACKLISTED
    reasons: List[str]
    latency_ms: float
    cached: bool = False
    matched_brand: Optional[str] = None
    brand_similarity_score: Optional[float] = None
    is_whitelisted: bool = False
    is_blacklisted: bool = False
    security_mode: str = "NORMAL"

# Threat & Event Schemas
class ThreatEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    event_id: str
    timestamp: datetime
    threat_type: str
    url: str
    domain: str
    risk_score: float
    confidence: float
    severity: str
    action_taken: str
    reasons: List[str]
    resolved: bool

class ScanEventResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    scan_id: str
    timestamp: datetime
    url: str
    domain: str
    decision: str
    risk_score: float
    confidence: float
    threat_type: str
    reasons: List[str]
    latency_ms: float
    source: str

class StatsResponse(BaseModel):
    total_scans: int
    threats_blocked: int
    warnings_issued: int
    safe_requests: int
    phishing_detections: int
    spoof_detections: int
    malicious_downloads: int
    avg_latency_ms: float
    false_positive_reports: int

class WhitelistCreate(BaseModel):
    domain_or_url: str
    match_type: str = "domain"  # domain, subdomain, exact_url
    reason: Optional[str] = None
    is_permanent: bool = True
    expires_at: Optional[datetime] = None

class WhitelistResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    domain_or_url: str
    match_type: str
    reason: Optional[str]
    added_by: str
    is_permanent: bool
    expires_at: Optional[datetime]
    is_active: bool
    created_at: datetime

class BlacklistCreate(BaseModel):
    domain_or_url: str
    match_type: str = "domain"
    threat_type: str = "MALICIOUS"
    severity: str = "CRITICAL"
    reason: Optional[str] = None

class BlacklistResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    domain_or_url: str
    match_type: str
    threat_type: str
    severity: str
    reason: Optional[str]
    added_by: str
    is_active: bool
    created_at: datetime

class FalsePositiveCreate(BaseModel):
    url: str
    domain: str
    original_verdict: str
    threat_type: Optional[str] = None
    user_notes: Optional[str] = None

class FalsePositiveResponse(BaseModel):
    model_config = ConfigDict(from_attributes=True)

    id: str
    report_id: str
    url: str
    domain: str
    original_verdict: str
    threat_type: Optional[str]
    user_notes: Optional[str]
    status: str
    created_at: datetime

class VersionCheckResponse(BaseModel):
    current_backend_version: str
    minimum_supported_extension_version: str
    latest_extension_version: str
    update_recommended: bool
    release_notes: str
