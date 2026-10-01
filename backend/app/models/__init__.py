import uuid
from datetime import datetime
from typing import Optional, List
from sqlalchemy import (
    Column,
    String,
    Integer,
    Float,
    Boolean,
    DateTime,
    Text,
    JSON,
    ForeignKey,
    Index,
)
from sqlalchemy.orm import relationship
from backend.app.database import Base

def generate_uuid() -> str:
    return str(uuid.uuid4())

class User(Base):
    __tablename__ = "users"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    email = Column(String(255), unique=True, index=True, nullable=False)
    hashed_password = Column(String(255), nullable=False)
    full_name = Column(String(100), nullable=True)
    is_active = Column(Boolean, default=True)
    is_superuser = Column(Boolean, default=False)
    created_at = Column(DateTime, default=datetime.utcnow)
    last_login = Column(DateTime, nullable=True)

class Domain(Base):
    __tablename__ = "domains"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    domain_name = Column(String(255), unique=True, index=True, nullable=False)
    registered_domain = Column(String(255), index=True, nullable=False)
    tld = Column(String(50), nullable=False)
    reputation_score = Column(Float, default=0.0) # 0 to 100 risk
    confidence = Column(Float, default=50.0)
    category = Column(String(100), default="unknown")
    is_known_safe = Column(Boolean, default=False)
    is_known_malicious = Column(Boolean, default=False)
    first_seen = Column(DateTime, default=datetime.utcnow)
    last_scanned = Column(DateTime, default=datetime.utcnow)
    scan_count = Column(Integer, default=1)

class UrlReputation(Base):
    __tablename__ = "url_reputations"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    normalized_url = Column(Text, unique=True, index=True, nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    risk_score = Column(Float, default=0.0)
    confidence = Column(Float, default=0.0)
    verdict = Column(String(20), default="ALLOW") # ALLOW, WARN, BLOCK, REVIEW
    threat_type = Column(String(50), default="NONE") # PHISHING, SPOOFING, MALWARE, etc.
    reasons = Column(JSON, default=list)
    last_analyzed = Column(DateTime, default=datetime.utcnow, index=True)

class ScanEvent(Base):
    __tablename__ = "scan_events"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    scan_id = Column(String(64), index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    url = Column(Text, nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    decision = Column(String(20), nullable=False) # ALLOW, WARN, BLOCK, REVIEW
    risk_score = Column(Float, nullable=False)
    confidence = Column(Float, nullable=False)
    threat_type = Column(String(50), default="NONE")
    reasons = Column(JSON, default=list)
    latency_ms = Column(Float, default=0.0)
    source = Column(String(50), default="extension") # extension, api, manual
    user_ip = Column(String(45), nullable=True)

class ThreatEvent(Base):
    __tablename__ = "threat_events"

    id = Column(String(64), primary_key=True, default=generate_uuid)
    event_id = Column(String(64), unique=True, index=True, nullable=False)
    timestamp = Column(DateTime, default=datetime.utcnow, index=True)
    threat_type = Column(String(50), nullable=False) # PHISHING, BRAND_SPOOF, MALWARE_DOWNLOAD, etc.
    url = Column(Text, nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    risk_score = Column(Float, nullable=False)
    confidence = Column(Float, nullable=False)
    severity = Column(String(20), default="HIGH") # LOW, MEDIUM, HIGH, CRITICAL
    action_taken = Column(String(20), default="BLOCKED") # BLOCKED, WARNED, MONITORED
    reasons = Column(JSON, default=list)
    resolved = Column(Boolean, default=False)

class Whitelist(Base):
    __tablename__ = "whitelist"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    domain_or_url = Column(String(500), unique=True, index=True, nullable=False)
    match_type = Column(String(20), default="domain") # domain, subdomain, exact_url
    reason = Column(String(255), nullable=True)
    added_by = Column(String(100), default="admin")
    is_permanent = Column(Boolean, default=True)
    expires_at = Column(DateTime, nullable=True)
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class Blacklist(Base):
    __tablename__ = "blacklist"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    domain_or_url = Column(String(500), unique=True, index=True, nullable=False)
    match_type = Column(String(20), default="domain") # domain, subdomain, exact_url
    threat_type = Column(String(50), default="MALICIOUS")
    severity = Column(String(20), default="CRITICAL")
    reason = Column(String(255), nullable=True)
    added_by = Column(String(100), default="admin")
    is_active = Column(Boolean, default=True)
    created_at = Column(DateTime, default=datetime.utcnow)

class SecurityRule(Base):
    __tablename__ = "security_rules"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    rule_code = Column(String(50), unique=True, index=True, nullable=False)
    rule_name = Column(String(100), nullable=False)
    description = Column(Text, nullable=True)
    rule_type = Column(String(50), default="HEURISTIC")
    severity = Column(String(20), default="HIGH")
    is_enabled = Column(Boolean, default=True)
    condition_json = Column(JSON, default=dict)
    created_at = Column(DateTime, default=datetime.utcnow)

class NotificationEvent(Base):
    __tablename__ = "notifications"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    domain = Column(String(255), nullable=False)
    url = Column(Text, nullable=True)
    blocked_reason = Column(String(255), nullable=False)
    abuse_type = Column(String(50), default="PERMISSION_SPAM")
    created_at = Column(DateTime, default=datetime.utcnow)

class DownloadEvent(Base):
    __tablename__ = "download_events"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    filename = Column(String(255), nullable=False)
    file_extension = Column(String(50), nullable=False)
    url = Column(Text, nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    mime_type = Column(String(100), nullable=True)
    risk_score = Column(Float, default=0.0)
    decision = Column(String(20), default="ALLOW")
    reasons = Column(JSON, default=list)
    created_at = Column(DateTime, default=datetime.utcnow)

class SystemSetting(Base):
    __tablename__ = "system_settings"

    key = Column(String(100), primary_key=True, index=True)
    value = Column(Text, nullable=False)
    description = Column(String(255), nullable=True)
    updated_at = Column(DateTime, default=datetime.utcnow, onupdate=datetime.utcnow)

class FalsePositiveReport(Base):
    __tablename__ = "false_positive_reports"

    id = Column(String(36), primary_key=True, default=generate_uuid)
    report_id = Column(String(64), unique=True, index=True, nullable=False)
    url = Column(Text, nullable=False)
    domain = Column(String(255), index=True, nullable=False)
    original_verdict = Column(String(20), nullable=False)
    threat_type = Column(String(50), nullable=True)
    user_notes = Column(Text, nullable=True)
    status = Column(String(20), default="PENDING") # PENDING, APPROVED, REJECTED
    created_at = Column(DateTime, default=datetime.utcnow)
