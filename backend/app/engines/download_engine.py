import os
from typing import Dict, List, Optional
from backend.app.schemas import DownloadScanRequest

EXECUTABLE_EXTENSIONS = {
    ".exe", ".scr", ".bat", ".cmd", ".ps1", ".vbs", ".js", ".wsf", ".hta", 
    ".cpl", ".msi", ".jar", ".com", ".pif", ".gadget"
}

ARCHIVE_EXTENSIONS = {
    ".zip", ".rar", ".7z", ".tar", ".gz", ".iso", ".img", ".vhd"
}

DOCUMENT_EXTENSIONS = {
    ".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".txt"
}

IMAGE_EXTENSIONS = {
    ".jpg", ".jpeg", ".png", ".gif", ".webp", ".svg", ".bmp"
}

class DownloadAnalysisResult:
    def __init__(
        self,
        risk_score: float,
        confidence: float,
        decision: str, # ALLOW, WARN, BLOCK
        threat_type: str,
        reasons: List[str]
    ):
        self.risk_score = risk_score
        self.confidence = confidence
        self.decision = decision
        self.threat_type = threat_type
        self.reasons = reasons

class DownloadEngine:
    @staticmethod
    def analyze_download(req: DownloadScanRequest, source_domain_risk: float = 0.0) -> DownloadAnalysisResult:
        filename = req.filename.strip()
        lower_name = filename.lower()
        reasons = []
        score = source_domain_risk * 0.3
        confidence = 70.0

        # Check for double extension (e.g. invoice.pdf.exe)
        parts = lower_name.split(".")
        if len(parts) >= 3:
            penultimate_ext = "." + parts[-2]
            final_ext = "." + parts[-1]
            if (penultimate_ext in DOCUMENT_EXTENSIONS or penultimate_ext in IMAGE_EXTENSIONS or penultimate_ext in ARCHIVE_EXTENSIONS) and final_ext in EXECUTABLE_EXTENSIONS:
                score = 95.0
                confidence = 98.0
                reasons.append(f"Dangerous masquerading double-extension detected: '{penultimate_ext}{final_ext}'")
                return DownloadAnalysisResult(
                    risk_score=score,
                    confidence=confidence,
                    decision="BLOCK",
                    threat_type="MALICIOUS_DOWNLOAD",
                    reasons=reasons
                )

        # Check single extension
        _, ext = os.path.splitext(lower_name)
        if ext in EXECUTABLE_EXTENSIONS:
            score += 45.0
            confidence = max(confidence, 80.0)
            reasons.append(f"Direct executable file download ({ext})")
            if source_domain_risk >= 40.0:
                score += 40.0
                reasons.append(f"Executable hosted on domain with elevated risk ({source_domain_risk:.0f}/100)")
        elif ext in ARCHIVE_EXTENSIONS:
            score += 15.0
            if source_domain_risk >= 50.0:
                score += 35.0
                reasons.append(f"Archive download ({ext}) from suspicious/untrusted domain")

        # MIME type mismatch check
        if req.mime_type:
            mime = req.mime_type.lower()
            if "application/x-msdownload" in mime or "application/x-executable" in mime:
                if ext in DOCUMENT_EXTENSIONS or ext in IMAGE_EXTENSIONS:
                    score = 92.0
                    confidence = 95.0
                    reasons.append(f"Severe MIME type mismatch: '{mime}' masked as '{ext}'")

        final_score = max(0.0, min(score, 100.0))
        if final_score >= 80.0:
            decision = "BLOCK"
            threat_type = "MALICIOUS_DOWNLOAD"
        elif final_score >= 40.0:
            decision = "WARN"
            threat_type = "SUSPICIOUS_DOWNLOAD"
        else:
            decision = "ALLOW"
            threat_type = "NONE"

        return DownloadAnalysisResult(
            risk_score=final_score,
            confidence=confidence,
            decision=decision,
            threat_type=threat_type,
            reasons=reasons
        )
