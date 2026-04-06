from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import hashlib
import json
from urllib.parse import urlparse


class Severity(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"
    INFO = "info"


@dataclass
class Finding:
    """Unified finding for aggregation across scanners."""

    target: str
    vulnerability_type: str
    severity: Severity
    evidence: dict[str, Any] = field(default_factory=dict)
    source_scanner: str = ""
    title: str = ""
    description: str = ""
    created_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    asset_id: str | None = None
    raw_reference: str | None = None
    # Extended PT fields (optional for backward compatibility)
    confidence: float | None = None
    """0.0–1.0 when set; higher = more reliable match."""
    exploitability: str | None = None
    """Short label, e.g. immediate, chained, theoretical."""
    source_ref: str | None = None
    """Primary evidence URL, file URL, or response source."""
    attack_path: list[str] = field(default_factory=list)
    """Ordered narrative steps for correlated chains."""
    risk_score: float | None = None
    """Computed prioritization score (see risk_scoring module)."""

    def dedupe_key(self) -> str:
        payload = json.dumps(
            {
                "target": self.target,
                "vulnerability_type": self.vulnerability_type,
                "severity": self.severity.value,
                "source": self.source_scanner,
                "attack_path": self.attack_path,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def _httpx_tech_fingerprint_dedupe_key(self) -> str | None:
        """
        Same host + same httpx tech evidence → one key (avoids #tech spam for every
        static URL when the stack is identical).
        """
        if (
            self.vulnerability_type != "live_http_service"
            or (self.source_scanner or "") != "httpx_scanner"
        ):
            return None
        t = (self.target or "").strip()
        host = ""
        if "://" in t:
            host = (urlparse(t).hostname or "").lower().rstrip(".")
        else:
            host = t.split("/")[0].split(":")[0].lower().rstrip(".")
        if not host:
            return None
        ev = self.evidence or {}
        tech_raw = ev.get("technologies") or ev.get("tech") or []
        if isinstance(tech_raw, str):
            tech_raw = [tech_raw]
        tech_list = sorted(
            str(x).strip().lower()
            for x in tech_raw
            if x is not None and str(x).strip()
        )
        server = ev.get("server")
        srv_norm = (
            str(server).strip().lower() if server is not None and str(server).strip() else None
        )
        fingerprint = {
            "host": host,
            "status_code": ev.get("status_code"),
            "server": srv_norm,
            "technologies": tech_list,
            "title": ev.get("title"),
        }
        payload = json.dumps(fingerprint, sort_keys=True, default=str)
        return hashlib.sha256(payload.encode()).hexdigest()

    def discord_notify_dedupe_key(self, channel_key: str) -> str:
        """Per-channel notification dedupe (e.g. collapse httpx tech by fingerprint on #tech)."""
        if channel_key == "tech":
            fp = self._httpx_tech_fingerprint_dedupe_key()
            if fp is not None:
                return fp
        return self.dedupe_key()

    def to_dict(self) -> dict[str, Any]:
        d: dict[str, Any] = {
            "target": self.target,
            "vulnerability_type": self.vulnerability_type,
            "severity": self.severity.value,
            "evidence": self.evidence,
            "source_scanner": self.source_scanner,
            "title": self.title,
            "description": self.description,
            "created_at": self.created_at.isoformat(),
            "asset_id": self.asset_id,
            "raw_reference": self.raw_reference,
            "dedupe_key": self.dedupe_key(),
        }
        if self.confidence is not None:
            d["confidence"] = self.confidence
        if self.exploitability:
            d["exploitability"] = self.exploitability
        if self.source_ref:
            d["source_ref"] = self.source_ref
        if self.attack_path:
            d["attack_path"] = list(self.attack_path)
        if self.risk_score is not None:
            d["risk_score"] = self.risk_score
        return d

    @staticmethod
    def from_dict(data: dict[str, Any]) -> Finding:
        return Finding(
            target=data["target"],
            vulnerability_type=data["vulnerability_type"],
            severity=Severity(data["severity"]),
            evidence=dict(data.get("evidence", {})),
            source_scanner=data.get("source_scanner", ""),
            title=data.get("title", ""),
            description=data.get("description", ""),
            created_at=datetime.fromisoformat(
                data.get("created_at", datetime.now(timezone.utc).isoformat())
            ),
            asset_id=data.get("asset_id"),
            raw_reference=data.get("raw_reference"),
            confidence=data.get("confidence"),
            exploitability=data.get("exploitability"),
            source_ref=data.get("source_ref"),
            attack_path=list(data.get("attack_path", []) or []),
            risk_score=data.get("risk_score"),
        )
