from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import hashlib
import json


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

    def dedupe_key(self) -> str:
        payload = json.dumps(
            {
                "target": self.target,
                "vulnerability_type": self.vulnerability_type,
                "severity": self.severity.value,
                "source": self.source_scanner,
            },
            sort_keys=True,
        )
        return hashlib.sha256(payload.encode()).hexdigest()

    def to_dict(self) -> dict[str, Any]:
        return {
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
        )
