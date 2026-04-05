from __future__ import annotations

from dataclasses import dataclass, field
from datetime import datetime, timezone
from enum import Enum
from typing import Any
import hashlib
import json


class AssetType(str, Enum):
    DOMAIN = "domain"
    SUBDOMAIN = "subdomain"
    IP = "ip"
    WEB = "web"
    API = "api"
    AUTH = "auth"
    JAVASCRIPT = "javascript"
    UNKNOWN = "unknown"


class Priority(str, Enum):
    CRITICAL = "critical"
    HIGH = "high"
    MEDIUM = "medium"
    LOW = "low"


@dataclass(frozen=True)
class Asset:
    """Discovered or inferred target surface unit."""

    identifier: str
    asset_type: AssetType = AssetType.UNKNOWN
    priority: Priority = Priority.MEDIUM
    tags: frozenset[str] = field(default_factory=frozenset)
    metadata: dict[str, Any] = field(default_factory=dict)
    discovered_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    parent_domain: str | None = None

    def stable_id(self) -> str:
        raw = f"{self.identifier}|{self.asset_type.value}"
        return hashlib.sha256(raw.encode()).hexdigest()[:16]

    def to_dict(self) -> dict[str, Any]:
        return {
            "id": self.stable_id(),
            "identifier": self.identifier,
            "asset_type": self.asset_type.value,
            "priority": self.priority.value,
            "tags": sorted(self.tags),
            "metadata": self.metadata,
            "discovered_at": self.discovered_at.isoformat(),
            "parent_domain": self.parent_domain,
        }

    @staticmethod
    def from_dict(data: dict[str, Any]) -> Asset:
        return Asset(
            identifier=data["identifier"],
            asset_type=AssetType(data.get("asset_type", "unknown")),
            priority=Priority(data.get("priority", "medium")),
            tags=frozenset(data.get("tags", [])),
            metadata=dict(data.get("metadata", {})),
            discovered_at=datetime.fromisoformat(
                data.get("discovered_at", datetime.now(timezone.utc).isoformat())
            ),
            parent_domain=data.get("parent_domain"),
        )

    def fingerprint_for_scan(self, scanner_name: str) -> str:
        payload = json.dumps(
            {"id": self.stable_id(), "scanner": scanner_name}, sort_keys=True
        )
        return hashlib.sha256(payload.encode()).hexdigest()
