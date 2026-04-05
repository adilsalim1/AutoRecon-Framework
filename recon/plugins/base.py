from __future__ import annotations

import asyncio
from abc import ABC, abstractmethod
from dataclasses import dataclass, field
from datetime import datetime, timezone
from typing import Any

from recon.models.assets import Asset
from recon.models.findings import Finding


@dataclass
class RawScanResult:
    """Opaque container for tool-native output before normalization."""

    scanner_name: str
    targets: list[str] = field(default_factory=list)
    raw_payload: dict[str, Any] = field(default_factory=dict)
    captured_at: datetime = field(default_factory=lambda: datetime.now(timezone.utc))
    success: bool = True
    error_message: str | None = None


@dataclass
class ScanContext:
    """Injected dependencies and options for scanner plugins (tool-agnostic)."""

    domain: str
    rate_limit_per_second: float = 0.0
    metadata: dict[str, Any] = field(default_factory=dict)


class ScannerPlugin(ABC):
    """
    Pluggable scanner contract: run → parse → normalize.
    External tools integrate by subclassing and delegating run() to the tool.
    """

    name: str = "abstract"
    version: str = "0.0.0"

    @abstractmethod
    def run(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        """Execute the scanner against the given assets (sync; may use subprocess)."""
        ...

    @abstractmethod
    def parse(self, raw: RawScanResult) -> list[Finding]:
        """Convert raw tool output into preliminary Finding objects."""
        ...

    def normalize(self, findings: list[Finding]) -> list[Finding]:
        """Final pass: dedupe within plugin, enrich fields, severity mapping."""
        return findings

    async def run_async(self, targets: list[Asset], context: ScanContext) -> RawScanResult:
        """Default async wrapper; override for native async scanners."""
        return await asyncio.to_thread(self.run, targets, context)
