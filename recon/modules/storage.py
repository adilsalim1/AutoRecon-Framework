from __future__ import annotations

import json
from abc import ABC, abstractmethod
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

from recon.models.assets import Asset
from recon.models.findings import Finding


class StorageBackend(ABC):
    """Abstraction for JSON today; swap for SQL/NoSQL without changing engine."""

    @abstractmethod
    def save_assets(self, run_id: str, assets: list[Asset]) -> None:
        ...

    @abstractmethod
    def save_findings(self, run_id: str, findings: list[Finding]) -> None:
        ...

    @abstractmethod
    def append_scan_record(self, run_id: str, record: dict[str, Any]) -> None:
        ...

    @abstractmethod
    def has_scan_fingerprint(self, fingerprint: str) -> bool:
        ...

    @abstractmethod
    def record_scan_fingerprint(self, fingerprint: str, meta: dict[str, Any]) -> None:
        ...


class JsonStorageBackend(StorageBackend):
    def __init__(self, output_dir: Path) -> None:
        self._root = output_dir
        self._root.mkdir(parents=True, exist_ok=True)
        self._fingerprints_path = self._root / "scan_fingerprints.json"
        self._fingerprints: dict[str, dict[str, Any]] = {}
        self._load_fingerprints()

    def _load_fingerprints(self) -> None:
        if self._fingerprints_path.is_file():
            try:
                data = json.loads(self._fingerprints_path.read_text(encoding="utf-8"))
                if isinstance(data, dict):
                    self._fingerprints = data
            except json.JSONDecodeError:
                self._fingerprints = {}

    def _persist_fingerprints(self) -> None:
        self._fingerprints_path.write_text(
            json.dumps(self._fingerprints, indent=2, default=str), encoding="utf-8"
        )

    def save_assets(self, run_id: str, assets: list[Asset]) -> None:
        path = self._root / f"assets_{run_id}.json"
        path.write_text(
            json.dumps([a.to_dict() for a in assets], indent=2, default=str),
            encoding="utf-8",
        )

    def save_findings(self, run_id: str, findings: list[Finding]) -> None:
        path = self._root / f"findings_{run_id}.json"
        path.write_text(
            json.dumps([f.to_dict() for f in findings], indent=2, default=str),
            encoding="utf-8",
        )

    def append_scan_record(self, run_id: str, record: dict[str, Any]) -> None:
        path = self._root / f"scans_{run_id}.jsonl"
        line = json.dumps(record, default=str)
        with open(path, "a", encoding="utf-8") as f:
            f.write(line + "\n")

    def has_scan_fingerprint(self, fingerprint: str) -> bool:
        return fingerprint in self._fingerprints

    def record_scan_fingerprint(self, fingerprint: str, meta: dict[str, Any]) -> None:
        self._fingerprints[fingerprint] = {
            **meta,
            "recorded_at": datetime.now(timezone.utc).isoformat(),
        }
        self._persist_fingerprints()
