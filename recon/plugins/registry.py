from __future__ import annotations

from typing import Type

from recon.plugins.base import ScannerPlugin
from recon.plugins.mock_scanner import MockVulnerabilityScanner
from recon.plugins.tech_scanners import WappalyzerScannerPlugin, WhatWebScannerPlugin
from recon.plugins.tool_scanners import (
    FfufScannerPlugin,
    HttpxScannerPlugin,
    NaabuScannerPlugin,
    NmapScannerPlugin,
    NucleiScannerPlugin,
    SecretFinderScannerPlugin,
    SubjackScannerPlugin,
    SubzyScannerPlugin,
    VhostFfufScannerPlugin,
    Wafw00fScannerPlugin,
)


class PluginRegistry:
    def __init__(self) -> None:
        self._plugins: dict[str, Type[ScannerPlugin]] = {}

    def register(self, cls: Type[ScannerPlugin]) -> None:
        inst = cls()
        self._plugins[inst.name] = cls

    def get(self, name: str) -> ScannerPlugin:
        cls = self._plugins.get(name)
        if cls is None:
            raise KeyError(f"Unknown scanner plugin: {name}")
        return cls()

    def resolve(self, names: list[str]) -> list[ScannerPlugin]:
        return [self.get(n) for n in names]


def load_builtin_plugins() -> PluginRegistry:
    reg = PluginRegistry()
    reg.register(MockVulnerabilityScanner)
    reg.register(HttpxScannerPlugin)
    reg.register(NucleiScannerPlugin)
    reg.register(SubjackScannerPlugin)
    reg.register(SubzyScannerPlugin)
    reg.register(Wafw00fScannerPlugin)
    reg.register(NaabuScannerPlugin)
    reg.register(NmapScannerPlugin)
    reg.register(FfufScannerPlugin)
    reg.register(VhostFfufScannerPlugin)
    reg.register(SecretFinderScannerPlugin)
    reg.register(WhatWebScannerPlugin)
    reg.register(WappalyzerScannerPlugin)
    return reg
