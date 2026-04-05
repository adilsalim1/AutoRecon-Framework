"""
Regex-based secret classifiers for defense-style triage (high false-positive rate).
Tune for your program; pair with LinkFinder/SecretFinder for higher signal.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

from recon.models.findings import Severity


@dataclass(frozen=True)
class SecretPattern:
    name: str
    pattern: re.Pattern[str]
    severity: Severity
    confidence: float


# JWT: three base64url segments
_JWT = re.compile(
    r"\beyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\b"
)

# AWS access key id (20 chars) — often appears near secret key in files
_AWS_KEY = re.compile(r"\bAKIA[0-9A-Z]{16}\b")

# Generic high-entropy API key style (adjust to reduce noise)
_API_KEY = re.compile(
    r"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token)\s*[=:]\s*['\"]?([a-z0-9_\-]{20,80})['\"]?"
)

# OAuth client secret in JS/config
_OAUTH = re.compile(
    r"(?i)(?:client_secret|oauth[_-]?secret)\s*[=:]\s*['\"]([a-z0-9A-Z+/=_\-]{16,128})['\"]"
)

# Slack, GitHub classic PAT-style (broad — expect FPs)
_SLACK_TOKEN = re.compile(r"xox[baprs]-[0-9A-Za-z\-]{10,}")
_GH_PAT = re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")

# Hardcoded password in assignments (very noisy)
_CREDS = re.compile(
    r"(?i)(?:password|passwd|pwd)\s*[=:]\s*['\"]([^'\"]{6,64})['\"]"
)

BUILTIN_PATTERNS: tuple[SecretPattern, ...] = (
    SecretPattern("jwt_token", _JWT, Severity.HIGH, 0.75),
    SecretPattern("aws_access_key_id", _AWS_KEY, Severity.HIGH, 0.65),
    SecretPattern("api_key_assignment", _API_KEY, Severity.MEDIUM, 0.45),
    SecretPattern("oauth_client_secret", _OAUTH, Severity.HIGH, 0.55),
    SecretPattern("slack_token", _SLACK_TOKEN, Severity.CRITICAL, 0.7),
    SecretPattern("github_token", _GH_PAT, Severity.CRITICAL, 0.65),
    SecretPattern("hardcoded_password", _CREDS, Severity.MEDIUM, 0.35),
)
