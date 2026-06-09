"""Shared data models for scan pipeline typing."""

from __future__ import annotations

from dataclasses import dataclass, field
from dataclasses import asdict
from typing import Any, Dict, List, Optional


@dataclass
class ContextAnalysis:
    location: str
    type: str
    quote_char: Optional[str] = None
    attribute_name: Optional[str] = None
    tag_name: Optional[str] = None
    confidence: str = "MEDIUM"
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class BrowserExecutionResult:
    executed: bool
    method: Optional[str] = None
    evidence: Optional[str] = None
    error: Optional[str] = None
    browser_engine: str = "chromium"

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class VerificationResult:
    url: str
    payload: str
    validated: bool
    confidence: int
    severity_level: str
    context: Dict[str, Any]
    execution: Optional[BrowserExecutionResult] = None

    def to_dict(self) -> Dict[str, Any]:
        data = asdict(self)
        if self.execution is not None:
            data["execution"] = self.execution.to_dict()
        return data


@dataclass
class PayloadCandidate:
    url: str
    parameter: str
    payload: str
    context: Dict[str, Any]
    test_url: Optional[str] = None
    location: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class CrawlNode:
    url: str
    method: str
    status_code: int
    content_type: str
    depth: int
    parameters: List[Dict[str, Any]] = field(default_factory=list)
    forms: List[Dict[str, Any]] = field(default_factory=list)

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class WAFProfile:
    name: str
    vendor: Optional[str] = None
    detected: bool = False
    confidence: int = 0
    evidence: Optional[str] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)


@dataclass
class ScanResult:
    target: str
    scan_mode: str
    vulnerabilities: List[Dict[str, Any]]
    statistics: Dict[str, Any]
    start_time: Optional[float] = None
    end_time: Optional[float] = None

    def to_dict(self) -> Dict[str, Any]:
        return asdict(self)
